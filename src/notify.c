/*
 * notify.c - Webhook notifications for security events
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <json-c/json.h>

#include "notify.h"

/* Notification context */
struct notify_context {
    notify_config_t config;
    CURL *curl;
    char error_buf[256];
    char hostname[256];
};

/* Response buffer (we don't need the response, but curl needs somewhere to write) */
static size_t discard_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    (void)contents;
    (void)userp;
    return size * nmemb;
}

/* Secure free for strings containing secrets */
static void secure_free_str(char *ptr)
{
    if (ptr) {
        explicit_bzero(ptr, strlen(ptr));
        free(ptr);
    }
}

/* Generate HMAC-SHA256 signature */
static void generate_signature(const char *secret, const char *payload,
                               char *signature, size_t sig_size)
{
    if (!secret || !payload || !signature || sig_size < 65) {
        if (signature && sig_size > 0) signature[0] = '\0';
        return;
    }

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), secret, strlen(secret),
         (unsigned char *)payload, strlen(payload),
         hmac, &hmac_len);

    /* Convert to hex string */
    for (unsigned int i = 0; i < hmac_len && (i * 2 + 2) < sig_size; i++) {
        snprintf(signature + (i * 2), 3, "%02x", hmac[i]);
    }
}

notify_context_t *notify_init(const notify_config_t *config)
{
    if (!config || !config->webhook_url) {
        return NULL;
    }

    notify_context_t *ctx = calloc(1, sizeof(notify_context_t));
    if (!ctx) return NULL;

    /* Copy configuration */
    ctx->config.enabled = config->enabled;
    ctx->config.webhook_url = strdup(config->webhook_url);
    if (config->hmac_secret) {
        ctx->config.hmac_secret = strdup(config->hmac_secret);
    }
    ctx->config.timeout = config->timeout > 0 ? config->timeout : 30;
    ctx->config.verify_ssl = config->verify_ssl;
    ctx->config.retry_count = config->retry_count > 0 ? config->retry_count : 2;
    ctx->config.retry_delay_ms = config->retry_delay_ms > 0 ? config->retry_delay_ms : 1000;

    /* Initialize curl */
    ctx->curl = curl_easy_init();
    if (!ctx->curl) {
        notify_destroy(ctx);
        return NULL;
    }

    /* Get hostname */
    if (gethostname(ctx->hostname, sizeof(ctx->hostname)) != 0) {
        strncpy(ctx->hostname, "unknown", sizeof(ctx->hostname) - 1);
    }

    return ctx;
}

void notify_destroy(notify_context_t *ctx)
{
    if (!ctx) return;

    if (ctx->curl) {
        curl_easy_cleanup(ctx->curl);
    }

    free(ctx->config.webhook_url);
    secure_free_str(ctx->config.hmac_secret);

    explicit_bzero(ctx, sizeof(*ctx));
    free(ctx);
}

bool notify_should_send(audit_event_type_t event_type)
{
    switch (event_type) {
        case AUDIT_RATE_LIMITED:
        case AUDIT_SECURITY_ERROR:
        case AUDIT_CONFIG_ERROR:
        case AUDIT_AUTH_DENIED:
        case AUDIT_AUTHZ_DENIED:
            return true;
        default:
            return false;
    }
}

int notify_send_json(notify_context_t *ctx, const char *json_payload)
{
    if (!ctx || !ctx->config.enabled || !json_payload) {
        return -1;
    }

    int result = -1;

    /* Setup curl */
    curl_easy_reset(ctx->curl);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Add HMAC signature header if secret is configured */
    if (ctx->config.hmac_secret) {
        /*
         * Include timestamp in HMAC for replay attack protection.
         * Signature is computed as: HMAC-SHA256(secret, timestamp + "." + body)
         * This binds the timestamp to the payload, preventing replay attacks.
         *
         * Webhook receivers MUST:
         * 1. Reject requests with timestamps older than a threshold (e.g., 5 minutes)
         * 2. Verify signature using: HMAC-SHA256(secret, X-Timestamp + "." + body)
         */
        long timestamp = (long)time(NULL);
        char ts_str[32];
        snprintf(ts_str, sizeof(ts_str), "%ld", timestamp);

        /* Build signed message: timestamp.payload */
        size_t ts_len = strlen(ts_str);
        size_t payload_len = strlen(json_payload);
        size_t signed_msg_len = ts_len + 1 + payload_len;
        char *signed_msg = malloc(signed_msg_len + 1);

        if (signed_msg) {
            memcpy(signed_msg, ts_str, ts_len);
            signed_msg[ts_len] = '.';
            memcpy(signed_msg + ts_len + 1, json_payload, payload_len + 1);

            char signature[65];
            generate_signature(ctx->config.hmac_secret, signed_msg,
                              signature, sizeof(signature));
            free(signed_msg);

            char sig_header[128];
            snprintf(sig_header, sizeof(sig_header), "X-Signature-256: sha256=%s", signature);
            headers = curl_slist_append(headers, sig_header);

            char ts_header[64];
            snprintf(ts_header, sizeof(ts_header), "X-Timestamp: %ld", timestamp);
            headers = curl_slist_append(headers, ts_header);
        }
    }

    curl_easy_setopt(ctx->curl, CURLOPT_URL, ctx->config.webhook_url);
    curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, discard_callback);
    curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, (long)ctx->config.timeout);
    curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, ctx->config.verify_ssl ? 1L : 0L);
    curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, ctx->config.verify_ssl ? 2L : 0L);

    /* Retry loop */
    for (int attempt = 0; attempt <= ctx->config.retry_count; attempt++) {
        CURLcode res = curl_easy_perform(ctx->curl);

        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

            if (http_code >= 200 && http_code < 300) {
                result = 0;
                break;
            } else {
                snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                         "Webhook returned HTTP %ld", http_code);
            }
        } else {
            snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                     "Webhook failed: %s", curl_easy_strerror(res));
        }

        /* Wait before retry (except on last attempt) */
        if (attempt < ctx->config.retry_count) {
            usleep(ctx->config.retry_delay_ms * 1000);
        }
    }

    curl_slist_free_all(headers);
    return result;
}

int notify_send_event(notify_context_t *ctx, const audit_event_t *event)
{
    if (!ctx || !ctx->config.enabled || !event) {
        return -1;
    }

    /* Only send notifications for critical events */
    if (!notify_should_send(event->event_type)) {
        return 0;  /* Not an error, just filtered */
    }

    /* Build JSON payload using json-c for proper escaping */
    char timestamp[32];
    struct tm tm;
    time_t now = time(NULL);
    gmtime_r(&now, &tm);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm);

    json_object *jobj = json_object_new_object();
    if (!jobj) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "Failed to create JSON object");
        return -1;
    }

    json_object_object_add(jobj, "timestamp", json_object_new_string(timestamp));
    json_object_object_add(jobj, "event_type",
                           json_object_new_string(audit_event_type_str(event->event_type)));
    json_object_object_add(jobj, "correlation_id",
                           json_object_new_string(event->correlation_id));
    json_object_object_add(jobj, "host", json_object_new_string(ctx->hostname));
    json_object_object_add(jobj, "user",
                           json_object_new_string(event->user ? event->user : ""));
    json_object_object_add(jobj, "service",
                           json_object_new_string(event->service ? event->service : ""));
    json_object_object_add(jobj, "client_ip",
                           json_object_new_string(event->client_ip ? event->client_ip : ""));
    json_object_object_add(jobj, "result_code", json_object_new_int(event->result_code));
    json_object_object_add(jobj, "reason",
                           json_object_new_string(event->reason ? event->reason : ""));

    const char *json_str = json_object_to_json_string(jobj);
    int result = notify_send_json(ctx, json_str);

    json_object_put(jobj);  /* Free the JSON object */
    return result;
}

const char *notify_error(notify_context_t *ctx)
{
    return ctx ? ctx->error_buf : "NULL notify context";
}
