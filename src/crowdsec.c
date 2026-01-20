/*
 * crowdsec.c - CrowdSec integration for Open Bastion PAM module
 *
 * Implements bouncer (pre-auth IP check) and watcher (post-auth alert reporting)
 * using the CrowdSec Local API (LAPI).
 *
 * Based on LemonLDAP::NG CrowdSec implementation.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/sha.h>

#include "crowdsec.h"

/* Module version for scenario_version field */
#define CROWDSEC_MODULE_VERSION "1.0.0"

/* Maximum response size to prevent DoS */
#define MAX_RESPONSE_SIZE (256 * 1024)

/* Initial buffer size for responses */
#define INITIAL_BUFFER_SIZE 4096

/* Decision cache TTL in seconds (avoid hammering LAPI) */
#define DECISION_CACHE_TTL 30

/* Maximum cached IPs */
#define DECISION_CACHE_SIZE 16

/* Minimum interval between failed login attempts (avoid hammering LAPI) */
#define TOKEN_RETRY_INTERVAL 30

/* Cached decision entry */
typedef struct {
    char ip[46];                /* IPv4 or IPv6 address */
    crowdsec_result_t result;   /* Cached decision */
    time_t timestamp;           /* When the decision was cached */
} decision_cache_entry_t;

/* CrowdSec context */
struct crowdsec_context {
    crowdsec_config_t config;
    CURL *curl;
    char error_buf[256];
    char *token;                /* JWT token from watcher login */
    time_t token_exp;           /* Token expiration time */
    time_t last_login_failure;  /* Timestamp of last failed login attempt */

    /* Decision cache to avoid hammering LAPI */
    decision_cache_entry_t decision_cache[DECISION_CACHE_SIZE];
    int decision_cache_idx;     /* Next index to use (circular) */
};

/* Response buffer for curl */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} response_buffer_t;

/* Secure string free */
static void secure_free_str(char *ptr)
{
    if (ptr) {
        explicit_bzero(ptr, strlen(ptr));
        free(ptr);
    }
}

/* Initialize response buffer - returns 0 on success, -1 on failure */
static int init_buffer(response_buffer_t *buf)
{
    buf->data = malloc(INITIAL_BUFFER_SIZE);
    buf->size = 0;
    buf->capacity = INITIAL_BUFFER_SIZE;
    if (!buf->data) {
        return -1;
    }
    buf->data[0] = '\0';
    return 0;
}

/* Free response buffer */
static void free_buffer(response_buffer_t *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

/* Curl write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    response_buffer_t *buf = (response_buffer_t *)userp;

    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        return 0;  /* Overflow */
    }
    size_t realsize = size * nmemb;

    if (buf->size + realsize > MAX_RESPONSE_SIZE) {
        return 0;  /* Response too large */
    }

    size_t needed = buf->size + realsize + 1;
    if (needed > buf->capacity) {
        size_t new_capacity = buf->capacity + (buf->capacity >> 1);
        if (new_capacity < needed) {
            new_capacity = needed;
        }
        if (new_capacity > MAX_RESPONSE_SIZE + 1) {
            new_capacity = MAX_RESPONSE_SIZE + 1;
        }
        char *ptr = realloc(buf->data, new_capacity);
        if (!ptr) {
            return 0;
        }
        buf->data = ptr;
        buf->capacity = new_capacity;
    }

    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';

    return realsize;
}

/* Setup curl with common options */
static void setup_curl(crowdsec_context_t *ctx)
{
    curl_easy_reset(ctx->curl);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, (long)ctx->config.timeout);
    curl_easy_setopt(ctx->curl, CURLOPT_CONNECTTIMEOUT, (long)ctx->config.timeout);

    if (ctx->config.verify_ssl) {
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, 2L);
        if (ctx->config.ca_cert) {
            curl_easy_setopt(ctx->curl, CURLOPT_CAINFO, ctx->config.ca_cert);
        }
    } else {
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

/* Compute SHA256 hash of scenario name */
static void compute_scenario_hash(const char *scenario, char *hash_out, size_t hash_size)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)scenario, strlen(scenario), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH && (size_t)(i * 2 + 2) < hash_size; i++) {
        snprintf(hash_out + (i * 2), 3, "%02x", hash[i]);
    }
}

/* Get current timestamp in ISO 8601 format */
static void get_timestamp(char *buf, size_t size)
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Check if IP is in decision cache (returns 1 if found and result is set) */
static int cache_lookup(crowdsec_context_t *ctx, const char *ip,
                        crowdsec_result_t *result)
{
    time_t now = time(NULL);

    for (int i = 0; i < DECISION_CACHE_SIZE; i++) {
        if (ctx->decision_cache[i].ip[0] != '\0' &&
            strcmp(ctx->decision_cache[i].ip, ip) == 0) {
            /* Check TTL */
            if (now - ctx->decision_cache[i].timestamp < DECISION_CACHE_TTL) {
                *result = ctx->decision_cache[i].result;
                return 1;
            }
            /* Entry expired, invalidate it */
            ctx->decision_cache[i].ip[0] = '\0';
            break;
        }
    }
    return 0;
}

/* Store decision in cache */
static void cache_store(crowdsec_context_t *ctx, const char *ip,
                        crowdsec_result_t result)
{
    /* Use circular buffer, overwrite oldest entry */
    int idx = ctx->decision_cache_idx;

    strncpy(ctx->decision_cache[idx].ip, ip,
            sizeof(ctx->decision_cache[idx].ip) - 1);
    ctx->decision_cache[idx].ip[sizeof(ctx->decision_cache[idx].ip) - 1] = '\0';
    ctx->decision_cache[idx].result = result;
    ctx->decision_cache[idx].timestamp = time(NULL);

    ctx->decision_cache_idx = (idx + 1) % DECISION_CACHE_SIZE;
}

/* Login to CrowdSec LAPI to get JWT token (watcher role) */
static int watcher_login(crowdsec_context_t *ctx)
{
    if (!ctx->config.machine_id || !ctx->config.password) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Missing machine_id or password for watcher login");
        return -1;
    }

    /* Build URL */
    char url[1024];
    int url_len = snprintf(url, sizeof(url), "%s/v1/watchers/login", ctx->config.url);
    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "URL too long");
        return -1;
    }

    /* Build JSON body */
    struct json_object *req = json_object_new_object();
    if (!req) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "Failed to create JSON object");
        return -1;
    }
    json_object_object_add(req, "machine_id",
                           json_object_new_string(ctx->config.machine_id));
    json_object_object_add(req, "password",
                           json_object_new_string(ctx->config.password));

    const char *body = json_object_to_json_string(req);

    /* Setup curl */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    response_buffer_t buf;
    if (init_buffer(&buf) != 0) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to allocate response buffer");
        json_object_put(req);
        curl_slist_free_all(headers);
        return -1;
    }
    setup_curl(ctx);

    curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(ctx->curl);
    json_object_put(req);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Watcher login failed: %s", curl_easy_strerror(res));
        free_buffer(&buf);
        return -1;
    }

    long http_code;
    curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Watcher login failed: HTTP %ld", http_code);
        free_buffer(&buf);
        return -1;
    }

    /* Parse response */
    struct json_object *resp = json_tokener_parse(buf.data);
    free_buffer(&buf);

    if (!resp) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to parse watcher login response");
        return -1;
    }

    struct json_object *token_obj, *expire_obj;
    if (json_object_object_get_ex(resp, "token", &token_obj)) {
        secure_free_str(ctx->token);
        ctx->token = strdup(json_object_get_string(token_obj));
    }

    if (json_object_object_get_ex(resp, "expire", &expire_obj)) {
        /* Parse ISO 8601 timestamp */
        const char *expire_str = json_object_get_string(expire_obj);
        struct tm tm = {0};
        if (strptime(expire_str, "%Y-%m-%dT%H:%M:%S", &tm)) {
            ctx->token_exp = timegm(&tm);
        } else {
            /* Fallback: assume 1 hour validity */
            ctx->token_exp = time(NULL) + 3600;
        }
    } else {
        ctx->token_exp = time(NULL) + 3600;
    }

    json_object_put(resp);

    return ctx->token ? 0 : -1;
}

/* Ensure we have a valid token */
static int ensure_token(crowdsec_context_t *ctx)
{
    time_t now = time(NULL);

    if (ctx->token && ctx->token_exp > now + 10) {
        return 0;  /* Token still valid */
    }

    /* Avoid hammering LAPI if login recently failed */
    if (ctx->last_login_failure > 0 &&
        now - ctx->last_login_failure < TOKEN_RETRY_INTERVAL) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Token refresh skipped (recent failure)");
        return -1;
    }

    int result = watcher_login(ctx);
    if (result != 0) {
        ctx->last_login_failure = now;
    } else {
        ctx->last_login_failure = 0;  /* Clear failure state on success */
    }

    return result;
}

/*
 * Get count of alerts for IP in the time window.
 *
 * @param ctx CrowdSec context
 * @param ip IP address to check
 * @param max_needed Stop counting once this threshold is reached (0 = count all)
 * @return Number of matching alerts (capped at max_needed if specified)
 */
static int get_alerts_count(crowdsec_context_t *ctx, const char *ip, int max_needed)
{
    if (ensure_token(ctx) != 0) {
        return 0;  /* Can't get count, assume 0 */
    }

    /* Build URL with server-side filtering */
    char url[1024];
    char *escaped_ip = curl_easy_escape(ctx->curl, ip, 0);
    char *escaped_scenario = curl_easy_escape(ctx->curl, ctx->config.scenario, 0);
    if (!escaped_ip || !escaped_scenario) {
        curl_free(escaped_ip);
        curl_free(escaped_scenario);
        return 0;
    }

    /* Calculate since timestamp for block_delay window */
    time_t since = time(NULL) - ctx->config.block_delay;
    struct tm tm;
    char since_str[32];
    gmtime_r(&since, &tm);
    strftime(since_str, sizeof(since_str), "%Y-%m-%dT%H:%M:%SZ", &tm);

    int written = snprintf(url, sizeof(url),
                           "%s/v1/alerts?ip=%s&scenario=%s&since=%s",
                           ctx->config.url, escaped_ip, escaped_scenario, since_str);
    curl_free(escaped_ip);
    curl_free(escaped_scenario);

    if (written < 0 || (size_t)written >= sizeof(url)) {
        return 0;  /* URL truncated */
    }

    /* Setup curl */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");

    char auth_header[4096];
    int auth_len = snprintf(auth_header, sizeof(auth_header),
                            "Authorization: Bearer %s", ctx->token);
    if (auth_len < 0 || (size_t)auth_len >= sizeof(auth_header)) {
        curl_slist_free_all(headers);
        return 0;  /* Token too long */
    }
    headers = curl_slist_append(headers, auth_header);

    response_buffer_t buf;
    if (init_buffer(&buf) != 0) {
        explicit_bzero(auth_header, sizeof(auth_header));
        curl_slist_free_all(headers);
        return 0;
    }
    setup_curl(ctx);

    curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(ctx->curl);
    explicit_bzero(auth_header, sizeof(auth_header));
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        free_buffer(&buf);
        return 0;
    }

    long http_code;
    curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        free_buffer(&buf);
        return 0;
    }

    /* Parse response */
    struct json_object *alerts = json_tokener_parse(buf.data);
    free_buffer(&buf);

    if (!alerts || !json_object_is_type(alerts, json_type_array)) {
        if (alerts) json_object_put(alerts);
        return 0;
    }

    /* Count alerts matching our criteria */
    time_t time_limit = time(NULL) - ctx->config.block_delay;
    int count = 0;
    int len = json_object_array_length(alerts);

    for (int i = 0; i < len; i++) {
        struct json_object *alert = json_object_array_get_idx(alerts, i);

        /* Check scenario matches */
        struct json_object *scenario_obj;
        if (!json_object_object_get_ex(alert, "scenario", &scenario_obj)) {
            continue;
        }
        const char *scenario = json_object_get_string(scenario_obj);
        if (!scenario || strcmp(scenario, ctx->config.scenario) != 0) {
            continue;
        }

        /* Check source IP matches */
        struct json_object *source_obj, *value_obj;
        if (!json_object_object_get_ex(alert, "source", &source_obj)) {
            continue;
        }
        if (!json_object_object_get_ex(source_obj, "value", &value_obj)) {
            continue;
        }
        const char *source_ip = json_object_get_string(value_obj);
        if (!source_ip || strcmp(source_ip, ip) != 0) {
            continue;
        }

        /* Check timestamp is within block_delay window */
        struct json_object *start_at_obj;
        if (json_object_object_get_ex(alert, "start_at", &start_at_obj)) {
            const char *start_at = json_object_get_string(start_at_obj);
            if (start_at) {
                struct tm tm = {0};
                if (strptime(start_at, "%Y-%m-%dT%H:%M:%S", &tm)) {
                    time_t alert_time = timegm(&tm);
                    if (alert_time < time_limit) {
                        continue;  /* Alert too old */
                    }
                }
            }
        }

        count++;

        /* Early termination: stop once we've reached the threshold */
        if (max_needed > 0 && count >= max_needed) {
            break;
        }
    }

    json_object_put(alerts);
    return count;
}

/* Build alert JSON payload */
static char *build_alert_payload(crowdsec_context_t *ctx,
                                 const char *ip,
                                 const char *user,
                                 const char *service,
                                 bool remediation)
{
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    char scenario_hash[65];
    compute_scenario_hash(ctx->config.scenario, scenario_hash, sizeof(scenario_hash));

    /* Build message */
    char message[256];
    snprintf(message, sizeof(message), "SSH auth failure for user %s (service: %s)",
             user ? user : "unknown", service ? service : "unknown");

    /* Build alert object */
    struct json_object *alert = json_object_new_object();
    if (!alert) return NULL;

    /* Add fields - json-c handles NULL from json_object_new_* gracefully */
    json_object_object_add(alert, "scenario",
                           json_object_new_string(ctx->config.scenario));
    json_object_object_add(alert, "scenario_hash",
                           json_object_new_string(scenario_hash));
    json_object_object_add(alert, "scenario_version",
                           json_object_new_string(CROWDSEC_MODULE_VERSION));
    json_object_object_add(alert, "message",
                           json_object_new_string(message));
    json_object_object_add(alert, "events_count", json_object_new_int(1));
    json_object_object_add(alert, "start_at", json_object_new_string(timestamp));
    json_object_object_add(alert, "stop_at", json_object_new_string(timestamp));
    json_object_object_add(alert, "capacity", json_object_new_int(1));
    json_object_object_add(alert, "leakspeed", json_object_new_string("1s"));
    json_object_object_add(alert, "simulated", json_object_new_boolean(0));
    json_object_object_add(alert, "remediation", json_object_new_boolean(remediation));

    /* Source */
    struct json_object *source = json_object_new_object();
    if (!source) {
        json_object_put(alert);
        return NULL;
    }
    json_object_object_add(source, "scope", json_object_new_string("ip"));
    json_object_object_add(source, "value", json_object_new_string(ip));
    json_object_object_add(alert, "source", source);

    /* Events with metadata */
    struct json_object *events = json_object_new_array();
    if (!events) {
        json_object_put(alert);
        return NULL;
    }
    struct json_object *event = json_object_new_object();
    if (!event) {
        json_object_put(events);
        json_object_put(alert);
        return NULL;
    }
    json_object_object_add(event, "timestamp", json_object_new_string(timestamp));

    struct json_object *meta = json_object_new_array();
    if (!meta) {
        json_object_put(event);
        json_object_put(events);
        json_object_put(alert);
        return NULL;
    }

    struct json_object *meta_type = json_object_new_object();
    if (meta_type) {
        json_object_object_add(meta_type, "key", json_object_new_string("log_type"));
        json_object_object_add(meta_type, "value", json_object_new_string("ssh-auth"));
        json_object_array_add(meta, meta_type);
    }

    struct json_object *meta_reason = json_object_new_object();
    if (meta_reason) {
        json_object_object_add(meta_reason, "key", json_object_new_string("reason"));
        json_object_object_add(meta_reason, "value", json_object_new_string("Authentication failed"));
        json_object_array_add(meta, meta_reason);
    }

    if (user) {
        struct json_object *meta_login = json_object_new_object();
        if (meta_login) {
            json_object_object_add(meta_login, "key", json_object_new_string("login"));
            json_object_object_add(meta_login, "value", json_object_new_string(user));
            json_object_array_add(meta, meta_login);
        }
    }

    if (service) {
        struct json_object *meta_service = json_object_new_object();
        if (meta_service) {
            json_object_object_add(meta_service, "key", json_object_new_string("service"));
            json_object_object_add(meta_service, "value", json_object_new_string(service));
            json_object_array_add(meta, meta_service);
        }
    }

    json_object_object_add(event, "meta", meta);

    /* Add source to event as well */
    struct json_object *event_source = json_object_new_object();
    if (event_source) {
        json_object_object_add(event_source, "scope", json_object_new_string("ip"));
        json_object_object_add(event_source, "value", json_object_new_string(ip));
        json_object_object_add(event, "source", event_source);
    }

    json_object_array_add(events, event);
    json_object_object_add(alert, "events", events);

    /* Add decision if remediation is requested */
    if (remediation) {
        struct json_object *decisions = json_object_new_array();
        if (decisions) {
            struct json_object *decision = json_object_new_object();
            if (decision) {
                json_object_object_add(decision, "duration",
                                       json_object_new_string(ctx->config.ban_duration));
                json_object_object_add(decision, "type", json_object_new_string("ban"));
                json_object_object_add(decision, "scope", json_object_new_string("ip"));
                json_object_object_add(decision, "value", json_object_new_string(ip));
                json_object_object_add(decision, "origin", json_object_new_string("open-bastion"));
                json_object_object_add(decision, "scenario",
                                       json_object_new_string(ctx->config.scenario));
                json_object_array_add(decisions, decision);
            }
            json_object_object_add(alert, "decisions", decisions);
        }
    }

    /* Wrap in array as LAPI expects */
    struct json_object *alerts_array = json_object_new_array();
    if (!alerts_array) {
        json_object_put(alert);
        return NULL;
    }
    json_object_array_add(alerts_array, alert);

    const char *json_str = json_object_to_json_string(alerts_array);
    char *result = NULL;
    if (json_str) {
        result = strdup(json_str);
    }

    json_object_put(alerts_array);

    return result;
}

/* Public API */

crowdsec_context_t *crowdsec_init(const crowdsec_config_t *config)
{
    if (!config) {
        return NULL;
    }

    crowdsec_context_t *ctx = calloc(1, sizeof(crowdsec_context_t));
    if (!ctx) {
        return NULL;
    }

    /* Copy configuration */
    ctx->config.enabled = config->enabled;
    ctx->config.url = config->url ? strdup(config->url) : strdup(CROWDSEC_DEFAULT_URL);
    if (!ctx->config.url) {
        crowdsec_destroy(ctx);
        return NULL;
    }

    ctx->config.timeout = config->timeout > 0 ? config->timeout : CROWDSEC_DEFAULT_TIMEOUT;
    ctx->config.fail_open = config->fail_open;
    ctx->config.verify_ssl = config->verify_ssl;
    ctx->config.ca_cert = config->ca_cert ? strdup(config->ca_cert) : NULL;
    if (config->ca_cert && !ctx->config.ca_cert) {
        crowdsec_destroy(ctx);
        return NULL;
    }

    ctx->config.bouncer_key = config->bouncer_key ? strdup(config->bouncer_key) : NULL;
    if (config->bouncer_key && !ctx->config.bouncer_key) {
        crowdsec_destroy(ctx);
        return NULL;
    }
    ctx->config.action = config->action;

    ctx->config.machine_id = config->machine_id ? strdup(config->machine_id) : NULL;
    if (config->machine_id && !ctx->config.machine_id) {
        crowdsec_destroy(ctx);
        return NULL;
    }
    ctx->config.password = config->password ? strdup(config->password) : NULL;
    if (config->password && !ctx->config.password) {
        crowdsec_destroy(ctx);
        return NULL;
    }

    ctx->config.scenario = config->scenario ? strdup(config->scenario) :
                           strdup(CROWDSEC_DEFAULT_SCENARIO);
    if (!ctx->config.scenario) {
        crowdsec_destroy(ctx);
        return NULL;
    }

    ctx->config.send_all_alerts = config->send_all_alerts;
    ctx->config.max_failures = config->max_failures > 0 ? config->max_failures :
                               CROWDSEC_DEFAULT_MAX_FAILURES;
    ctx->config.block_delay = config->block_delay > 0 ? config->block_delay :
                              CROWDSEC_DEFAULT_BLOCK_DELAY;

    ctx->config.ban_duration = config->ban_duration ? strdup(config->ban_duration) :
                               strdup(CROWDSEC_DEFAULT_BAN_DURATION);
    if (!ctx->config.ban_duration) {
        crowdsec_destroy(ctx);
        return NULL;
    }

    /* Initialize curl */
    ctx->curl = curl_easy_init();
    if (!ctx->curl) {
        crowdsec_destroy(ctx);
        return NULL;
    }

    ctx->error_buf[0] = '\0';

    return ctx;
}

void crowdsec_destroy(crowdsec_context_t *ctx)
{
    if (!ctx) return;

    if (ctx->curl) {
        curl_easy_cleanup(ctx->curl);
    }

    free(ctx->config.url);
    free(ctx->config.ca_cert);
    secure_free_str(ctx->config.bouncer_key);
    free(ctx->config.machine_id);
    secure_free_str(ctx->config.password);
    free(ctx->config.scenario);
    free(ctx->config.ban_duration);
    secure_free_str(ctx->token);

    explicit_bzero(ctx, sizeof(*ctx));
    free(ctx);
}

crowdsec_result_t crowdsec_check_ip(crowdsec_context_t *ctx, const char *ip)
{
    if (!ctx || !ctx->config.enabled || !ip) {
        return CS_ALLOW;
    }

    if (!ctx->config.bouncer_key) {
        /* No bouncer key configured, allow by default */
        return CS_ALLOW;
    }

    ctx->error_buf[0] = '\0';

    /* Check cache first to avoid hammering LAPI */
    crowdsec_result_t cached_result;
    if (cache_lookup(ctx, ip, &cached_result)) {
        return cached_result;
    }

    /* Build URL */
    char url[1024];
    char *escaped_ip = curl_easy_escape(ctx->curl, ip, 0);
    if (!escaped_ip) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "Failed to escape IP");
        return CS_ERROR;
    }
    int url_len = snprintf(url, sizeof(url), "%s/v1/decisions?ip=%s",
                           ctx->config.url, escaped_ip);
    curl_free(escaped_ip);

    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "URL too long");
        return CS_ERROR;
    }

    /* Setup headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");

    char api_key_header[256];
    snprintf(api_key_header, sizeof(api_key_header), "X-Api-Key: %s", ctx->config.bouncer_key);
    headers = curl_slist_append(headers, api_key_header);

    /* Execute request */
    response_buffer_t buf;
    if (init_buffer(&buf) != 0) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to allocate response buffer");
        explicit_bzero(api_key_header, sizeof(api_key_header));
        curl_slist_free_all(headers);
        return CS_ERROR;
    }
    setup_curl(ctx);

    curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(ctx->curl);
    explicit_bzero(api_key_header, sizeof(api_key_header));
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "CrowdSec request failed: %s", curl_easy_strerror(res));
        free_buffer(&buf);
        return CS_ERROR;
    }

    long http_code;
    curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code == 403) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "Invalid bouncer API key");
        free_buffer(&buf);
        return CS_ERROR;
    }

    if (http_code != 200) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "CrowdSec returned HTTP %ld", http_code);
        free_buffer(&buf);
        return CS_ERROR;
    }

    /* Parse response */
    /* "null" or empty means no decisions = allow */
    if (buf.size == 0 || strcmp(buf.data, "null") == 0) {
        free_buffer(&buf);
        cache_store(ctx, ip, CS_ALLOW);
        return CS_ALLOW;
    }

    struct json_object *json = json_tokener_parse(buf.data);
    free_buffer(&buf);

    if (!json) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "Failed to parse CrowdSec response");
        return CS_ERROR;
    }

    if (!json_object_is_type(json, json_type_array)) {
        json_object_put(json);
        cache_store(ctx, ip, CS_ALLOW);
        return CS_ALLOW;
    }

    /* Check for ban decisions */
    int len = json_object_array_length(json);
    for (int i = 0; i < len; i++) {
        struct json_object *decision = json_object_array_get_idx(json, i);
        struct json_object *type_obj;

        if (json_object_object_get_ex(decision, "type", &type_obj)) {
            const char *type = json_object_get_string(type_obj);
            if (type && strcmp(type, "ban") == 0) {
                json_object_put(json);
                cache_store(ctx, ip, CS_DENY);
                return CS_DENY;
            }
        }
    }

    json_object_put(json);
    cache_store(ctx, ip, CS_ALLOW);
    return CS_ALLOW;
}

int crowdsec_report_failure(crowdsec_context_t *ctx,
                            const char *ip,
                            const char *user,
                            const char *service)
{
    if (!ctx || !ctx->config.enabled || !ip) {
        return 0;  /* Silent no-op if disabled */
    }

    if (!ctx->config.machine_id || !ctx->config.password) {
        /* Watcher credentials not configured */
        return 0;
    }

    ctx->error_buf[0] = '\0';

    /* Check if already banned (avoid duplicate alerts) */
    crowdsec_result_t current = crowdsec_check_ip(ctx, ip);
    if (current == CS_DENY) {
        return 0;  /* Already banned, no need to report */
    }

    /*
     * Get existing alerts count.
     *
     * NOTE: There is an inherent race condition here in concurrent environments.
     * Multiple PAM processes could simultaneously pass the CS_DENY check above,
     * count the same number of alerts, and all decide to trigger a ban.
     * This is acceptable because:
     * - CrowdSec LAPI handles duplicate decisions idempotently
     * - Multiple ban decisions for the same IP are merged, not stacked
     * - Slight over-counting is acceptable for security purposes
     *
     * For stricter atomic counting, use CrowdSec's built-in scenarios or
     * Crowdsieve (https://github.com/linagora/crowdsieve) which handles
     * aggregation server-side.
     */
    /*
     * Get alert count with early termination optimization.
     * We only need to know if we've reached max_failures, so stop counting there.
     */
    int count = get_alerts_count(ctx, ip, ctx->config.max_failures);

    /* Determine if this alert should trigger a ban */
    bool remediation = (ctx->config.max_failures > 0 &&
                       count >= ctx->config.max_failures - 1);

    /* If send_all_alerts=false, only send when remediation triggers */
    if (!ctx->config.send_all_alerts && !remediation) {
        return 0;  /* Skip this alert */
    }

    /* Ensure we have a valid token */
    if (ensure_token(ctx) != 0) {
        return -1;
    }

    /* Build alert payload */
    char *payload = build_alert_payload(ctx, ip, user, service, remediation);
    if (!payload) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "Failed to build alert payload");
        return -1;
    }

    /* Build URL */
    char url[1024];
    int url_len = snprintf(url, sizeof(url), "%s/v1/alerts", ctx->config.url);
    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "URL too long");
        free(payload);
        return -1;
    }

    /* Setup headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    char auth_header[4096];
    int auth_len = snprintf(auth_header, sizeof(auth_header),
                            "Authorization: Bearer %s", ctx->token);
    if (auth_len < 0 || (size_t)auth_len >= sizeof(auth_header)) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf), "Token too long");
        curl_slist_free_all(headers);
        free(payload);
        return -1;
    }
    headers = curl_slist_append(headers, auth_header);

    /* Execute request */
    response_buffer_t buf;
    if (init_buffer(&buf) != 0) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to allocate response buffer");
        explicit_bzero(auth_header, sizeof(auth_header));
        curl_slist_free_all(headers);
        free(payload);
        return -1;
    }
    setup_curl(ctx);

    curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(ctx->curl);
    explicit_bzero(auth_header, sizeof(auth_header));
    curl_slist_free_all(headers);
    free(payload);
    free_buffer(&buf);

    if (res != CURLE_OK) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Failed to send alert: %s", curl_easy_strerror(res));
        return -1;
    }

    long http_code;
    curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code < 200 || http_code >= 300) {
        snprintf(ctx->error_buf, sizeof(ctx->error_buf),
                 "Alert request failed: HTTP %ld", http_code);
        return -1;
    }

    return 0;
}

const char *crowdsec_error(crowdsec_context_t *ctx)
{
    return ctx ? ctx->error_buf : "NULL context";
}
