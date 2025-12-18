/*
 * token_manager.c - Token management with refresh rotation for PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "token_manager.h"

/* Token manager structure */
struct token_manager {
    token_manager_config_t config;
    CURL *curl;
    char error_buf[256];
};

/* Response buffer for curl */
typedef struct {
    char *data;
    size_t size;
} response_buffer_t;

/* Curl write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t total = size * nmemb;
    response_buffer_t *buf = (response_buffer_t *)userp;

    char *ptr = realloc(buf->data, buf->size + total + 1);
    if (!ptr) return 0;

    buf->data = ptr;
    memcpy(buf->data + buf->size, contents, total);
    buf->size += total;
    buf->data[buf->size] = '\0';

    return total;
}

/* Secure free for strings containing secrets */
static void secure_free_str(char *ptr)
{
    if (ptr) {
        explicit_bzero(ptr, strlen(ptr));
        free(ptr);
    }
}

/* For unit testing, expose internal functions */
#ifdef TOKEN_MANAGER_TEST
#define STATIC_OR_TEST
#else
#define STATIC_OR_TEST static
#endif

/* Base64url encode (RFC 4648 section 5) */
STATIC_OR_TEST char *base64url_encode(const unsigned char *data, size_t len)
{
    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3) {
        unsigned int val = data[i] << 16;
        if (i + 1 < len) val |= data[i + 1] << 8;
        if (i + 2 < len) val |= data[i + 2];

        out[j++] = b64_table[(val >> 18) & 0x3F];
        out[j++] = b64_table[(val >> 12) & 0x3F];
        if (i + 1 < len) out[j++] = b64_table[(val >> 6) & 0x3F];
        if (i + 2 < len) out[j++] = b64_table[val & 0x3F];
    }
    out[j] = '\0';

    return out;
}

/* Generate a UUID v4 for JWT jti claim */
STATIC_OR_TEST char *generate_uuid(void)
{
    unsigned char uuid_bytes[16];
    if (RAND_bytes(uuid_bytes, sizeof(uuid_bytes)) != 1) {
        return NULL;
    }

    /* Set version 4 (random) */
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    /* Set variant (RFC 4122) */
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;

    char *uuid = malloc(37);
    if (!uuid) return NULL;

    snprintf(uuid, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
             uuid_bytes[4], uuid_bytes[5],
             uuid_bytes[6], uuid_bytes[7],
             uuid_bytes[8], uuid_bytes[9],
             uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13],
             uuid_bytes[14], uuid_bytes[15]);

    return uuid;
}

/*
 * Generate client_secret_jwt assertion (RFC 7523)
 * Returns dynamically allocated JWT string or NULL on error
 * Caller must free with secure_free_str()
 */
STATIC_OR_TEST char *generate_client_jwt(const char *client_id, const char *client_secret,
                                          const char *token_endpoint)
{
    if (!client_id || !client_secret || !token_endpoint) {
        return NULL;
    }

    /* Generate UUID for jti */
    char *jti = generate_uuid();
    if (!jti) return NULL;

    time_t now = time(NULL);
    time_t exp = now + 300;  /* 5 minute expiry */

    /* Build header: {"alg":"HS256","typ":"JWT"} */
    const char *header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char *header_b64 = base64url_encode((const unsigned char *)header_json,
                                         strlen(header_json));
    if (!header_b64) {
        free(jti);
        return NULL;
    }

    /* Build payload using json-c to properly escape strings */
    struct json_object *payload_obj = json_object_new_object();
    if (!payload_obj) {
        free(jti);
        free(header_b64);
        return NULL;
    }

    json_object_object_add(payload_obj, "iss", json_object_new_string(client_id));
    json_object_object_add(payload_obj, "sub", json_object_new_string(client_id));
    json_object_object_add(payload_obj, "aud", json_object_new_string(token_endpoint));
    json_object_object_add(payload_obj, "exp", json_object_new_int64((int64_t)exp));
    json_object_object_add(payload_obj, "iat", json_object_new_int64((int64_t)now));
    json_object_object_add(payload_obj, "jti", json_object_new_string(jti));

    free(jti);

    const char *payload_json = json_object_to_json_string_ext(payload_obj,
                                                               JSON_C_TO_STRING_PLAIN);
    if (!payload_json) {
        json_object_put(payload_obj);
        free(header_b64);
        return NULL;
    }

    char *payload_b64 = base64url_encode((const unsigned char *)payload_json,
                                          strlen(payload_json));
    json_object_put(payload_obj);

    if (!payload_b64) {
        free(header_b64);
        return NULL;
    }

    /* Build signing input: header.payload */
    size_t signing_input_len = strlen(header_b64) + 1 + strlen(payload_b64) + 1;
    char *signing_input = malloc(signing_input_len);
    if (!signing_input) {
        free(header_b64);
        free(payload_b64);
        return NULL;
    }
    snprintf(signing_input, signing_input_len, "%s.%s", header_b64, payload_b64);

    /* Sign with HMAC-SHA256 */
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    unsigned char *result = HMAC(EVP_sha256(),
                                  client_secret, strlen(client_secret),
                                  (const unsigned char *)signing_input, strlen(signing_input),
                                  hmac_result, &hmac_len);

    if (!result) {
        free(header_b64);
        free(payload_b64);
        free(signing_input);
        return NULL;
    }

    /* Base64url encode signature */
    char *sig_b64 = base64url_encode(hmac_result, hmac_len);
    explicit_bzero(hmac_result, sizeof(hmac_result));

    if (!sig_b64) {
        free(header_b64);
        free(payload_b64);
        free(signing_input);
        return NULL;
    }

    /* Build final JWT: header.payload.signature */
    size_t jwt_len = strlen(signing_input) + 1 + strlen(sig_b64) + 1;
    char *jwt = malloc(jwt_len);
    if (!jwt) {
        free(header_b64);
        free(payload_b64);
        free(signing_input);
        free(sig_b64);
        return NULL;
    }
    snprintf(jwt, jwt_len, "%s.%s", signing_input, sig_b64);

    free(header_b64);
    free(payload_b64);
    free(signing_input);
    free(sig_b64);

    return jwt;
}

token_manager_t *token_manager_init(const token_manager_config_t *config)
{
    if (!config || !config->portal_url || !config->client_id) {
        return NULL;
    }

    token_manager_t *tm = calloc(1, sizeof(token_manager_t));
    if (!tm) return NULL;

    /* Copy configuration */
    tm->config.portal_url = strdup(config->portal_url);
    tm->config.client_id = strdup(config->client_id);
    if (config->client_secret) {
        tm->config.client_secret = strdup(config->client_secret);
    }
    if (config->ca_cert) {
        tm->config.ca_cert = strdup(config->ca_cert);
    }

    tm->config.timeout = config->timeout > 0 ? config->timeout : 10;
    tm->config.verify_ssl = config->verify_ssl;
    tm->config.rotate_refresh = config->rotate_refresh;
    tm->config.bind_ip = config->bind_ip;
    tm->config.bind_fingerprint = config->bind_fingerprint;

    /* Initialize curl */
    tm->curl = curl_easy_init();
    if (!tm->curl) {
        token_manager_destroy(tm);
        return NULL;
    }

    return tm;
}

void token_manager_destroy(token_manager_t *tm)
{
    if (!tm) return;

    if (tm->curl) {
        curl_easy_cleanup(tm->curl);
    }

    free(tm->config.portal_url);
    free(tm->config.client_id);
    secure_free_str(tm->config.client_secret);
    free(tm->config.ca_cert);

    explicit_bzero(tm, sizeof(*tm));
    free(tm);
}

void token_info_free(token_info_t *info)
{
    if (!info) return;

    secure_free_str(info->access_token);
    secure_free_str(info->refresh_token);
    free(info->token_type);
    free(info->scope);
    free(info->client_ip);
    free(info->fingerprint);
    free(info->user);

    explicit_bzero(info, sizeof(*info));
}

/* Parse token response JSON */
static int parse_token_response(const char *json_str, token_info_t *info)
{
    struct json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    struct json_object *obj;

    if (json_object_object_get_ex(root, "access_token", &obj)) {
        info->access_token = strdup(json_object_get_string(obj));
    }

    if (json_object_object_get_ex(root, "refresh_token", &obj)) {
        info->refresh_token = strdup(json_object_get_string(obj));
    }

    if (json_object_object_get_ex(root, "token_type", &obj)) {
        info->token_type = strdup(json_object_get_string(obj));
    }

    if (json_object_object_get_ex(root, "scope", &obj)) {
        info->scope = strdup(json_object_get_string(obj));
    }

    if (json_object_object_get_ex(root, "expires_in", &obj)) {
        info->expires_in = json_object_get_int(obj);
        info->expires_at = time(NULL) + info->expires_in;
    }

    info->issued_at = time(NULL);

    json_object_put(root);
    return 0;
}

/* Parse introspection response JSON */
static int parse_introspection_response(const char *json_str, token_info_t *info)
{
    struct json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    struct json_object *obj;

    if (json_object_object_get_ex(root, "active", &obj)) {
        info->active = json_object_get_boolean(obj);
    }

    if (json_object_object_get_ex(root, "username", &obj)) {
        info->user = strdup(json_object_get_string(obj));
    } else if (json_object_object_get_ex(root, "sub", &obj)) {
        info->user = strdup(json_object_get_string(obj));
    }

    if (json_object_object_get_ex(root, "scope", &obj)) {
        info->scope = strdup(json_object_get_string(obj));
    }

    if (json_object_object_get_ex(root, "exp", &obj)) {
        info->server_exp = (time_t)json_object_get_int64(obj);
        info->expires_at = info->server_exp;
        info->expires_in = (int)(info->server_exp - time(NULL));
        if (info->expires_in < 0) info->expires_in = 0;
    }

    /* Check for client_ip in token claims if bound */
    if (json_object_object_get_ex(root, "client_ip", &obj)) {
        info->client_ip = strdup(json_object_get_string(obj));
    }

    if (json_object_object_get_ex(root, "fingerprint", &obj)) {
        info->fingerprint = strdup(json_object_get_string(obj));
    }

    json_object_put(root);
    return 0;
}

int token_manager_refresh(token_manager_t *tm,
                          const char *refresh_token,
                          token_info_t *new_info)
{
    if (!tm || !refresh_token || !new_info) {
        return -1;
    }

    memset(new_info, 0, sizeof(*new_info));

    /* Build token endpoint URL */
    char url[512];
    int url_len = snprintf(url, sizeof(url), "%s/oauth2/token", tm->config.portal_url);
    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token refresh failed: URL too long");
        return -1;
    }

    /* URL-encode parameters */
    char *encoded_refresh = curl_easy_escape(tm->curl, refresh_token, 0);
    char *encoded_client_id = curl_easy_escape(tm->curl, tm->config.client_id, 0);

    if (!encoded_refresh || !encoded_client_id) {
        curl_free(encoded_refresh);
        curl_free(encoded_client_id);
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token refresh failed: URL encoding failed");
        return -1;
    }

    /* Build POST data */
    char post_data[4096];
    int len = snprintf(post_data, sizeof(post_data),
                       "grant_type=refresh_token&refresh_token=%s&client_id=%s",
                       encoded_refresh, encoded_client_id);

    curl_free(encoded_refresh);
    curl_free(encoded_client_id);

    if (len < 0 || (size_t)len >= sizeof(post_data)) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token refresh failed: POST data too long");
        return -1;
    }

    /* Use client_secret_jwt authentication (RFC 7523) */
    if (tm->config.client_secret) {
        char *client_jwt = generate_client_jwt(tm->config.client_id,
                                                tm->config.client_secret, url);
        if (!client_jwt) {
            explicit_bzero(post_data, sizeof(post_data));
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "Token refresh failed: JWT generation failed");
            return -1;
        }

        char *encoded_jwt = curl_easy_escape(tm->curl, client_jwt, 0);
        secure_free_str(client_jwt);

        if (!encoded_jwt) {
            explicit_bzero(post_data, sizeof(post_data));
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "Token refresh failed: URL encoding failed");
            return -1;
        }

        int add_len = snprintf(post_data + len, sizeof(post_data) - len,
                               "&client_assertion_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Aclient-assertion-type%%3Ajwt-bearer"
                               "&client_assertion=%s", encoded_jwt);
        curl_free(encoded_jwt);

        if (add_len < 0 || (size_t)add_len >= sizeof(post_data) - len) {
            explicit_bzero(post_data, sizeof(post_data));
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "Token refresh failed: POST data too long");
            return -1;
        }
        len += add_len;
    }

    /* Request rotation if configured */
    if (tm->config.rotate_refresh) {
        int add_len = snprintf(post_data + len, sizeof(post_data) - len,
                               "&rotate_refresh_token=1");
        if (add_len > 0) len += add_len;
    }

    /* Setup curl */
    response_buffer_t response = {0};
    curl_easy_reset(tm->curl);

    curl_easy_setopt(tm->curl, CURLOPT_URL, url);
    curl_easy_setopt(tm->curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(tm->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(tm->curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(tm->curl, CURLOPT_TIMEOUT, (long)tm->config.timeout);
    curl_easy_setopt(tm->curl, CURLOPT_SSL_VERIFYPEER, tm->config.verify_ssl ? 1L : 0L);
    curl_easy_setopt(tm->curl, CURLOPT_SSL_VERIFYHOST, tm->config.verify_ssl ? 2L : 0L);

    if (tm->config.ca_cert) {
        curl_easy_setopt(tm->curl, CURLOPT_CAINFO, tm->config.ca_cert);
    }

    /* Perform request */
    CURLcode res = curl_easy_perform(tm->curl);

    /* Clear post data containing secrets */
    explicit_bzero(post_data, sizeof(post_data));

    if (res != CURLE_OK) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token refresh failed: %s", curl_easy_strerror(res));
        free(response.data);
        return -1;
    }

    /* Check HTTP status */
    long http_code = 0;
    curl_easy_getinfo(tm->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token refresh failed: HTTP %ld", http_code);
        free(response.data);
        return -1;
    }

    /* Parse response */
    int ret = parse_token_response(response.data, new_info);
    free(response.data);

    if (ret != 0 || !new_info->access_token) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token refresh failed: invalid response");
        return -1;
    }

    return 0;
}

int token_manager_introspect(token_manager_t *tm,
                             const char *access_token,
                             token_info_t *info)
{
    if (!tm || !access_token || !info) {
        return -1;
    }

    memset(info, 0, sizeof(*info));

    /* Build introspection endpoint URL */
    char url[512];
    int url_len = snprintf(url, sizeof(url), "%s/oauth2/introspect", tm->config.portal_url);
    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token introspection failed: URL too long");
        return -1;
    }

    /* URL-encode parameters */
    char *encoded_token = curl_easy_escape(tm->curl, access_token, 0);
    char *encoded_client_id = curl_easy_escape(tm->curl, tm->config.client_id, 0);

    if (!encoded_token || !encoded_client_id) {
        curl_free(encoded_token);
        curl_free(encoded_client_id);
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token introspection failed: URL encoding failed");
        return -1;
    }

    /* Build POST data */
    char post_data[4096];
    int len = snprintf(post_data, sizeof(post_data),
                       "token=%s&client_id=%s",
                       encoded_token, encoded_client_id);

    curl_free(encoded_token);
    curl_free(encoded_client_id);

    if (len < 0 || (size_t)len >= sizeof(post_data)) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token introspection failed: POST data too long");
        return -1;
    }

    /* Use client_secret_jwt authentication (RFC 7523) */
    if (tm->config.client_secret) {
        char *client_jwt = generate_client_jwt(tm->config.client_id,
                                                tm->config.client_secret, url);
        if (!client_jwt) {
            explicit_bzero(post_data, sizeof(post_data));
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "Token introspection failed: JWT generation failed");
            return -1;
        }

        char *encoded_jwt = curl_easy_escape(tm->curl, client_jwt, 0);
        secure_free_str(client_jwt);

        if (!encoded_jwt) {
            explicit_bzero(post_data, sizeof(post_data));
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "Token introspection failed: URL encoding failed");
            return -1;
        }

        int add_len = snprintf(post_data + len, sizeof(post_data) - len,
                               "&client_assertion_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Aclient-assertion-type%%3Ajwt-bearer"
                               "&client_assertion=%s", encoded_jwt);
        curl_free(encoded_jwt);

        if (add_len < 0 || (size_t)add_len >= sizeof(post_data) - len) {
            explicit_bzero(post_data, sizeof(post_data));
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "Token introspection failed: POST data too long");
            return -1;
        }
        len += add_len;
    }

    /* Setup curl */
    response_buffer_t response = {0};
    curl_easy_reset(tm->curl);

    curl_easy_setopt(tm->curl, CURLOPT_URL, url);
    curl_easy_setopt(tm->curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(tm->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(tm->curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(tm->curl, CURLOPT_TIMEOUT, (long)tm->config.timeout);
    curl_easy_setopt(tm->curl, CURLOPT_SSL_VERIFYPEER, tm->config.verify_ssl ? 1L : 0L);
    curl_easy_setopt(tm->curl, CURLOPT_SSL_VERIFYHOST, tm->config.verify_ssl ? 2L : 0L);

    if (tm->config.ca_cert) {
        curl_easy_setopt(tm->curl, CURLOPT_CAINFO, tm->config.ca_cert);
    }

    /* Perform request */
    CURLcode res = curl_easy_perform(tm->curl);

    /* Clear post data containing secrets */
    explicit_bzero(post_data, sizeof(post_data));

    if (res != CURLE_OK) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token introspection failed: %s", curl_easy_strerror(res));
        free(response.data);
        return -1;
    }

    /* Check HTTP status */
    long http_code = 0;
    curl_easy_getinfo(tm->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token introspection failed: HTTP %ld", http_code);
        free(response.data);
        return -1;
    }

    /* Parse response */
    int ret = parse_introspection_response(response.data, info);
    free(response.data);

    if (ret != 0) {
        snprintf(tm->error_buf, sizeof(tm->error_buf),
                 "Token introspection failed: invalid response");
        return -1;
    }

    return 0;
}

bool token_manager_needs_refresh(const token_info_t *info, int threshold_sec)
{
    if (!info) return true;

    time_t now = time(NULL);

    /* Token already expired */
    if (info->expires_at > 0 && now >= info->expires_at) {
        return true;
    }

    /* Token about to expire */
    if (info->expires_at > 0 && (info->expires_at - now) <= threshold_sec) {
        return true;
    }

    return false;
}

bool token_manager_check_binding(token_manager_t *tm,
                                  const token_info_t *info,
                                  const char *client_ip,
                                  const char *fingerprint)
{
    if (!tm || !info) return false;

    /* If IP binding is enabled, check it */
    if (tm->config.bind_ip && info->client_ip && client_ip) {
        if (strcmp(info->client_ip, client_ip) != 0) {
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "IP binding mismatch: token bound to %s, request from %s",
                     info->client_ip, client_ip);
            return false;
        }
    }

    /* If fingerprint binding is enabled, check it */
    if (tm->config.bind_fingerprint && info->fingerprint && fingerprint) {
        if (strcmp(info->fingerprint, fingerprint) != 0) {
            snprintf(tm->error_buf, sizeof(tm->error_buf),
                     "Fingerprint binding mismatch");
            return false;
        }
    }

    return true;
}

const char *token_manager_error(token_manager_t *tm)
{
    return tm ? tm->error_buf : "NULL token manager";
}

int token_manager_load_file(const char *filepath, token_info_t *info)
{
    if (!filepath || !info) return -1;

    memset(info, 0, sizeof(*info));

    FILE *fp = fopen(filepath, "r");
    if (!fp) return -1;

    /* Read first character to detect format */
    int c = fgetc(fp);
    if (c == EOF) {
        fclose(fp);
        return -1;
    }
    ungetc(c, fp);

    if (c == '{') {
        /* JSON format */
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (fsize <= 0 || fsize > 1024 * 1024) {
            fclose(fp);
            return -1;
        }

        char *content = malloc(fsize + 1);
        if (!content) {
            fclose(fp);
            return -1;
        }

        if (fread(content, 1, fsize, fp) != (size_t)fsize) {
            free(content);
            fclose(fp);
            return -1;
        }
        content[fsize] = '\0';
        fclose(fp);

        /* Parse JSON */
        struct json_object *root = json_tokener_parse(content);
        explicit_bzero(content, fsize);
        free(content);

        if (!root) return -1;

        struct json_object *obj;

        if (json_object_object_get_ex(root, "access_token", &obj)) {
            info->access_token = strdup(json_object_get_string(obj));
        }

        if (json_object_object_get_ex(root, "refresh_token", &obj)) {
            info->refresh_token = strdup(json_object_get_string(obj));
        }

        if (json_object_object_get_ex(root, "expires_at", &obj)) {
            info->expires_at = (time_t)json_object_get_int64(obj);
            time_t now = time(NULL);
            info->expires_in = (info->expires_at > now) ?
                               (int)(info->expires_at - now) : 0;
        }

        if (json_object_object_get_ex(root, "enrolled_at", &obj)) {
            info->issued_at = (time_t)json_object_get_int64(obj);
        }

        json_object_put(root);
    } else {
        /* Legacy plain text format - single line with access_token */
        char line[8192];
        if (!fgets(line, sizeof(line), fp)) {
            fclose(fp);
            return -1;
        }
        fclose(fp);

        /* Remove trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0) return -1;

        info->access_token = strdup(line);
        explicit_bzero(line, sizeof(line));

        /* Legacy format doesn't have expiry info - assume valid */
        info->expires_at = 0;
        info->expires_in = 0;
    }

    return info->access_token ? 0 : -1;
}

int token_manager_save_file(const char *filepath, const token_info_t *info)
{
    if (!filepath || !info || !info->access_token) return -1;

    /* Build JSON object */
    struct json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "access_token",
                           json_object_new_string(info->access_token));

    if (info->refresh_token) {
        json_object_object_add(root, "refresh_token",
                               json_object_new_string(info->refresh_token));
    }

    if (info->expires_at > 0) {
        json_object_object_add(root, "expires_at",
                               json_object_new_int64((int64_t)info->expires_at));
    }

    if (info->issued_at > 0) {
        json_object_object_add(root, "enrolled_at",
                               json_object_new_int64((int64_t)info->issued_at));
    }

    /* Serialize JSON */
    const char *json_str = json_object_to_json_string_ext(root,
                                                          JSON_C_TO_STRING_PRETTY);
    if (!json_str) {
        json_object_put(root);
        return -1;
    }

    /* Write to temp file first, then rename (atomic) */
    char tmppath[PATH_MAX];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", filepath, (int)getpid());

    /* Set restrictive umask */
    mode_t old_umask = umask(077);

    FILE *fp = fopen(tmppath, "w");
    if (!fp) {
        umask(old_umask);
        json_object_put(root);
        return -1;
    }

    int ret = 0;
    if (fputs(json_str, fp) == EOF) {
        ret = -1;
    }

    fclose(fp);
    json_object_put(root);
    umask(old_umask);

    if (ret != 0) {
        unlink(tmppath);
        return -1;
    }

    /* Atomic rename */
    if (rename(tmppath, filepath) != 0) {
        unlink(tmppath);
        return -1;
    }

    return 0;
}
