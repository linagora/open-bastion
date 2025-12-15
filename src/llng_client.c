/*
 * llng_client.c - HTTP client for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include "llng_client.h"

/* Thread-safe curl initialization */
static pthread_once_t curl_init_once = PTHREAD_ONCE_INIT;
static void curl_global_init_once(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

/* Client structure */
struct llng_client {
    CURL *curl;
    char *portal_url;
    char *client_id;
    char *client_secret;
    char *server_token;
    char *server_group;
    char error[256];
    int timeout;
    bool verify_ssl;
    char *ca_cert;
};

/* Buffer for curl responses */
typedef struct {
    char *data;
    size_t size;
} response_buffer_t;

/* Curl write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    response_buffer_t *buf = (response_buffer_t *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';

    return realsize;
}

/* Initialize response buffer */
static void init_buffer(response_buffer_t *buf)
{
    buf->data = malloc(1);
    buf->size = 0;
    if (buf->data) {
        buf->data[0] = '\0';
    }
}

/* Free response buffer */
static void free_buffer(response_buffer_t *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
}

/* Helper to duplicate string or NULL */
static char *strdup_or_null(const char *s)
{
    return s ? strdup(s) : NULL;
}

/* Base64 encode for Basic auth */
static char *base64_encode(const char *input, size_t len)
{
    static const char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t output_len = 4 * ((len + 2) / 3);
    char *output = malloc(output_len + 1);
    if (!output) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t octet_a = i < len ? (unsigned char)input[i] : 0;
        uint32_t octet_b = i + 1 < len ? (unsigned char)input[i + 1] : 0;
        uint32_t octet_c = i + 2 < len ? (unsigned char)input[i + 2] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j] = b64_table[(triple >> 18) & 0x3F];
        output[j + 1] = b64_table[(triple >> 12) & 0x3F];
        output[j + 2] = (i + 1 < len) ? b64_table[(triple >> 6) & 0x3F] : '=';
        output[j + 3] = (i + 2 < len) ? b64_table[triple & 0x3F] : '=';
    }
    output[output_len] = '\0';
    return output;
}

llng_client_t *llng_client_init(const llng_client_config_t *config)
{
    if (!config || !config->portal_url) {
        return NULL;
    }

    llng_client_t *client = calloc(1, sizeof(llng_client_t));
    if (!client) {
        return NULL;
    }

    /* Thread-safe curl initialization */
    pthread_once(&curl_init_once, curl_global_init_once);

    client->curl = curl_easy_init();
    if (!client->curl) {
        free(client);
        return NULL;
    }

    client->portal_url = strdup(config->portal_url);
    client->client_id = strdup_or_null(config->client_id);
    client->client_secret = strdup_or_null(config->client_secret);
    client->server_token = strdup_or_null(config->server_token);
    client->server_group = strdup_or_null(config->server_group);
    client->timeout = config->timeout > 0 ? config->timeout : 10;
    client->verify_ssl = config->verify_ssl;
    client->ca_cert = strdup_or_null(config->ca_cert);

    return client;
}

/* Secure free: zero memory before freeing */
static void secure_free(char *ptr)
{
    if (ptr) {
        explicit_bzero(ptr, strlen(ptr));
        free(ptr);
    }
}

void llng_client_destroy(llng_client_t *client)
{
    if (!client) return;

    if (client->curl) {
        curl_easy_cleanup(client->curl);
    }
    free(client->portal_url);
    free(client->client_id);
    /* Securely erase secrets before freeing */
    secure_free(client->client_secret);
    secure_free(client->server_token);
    free(client->server_group);
    free(client->ca_cert);
    explicit_bzero(client->error, sizeof(client->error));
    free(client);
}

const char *llng_client_error(llng_client_t *client)
{
    return client ? client->error : "No client";
}

/* Setup curl common options */
static void setup_curl(llng_client_t *client)
{
    curl_easy_reset(client->curl);
    curl_easy_setopt(client->curl, CURLOPT_TIMEOUT, (long)client->timeout);
    curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION, write_callback);

    if (!client->verify_ssl) {
        curl_easy_setopt(client->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(client->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (client->ca_cert) {
        curl_easy_setopt(client->curl, CURLOPT_CAINFO, client->ca_cert);
    }
}

int llng_verify_token(llng_client_t *client,
                      const char *user_token,
                      llng_response_t *response)
{
    if (!client || !user_token || !response) {
        if (client) snprintf(client->error, sizeof(client->error), "Invalid parameters");
        return -1;
    }

    if (!client->server_token) {
        snprintf(client->error, sizeof(client->error),
                 "No server token configured. Server must be enrolled first.");
        return -1;
    }

    memset(response, 0, sizeof(*response));
    setup_curl(client);

    /* Build URL */
    char url[1024];
    snprintf(url, sizeof(url), "%s/pam/verify", client->portal_url);

    /* Build JSON request body */
    struct json_object *req_json = json_object_new_object();
    json_object_object_add(req_json, "token", json_object_new_string(user_token));

    const char *req_body = json_object_to_json_string(req_json);

    /* Build headers with Bearer token (server authentication) */
    struct curl_slist *headers = NULL;
    char auth_header[4200];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
             client->server_token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    response_buffer_t buf;
    init_buffer(&buf);

    curl_easy_setopt(client->curl, CURLOPT_URL, url);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, req_body);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(client->curl);

    json_object_put(req_json);
    curl_slist_free_all(headers);
    explicit_bzero(auth_header, sizeof(auth_header));

    if (res != CURLE_OK) {
        snprintf(client->error, sizeof(client->error),
                 "Curl error: %s", curl_easy_strerror(res));
        free_buffer(&buf);
        return -1;
    }

    long http_code;
    curl_easy_getinfo(client->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code == 401) {
        snprintf(client->error, sizeof(client->error),
                 "Server token invalid or expired. Re-enrollment required.");
        free_buffer(&buf);
        return -1;
    }

    if (http_code == 403) {
        snprintf(client->error, sizeof(client->error),
                 "Server not enrolled. Run enrollment first.");
        free_buffer(&buf);
        return -1;
    }

    if (http_code != 200) {
        snprintf(client->error, sizeof(client->error),
                 "HTTP error: %ld", http_code);
        free_buffer(&buf);
        return -1;
    }

    /* Parse JSON response */
    struct json_object *json = json_tokener_parse(buf.data);
    free_buffer(&buf);

    if (!json) {
        snprintf(client->error, sizeof(client->error), "Invalid JSON response");
        return -1;
    }

    struct json_object *val;

    /* Check 'valid' field (maps to 'active' for compatibility) */
    if (json_object_object_get_ex(json, "valid", &val)) {
        response->active = json_object_get_boolean(val);
    }

    if (json_object_object_get_ex(json, "user", &val)) {
        response->user = strdup(json_object_get_string(val));
    }

    if (json_object_object_get_ex(json, "error", &val)) {
        response->reason = strdup(json_object_get_string(val));
    }

    if (json_object_object_get_ex(json, "groups", &val)) {
        if (json_object_is_type(val, json_type_array)) {
            size_t count = json_object_array_length(val);
            response->groups = calloc(count + 1, sizeof(char *));
            if (response->groups) {
                response->groups_count = count;
                for (size_t i = 0; i < count; i++) {
                    struct json_object *g = json_object_array_get_idx(val, i);
                    response->groups[i] = strdup(json_object_get_string(g));
                }
            }
        }
    }

    json_object_put(json);
    return 0;
}

int llng_introspect_token(llng_client_t *client,
                          const char *token,
                          llng_response_t *response)
{
    if (!client || !token || !response) {
        if (client) snprintf(client->error, sizeof(client->error), "Invalid parameters");
        return -1;
    }

    memset(response, 0, sizeof(*response));
    setup_curl(client);

    /* Build URL */
    char url[1024];
    snprintf(url, sizeof(url), "%s/oauth2/introspect", client->portal_url);

    /* Build POST data */
    char *escaped_token = curl_easy_escape(client->curl, token, 0);
    char postdata[4096];
    snprintf(postdata, sizeof(postdata), "token=%s", escaped_token);
    curl_free(escaped_token);

    /* Build Basic auth header */
    struct curl_slist *headers = NULL;
    if (client->client_id && client->client_secret) {
        char auth_str[512];
        snprintf(auth_str, sizeof(auth_str), "%s:%s",
                 client->client_id, client->client_secret);
        char *b64 = base64_encode(auth_str, strlen(auth_str));
        if (b64) {
            char auth_header[600];
            snprintf(auth_header, sizeof(auth_header), "Authorization: Basic %s", b64);
            headers = curl_slist_append(headers, auth_header);
            free(b64);
        }
    }
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

    response_buffer_t buf;
    init_buffer(&buf);

    curl_easy_setopt(client->curl, CURLOPT_URL, url);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, postdata);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(client->curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        snprintf(client->error, sizeof(client->error),
                 "Curl error: %s", curl_easy_strerror(res));
        free_buffer(&buf);
        return -1;
    }

    long http_code;
    curl_easy_getinfo(client->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        snprintf(client->error, sizeof(client->error),
                 "HTTP error: %ld", http_code);
        free_buffer(&buf);
        return -1;
    }

    /* Parse JSON response */
    struct json_object *json = json_tokener_parse(buf.data);
    free_buffer(&buf);

    if (!json) {
        snprintf(client->error, sizeof(client->error), "Invalid JSON response");
        return -1;
    }

    struct json_object *val;

    if (json_object_object_get_ex(json, "active", &val)) {
        response->active = json_object_get_boolean(val);
    }

    if (json_object_object_get_ex(json, "sub", &val)) {
        response->user = strdup(json_object_get_string(val));
    }

    if (json_object_object_get_ex(json, "scope", &val)) {
        response->scope = strdup(json_object_get_string(val));
    }

    if (json_object_object_get_ex(json, "exp", &val)) {
        /* Calculate expires_in from exp timestamp */
        time_t exp = (time_t)json_object_get_int64(val);
        time_t now = time(NULL);
        response->expires_in = (int)(exp - now);
        if (response->expires_in < 0) response->expires_in = 0;
    }

    json_object_put(json);
    return 0;
}

int llng_authorize_user(llng_client_t *client,
                        const char *user,
                        const char *host,
                        const char *service,
                        llng_response_t *response)
{
    if (!client || !user || !response) {
        if (client) snprintf(client->error, sizeof(client->error), "Invalid parameters");
        return -1;
    }

    if (!client->server_token) {
        snprintf(client->error, sizeof(client->error),
                 "No server token configured. Server must be enrolled first.");
        return -1;
    }

    memset(response, 0, sizeof(*response));
    setup_curl(client);

    /* Build URL */
    char url[1024];
    snprintf(url, sizeof(url), "%s/pam/authorize", client->portal_url);

    /* Build JSON request body */
    struct json_object *req_json = json_object_new_object();
    json_object_object_add(req_json, "user", json_object_new_string(user));
    if (host) {
        json_object_object_add(req_json, "host", json_object_new_string(host));
    }
    if (service) {
        json_object_object_add(req_json, "service", json_object_new_string(service));
    }
    if (client->server_group) {
        json_object_object_add(req_json, "server_group",
                               json_object_new_string(client->server_group));
    }

    const char *req_body = json_object_to_json_string(req_json);

    /* Build headers with Bearer token */
    struct curl_slist *headers = NULL;
    char auth_header[4200];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
             client->server_token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    response_buffer_t buf;
    init_buffer(&buf);

    curl_easy_setopt(client->curl, CURLOPT_URL, url);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, req_body);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &buf);

    CURLcode res = curl_easy_perform(client->curl);

    json_object_put(req_json);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        snprintf(client->error, sizeof(client->error),
                 "Curl error: %s", curl_easy_strerror(res));
        free_buffer(&buf);
        return -1;
    }

    long http_code;
    curl_easy_getinfo(client->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code == 401) {
        snprintf(client->error, sizeof(client->error),
                 "Server token invalid or expired. Re-enrollment required.");
        free_buffer(&buf);
        return -1;
    }

    if (http_code == 403) {
        snprintf(client->error, sizeof(client->error),
                 "Server not enrolled. Run enrollment first.");
        free_buffer(&buf);
        return -1;
    }

    if (http_code != 200) {
        snprintf(client->error, sizeof(client->error),
                 "HTTP error: %ld", http_code);
        free_buffer(&buf);
        return -1;
    }

    /* Parse JSON response */
    struct json_object *json = json_tokener_parse(buf.data);
    free_buffer(&buf);

    if (!json) {
        snprintf(client->error, sizeof(client->error), "Invalid JSON response");
        return -1;
    }

    struct json_object *val;

    if (json_object_object_get_ex(json, "authorized", &val)) {
        response->authorized = json_object_get_boolean(val);
    }

    if (json_object_object_get_ex(json, "user", &val)) {
        response->user = strdup(json_object_get_string(val));
    }

    if (json_object_object_get_ex(json, "reason", &val)) {
        response->reason = strdup(json_object_get_string(val));
    }

    if (json_object_object_get_ex(json, "groups", &val)) {
        if (json_object_is_type(val, json_type_array)) {
            size_t count = json_object_array_length(val);
            response->groups = calloc(count + 1, sizeof(char *));
            if (response->groups) {
                response->groups_count = count;
                for (size_t i = 0; i < count; i++) {
                    struct json_object *g = json_object_array_get_idx(val, i);
                    response->groups[i] = strdup(json_object_get_string(g));
                }
            }
        }
    }

    json_object_put(json);
    return 0;
}

void llng_response_free(llng_response_t *response)
{
    if (!response) return;

    free(response->user);
    free(response->reason);
    free(response->scope);

    if (response->groups) {
        for (size_t i = 0; i < response->groups_count; i++) {
            free(response->groups[i]);
        }
        free(response->groups);
    }

    memset(response, 0, sizeof(*response));
}
