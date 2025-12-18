/*
 * llng_client.c - HTTP client for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "llng_client.h"

/* TLS version constants for min_tls_version configuration */
#define TLS_VERSION_1_2 12
#define TLS_VERSION_1_3 13

/* Stack buffer size for HMAC signature message building */
#define SIGNATURE_STACK_BUFFER_SIZE 512

/* Security: Maximum user groups to prevent DoS via memory exhaustion */
#define MAX_USER_GROUPS 256

/* Security: Maximum base64 input size to prevent integer overflow (64KB) */
#define MAX_BASE64_INPUT_SIZE (64 * 1024)

/* Safe strdup from JSON - returns NULL if json string is NULL */
static inline char *safe_json_strdup(struct json_object *obj)
{
    const char *str = json_object_get_string(obj);
    return str ? strdup(str) : NULL;
}

/* Forward declaration for internal authorize function */
static int llng_authorize_user_internal(llng_client_t *client,
                                         const char *user,
                                         const char *host,
                                         const char *service,
                                         const llng_ssh_cert_info_t *ssh_cert,
                                         llng_response_t *response);

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
    char *signing_secret;  /* Optional HMAC secret for request signing */
    int min_tls_version;   /* Minimum TLS version: 12=1.2, 13=1.3 */
    char *cert_pin;        /* Certificate pin for CURLOPT_PINNEDPUBLICKEY */
};

/* Buffer for curl responses with exponential growth */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} response_buffer_t;

#define INITIAL_BUFFER_SIZE 4096

/*
 * Security: Maximum response size to prevent DoS via memory exhaustion
 * 256 KB should be more than enough for any legitimate LLNG API response
 * (typical responses are under 10 KB)
 */
#define MAX_RESPONSE_SIZE (256 * 1024)

/* Curl write callback with exponential buffer growth */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    response_buffer_t *buf = (response_buffer_t *)userp;

    /* Security: Check for integer overflow in size calculation */
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        return 0;  /* Overflow - abort transfer */
    }
    size_t realsize = size * nmemb;

    /* Security: Check maximum response size limit (fixes #48) */
    if (buf->size + realsize > MAX_RESPONSE_SIZE) {
        /* Response too large - return 0 to abort transfer */
        return 0;
    }

    /* Check if we need to grow the buffer */
    size_t needed = buf->size + realsize + 1;
    if (needed > buf->capacity) {
        /* Grow by 1.5x or to needed size, whichever is larger */
        size_t new_capacity = buf->capacity + (buf->capacity >> 1);
        if (new_capacity < needed) {
            new_capacity = needed;
        }
        /* Cap capacity at max response size */
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

/* Initialize response buffer */
static void init_buffer(response_buffer_t *buf)
{
    buf->data = malloc(INITIAL_BUFFER_SIZE);
    buf->size = 0;
    buf->capacity = INITIAL_BUFFER_SIZE;
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
    buf->capacity = 0;
}

/* Helper to duplicate string or NULL */
static char *strdup_or_null(const char *s)
{
    return s ? strdup(s) : NULL;
}

/*
 * Generate HMAC-SHA256 signature for request signing.
 * Message format: timestamp.method.path.body
 * Output: hex-encoded signature string (65 bytes including null terminator)
 */
static void generate_request_signature(const char *secret,
                                        long timestamp,
                                        const char *method,
                                        const char *path,
                                        const char *body,
                                        char *signature,
                                        size_t sig_size)
{
    if (!secret || !signature || sig_size < 65) {
        if (signature && sig_size > 0) signature[0] = '\0';
        return;
    }

    /* Build message: timestamp.method.path.body
     * Use stack allocation for typical message sizes to avoid malloc overhead.
     * Typical: timestamp(~10) + method(~4) + path(~50) + body(~200) < SIGNATURE_STACK_BUFFER_SIZE
     */
    char ts_str[32];
    snprintf(ts_str, sizeof(ts_str), "%ld", timestamp);

    size_t msg_len = strlen(ts_str) + 1 + strlen(method) + 1 +
                     strlen(path) + 1 + (body ? strlen(body) : 0);

    /* Use stack buffer for small messages, heap for large ones */
    char stack_message[SIGNATURE_STACK_BUFFER_SIZE];
    char *message;
    bool heap_allocated = false;

    if (msg_len < sizeof(stack_message)) {
        message = stack_message;
    } else {
        message = malloc(msg_len + 1);
        if (!message) {
            signature[0] = '\0';
            return;
        }
        heap_allocated = true;
    }

    snprintf(message, msg_len + 1, "%s.%s.%s.%s",
             ts_str, method, path, body ? body : "");

    /* Generate HMAC-SHA256 */
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    unsigned char *result = HMAC(EVP_sha256(), secret, strlen(secret),
                                  (unsigned char *)message, strlen(message),
                                  hmac, &hmac_len);

    /* Clear message buffer */
    explicit_bzero(message, msg_len + 1);
    if (heap_allocated) {
        free(message);
    }

    /* Check HMAC result */
    if (!result) {
        signature[0] = '\0';
        return;
    }

    /* Convert to hex string */
    for (unsigned int i = 0; i < hmac_len && (i * 2 + 2) < sig_size; i++) {
        snprintf(signature + (i * 2), 3, "%02x", hmac[i]);
    }

    /* Clear HMAC buffer */
    explicit_bzero(hmac, sizeof(hmac));
}

/*
 * Generate a unique nonce for replay protection.
 * Format: timestamp_ms-uuid
 * Uses OpenSSL RAND_bytes for cryptographically secure random generation.
 */
static void generate_nonce(char *nonce, size_t nonce_size)
{
    if (!nonce || nonce_size < 64) {
        if (nonce && nonce_size > 0) nonce[0] = '\0';
        return;
    }

    /* Get timestamp in milliseconds */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long timestamp_ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    /* Generate UUID v4 using OpenSSL RAND_bytes (CSPRNG) */
    unsigned char uuid[16];
    if (RAND_bytes(uuid, sizeof(uuid)) != 1) {
        /* RAND_bytes failed - this is a critical error, but use timestamp as fallback */
        snprintf(nonce, nonce_size, "%lld", timestamp_ms);
        return;
    }

    /* Set version (4) and variant bits */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    snprintf(nonce, nonce_size,
             "%lld-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             timestamp_ms,
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5],
             uuid[6], uuid[7],
             uuid[8], uuid[9],
             uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

/*
 * Add request signing headers if signing_secret is configured.
 * Adds X-Timestamp, X-Nonce, and X-Signature-256 headers.
 *
 * The nonce provides replay protection - server should reject
 * requests with previously seen nonces within a time window.
 */
static struct curl_slist *add_signing_headers(struct curl_slist *headers,
                                               const char *signing_secret,
                                               const char *method,
                                               const char *path,
                                               const char *body)
{
    if (!signing_secret) {
        return headers;
    }

    long timestamp = (long)time(NULL);

    /* Generate unique nonce */
    char nonce[80];
    generate_nonce(nonce, sizeof(nonce));

    /* Generate signature (includes nonce in message) */
    char signature[65];
    generate_request_signature(signing_secret, timestamp, method, path, body,
                               signature, sizeof(signature));

    /* Add headers */
    char ts_header[64];
    snprintf(ts_header, sizeof(ts_header), "X-Timestamp: %ld", timestamp);
    headers = curl_slist_append(headers, ts_header);

    char nonce_header[128];
    snprintf(nonce_header, sizeof(nonce_header), "X-Nonce: %s", nonce);
    headers = curl_slist_append(headers, nonce_header);

    char sig_header[128];
    snprintf(sig_header, sizeof(sig_header), "X-Signature-256: sha256=%s", signature);
    headers = curl_slist_append(headers, sig_header);

    return headers;
}

/*
 * Security: Validate certificate pin format (fixes #47)
 * Valid formats:
 * - sha256//base64hash (44 chars of base64 after sha256//)
 * - Path to DER or PEM file (starts with / or .)
 * Multiple pins can be separated by ';'
 * Returns 1 if valid, 0 if invalid
 */
static int validate_cert_pin_format(const char *pin)
{
    if (!pin || !*pin) {
        return 0;
    }

    /* Work on a copy to handle multiple pins */
    char *pin_copy = strdup(pin);
    if (!pin_copy) {
        return 0;
    }

    int valid = 1;
    char *saveptr = NULL;
    char *token = strtok_r(pin_copy, ";", &saveptr);

    while (token && valid) {
        /* Skip leading whitespace */
        while (*token == ' ') token++;

        /* Strip trailing whitespace */
        size_t token_len = strlen(token);
        while (token_len > 0 && token[token_len - 1] == ' ') {
            token[token_len - 1] = '\0';
            token_len--;
        }

        if (strncmp(token, "sha256//", 8) == 0) {
            /* SHA256 hash format: "sha256//" followed by base64 of 32 bytes
             * Standard base64 encoding of 32 bytes is 44 characters (with padding);
             * we also accept 43-character encodings when the trailing padding is omitted.
             */
            const char *hash = token + 8;
            size_t len = strlen(hash);
            /* Accept standard base64 length for 32 bytes (44 chars) and the
             * no-padding variant (43 chars). Only the standard base64 alphabet
             * (+ and /, not - or _) is allowed by the character check below.
             */
            if (len < 43 || len > 44) {
                valid = 0;
            } else {
                /* Validate base64 characters */
                for (size_t i = 0; i < len && valid; i++) {
                    char c = hash[i];
                    if (!((c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') ||
                          c == '+' || c == '/' || c == '=')) {
                        valid = 0;
                    }
                }
            }
        } else if (token[0] == '/' || token[0] == '.') {
            /* File path - check if it looks like a valid path */
            /* Basic check: not empty after prefix, no control characters */
            if (strlen(token) < 2) {
                valid = 0;
            } else {
                for (const char *p = token; *p && valid; p++) {
                    if ((unsigned char)*p < 32) {
                        valid = 0;
                    }
                }
            }
        } else {
            /* Unknown format */
            valid = 0;
        }

        token = strtok_r(NULL, ";", &saveptr);
    }

    free(pin_copy);
    return valid;
}

/* Base64 encode for Basic auth */
static char *base64_encode(const char *input, size_t len)
{
    /* Security: Validate input parameters */
    if (!input || len == 0) return NULL;

    /* Security: Prevent integer overflow and excessive allocation */
    if (len > MAX_BASE64_INPUT_SIZE) return NULL;

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
    client->signing_secret = strdup_or_null(config->signing_secret);
    client->min_tls_version = config->min_tls_version > 0 ? config->min_tls_version : TLS_VERSION_1_3;

    /* Security: Validate certificate pin format before use (fixes #47) */
    if (config->cert_pin) {
        if (!validate_cert_pin_format(config->cert_pin)) {
            snprintf(client->error, sizeof(client->error),
                     "Invalid certificate pin format. Expected sha256//base64 or file path");
            llng_client_destroy(client);
            return NULL;
        }
        client->cert_pin = strdup(config->cert_pin);
    }

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
    secure_free(client->signing_secret);
    free(client->server_group);
    free(client->ca_cert);
    free(client->cert_pin);
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

    /* Set minimum TLS version (default: TLS 1.3) */
    long ssl_version;
    switch (client->min_tls_version) {
        case TLS_VERSION_1_2:
            ssl_version = CURL_SSLVERSION_TLSv1_2;
            break;
        case TLS_VERSION_1_3:
        default:
            ssl_version = CURL_SSLVERSION_TLSv1_3;
            break;
    }
    curl_easy_setopt(client->curl, CURLOPT_SSLVERSION, ssl_version);

    /* Certificate pinning if configured */
    if (client->cert_pin) {
        /*
         * CURLOPT_PINNEDPUBLICKEY accepts formats:
         * - sha256//base64hash (recommended)
         * - Path to DER or PEM file
         * Multiple pins can be separated by ';'
         */
        curl_easy_setopt(client->curl, CURLOPT_PINNEDPUBLICKEY, client->cert_pin);
    }

    /* Performance: Enable TCP keep-alive for connection reuse */
    curl_easy_setopt(client->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(client->curl, CURLOPT_TCP_KEEPIDLE, 120L);
    curl_easy_setopt(client->curl, CURLOPT_TCP_KEEPINTVL, 60L);

    /* Performance: Accept compressed responses */
    curl_easy_setopt(client->curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");
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

    /* Add request signing headers if configured */
    headers = add_signing_headers(headers, client->signing_secret,
                                   "POST", "/pam/verify", req_body);

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

    /* Security: Validate required fields are present and have correct type */
    if (!json_object_object_get_ex(json, "valid", &val)) {
        snprintf(client->error, sizeof(client->error),
                 "Missing required 'valid' field in response");
        json_object_put(json);
        return -1;
    }
    if (!json_object_is_type(val, json_type_boolean)) {
        snprintf(client->error, sizeof(client->error),
                 "Invalid 'valid' field type in response (expected boolean)");
        json_object_put(json);
        return -1;
    }
    response->active = json_object_get_boolean(val);

    if (!json_object_object_get_ex(json, "user", &val)) {
        snprintf(client->error, sizeof(client->error),
                 "Missing required 'user' field in response");
        json_object_put(json);
        return -1;
    }
    const char *user_str = json_object_get_string(val);
    if (!user_str) {
        snprintf(client->error, sizeof(client->error),
                 "Invalid 'user' field type in response");
        json_object_put(json);
        return -1;
    }
    response->user = strdup(user_str);
    if (!response->user) {
        snprintf(client->error, sizeof(client->error),
                 "Out of memory copying 'user' field");
        json_object_put(json);
        return -1;
    }

    if (json_object_object_get_ex(json, "error", &val)) {
        response->reason = safe_json_strdup(val);
    }

    if (json_object_object_get_ex(json, "groups", &val)) {
        if (json_object_is_type(val, json_type_array)) {
            size_t count = json_object_array_length(val);
            /* Security: Limit groups to prevent DoS via memory exhaustion */
            if (count > MAX_USER_GROUPS) {
                count = MAX_USER_GROUPS;
            }
            response->groups = calloc(count + 1, sizeof(char *));
            if (response->groups) {
                response->groups_count = count;
                for (size_t i = 0; i < count; i++) {
                    struct json_object *g = json_object_array_get_idx(val, i);
                    if (g) {
                        response->groups[i] = safe_json_strdup(g);
                    }
                }
            }
        }
    }

    /* User attributes for account creation (from attrs object) */
    struct json_object *attrs_obj;
    if (json_object_object_get_ex(json, "attrs", &attrs_obj)) {
        if (json_object_is_type(attrs_obj, json_type_object)) {
            if (json_object_object_get_ex(attrs_obj, "gecos", &val)) {
                response->gecos = safe_json_strdup(val);
            }
            if (json_object_object_get_ex(attrs_obj, "shell", &val)) {
                response->shell = safe_json_strdup(val);
            }
            if (json_object_object_get_ex(attrs_obj, "home", &val)) {
                response->home = safe_json_strdup(val);
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
        response->user = safe_json_strdup(val);
    }

    if (json_object_object_get_ex(json, "scope", &val)) {
        response->scope = safe_json_strdup(val);
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
    /* Delegate to internal function without SSH certificate info */
    return llng_authorize_user_internal(client, user, host, service, NULL, response);
}

/*
 * Internal helper for authorize with optional SSH cert info
 */
static int llng_authorize_user_internal(llng_client_t *client,
                                         const char *user,
                                         const char *host,
                                         const char *service,
                                         const llng_ssh_cert_info_t *ssh_cert,
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

    /* Add SSH certificate info if provided */
    if (ssh_cert && ssh_cert->valid) {
        struct json_object *cert_json = json_object_new_object();
        if (ssh_cert->key_id) {
            json_object_object_add(cert_json, "key_id",
                                   json_object_new_string(ssh_cert->key_id));
        }
        if (ssh_cert->serial) {
            json_object_object_add(cert_json, "serial",
                                   json_object_new_string(ssh_cert->serial));
        }
        if (ssh_cert->principals) {
            json_object_object_add(cert_json, "principals",
                                   json_object_new_string(ssh_cert->principals));
        }
        if (ssh_cert->ca_fingerprint) {
            json_object_object_add(cert_json, "ca_fingerprint",
                                   json_object_new_string(ssh_cert->ca_fingerprint));
        }
        json_object_object_add(req_json, "ssh_cert", cert_json);
    }

    const char *req_body = json_object_to_json_string(req_json);

    /* Build headers with Bearer token */
    struct curl_slist *headers = NULL;
    char auth_header[4200];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
             client->server_token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Add request signing headers if configured */
    headers = add_signing_headers(headers, client->signing_secret,
                                   "POST", "/pam/authorize", req_body);

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

    /* Security: Validate required fields are present and have correct type */
    if (!json_object_object_get_ex(json, "authorized", &val)) {
        snprintf(client->error, sizeof(client->error),
                 "Missing required 'authorized' field in response");
        json_object_put(json);
        return -1;
    }
    if (!json_object_is_type(val, json_type_boolean)) {
        snprintf(client->error, sizeof(client->error),
                 "Invalid 'authorized' field type in response (expected boolean)");
        json_object_put(json);
        return -1;
    }
    response->authorized = json_object_get_boolean(val);

    if (!json_object_object_get_ex(json, "user", &val)) {
        snprintf(client->error, sizeof(client->error),
                 "Missing required 'user' field in response");
        json_object_put(json);
        return -1;
    }
    const char *authz_user_str = json_object_get_string(val);
    if (!authz_user_str) {
        snprintf(client->error, sizeof(client->error),
                 "Invalid 'user' field type in response");
        json_object_put(json);
        return -1;
    }
    response->user = strdup(authz_user_str);
    if (!response->user) {
        snprintf(client->error, sizeof(client->error),
                 "Out of memory copying 'user' field");
        json_object_put(json);
        return -1;
    }

    if (json_object_object_get_ex(json, "reason", &val)) {
        response->reason = safe_json_strdup(val);
    }

    if (json_object_object_get_ex(json, "groups", &val)) {
        if (json_object_is_type(val, json_type_array)) {
            size_t count = json_object_array_length(val);
            /* Security: Limit groups to prevent DoS via memory exhaustion */
            if (count > MAX_USER_GROUPS) {
                count = MAX_USER_GROUPS;
            }
            response->groups = calloc(count + 1, sizeof(char *));
            if (response->groups) {
                response->groups_count = count;
                for (size_t i = 0; i < count; i++) {
                    struct json_object *g = json_object_array_get_idx(val, i);
                    if (g) {
                        response->groups[i] = safe_json_strdup(g);
                    }
                }
            }
        }
    }

    /* Parse permissions object */
    struct json_object *perms_obj;
    if (json_object_object_get_ex(json, "permissions", &perms_obj)) {
        if (json_object_is_type(perms_obj, json_type_object)) {
            response->has_permissions = true;
            if (json_object_object_get_ex(perms_obj, "sudo_allowed", &val)) {
                response->permissions.sudo_allowed = json_object_get_boolean(val);
            }
            if (json_object_object_get_ex(perms_obj, "sudo_nopasswd", &val)) {
                response->permissions.sudo_nopasswd = json_object_get_boolean(val);
            }
        }
    }

    /* Parse offline settings object */
    struct json_object *offline_obj;
    if (json_object_object_get_ex(json, "offline", &offline_obj)) {
        if (json_object_is_type(offline_obj, json_type_object)) {
            response->has_offline = true;
            if (json_object_object_get_ex(offline_obj, "enabled", &val)) {
                response->offline.enabled = json_object_get_boolean(val);
            }
            if (json_object_object_get_ex(offline_obj, "ttl", &val)) {
                response->offline.ttl = json_object_get_int(val);
            }
        }
    }

    json_object_put(json);
    return 0;
}

int llng_authorize_user_with_cert(llng_client_t *client,
                                   const char *user,
                                   const char *host,
                                   const char *service,
                                   const llng_ssh_cert_info_t *ssh_cert,
                                   llng_response_t *response)
{
    return llng_authorize_user_internal(client, user, host, service, ssh_cert, response);
}

void llng_ssh_cert_info_free(llng_ssh_cert_info_t *cert_info)
{
    if (!cert_info) return;
    free(cert_info->key_id);
    free(cert_info->serial);
    free(cert_info->principals);
    free(cert_info->ca_fingerprint);
    memset(cert_info, 0, sizeof(*cert_info));
}

void llng_response_init(llng_response_t *response)
{
    if (!response) return;
    memset(response, 0, sizeof(*response));
}

void llng_response_free(llng_response_t *response)
{
    if (!response) return;

    free(response->user);
    free(response->reason);
    free(response->scope);
    free(response->gecos);
    free(response->shell);
    free(response->home);

    if (response->groups) {
        for (size_t i = 0; i < response->groups_count; i++) {
            free(response->groups[i]);
        }
        free(response->groups);
    }

    memset(response, 0, sizeof(*response));
}
