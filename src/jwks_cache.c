/*
 * jwks_cache.c - JWKS (JSON Web Key Set) cache for JWT verification
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

#include "jwks_cache.h"

/* Maximum response size from JWKS endpoint */
#define MAX_JWKS_RESPONSE_SIZE (64 * 1024)

/* Cached key entry */
typedef struct {
    char *kid;           /* Key ID */
    EVP_PKEY *key;       /* Public key */
} jwks_key_entry_t;

/* JWKS cache structure */
struct jwks_cache {
    char *jwks_url;
    char *cache_file;
    int refresh_interval;
    int timeout;
    bool verify_ssl;
    char *ca_cert;

    jwks_key_entry_t keys[JWKS_MAX_KEYS];
    size_t key_count;
    time_t last_refresh;
    bool initialized;
};

/* CURL write callback data */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} curl_buffer_t;

/* CURL write callback */
static size_t jwks_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    curl_buffer_t *buf = (curl_buffer_t *)userp;
    size_t realsize = size * nmemb;

    /* Security: Limit response size */
    if (buf->size + realsize > MAX_JWKS_RESPONSE_SIZE) {
        return 0;  /* Signal error to curl */
    }

    /* Grow buffer if needed */
    if (buf->size + realsize + 1 > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        if (new_capacity < buf->size + realsize + 1) {
            new_capacity = buf->size + realsize + 1;
        }
        if (new_capacity > MAX_JWKS_RESPONSE_SIZE) {
            new_capacity = MAX_JWKS_RESPONSE_SIZE;
        }
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) return 0;
        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    memcpy(buf->data + buf->size, contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';

    return realsize;
}

/* Base64url decode for JWK parameters */
static unsigned char *base64url_decode_jwk(const char *input, size_t *out_len)
{
    if (!input || !out_len) return NULL;

    size_t input_len = strlen(input);
    if (input_len == 0 || input_len > 2048) return NULL;

    static const unsigned char b64_table[256] = {
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
        ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
        ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
        ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
        ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
        ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61, ['-'] = 62, ['_'] = 63,
    };

    size_t out_size = ((input_len + 3) / 4) * 3;
    unsigned char *out = malloc(out_size + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_len; i += 4) {
        unsigned int val = 0;
        size_t k;
        for (k = 0; k < 4 && i + k < input_len; k++) {
            unsigned char c = (unsigned char)input[i + k];
            if (c > 127) {
                free(out);
                return NULL;
            }
            val = (val << 6) | b64_table[c];
        }
        for (; k < 4; k++) {
            val <<= 6;
        }

        if (j < out_size) out[j++] = (val >> 16) & 0xff;
        if (j < out_size && i + 2 <= input_len) out[j++] = (val >> 8) & 0xff;
        if (j < out_size && i + 3 <= input_len) out[j++] = val & 0xff;
    }

    /* Adjust for base64url without padding */
    size_t mod = input_len % 4;
    if (mod == 2) j -= 2;
    else if (mod == 3) j -= 1;

    out[j] = '\0';
    *out_len = j;
    return out;
}

/* Parse a single RSA JWK and create EVP_PKEY */
static EVP_PKEY *parse_rsa_jwk(struct json_object *jwk)
{
    struct json_object *val;
    const char *n_b64 = NULL;
    const char *e_b64 = NULL;

    /* Get n (modulus) */
    if (!json_object_object_get_ex(jwk, "n", &val)) return NULL;
    n_b64 = json_object_get_string(val);
    if (!n_b64) return NULL;

    /* Get e (exponent) */
    if (!json_object_object_get_ex(jwk, "e", &val)) return NULL;
    e_b64 = json_object_get_string(val);
    if (!e_b64) return NULL;

    /* Decode n and e */
    size_t n_len, e_len;
    unsigned char *n_bytes = base64url_decode_jwk(n_b64, &n_len);
    unsigned char *e_bytes = base64url_decode_jwk(e_b64, &e_len);

    if (!n_bytes || !e_bytes) {
        free(n_bytes);
        free(e_bytes);
        return NULL;
    }

    /* Create BIGNUM for n and e */
    BIGNUM *bn_n = BN_bin2bn(n_bytes, n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e_bytes, e_len, NULL);

    explicit_bzero(n_bytes, n_len);
    explicit_bzero(e_bytes, e_len);
    free(n_bytes);
    free(e_bytes);

    if (!bn_n || !bn_e) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    /* Create RSA key */
    EVP_PKEY *pkey = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0+ */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e)) {
        OSSL_PARAM_BLD_free(bld);
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    if (!params) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        OSSL_PARAM_free(params);
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    if (EVP_PKEY_fromdata_init(ctx) > 0 &&
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0) {
        /* Success */
    } else {
        pkey = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    BN_free(bn_n);
    BN_free(bn_e);

#else
    /* OpenSSL 1.1.x */
    RSA *rsa = RSA_new();
    if (!rsa) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    if (RSA_set0_key(rsa, bn_n, bn_e, NULL) != 1) {
        RSA_free(rsa);
        return NULL;
    }
    /* bn_n and bn_e are now owned by rsa */

    pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa);
        return NULL;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return NULL;
    }
    /* rsa is now owned by pkey */
#endif

    return pkey;
}

/* Parse JWKS JSON and populate keys array */
static int parse_jwks(jwks_cache_t *cache, const char *jwks_json)
{
    if (!cache || !jwks_json) return -1;

    struct json_object *json = json_tokener_parse(jwks_json);
    if (!json) return -1;

    struct json_object *keys_array;
    if (!json_object_object_get_ex(json, "keys", &keys_array) ||
        !json_object_is_type(keys_array, json_type_array)) {
        json_object_put(json);
        return -1;
    }

    /* Clear existing keys */
    for (size_t i = 0; i < cache->key_count; i++) {
        free(cache->keys[i].kid);
        EVP_PKEY_free(cache->keys[i].key);
        cache->keys[i].kid = NULL;
        cache->keys[i].key = NULL;
    }
    cache->key_count = 0;

    /* Parse each key */
    size_t count = json_object_array_length(keys_array);
    for (size_t i = 0; i < count && cache->key_count < JWKS_MAX_KEYS; i++) {
        struct json_object *jwk = json_object_array_get_idx(keys_array, i);
        if (!jwk) continue;

        struct json_object *val;

        /* Check key type is RSA */
        if (!json_object_object_get_ex(jwk, "kty", &val)) continue;
        const char *kty = json_object_get_string(val);
        if (!kty || strcmp(kty, "RSA") != 0) continue;

        /* Check use is sig (signature) or not specified */
        if (json_object_object_get_ex(jwk, "use", &val)) {
            const char *use = json_object_get_string(val);
            if (use && strcmp(use, "sig") != 0) continue;
        }

        /* Get key ID */
        char *kid = NULL;
        if (json_object_object_get_ex(jwk, "kid", &val)) {
            const char *kid_str = json_object_get_string(val);
            if (kid_str) {
                kid = strdup(kid_str);
            }
        }

        /* Parse RSA key */
        EVP_PKEY *key = parse_rsa_jwk(jwk);
        if (key) {
            cache->keys[cache->key_count].kid = kid;
            cache->keys[cache->key_count].key = key;
            cache->key_count++;
        } else {
            free(kid);
        }
    }

    json_object_put(json);
    cache->last_refresh = time(NULL);
    cache->initialized = true;

    return cache->key_count > 0 ? 0 : -1;
}

/* Fetch JWKS from URL */
static int fetch_jwks(jwks_cache_t *cache)
{
    if (!cache || !cache->jwks_url) return -1;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    curl_buffer_t buf = {
        .data = malloc(4096),
        .size = 0,
        .capacity = 4096
    };

    if (!buf.data) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, cache->jwks_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jwks_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, cache->timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, cache->timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);

    if (!cache->verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        /* Log warning only once per process to avoid log spam */
        static int ssl_warning_logged = 0;
        if (!ssl_warning_logged) {
            ssl_warning_logged = 1;
            syslog(LOG_WARNING, "open-bastion: JWKS fetch with SSL verification "
                   "disabled - vulnerable to MITM attacks");
        }
    }

    if (cache->ca_cert) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, cache->ca_cert);
    }

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(buf.data);
        return -1;
    }

    int ret = parse_jwks(cache, buf.data);

    /* Save to cache file */
    if (ret == 0 && cache->cache_file) {
        char temp_path[1024];
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", cache->cache_file);

        int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            ssize_t written = write(fd, buf.data, buf.size);
            close(fd);

            if (written == (ssize_t)buf.size) {
                rename(temp_path, cache->cache_file);
            } else {
                unlink(temp_path);
            }
        }
    }

    free(buf.data);
    return ret;
}

/* Load JWKS from cache file */
static int load_jwks_from_file(jwks_cache_t *cache)
{
    if (!cache || !cache->cache_file) return -1;

    int fd = open(cache->cache_file, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0 || st.st_size > MAX_JWKS_RESPONSE_SIZE) {
        close(fd);
        return -1;
    }

    /* Check if cache is still valid */
    time_t now = time(NULL);
    if (now - st.st_mtime > cache->refresh_interval) {
        close(fd);
        return -1;  /* Cache expired */
    }

    char *data = malloc(st.st_size + 1);
    if (!data) {
        close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, data, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(data);
        return -1;
    }
    data[st.st_size] = '\0';

    int ret = parse_jwks(cache, data);
    free(data);

    /* Set last_refresh to file mtime so we know when it was cached */
    if (ret == 0) {
        cache->last_refresh = st.st_mtime;
    }

    return ret;
}

jwks_cache_t *jwks_cache_init(const jwks_cache_config_t *config)
{
    if (!config || !config->jwks_url) return NULL;

    jwks_cache_t *cache = calloc(1, sizeof(*cache));
    if (!cache) return NULL;

    cache->jwks_url = strdup(config->jwks_url);
    if (!cache->jwks_url) {
        free(cache);
        return NULL;
    }

    if (config->cache_file) {
        cache->cache_file = strdup(config->cache_file);
    }

    cache->refresh_interval = config->refresh_interval > 0 ? config->refresh_interval : 3600;
    cache->timeout = config->timeout > 0 ? config->timeout : 10;
    cache->verify_ssl = config->verify_ssl;

    if (config->ca_cert) {
        cache->ca_cert = strdup(config->ca_cert);
    }

    /* Try to load from cache file first */
    if (load_jwks_from_file(cache) != 0) {
        /* Cache miss or expired, fetch from URL */
        if (fetch_jwks(cache) != 0) {
            /* Could not fetch, but don't fail initialization
             * (will retry on first key lookup) */
        }
    }

    return cache;
}

void jwks_cache_destroy(jwks_cache_t *cache)
{
    if (!cache) return;

    /* Free keys */
    for (size_t i = 0; i < cache->key_count; i++) {
        free(cache->keys[i].kid);
        EVP_PKEY_free(cache->keys[i].key);
    }

    free(cache->jwks_url);
    free(cache->cache_file);
    free(cache->ca_cert);
    free(cache);
}

EVP_PKEY *jwks_cache_get_key(jwks_cache_t *cache, const char *kid)
{
    if (!cache) return NULL;

    /* Check if refresh needed */
    if (jwks_cache_needs_refresh(cache)) {
        fetch_jwks(cache);
    }

    /* If no keys and not initialized, try to load */
    if (cache->key_count == 0 && !cache->initialized) {
        if (load_jwks_from_file(cache) != 0) {
            fetch_jwks(cache);
        }
    }

    /* Look for key by ID */
    if (kid && *kid) {
        for (size_t i = 0; i < cache->key_count; i++) {
            if (cache->keys[i].kid && strcmp(cache->keys[i].kid, kid) == 0) {
                return cache->keys[i].key;
            }
        }
    }

    /* Return first key if kid not specified or not found */
    if (cache->key_count > 0) {
        return cache->keys[0].key;
    }

    return NULL;
}

int jwks_cache_refresh(jwks_cache_t *cache)
{
    if (!cache) return -1;
    return fetch_jwks(cache);
}

bool jwks_cache_needs_refresh(jwks_cache_t *cache)
{
    if (!cache) return false;

    time_t now = time(NULL);
    return (now - cache->last_refresh) >= cache->refresh_interval;
}

time_t jwks_cache_last_refresh(jwks_cache_t *cache)
{
    return cache ? cache->last_refresh : 0;
}

size_t jwks_cache_key_count(jwks_cache_t *cache)
{
    return cache ? cache->key_count : 0;
}
