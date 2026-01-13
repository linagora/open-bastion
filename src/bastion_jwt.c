/*
 * bastion_jwt.c - JWT verification for bastion-to-backend authentication
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "bastion_jwt.h"
#include "jwks_cache.h"
#include "jti_cache.h"

/* Security limits */
#define MAX_JWT_LENGTH 8192
#define MAX_HEADER_LENGTH 1024
#define MAX_PAYLOAD_LENGTH 4096
#define MAX_GROUPS 256

/* JWT verifier structure */
struct bastion_jwt_verifier {
    char *issuer;
    char *audience;
    int max_clock_skew;
    char *allowed_bastions;
    jwks_cache_t *jwks_cache;
    jti_cache_t *jti_cache;  /* For replay detection (NULL = disabled) */
};

/* Base64url decode (RFC 4648 section 5) */
static unsigned char *base64url_decode(const char *input, size_t input_len, size_t *out_len)
{
    if (!input || input_len == 0) return NULL;

    /* Security check */
    if (input_len > MAX_JWT_LENGTH) return NULL;

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

    /* Calculate output size (roughly input_len * 3/4) */
    size_t padding = 0;
    while (input_len > 0 && input[input_len - 1] == '=') {
        padding++;
        input_len--;
    }

    /* Base64url doesn't require padding, but handle if present */
    size_t out_size = ((input_len + 3) / 4) * 3;
    if (out_size < padding) return NULL;
    out_size -= padding;

    unsigned char *out = malloc(out_size + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_len; i += 4) {
        unsigned int val = 0;
        size_t k;
        for (k = 0; k < 4 && i + k < input_len; k++) {
            unsigned char c = (unsigned char)input[i + k];
            if (c > 127 || (b64_table[c] == 0 && c != 'A')) {
                free(out);
                return NULL;
            }
            val = (val << 6) | b64_table[c];
        }
        /* Shift for missing characters */
        for (; k < 4; k++) {
            val <<= 6;
        }

        /* Calculate how many bytes to write for this block:
         * - Full 4-char block produces 3 bytes
         * - 3-char block (1 padding) produces 2 bytes
         * - 2-char block (2 padding) produces 1 byte
         * Use remaining space as upper bound */
        size_t remaining = out_size - j;
        if (remaining >= 1) out[j++] = (val >> 16) & 0xff;
        if (remaining >= 2) out[j++] = (val >> 8) & 0xff;
        if (remaining >= 3) out[j++] = val & 0xff;
    }

    out[j] = '\0';
    *out_len = j;
    return out;
}

/* Parse JWT header to get algorithm and key ID */
static int parse_jwt_header(const char *header_b64, size_t header_len,
                            char **alg, char **kid)
{
    *alg = NULL;
    *kid = NULL;

    if (header_len > MAX_HEADER_LENGTH) return -1;

    size_t decoded_len;
    unsigned char *decoded = base64url_decode(header_b64, header_len, &decoded_len);
    if (!decoded) return -1;

    struct json_object *json = json_tokener_parse((char *)decoded);
    explicit_bzero(decoded, decoded_len);
    free(decoded);

    if (!json) return -1;

    struct json_object *val;

    /* Get algorithm */
    if (json_object_object_get_ex(json, "alg", &val)) {
        const char *alg_str = json_object_get_string(val);
        if (alg_str) {
            *alg = strdup(alg_str);
        }
    }

    /* Get key ID (optional) */
    if (json_object_object_get_ex(json, "kid", &val)) {
        const char *kid_str = json_object_get_string(val);
        if (kid_str) {
            *kid = strdup(kid_str);
        }
    }

    json_object_put(json);

    if (!*alg) {
        free(*kid);
        *kid = NULL;
        return -1;
    }

    return 0;
}

/* Parse JWT payload and extract claims */
static int parse_jwt_payload(const char *payload_b64, size_t payload_len,
                             bastion_jwt_claims_t *claims)
{
    memset(claims, 0, sizeof(*claims));

    if (payload_len > MAX_PAYLOAD_LENGTH) return -1;

    size_t decoded_len;
    unsigned char *decoded = base64url_decode(payload_b64, payload_len, &decoded_len);
    if (!decoded) return -1;

    struct json_object *json = json_tokener_parse((char *)decoded);
    explicit_bzero(decoded, decoded_len);
    free(decoded);

    if (!json) return -1;

    struct json_object *val;

    /* Required claims */
    if (json_object_object_get_ex(json, "iss", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->iss = strdup(str);
    }

    if (json_object_object_get_ex(json, "sub", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->sub = strdup(str);
    }

    if (json_object_object_get_ex(json, "aud", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->aud = strdup(str);
    }

    if (json_object_object_get_ex(json, "exp", &val)) {
        claims->exp = (time_t)json_object_get_int64(val);
    }

    if (json_object_object_get_ex(json, "iat", &val)) {
        claims->iat = (time_t)json_object_get_int64(val);
    }

    if (json_object_object_get_ex(json, "jti", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->jti = strdup(str);
    }

    /* Bastion-specific claims */
    if (json_object_object_get_ex(json, "bastion_id", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->bastion_id = strdup(str);
    }

    if (json_object_object_get_ex(json, "bastion_group", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->bastion_group = strdup(str);
    }

    if (json_object_object_get_ex(json, "bastion_ip", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->bastion_ip = strdup(str);
    }

    if (json_object_object_get_ex(json, "target_host", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->target_host = strdup(str);
    }

    if (json_object_object_get_ex(json, "target_group", &val)) {
        const char *str = json_object_get_string(val);
        if (str) claims->target_group = strdup(str);
    }

    /* User groups array */
    if (json_object_object_get_ex(json, "user_groups", &val)) {
        if (json_object_is_type(val, json_type_array)) {
            size_t count = json_object_array_length(val);
            if (count > MAX_GROUPS) count = MAX_GROUPS;

            claims->user_groups = calloc(count + 1, sizeof(char *));
            if (claims->user_groups) {
                claims->user_groups_count = count;
                for (size_t i = 0; i < count; i++) {
                    struct json_object *g = json_object_array_get_idx(val, i);
                    if (g) {
                        const char *str = json_object_get_string(g);
                        if (str) {
                            claims->user_groups[i] = strdup(str);
                        }
                    }
                }
            }
        }
    }

    json_object_put(json);
    return 0;
}

/* Verify RS256 signature */
static int verify_rs256_signature(EVP_PKEY *key,
                                  const char *signing_input, size_t signing_input_len,
                                  const unsigned char *signature, size_t signature_len)
{
    if (!key || !signing_input || !signature) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int ret = -1;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) != 1) {
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, signing_input, signing_input_len) != 1) {
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(ctx, signature, signature_len) == 1) {
        ret = 0;  /* Signature valid */
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

bastion_jwt_verifier_t *bastion_jwt_verifier_init(const bastion_jwt_config_t *config)
{
    if (!config || !config->jwks_cache) return NULL;

    bastion_jwt_verifier_t *verifier = calloc(1, sizeof(*verifier));
    if (!verifier) return NULL;

    if (config->issuer) {
        verifier->issuer = strdup(config->issuer);
    }

    verifier->audience = strdup(config->audience ? config->audience : "pam:bastion-backend");
    if (!verifier->audience) {
        free(verifier->issuer);
        free(verifier);
        return NULL;
    }

    verifier->max_clock_skew = config->max_clock_skew > 0 ? config->max_clock_skew : 60;

    if (config->allowed_bastions) {
        verifier->allowed_bastions = strdup(config->allowed_bastions);
    }

    verifier->jwks_cache = config->jwks_cache;
    verifier->jti_cache = config->jti_cache;  /* May be NULL (disabled) */

    return verifier;
}

void bastion_jwt_verifier_destroy(bastion_jwt_verifier_t *verifier)
{
    if (!verifier) return;

    free(verifier->issuer);
    free(verifier->audience);
    free(verifier->allowed_bastions);
    /* Note: jwks_cache is owned by caller, do not destroy */
    free(verifier);
}

bastion_jwt_result_t bastion_jwt_verify(bastion_jwt_verifier_t *verifier,
                                        const char *jwt,
                                        bastion_jwt_claims_t *claims)
{
    if (!verifier || !jwt || !claims) {
        return BASTION_JWT_INTERNAL_ERROR;
    }

    memset(claims, 0, sizeof(*claims));

    /* Security: Check JWT length */
    size_t jwt_len = strlen(jwt);
    if (jwt_len > MAX_JWT_LENGTH || jwt_len < 10) {
        return BASTION_JWT_INVALID_FORMAT;
    }

    /* Split JWT into header.payload.signature */
    const char *first_dot = strchr(jwt, '.');
    if (!first_dot) return BASTION_JWT_INVALID_FORMAT;

    const char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) return BASTION_JWT_INVALID_FORMAT;

    /* Check no more dots */
    if (strchr(second_dot + 1, '.')) {
        return BASTION_JWT_INVALID_FORMAT;
    }

    size_t header_len = first_dot - jwt;
    size_t payload_len = second_dot - first_dot - 1;
    size_t sig_len = jwt_len - (second_dot - jwt) - 1;

    if (header_len == 0 || payload_len == 0 || sig_len == 0) {
        return BASTION_JWT_INVALID_FORMAT;
    }

    /* Parse header */
    char *alg = NULL;
    char *kid = NULL;
    if (parse_jwt_header(jwt, header_len, &alg, &kid) != 0) {
        return BASTION_JWT_INVALID_HEADER;
    }

    /* Check algorithm is RS256 */
    if (strcmp(alg, "RS256") != 0) {
        free(alg);
        free(kid);
        return BASTION_JWT_INVALID_HEADER;
    }
    free(alg);

    /* Get public key from JWKS cache */
    EVP_PKEY *key = jwks_cache_get_key(verifier->jwks_cache, kid);
    free(kid);

    if (!key) {
        /* Try refreshing cache and retry */
        if (jwks_cache_refresh(verifier->jwks_cache) == 0) {
            key = jwks_cache_get_key(verifier->jwks_cache, NULL);
        }
        if (!key) {
            return BASTION_JWT_NO_KEY_FOUND;
        }
    }

    /* Decode signature */
    size_t decoded_sig_len;
    unsigned char *decoded_sig = base64url_decode(second_dot + 1, sig_len, &decoded_sig_len);
    if (!decoded_sig) {
        return BASTION_JWT_INVALID_SIGNATURE;
    }

    /* Verify signature */
    size_t signing_input_len = second_dot - jwt;  /* header.payload */
    if (verify_rs256_signature(key, jwt, signing_input_len, decoded_sig, decoded_sig_len) != 0) {
        explicit_bzero(decoded_sig, decoded_sig_len);
        free(decoded_sig);
        return BASTION_JWT_INVALID_SIGNATURE;
    }

    explicit_bzero(decoded_sig, decoded_sig_len);
    free(decoded_sig);

    /* Parse payload */
    if (parse_jwt_payload(first_dot + 1, payload_len, claims) != 0) {
        return BASTION_JWT_INVALID_PAYLOAD;
    }

    /* Verify claims */
    time_t now = time(NULL);

    /* Check expiration */
    if (claims->exp > 0 && now > claims->exp + verifier->max_clock_skew) {
        bastion_jwt_claims_free(claims);
        return BASTION_JWT_EXPIRED;
    }

    /* Check not-before (iat) */
    if (claims->iat > 0 && now < claims->iat - verifier->max_clock_skew) {
        bastion_jwt_claims_free(claims);
        return BASTION_JWT_NOT_YET_VALID;
    }

    /* Verify issuer if configured */
    if (verifier->issuer && claims->iss) {
        if (strcmp(claims->iss, verifier->issuer) != 0) {
            bastion_jwt_claims_free(claims);
            return BASTION_JWT_INVALID_ISSUER;
        }
    }

    /* Verify audience */
    if (claims->aud && strcmp(claims->aud, verifier->audience) != 0) {
        bastion_jwt_claims_free(claims);
        return BASTION_JWT_INVALID_AUDIENCE;
    }

    /* Verify bastion is in allowed list */
    if (verifier->allowed_bastions && claims->bastion_id) {
        if (!bastion_jwt_is_bastion_allowed(claims->bastion_id, verifier->allowed_bastions)) {
            bastion_jwt_claims_free(claims);
            return BASTION_JWT_UNAUTHORIZED_BASTION;
        }
    }

    /* Check for replay attack if JTI cache is enabled */
    if (verifier->jti_cache) {
        if (claims->jti) {
            jti_cache_result_t jti_result = jti_cache_check_and_add(
                verifier->jti_cache, claims->jti, claims->exp);

            if (jti_result == JTI_CACHE_REPLAY_DETECTED) {
                bastion_jwt_claims_free(claims);
                return BASTION_JWT_REPLAY_DETECTED;
            } else if (jti_result != JTI_CACHE_OK) {
                /* Log non-fatal cache errors (full, internal error, etc.) */
                fprintf(stderr, "bastion_jwt: JTI cache warning: %s (jti=%s)\n",
                        jti_cache_result_str(jti_result), claims->jti);
            }
        } else {
            /* Replay detection configured but token has no jti claim */
            fprintf(stderr, "bastion_jwt: warning: replay detection enabled but "
                    "token has no 'jti' claim, skipping replay check\n");
        }
    }

    return BASTION_JWT_OK;
}

const char *bastion_jwt_result_str(bastion_jwt_result_t result)
{
    switch (result) {
    case BASTION_JWT_OK:
        return "OK";
    case BASTION_JWT_INVALID_FORMAT:
        return "Invalid JWT format";
    case BASTION_JWT_INVALID_HEADER:
        return "Invalid JWT header";
    case BASTION_JWT_INVALID_PAYLOAD:
        return "Invalid JWT payload";
    case BASTION_JWT_INVALID_SIGNATURE:
        return "Invalid JWT signature";
    case BASTION_JWT_EXPIRED:
        return "JWT expired";
    case BASTION_JWT_NOT_YET_VALID:
        return "JWT not yet valid";
    case BASTION_JWT_INVALID_ISSUER:
        return "Invalid JWT issuer";
    case BASTION_JWT_INVALID_AUDIENCE:
        return "Invalid JWT audience";
    case BASTION_JWT_UNAUTHORIZED_BASTION:
        return "Unauthorized bastion";
    case BASTION_JWT_NO_KEY_FOUND:
        return "No public key found for verification";
    case BASTION_JWT_REPLAY_DETECTED:
        return "JWT replay detected";
    case BASTION_JWT_INTERNAL_ERROR:
        return "Internal error";
    default:
        return "Unknown error";
    }
}

void bastion_jwt_claims_free(bastion_jwt_claims_t *claims)
{
    if (!claims) return;

    free(claims->iss);
    free(claims->sub);
    free(claims->aud);
    free(claims->jti);
    free(claims->bastion_id);
    free(claims->bastion_group);
    free(claims->bastion_ip);
    free(claims->target_host);
    free(claims->target_group);

    if (claims->user_groups) {
        for (size_t i = 0; i < claims->user_groups_count; i++) {
            free(claims->user_groups[i]);
        }
        free(claims->user_groups);
    }

    memset(claims, 0, sizeof(*claims));
}

bool bastion_jwt_is_bastion_allowed(const char *bastion_id, const char *allowed_bastions)
{
    if (!bastion_id) return false;
    if (!allowed_bastions || !*allowed_bastions) return true;  /* No whitelist = all allowed */

    /* Parse comma-separated list */
    char *list = strdup(allowed_bastions);
    if (!list) return false;

    char *saveptr;
    char *token = strtok_r(list, ",", &saveptr);

    while (token) {
        /* Trim whitespace */
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (strcmp(token, bastion_id) == 0) {
            free(list);
            return true;
        }

        token = strtok_r(NULL, ",", &saveptr);
    }

    free(list);
    return false;
}
