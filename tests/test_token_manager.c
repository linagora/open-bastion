/*
 * test_token_manager.c - Tests for token_manager JWT functions
 *
 * Tests the JWT generation functions:
 * - base64url_encode()
 * - generate_uuid()
 * - generate_client_jwt()
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <json-c/json.h>

#include "token_manager.h"

/* Declare test-exposed functions */
extern char *base64url_encode(const unsigned char *data, size_t len);
extern char *generate_uuid(void);
extern char *generate_client_jwt(const char *client_id, const char *client_secret,
                                  const char *token_endpoint);

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", name); \
    tests_run++; \
} while(0)

#define PASS() do { \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define FAIL(msg) do { \
    printf("FAILED: %s\n", msg); \
} while(0)

/* Helper: base64url decode for verification */
static unsigned char *base64url_decode(const char *input, size_t *out_len)
{
    static const int b64_table[256] = {
        ['A'] = 0, ['B'] = 1, ['C'] = 2, ['D'] = 3, ['E'] = 4, ['F'] = 5,
        ['G'] = 6, ['H'] = 7, ['I'] = 8, ['J'] = 9, ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
        ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
        ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
        ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
        ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61, ['-'] = 62, ['_'] = 63
    };

    size_t len = strlen(input);
    size_t out_size = (len * 3) / 4 + 3;
    unsigned char *out = malloc(out_size);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i += 4) {
        int n = b64_table[(unsigned char)input[i]] << 18;
        if (i + 1 < len) n |= b64_table[(unsigned char)input[i + 1]] << 12;
        if (i + 2 < len) n |= b64_table[(unsigned char)input[i + 2]] << 6;
        if (i + 3 < len) n |= b64_table[(unsigned char)input[i + 3]];

        out[j++] = (n >> 16) & 0xFF;
        if (i + 2 < len) out[j++] = (n >> 8) & 0xFF;
        if (i + 3 < len) out[j++] = n & 0xFF;
    }

    *out_len = j;
    return out;
}

/*
 * Test base64url_encode with known values
 */
static void test_base64url_encode_basic(void)
{
    TEST("base64url_encode basic");

    /* Test vector: "Hello" -> "SGVsbG8" */
    const char *input = "Hello";
    char *result = base64url_encode((const unsigned char *)input, strlen(input));

    if (result && strcmp(result, "SGVsbG8") == 0) {
        PASS();
    } else {
        FAIL(result ? result : "NULL result");
    }
    free(result);
}

static void test_base64url_encode_empty(void)
{
    TEST("base64url_encode empty");

    char *result = base64url_encode((const unsigned char *)"", 0);

    if (result && strlen(result) == 0) {
        PASS();
    } else {
        FAIL("Expected empty string");
    }
    free(result);
}

static void test_base64url_encode_binary(void)
{
    TEST("base64url_encode binary data");

    /* Binary data with bytes that would produce + and / in standard base64 */
    unsigned char binary[] = {0xfb, 0xff, 0xfe};
    char *result = base64url_encode(binary, sizeof(binary));

    /* Should use - and _ instead of + and / */
    if (result && strchr(result, '+') == NULL && strchr(result, '/') == NULL) {
        PASS();
    } else {
        FAIL("Contains forbidden characters + or /");
    }
    free(result);
}

static void test_base64url_encode_no_padding(void)
{
    TEST("base64url_encode no padding");

    /* "a" would produce "YQ==" in standard base64, should be "YQ" in base64url */
    char *result = base64url_encode((const unsigned char *)"a", 1);

    if (result && strchr(result, '=') == NULL) {
        PASS();
    } else {
        FAIL("Contains padding character =");
    }
    free(result);
}

/*
 * Test generate_uuid
 */
static void test_generate_uuid_format(void)
{
    TEST("generate_uuid format");

    char *uuid = generate_uuid();

    if (!uuid) {
        FAIL("NULL result");
        return;
    }

    /* Check length: 36 chars (8-4-4-4-12) */
    if (strlen(uuid) != 36) {
        FAIL("Wrong length");
        free(uuid);
        return;
    }

    /* Check hyphens at positions 8, 13, 18, 23 */
    if (uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-') {
        FAIL("Hyphens in wrong positions");
        free(uuid);
        return;
    }

    /* Check version 4 (character at position 14 should be '4') */
    if (uuid[14] != '4') {
        FAIL("Not version 4 UUID");
        free(uuid);
        return;
    }

    /* Check variant (character at position 19 should be 8, 9, a, or b) */
    char variant = uuid[19];
    if (variant != '8' && variant != '9' && variant != 'a' && variant != 'b') {
        FAIL("Invalid variant");
        free(uuid);
        return;
    }

    PASS();
    free(uuid);
}

static void test_generate_uuid_unique(void)
{
    TEST("generate_uuid uniqueness");

    char *uuid1 = generate_uuid();
    char *uuid2 = generate_uuid();

    if (uuid1 && uuid2 && strcmp(uuid1, uuid2) != 0) {
        PASS();
    } else {
        FAIL("Generated identical UUIDs");
    }

    free(uuid1);
    free(uuid2);
}

/*
 * Test generate_client_jwt
 */
static void test_generate_client_jwt_structure(void)
{
    TEST("generate_client_jwt structure");

    char *jwt = generate_client_jwt("test-client", "test-secret",
                                     "https://example.com/token");

    if (!jwt) {
        FAIL("NULL result");
        return;
    }

    /* JWT should have 3 parts separated by dots */
    int dots = 0;
    for (char *p = jwt; *p; p++) {
        if (*p == '.') dots++;
    }

    if (dots != 2) {
        FAIL("JWT doesn't have 3 parts");
        free(jwt);
        return;
    }

    PASS();
    free(jwt);
}

static void test_generate_client_jwt_header(void)
{
    TEST("generate_client_jwt header");

    char *jwt = generate_client_jwt("test-client", "test-secret",
                                     "https://example.com/token");

    if (!jwt) {
        FAIL("NULL result");
        return;
    }

    /* Extract header (first part before .) */
    char *dot = strchr(jwt, '.');
    if (!dot) {
        FAIL("No dot found");
        free(jwt);
        return;
    }

    size_t header_len = dot - jwt;
    char *header_b64 = strndup(jwt, header_len);

    /* Decode header */
    size_t decoded_len;
    unsigned char *header_json = base64url_decode(header_b64, &decoded_len);
    free(header_b64);

    if (!header_json) {
        FAIL("Failed to decode header");
        free(jwt);
        return;
    }

    /* Parse JSON */
    struct json_object *header = json_tokener_parse((char *)header_json);
    free(header_json);

    if (!header) {
        FAIL("Failed to parse header JSON");
        free(jwt);
        return;
    }

    struct json_object *alg, *typ;
    json_object_object_get_ex(header, "alg", &alg);
    json_object_object_get_ex(header, "typ", &typ);

    int passed = (alg && typ &&
                  strcmp(json_object_get_string(alg), "HS256") == 0 &&
                  strcmp(json_object_get_string(typ), "JWT") == 0);

    json_object_put(header);
    free(jwt);

    if (passed) {
        PASS();
    } else {
        FAIL("Invalid header alg/typ");
    }
}

static void test_generate_client_jwt_payload_claims(void)
{
    TEST("generate_client_jwt payload claims");

    const char *client_id = "my-client";
    const char *token_endpoint = "https://sso.example.com/oauth2/token";

    char *jwt = generate_client_jwt(client_id, "secret", token_endpoint);

    if (!jwt) {
        FAIL("NULL result");
        return;
    }

    /* Extract payload (second part between dots) */
    char *first_dot = strchr(jwt, '.');
    char *second_dot = strchr(first_dot + 1, '.');

    if (!first_dot || !second_dot) {
        FAIL("Invalid JWT structure");
        free(jwt);
        return;
    }

    size_t payload_len = second_dot - first_dot - 1;
    char *payload_b64 = strndup(first_dot + 1, payload_len);

    /* Decode payload */
    size_t decoded_len;
    unsigned char *payload_json = base64url_decode(payload_b64, &decoded_len);
    free(payload_b64);

    if (!payload_json) {
        FAIL("Failed to decode payload");
        free(jwt);
        return;
    }

    /* Parse JSON */
    struct json_object *payload = json_tokener_parse((char *)payload_json);
    free(payload_json);

    if (!payload) {
        FAIL("Failed to parse payload JSON");
        free(jwt);
        return;
    }

    struct json_object *iss, *sub, *aud, *exp, *iat, *jti;
    json_object_object_get_ex(payload, "iss", &iss);
    json_object_object_get_ex(payload, "sub", &sub);
    json_object_object_get_ex(payload, "aud", &aud);
    json_object_object_get_ex(payload, "exp", &exp);
    json_object_object_get_ex(payload, "iat", &iat);
    json_object_object_get_ex(payload, "jti", &jti);

    int passed = 1;

    /* Check iss and sub are client_id */
    if (!iss || strcmp(json_object_get_string(iss), client_id) != 0) {
        printf("(iss mismatch) ");
        passed = 0;
    }
    if (!sub || strcmp(json_object_get_string(sub), client_id) != 0) {
        printf("(sub mismatch) ");
        passed = 0;
    }

    /* Check aud is token_endpoint */
    if (!aud || strcmp(json_object_get_string(aud), token_endpoint) != 0) {
        printf("(aud mismatch) ");
        passed = 0;
    }

    /* Check exp > iat (expiry after issued) */
    if (!exp || !iat || json_object_get_int64(exp) <= json_object_get_int64(iat)) {
        printf("(exp/iat invalid) ");
        passed = 0;
    }

    /* Check exp is ~5 minutes after iat */
    int64_t diff = json_object_get_int64(exp) - json_object_get_int64(iat);
    if (diff < 290 || diff > 310) {  /* Allow 10 second tolerance */
        printf("(exp not ~5min after iat: %ld) ", (long)diff);
        passed = 0;
    }

    /* Check jti exists and is non-empty */
    if (!jti || strlen(json_object_get_string(jti)) == 0) {
        printf("(jti missing) ");
        passed = 0;
    }

    json_object_put(payload);
    free(jwt);

    if (passed) {
        PASS();
    } else {
        FAIL("Claim validation failed");
    }
}

static void test_generate_client_jwt_signature(void)
{
    TEST("generate_client_jwt signature verification");

    const char *secret = "my-test-secret";
    char *jwt = generate_client_jwt("client", secret, "https://example.com/token");

    if (!jwt) {
        FAIL("NULL result");
        return;
    }

    /* Split JWT into parts */
    char *jwt_copy = strdup(jwt);
    char *header_b64 = strtok(jwt_copy, ".");
    char *payload_b64 = strtok(NULL, ".");
    char *sig_b64 = strtok(NULL, ".");

    if (!header_b64 || !payload_b64 || !sig_b64) {
        FAIL("Failed to split JWT");
        free(jwt_copy);
        free(jwt);
        return;
    }

    /* Reconstruct signing input */
    size_t signing_input_len = strlen(header_b64) + 1 + strlen(payload_b64) + 1;
    char *signing_input = malloc(signing_input_len);
    snprintf(signing_input, signing_input_len, "%s.%s", header_b64, payload_b64);

    /* Compute expected signature */
    unsigned char expected_sig[EVP_MAX_MD_SIZE];
    unsigned int expected_len = 0;
    HMAC(EVP_sha256(), secret, strlen(secret),
         (unsigned char *)signing_input, strlen(signing_input),
         expected_sig, &expected_len);

    /* Encode expected signature */
    char *expected_sig_b64 = base64url_encode(expected_sig, expected_len);

    int passed = (expected_sig_b64 && strcmp(sig_b64, expected_sig_b64) == 0);

    free(signing_input);
    free(expected_sig_b64);
    free(jwt_copy);
    free(jwt);

    if (passed) {
        PASS();
    } else {
        FAIL("Signature mismatch");
    }
}

static void test_generate_client_jwt_null_inputs(void)
{
    TEST("generate_client_jwt NULL inputs");

    char *jwt1 = generate_client_jwt(NULL, "secret", "https://example.com");
    char *jwt2 = generate_client_jwt("client", NULL, "https://example.com");
    char *jwt3 = generate_client_jwt("client", "secret", NULL);

    if (jwt1 == NULL && jwt2 == NULL && jwt3 == NULL) {
        PASS();
    } else {
        FAIL("Should return NULL for NULL inputs");
        free(jwt1);
        free(jwt2);
        free(jwt3);
    }
}

static void test_generate_client_jwt_special_chars(void)
{
    TEST("generate_client_jwt with special JSON characters");

    /* Test with client_id containing special JSON chars */
    char *jwt = generate_client_jwt("client\"with'quotes", "secret",
                                     "https://example.com/path?query=1&foo=bar");

    if (!jwt) {
        FAIL("NULL result");
        return;
    }

    /* Extract and decode payload to verify proper escaping */
    char *first_dot = strchr(jwt, '.');
    char *second_dot = strchr(first_dot + 1, '.');

    size_t payload_len = second_dot - first_dot - 1;
    char *payload_b64 = strndup(first_dot + 1, payload_len);

    size_t decoded_len;
    unsigned char *payload_json = base64url_decode(payload_b64, &decoded_len);
    free(payload_b64);

    /* JSON should be parseable (properly escaped) */
    struct json_object *payload = json_tokener_parse((char *)payload_json);
    free(payload_json);

    if (payload) {
        struct json_object *iss;
        json_object_object_get_ex(payload, "iss", &iss);

        if (iss && strcmp(json_object_get_string(iss), "client\"with'quotes") == 0) {
            PASS();
        } else {
            FAIL("Client ID not properly preserved");
        }
        json_object_put(payload);
    } else {
        FAIL("Invalid JSON (escaping issue)");
    }

    free(jwt);
}

static void test_generate_client_jwt_unique_jti(void)
{
    TEST("generate_client_jwt unique jti per call");

    char *jwt1 = generate_client_jwt("client", "secret", "https://example.com");
    char *jwt2 = generate_client_jwt("client", "secret", "https://example.com");

    if (!jwt1 || !jwt2) {
        FAIL("NULL result");
        free(jwt1);
        free(jwt2);
        return;
    }

    /* JWTs should be different (different jti) */
    if (strcmp(jwt1, jwt2) != 0) {
        PASS();
    } else {
        FAIL("JWTs are identical (jti not unique)");
    }

    free(jwt1);
    free(jwt2);
}

int main(void)
{
    printf("Token Manager JWT Tests\n");
    printf("========================\n\n");

    printf("base64url_encode tests:\n");
    test_base64url_encode_basic();
    test_base64url_encode_empty();
    test_base64url_encode_binary();
    test_base64url_encode_no_padding();

    printf("\ngenerate_uuid tests:\n");
    test_generate_uuid_format();
    test_generate_uuid_unique();

    printf("\ngenerate_client_jwt tests:\n");
    test_generate_client_jwt_structure();
    test_generate_client_jwt_header();
    test_generate_client_jwt_payload_claims();
    test_generate_client_jwt_signature();
    test_generate_client_jwt_null_inputs();
    test_generate_client_jwt_special_chars();
    test_generate_client_jwt_unique_jti();

    printf("\n========================\n");
    printf("Tests: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
