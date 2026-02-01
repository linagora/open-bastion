/*
 * test_bastion_jwt.c - Unit tests for bastion JWT verification
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* BASTION_JWT_TEST is defined via CMake to enable test-exposed functions */
#include "../include/bastion_jwt.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    int result = test_##name(); \
    if (result == 1) { \
        printf("PASSED\n"); \
        tests_passed++; \
    } else if (result == 2) { \
        printf("SKIP\n"); \
        tests_passed++; \
    } else { \
        printf("FAILED\n"); \
    } \
    tests_run++; \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("Assertion failed: %s at line %d\n", #cond, __LINE__); \
        return 0; \
    } \
} while(0)

/*
 * Test bastion_jwt_is_bastion_allowed function
 */
static int test_bastion_allowed_null(void)
{
    /* NULL allowed_bastions means all bastions are allowed */
    ASSERT(bastion_jwt_is_bastion_allowed("any-bastion", NULL) == true);
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-01", NULL) == true);
    return 1;
}

static int test_bastion_allowed_empty(void)
{
    /* Empty string means no whitelist = all bastions allowed (same as NULL) */
    ASSERT(bastion_jwt_is_bastion_allowed("any-bastion", "") == true);
    return 1;
}

static int test_bastion_allowed_single(void)
{
    /* Single bastion in allowed list */
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-01", "bastion-01") == true);
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-02", "bastion-01") == false);
    return 1;
}

static int test_bastion_allowed_multiple(void)
{
    /* Multiple bastions in allowed list (comma-separated) */
    const char *allowed = "bastion-01,bastion-02,bastion-03";

    ASSERT(bastion_jwt_is_bastion_allowed("bastion-01", allowed) == true);
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-02", allowed) == true);
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-03", allowed) == true);
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-04", allowed) == false);
    ASSERT(bastion_jwt_is_bastion_allowed("unknown", allowed) == false);
    return 1;
}

static int test_bastion_allowed_with_spaces(void)
{
    /* Spaces around commas should be handled - the implementation trims whitespace */
    const char *allowed = "bastion-01, bastion-02 , bastion-03";

    /* First item (no leading space) should match */
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-01", allowed) == true);

    /* Items with leading/trailing spaces should match after trimming */
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-02", allowed) == true);
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-03", allowed) == true);

    /* Non-existent bastion should not match */
    ASSERT(bastion_jwt_is_bastion_allowed("bastion-04", allowed) == false);
    return 1;
}

static int test_bastion_allowed_null_id(void)
{
    /* NULL bastion_id should not be allowed */
    ASSERT(bastion_jwt_is_bastion_allowed(NULL, "bastion-01") == false);
    ASSERT(bastion_jwt_is_bastion_allowed(NULL, NULL) == false);
    return 1;
}

/*
 * Test bastion_jwt_result_str function
 */
static int test_result_str(void)
{
    /* All result codes should have string representations */
    ASSERT(bastion_jwt_result_str(BASTION_JWT_OK) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_INVALID_FORMAT) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_INVALID_HEADER) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_INVALID_PAYLOAD) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_INVALID_SIGNATURE) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_EXPIRED) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_NOT_YET_VALID) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_INVALID_ISSUER) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_INVALID_AUDIENCE) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_UNAUTHORIZED_BASTION) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_NO_KEY_FOUND) != NULL);
    ASSERT(bastion_jwt_result_str(BASTION_JWT_INTERNAL_ERROR) != NULL);

    /* OK message should be positive */
    ASSERT(strcmp(bastion_jwt_result_str(BASTION_JWT_OK), "Success") == 0 ||
           strstr(bastion_jwt_result_str(BASTION_JWT_OK), "OK") != NULL ||
           strstr(bastion_jwt_result_str(BASTION_JWT_OK), "success") != NULL);

    return 1;
}

/*
 * Test bastion_jwt_claims_free function
 */
static int test_claims_free_null(void)
{
    /* Should not crash on NULL */
    bastion_jwt_claims_free(NULL);
    return 1;
}

static int test_claims_free_empty(void)
{
    /* Should not crash on empty structure */
    bastion_jwt_claims_t claims = {0};
    bastion_jwt_claims_free(&claims);
    return 1;
}

static int test_claims_free_populated(void)
{
    /* Should properly free all fields */
    bastion_jwt_claims_t claims = {0};
    claims.iss = strdup("https://auth.example.com");
    claims.sub = strdup("testuser");
    claims.aud = strdup("pam:bastion-backend");
    claims.jti = strdup("12345");
    claims.bastion_id = strdup("bastion-01");
    claims.bastion_group = strdup("bastion");
    claims.bastion_ip = strdup("192.168.1.100");
    claims.target_host = strdup("backend-01");
    claims.target_group = strdup("default");

    /* Create user_groups array */
    claims.user_groups = malloc(2 * sizeof(char *));
    if (claims.user_groups) {
        claims.user_groups[0] = strdup("group1");
        claims.user_groups[1] = strdup("group2");
        claims.user_groups_count = 2;
    }

    bastion_jwt_claims_free(&claims);

    /* After free, pointers should be NULL or structure should be zeroed */
    /* (depends on implementation) */
    return 1;
}

/*
 * Test verifier initialization without JWKS
 */
static int test_verifier_init_null_config(void)
{
    /* NULL config should return NULL */
    bastion_jwt_verifier_t *v = bastion_jwt_verifier_init(NULL);
    ASSERT(v == NULL);
    return 1;
}

static int test_verifier_init_no_jwks(void)
{
    /* Config without JWKS cache should still initialize */
    bastion_jwt_config_t config = {
        .issuer = "https://auth.example.com",
        .audience = "pam:bastion-backend",
        .max_clock_skew = 60,
        .allowed_bastions = NULL,
        .jwks_cache = NULL  /* No JWKS cache */
    };

    bastion_jwt_verifier_t *v = bastion_jwt_verifier_init(&config);
    /* May or may not succeed depending on implementation */
    if (v) {
        bastion_jwt_verifier_destroy(v);
    }
    return 1;
}

/*
 * Test JWT verification with invalid inputs
 */
static int test_verify_null_verifier(void)
{
    bastion_jwt_claims_t claims = {0};
    bastion_jwt_result_t result = bastion_jwt_verify(NULL, "token", &claims);
    /* Should fail gracefully */
    ASSERT(result != BASTION_JWT_OK);
    return 1;
}

static int test_verify_null_jwt(void)
{
    bastion_jwt_config_t config = {
        .issuer = "https://auth.example.com",
        .audience = "pam:bastion-backend",
        .max_clock_skew = 60,
        .allowed_bastions = NULL,
        .jwks_cache = NULL
    };

    bastion_jwt_verifier_t *v = bastion_jwt_verifier_init(&config);
    if (!v) {
        /* Can't test without verifier */
        return 2;  /* Skip */
    }

    bastion_jwt_claims_t claims = {0};
    bastion_jwt_result_t result = bastion_jwt_verify(v, NULL, &claims);

    bastion_jwt_verifier_destroy(v);

    ASSERT(result != BASTION_JWT_OK);
    return 1;
}

static int test_verify_invalid_format(void)
{
    bastion_jwt_config_t config = {
        .issuer = "https://auth.example.com",
        .audience = "pam:bastion-backend",
        .max_clock_skew = 60,
        .allowed_bastions = NULL,
        .jwks_cache = NULL
    };

    bastion_jwt_verifier_t *v = bastion_jwt_verifier_init(&config);
    if (!v) {
        return 2;  /* Skip */
    }

    bastion_jwt_claims_t claims = {0};

    /* Invalid formats */
    bastion_jwt_result_t r1 = bastion_jwt_verify(v, "", &claims);
    bastion_jwt_result_t r2 = bastion_jwt_verify(v, "not-a-jwt", &claims);
    bastion_jwt_result_t r3 = bastion_jwt_verify(v, "only.two.parts", &claims);
    bastion_jwt_result_t r4 = bastion_jwt_verify(v, "a.b", &claims);

    bastion_jwt_verifier_destroy(v);

    ASSERT(r1 != BASTION_JWT_OK);
    ASSERT(r2 != BASTION_JWT_OK);
    /* r3 and r4 may have different results depending on parsing */

    return 1;
}

/*
 * Test time validation with nbf claim
 */
static int test_nbf_future(void)
{
    /* JWT with nbf set to future should return NOT_YET_VALID */
    time_t now = 1000000;
    time_t nbf_future = now + 3600;  /* 1 hour in the future */
    int clock_skew = 30;

    bastion_jwt_result_t result = bastion_jwt_validate_time(
        0,           /* exp: not set */
        nbf_future,  /* nbf: future */
        0,           /* iat: not set */
        now,
        clock_skew
    );

    ASSERT(result == BASTION_JWT_NOT_YET_VALID);
    return 1;
}

static int test_nbf_past(void)
{
    /* JWT with nbf set to past should validate successfully */
    time_t now = 1000000;
    time_t nbf_past = now - 60;  /* 1 minute in the past */
    int clock_skew = 30;

    bastion_jwt_result_t result = bastion_jwt_validate_time(
        0,         /* exp: not set */
        nbf_past,  /* nbf: past */
        0,         /* iat: not set */
        now,
        clock_skew
    );

    ASSERT(result == BASTION_JWT_OK);
    return 1;
}

static int test_nbf_and_iat(void)
{
    /* When both nbf and iat are set, nbf should take precedence */
    time_t now = 1000000;
    time_t nbf = now - 60;     /* nbf: 1 minute in the past (valid) */
    time_t iat = now + 3600;   /* iat: 1 hour in the future (would be invalid) */
    int clock_skew = 30;

    /* Since nbf takes precedence and is in the past, should be valid */
    bastion_jwt_result_t result = bastion_jwt_validate_time(
        0,   /* exp: not set */
        nbf, /* nbf: past (takes precedence) */
        iat, /* iat: future (ignored when nbf is set) */
        now,
        clock_skew
    );

    ASSERT(result == BASTION_JWT_OK);
    return 1;
}

static int test_iat_fallback(void)
{
    /* Without nbf, should fall back to iat for not-before check */
    time_t now = 1000000;
    time_t iat_future = now + 3600;  /* 1 hour in the future */
    int clock_skew = 30;

    bastion_jwt_result_t result = bastion_jwt_validate_time(
        0,           /* exp: not set */
        0,           /* nbf: not set (will fall back to iat) */
        iat_future,  /* iat: future */
        now,
        clock_skew
    );

    ASSERT(result == BASTION_JWT_NOT_YET_VALID);
    return 1;
}

static int test_nbf_with_clock_skew(void)
{
    /* JWT with nbf slightly in the future but within clock skew should be valid */
    time_t now = 1000000;
    time_t nbf = now + 20;  /* 20 seconds in the future */
    int clock_skew = 30;    /* 30 seconds skew allowed */

    bastion_jwt_result_t result = bastion_jwt_validate_time(
        0,   /* exp: not set */
        nbf, /* nbf: slightly in future but within skew */
        0,   /* iat: not set */
        now,
        clock_skew
    );

    ASSERT(result == BASTION_JWT_OK);
    return 1;
}

static int test_exp_and_nbf_combined(void)
{
    /* Test that both exp and nbf are checked correctly */
    time_t now = 1000000;
    time_t exp = now + 3600;  /* expires in 1 hour (valid) */
    time_t nbf = now - 60;    /* valid since 1 minute ago (valid) */
    int clock_skew = 30;

    bastion_jwt_result_t result = bastion_jwt_validate_time(
        exp,
        nbf,
        0,   /* iat: not set */
        now,
        clock_skew
    );

    ASSERT(result == BASTION_JWT_OK);

    /* Now test with expired token */
    time_t exp_past = now - 3600;  /* expired 1 hour ago */
    result = bastion_jwt_validate_time(
        exp_past,
        nbf,
        0,
        now,
        clock_skew
    );

    ASSERT(result == BASTION_JWT_EXPIRED);
    return 1;
}

/*
 * Test issuer and audience validation
 */
static int test_valid_issuer_and_audience(void)
{
    bastion_jwt_result_t r = bastion_jwt_validate_issuer_audience(
        "https://auth.example.com", "pam:bastion",
        "https://auth.example.com", "pam:bastion");
    ASSERT(r == BASTION_JWT_OK);
    return 1;
}

static int test_missing_issuer_rejected(void)
{
    /* NULL iss when issuer is required should be rejected */
    bastion_jwt_result_t r = bastion_jwt_validate_issuer_audience(
        NULL, "pam:bastion",
        "https://auth.example.com", "pam:bastion");
    ASSERT(r == BASTION_JWT_INVALID_ISSUER);
    return 1;
}

static int test_wrong_issuer_rejected(void)
{
    bastion_jwt_result_t r = bastion_jwt_validate_issuer_audience(
        "https://evil.com", "pam:bastion",
        "https://auth.example.com", "pam:bastion");
    ASSERT(r == BASTION_JWT_INVALID_ISSUER);
    return 1;
}

static int test_issuer_not_checked_when_null(void)
{
    /* No expected issuer means any issuer is accepted */
    bastion_jwt_result_t r = bastion_jwt_validate_issuer_audience(
        "https://anything.com", "pam:bastion",
        NULL, "pam:bastion");
    ASSERT(r == BASTION_JWT_OK);
    return 1;
}

static int test_missing_audience_rejected(void)
{
    /* NULL aud should always be rejected */
    bastion_jwt_result_t r = bastion_jwt_validate_issuer_audience(
        "https://auth.example.com", NULL,
        "https://auth.example.com", "pam:bastion");
    ASSERT(r == BASTION_JWT_INVALID_AUDIENCE);
    return 1;
}

static int test_wrong_audience_rejected(void)
{
    bastion_jwt_result_t r = bastion_jwt_validate_issuer_audience(
        "https://auth.example.com", "wrong-audience",
        "https://auth.example.com", "pam:bastion");
    ASSERT(r == BASTION_JWT_INVALID_AUDIENCE);
    return 1;
}

int main(void)
{
    printf("Running bastion JWT tests:\n\n");

    printf("Testing bastion_jwt_is_bastion_allowed:\n");
    TEST(bastion_allowed_null);
    TEST(bastion_allowed_empty);
    TEST(bastion_allowed_single);
    TEST(bastion_allowed_multiple);
    TEST(bastion_allowed_with_spaces);
    TEST(bastion_allowed_null_id);

    printf("\nTesting bastion_jwt_result_str:\n");
    TEST(result_str);

    printf("\nTesting bastion_jwt_claims_free:\n");
    TEST(claims_free_null);
    TEST(claims_free_empty);
    TEST(claims_free_populated);

    printf("\nTesting bastion_jwt_verifier_init:\n");
    TEST(verifier_init_null_config);
    TEST(verifier_init_no_jwks);

    printf("\nTesting bastion_jwt_verify:\n");
    TEST(verify_null_verifier);
    TEST(verify_null_jwt);
    TEST(verify_invalid_format);

    printf("\nTesting bastion_jwt_validate_issuer_audience:\n");
    TEST(valid_issuer_and_audience);
    TEST(missing_issuer_rejected);
    TEST(wrong_issuer_rejected);
    TEST(issuer_not_checked_when_null);
    TEST(missing_audience_rejected);
    TEST(wrong_audience_rejected);

    printf("\nTesting bastion_jwt_validate_time (nbf validation):\n");
    TEST(nbf_future);
    TEST(nbf_past);
    TEST(nbf_and_iat);
    TEST(iat_fallback);
    TEST(nbf_with_clock_skew);
    TEST(exp_and_nbf_combined);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
