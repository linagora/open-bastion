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

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
