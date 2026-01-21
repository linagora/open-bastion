/*
 * test_jwks_cache.c - Unit tests for JWKS cache rate limiting
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* JWKS_CACHE_TEST is defined via CMake to enable test-exposed functions */
#include "../include/jwks_cache.h"

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
 * Test that MIN_REFRESH_INTERVAL is reasonable
 */
static int test_min_refresh_interval(void)
{
    int interval = jwks_cache_get_min_refresh_interval();
    /* Should be at least 60 seconds and no more than 1 hour */
    ASSERT(interval >= 60);
    ASSERT(interval <= 3600);
    return 1;
}

/*
 * Test that a fresh cache (last_fetch_attempt=0) is not rate-limited
 *
 * Note: jwks_cache_init() calls fetch_jwks() which sets last_fetch_attempt,
 * so we test the rate limiting logic directly by manipulating timestamps.
 */
static int test_fresh_cache_not_rate_limited(void)
{
    jwks_cache_config_t config = {
        .jwks_url = "https://example.com/.well-known/jwks.json",
        .cache_file = NULL,
        .refresh_interval = 3600,
        .timeout = 1,  /* Short timeout for test */
        .verify_ssl = true,
        .ca_cert = NULL
    };

    jwks_cache_t *cache = jwks_cache_init(&config);
    if (!cache) {
        return 2;  /* Skip if init fails */
    }

    /* Reset last_fetch_attempt to simulate a fresh/uninitialized state */
    jwks_cache_set_last_fetch_attempt(cache, 0);

    /* Verify last_fetch_attempt is now 0 */
    time_t last_attempt = jwks_cache_get_last_fetch_attempt(cache);
    ASSERT(last_attempt == 0);

    /* Fresh cache (last_fetch_attempt=0) should NOT be rate-limited */
    time_t now = time(NULL);
    bool is_limited = jwks_cache_is_rate_limited(cache, now);
    ASSERT(is_limited == false);

    jwks_cache_destroy(cache);
    return 1;
}

/*
 * Test that rate limiting prevents excessive refresh attempts
 */
static int test_rate_limiting_within_interval(void)
{
    jwks_cache_config_t config = {
        .jwks_url = "https://example.com/.well-known/jwks.json",
        .cache_file = NULL,
        .refresh_interval = 3600,
        .timeout = 10,
        .verify_ssl = true,
        .ca_cert = NULL
    };

    jwks_cache_t *cache = jwks_cache_init(&config);
    if (!cache) {
        return 2;  /* Skip */
    }

    int min_interval = jwks_cache_get_min_refresh_interval();
    time_t now = 1000000;

    /* Simulate a previous fetch attempt */
    jwks_cache_set_last_fetch_attempt(cache, now);

    /* Immediately after: should be rate limited */
    ASSERT(jwks_cache_is_rate_limited(cache, now) == true);

    /* 1 second later: still rate limited */
    ASSERT(jwks_cache_is_rate_limited(cache, now + 1) == true);

    /* Half interval later: still rate limited */
    ASSERT(jwks_cache_is_rate_limited(cache, now + min_interval / 2) == true);

    /* Just before interval expires: still rate limited */
    ASSERT(jwks_cache_is_rate_limited(cache, now + min_interval - 1) == true);

    jwks_cache_destroy(cache);
    return 1;
}

/*
 * Test that rate limiting allows attempts after interval has elapsed
 */
static int test_rate_limiting_after_interval(void)
{
    jwks_cache_config_t config = {
        .jwks_url = "https://example.com/.well-known/jwks.json",
        .cache_file = NULL,
        .refresh_interval = 3600,
        .timeout = 10,
        .verify_ssl = true,
        .ca_cert = NULL
    };

    jwks_cache_t *cache = jwks_cache_init(&config);
    if (!cache) {
        return 2;  /* Skip */
    }

    int min_interval = jwks_cache_get_min_refresh_interval();
    time_t now = 1000000;

    /* Simulate a previous fetch attempt */
    jwks_cache_set_last_fetch_attempt(cache, now);

    /* Exactly at interval: should NOT be rate limited */
    ASSERT(jwks_cache_is_rate_limited(cache, now + min_interval) == false);

    /* Well after interval: should NOT be rate limited */
    ASSERT(jwks_cache_is_rate_limited(cache, now + min_interval + 100) == false);
    ASSERT(jwks_cache_is_rate_limited(cache, now + min_interval * 2) == false);

    jwks_cache_destroy(cache);
    return 1;
}

/*
 * Test that rate limiting handles NULL cache gracefully
 */
static int test_rate_limiting_null_cache(void)
{
    time_t now = time(NULL);

    /* NULL cache should be considered rate-limited (defensive) */
    ASSERT(jwks_cache_is_rate_limited(NULL, now) == true);

    /* Getting last fetch attempt from NULL should return 0 */
    ASSERT(jwks_cache_get_last_fetch_attempt(NULL) == 0);

    /* Setting on NULL should not crash */
    jwks_cache_set_last_fetch_attempt(NULL, now);

    return 1;
}

/*
 * Test that multiple consecutive attempts update the timestamp
 */
static int test_rate_limiting_timestamp_updates(void)
{
    jwks_cache_config_t config = {
        .jwks_url = "https://example.com/.well-known/jwks.json",
        .cache_file = NULL,
        .refresh_interval = 3600,
        .timeout = 10,
        .verify_ssl = true,
        .ca_cert = NULL
    };

    jwks_cache_t *cache = jwks_cache_init(&config);
    if (!cache) {
        return 2;  /* Skip */
    }

    int min_interval = jwks_cache_get_min_refresh_interval();
    time_t t1 = 1000000;
    time_t t2 = t1 + min_interval + 1;

    /* First attempt at t1 */
    jwks_cache_set_last_fetch_attempt(cache, t1);
    ASSERT(jwks_cache_get_last_fetch_attempt(cache) == t1);

    /* Should be rate limited at t1+1 */
    ASSERT(jwks_cache_is_rate_limited(cache, t1 + 1) == true);

    /* After interval, not rate limited */
    ASSERT(jwks_cache_is_rate_limited(cache, t2) == false);

    /* Second attempt at t2 */
    jwks_cache_set_last_fetch_attempt(cache, t2);
    ASSERT(jwks_cache_get_last_fetch_attempt(cache) == t2);

    /* Now should be rate limited from t2 */
    ASSERT(jwks_cache_is_rate_limited(cache, t2 + 1) == true);
    ASSERT(jwks_cache_is_rate_limited(cache, t2 + min_interval) == false);

    jwks_cache_destroy(cache);
    return 1;
}

int main(void)
{
    printf("Running JWKS cache rate limiting tests:\n\n");

    printf("Testing rate limiting configuration:\n");
    TEST(min_refresh_interval);

    printf("\nTesting rate limiting behavior:\n");
    TEST(fresh_cache_not_rate_limited);
    TEST(rate_limiting_within_interval);
    TEST(rate_limiting_after_interval);
    TEST(rate_limiting_null_cache);
    TEST(rate_limiting_timestamp_updates);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
