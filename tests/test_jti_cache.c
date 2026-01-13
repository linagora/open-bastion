/*
 * test_jti_cache.c - Unit tests for JTI replay detection cache
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include "../include/jti_cache.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    int result = test_##name(); \
    if (result == 1) { \
        printf("PASSED\n"); \
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

/* Test basic creation and destruction */
static int test_create_destroy(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);
    jti_cache_destroy(cache);
    return 1;
}

/* Test creation with custom config */
static int test_create_with_config(void)
{
    jti_cache_config_t config = {
        .max_entries = 100,
        .cleanup_interval = 30,
        .persist_path = NULL
    };

    jti_cache_t *cache = jti_cache_create(&config);
    ASSERT(cache != NULL);

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(max_entries == 100);
    ASSERT(count == 0);

    jti_cache_destroy(cache);
    return 1;
}

/* Test adding a new JTI */
static int test_add_new_jti(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);

    time_t exp = time(NULL) + 300;  /* 5 minutes from now */
    jti_cache_result_t result = jti_cache_check_and_add(cache, "test-jti-123", exp);
    ASSERT(result == JTI_CACHE_OK);

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == 1);
    ASSERT(misses == 1);
    ASSERT(hits == 0);

    jti_cache_destroy(cache);
    return 1;
}

/* Test replay detection */
static int test_replay_detection(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);

    time_t exp = time(NULL) + 300;

    /* First use should succeed */
    jti_cache_result_t result = jti_cache_check_and_add(cache, "replay-test-jti", exp);
    ASSERT(result == JTI_CACHE_OK);

    /* Second use should be detected as replay */
    result = jti_cache_check_and_add(cache, "replay-test-jti", exp);
    ASSERT(result == JTI_CACHE_REPLAY_DETECTED);

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == 1);
    ASSERT(hits == 1);  /* One replay detected */
    ASSERT(misses == 1); /* One new JTI added */

    jti_cache_destroy(cache);
    return 1;
}

/* Test that different JTIs don't conflict */
static int test_different_jtis(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);

    time_t exp = time(NULL) + 300;

    ASSERT(jti_cache_check_and_add(cache, "jti-aaa", exp) == JTI_CACHE_OK);
    ASSERT(jti_cache_check_and_add(cache, "jti-bbb", exp) == JTI_CACHE_OK);
    ASSERT(jti_cache_check_and_add(cache, "jti-ccc", exp) == JTI_CACHE_OK);

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == 3);

    jti_cache_destroy(cache);
    return 1;
}

/* Test expiration cleanup */
static int test_expiration(void)
{
    jti_cache_config_t config = {
        .max_entries = 1000,
        .cleanup_interval = 1,  /* 1 second */
        .persist_path = NULL
    };

    jti_cache_t *cache = jti_cache_create(&config);
    ASSERT(cache != NULL);

    /* Add JTI that expires in 1 second */
    time_t short_exp = time(NULL) + 1;
    ASSERT(jti_cache_check_and_add(cache, "short-lived-jti", short_exp) == JTI_CACHE_OK);

    /* Add JTI that expires in 1 hour */
    time_t long_exp = time(NULL) + 3600;
    ASSERT(jti_cache_check_and_add(cache, "long-lived-jti", long_exp) == JTI_CACHE_OK);

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == 2);

    /* Wait for expiration */
    sleep(2);

    /* Trigger cleanup */
    size_t removed = jti_cache_cleanup(cache);
    ASSERT(removed >= 1);  /* At least the short-lived one should be removed */

    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == 1);  /* Only long-lived should remain */

    /* The expired JTI should now be acceptable again */
    ASSERT(jti_cache_check_and_add(cache, "short-lived-jti", long_exp) == JTI_CACHE_OK);

    jti_cache_destroy(cache);
    return 1;
}

/* Test contains function */
static int test_contains(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);

    time_t exp = time(NULL) + 300;

    /* JTI not in cache */
    ASSERT(jti_cache_contains(cache, "nonexistent") == false);

    /* Add JTI */
    ASSERT(jti_cache_check_and_add(cache, "existing-jti", exp) == JTI_CACHE_OK);

    /* Now it should be found */
    ASSERT(jti_cache_contains(cache, "existing-jti") == true);
    ASSERT(jti_cache_contains(cache, "nonexistent") == false);

    jti_cache_destroy(cache);
    return 1;
}

/* Test cache full behavior */
static int test_cache_full(void)
{
    jti_cache_config_t config = {
        .max_entries = 5,
        .cleanup_interval = 3600,  /* Long interval - no automatic cleanup */
        .persist_path = NULL
    };

    jti_cache_t *cache = jti_cache_create(&config);
    ASSERT(cache != NULL);

    time_t exp = time(NULL) + 3600;  /* Far future - won't expire */

    /* Fill the cache */
    for (int i = 0; i < 5; i++) {
        char jti[32];
        snprintf(jti, sizeof(jti), "jti-fill-%d", i);
        ASSERT(jti_cache_check_and_add(cache, jti, exp) == JTI_CACHE_OK);
    }

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == 5);

    /* Try to add one more - should fail as cache is full and nothing expired */
    jti_cache_result_t result = jti_cache_check_and_add(cache, "jti-overflow", exp);
    ASSERT(result == JTI_CACHE_FULL);

    jti_cache_destroy(cache);
    return 1;
}

/* Test invalid parameters */
static int test_invalid_params(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);

    time_t exp = time(NULL) + 300;

    /* NULL cache */
    ASSERT(jti_cache_check_and_add(NULL, "jti", exp) == JTI_CACHE_INVALID_PARAM);

    /* NULL JTI */
    ASSERT(jti_cache_check_and_add(cache, NULL, exp) == JTI_CACHE_INVALID_PARAM);

    /* Empty JTI */
    ASSERT(jti_cache_check_and_add(cache, "", exp) == JTI_CACHE_INVALID_PARAM);

    /* NULL cache for contains */
    ASSERT(jti_cache_contains(NULL, "jti") == false);

    jti_cache_destroy(cache);
    return 1;
}

/* Test already expired JTI is not cached */
static int test_expired_jti_not_cached(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);

    /* JTI that's already expired */
    time_t past_exp = time(NULL) - 60;

    /* Should succeed but not actually cache it */
    jti_cache_result_t result = jti_cache_check_and_add(cache, "already-expired", past_exp);
    ASSERT(result == JTI_CACHE_OK);

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == 0);  /* Not cached because already expired */

    jti_cache_destroy(cache);
    return 1;
}

/* Test result string function */
static int test_result_strings(void)
{
    ASSERT(strcmp(jti_cache_result_str(JTI_CACHE_OK), "OK") == 0);
    ASSERT(strcmp(jti_cache_result_str(JTI_CACHE_REPLAY_DETECTED), "Replay detected") == 0);
    ASSERT(strcmp(jti_cache_result_str(JTI_CACHE_FULL), "Cache full") == 0);
    ASSERT(strcmp(jti_cache_result_str(JTI_CACHE_INVALID_PARAM), "Invalid parameter") == 0);
    ASSERT(strcmp(jti_cache_result_str(JTI_CACHE_INTERNAL_ERROR), "Internal error") == 0);
    return 1;
}

/* Concurrent access test structure */
typedef struct {
    jti_cache_t *cache;
    int thread_id;
    int iterations;
    int replays_detected;
    int successes;
} thread_data_t;

/* Thread function for concurrent test */
static void *concurrent_thread(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    time_t exp = time(NULL) + 3600;

    for (int i = 0; i < data->iterations; i++) {
        char jti[64];
        /* Each thread uses unique JTIs to test concurrent adds */
        snprintf(jti, sizeof(jti), "concurrent-thread-%d-iter-%d", data->thread_id, i);

        jti_cache_result_t result = jti_cache_check_and_add(data->cache, jti, exp);
        if (result == JTI_CACHE_OK) {
            data->successes++;
        } else if (result == JTI_CACHE_REPLAY_DETECTED) {
            data->replays_detected++;
        }
    }

    return NULL;
}

/* Test thread safety with concurrent access */
static int test_concurrent_access(void)
{
    jti_cache_config_t config = {
        .max_entries = 100000,  /* Large enough for all threads */
        .cleanup_interval = 3600,
        .persist_path = NULL
    };

    jti_cache_t *cache = jti_cache_create(&config);
    ASSERT(cache != NULL);

    #define NUM_THREADS 4
    #define ITERATIONS_PER_THREAD 1000

    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];

    /* Start threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].cache = cache;
        thread_data[i].thread_id = i;
        thread_data[i].iterations = ITERATIONS_PER_THREAD;
        thread_data[i].replays_detected = 0;
        thread_data[i].successes = 0;

        pthread_create(&threads[i], NULL, concurrent_thread, &thread_data[i]);
    }

    /* Wait for threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Verify results */
    int total_successes = 0;
    int total_replays = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        total_successes += thread_data[i].successes;
        total_replays += thread_data[i].replays_detected;
    }

    /* Each thread adds unique JTIs, so all should succeed */
    ASSERT(total_successes == NUM_THREADS * ITERATIONS_PER_THREAD);
    ASSERT(total_replays == 0);

    size_t count, max_entries, hits, misses;
    jti_cache_stats(cache, &count, &max_entries, &hits, &misses);
    ASSERT(count == NUM_THREADS * ITERATIONS_PER_THREAD);

    jti_cache_destroy(cache);
    return 1;
}

/* Thread data for concurrent replay test */
typedef struct {
    jti_cache_t *cache;
    const char *shared_jti;
    time_t exp;
    int replay_detected;
    int success;
} replay_thread_data_t;

/* Thread function for concurrent replay test */
static void *replay_thread(void *arg)
{
    replay_thread_data_t *data = (replay_thread_data_t *)arg;

    jti_cache_result_t result = jti_cache_check_and_add(
        data->cache, data->shared_jti, data->exp);

    if (result == JTI_CACHE_REPLAY_DETECTED) {
        data->replay_detected = 1;
    } else if (result == JTI_CACHE_OK) {
        data->success = 1;
    }

    return NULL;
}

/* Test concurrent replay detection with actual threads */
static int test_concurrent_replay(void)
{
    jti_cache_t *cache = jti_cache_create(NULL);
    ASSERT(cache != NULL);

    time_t exp = time(NULL) + 3600;
    const char *shared_jti = "shared-concurrent-jti";

    #define REPLAY_THREADS 8

    pthread_t threads[REPLAY_THREADS];
    replay_thread_data_t thread_data[REPLAY_THREADS];

    /* Initialize thread data - all threads will try the same JTI */
    for (int i = 0; i < REPLAY_THREADS; i++) {
        thread_data[i].cache = cache;
        thread_data[i].shared_jti = shared_jti;
        thread_data[i].exp = exp;
        thread_data[i].replay_detected = 0;
        thread_data[i].success = 0;
    }

    /* Start all threads simultaneously */
    for (int i = 0; i < REPLAY_THREADS; i++) {
        pthread_create(&threads[i], NULL, replay_thread, &thread_data[i]);
    }

    /* Wait for all threads */
    for (int i = 0; i < REPLAY_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Exactly one thread should succeed, all others should detect replay */
    int total_successes = 0;
    int total_replays = 0;
    for (int i = 0; i < REPLAY_THREADS; i++) {
        total_successes += thread_data[i].success;
        total_replays += thread_data[i].replay_detected;
    }

    ASSERT(total_successes == 1);  /* Only one thread wins the race */
    ASSERT(total_replays == REPLAY_THREADS - 1);  /* All others detect replay */

    jti_cache_destroy(cache);
    return 1;
}

int main(void)
{
    printf("Running JTI cache tests:\n\n");

    TEST(create_destroy);
    TEST(create_with_config);
    TEST(add_new_jti);
    TEST(replay_detection);
    TEST(different_jtis);
    TEST(expiration);
    TEST(contains);
    TEST(cache_full);
    TEST(invalid_params);
    TEST(expired_jti_not_cached);
    TEST(result_strings);
    TEST(concurrent_access);
    TEST(concurrent_replay);

    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
