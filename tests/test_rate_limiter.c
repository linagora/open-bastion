/*
 * test_rate_limiter.c - Unit tests for rate limiter
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "rate_limiter.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    tests_run++; \
    if (test_##name()) { \
        printf("PASS\n"); \
        tests_passed++; \
    } else { \
        printf("FAIL\n"); \
    } \
} while(0)

static const char *test_state_dir = "/tmp/test_pam_llng_ratelimit";

/* Setup test directory */
static void setup(void)
{
    mkdir(test_state_dir, 0700);
}

/* Recursively remove directory - safe alternative to system("rm -rf") */
static int remove_directory(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) {
        if (errno == ENOENT) return 0;  /* Already gone */
        return -1;
    }

    struct dirent *entry;
    char filepath[512];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(filepath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                remove_directory(filepath);
            } else {
                unlink(filepath);
            }
        }
    }

    closedir(dir);
    return rmdir(path);
}

/* Cleanup test directory */
static void cleanup(void)
{
    remove_directory(test_state_dir);
}

/* Test initialization */
static int test_init(void)
{
    rate_limiter_config_t config = {
        .enabled = true,
        .state_dir = (char *)test_state_dir,
        .max_attempts = 3,
        .initial_lockout_sec = 10,
        .max_lockout_sec = 60,
        .backoff_multiplier = 2.0
    };

    rate_limiter_t *rl = rate_limiter_init(&config);
    if (!rl) return 0;

    rate_limiter_destroy(rl);
    return 1;
}

/* Test that new key is not rate limited */
static int test_new_key_allowed(void)
{
    rate_limiter_config_t config = {
        .enabled = true,
        .state_dir = (char *)test_state_dir,
        .max_attempts = 3,
        .initial_lockout_sec = 10,
        .max_lockout_sec = 60,
        .backoff_multiplier = 2.0
    };

    rate_limiter_t *rl = rate_limiter_init(&config);
    if (!rl) return 0;

    int result = rate_limiter_check(rl, "newuser:192.168.1.1");

    rate_limiter_destroy(rl);
    return (result == 0);  /* Should be allowed */
}

/* Test failures before lockout */
static int test_failures_before_lockout(void)
{
    rate_limiter_config_t config = {
        .enabled = true,
        .state_dir = (char *)test_state_dir,
        .max_attempts = 3,
        .initial_lockout_sec = 10,
        .max_lockout_sec = 60,
        .backoff_multiplier = 2.0
    };

    rate_limiter_t *rl = rate_limiter_init(&config);
    if (!rl) return 0;

    const char *key = "testuser1:10.0.0.1";
    int ok = 1;

    /* First two failures should not trigger lockout */
    int lockout1 = rate_limiter_record_failure(rl, key);
    ok = ok && (lockout1 == 0);

    int lockout2 = rate_limiter_record_failure(rl, key);
    ok = ok && (lockout2 == 0);

    /* Should still be allowed */
    int check = rate_limiter_check(rl, key);
    ok = ok && (check == 0);

    rate_limiter_destroy(rl);
    return ok;
}

/* Test lockout after max attempts */
static int test_lockout_after_max_attempts(void)
{
    rate_limiter_config_t config = {
        .enabled = true,
        .state_dir = (char *)test_state_dir,
        .max_attempts = 3,
        .initial_lockout_sec = 10,
        .max_lockout_sec = 60,
        .backoff_multiplier = 2.0
    };

    rate_limiter_t *rl = rate_limiter_init(&config);
    if (!rl) return 0;

    const char *key = "testuser2:10.0.0.2";
    int ok = 1;

    /* Record max_attempts failures */
    rate_limiter_record_failure(rl, key);
    rate_limiter_record_failure(rl, key);
    int lockout = rate_limiter_record_failure(rl, key);

    /* Should now be locked out */
    ok = ok && (lockout > 0);

    /* Check should return lockout time */
    int check = rate_limiter_check(rl, key);
    ok = ok && (check > 0);

    rate_limiter_destroy(rl);
    return ok;
}

/* Test reset clears failures */
static int test_reset(void)
{
    rate_limiter_config_t config = {
        .enabled = true,
        .state_dir = (char *)test_state_dir,
        .max_attempts = 3,
        .initial_lockout_sec = 10,
        .max_lockout_sec = 60,
        .backoff_multiplier = 2.0
    };

    rate_limiter_t *rl = rate_limiter_init(&config);
    if (!rl) return 0;

    const char *key = "testuser3:10.0.0.3";
    int ok = 1;

    /* Record some failures */
    rate_limiter_record_failure(rl, key);
    rate_limiter_record_failure(rl, key);

    /* Reset */
    rate_limiter_reset(rl, key);

    /* Should be allowed again */
    int check = rate_limiter_check(rl, key);
    ok = ok && (check == 0);

    /* State should not exist */
    rate_limit_state_t state;
    ok = ok && !rate_limiter_get_state(rl, key, &state);

    rate_limiter_destroy(rl);
    return ok;
}

/* Test build key function */
static int test_build_key(void)
{
    char key[256];

    rate_limiter_build_key("alice", "192.168.1.100", key, sizeof(key));
    if (strcmp(key, "alice:192.168.1.100") != 0) return 0;

    rate_limiter_build_key(NULL, "10.0.0.1", key, sizeof(key));
    if (strcmp(key, "unknown:10.0.0.1") != 0) return 0;

    rate_limiter_build_key("bob", NULL, key, sizeof(key));
    if (strcmp(key, "bob:local") != 0) return 0;

    return 1;
}

/* Test disabled rate limiter */
static int test_disabled(void)
{
    rate_limiter_config_t config = {
        .enabled = false,
        .state_dir = (char *)test_state_dir,
        .max_attempts = 1,
        .initial_lockout_sec = 10,
        .max_lockout_sec = 60,
        .backoff_multiplier = 2.0
    };

    rate_limiter_t *rl = rate_limiter_init(&config);
    if (!rl) return 0;

    const char *key = "testuser4:10.0.0.4";

    /* Even with many failures, should not be locked out when disabled */
    rate_limiter_record_failure(rl, key);
    rate_limiter_record_failure(rl, key);
    rate_limiter_record_failure(rl, key);

    int check = rate_limiter_check(rl, key);

    rate_limiter_destroy(rl);
    return (check == 0);  /* Should always be allowed when disabled */
}

int main(void)
{
    printf("Running rate limiter tests...\n\n");

    setup();

    TEST(init);
    TEST(new_key_allowed);
    TEST(failures_before_lockout);
    TEST(lockout_after_max_attempts);
    TEST(reset);
    TEST(build_key);
    TEST(disabled);

    cleanup();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
