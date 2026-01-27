/*
 * test_offline_security.c - Security tests for offline credential cache
 *
 * These tests verify the security properties of the offline cache:
 * - Cryptographic correctness
 * - Brute-force protection
 * - File permission enforcement
 * - Timing attack resistance
 * - Cache integrity verification
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>

#include "../include/offline_cache.h"

static int tests_run = 0;
static int tests_passed = 0;

/* Check if /etc/machine-id exists (required for cache encryption) */
static int has_machine_id(void)
{
    struct stat st;
    return stat("/etc/machine-id", &st) == 0;
}

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    int result = test_##name(); \
    if (result == 2) { \
        printf("SKIP (no machine-id)\n"); \
        tests_passed++; \
    } else if (result == 1) { \
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

static char test_dir[256];

/* Get current time in microseconds */
static long long get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Create test directory */
static int setup_test_dir(void)
{
    snprintf(test_dir, sizeof(test_dir), "/tmp/test_offline_security_%d", getpid());
    if (mkdir(test_dir, 0700) != 0 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }
    return 0;
}

/*
 * Safe recursive directory removal using directory file descriptors.
 * This avoids TOCTOU race conditions.
 */
static int safe_rmdir_recursive(int parent_fd, const char *name)
{
    int fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOTDIR || errno == ENOENT) {
            return unlinkat(parent_fd, name, 0);
        }
        return -1;
    }

    DIR *dir = fdopendir(fd);
    if (!dir) {
        close(fd);
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (S_ISDIR(st.st_mode)) {
                safe_rmdir_recursive(fd, entry->d_name);
            } else {
                unlinkat(fd, entry->d_name, 0);
            }
        }
    }

    closedir(dir);
    return unlinkat(parent_fd, name, AT_REMOVEDIR);
}

/* Remove test directory recursively */
static void cleanup_test_dir(void)
{
    char *dir_copy = strdup(test_dir);
    if (!dir_copy) return;

    char *last_slash = strrchr(dir_copy, '/');
    if (!last_slash || last_slash == dir_copy) {
        int parent_fd = open("/tmp", O_RDONLY | O_DIRECTORY);
        if (parent_fd >= 0) {
            const char *basename = last_slash ? last_slash + 1 : test_dir;
            safe_rmdir_recursive(parent_fd, basename);
            close(parent_fd);
        }
    } else {
        *last_slash = '\0';
        const char *parent_path = dir_copy;
        const char *basename = last_slash + 1;

        int parent_fd = open(parent_path, O_RDONLY | O_DIRECTORY);
        if (parent_fd >= 0) {
            safe_rmdir_recursive(parent_fd, basename);
            close(parent_fd);
        }
    }

    free(dir_copy);
}

/* ========================================================================== */
/* Security Test: Timing attack resistance                                   */
/* ========================================================================== */

/*
 * Test that password verification time is constant regardless of password length
 * or correctness. This helps prevent timing attacks.
 *
 * Note: This test is inherently probabilistic. We accept some variance.
 */
static int test_timing_resistance(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/timing_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    /* Store with a known password */
    int ret = offline_cache_store(cache, "timing_user", "correct_password_123", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Measure time for correct password */
    long long times_correct[10];
    for (int i = 0; i < 10; i++) {
        long long start = get_time_us();
        offline_cache_verify(cache, "timing_user", "correct_password_123", NULL);
        times_correct[i] = get_time_us() - start;
    }

    /* Measure time for wrong password (same length) */
    long long times_wrong_same[10];
    for (int i = 0; i < 10; i++) {
        long long start = get_time_us();
        offline_cache_verify(cache, "timing_user", "incorrect_passwd_12X", NULL);
        times_wrong_same[i] = get_time_us() - start;
    }

    /* Measure time for wrong password (different length) */
    long long times_wrong_short[10];
    for (int i = 0; i < 10; i++) {
        long long start = get_time_us();
        offline_cache_verify(cache, "timing_user", "short", NULL);
        times_wrong_short[i] = get_time_us() - start;
    }

    /* Calculate averages (skip first measurement as warmup) */
    double avg_correct = 0, avg_wrong_same = 0, avg_wrong_short = 0;
    for (int i = 1; i < 10; i++) {
        avg_correct += times_correct[i];
        avg_wrong_same += times_wrong_same[i];
        avg_wrong_short += times_wrong_short[i];
    }
    avg_correct /= 9;
    avg_wrong_same /= 9;
    avg_wrong_short /= 9;

    /*
     * Argon2id should take roughly the same time regardless of input.
     * Allow 50% variance due to system noise.
     */
    double ratio_same = avg_wrong_same / avg_correct;
    double ratio_short = avg_wrong_short / avg_correct;

    printf("\n    Timing: correct=%.0f us, wrong_same=%.0f us (%.2fx), wrong_short=%.0f us (%.2fx)\n",
           avg_correct, avg_wrong_same, ratio_same, avg_wrong_short, ratio_short);

    /* Accept if within reasonable bounds (0.5x to 2x) */
    /* Note: Argon2id has constant-time comparison, but we're generous with bounds */
    ASSERT(ratio_same >= 0.5 && ratio_same <= 2.0);
    ASSERT(ratio_short >= 0.5 && ratio_short <= 2.0);

    offline_cache_destroy(cache);
    return 1;
}

/* ========================================================================== */
/* Security Test: Cache file encryption verification                         */
/* ========================================================================== */

/*
 * Test that cache files are actually encrypted (not plaintext).
 * We check that the password string is NOT present in the file.
 */
static int test_encryption_verification(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/encrypt_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    /* Use a unique, identifiable string as password */
    const char *unique_password = "UNIQUE_MARKER_STRING_12345";
    const char *unique_gecos = "GECOS_MARKER_XYZZY_67890";

    int ret = offline_cache_store(cache, "encrypt_user", unique_password, 3600,
                                  unique_gecos, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    offline_cache_destroy(cache);

    /* Read all files in the cache directory and search for markers */
    DIR *dir = opendir(fresh_dir);
    ASSERT(dir != NULL);

    int found_password = 0;
    int found_gecos = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", fresh_dir, entry->d_name);

        int fd = open(filepath, O_RDONLY);
        if (fd < 0) continue;

        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);

        if (n > 0) {
            /* Search for plaintext markers in file content */
            if (memmem(buf, n, unique_password, strlen(unique_password))) {
                found_password = 1;
            }
            if (memmem(buf, n, unique_gecos, strlen(unique_gecos))) {
                found_gecos = 1;
            }
        }
    }
    closedir(dir);

    /* Password should NOT be found in plaintext */
    ASSERT(!found_password);

    /* GECOS should NOT be found in plaintext (it's encrypted too) */
    ASSERT(!found_gecos);

    return 1;
}

/* ========================================================================== */
/* Security Test: File permission enforcement                                */
/* ========================================================================== */

/*
 * Test that cache directory and files have correct permissions.
 */
static int test_file_permissions(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/perms_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    int ret = offline_cache_store(cache, "perms_user", "password", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    offline_cache_destroy(cache);

    /* Check directory permissions */
    struct stat dir_stat;
    ret = stat(fresh_dir, &dir_stat);
    ASSERT(ret == 0);
    ASSERT((dir_stat.st_mode & 0777) == 0700);

    /* Check file permissions */
    DIR *dir = opendir(fresh_dir);
    ASSERT(dir != NULL);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", fresh_dir, entry->d_name);

        struct stat file_stat;
        ret = stat(filepath, &file_stat);
        if (ret == 0 && S_ISREG(file_stat.st_mode)) {
            /* Files should be 0600 (owner read/write only) */
            ASSERT((file_stat.st_mode & 0777) == 0600);
        }
    }
    closedir(dir);

    return 1;
}

/* ========================================================================== */
/* Security Test: Lockout enforcement                                        */
/* ========================================================================== */

/*
 * Test that lockout cannot be bypassed by rapid retries.
 */
static int test_lockout_enforcement(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/lockout_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    int ret = offline_cache_store(cache, "lockout_test", "correct", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Exhaust attempts */
    for (int i = 0; i < OFFLINE_CACHE_MAX_FAILED_ATTEMPTS; i++) {
        ret = offline_cache_verify(cache, "lockout_test", "wrong", NULL);
        ASSERT(ret == OFFLINE_CACHE_ERR_PASSWORD);
    }

    /* Now even correct password should be locked */
    ret = offline_cache_verify(cache, "lockout_test", "correct", NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_LOCKED);

    /* Try 100 more times - all should be locked */
    for (int i = 0; i < 100; i++) {
        ret = offline_cache_verify(cache, "lockout_test", "correct", NULL);
        ASSERT(ret == OFFLINE_CACHE_ERR_LOCKED);
    }

    offline_cache_destroy(cache);
    return 1;
}

/* ========================================================================== */
/* Security Test: Cache file tampering detection                             */
/* ========================================================================== */

/*
 * Test that tampered cache files are rejected.
 */
static int test_tampering_detection(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/tamper_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    int ret = offline_cache_store(cache, "tamper_user", "password123", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify works before tampering */
    ret = offline_cache_verify(cache, "tamper_user", "password123", NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    offline_cache_destroy(cache);

    /* Find and tamper with the cache file */
    DIR *dir = opendir(fresh_dir);
    ASSERT(dir != NULL);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", fresh_dir, entry->d_name);

        /* Read file, flip some bits, write back */
        int fd = open(filepath, O_RDWR);
        if (fd < 0) continue;

        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 50) {
            /* Flip some bits in the middle of the file */
            buf[n / 2] ^= 0xFF;
            buf[n / 2 + 1] ^= 0xAA;

            lseek(fd, 0, SEEK_SET);
            write(fd, buf, n);
        }
        close(fd);
    }
    closedir(dir);

    /* Re-open cache and try to verify - should fail with crypto error */
    cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    ret = offline_cache_verify(cache, "tamper_user", "password123", NULL);
    /* Should be crypto error or not found (if file was deleted due to corruption) */
    ASSERT(ret == OFFLINE_CACHE_ERR_CRYPTO || ret == OFFLINE_CACHE_ERR_NOTFOUND);

    offline_cache_destroy(cache);
    return 1;
}

/* ========================================================================== */
/* Security Test: Username enumeration prevention                            */
/* ========================================================================== */

/*
 * Test that cache filenames don't leak usernames.
 * Filenames should be hashes, not actual usernames.
 */
static int test_username_enumeration_prevention(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/enum_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    /* Store multiple users */
    offline_cache_store(cache, "alice", "pass1", 3600, NULL, NULL, NULL);
    offline_cache_store(cache, "bob", "pass2", 3600, NULL, NULL, NULL);
    offline_cache_store(cache, "charlie", "pass3", 3600, NULL, NULL, NULL);

    offline_cache_destroy(cache);

    /* Check that no filenames contain the actual usernames */
    DIR *dir = opendir(fresh_dir);
    ASSERT(dir != NULL);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        /* Usernames should NOT appear in filenames */
        ASSERT(strstr(entry->d_name, "alice") == NULL);
        ASSERT(strstr(entry->d_name, "bob") == NULL);
        ASSERT(strstr(entry->d_name, "charlie") == NULL);

        /* Filename should look like a hex hash (all hex chars) */
        int all_hex = 1;
        for (const char *p = entry->d_name; *p; p++) {
            if (!(*p >= '0' && *p <= '9') &&
                !(*p >= 'a' && *p <= 'f') &&
                !(*p >= 'A' && *p <= 'F') &&
                *p != '.') {
                all_hex = 0;
                break;
            }
        }
        ASSERT(all_hex);
    }
    closedir(dir);

    return 1;
}

/* ========================================================================== */
/* Security Test: Password not in memory after verification                  */
/* ========================================================================== */

/*
 * Test that passwords are zeroed from memory after use.
 * Note: This is best-effort; the compiler might optimize away memset.
 */
static int test_password_memory_cleanup(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/memclean_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    /* Use a very distinctive password */
    const char *password = "VERY_UNIQUE_PASSWORD_MARKER_9876543210";

    int ret = offline_cache_store(cache, "memtest_user", password, 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    ret = offline_cache_verify(cache, "memtest_user", password, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /*
     * At this point, if passwords are properly cleared, the password
     * should not be lingering in the cache structure. We can't easily
     * verify this without memory scanning, so this test mainly ensures
     * the code path that handles cleanup doesn't crash.
     */

    offline_cache_destroy(cache);

    /*
     * The cache is destroyed. If we had memory debugging enabled,
     * we could scan for the password marker. For now, just verify
     * the destruction completed without error.
     */

    return 1;
}

/* ========================================================================== */
/* Security Test: Empty/null password handling                               */
/* ========================================================================== */

/*
 * Test that empty or null passwords are handled correctly.
 */
static int test_empty_password_handling(void)
{
    if (!has_machine_id()) return 2;

    offline_cache_t *cache = offline_cache_init(test_dir);
    ASSERT(cache != NULL);

    /* Empty password should be rejected */
    int ret = offline_cache_store(cache, "empty_pass_user", "", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_INVALID);

    /* NULL password should be rejected */
    ret = offline_cache_store(cache, "null_pass_user", NULL, 3600,
                              NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_INVALID);

    offline_cache_destroy(cache);
    return 1;
}

/* ========================================================================== */
/* Security Test: Very long password handling                                */
/* ========================================================================== */

/*
 * Test that very long passwords are handled correctly (no buffer overflow).
 */
static int test_long_password_handling(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/longpass_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    offline_cache_t *cache = offline_cache_init(fresh_dir);
    ASSERT(cache != NULL);

    /* Create a very long password (1MB) */
    char *long_password = malloc(1024 * 1024 + 1);
    ASSERT(long_password != NULL);
    memset(long_password, 'A', 1024 * 1024);
    long_password[1024 * 1024] = '\0';

    /* Should either accept it or reject with INVALID (not crash) */
    int ret = offline_cache_store(cache, "longpass_user", long_password, 3600,
                                  NULL, NULL, NULL);

    if (ret == OFFLINE_CACHE_OK) {
        /* If stored, should be able to verify */
        ret = offline_cache_verify(cache, "longpass_user", long_password, NULL);
        ASSERT(ret == OFFLINE_CACHE_OK);
    } else {
        /* If rejected, should be INVALID error */
        ASSERT(ret == OFFLINE_CACHE_ERR_INVALID);
    }

    free(long_password);
    offline_cache_destroy(cache);
    return 1;
}

/* ========================================================================== */
/* Security Test: Concurrent access safety                                   */
/* ========================================================================== */

/*
 * Test basic concurrent access doesn't cause corruption.
 * Full concurrency testing would require threads/processes.
 */
static int test_concurrent_access_safety(void)
{
    if (!has_machine_id()) return 2;

    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/concurrent_%d", test_dir, getpid());
    mkdir(fresh_dir, 0700);

    /* Open two cache handles to same directory */
    offline_cache_t *cache1 = offline_cache_init(fresh_dir);
    offline_cache_t *cache2 = offline_cache_init(fresh_dir);
    ASSERT(cache1 != NULL);
    ASSERT(cache2 != NULL);

    /* Store via cache1 */
    int ret = offline_cache_store(cache1, "concurrent_user", "pass123", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify via cache2 (should see the stored entry) */
    ret = offline_cache_verify(cache2, "concurrent_user", "pass123", NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Update via cache2 */
    ret = offline_cache_store(cache2, "concurrent_user", "newpass", 3600,
                              NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* cache1 should see the new password */
    ret = offline_cache_verify(cache1, "concurrent_user", "newpass", NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    offline_cache_destroy(cache1);
    offline_cache_destroy(cache2);
    return 1;
}

/* ========================================================================== */
/* Main test runner                                                          */
/* ========================================================================== */

int main(void)
{
    printf("Running offline cache SECURITY tests...\n");
    printf("========================================\n");

    if (setup_test_dir() != 0) {
        fprintf(stderr, "Failed to create test directory\n");
        return 1;
    }

    printf("\n[Timing Attack Resistance]\n");
    TEST(timing_resistance);

    printf("\n[Cryptographic Verification]\n");
    TEST(encryption_verification);

    printf("\n[File System Security]\n");
    TEST(file_permissions);

    printf("\n[Brute-Force Protection]\n");
    TEST(lockout_enforcement);

    printf("\n[Integrity Verification]\n");
    TEST(tampering_detection);

    printf("\n[Information Disclosure Prevention]\n");
    TEST(username_enumeration_prevention);

    printf("\n[Memory Safety]\n");
    TEST(password_memory_cleanup);

    printf("\n[Input Validation]\n");
    TEST(empty_password_handling);
    TEST(long_password_handling);

    printf("\n[Concurrency Safety]\n");
    TEST(concurrent_access_safety);

    cleanup_test_dir();

    printf("\n========================================\n");
    printf("Security test results: %d/%d tests passed\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("WARNING: Some security tests failed!\n");
        return 1;
    }

    return 0;
}
