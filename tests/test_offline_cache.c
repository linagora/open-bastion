/*
 * test_offline_cache.c - Unit tests for offline credential cache
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>

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

/*
 * Create test directory.
 *
 * mkdtemp, not "/tmp/test_offline_cache_<pid>": that name is reproducible, and
 * mkdir's EEXIST was accepted, so a directory left behind by an earlier run
 * that died before cleanup_test_dir() -- a killed CI job, a crash -- would be
 * silently reused with its entries in place. In a container PIDs restart low
 * and repeat, which makes the collision likely rather than theoretical (#244).
 */
static int setup_test_dir(void)
{
    snprintf(test_dir, sizeof(test_dir), "/tmp/test_offline_cache_XXXXXX");
    if (mkdtemp(test_dir) == NULL) {
        perror("mkdtemp");
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

/* Test: Initialize and destroy cache */
static int test_init_destroy(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);
    offline_cache_destroy(cache);
    return 1;
}

/* Test: Init with NULL directory fails */
static int test_init_null(void)
{
    offline_cache_t *cache = offline_cache_init(NULL, NULL);
    ASSERT(cache == NULL);
    return 1;
}

/* Test: Store and verify credentials */
static int test_store_verify(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store credentials */
    int ret = offline_cache_store(cache, "testuser", "testpass123", 3600,
                                  "Test User", "/bin/bash", "/home/testuser");
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify with correct password */
    offline_cache_entry_t entry;
    ret = offline_cache_verify(cache, "testuser", "testpass123", &entry);
    ASSERT(ret == OFFLINE_CACHE_OK);
    ASSERT(strcmp(entry.user, "testuser") == 0);
    ASSERT(strcmp(entry.gecos, "Test User") == 0);
    ASSERT(strcmp(entry.shell, "/bin/bash") == 0);
    ASSERT(strcmp(entry.home, "/home/testuser") == 0);
    ASSERT(entry.failed_attempts == 0);
    offline_cache_entry_free(&entry);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Verify with wrong password fails */
static int test_wrong_password(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store credentials */
    int ret = offline_cache_store(cache, "testuser2", "correct_pass", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify with wrong password */
    ret = offline_cache_verify(cache, "testuser2", "wrong_pass", NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_PASSWORD);

    /* Check that failed attempts was incremented */
    offline_cache_entry_t entry;
    ret = offline_cache_get_entry(cache, "testuser2", &entry);
    ASSERT(ret == OFFLINE_CACHE_OK);
    ASSERT(entry.failed_attempts == 1);
    offline_cache_entry_free(&entry);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: User not found */
static int test_user_not_found(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    int ret = offline_cache_verify(cache, "nonexistent", "anypass", NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_NOTFOUND);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Entry expiration */
static int test_expiration(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /*
     * 2 seconds, not 1. store() writes expires_at = now + ttl and verify()
     * expires on now >= expires_at, both at one-second granularity, so with
     * ttl = 1 the immediate verify below fails whenever a wall-clock second
     * boundary happens to fall between store()'s time() (offline_cache.c:618,
     * taken after the Argon2id hash) and verify()'s (offline_cache.c:1180,
     * taken after the read and decrypt). That window is short but real: it
     * contains the AES-GCM encrypt, the write and an fsync(), measured at
     * 0.09 ms with the cache on tmpfs and 1.7 ms on ext4, i.e. a 0.01% to
     * 0.2% chance per run -- and higher on a CI runner with a contended
     * disk, which is where the flake of #244 was seen.
     *
     * With ttl = 2 the immediate verify would need a full second to elapse
     * inside that window, so it cannot lose the race, and sleep(3) still
     * guarantees expiry. The assertions are unchanged; only their timing
     * margin is.
     */
    int ret = offline_cache_store(cache, "expiring_user", "pass", 2,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify immediately should work */
    ret = offline_cache_verify(cache, "expiring_user", "pass", NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Wait for expiration */
    sleep(3);

    /* Verify after expiration should fail */
    ret = offline_cache_verify(cache, "expiring_user", "pass", NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_EXPIRED);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Invalidate entry */
static int test_invalidate(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store credentials */
    int ret = offline_cache_store(cache, "user_to_remove", "pass", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify entry exists */
    ASSERT(offline_cache_has_entry(cache, "user_to_remove"));

    /* Invalidate */
    ret = offline_cache_invalidate(cache, "user_to_remove");
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify entry is gone */
    ASSERT(!offline_cache_has_entry(cache, "user_to_remove"));

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Lockout after max failures */
static int test_lockout(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store credentials */
    int ret = offline_cache_store(cache, "lockout_user", "secret", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Fail MAX_FAILED_ATTEMPTS times */
    for (int i = 0; i < OFFLINE_CACHE_MAX_FAILED_ATTEMPTS; i++) {
        ret = offline_cache_verify(cache, "lockout_user", "wrong", NULL);
        ASSERT(ret == OFFLINE_CACHE_ERR_PASSWORD);
    }

    /* Next attempt should be locked */
    ret = offline_cache_verify(cache, "lockout_user", "secret", NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_LOCKED);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Reset failures */
static int test_reset_failures(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store credentials */
    int ret = offline_cache_store(cache, "reset_user", "pass123", 3600,
                                  NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Fail a few times */
    offline_cache_verify(cache, "reset_user", "wrong1", NULL);
    offline_cache_verify(cache, "reset_user", "wrong2", NULL);

    /* Check failures incremented */
    offline_cache_entry_t entry;
    ret = offline_cache_get_entry(cache, "reset_user", &entry);
    ASSERT(ret == OFFLINE_CACHE_OK);
    ASSERT(entry.failed_attempts == 2);
    offline_cache_entry_free(&entry);

    /* Reset failures */
    ret = offline_cache_reset_failures(cache, "reset_user");
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Check failures are 0 */
    ret = offline_cache_get_entry(cache, "reset_user", &entry);
    ASSERT(ret == OFFLINE_CACHE_OK);
    ASSERT(entry.failed_attempts == 0);
    offline_cache_entry_free(&entry);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Cleanup expired entries */
static int test_cleanup(void)
{
    if (!has_machine_id()) return 2;

    /* Create fresh test directory for this test to avoid interference.
     * test_dir is already unique (mkdtemp), so a fixed name is enough. */
    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/cleanup", test_dir);
    if (mkdir(fresh_dir, 0700) != 0 && errno != EEXIST) {
        printf("(mkdir %s: %s) ", fresh_dir, strerror(errno));
        return 0;
    }

    offline_cache_t *cache = offline_cache_init(fresh_dir, NULL);
    ASSERT(cache != NULL);

    /* Store some entries. ttl = 1 is safe here, unlike in test_expiration:
     * nothing is asserted about user1 before it expires, and the assertions
     * below are all on the expired side of the boundary. */
    int r1 = offline_cache_store(cache, "cleanup_user1", "pass", 1, NULL, NULL, NULL);
    ASSERT(r1 == OFFLINE_CACHE_OK);
    int r2 = offline_cache_store(cache, "cleanup_user2", "pass", 3600, NULL, NULL, NULL);
    ASSERT(r2 == OFFLINE_CACHE_OK);

    /* Wait for first to expire */
    sleep(2);

    /* Cleanup */
    int removed = offline_cache_cleanup(cache);
    ASSERT(removed >= 1);  /* At least the expired entry should be removed */

    /* Verify only user2 remains */
    ASSERT(!offline_cache_has_entry(cache, "cleanup_user1"));
    ASSERT(offline_cache_has_entry(cache, "cleanup_user2"));

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Cache stats */
static int test_stats(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store some entries */
    ASSERT(offline_cache_store(cache, "stats_user1", "pass", 3600, NULL, NULL, NULL) == OFFLINE_CACHE_OK);
    ASSERT(offline_cache_store(cache, "stats_user2", "pass", 3600, NULL, NULL, NULL) == OFFLINE_CACHE_OK);
    ASSERT(offline_cache_store(cache, "stats_user3", "pass", 3600, NULL, NULL, NULL) == OFFLINE_CACHE_OK);

    int total = 0, active = 0, locked = 0;
    int ret = offline_cache_stats(cache, &total, &active, &locked);
    ASSERT(ret == OFFLINE_CACHE_OK);
    ASSERT(total >= 3);  /* May have entries from other tests */
    ASSERT(active >= 3);
    ASSERT(locked >= 0);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Invalidate all */
static int test_invalidate_all(void)
{
    if (!has_machine_id()) return 2;

    /* Create fresh test directory for this test */
    char fresh_dir[256];
    snprintf(fresh_dir, sizeof(fresh_dir), "%s/fresh", test_dir);
    if (mkdir(fresh_dir, 0700) != 0 && errno != EEXIST) {
        printf("(mkdir %s: %s) ", fresh_dir, strerror(errno));
        return 0;
    }

    offline_cache_t *cache = offline_cache_init(fresh_dir, NULL);
    ASSERT(cache != NULL);

    /* Store some entries */
    int r1 = offline_cache_store(cache, "all_user1", "pass", 3600, NULL, NULL, NULL);
    ASSERT(r1 == OFFLINE_CACHE_OK);
    int r2 = offline_cache_store(cache, "all_user2", "pass", 3600, NULL, NULL, NULL);
    ASSERT(r2 == OFFLINE_CACHE_OK);

    /* Verify entries exist */
    ASSERT(offline_cache_has_entry(cache, "all_user1"));
    ASSERT(offline_cache_has_entry(cache, "all_user2"));

    /* Invalidate all */
    int ret = offline_cache_invalidate_all(cache);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify all gone */
    ASSERT(!offline_cache_has_entry(cache, "all_user1"));
    ASSERT(!offline_cache_has_entry(cache, "all_user2"));

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Overwrite existing entry */
static int test_overwrite(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store initial credentials */
    int ret = offline_cache_store(cache, "overwrite_user", "old_pass", 3600,
                                  "Old Name", NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Verify with old password */
    ret = offline_cache_verify(cache, "overwrite_user", "old_pass", NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Store new credentials (should overwrite) */
    ret = offline_cache_store(cache, "overwrite_user", "new_pass", 3600,
                              "New Name", NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Old password should fail */
    ret = offline_cache_verify(cache, "overwrite_user", "old_pass", NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_PASSWORD);

    /* New password should work */
    offline_cache_entry_t entry;
    ret = offline_cache_verify(cache, "overwrite_user", "new_pass", &entry);
    ASSERT(ret == OFFLINE_CACHE_OK);
    ASSERT(strcmp(entry.gecos, "New Name") == 0);
    offline_cache_entry_free(&entry);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Error string conversion */
static int test_strerror(void)
{
    const char *msg;

    msg = offline_cache_strerror(OFFLINE_CACHE_OK);
    ASSERT(msg != NULL);
    ASSERT(strcmp(msg, "Success") == 0);

    msg = offline_cache_strerror(OFFLINE_CACHE_ERR_NOTFOUND);
    ASSERT(msg != NULL);
    ASSERT(strstr(msg, "not found") != NULL);

    msg = offline_cache_strerror(OFFLINE_CACHE_ERR_PASSWORD);
    ASSERT(msg != NULL);
    ASSERT(strstr(msg, "mismatch") != NULL);

    msg = offline_cache_strerror(-100);
    ASSERT(msg != NULL);
    ASSERT(strstr(msg, "Unknown") != NULL);

    msg = offline_cache_strerror(1);
    ASSERT(msg != NULL);
    ASSERT(strstr(msg, "Unknown") != NULL);

    for (int code = OFFLINE_CACHE_ERR_NOMEM; code >= OFFLINE_CACHE_ERR_PASSWORD; code--) {
        msg = offline_cache_strerror(code);
        ASSERT(msg != NULL);
        ASSERT(strcmp(msg, "Unknown error") != 0);
    }

    return 1;
}

/* Test: Store with NULL parameters */
static int test_store_null_params(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* NULL cache */
    int ret = offline_cache_store(NULL, "user", "pass", 3600, NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_INVALID);

    /* NULL user */
    ret = offline_cache_store(cache, NULL, "pass", 3600, NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_INVALID);

    /* NULL password */
    ret = offline_cache_store(cache, "user", NULL, 3600, NULL, NULL, NULL);
    ASSERT(ret == OFFLINE_CACHE_ERR_INVALID);

    offline_cache_destroy(cache);
    return 1;
}

/* Test: Entry with all optional fields */
static int test_full_entry(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Store with all fields */
    int ret = offline_cache_store(cache, "full_user", "full_pass", 7200,
                                  "Full User Name", "/bin/zsh", "/home/full_user");
    ASSERT(ret == OFFLINE_CACHE_OK);

    /* Get entry and verify all fields */
    offline_cache_entry_t entry;
    ret = offline_cache_get_entry(cache, "full_user", &entry);
    ASSERT(ret == OFFLINE_CACHE_OK);
    ASSERT(entry.version == OFFLINE_CACHE_VERSION);
    ASSERT(strcmp(entry.user, "full_user") == 0);
    ASSERT(strcmp(entry.gecos, "Full User Name") == 0);
    ASSERT(strcmp(entry.shell, "/bin/zsh") == 0);
    ASSERT(strcmp(entry.home, "/home/full_user") == 0);
    ASSERT(entry.created_at > 0);
    ASSERT(entry.expires_at > entry.created_at);
    ASSERT(entry.failed_attempts == 0);
    ASSERT(entry.locked_until == 0);
    offline_cache_entry_free(&entry);

    offline_cache_destroy(cache);
    return 1;
}

/*
 * Concurrency regression for #186.
 *
 * PAM runs one process per authentication attempt, so failed_attempts is
 * updated by concurrent processes. Before the fix offline_cache_verify() did
 * its read-decrypt-mutate-encrypt-write with no inter-process lock: N parallel
 * wrong-password attempts each read the same counter and each wrote count+1,
 * so max_failed_attempts was never reached and the lockout could be bypassed.
 *
 * The children are released together by a pipe barrier (no sleeps) and the
 * expected value is exact, so this is a deterministic assertion.
 */
#define OC_CONC_CHILDREN 6

static int test_concurrent_failed_attempts(void)
{
    if (!has_machine_id()) return 2;
    offline_cache_t *cache = offline_cache_init(test_dir, NULL);
    ASSERT(cache != NULL);

    /* Keep the threshold out of reach: a lockout would make later attempts
     * return ERR_LOCKED without incrementing and blur the exact-N assertion. */
    offline_cache_set_lockout(cache, OC_CONC_CHILDREN + 1, 3600);

    int ret = offline_cache_store(cache, "concurrent_user", "correct_pass",
                                  3600, NULL, NULL, NULL);
    if (ret != OFFLINE_CACHE_OK) {
        offline_cache_destroy(cache);
        ASSERT(ret == OFFLINE_CACHE_OK);
    }

    int barrier[2];
    if (pipe(barrier) != 0) {
        printf("(pipe failed: %s) ", strerror(errno));
        offline_cache_destroy(cache);
        return 0;
    }

    int started = 0;
    int ok = 1;
    for (int i = 0; i < OC_CONC_CHILDREN; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            printf("(fork %d/%d failed: %s) ",
                   i + 1, OC_CONC_CHILDREN, strerror(errno));
            ok = 0;
            break;
        }
        if (pid == 0) {
            close(barrier[1]);
            /* Block until the parent releases every child at once. */
            char c;
            ssize_t r;
            do {
                r = read(barrier[0], &c, 1);
            } while (r < 0 && errno == EINTR);
            close(barrier[0]);

            /* The exit status carries the verdict, encoded so the parent can
             * name it: 0 for the expected wrong-password result, the negated
             * error code (1..8) for anything else, 127 for the one case that
             * must never be mistaken for success — a wrong password that
             * verified.
             *
             * This channel does NOT cover the lost-increment mode of #186:
             * there the write is what is lost (lock_cache_entry() fails and
             * the read-modify-write runs unlocked, or update_cache_entry()'s
             * return is discarded at offline_cache.c:1268), while verify()
             * still returns ERR_PASSWORD, so every child exits 0. That mode
             * is caught by the exact-N counter assertion below, and shows up
             * exactly as the bare "(failed_attempts=5 expected=6)" it always
             * did. What this adds is a name for the *other* failures: a child
             * that errored out early, or one that was killed. */
            int cret = offline_cache_verify(cache, "concurrent_user",
                                            "wrong_pass", NULL);
            int code;
            if (cret == OFFLINE_CACHE_ERR_PASSWORD)      code = 0;
            else if (cret < 0 && cret >= -8)             code = -cret;
            else                                          code = 127;
            _exit(code);
        }
        started++;
    }

    close(barrier[0]);
    for (int i = 0; i < started; i++) {
        if (write(barrier[1], "g", 1) != 1) {
            printf("(barrier write %d/%d failed: %s) ",
                   i + 1, started, strerror(errno));
            ok = 0;
            break;
        }
    }
    close(barrier[1]);

    for (int i = 0; i < started; i++) {
        int status;
        if (wait(&status) < 0) {
            printf("(wait failed: %s) ", strerror(errno));
            ok = 0;
            continue;
        }
        if (!WIFEXITED(status)) {
            printf("(child killed by signal %d) ",
                   WIFSIGNALED(status) ? WTERMSIG(status) : 0);
            ok = 0;
        } else if (WEXITSTATUS(status) != 0) {
            int code = WEXITSTATUS(status);
            if (code == 127)
                printf("(a child's verify ACCEPTED the wrong password) ");
            else
                printf("(a child's verify returned %s) ",
                       offline_cache_strerror(-code));
            ok = 0;
        }
    }

    if (started != OC_CONC_CHILDREN) {
        printf("(started=%d expected=%d) ", started, OC_CONC_CHILDREN);
        ok = 0;
    }

    offline_cache_entry_t entry;
    int gret = offline_cache_get_entry(cache, "concurrent_user", &entry);
    if (gret == OFFLINE_CACHE_OK) {
        /* Against `started`, not OC_CONC_CHILDREN: when a fork failed, the
         * children that did run each incremented correctly, and comparing to
         * the full count would print a second, false layer of failure that
         * reads as a cache-integrity regression on top of the fork error. */
        if (entry.failed_attempts != started) {
            printf("(failed_attempts=%d expected=%d) ",
                   entry.failed_attempts, started);
            ok = 0;
        }
        offline_cache_entry_free(&entry);
    } else {
        printf("(get_entry failed: %s) ", offline_cache_strerror(gret));
        ok = 0;
    }

    offline_cache_invalidate(cache, "concurrent_user");
    offline_cache_destroy(cache);
    return ok;
}

int main(void)
{
    printf("Running offline cache tests...\n");

    if (setup_test_dir() != 0) {
        fprintf(stderr, "Failed to create test directory\n");
        return 1;
    }

    /* Run tests */
    TEST(init_destroy);
    TEST(init_null);
    TEST(store_verify);
    TEST(wrong_password);
    TEST(user_not_found);
    TEST(expiration);
    TEST(invalidate);
    TEST(lockout);
    TEST(reset_failures);
    TEST(cleanup);
    TEST(stats);
    TEST(invalidate_all);
    TEST(overwrite);
    TEST(strerror);
    TEST(store_null_params);
    TEST(full_entry);
    TEST(concurrent_failed_attempts);

    cleanup_test_dir();

    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
