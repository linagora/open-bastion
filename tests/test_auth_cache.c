/*
 * test_auth_cache.c - Unit tests for authorization cache
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include "../include/auth_cache.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    if (test_##name()) { \
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

/* Create test directory */
static int setup_test_dir(void)
{
    snprintf(test_dir, sizeof(test_dir), "/tmp/test_auth_cache_%d", getpid());
    if (mkdir(test_dir, 0700) != 0 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }
    return 0;
}

/*
 * Safe recursive directory removal using directory file descriptors.
 * This avoids TOCTOU race conditions that exist with system("rm -rf").
 */
static int safe_rmdir_recursive(int parent_fd, const char *name)
{
    int fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) {
        /* Not a directory or doesn't exist - try to unlink as file */
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

    closedir(dir);  /* Also closes fd */
    return unlinkat(parent_fd, name, AT_REMOVEDIR);
}

/* Remove test directory recursively using safe method */
static void cleanup_test_dir(void)
{
    /* Extract parent directory and basename from test_dir */
    char *dir_copy = strdup(test_dir);
    if (!dir_copy) return;

    char *last_slash = strrchr(dir_copy, '/');
    if (!last_slash || last_slash == dir_copy) {
        /* Handle /tmp case or no slash */
        int parent_fd = open("/tmp", O_RDONLY | O_DIRECTORY);
        if (parent_fd >= 0) {
            /* Get just the directory name */
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
    auth_cache_t *cache = auth_cache_init(test_dir);
    ASSERT(cache != NULL);
    auth_cache_destroy(cache);
    return 1;
}

/* Test: Init with NULL directory fails */
static int test_init_null(void)
{
    auth_cache_t *cache = auth_cache_init(NULL);
    ASSERT(cache == NULL);
    return 1;
}

/* Test: Store and lookup entry */
static int test_store_lookup(void)
{
    auth_cache_t *cache = auth_cache_init(test_dir);
    ASSERT(cache != NULL);

    /* Create entry */
    auth_cache_entry_t entry = {
        .version = 3,
        .user = "testuser",
        .authorized = true,
        .groups = NULL,
        .groups_count = 0,
        .sudo_allowed = true,
        .sudo_nopasswd = false,
        .gecos = "Test User",
        .shell = "/bin/bash",
        .home = "/home/testuser"
    };

    /* Store with 60 second TTL */
    int ret = auth_cache_store(cache, "testuser", "default", "testhost", &entry, 60);
    ASSERT(ret == 0);

    /* Lookup */
    auth_cache_entry_t lookup_entry = {0};
    int found = auth_cache_lookup(cache, "testuser", "default", "testhost", &lookup_entry);
    ASSERT(found == true);
    ASSERT(lookup_entry.authorized == true);
    ASSERT(lookup_entry.sudo_allowed == true);
    ASSERT(lookup_entry.sudo_nopasswd == false);
    ASSERT(lookup_entry.user != NULL && strcmp(lookup_entry.user, "testuser") == 0);
    ASSERT(lookup_entry.gecos != NULL && strcmp(lookup_entry.gecos, "Test User") == 0);
    ASSERT(lookup_entry.shell != NULL && strcmp(lookup_entry.shell, "/bin/bash") == 0);
    ASSERT(lookup_entry.home != NULL && strcmp(lookup_entry.home, "/home/testuser") == 0);

    auth_cache_entry_free(&lookup_entry);
    auth_cache_destroy(cache);
    return 1;
}

/* Test: Lookup non-existent entry */
static int test_lookup_missing(void)
{
    auth_cache_t *cache = auth_cache_init(test_dir);
    ASSERT(cache != NULL);

    auth_cache_entry_t entry = {0};
    int found = auth_cache_lookup(cache, "nonexistent", "default", "testhost", &entry);
    ASSERT(found == false);

    auth_cache_destroy(cache);
    return 1;
}

/* Test: Lookup with different server_group */
static int test_lookup_different_group(void)
{
    auth_cache_t *cache = auth_cache_init(test_dir);
    ASSERT(cache != NULL);

    /* Store for group "web" */
    auth_cache_entry_t entry = {
        .version = 3,
        .user = "webuser",
        .authorized = true,
        .sudo_allowed = false
    };
    int ret = auth_cache_store(cache, "webuser", "web", "webhost", &entry, 60);
    ASSERT(ret == 0);

    /* Lookup with different group should fail */
    auth_cache_entry_t lookup = {0};
    int found = auth_cache_lookup(cache, "webuser", "database", "webhost", &lookup);
    ASSERT(found == false);

    /* Lookup with correct group should succeed */
    found = auth_cache_lookup(cache, "webuser", "web", "webhost", &lookup);
    ASSERT(found == true);
    auth_cache_entry_free(&lookup);

    auth_cache_destroy(cache);
    return 1;
}

/* Test: Invalidate entry */
static int test_invalidate(void)
{
    auth_cache_t *cache = auth_cache_init(test_dir);
    ASSERT(cache != NULL);

    /* Store entry */
    auth_cache_entry_t entry = {
        .version = 3,
        .user = "invaliduser",
        .authorized = true
    };
    int ret = auth_cache_store(cache, "invaliduser", "default", "host1", &entry, 60);
    ASSERT(ret == 0);

    /* Verify it exists */
    auth_cache_entry_t lookup = {0};
    int found = auth_cache_lookup(cache, "invaliduser", "default", "host1", &lookup);
    ASSERT(found == true);
    auth_cache_entry_free(&lookup);

    /* Invalidate */
    auth_cache_invalidate(cache, "invaliduser", "default", "host1");

    /* Verify it's gone */
    found = auth_cache_lookup(cache, "invaliduser", "default", "host1", &lookup);
    ASSERT(found == false);

    auth_cache_destroy(cache);
    return 1;
}

/* Test: Entry with groups */
static int test_entry_with_groups(void)
{
    auth_cache_t *cache = auth_cache_init(test_dir);
    ASSERT(cache != NULL);

    /* Create groups array */
    char *groups[] = {"admins", "developers", "users"};
    auth_cache_entry_t entry = {
        .version = 3,
        .user = "groupuser",
        .authorized = true,
        .groups = groups,
        .groups_count = 3,
        .sudo_allowed = true
    };

    int ret = auth_cache_store(cache, "groupuser", "default", "host2", &entry, 60);
    ASSERT(ret == 0);

    /* Lookup and verify groups */
    auth_cache_entry_t lookup = {0};
    int found = auth_cache_lookup(cache, "groupuser", "default", "host2", &lookup);
    ASSERT(found == true);
    ASSERT(lookup.groups_count == 3);
    ASSERT(lookup.groups != NULL);
    ASSERT(strcmp(lookup.groups[0], "admins") == 0);
    ASSERT(strcmp(lookup.groups[1], "developers") == 0);
    ASSERT(strcmp(lookup.groups[2], "users") == 0);

    auth_cache_entry_free(&lookup);
    auth_cache_destroy(cache);
    return 1;
}

/* Test: Force-online file (empty = all users) */
static int test_force_online_empty_file(void)
{
    char force_file[512];
    snprintf(force_file, sizeof(force_file), "%s/force_online", test_dir);

    /* Create empty file */
    FILE *f = fopen(force_file, "w");
    ASSERT(f != NULL);
    fclose(f);

    /* Empty file means all users should force online */
    int result = auth_cache_force_online(force_file, "anyuser");
    ASSERT(result == true);

    unlink(force_file);
    return 1;
}

/* Test: Force-online file with specific users */
static int test_force_online_specific_users(void)
{
    char force_file[512];
    snprintf(force_file, sizeof(force_file), "%s/force_online_users", test_dir);

    /* Create file with specific users */
    FILE *f = fopen(force_file, "w");
    ASSERT(f != NULL);
    fprintf(f, "admin\n");
    fprintf(f, "root\n");
    fprintf(f, "security\n");
    fclose(f);

    /* Listed users should force online */
    ASSERT(auth_cache_force_online(force_file, "admin") == true);
    ASSERT(auth_cache_force_online(force_file, "root") == true);
    ASSERT(auth_cache_force_online(force_file, "security") == true);

    /* Non-listed users should use cache */
    ASSERT(auth_cache_force_online(force_file, "normaluser") == false);
    ASSERT(auth_cache_force_online(force_file, "testuser") == false);

    unlink(force_file);
    return 1;
}

/* Test: Force-online file not existing */
static int test_force_online_no_file(void)
{
    int result = auth_cache_force_online("/nonexistent/force_online", "anyuser");
    ASSERT(result == false);  /* No file = use cache */
    return 1;
}

/* Test: Cleanup expired entries */
static int test_cleanup_expired(void)
{
    auth_cache_t *cache = auth_cache_init(test_dir);
    ASSERT(cache != NULL);

    /* Store entry with 1 second TTL */
    auth_cache_entry_t entry = {
        .version = 3,
        .user = "expireuser",
        .authorized = true
    };
    int ret = auth_cache_store(cache, "expireuser", "default", "exphost", &entry, 1);
    ASSERT(ret == 0);

    /* Verify it exists */
    auth_cache_entry_t lookup = {0};
    int found = auth_cache_lookup(cache, "expireuser", "default", "exphost", &lookup);
    ASSERT(found == true);
    auth_cache_entry_free(&lookup);

    /* Wait for expiration */
    sleep(2);

    /* Lookup should fail now */
    found = auth_cache_lookup(cache, "expireuser", "default", "exphost", &lookup);
    ASSERT(found == false);

    auth_cache_destroy(cache);
    return 1;
}

/* Test: Entry free with NULL fields */
static int test_entry_free_null(void)
{
    auth_cache_entry_t entry = {0};
    /* Should not crash */
    auth_cache_entry_free(&entry);
    return 1;
}

int main(void)
{
    printf("=== Authorization Cache Tests ===\n\n");

    if (setup_test_dir() != 0) {
        fprintf(stderr, "Failed to create test directory\n");
        return 1;
    }

    TEST(init_destroy);
    TEST(init_null);
    TEST(store_lookup);
    TEST(lookup_missing);
    TEST(lookup_different_group);
    TEST(invalidate);
    TEST(entry_with_groups);
    TEST(force_online_empty_file);
    TEST(force_online_specific_users);
    TEST(force_online_no_file);
    TEST(cleanup_expired);
    TEST(entry_free_null);

    cleanup_test_dir();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
