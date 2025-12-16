/*
 * test_secret_store.c - Unit tests for secret store
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include "secret_store.h"

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

static const char *test_store_dir = "/tmp/test_pam_llng_secrets";
static int machine_id_available = 0;

/* Check if /etc/machine-id exists (required for secret store) */
static int check_machine_id(void)
{
    struct stat st;
    return stat("/etc/machine-id", &st) == 0;
}

/* Setup test directory */
static void setup(void)
{
    mkdir(test_store_dir, 0700);
    machine_id_available = check_machine_id();
}

/* Recursively remove directory - safe alternative to system("rm -rf")
 * Uses openat/unlinkat to avoid TOCTOU race conditions */
static int remove_directory(const char *path)
{
    int dir_fd = open(path, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) {
        if (errno == ENOENT) return 0;  /* Already gone */
        return -1;
    }

    DIR *dir = fdopendir(dir_fd);
    if (!dir) {
        close(dir_fd);
        return -1;
    }

    struct dirent *entry;
    char filepath[512];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        struct stat st;
        if (fstatat(dir_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (S_ISDIR(st.st_mode)) {
                snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
                remove_directory(filepath);
            } else {
                unlinkat(dir_fd, entry->d_name, 0);
            }
        }
    }

    closedir(dir);  /* Also closes dir_fd */
    return rmdir(path);
}

/* Cleanup test directory */
static void cleanup(void)
{
    remove_directory(test_store_dir);
}

/* Test initialization */
static int test_init(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    secret_store_destroy(store);
    return 1;
}

/* Test store and retrieve */
static int test_put_get(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    const char *secret = "my-super-secret-token-12345";
    int ret = secret_store_put(store, "user:token", secret, strlen(secret));
    if (ret != 0) {
        secret_store_destroy(store);
        return 0;
    }

    char retrieved[256] = {0};
    size_t actual_len = 0;
    ret = secret_store_get(store, "user:token", retrieved, sizeof(retrieved), &actual_len);

    secret_store_destroy(store);

    if (ret != 0) return 0;
    if (actual_len != strlen(secret)) return 0;
    if (strcmp(retrieved, secret) != 0) return 0;

    return 1;
}

/* Test exists */
static int test_exists(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    const char *secret = "test-secret";
    secret_store_put(store, "exists:key", secret, strlen(secret));

    int ok = 1;
    ok = ok && secret_store_exists(store, "exists:key");
    ok = ok && !secret_store_exists(store, "nonexistent:key");

    secret_store_destroy(store);
    return ok;
}

/* Test delete */
static int test_delete(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    const char *secret = "to-be-deleted";
    secret_store_put(store, "delete:key", secret, strlen(secret));

    int ok = 1;
    ok = ok && secret_store_exists(store, "delete:key");

    int ret = secret_store_delete(store, "delete:key");
    ok = ok && (ret == 0);
    ok = ok && !secret_store_exists(store, "delete:key");

    secret_store_destroy(store);
    return ok;
}

/* Test not found */
static int test_not_found(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    char retrieved[256];
    size_t actual_len;
    int ret = secret_store_get(store, "nonexistent:key", retrieved,
                                sizeof(retrieved), &actual_len);

    secret_store_destroy(store);
    return (ret == -2);  /* -2 = not found */
}

/* Test different keys */
static int test_different_keys(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    const char *secret1 = "secret-for-alice";
    const char *secret2 = "secret-for-bob";

    secret_store_put(store, "alice:token", secret1, strlen(secret1));
    secret_store_put(store, "bob:token", secret2, strlen(secret2));

    char retrieved1[256] = {0};
    char retrieved2[256] = {0};
    size_t len1, len2;

    secret_store_get(store, "alice:token", retrieved1, sizeof(retrieved1), &len1);
    secret_store_get(store, "bob:token", retrieved2, sizeof(retrieved2), &len2);

    secret_store_destroy(store);

    return (strcmp(retrieved1, secret1) == 0 &&
            strcmp(retrieved2, secret2) == 0);
}

/* Test overwrite */
static int test_overwrite(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    const char *secret1 = "original-secret";
    const char *secret2 = "updated-secret";

    secret_store_put(store, "overwrite:key", secret1, strlen(secret1));
    secret_store_put(store, "overwrite:key", secret2, strlen(secret2));

    char retrieved[256] = {0};
    size_t actual_len;
    secret_store_get(store, "overwrite:key", retrieved, sizeof(retrieved), &actual_len);

    secret_store_destroy(store);

    return (strcmp(retrieved, secret2) == 0);
}

/* Test disabled store */
static int test_disabled(void)
{
    secret_store_config_t config = {
        .enabled = false,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    const char *secret = "test";
    int ret = secret_store_put(store, "disabled:key", secret, strlen(secret));

    secret_store_destroy(store);
    return (ret == -1);  /* Should fail when disabled */
}

/* Test binary data */
static int test_binary_data(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    /* Binary data with null bytes */
    unsigned char binary_secret[32];
    for (int i = 0; i < 32; i++) {
        binary_secret[i] = (unsigned char)i;
    }

    int ret = secret_store_put(store, "binary:key", binary_secret, sizeof(binary_secret));
    if (ret != 0) {
        secret_store_destroy(store);
        return 0;
    }

    unsigned char retrieved[64] = {0};
    size_t actual_len = 0;
    ret = secret_store_get(store, "binary:key", retrieved, sizeof(retrieved), &actual_len);

    secret_store_destroy(store);

    if (ret != 0) return 0;
    if (actual_len != sizeof(binary_secret)) return 0;
    if (memcmp(retrieved, binary_secret, sizeof(binary_secret)) != 0) return 0;

    return 1;
}

/* Test error message */
static int test_error_message(void)
{
    secret_store_config_t config = {
        .enabled = false,
        .store_dir = (char *)test_store_dir,
        .salt = NULL,
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    secret_store_put(store, "test", "test", 4);

    const char *error = secret_store_error(store);
    int ok = (error != NULL && strlen(error) > 0);

    secret_store_destroy(store);
    return ok;
}

/* Test rotate key returns error (not implemented) */
static int test_rotate_key_not_implemented(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    int ret = secret_store_rotate_key(store);

    secret_store_destroy(store);
    return (ret == -1);  /* Should return -1 (not implemented) */
}

int main(void)
{
    printf("Running secret store tests...\n\n");

    setup();

    TEST(init);
    TEST(put_get);
    TEST(exists);
    TEST(delete);
    TEST(not_found);
    TEST(different_keys);
    TEST(overwrite);
    TEST(disabled);
    TEST(binary_data);
    TEST(error_message);
    TEST(rotate_key_not_implemented);

    cleanup();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
