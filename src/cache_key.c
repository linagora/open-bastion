/*
 * cache_key.c - Shared PBKDF2 key derivation for cache encryption
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cache_key.h"

/* Machine ID file path */
#define MACHINE_ID_FILE "/etc/machine-id"

/*
 * Read machine-id from /etc/machine-id
 * buf: Output buffer (at least 64 bytes)
 * buf_size: Size of output buffer
 * Returns 0 on success, -1 on failure
 */
static int read_machine_id(char *buf, size_t buf_size)
{
    FILE *f = fopen(MACHINE_ID_FILE, "r");
    if (!f) {
        return -1;
    }

    if (!fgets(buf, buf_size, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Remove trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    return 0;
}

/*
 * Load or generate random salt for PBKDF2.
 * Security: uses random salt instead of deterministic machine-id hash
 * to prevent precomputation attacks.
 *
 * cache_dir: Directory where salt file is stored
 * salt_filename: Name of the salt file
 * salt: Output buffer for salt (CACHE_SALT_SIZE bytes)
 * salt_size: Size of salt buffer (should be CACHE_SALT_SIZE)
 * Returns 0 on success, -1 on failure
 */
static int load_or_generate_salt(const char *cache_dir,
                                  const char *salt_filename,
                                  unsigned char *salt,
                                  size_t salt_size)
{
    char salt_path[512];
    int ret = snprintf(salt_path, sizeof(salt_path), "%s/%s", cache_dir, salt_filename);
    if (ret < 0 || ret >= (int)sizeof(salt_path)) {
        return -1;
    }

    /* Try to load existing salt */
    int fd = open(salt_path, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        ssize_t bytes_read = read(fd, salt, salt_size);
        close(fd);
        if (bytes_read == (ssize_t)salt_size) {
            return 0;  /* Successfully loaded existing salt */
        }
        /* Salt file corrupted or wrong size - regenerate */
    }

    /* Generate new random salt */
    if (RAND_bytes(salt, salt_size) != 1) {
        return -1;  /* Failed to generate random bytes */
    }

    /* Save salt to file (atomic write via temp file) */
    char temp_path[520];
    ret = snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", salt_path, (int)getpid());
    if (ret < 0 || ret >= (int)sizeof(temp_path)) {
        return -1;
    }

    /* Security: use O_EXCL to prevent symlink/race attacks on temp file */
    fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        /* If file exists (stale temp), try to remove and retry */
        if (errno == EEXIST) {
            unlink(temp_path);
            fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        }
        if (fd < 0) {
            return -1;  /* Can't create salt file */
        }
    }

    ssize_t written = write(fd, salt, salt_size);
    close(fd);

    if (written != (ssize_t)salt_size) {
        unlink(temp_path);
        return -1;
    }

    if (rename(temp_path, salt_path) != 0) {
        unlink(temp_path);
        /*
         * Another process may have won the race and created the salt file.
         * Try loading it instead of failing.
         */
        fd = open(salt_path, O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) {
            ssize_t bytes_read = read(fd, salt, salt_size);
            close(fd);
            if (bytes_read == (ssize_t)salt_size) {
                return 0;
            }
        }
        return -1;
    }

    return 0;
}

/*
 * Derive encryption key from machine-id with salt from given directory.
 * This is the shared implementation used by both token_cache and auth_cache.
 */
int cache_derive_key(const char *cache_dir, const char *salt_filename,
                     cache_derived_key_t *out)
{
    if (!cache_dir || !salt_filename || !out) {
        return -1;
    }

    /* Clear output structure */
    memset(out, 0, sizeof(*out));

    /* Read machine-id */
    char machine_id[64] = {0};
    if (read_machine_id(machine_id, sizeof(machine_id)) != 0) {
        return -1;
    }

    /* Load or generate salt */
    unsigned char pbkdf_salt[CACHE_SALT_SIZE];
    if (load_or_generate_salt(cache_dir, salt_filename, pbkdf_salt, CACHE_SALT_SIZE) != 0) {
        explicit_bzero(machine_id, sizeof(machine_id));
        return -1;
    }

    /* Derive key using PBKDF2-HMAC-SHA256 */
    if (PKCS5_PBKDF2_HMAC(machine_id, strlen(machine_id),
                          pbkdf_salt, CACHE_SALT_SIZE,
                          CACHE_PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          CACHE_KEY_SIZE, out->key) != 1) {
        explicit_bzero(machine_id, sizeof(machine_id));
        explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));
        return -1;
    }

    /* Clean up sensitive data */
    explicit_bzero(machine_id, sizeof(machine_id));
    explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));

    out->derived = true;
    return 0;
}
