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
#include <syslog.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cache_key.h"

/* Machine ID file path */
#define MACHINE_ID_FILE "/etc/machine-id"

/* Instance ID size (32 hex chars + null) */
#define INSTANCE_ID_SIZE 33

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

    /* Reject empty machine-id */
    if (strlen(buf) == 0) {
        return -1;
    }

    return 0;
}

/*
 * Load or generate a persistent instance ID.
 * Used as fallback when /etc/machine-id is not available.
 *
 * cache_dir: Directory where instance ID file is stored
 * buf: Output buffer (at least INSTANCE_ID_SIZE bytes)
 * buf_size: Size of output buffer
 * Returns 0 on success, -1 on failure
 */
static int load_or_generate_instance_id(const char *cache_dir, char *buf, size_t buf_size)
{
    if (buf_size < INSTANCE_ID_SIZE) {
        return -1;
    }

    char id_path[512];
    int ret = snprintf(id_path, sizeof(id_path), "%s/.instance_id", cache_dir);
    if (ret < 0 || ret >= (int)sizeof(id_path)) {
        return -1;
    }

    /* Try to load existing instance ID */
    FILE *f = fopen(id_path, "r");
    if (f) {
        if (fgets(buf, buf_size, f)) {
            fclose(f);
            /* Remove trailing newline */
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }
            if (strlen(buf) >= 32) {
                return 0;  /* Successfully loaded existing ID */
            }
        } else {
            fclose(f);
        }
        /* File corrupted or too short - regenerate */
    }

    /* Generate new random instance ID (16 bytes = 32 hex chars) */
    unsigned char random_bytes[16];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return -1;
    }

    /* Convert to hex string */
    for (int i = 0; i < 16; i++) {
        snprintf(buf + (i * 2), 3, "%02x", random_bytes[i]);
    }
    buf[32] = '\0';

    /* Save to file (atomic write via temp file) */
    char temp_path[520];
    ret = snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", id_path, (int)getpid());
    if (ret < 0 || ret >= (int)sizeof(temp_path)) {
        return -1;
    }

    /* Use O_CREAT|O_EXCL|O_NOFOLLOW to prevent symlink attacks and races */
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        /* File exists (race) or symlink attack - clean up and retry */
        unlink(temp_path);
        fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0) {
            return -1;
        }
    }

    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    if (fprintf(f, "%s\n", buf) < 0) {
        fclose(f);
        unlink(temp_path);
        return -1;
    }

    /* Check fclose() return - flush errors (ENOSPC, NFS) would be missed otherwise */
    if (fclose(f) != 0) {
        unlink(temp_path);
        return -1;
    }

    if (rename(temp_path, id_path) != 0) {
        unlink(temp_path);
        /* Another process may have created the file - try loading it */
        f = fopen(id_path, "r");
        if (f && fgets(buf, buf_size, f)) {
            fclose(f);
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }
            if (strlen(buf) >= 32) {
                return 0;
            }
        }
        if (f) fclose(f);
        return -1;
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
 * Derive encryption key from machine-id (or fallback instance-id) with salt.
 * This is the shared implementation used by auth_cache and offline_cache.
 *
 * Fallback chain:
 * 1. /etc/machine-id (preferred, stable across reboots)
 * 2. {cache_dir}/.instance_id (generated, for containers/chroots)
 */
int cache_derive_key(const char *cache_dir, const char *salt_filename,
                     cache_derived_key_t *out)
{
    if (!cache_dir || !salt_filename || !out) {
        return -1;
    }

    /* Clear output structure */
    memset(out, 0, sizeof(*out));

    /* Try machine-id first, fallback to instance-id */
    char instance_id[64] = {0};
    if (read_machine_id(instance_id, sizeof(instance_id)) != 0) {
        /* Fallback: use persistent instance ID from cache directory */
        if (load_or_generate_instance_id(cache_dir, instance_id, sizeof(instance_id)) != 0) {
            return -1;
        }
    }

    /* Load or generate salt */
    unsigned char pbkdf_salt[CACHE_SALT_SIZE];
    if (load_or_generate_salt(cache_dir, salt_filename, pbkdf_salt, CACHE_SALT_SIZE) != 0) {
        explicit_bzero(instance_id, sizeof(instance_id));
        return -1;
    }

    /* Derive key using PBKDF2-HMAC-SHA256 */
    if (PKCS5_PBKDF2_HMAC(instance_id, strlen(instance_id),
                          pbkdf_salt, CACHE_SALT_SIZE,
                          CACHE_PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          CACHE_KEY_SIZE, out->key) != 1) {
        explicit_bzero(instance_id, sizeof(instance_id));
        explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));
        return -1;
    }

    /* Clean up sensitive data */
    explicit_bzero(instance_id, sizeof(instance_id));
    explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));

    out->derived = true;
    return 0;
}

/* Key file size for offline cache (256-bit secret) */
#define KEY_FILE_SIZE 32

/*
 * Decide whether a stat'd key file is acceptable. Returns 1 when it must be
 * REFUSED, 0 when it may be used.
 *
 * `owner` is the uid the file must belong to. Every caller in the module passes
 * 0: a key file not owned by root is not a key file. It is an argument rather
 * than a hard-coded 0 so that tests/test_cache_key.c can reach the four
 * refusals that sit BELOW the ownership test -- as an ordinary user every file
 * a test can create fails the uid check first, which would leave those branches
 * uncovered in every CI job that is not root (#268). The root requirement
 * itself is then asserted against the shipped value, 0.
 */
static int key_file_rejected(const struct stat *st, const char *path, uid_t owner)
{
    /* Must be a regular file, not a fifo/device that could block or feed us
     * attacker-chosen bytes. */
    if (!S_ISREG(st->st_mode)) {
        syslog(LOG_WARNING, "open-bastion: key file %s is not a regular file (rejected)",
               path);
        return 1;
    }

    /*
     * Ownership is checked unconditionally: a key file that happens to be mode
     * 0600 but is owned by some other uid used to slip through entirely,
     * because the uid test sat inside the loose-permissions branch below.
     */
    if (st->st_uid != owner) {
        syslog(LOG_WARNING, "open-bastion: key file %s is not owned by root (rejected)",
               path);
        return 1;
    }

    /*
     * setuid/setgid on a key file is always nonsense: it is data, never an
     * executable. It is also the classic marker of a file that was planted
     * rather than generated by ob-desktop-setup, so refuse it outright.
     */
    if ((st->st_mode & (S_ISUID | S_ISGID)) != 0) {
        syslog(LOG_WARNING,
               "open-bastion: key file %s has setuid/setgid bits (mode %04o) - rejected",
               path, (unsigned)(st->st_mode & 07777));
        return 1;
    }

    /*
     * Enforce strict permissions on the key file. This is fail-closed: a
     * root-owned key file with any group/other bit set is rejected rather than
     * merely warned about. Rejecting is safe — the caller
     * (cache_derive_key_with_keyfile) falls back to machine-id derivation and
     * logs "cache key derived without key file", so the effect is a weaker
     * derivation and an invalidated offline cache, never a lockout.
     *
     * The message is deliberately directive: SECURITY.md used to document
     * `dd if=/dev/urandom of=/etc/open-bastion/cache.key ...` with no chmod,
     * which under root's umask 022 yields 0644. Hosts set up from that recipe
     * hit this path on upgrade, and the admin must be told exactly what to do
     * rather than left to work it out from "rejected".
     */
    if ((st->st_mode & 0077) != 0) {
        syslog(LOG_WARNING,
               "open-bastion: key file %s has insecure permissions %04o (must be 0600 "
               "root:root) - rejected, falling back to machine-id key derivation; "
               "existing offline cache entries become undecryptable. Fix with: "
               "chown root:root %s && chmod 600 %s",
               path, (unsigned)(st->st_mode & 0777), path, path);
        return 1;
    }

    return 0;
}

/*
 * Read a secret key file (root-only, for offline cache).
 * Returns 0 on success, -1 on failure.
 */
static int read_key_file(const char *path, unsigned char *buf, size_t buf_size)
{
    if (!path || buf_size < KEY_FILE_SIZE) {
        return -1;
    }

    /*
     * O_NONBLOCK so that a fifo left at this path opens instead of parking the
     * caller forever: without it the S_ISREG refusal below is unreachable, the
     * open never returns, and on the PAM path that is a login that never
     * finishes. It has no effect on a regular file, which is the only thing
     * that gets past the check.
     */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }

    /* Verify file permissions (should be 0600 and owned by root) */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }

    if (key_file_rejected(&st, path, 0)) {
        close(fd);
        return -1;
    }

    /* Read exactly KEY_FILE_SIZE bytes, handling short reads */
    size_t total_read = 0;
    while (total_read < KEY_FILE_SIZE) {
        ssize_t n = read(fd, buf + total_read, KEY_FILE_SIZE - total_read);
        if (n <= 0) {
            close(fd);
            return -1;  /* EOF or error before reading enough bytes */
        }
        total_read += (size_t)n;
    }
    close(fd);

    return 0;
}

/*
 * Derive encryption key with optional key file support.
 * Used by offline_cache for stronger security when key file is available.
 */
int cache_derive_key_with_keyfile(const char *cache_dir,
                                   const char *salt_filename,
                                   const char *key_file,
                                   cache_derived_key_t *out)
{
    if (!cache_dir || !salt_filename || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Key material buffer: key_file (32 bytes) + instance_id (up to 64 bytes) */
    unsigned char key_material[KEY_FILE_SIZE + 64];
    size_t key_material_len = 0;
    bool have_key_file = false;

    /* Try to read key file if provided */
    if (key_file) {
        unsigned char file_key[KEY_FILE_SIZE];
        if (read_key_file(key_file, file_key, KEY_FILE_SIZE) == 0) {
            memcpy(key_material, file_key, KEY_FILE_SIZE);
            key_material_len = KEY_FILE_SIZE;
            explicit_bzero(file_key, sizeof(file_key));
            have_key_file = true;
        } else {
            explicit_bzero(file_key, sizeof(file_key));
        }
    }

    /* Get machine-id or instance-id fallback */
    char instance_id[64] = {0};
    if (read_machine_id(instance_id, sizeof(instance_id)) != 0) {
        if (load_or_generate_instance_id(cache_dir, instance_id, sizeof(instance_id)) != 0) {
            explicit_bzero(key_material, sizeof(key_material));
            return -1;
        }
    }

    /* Append instance_id to key material */
    size_t id_len = strlen(instance_id);
    memcpy(key_material + key_material_len, instance_id, id_len);
    key_material_len += id_len;
    explicit_bzero(instance_id, sizeof(instance_id));

    /* Emit warning if no key file (weaker security) */
    if (!have_key_file && key_file) {
        syslog(LOG_WARNING,
               "open-bastion: cache key derived without key file (weaker security). "
               "See documentation for key file setup.");
    }

    /* Load or generate salt */
    unsigned char pbkdf_salt[CACHE_SALT_SIZE];
    if (load_or_generate_salt(cache_dir, salt_filename, pbkdf_salt, CACHE_SALT_SIZE) != 0) {
        explicit_bzero(key_material, sizeof(key_material));
        return -1;
    }

    /* Derive key using PBKDF2-HMAC-SHA256 */
    if (PKCS5_PBKDF2_HMAC((char *)key_material, key_material_len,
                          pbkdf_salt, CACHE_SALT_SIZE,
                          CACHE_PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          CACHE_KEY_SIZE, out->key) != 1) {
        explicit_bzero(key_material, sizeof(key_material));
        explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));
        return -1;
    }

    explicit_bzero(key_material, sizeof(key_material));
    explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));

    out->derived = true;
    return 0;
}
