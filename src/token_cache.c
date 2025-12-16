/*
 * token_cache.c - Token caching for LemonLDAP::NG PAM module
 *
 * Uses file-based cache with SHA256 hashed token names.
 * Supports optional AES-256-GCM encryption derived from machine-id.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "token_cache.h"

/* Maximum number of cache entries to prevent DoS */
#define MAX_CACHE_ENTRIES 10000

/* Encryption constants */
#define MACHINE_ID_FILE "/etc/machine-id"
#define KEY_SIZE 32         /* AES-256 */
#define IV_SIZE 12          /* GCM recommended IV size */
#define TAG_SIZE 16         /* GCM authentication tag */
#define SALT_SIZE 16        /* PBKDF2 salt */
#define PBKDF2_ITERATIONS 100000
#define CACHE_MAGIC "LLNGCACHE02"   /* Version 02 = encrypted */
#define CACHE_MAGIC_V01 "LLNGCACHE01"  /* Version 01 = plaintext (for migration) */

/* SHA256 hash for cache keys - cryptographically secure (uses OpenSSL EVP API) */
static void hash_token(const char *token, const char *user, char *out, size_t out_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (!ctx) {
        if (out_size > 0) out[0] = '\0';
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, token, strlen(token)) != 1 ||
        EVP_DigestUpdate(ctx, ":", 1) != 1 ||
        EVP_DigestUpdate(ctx, user, strlen(user)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        if (out_size > 0) out[0] = '\0';
        return;
    }

    EVP_MD_CTX_free(ctx);

    /* Convert to hex string (use first 16 bytes = 32 hex chars) */
    if (out_size >= 33 && hash_len >= 16) {
        for (int i = 0; i < 16; i++) {
            snprintf(out + (i * 2), 3, "%02x", hash[i]);
        }
        out[32] = '\0';
    } else if (out_size > 0) {
        out[0] = '\0';
    }

    /* Clear sensitive data */
    explicit_bzero(hash, sizeof(hash));
}

/* Cache structure */
struct token_cache {
    char *cache_dir;
    int default_ttl;
    bool encrypt;                       /* Enable encryption */
    unsigned char derived_key[KEY_SIZE]; /* AES-256 key derived from machine-id */
    bool key_derived;                    /* True if key was successfully derived */
};

/* Read machine-id */
static int read_machine_id(char *buf, size_t buf_size)
{
    FILE *f = fopen(MACHINE_ID_FILE, "r");
    if (!f) return -1;

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

/* Derive encryption key from machine-id using PBKDF2 */
static int derive_cache_key(token_cache_t *cache)
{
    char machine_id[64] = {0};

    if (read_machine_id(machine_id, sizeof(machine_id)) != 0) {
        return -1;
    }

    /*
     * Derive a unique salt from machine-id for cache encryption.
     * Different from secret_store salt to use independent keys.
     */
    unsigned char pbkdf_salt[SALT_SIZE];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char salt_hash[EVP_MAX_MD_SIZE];
    unsigned int salt_hash_len = 0;

    if (!md_ctx ||
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, "pam_llng_cache_salt:", 20) != 1 ||
        EVP_DigestUpdate(md_ctx, machine_id, strlen(machine_id)) != 1 ||
        EVP_DigestFinal_ex(md_ctx, salt_hash, &salt_hash_len) != 1) {
        if (md_ctx) EVP_MD_CTX_free(md_ctx);
        explicit_bzero(machine_id, sizeof(machine_id));
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);

    /* Use first SALT_SIZE bytes of hash as salt */
    memcpy(pbkdf_salt, salt_hash, SALT_SIZE);
    explicit_bzero(salt_hash, sizeof(salt_hash));

    /* Derive key using PBKDF2 */
    if (PKCS5_PBKDF2_HMAC(machine_id, strlen(machine_id),
                          pbkdf_salt, SALT_SIZE,
                          PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          KEY_SIZE, cache->derived_key) != 1) {
        explicit_bzero(machine_id, sizeof(machine_id));
        explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));
        return -1;
    }

    explicit_bzero(machine_id, sizeof(machine_id));
    explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));

    cache->key_derived = true;
    return 0;
}

/* Encrypt cache data using AES-256-GCM */
static int encrypt_cache_data(token_cache_t *cache,
                              const unsigned char *plaintext,
                              size_t plaintext_len,
                              unsigned char **out,
                              size_t *out_len)
{
    if (!cache->key_derived) return -1;

    /* Generate random IV */
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        return -1;
    }

    /* Allocate output: IV + ciphertext + tag */
    size_t out_size = IV_SIZE + plaintext_len + TAG_SIZE + 16;
    *out = malloc(out_size);
    if (!*out) return -1;

    /* Copy IV to output */
    memcpy(*out, iv, IV_SIZE);

    /* Encrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*out);
        *out = NULL;
        return -1;
    }

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, cache->derived_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, *out + IV_SIZE, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, *out + IV_SIZE + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }
    ciphertext_len += len;

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                            *out + IV_SIZE + ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    *out_len = IV_SIZE + ciphertext_len + TAG_SIZE;
    return 0;
}

/* Decrypt cache data using AES-256-GCM */
static int decrypt_cache_data(token_cache_t *cache,
                              const unsigned char *encrypted,
                              size_t encrypted_len,
                              unsigned char **out,
                              size_t *out_len)
{
    if (!cache->key_derived) return -1;

    /* Minimum size: IV + tag */
    if (encrypted_len < IV_SIZE + TAG_SIZE) {
        return -1;
    }

    /* Extract IV, ciphertext, and tag */
    const unsigned char *iv = encrypted;
    size_t ciphertext_len = encrypted_len - IV_SIZE - TAG_SIZE;
    const unsigned char *ciphertext = encrypted + IV_SIZE;
    const unsigned char *tag = encrypted + IV_SIZE + ciphertext_len;

    /* Allocate output */
    *out = malloc(ciphertext_len + 1);
    if (!*out) return -1;

    /* Decrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*out);
        *out = NULL;
        return -1;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, cache->derived_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, *out, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }
    plaintext_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }

    /* Finalize and verify tag */
    int ret = EVP_DecryptFinal_ex(ctx, *out + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        /* Authentication failed - data may be tampered */
        explicit_bzero(*out, ciphertext_len + 1);
        free(*out);
        *out = NULL;
        return -1;
    }

    plaintext_len += len;
    (*out)[plaintext_len] = '\0';
    *out_len = plaintext_len;
    return 0;
}

token_cache_t *cache_init_config(const cache_config_t *config)
{
    if (!config || !config->cache_dir) {
        return NULL;
    }

    token_cache_t *cache = calloc(1, sizeof(token_cache_t));
    if (!cache) {
        return NULL;
    }

    cache->cache_dir = strdup(config->cache_dir);
    cache->default_ttl = config->ttl > 0 ? config->ttl : 300;
    cache->encrypt = config->encrypt;

    /* Create cache directory if it doesn't exist */
    struct stat st;
    if (stat(config->cache_dir, &st) != 0) {
        if (mkdir(config->cache_dir, 0700) != 0 && errno != EEXIST) {
            free(cache->cache_dir);
            free(cache);
            return NULL;
        }
    }

    /* Derive encryption key if encryption is enabled */
    if (cache->encrypt) {
        if (derive_cache_key(cache) != 0) {
            /* Key derivation failed - continue without encryption */
            cache->encrypt = false;
            cache->key_derived = false;
        }
    }

    return cache;
}

token_cache_t *cache_init(const char *cache_dir, int ttl)
{
    /* Legacy init - encryption disabled for backward compatibility */
    cache_config_t config = {
        .cache_dir = cache_dir,
        .ttl = ttl,
        .encrypt = false
    };
    return cache_init_config(&config);
}

void cache_destroy(token_cache_t *cache)
{
    if (!cache) return;
    free(cache->cache_dir);
    /* Securely clear derived key */
    explicit_bzero(cache->derived_key, sizeof(cache->derived_key));
    explicit_bzero(cache, sizeof(*cache));
    free(cache);
}

/* Forward declaration for read_cache_file */
static int read_cache_file(token_cache_t *cache, const char *path,
                           char **out, size_t *out_len);

/*
 * Combined count and cleanup in a single directory scan.
 * Returns the number of valid (non-expired) entries remaining.
 * This avoids triple directory scans in cache_store().
 *
 * New cache format: first line is plaintext "expires_at\n",
 * so we can check expiration without decrypting.
 */
static int count_and_cleanup_entries(token_cache_t *cache, int *removed)
{
    if (!cache) return 0;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return 0;

    int count = 0;
    int cleanup_count = 0;
    time_t now = time(NULL);
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cache") == NULL) {
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        /* Quick expiration check: read only the first line (plaintext timestamp) */
        FILE *f = fopen(path, "r");
        if (!f) {
            unlink(path);
            cleanup_count++;
            continue;
        }

        char line[64];
        if (!fgets(line, sizeof(line), f)) {
            fclose(f);
            unlink(path);
            cleanup_count++;
            continue;
        }
        fclose(f);

        /* Validate that we got a complete line with newline */
        if (!strchr(line, '\n') && strlen(line) >= sizeof(line) - 1) {
            /* Line too long - corrupted file */
            unlink(path);
            cleanup_count++;
            continue;
        }

        time_t expires_at;
        if (sscanf(line, "%ld", &expires_at) != 1) {
            /* Invalid format - corrupted */
            unlink(path);
            cleanup_count++;
            continue;
        }

        if (now >= expires_at) {
            /* Expired - remove it */
            unlink(path);
            cleanup_count++;
            continue;
        }

        count++;  /* Valid entry */
    }

    closedir(dir);
    if (removed) *removed = cleanup_count;
    return count;
}

/* Build cache file path */
static void build_cache_path(token_cache_t *cache,
                             const char *token,
                             const char *user,
                             char *path,
                             size_t path_size)
{
    char hash[64];  /* SHA256 truncated to first 16 bytes = 32 hex chars + null */
    hash_token(token, user, hash, sizeof(hash));
    snprintf(path, path_size, "%s/%s.cache", cache->cache_dir, hash);
}

bool cache_lookup(token_cache_t *cache,
                  const char *token,
                  const char *user,
                  cache_entry_t *entry)
{
    if (!cache || !token || !user || !entry) {
        return false;
    }

    memset(entry, 0, sizeof(*entry));

    char path[PATH_MAX];
    build_cache_path(cache, token, user, path, sizeof(path));

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            /* Symlink detected - security violation, remove it */
            unlink(path);
        }
        return false;
    }

    /* Get file size and check mtime for quick expiration check */
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return false;
    }

    /*
     * New cache format: "expires_at\n" followed by payload.
     * Read expiration first to avoid decryption if expired.
     * Buffer size 64 is sufficient for any time_t value plus newline.
     */
    char expires_line[64];
    ssize_t n = read(fd, expires_line, sizeof(expires_line) - 1);
    if (n <= 0) {
        close(fd);
        unlink(path);
        return false;
    }
    expires_line[n] = '\0';

    /* Parse expiration timestamp from first line */
    time_t expires_at;
    char *newline = strchr(expires_line, '\n');
    if (!newline) {
        /* No newline found in buffer - malformed or corrupted file */
        close(fd);
        unlink(path);
        return false;
    }
    if (sscanf(expires_line, "%ld", &expires_at) != 1) {
        close(fd);
        unlink(path);
        return false;
    }

    /* Check expiration BEFORE decrypting (optimization) */
    time_t now = time(NULL);
    if (now >= expires_at) {
        close(fd);
        unlink(path);
        return false;
    }

    /* Calculate offset to payload (after "expires_at\n") */
    size_t header_len = (size_t)(newline - expires_line + 1);

    /* Seek to start of payload */
    if (lseek(fd, header_len, SEEK_SET) == (off_t)-1) {
        close(fd);
        return false;
    }

    /* Read remaining payload */
    size_t payload_size = st.st_size - header_len;
    unsigned char *data = malloc(payload_size + 1);
    if (!data) {
        close(fd);
        return false;
    }

    ssize_t bytes_read = read(fd, data, payload_size);
    close(fd);

    if (bytes_read != (ssize_t)payload_size) {
        free(data);
        return false;
    }
    data[payload_size] = '\0';

    char *payload = NULL;
    size_t payload_len = 0;

    /* Check if encrypted (starts with magic) */
    if (cache->encrypt && cache->key_derived &&
        payload_size > strlen(CACHE_MAGIC) &&
        memcmp(data, CACHE_MAGIC, strlen(CACHE_MAGIC)) == 0) {
        /* Encrypted payload */
        unsigned char *decrypted = NULL;
        size_t decrypted_len = 0;

        size_t encrypted_offset = strlen(CACHE_MAGIC);
        if (decrypt_cache_data(cache,
                               data + encrypted_offset,
                               payload_size - encrypted_offset,
                               &decrypted, &decrypted_len) != 0) {
            /* Decryption failed - remove potentially tampered file */
            explicit_bzero(data, payload_size);
            free(data);
            unlink(path);
            return false;
        }

        explicit_bzero(data, payload_size);
        free(data);
        payload = (char *)decrypted;
        payload_len = decrypted_len;
    } else {
        /* Plaintext payload */
        payload = (char *)data;
        payload_len = payload_size;
    }

    time_t payload_expires_at;
    int authorized;
    char cached_user[256];

    /* Parse payload: "expires_at authorized user\n" */
    if (sscanf(payload, "%ld %d %255s", &payload_expires_at, &authorized, cached_user) != 3) {
        /* Invalid format, remove the file */
        explicit_bzero(payload, payload_len);
        free(payload);
        unlink(path);
        return false;
    }

    explicit_bzero(payload, payload_len);
    free(payload);

    /*
     * Security check: verify plaintext timestamp matches encrypted payload.
     * This prevents an attacker from modifying the plaintext timestamp
     * to extend cache validity without access to the encryption key.
     */
    if (payload_expires_at != expires_at) {
        /* Timestamp mismatch - possible tampering, remove file */
        unlink(path);
        return false;
    }

    /* Verify user matches */
    if (strcmp(cached_user, user) != 0) {
        return false;
    }

    entry->user = strdup(cached_user);
    entry->authorized = authorized != 0;
    entry->expires_at = expires_at;
    entry->cached_at = expires_at - cache->default_ttl;  /* Approximate */

    return true;
}

int cache_store(token_cache_t *cache,
                const char *token,
                const char *user,
                bool authorized,
                int ttl)
{
    if (!cache || !token || !user) {
        return -1;
    }

    /* Rate limiting: check if cache is full (single scan with cleanup) */
    int entry_count = count_and_cleanup_entries(cache, NULL);
    if (entry_count >= MAX_CACHE_ENTRIES) {
        /* Still full after cleanup, refuse to add more entries */
        return -1;
    }

    char path[PATH_MAX];
    build_cache_path(cache, token, user, path, sizeof(path));

    /* Build cache entry data */
    time_t expires_at = time(NULL) + (ttl > 0 ? ttl : cache->default_ttl);

    /*
     * Cache format (optimized for quick expiration check with integrity protection):
     * - Plaintext header: "expires_at\n" (allows checking expiration without decryption)
     * - If encrypted: CACHE_MAGIC + encrypted("expires_at authorized user\n")
     * - If plaintext: "expires_at authorized user\n"
     *
     * The expires_at is duplicated: once in plaintext for quick check, once in
     * encrypted payload for integrity verification. If an attacker modifies the
     * plaintext timestamp, it won't match the encrypted one and will be rejected.
     */
    char expires_header[32];
    int header_len = snprintf(expires_header, sizeof(expires_header), "%ld\n", expires_at);
    if (header_len < 0 || header_len >= (int)sizeof(expires_header)) {
        return -1;
    }

    /* Include expires_at in payload for integrity verification after decryption */
    char payload[1024];
    int payload_len = snprintf(payload, sizeof(payload), "%ld %d %s\n",
                               expires_at, authorized ? 1 : 0, user);
    if (payload_len < 0 || payload_len >= (int)sizeof(payload)) {
        return -1;
    }

    /* Use atomic write: write to temp file then rename */
    char temp_path[PATH_MAX + 8];  /* PATH_MAX + ".tmp" + margin */
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }

    int result = 0;

    /* Always write plaintext expiration header first */
    ssize_t written = write(fd, expires_header, header_len);
    if (written != header_len) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    if (cache->encrypt && cache->key_derived) {
        /* Encrypt the payload (not the expiration) */
        unsigned char *encrypted = NULL;
        size_t encrypted_len = 0;

        if (encrypt_cache_data(cache, (unsigned char *)payload, payload_len,
                               &encrypted, &encrypted_len) != 0) {
            close(fd);
            unlink(temp_path);
            return -1;
        }

        /* Write magic header + encrypted data */
        written = write(fd, CACHE_MAGIC, strlen(CACHE_MAGIC));
        if (written == (ssize_t)strlen(CACHE_MAGIC)) {
            written = write(fd, encrypted, encrypted_len);
            if (written != (ssize_t)encrypted_len) {
                result = -1;
            }
        } else {
            result = -1;
        }

        explicit_bzero(encrypted, encrypted_len);
        free(encrypted);
    } else {
        /* Write plaintext payload */
        written = write(fd, payload, payload_len);
        if (written != payload_len) {
            result = -1;
        }
    }

    explicit_bzero(payload, sizeof(payload));

    close(fd);

    if (result != 0) {
        unlink(temp_path);
        return -1;
    }

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return -1;
    }

    return 0;
}

/*
 * Helper to read and decrypt a cache file.
 * Returns decrypted/plaintext data in *out (caller must free).
 * Returns 0 on success, -1 on failure.
 */
static int read_cache_file(token_cache_t *cache, const char *path,
                           char **out, size_t *out_len)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            /* Symlink detected - security violation, remove it */
            unlink(path);
        }
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return -1;
    }

    unsigned char *data = malloc(st.st_size + 1);
    if (!data) {
        close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, data, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(data);
        return -1;
    }
    data[st.st_size] = '\0';

    /* Check if encrypted */
    if (cache->encrypt && cache->key_derived &&
        (size_t)st.st_size > strlen(CACHE_MAGIC) &&
        memcmp(data, CACHE_MAGIC, strlen(CACHE_MAGIC)) == 0) {
        /* Decrypt */
        unsigned char *decrypted = NULL;
        size_t decrypted_len = 0;

        size_t encrypted_offset = strlen(CACHE_MAGIC);
        if (decrypt_cache_data(cache,
                               data + encrypted_offset,
                               st.st_size - encrypted_offset,
                               &decrypted, &decrypted_len) != 0) {
            explicit_bzero(data, st.st_size);
            free(data);
            return -1;
        }

        explicit_bzero(data, st.st_size);
        free(data);
        *out = (char *)decrypted;
        *out_len = decrypted_len;
    } else {
        /* Plaintext */
        *out = (char *)data;
        *out_len = st.st_size;
    }

    return 0;
}

void cache_invalidate(token_cache_t *cache, const char *token)
{
    if (!cache || !token) return;

    /* Since we hash with user, we need to scan directory */
    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return;

    /* Hash the token part only for prefix matching isn't practical
     * with our hash scheme. For now, this is a no-op for single token.
     * Use cache_invalidate_user for user-based invalidation. */
    closedir(dir);
}

void cache_invalidate_user(token_cache_t *cache, const char *user)
{
    if (!cache || !user) return;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cache") == NULL) {
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        char *data = NULL;
        size_t data_len = 0;
        if (read_cache_file(cache, path, &data, &data_len) != 0) {
            continue;
        }

        time_t expires_at;
        int authorized;
        char cached_user[256];

        if (sscanf(data, "%ld %d %255s", &expires_at, &authorized, cached_user) == 3) {
            if (strcmp(cached_user, user) == 0) {
                explicit_bzero(data, data_len);
                free(data);
                unlink(path);
                continue;
            }
        }

        explicit_bzero(data, data_len);
        free(data);
    }

    closedir(dir);
}

int cache_cleanup(token_cache_t *cache)
{
    if (!cache) return 0;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return 0;

    int removed = 0;
    time_t now = time(NULL);
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cache") == NULL) {
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        char *data = NULL;
        size_t data_len = 0;
        if (read_cache_file(cache, path, &data, &data_len) != 0) {
            /* Cannot read/decrypt - might be corrupted, remove it */
            unlink(path);
            removed++;
            continue;
        }

        time_t expires_at;
        if (sscanf(data, "%ld", &expires_at) == 1) {
            if (now >= expires_at) {
                explicit_bzero(data, data_len);
                free(data);
                unlink(path);
                removed++;
                continue;
            }
        }

        explicit_bzero(data, data_len);
        free(data);
    }

    closedir(dir);
    return removed;
}

void cache_entry_free(cache_entry_t *entry)
{
    if (!entry) return;
    free(entry->token_hash);
    free(entry->user);
    memset(entry, 0, sizeof(*entry));
}
