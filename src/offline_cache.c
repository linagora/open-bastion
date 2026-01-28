/*
 * offline_cache.c - Offline credential cache for desktop SSO
 *
 * Implements secure credential caching using:
 * - Argon2id for password hashing (via libsodium)
 * - AES-256-GCM for data encryption
 * - Machine-id derived encryption key
 *
 * File format: OBCRED01 + encrypted JSON
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
#include <syslog.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <json-c/json.h>

#include "offline_cache.h"
#include "str_utils.h"

/* Try to use libsodium for Argon2id if available, otherwise use OpenSSL */
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#define USE_LIBSODIUM 1
#else
/* OpenSSL 3.0+ has Argon2 support via EVP_KDF */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define USE_OPENSSL_ARGON2 1
#else
#error "Requires OpenSSL 3.0+ or libsodium for Argon2id support"
#endif
#endif

/* Cache magic and version */
#define OFFLINE_CACHE_MAGIC "OBCRED01"
#define MAGIC_LEN 8

/* Use shared JSON strdup utility */
#define safe_json_strdup str_json_strdup

/* Encryption constants */
#define MACHINE_ID_FILE "/etc/machine-id"
#define DEFAULT_CACHE_KEY_FILE "/etc/open-bastion/cache.key"
#define KEY_FILE_SIZE 32  /* Expected key file size in bytes */
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 100000

/* Cache structure */
struct offline_cache {
    char *cache_dir;
    char *key_file;             /* Path to secret key file (root-only) */
    unsigned char derived_key[KEY_SIZE];
    bool key_derived;
    int max_failed_attempts;    /* 0 = use compile-time default */
    int lockout_duration;       /* 0 = use compile-time default */
#ifdef USE_LIBSODIUM
    bool sodium_initialized;
#endif
};

/* Error messages */
static const char *error_messages[] = {
    [0] = "Success",
    [-OFFLINE_CACHE_ERR_NOMEM] = "Out of memory",
    [-OFFLINE_CACHE_ERR_IO] = "I/O error",
    [-OFFLINE_CACHE_ERR_CRYPTO] = "Cryptographic error",
    [-OFFLINE_CACHE_ERR_NOTFOUND] = "Entry not found",
    [-OFFLINE_CACHE_ERR_EXPIRED] = "Entry expired",
    [-OFFLINE_CACHE_ERR_LOCKED] = "Entry locked",
    [-OFFLINE_CACHE_ERR_INVALID] = "Invalid data",
    [-OFFLINE_CACHE_ERR_PASSWORD] = "Password mismatch"
};

const char *offline_cache_strerror(int err)
{
    if (err == 0) return error_messages[0];
    if (err > 0 || err < -8) return "Unknown error";
    return error_messages[-err];
}

/* Secure memory clear */
static void secure_clear(void *ptr, size_t len)
{
    if (ptr && len > 0) {
#ifdef USE_LIBSODIUM
        sodium_memzero(ptr, len);
#else
        explicit_bzero(ptr, len);
#endif
    }
}

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

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    return 0;
}

/* Load or generate salt for PBKDF2 */
static int load_or_generate_salt(const char *cache_dir, unsigned char *salt, size_t salt_size)
{
    char salt_path[512];
    snprintf(salt_path, sizeof(salt_path), "%s/.cred_salt", cache_dir);

    int fd = open(salt_path, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        ssize_t bytes_read = read(fd, salt, salt_size);
        close(fd);
        if (bytes_read == (ssize_t)salt_size) {
            return 0;
        }
    }

    /* Generate new random salt */
    if (RAND_bytes(salt, salt_size) != 1) {
        return -1;
    }

    /* Save salt atomically */
    char temp_path[520];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", salt_path, (int)getpid());

    fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            unlink(temp_path);
            fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        }
        if (fd < 0) return -1;
    }

    ssize_t written = write(fd, salt, salt_size);
    close(fd);

    if (written != (ssize_t)salt_size) {
        unlink(temp_path);
        return -1;
    }

    if (rename(temp_path, salt_path) != 0) {
        unlink(temp_path);
        return -1;
    }

    return 0;
}

/*
 * Read a root-only secret key file (e.g., /etc/open-bastion/cache.key).
 * The file must be exactly KEY_FILE_SIZE bytes, owned by root, mode 0600.
 * Returns 0 on success, -1 if not available or invalid.
 */
static int read_key_file(const char *path, unsigned char *buf, size_t buf_size)
{
    if (!path) return -1;

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }

    /* Verify ownership and permissions */
    if (st.st_uid != 0 || (st.st_mode & 077) != 0) {
        close(fd);
        return -1;
    }

    if ((size_t)st.st_size != buf_size) {
        close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, buf, buf_size);
    close(fd);

    return (bytes_read == (ssize_t)buf_size) ? 0 : -1;
}

/*
 * Derive encryption key.
 * Priority: secret key file → machine-id fallback (with warning).
 *
 * When a key file is available, it is combined with machine-id via
 * PBKDF2 so that the cache is bound to both the secret and the machine.
 * When no key file exists, machine-id alone is used (world-readable,
 * weaker protection — a syslog warning is emitted).
 */
static int derive_cache_key(offline_cache_t *cache)
{
    unsigned char key_material[KEY_FILE_SIZE + 64];
    size_t key_material_len = 0;
    bool have_key_file = false;

    /* Try key file first */
    const char *kf = cache->key_file ? cache->key_file : DEFAULT_CACHE_KEY_FILE;
    unsigned char file_key[KEY_FILE_SIZE];
    if (read_key_file(kf, file_key, KEY_FILE_SIZE) == 0) {
        memcpy(key_material, file_key, KEY_FILE_SIZE);
        key_material_len = KEY_FILE_SIZE;
        secure_clear(file_key, sizeof(file_key));
        have_key_file = true;
    } else {
        secure_clear(file_key, sizeof(file_key));
    }

    /* Always include machine-id to bind cache to this machine */
    char machine_id[64] = {0};
    if (read_machine_id(machine_id, sizeof(machine_id)) != 0) {
        secure_clear(key_material, sizeof(key_material));
        return -1;
    }

    size_t mid_len = strlen(machine_id);
    memcpy(key_material + key_material_len, machine_id, mid_len);
    key_material_len += mid_len;
    secure_clear(machine_id, sizeof(machine_id));

    if (!have_key_file) {
        /* Emit syslog warning: key derived from world-readable machine-id only */
        syslog(LOG_WARNING,
               "open-bastion: offline cache key derived from machine-id only "
               "(no key file at %s). Generate one with: "
               "dd if=/dev/urandom bs=32 count=1 of=%s && chmod 600 %s",
               kf, kf, kf);
    }

    unsigned char pbkdf_salt[SALT_SIZE];
    if (load_or_generate_salt(cache->cache_dir, pbkdf_salt, SALT_SIZE) != 0) {
        secure_clear(key_material, sizeof(key_material));
        return -1;
    }

    if (PKCS5_PBKDF2_HMAC((char *)key_material, key_material_len,
                          pbkdf_salt, SALT_SIZE,
                          PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          KEY_SIZE, cache->derived_key) != 1) {
        secure_clear(key_material, sizeof(key_material));
        secure_clear(pbkdf_salt, sizeof(pbkdf_salt));
        return -1;
    }

    secure_clear(key_material, sizeof(key_material));
    secure_clear(pbkdf_salt, sizeof(pbkdf_salt));

    cache->key_derived = true;
    return 0;
}

/* Hash password with Argon2id */
static int hash_password(const char *password, size_t password_len,
                         unsigned char *salt, size_t salt_len,
                         unsigned char *hash, size_t hash_len)
{
#ifdef USE_LIBSODIUM
    /*
     * Use libsodium's Argon2id implementation with explicit parameters
     * to ensure cross-backend compatibility with OpenSSL implementation.
     * Note: libsodium's OPSLIMIT/MEMLIMIT_MODERATE differ from our constants.
     */
    unsigned long long opslimit = (unsigned long long)ARGON2_ITERATIONS;
    size_t memlimit = (size_t)ARGON2_MEMORY_KB * 1024ULL;

    if (crypto_pwhash(hash, hash_len,
                      password, password_len,
                      salt,
                      opslimit,
                      memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return -1;
    }
    return 0;
#elif defined(USE_OPENSSL_ARGON2)
    /* Use OpenSSL 3.0+ EVP_KDF for Argon2id */
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return -1;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return -1;

    /*
     * Note: We don't specify "threads" parameter because OpenSSL requires
     * explicit thread pool setup for multi-threaded Argon2. Without threads,
     * OpenSSL runs single-threaded which is fine for our use case.
     * The "lanes" parameter still controls the parallelism degree of the
     * algorithm (affecting memory-hardness), just executed sequentially.
     */
    OSSL_PARAM params[6];
    uint32_t lanes = ARGON2_PARALLELISM;
    uint32_t memcost = ARGON2_MEMORY_KB;
    uint32_t iter = ARGON2_ITERATIONS;

    params[0] = OSSL_PARAM_construct_octet_string("pass", (void *)password, password_len);
    params[1] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    params[2] = OSSL_PARAM_construct_uint32("lanes", &lanes);
    params[3] = OSSL_PARAM_construct_uint32("memcost", &memcost);
    params[4] = OSSL_PARAM_construct_uint32("iter", &iter);
    params[5] = OSSL_PARAM_construct_end();

    int ret = EVP_KDF_derive(kctx, hash, hash_len, params);
    EVP_KDF_CTX_free(kctx);

    return (ret == 1) ? 0 : -1;
#else
    return -1;
#endif
}

/* Verify password against stored hash */
static int verify_password(const char *password, size_t password_len,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *expected_hash, size_t hash_len)
{
    unsigned char computed_hash[ARGON2_HASH_LEN];

    if (hash_len != ARGON2_HASH_LEN) return -1;

    if (hash_password(password, password_len, (unsigned char *)salt, salt_len,
                      computed_hash, sizeof(computed_hash)) != 0) {
        return -1;
    }

    /* Constant-time comparison */
#ifdef USE_LIBSODIUM
    int result = sodium_memcmp(computed_hash, expected_hash, hash_len);
#else
    int result = CRYPTO_memcmp(computed_hash, expected_hash, hash_len);
#endif

    secure_clear(computed_hash, sizeof(computed_hash));
    return result;
}

/* Generate SHA256 hash for cache filename */
static void hash_username(const char *user, char *out, size_t out_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (!ctx) {
        if (out_size > 0) out[0] = '\0';
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, "cred:", 5) != 1 ||
        EVP_DigestUpdate(ctx, user, strlen(user)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        if (out_size > 0) out[0] = '\0';
        return;
    }

    EVP_MD_CTX_free(ctx);

    /* Convert to hex (first 16 bytes = 32 hex chars) */
    if (out_size >= 33 && hash_len >= 16) {
        for (int i = 0; i < 16; i++) {
            snprintf(out + (i * 2), 3, "%02x", hash[i]);
        }
        out[32] = '\0';
    } else if (out_size > 0) {
        out[0] = '\0';
    }

    secure_clear(hash, sizeof(hash));
}

/* Encrypt data using AES-256-GCM */
static int encrypt_data(offline_cache_t *cache,
                        const unsigned char *plaintext, size_t plaintext_len,
                        unsigned char **out, size_t *out_len)
{
    if (!cache->key_derived) return -1;

    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) return -1;

    size_t out_size = IV_SIZE + plaintext_len + TAG_SIZE + 16;
    *out = malloc(out_size);
    if (!*out) return -1;

    memcpy(*out, iv, IV_SIZE);

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

/* Decrypt data using AES-256-GCM */
static int decrypt_data(offline_cache_t *cache,
                        const unsigned char *encrypted, size_t encrypted_len,
                        unsigned char **out, size_t *out_len)
{
    if (!cache->key_derived) return -1;
    if (encrypted_len < IV_SIZE + TAG_SIZE) return -1;

    const unsigned char *iv = encrypted;
    size_t ciphertext_len = encrypted_len - IV_SIZE - TAG_SIZE;
    const unsigned char *ciphertext = encrypted + IV_SIZE;
    const unsigned char *tag = encrypted + IV_SIZE + ciphertext_len;

    *out = malloc(ciphertext_len + 1);
    if (!*out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*out);
        *out = NULL;
        return -1;
    }

    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, cache->derived_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, *out, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }

    int ret = EVP_DecryptFinal_ex(ctx, *out + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        secure_clear(*out, ciphertext_len + 1);
        free(*out);
        *out = NULL;
        return -1;
    }

    plaintext_len += len;
    (*out)[plaintext_len] = '\0';
    *out_len = plaintext_len;
    return 0;
}

/* Build cache file path */
static void build_cache_path(offline_cache_t *cache, const char *user,
                             char *path, size_t path_size)
{
    char hash[64];
    hash_username(user, hash, sizeof(hash));
    snprintf(path, path_size, "%s/%s.cred", cache->cache_dir, hash);
}

/* Base64 encode */
static char *base64_encode(const unsigned char *data, size_t len)
{
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;

    int encoded_len = EVP_EncodeBlock((unsigned char *)out, data, len);
    out[encoded_len] = '\0';
    return out;
}

/* Base64 decode */
static unsigned char *base64_decode(const char *data, size_t *out_len)
{
    size_t in_len = strlen(data);
    size_t max_out = (in_len / 4) * 3 + 1;
    unsigned char *out = malloc(max_out);
    if (!out) return NULL;

    int decoded_len = EVP_DecodeBlock(out, (const unsigned char *)data, in_len);
    if (decoded_len < 0) {
        free(out);
        return NULL;
    }

    /* Remove padding */
    while (decoded_len > 0 && in_len > 0 && data[in_len - 1] == '=') {
        decoded_len--;
        in_len--;
    }

    *out_len = decoded_len;
    return out;
}

offline_cache_t *offline_cache_init(const char *cache_dir, const char *key_file)
{
    if (!cache_dir) return NULL;

    offline_cache_t *cache = calloc(1, sizeof(offline_cache_t));
    if (!cache) return NULL;

#ifdef USE_LIBSODIUM
    if (sodium_init() < 0) {
        free(cache);
        return NULL;
    }
    cache->sodium_initialized = true;
#endif

    cache->cache_dir = strdup(cache_dir);
    if (!cache->cache_dir) {
        free(cache);
        return NULL;
    }

    cache->key_file = key_file ? strdup(key_file) : NULL;

    /* Create directory if needed */
    struct stat st;
    if (stat(cache_dir, &st) != 0) {
        if (mkdir(cache_dir, 0700) != 0 && errno != EEXIST) {
            free(cache->cache_dir);
            free(cache);
            return NULL;
        }
    }

    /* Derive encryption key */
    if (derive_cache_key(cache) != 0) {
        free(cache->cache_dir);
        free(cache);
        return NULL;
    }

    return cache;
}

void offline_cache_destroy(offline_cache_t *cache)
{
    if (!cache) return;

    free(cache->cache_dir);
    free(cache->key_file);
    secure_clear(cache->derived_key, sizeof(cache->derived_key));
    secure_clear(cache, sizeof(*cache));
    free(cache);
}

void offline_cache_set_key_file(offline_cache_t *cache, const char *key_file)
{
    if (!cache) return;
    free(cache->key_file);
    cache->key_file = key_file ? strdup(key_file) : NULL;
}

void offline_cache_set_lockout(offline_cache_t *cache,
                               int max_failures,
                               int lockout_duration)
{
    if (!cache) return;
    cache->max_failed_attempts = max_failures;
    cache->lockout_duration = lockout_duration;
}

void offline_cache_entry_free(offline_cache_entry_t *entry)
{
    if (!entry) return;

    free(entry->user);
    if (entry->password_hash) {
        secure_clear(entry->password_hash, entry->password_hash_len);
        free(entry->password_hash);
    }
    if (entry->salt) {
        secure_clear(entry->salt, entry->salt_len);
        free(entry->salt);
    }
    free(entry->gecos);
    free(entry->shell);
    free(entry->home);

    memset(entry, 0, sizeof(*entry));
}

int offline_cache_store(offline_cache_t *cache,
                        const char *user,
                        const char *password,
                        int ttl,
                        const char *gecos,
                        const char *shell,
                        const char *home)
{
    if (!cache || !user || !password) return OFFLINE_CACHE_ERR_INVALID;

    if (ttl <= 0) ttl = OFFLINE_CACHE_DEFAULT_TTL;

    /* Generate random salt for Argon2id */
    unsigned char salt[ARGON2_SALT_LEN];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        return OFFLINE_CACHE_ERR_CRYPTO;
    }

    /* Hash password with Argon2id */
    unsigned char hash[ARGON2_HASH_LEN];
    if (hash_password(password, strlen(password), salt, sizeof(salt),
                      hash, sizeof(hash)) != 0) {
        secure_clear(salt, sizeof(salt));
        return OFFLINE_CACHE_ERR_CRYPTO;
    }

    /* Build JSON */
    struct json_object *json = json_object_new_object();
    if (!json) {
        secure_clear(hash, sizeof(hash));
        secure_clear(salt, sizeof(salt));
        return OFFLINE_CACHE_ERR_NOMEM;
    }

    time_t now = time(NULL);

    json_object_object_add(json, "v", json_object_new_int(OFFLINE_CACHE_VERSION));
    json_object_object_add(json, "user", json_object_new_string(user));
    json_object_object_add(json, "created_at", json_object_new_int64(now));
    json_object_object_add(json, "expires_at", json_object_new_int64(now + ttl));
    json_object_object_add(json, "last_success", json_object_new_int64(now));
    json_object_object_add(json, "failed_attempts", json_object_new_int(0));
    json_object_object_add(json, "locked_until", json_object_new_int64(0));

    /* Base64 encode hash and salt */
    char *hash_b64 = base64_encode(hash, sizeof(hash));
    char *salt_b64 = base64_encode(salt, sizeof(salt));

    secure_clear(hash, sizeof(hash));
    secure_clear(salt, sizeof(salt));

    if (!hash_b64 || !salt_b64) {
        free(hash_b64);
        free(salt_b64);
        json_object_put(json);
        return OFFLINE_CACHE_ERR_NOMEM;
    }

    json_object_object_add(json, "password_hash", json_object_new_string(hash_b64));
    json_object_object_add(json, "salt", json_object_new_string(salt_b64));

    secure_clear(hash_b64, strlen(hash_b64));
    secure_clear(salt_b64, strlen(salt_b64));
    free(hash_b64);
    free(salt_b64);

    /* Add optional fields */
    if (gecos) {
        json_object_object_add(json, "gecos", json_object_new_string(gecos));
    }
    if (shell) {
        json_object_object_add(json, "shell", json_object_new_string(shell));
    }
    if (home) {
        json_object_object_add(json, "home", json_object_new_string(home));
    }

    const char *json_str = json_object_to_json_string(json);
    size_t json_len = strlen(json_str);

    /* Encrypt */
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;

    if (encrypt_data(cache, (unsigned char *)json_str, json_len,
                     &encrypted, &encrypted_len) != 0) {
        json_object_put(json);
        return OFFLINE_CACHE_ERR_CRYPTO;
    }

    json_object_put(json);

    /* Write to file */
    char path[PATH_MAX];
    build_cache_path(cache, user, path, sizeof(path));

    char temp_path[PATH_MAX + 16];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", path, (int)getpid());

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        secure_clear(encrypted, encrypted_len);
        free(encrypted);
        return OFFLINE_CACHE_ERR_IO;
    }

    /* Write magic + encrypted data */
    ssize_t written = write(fd, OFFLINE_CACHE_MAGIC, MAGIC_LEN);
    if (written != MAGIC_LEN) {
        close(fd);
        unlink(temp_path);
        secure_clear(encrypted, encrypted_len);
        free(encrypted);
        return OFFLINE_CACHE_ERR_IO;
    }

    written = write(fd, encrypted, encrypted_len);
    secure_clear(encrypted, encrypted_len);
    free(encrypted);

    if (written != (ssize_t)encrypted_len) {
        close(fd);
        unlink(temp_path);
        return OFFLINE_CACHE_ERR_IO;
    }

    /* Ensure data is persisted before rename to prevent data loss on crash */
    fsync(fd);
    close(fd);

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return OFFLINE_CACHE_ERR_IO;
    }

    return OFFLINE_CACHE_OK;
}

/* Internal function to read and parse cache entry */
static int read_cache_entry(offline_cache_t *cache, const char *user,
                            struct json_object **json_out)
{
    char path[PATH_MAX];
    build_cache_path(cache, user, path, sizeof(path));

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            unlink(path);
        }
        return OFFLINE_CACHE_ERR_NOTFOUND;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return OFFLINE_CACHE_ERR_NOTFOUND;
    }

    /* Sanity check: cache files should never exceed 1 MiB */
    if (st.st_size > 1024 * 1024) {
        close(fd);
        return OFFLINE_CACHE_ERR_INVALID;
    }

    unsigned char *data = malloc(st.st_size + 1);
    if (!data) {
        close(fd);
        return OFFLINE_CACHE_ERR_NOMEM;
    }

    ssize_t bytes_read = read(fd, data, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(data);
        return OFFLINE_CACHE_ERR_IO;
    }
    data[st.st_size] = '\0';

    /* Check magic */
    if ((size_t)st.st_size <= MAGIC_LEN ||
        memcmp(data, OFFLINE_CACHE_MAGIC, MAGIC_LEN) != 0) {
        free(data);
        unlink(path);
        return OFFLINE_CACHE_ERR_INVALID;
    }

    /* Decrypt */
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;

    if (decrypt_data(cache, data + MAGIC_LEN, st.st_size - MAGIC_LEN,
                     &decrypted, &decrypted_len) != 0) {
        secure_clear(data, st.st_size);
        free(data);
        unlink(path);
        return OFFLINE_CACHE_ERR_CRYPTO;
    }

    secure_clear(data, st.st_size);
    free(data);

    /* Parse JSON */
    *json_out = json_tokener_parse((char *)decrypted);
    secure_clear(decrypted, decrypted_len);
    free(decrypted);

    if (!*json_out) {
        unlink(path);
        return OFFLINE_CACHE_ERR_INVALID;
    }

    /* Verify user matches */
    struct json_object *val;
    if (json_object_object_get_ex(*json_out, "user", &val)) {
        const char *cached_user = json_object_get_string(val);
        if (!cached_user || strcmp(cached_user, user) != 0) {
            json_object_put(*json_out);
            *json_out = NULL;
            unlink(path);
            return OFFLINE_CACHE_ERR_INVALID;
        }
    }

    return OFFLINE_CACHE_OK;
}

/* Update cache entry (for failed attempts, locked_until, etc.) */
static int update_cache_entry(offline_cache_t *cache, const char *user,
                              struct json_object *json)
{
    const char *json_str = json_object_to_json_string(json);
    size_t json_len = strlen(json_str);

    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;

    if (encrypt_data(cache, (unsigned char *)json_str, json_len,
                     &encrypted, &encrypted_len) != 0) {
        return OFFLINE_CACHE_ERR_CRYPTO;
    }

    char path[PATH_MAX];
    build_cache_path(cache, user, path, sizeof(path));

    char temp_path[PATH_MAX + 16];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", path, (int)getpid());

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        secure_clear(encrypted, encrypted_len);
        free(encrypted);
        return OFFLINE_CACHE_ERR_IO;
    }

    ssize_t written = write(fd, OFFLINE_CACHE_MAGIC, MAGIC_LEN);
    if (written != MAGIC_LEN) {
        close(fd);
        unlink(temp_path);
        secure_clear(encrypted, encrypted_len);
        free(encrypted);
        return OFFLINE_CACHE_ERR_IO;
    }

    written = write(fd, encrypted, encrypted_len);
    secure_clear(encrypted, encrypted_len);
    free(encrypted);

    if (written != (ssize_t)encrypted_len) {
        close(fd);
        unlink(temp_path);
        return OFFLINE_CACHE_ERR_IO;
    }

    /* Ensure data is persisted before rename to prevent data loss on crash */
    fsync(fd);
    close(fd);

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return OFFLINE_CACHE_ERR_IO;
    }

    return OFFLINE_CACHE_OK;
}

int offline_cache_verify(offline_cache_t *cache,
                         const char *user,
                         const char *password,
                         offline_cache_entry_t *entry)
{
    if (!cache || !user || !password) return OFFLINE_CACHE_ERR_INVALID;

    if (entry) {
        memset(entry, 0, sizeof(*entry));
    }

    struct json_object *json = NULL;
    int ret = read_cache_entry(cache, user, &json);
    if (ret != OFFLINE_CACHE_OK) {
        return ret;
    }

    struct json_object *val;
    time_t now = time(NULL);

    /* Check expiration */
    if (json_object_object_get_ex(json, "expires_at", &val)) {
        time_t expires_at = (time_t)json_object_get_int64(val);
        if (now >= expires_at) {
            json_object_put(json);
            char path[PATH_MAX];
            build_cache_path(cache, user, path, sizeof(path));
            unlink(path);
            return OFFLINE_CACHE_ERR_EXPIRED;
        }
    }

    /* Check lockout */
    if (json_object_object_get_ex(json, "locked_until", &val)) {
        time_t locked_until = (time_t)json_object_get_int64(val);
        if (locked_until > 0 && now < locked_until) {
            json_object_put(json);
            return OFFLINE_CACHE_ERR_LOCKED;
        }
    }

    /* Get password hash and salt */
    const char *hash_b64 = NULL;
    const char *salt_b64 = NULL;

    if (json_object_object_get_ex(json, "password_hash", &val)) {
        hash_b64 = json_object_get_string(val);
    }
    if (json_object_object_get_ex(json, "salt", &val)) {
        salt_b64 = json_object_get_string(val);
    }

    if (!hash_b64 || !salt_b64) {
        json_object_put(json);
        return OFFLINE_CACHE_ERR_INVALID;
    }

    /* Decode hash and salt */
    size_t hash_len = 0, salt_len = 0;
    unsigned char *hash = base64_decode(hash_b64, &hash_len);
    unsigned char *salt = base64_decode(salt_b64, &salt_len);

    if (!hash || !salt || hash_len != ARGON2_HASH_LEN || salt_len != ARGON2_SALT_LEN) {
        if (hash) {
            secure_clear(hash, hash_len);
            free(hash);
        }
        if (salt) {
            secure_clear(salt, salt_len);
            free(salt);
        }
        json_object_put(json);
        return OFFLINE_CACHE_ERR_INVALID;
    }

    /* Verify password */
    int verify_result = verify_password(password, strlen(password),
                                        salt, salt_len, hash, hash_len);

    secure_clear(hash, hash_len);
    secure_clear(salt, salt_len);
    free(hash);
    free(salt);

    if (verify_result != 0) {
        /* Password mismatch - increment failed attempts */
        int failed_attempts = 0;
        if (json_object_object_get_ex(json, "failed_attempts", &val)) {
            failed_attempts = json_object_get_int(val);
        }
        failed_attempts++;

        /* Update failed attempts and possibly lock */
        json_object_object_del(json, "failed_attempts");
        json_object_object_add(json, "failed_attempts", json_object_new_int(failed_attempts));

        int max_attempts = cache->max_failed_attempts > 0
            ? cache->max_failed_attempts : OFFLINE_CACHE_MAX_FAILED_ATTEMPTS;
        int lockout_secs = cache->lockout_duration > 0
            ? cache->lockout_duration : OFFLINE_CACHE_LOCKOUT_DURATION;

        if (failed_attempts >= max_attempts) {
            time_t lockout_until = now + lockout_secs;
            json_object_object_del(json, "locked_until");
            json_object_object_add(json, "locked_until", json_object_new_int64(lockout_until));
        }

        update_cache_entry(cache, user, json);
        json_object_put(json);
        return OFFLINE_CACHE_ERR_PASSWORD;
    }

    /* Password verified - reset failed attempts and update last success */
    json_object_object_del(json, "failed_attempts");
    json_object_object_add(json, "failed_attempts", json_object_new_int(0));
    json_object_object_del(json, "locked_until");
    json_object_object_add(json, "locked_until", json_object_new_int64(0));
    json_object_object_del(json, "last_success");
    json_object_object_add(json, "last_success", json_object_new_int64(now));

    update_cache_entry(cache, user, json);

    /* Fill entry if requested */
    if (entry) {
        entry->version = OFFLINE_CACHE_VERSION;
        if (json_object_object_get_ex(json, "user", &val)) {
            entry->user = safe_json_strdup(val);
        }
        if (json_object_object_get_ex(json, "created_at", &val)) {
            entry->created_at = (time_t)json_object_get_int64(val);
        }
        if (json_object_object_get_ex(json, "expires_at", &val)) {
            entry->expires_at = (time_t)json_object_get_int64(val);
        }
        if (json_object_object_get_ex(json, "last_success", &val)) {
            entry->last_success = (time_t)json_object_get_int64(val);
        }
        if (json_object_object_get_ex(json, "gecos", &val)) {
            entry->gecos = safe_json_strdup(val);
        }
        if (json_object_object_get_ex(json, "shell", &val)) {
            entry->shell = safe_json_strdup(val);
        }
        if (json_object_object_get_ex(json, "home", &val)) {
            entry->home = safe_json_strdup(val);
        }
        entry->failed_attempts = 0;
        entry->locked_until = 0;
    }

    json_object_put(json);
    return OFFLINE_CACHE_OK;
}

bool offline_cache_has_entry(offline_cache_t *cache, const char *user)
{
    if (!cache || !user) return false;

    struct json_object *json = NULL;
    int ret = read_cache_entry(cache, user, &json);
    if (ret != OFFLINE_CACHE_OK) {
        return false;
    }

    struct json_object *val;
    time_t now = time(NULL);

    /* Check expiration */
    if (json_object_object_get_ex(json, "expires_at", &val)) {
        time_t expires_at = (time_t)json_object_get_int64(val);
        if (now >= expires_at) {
            json_object_put(json);
            return false;
        }
    }

    /* Check lockout */
    if (json_object_object_get_ex(json, "locked_until", &val)) {
        time_t locked_until = (time_t)json_object_get_int64(val);
        if (locked_until > 0 && now < locked_until) {
            json_object_put(json);
            return false;
        }
    }

    json_object_put(json);
    return true;
}

int offline_cache_get_entry(offline_cache_t *cache,
                            const char *user,
                            offline_cache_entry_t *entry)
{
    if (!cache || !user || !entry) return OFFLINE_CACHE_ERR_INVALID;

    memset(entry, 0, sizeof(*entry));

    struct json_object *json = NULL;
    int ret = read_cache_entry(cache, user, &json);
    if (ret != OFFLINE_CACHE_OK) {
        return ret;
    }

    struct json_object *val;

    entry->version = OFFLINE_CACHE_VERSION;
    if (json_object_object_get_ex(json, "user", &val)) {
        entry->user = safe_json_strdup(val);
    }
    if (json_object_object_get_ex(json, "created_at", &val)) {
        entry->created_at = (time_t)json_object_get_int64(val);
    }
    if (json_object_object_get_ex(json, "expires_at", &val)) {
        entry->expires_at = (time_t)json_object_get_int64(val);
    }
    if (json_object_object_get_ex(json, "last_success", &val)) {
        entry->last_success = (time_t)json_object_get_int64(val);
    }
    if (json_object_object_get_ex(json, "failed_attempts", &val)) {
        entry->failed_attempts = json_object_get_int(val);
    }
    if (json_object_object_get_ex(json, "locked_until", &val)) {
        entry->locked_until = (time_t)json_object_get_int64(val);
    }
    if (json_object_object_get_ex(json, "gecos", &val)) {
        entry->gecos = safe_json_strdup(val);
    }
    if (json_object_object_get_ex(json, "shell", &val)) {
        entry->shell = safe_json_strdup(val);
    }
    if (json_object_object_get_ex(json, "home", &val)) {
        entry->home = safe_json_strdup(val);
    }

    json_object_put(json);
    return OFFLINE_CACHE_OK;
}

int offline_cache_invalidate(offline_cache_t *cache, const char *user)
{
    if (!cache || !user) return OFFLINE_CACHE_ERR_INVALID;

    char path[PATH_MAX];
    build_cache_path(cache, user, path, sizeof(path));
    unlink(path);
    return OFFLINE_CACHE_OK;
}

int offline_cache_invalidate_all(offline_cache_t *cache)
{
    if (!cache) return OFFLINE_CACHE_ERR_INVALID;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return OFFLINE_CACHE_ERR_IO;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cred") == NULL) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);
        unlink(path);
    }

    closedir(dir);
    return OFFLINE_CACHE_OK;
}

int offline_cache_reset_failures(offline_cache_t *cache, const char *user)
{
    if (!cache || !user) return OFFLINE_CACHE_ERR_INVALID;

    struct json_object *json = NULL;
    int ret = read_cache_entry(cache, user, &json);
    if (ret != OFFLINE_CACHE_OK) {
        return ret;
    }

    json_object_object_del(json, "failed_attempts");
    json_object_object_add(json, "failed_attempts", json_object_new_int(0));
    json_object_object_del(json, "locked_until");
    json_object_object_add(json, "locked_until", json_object_new_int64(0));

    ret = update_cache_entry(cache, user, json);
    json_object_put(json);
    return ret;
}

int offline_cache_cleanup(offline_cache_t *cache)
{
    if (!cache) return 0;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return 0;

    int removed = 0;
    struct dirent *entry;
    time_t now = time(NULL);

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cred") == NULL) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        int fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
            if (errno == ELOOP) {
                unlink(path);
                removed++;
            }
            continue;
        }

        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size == 0) {
            close(fd);
            unlink(path);
            removed++;
            continue;
        }

        unsigned char *data = malloc(st.st_size + 1);
        if (!data) {
            close(fd);
            continue;
        }

        ssize_t bytes_read = read(fd, data, st.st_size);
        close(fd);

        if (bytes_read != st.st_size) {
            free(data);
            unlink(path);
            removed++;
            continue;
        }
        data[st.st_size] = '\0';

        /* Check magic */
        if ((size_t)st.st_size <= MAGIC_LEN ||
            memcmp(data, OFFLINE_CACHE_MAGIC, MAGIC_LEN) != 0) {
            free(data);
            unlink(path);
            removed++;
            continue;
        }

        /* Decrypt and check expiration */
        unsigned char *decrypted = NULL;
        size_t decrypted_len = 0;

        if (decrypt_data(cache, data + MAGIC_LEN, st.st_size - MAGIC_LEN,
                         &decrypted, &decrypted_len) != 0) {
            secure_clear(data, st.st_size);
            free(data);
            unlink(path);
            removed++;
            continue;
        }

        secure_clear(data, st.st_size);
        free(data);

        struct json_object *json = json_tokener_parse((char *)decrypted);
        secure_clear(decrypted, decrypted_len);
        free(decrypted);

        if (!json) {
            unlink(path);
            removed++;
            continue;
        }

        struct json_object *val;
        if (json_object_object_get_ex(json, "expires_at", &val)) {
            time_t expires_at = (time_t)json_object_get_int64(val);
            if (now >= expires_at) {
                json_object_put(json);
                unlink(path);
                removed++;
                continue;
            }
        }

        json_object_put(json);
    }

    closedir(dir);
    return removed;
}

int offline_cache_stats(offline_cache_t *cache,
                        int *total,
                        int *active,
                        int *locked)
{
    if (!cache) return OFFLINE_CACHE_ERR_INVALID;

    if (total) *total = 0;
    if (active) *active = 0;
    if (locked) *locked = 0;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return OFFLINE_CACHE_ERR_IO;

    struct dirent *entry;
    time_t now = time(NULL);

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cred") == NULL) continue;

        if (total) (*total)++;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        int fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) continue;

        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size == 0) {
            close(fd);
            continue;
        }

        unsigned char *data = malloc(st.st_size + 1);
        if (!data) {
            close(fd);
            continue;
        }

        ssize_t bytes_read = read(fd, data, st.st_size);
        close(fd);

        if (bytes_read != st.st_size) {
            free(data);
            continue;
        }
        data[st.st_size] = '\0';

        if ((size_t)st.st_size <= MAGIC_LEN ||
            memcmp(data, OFFLINE_CACHE_MAGIC, MAGIC_LEN) != 0) {
            free(data);
            continue;
        }

        unsigned char *decrypted = NULL;
        size_t decrypted_len = 0;

        if (decrypt_data(cache, data + MAGIC_LEN, st.st_size - MAGIC_LEN,
                         &decrypted, &decrypted_len) != 0) {
            secure_clear(data, st.st_size);
            free(data);
            continue;
        }

        secure_clear(data, st.st_size);
        free(data);

        struct json_object *json = json_tokener_parse((char *)decrypted);
        secure_clear(decrypted, decrypted_len);
        free(decrypted);

        if (!json) continue;

        struct json_object *val;

        /* Check if expired */
        bool is_active = true;
        if (json_object_object_get_ex(json, "expires_at", &val)) {
            time_t expires_at = (time_t)json_object_get_int64(val);
            if (now >= expires_at) {
                is_active = false;
            }
        }

        if (is_active && active) (*active)++;

        /* Check if locked */
        if (json_object_object_get_ex(json, "locked_until", &val)) {
            time_t locked_until = (time_t)json_object_get_int64(val);
            if (locked_until > 0 && now < locked_until) {
                if (locked) (*locked)++;
            }
        }

        json_object_put(json);
    }

    closedir(dir);
    return OFFLINE_CACHE_OK;
}
