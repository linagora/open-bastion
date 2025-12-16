/*
 * secret_store.c - Machine-specific secret encryption for PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include "secret_store.h"

/* Constants */
#define MACHINE_ID_FILE "/etc/machine-id"
#define KEY_SIZE 32         /* AES-256 */
#define IV_SIZE 12          /* GCM recommended IV size */
#define TAG_SIZE 16         /* GCM authentication tag */
#define SALT_SIZE 16        /* PBKDF2 salt */
#define PBKDF2_ITERATIONS 100000

/* Secret store structure */
struct secret_store {
    secret_store_config_t config;
    unsigned char derived_key[KEY_SIZE];
    bool key_derived;
    char error_buf[256];
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
static int derive_key(secret_store_t *store)
{
    char machine_id[64] = {0};

    if (read_machine_id(machine_id, sizeof(machine_id)) != 0) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to read machine-id");
        return -1;
    }

    /* Combine machine-id with optional salt */
    char combined[256];
    int combined_len;
    if (store->config.salt) {
        combined_len = snprintf(combined, sizeof(combined), "%s:%s",
                                machine_id, store->config.salt);
    } else {
        combined_len = snprintf(combined, sizeof(combined), "%s", machine_id);
    }

    /*
     * Derive a unique salt from machine-id to avoid rainbow table attacks.
     * We hash the machine-id to create a per-installation salt.
     * This is better than a static salt while still being deterministic.
     */
    unsigned char pbkdf_salt[SALT_SIZE];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char salt_hash[EVP_MAX_MD_SIZE];
    unsigned int salt_hash_len = 0;

    if (!md_ctx ||
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, "pam_llng_salt:", 14) != 1 ||
        EVP_DigestUpdate(md_ctx, machine_id, strlen(machine_id)) != 1 ||
        EVP_DigestFinal_ex(md_ctx, salt_hash, &salt_hash_len) != 1) {
        if (md_ctx) EVP_MD_CTX_free(md_ctx);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Salt derivation failed");
        explicit_bzero(machine_id, sizeof(machine_id));
        explicit_bzero(combined, sizeof(combined));
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);

    /* Use first SALT_SIZE bytes of hash as salt */
    memcpy(pbkdf_salt, salt_hash, SALT_SIZE);
    explicit_bzero(salt_hash, sizeof(salt_hash));

    /* Derive key using PBKDF2 */
    if (PKCS5_PBKDF2_HMAC(combined, combined_len,
                          pbkdf_salt, SALT_SIZE,
                          PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          KEY_SIZE, store->derived_key) != 1) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Key derivation failed");
        explicit_bzero(machine_id, sizeof(machine_id));
        explicit_bzero(combined, sizeof(combined));
        explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));
        return -1;
    }

    explicit_bzero(machine_id, sizeof(machine_id));
    explicit_bzero(combined, sizeof(combined));
    explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));

    store->key_derived = true;
    return 0;
}

/* Build file path for a key */
static void build_path(secret_store_t *store, const char *key,
                       char *path, size_t path_size)
{
    /* Hash the key to get a filename-safe string */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, key, strlen(key)) == 1 &&
        EVP_DigestFinal_ex(ctx, hash, &hash_len) == 1) {

        char hash_hex[65];
        for (unsigned int i = 0; i < 32 && i < hash_len; i++) {
            snprintf(hash_hex + (i * 2), 3, "%02x", hash[i]);
        }

        snprintf(path, path_size, "%s/%s.enc", store->config.store_dir, hash_hex);
    } else {
        path[0] = '\0';
    }

    if (ctx) EVP_MD_CTX_free(ctx);
}

secret_store_t *secret_store_init(const secret_store_config_t *config)
{
    if (!config) return NULL;

    secret_store_t *store = calloc(1, sizeof(secret_store_t));
    if (!store) return NULL;

    /* Copy configuration */
    store->config.enabled = config->enabled;
    store->config.use_keyring = config->use_keyring;

    if (config->store_dir) {
        store->config.store_dir = strdup(config->store_dir);
    } else {
        store->config.store_dir = strdup("/var/lib/pam_llng/secrets");
    }

    if (config->salt) {
        store->config.salt = strdup(config->salt);
    }

    if (config->keyring_name) {
        store->config.keyring_name = strdup(config->keyring_name);
    } else {
        store->config.keyring_name = strdup("pam_llng");
    }

    /* Create store directory if needed */
    struct stat st;
    if (stat(store->config.store_dir, &st) != 0) {
        if (mkdir(store->config.store_dir, 0700) != 0 && errno != EEXIST) {
            /* Try to create parent directories with restricted permissions */
            char *parent = strdup(store->config.store_dir);
            if (parent) {
                char *last_slash = strrchr(parent, '/');
                if (last_slash) {
                    *last_slash = '\0';
                    mkdir(parent, 0700);
                }
                free(parent);
            }
            mkdir(store->config.store_dir, 0700);
        }
    }

    /* Derive encryption key */
    if (store->config.enabled && derive_key(store) != 0) {
        secret_store_destroy(store);
        return NULL;
    }

    return store;
}

void secret_store_destroy(secret_store_t *store)
{
    if (!store) return;

    free(store->config.store_dir);
    free(store->config.salt);
    free(store->config.keyring_name);

    /* Securely clear derived key */
    explicit_bzero(store->derived_key, sizeof(store->derived_key));
    explicit_bzero(store, sizeof(*store));
    free(store);
}

int secret_store_put(secret_store_t *store,
                     const char *key,
                     const void *secret,
                     size_t secret_len)
{
    if (!store || !key || !secret || secret_len == 0) {
        return -1;
    }

    if (!store->config.enabled) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Secret store is disabled");
        return -1;
    }

    if (!store->key_derived) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Encryption key not derived");
        return -1;
    }

    /* Generate random IV */
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to generate IV");
        return -1;
    }

    /* Allocate output buffer: IV + ciphertext + tag */
    size_t out_size = IV_SIZE + secret_len + TAG_SIZE + 16;  /* +16 for potential padding */
    unsigned char *out = malloc(out_size);
    if (!out) return -1;

    /* Copy IV to output */
    memcpy(out, iv, IV_SIZE);

    /* Encrypt using AES-256-GCM */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(out);
        return -1;
    }

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, store->derived_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, out + IV_SIZE, &len, secret, secret_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(out);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Encryption failed");
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, out + IV_SIZE + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(out);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Encryption finalization failed");
        return -1;
    }
    ciphertext_len += len;

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                            out + IV_SIZE + ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(out);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to get auth tag");
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    /* Total output size: IV + ciphertext + tag */
    size_t total_size = IV_SIZE + ciphertext_len + TAG_SIZE;

    /* Write to file */
    char path[512];
    build_path(store, key, path, sizeof(path));

    char temp_path[520];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        free(out);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to create secret file: %s", strerror(errno));
        return -1;
    }

    ssize_t written = write(fd, out, total_size);
    close(fd);

    /* Clear and free output buffer */
    explicit_bzero(out, out_size);
    free(out);

    if (written != (ssize_t)total_size) {
        unlink(temp_path);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to write secret file");
        return -1;
    }

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to rename secret file");
        return -1;
    }

    return 0;
}

int secret_store_get(secret_store_t *store,
                     const char *key,
                     void *secret,
                     size_t secret_size,
                     size_t *actual_len)
{
    if (!store || !key || !secret || secret_size == 0) {
        return -1;
    }

    if (!store->config.enabled) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Secret store is disabled");
        return -1;
    }

    if (!store->key_derived) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Encryption key not derived");
        return -1;
    }

    /* Read from file */
    char path[512];
    build_path(store, key, path, sizeof(path));

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) {
            return -2;  /* Not found */
        }
        if (errno == ELOOP) {
            /* Symlink detected - security violation, remove it */
            unlink(path);
            snprintf(store->error_buf, sizeof(store->error_buf),
                     "Symlink detected in secret store - removed");
            return -1;
        }
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to open secret file: %s", strerror(errno));
        return -1;
    }

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }

    /* Minimum size: IV + tag */
    if (st.st_size < IV_SIZE + TAG_SIZE) {
        close(fd);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Secret file too small");
        return -1;
    }

    /* Read file */
    unsigned char *data = malloc(st.st_size);
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

    /* Extract IV, ciphertext, and tag */
    unsigned char *iv = data;
    size_t ciphertext_len = st.st_size - IV_SIZE - TAG_SIZE;
    unsigned char *ciphertext = data + IV_SIZE;
    unsigned char *tag = data + IV_SIZE + ciphertext_len;

    /* Decrypt using AES-256-GCM */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        explicit_bzero(data, st.st_size);
        free(data);
        return -1;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, store->derived_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, secret, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        explicit_bzero(data, st.st_size);
        free(data);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Decryption failed");
        return -1;
    }
    plaintext_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        explicit_bzero(data, st.st_size);
        free(data);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to set auth tag");
        return -1;
    }

    /* Finalize and verify tag */
    int ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)secret + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    explicit_bzero(data, st.st_size);
    free(data);

    if (ret <= 0) {
        /* Tag verification failed - data may be tampered */
        explicit_bzero(secret, secret_size);
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Authentication failed - secret may be tampered");
        return -1;
    }

    plaintext_len += len;
    if (actual_len) {
        *actual_len = plaintext_len;
    }

    return 0;
}

int secret_store_delete(secret_store_t *store, const char *key)
{
    if (!store || !key) {
        return -1;
    }

    char path[512];
    build_path(store, key, path, sizeof(path));

    /* Overwrite file with zeros before deletion */
    int fd = open(path, O_WRONLY | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) {
            char *zeros = calloc(1, st.st_size);
            if (zeros) {
                ssize_t ret = write(fd, zeros, st.st_size);
                (void)ret;  /* Best effort secure deletion */
                free(zeros);
            }
        }
        close(fd);
    }

    if (unlink(path) != 0 && errno != ENOENT) {
        snprintf(store->error_buf, sizeof(store->error_buf),
                 "Failed to delete secret: %s", strerror(errno));
        return -1;
    }

    return 0;
}

bool secret_store_exists(secret_store_t *store, const char *key)
{
    if (!store || !key) return false;

    char path[512];
    build_path(store, key, path, sizeof(path));

    struct stat st;
    return stat(path, &st) == 0;
}

int secret_store_rotate_key(secret_store_t *store)
{
    if (!store) return -1;

    /*
     * Key rotation is not automatically supported.
     *
     * If machine-id changes (e.g., VM cloning, reinstallation), all stored
     * secrets become unreadable because the derived encryption key changes.
     *
     * To handle this scenario:
     * 1. Before machine-id change: decrypt and backup all secrets
     * 2. After machine-id change: re-encrypt secrets with new key
     *
     * This function exists as a placeholder to document this limitation.
     * A future implementation could iterate all .enc files in store_dir,
     * but would need the old key to decrypt first.
     */
    snprintf(store->error_buf, sizeof(store->error_buf),
             "Automatic key rotation not supported. "
             "If machine-id changed, secrets must be manually re-created.");
    return -1;
}

const char *secret_store_error(secret_store_t *store)
{
    return store ? store->error_buf : "NULL secret store";
}
