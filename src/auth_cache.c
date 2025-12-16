/*
 * auth_cache.c - Authorization cache for offline mode
 *
 * Caches authorization responses from LLNG server for offline use.
 * Uses JSON format (LLNGCACHE03) with AES-256-GCM encryption.
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
#include <json-c/json.h>

#include "auth_cache.h"

/* Cache format version */
#define AUTH_CACHE_VERSION 3
#define AUTH_CACHE_MAGIC "LLNGCACHE03"

/* Safe strdup from JSON - returns NULL if json string is NULL */
static inline char *safe_json_strdup(struct json_object *obj)
{
    const char *str = json_object_get_string(obj);
    return str ? strdup(str) : NULL;
}

/* Encryption constants (same as token_cache) */
#define MACHINE_ID_FILE "/etc/machine-id"
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 100000

/* Maximum cache entries */
#define MAX_AUTH_CACHE_ENTRIES 10000

/* Cache structure */
struct auth_cache {
    char *cache_dir;
    unsigned char derived_key[KEY_SIZE];
    bool key_derived;
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

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    return 0;
}

/* Derive encryption key from machine-id */
static int derive_auth_cache_key(auth_cache_t *cache)
{
    char machine_id[64] = {0};

    if (read_machine_id(machine_id, sizeof(machine_id)) != 0) {
        return -1;
    }

    /* Derive unique salt for auth cache */
    unsigned char pbkdf_salt[SALT_SIZE];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char salt_hash[EVP_MAX_MD_SIZE];
    unsigned int salt_hash_len = 0;

    if (!md_ctx ||
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, "pam_llng_auth_cache_salt:", 25) != 1 ||
        EVP_DigestUpdate(md_ctx, machine_id, strlen(machine_id)) != 1 ||
        EVP_DigestFinal_ex(md_ctx, salt_hash, &salt_hash_len) != 1) {
        if (md_ctx) EVP_MD_CTX_free(md_ctx);
        explicit_bzero(machine_id, sizeof(machine_id));
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);

    memcpy(pbkdf_salt, salt_hash, SALT_SIZE);
    explicit_bzero(salt_hash, sizeof(salt_hash));

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

/* Generate SHA256 hash for cache key */
static void hash_cache_key(const char *user, const char *server_group,
                           const char *host, char *out, size_t out_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (!ctx) {
        if (out_size > 0) out[0] = '\0';
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, "auth:", 5) != 1 ||
        EVP_DigestUpdate(ctx, user, strlen(user)) != 1 ||
        EVP_DigestUpdate(ctx, ":", 1) != 1 ||
        EVP_DigestUpdate(ctx, server_group ? server_group : "default",
                         server_group ? strlen(server_group) : 7) != 1 ||
        EVP_DigestUpdate(ctx, ":", 1) != 1 ||
        EVP_DigestUpdate(ctx, host, strlen(host)) != 1 ||
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

    explicit_bzero(hash, sizeof(hash));
}

/* Encrypt data using AES-256-GCM */
static int encrypt_data(auth_cache_t *cache,
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
static int decrypt_data(auth_cache_t *cache,
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

auth_cache_t *auth_cache_init(const char *cache_dir)
{
    if (!cache_dir) return NULL;

    auth_cache_t *cache = calloc(1, sizeof(auth_cache_t));
    if (!cache) return NULL;

    cache->cache_dir = strdup(cache_dir);
    if (!cache->cache_dir) {
        free(cache);
        return NULL;
    }

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
    if (derive_auth_cache_key(cache) != 0) {
        free(cache->cache_dir);
        free(cache);
        return NULL;
    }

    return cache;
}

void auth_cache_destroy(auth_cache_t *cache)
{
    if (!cache) return;
    free(cache->cache_dir);
    explicit_bzero(cache->derived_key, sizeof(cache->derived_key));
    explicit_bzero(cache, sizeof(*cache));
    free(cache);
}

/* Build cache file path */
static void build_auth_cache_path(auth_cache_t *cache,
                                  const char *user,
                                  const char *server_group,
                                  const char *host,
                                  char *path, size_t path_size)
{
    char hash[64];
    hash_cache_key(user, server_group, host, hash, sizeof(hash));
    snprintf(path, path_size, "%s/%s.authcache", cache->cache_dir, hash);
}

bool auth_cache_lookup(auth_cache_t *cache,
                       const char *user,
                       const char *server_group,
                       const char *host,
                       auth_cache_entry_t *entry)
{
    if (!cache || !user || !host || !entry) return false;

    memset(entry, 0, sizeof(*entry));

    char path[PATH_MAX];
    build_auth_cache_path(cache, user, server_group, host, path, sizeof(path));

    /* Read file */
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            /* Symlink detected - security violation, remove it */
            unlink(path);
        }
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return false;
    }

    unsigned char *data = malloc(st.st_size + 1);
    if (!data) {
        close(fd);
        return false;
    }

    ssize_t bytes_read = read(fd, data, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(data);
        return false;
    }
    data[st.st_size] = '\0';

    /* Check magic */
    size_t magic_len = strlen(AUTH_CACHE_MAGIC);
    if ((size_t)st.st_size <= magic_len ||
        memcmp(data, AUTH_CACHE_MAGIC, magic_len) != 0) {
        free(data);
        unlink(path);
        return false;
    }

    /* Decrypt */
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;

    if (decrypt_data(cache, data + magic_len, st.st_size - magic_len,
                     &decrypted, &decrypted_len) != 0) {
        explicit_bzero(data, st.st_size);
        free(data);
        unlink(path);
        return false;
    }

    explicit_bzero(data, st.st_size);
    free(data);

    /* Parse JSON */
    struct json_object *json = json_tokener_parse((char *)decrypted);
    explicit_bzero(decrypted, decrypted_len);
    free(decrypted);

    if (!json) {
        unlink(path);
        return false;
    }

    struct json_object *val;

    /* Check version */
    if (json_object_object_get_ex(json, "v", &val)) {
        if (json_object_get_int(val) != AUTH_CACHE_VERSION) {
            json_object_put(json);
            unlink(path);
            return false;
        }
    }

    /* Check expiration */
    if (json_object_object_get_ex(json, "expires_at", &val)) {
        entry->expires_at = (time_t)json_object_get_int64(val);
        if (time(NULL) >= entry->expires_at) {
            json_object_put(json);
            unlink(path);
            return false;
        }
    } else {
        json_object_put(json);
        unlink(path);
        return false;
    }

    /* Verify user matches */
    if (json_object_object_get_ex(json, "user", &val)) {
        const char *cached_user = json_object_get_string(val);
        if (!cached_user || strcmp(cached_user, user) != 0) {
            json_object_put(json);
            unlink(path);
            return false;
        }
        entry->user = strdup(cached_user);
    }

    /* Parse remaining fields */
    if (json_object_object_get_ex(json, "authorized", &val)) {
        entry->authorized = json_object_get_boolean(val);
    }

    if (json_object_object_get_ex(json, "groups", &val)) {
        if (json_object_is_type(val, json_type_array)) {
            size_t count = json_object_array_length(val);
            entry->groups = calloc(count + 1, sizeof(char *));
            if (entry->groups) {
                entry->groups_count = count;
                for (size_t i = 0; i < count; i++) {
                    struct json_object *g = json_object_array_get_idx(val, i);
                    if (g) {
                        entry->groups[i] = safe_json_strdup(g);
                    }
                }
            }
        }
    }

    if (json_object_object_get_ex(json, "sudo_allowed", &val)) {
        entry->sudo_allowed = json_object_get_boolean(val);
    }

    if (json_object_object_get_ex(json, "sudo_nopasswd", &val)) {
        entry->sudo_nopasswd = json_object_get_boolean(val);
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

    entry->version = AUTH_CACHE_VERSION;
    json_object_put(json);
    return true;
}

int auth_cache_store(auth_cache_t *cache,
                     const char *user,
                     const char *server_group,
                     const char *host,
                     const auth_cache_entry_t *entry,
                     int ttl)
{
    if (!cache || !user || !host || !entry || ttl <= 0) return -1;

    /* Build JSON */
    struct json_object *json = json_object_new_object();
    if (!json) return -1;

    time_t expires_at = time(NULL) + ttl;

    json_object_object_add(json, "v", json_object_new_int(AUTH_CACHE_VERSION));
    json_object_object_add(json, "expires_at", json_object_new_int64(expires_at));
    json_object_object_add(json, "user", json_object_new_string(user));
    json_object_object_add(json, "authorized", json_object_new_boolean(entry->authorized));
    json_object_object_add(json, "sudo_allowed", json_object_new_boolean(entry->sudo_allowed));
    json_object_object_add(json, "sudo_nopasswd", json_object_new_boolean(entry->sudo_nopasswd));

    if (entry->groups && entry->groups_count > 0) {
        struct json_object *groups = json_object_new_array();
        for (size_t i = 0; i < entry->groups_count; i++) {
            if (entry->groups[i]) {
                json_object_array_add(groups, json_object_new_string(entry->groups[i]));
            }
        }
        json_object_object_add(json, "groups", groups);
    }

    if (entry->gecos) {
        json_object_object_add(json, "gecos", json_object_new_string(entry->gecos));
    }
    if (entry->shell) {
        json_object_object_add(json, "shell", json_object_new_string(entry->shell));
    }
    if (entry->home) {
        json_object_object_add(json, "home", json_object_new_string(entry->home));
    }

    const char *json_str = json_object_to_json_string(json);
    size_t json_len = strlen(json_str);

    /* Encrypt */
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;

    if (encrypt_data(cache, (unsigned char *)json_str, json_len,
                     &encrypted, &encrypted_len) != 0) {
        json_object_put(json);
        return -1;
    }

    json_object_put(json);

    /* Write to file */
    char path[PATH_MAX];
    build_auth_cache_path(cache, user, server_group, host, path, sizeof(path));

    char temp_path[PATH_MAX + 8];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        explicit_bzero(encrypted, encrypted_len);
        free(encrypted);
        return -1;
    }

    /* Write magic + encrypted data */
    ssize_t written = write(fd, AUTH_CACHE_MAGIC, strlen(AUTH_CACHE_MAGIC));
    if (written != (ssize_t)strlen(AUTH_CACHE_MAGIC)) {
        close(fd);
        unlink(temp_path);
        explicit_bzero(encrypted, encrypted_len);
        free(encrypted);
        return -1;
    }

    written = write(fd, encrypted, encrypted_len);
    explicit_bzero(encrypted, encrypted_len);
    free(encrypted);

    if (written != (ssize_t)encrypted_len) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    close(fd);

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return -1;
    }

    return 0;
}

void auth_cache_invalidate(auth_cache_t *cache,
                           const char *user,
                           const char *server_group,
                           const char *host)
{
    if (!cache || !user || !host) return;

    char path[PATH_MAX];
    build_auth_cache_path(cache, user, server_group, host, path, sizeof(path));
    unlink(path);
}

bool auth_cache_force_online(const char *force_online_file, const char *user)
{
    if (!force_online_file) return false;

    /* Open file first, then stat via fd to avoid TOCTOU race */
    int fd = open(force_online_file, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return false;  /* File doesn't exist or unreadable, normal operation */
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return false;
    }

    /* File exists - check if empty (means all users) */
    if (st.st_size == 0) {
        close(fd);
        return true;  /* All users forced online */
    }

    /* File has content - check if user is listed */
    if (!user) {
        close(fd);
        return true;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return true;  /* Can't read, assume force online */
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#') continue;

        if (strcmp(line, user) == 0) {
            fclose(f);  /* Also closes fd */
            return true;  /* User is listed */
        }
    }

    fclose(f);  /* Also closes fd */
    return false;  /* User not listed, use cache */
}

void auth_cache_entry_free(auth_cache_entry_t *entry)
{
    if (!entry) return;

    free(entry->user);
    free(entry->gecos);
    free(entry->shell);
    free(entry->home);

    if (entry->groups) {
        for (size_t i = 0; i < entry->groups_count; i++) {
            free(entry->groups[i]);
        }
        free(entry->groups);
    }

    memset(entry, 0, sizeof(*entry));
}

int auth_cache_cleanup(auth_cache_t *cache)
{
    if (!cache) return 0;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return 0;

    int removed = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".authcache") == NULL) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        /* Try to read and check expiration */
        int fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
            if (errno == ELOOP) {
                /* Symlink - remove it */
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
        size_t magic_len = strlen(AUTH_CACHE_MAGIC);
        if ((size_t)st.st_size <= magic_len ||
            memcmp(data, AUTH_CACHE_MAGIC, magic_len) != 0) {
            free(data);
            unlink(path);
            removed++;
            continue;
        }

        /* Decrypt and check expiration */
        unsigned char *decrypted = NULL;
        size_t decrypted_len = 0;

        if (decrypt_data(cache, data + magic_len, st.st_size - magic_len,
                         &decrypted, &decrypted_len) != 0) {
            explicit_bzero(data, st.st_size);
            free(data);
            unlink(path);
            removed++;
            continue;
        }

        explicit_bzero(data, st.st_size);
        free(data);

        struct json_object *json = json_tokener_parse((char *)decrypted);
        explicit_bzero(decrypted, decrypted_len);
        free(decrypted);

        if (!json) {
            unlink(path);
            removed++;
            continue;
        }

        struct json_object *val;
        if (json_object_object_get_ex(json, "expires_at", &val)) {
            time_t expires_at = (time_t)json_object_get_int64(val);
            if (time(NULL) >= expires_at) {
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
