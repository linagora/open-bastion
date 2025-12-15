/*
 * token_cache.c - Token caching for LemonLDAP::NG PAM module
 *
 * Uses simple file-based cache with SHA256 hashed token names.
 *
 * Copyright (C) 2024 Linagora
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
#include <openssl/evp.h>

#include "token_cache.h"

/* Maximum number of cache entries to prevent DoS */
#define MAX_CACHE_ENTRIES 10000

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
};

token_cache_t *cache_init(const char *cache_dir, int ttl)
{
    if (!cache_dir) {
        return NULL;
    }

    token_cache_t *cache = calloc(1, sizeof(token_cache_t));
    if (!cache) {
        return NULL;
    }

    cache->cache_dir = strdup(cache_dir);
    cache->default_ttl = ttl > 0 ? ttl : 300;

    /* Create cache directory if it doesn't exist */
    struct stat st;
    if (stat(cache_dir, &st) != 0) {
        if (mkdir(cache_dir, 0700) != 0 && errno != EEXIST) {
            free(cache->cache_dir);
            free(cache);
            return NULL;
        }
    }

    return cache;
}

void cache_destroy(token_cache_t *cache)
{
    if (!cache) return;
    free(cache->cache_dir);
    free(cache);
}

/* Count entries in cache directory */
static int count_cache_entries(const char *cache_dir)
{
    DIR *dir = opendir(cache_dir);
    if (!dir) return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cache") != NULL) {
            count++;
        }
    }
    closedir(dir);
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

    char path[512];
    build_cache_path(cache, token, user, path, sizeof(path));

    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }

    /* Read cache entry: expires_at authorized user */
    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return false;
    }
    fclose(f);

    time_t expires_at;
    int authorized;
    char cached_user[256];

    if (sscanf(line, "%ld %d %255s", &expires_at, &authorized, cached_user) != 3) {
        /* Invalid format, remove the file */
        unlink(path);
        return false;
    }

    /* Check expiration */
    time_t now = time(NULL);
    if (now >= expires_at) {
        /* Expired, remove */
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

    /* Rate limiting: check if cache is full */
    int entry_count = count_cache_entries(cache->cache_dir);
    if (entry_count >= MAX_CACHE_ENTRIES) {
        /* Try to clean up expired entries first */
        cache_cleanup(cache);
        entry_count = count_cache_entries(cache->cache_dir);
        if (entry_count >= MAX_CACHE_ENTRIES) {
            /* Still full, refuse to add more entries */
            return -1;
        }
    }

    char path[512];
    build_cache_path(cache, token, user, path, sizeof(path));

    /* Use atomic write: write to temp file then rename */
    char temp_path[520];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    time_t expires_at = time(NULL) + (ttl > 0 ? ttl : cache->default_ttl);
    fprintf(f, "%ld %d %s\n", expires_at, authorized ? 1 : 0, user);
    fclose(f);

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return -1;
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

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        FILE *f = fopen(path, "r");
        if (!f) continue;

        char line[1024];
        if (fgets(line, sizeof(line), f)) {
            time_t expires_at;
            int authorized;
            char cached_user[256];

            if (sscanf(line, "%ld %d %255s", &expires_at, &authorized, cached_user) == 3) {
                if (strcmp(cached_user, user) == 0) {
                    fclose(f);
                    unlink(path);
                    continue;
                }
            }
        }
        fclose(f);
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

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        FILE *f = fopen(path, "r");
        if (!f) continue;

        char line[1024];
        if (fgets(line, sizeof(line), f)) {
            time_t expires_at;
            if (sscanf(line, "%ld", &expires_at) == 1) {
                if (now >= expires_at) {
                    fclose(f);
                    unlink(path);
                    removed++;
                    continue;
                }
            }
        }
        fclose(f);
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
