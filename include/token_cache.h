/*
 * token_cache.h - Token caching for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#ifndef TOKEN_CACHE_H
#define TOKEN_CACHE_H

#include <stdbool.h>
#include <time.h>

/* Cache entry structure */
typedef struct {
    char *token_hash;      /* SHA256 hash of the token */
    char *user;            /* Associated username */
    bool authorized;       /* Authorization result */
    time_t expires_at;     /* Expiration timestamp */
    time_t cached_at;      /* When entry was cached */
} cache_entry_t;

/* Cache handle */
typedef struct token_cache token_cache_t;

/*
 * Initialize the token cache
 * cache_dir: Directory for cache files
 * ttl: Default TTL in seconds
 * Returns NULL on failure
 */
token_cache_t *cache_init(const char *cache_dir, int ttl);

/*
 * Destroy cache and free resources
 */
void cache_destroy(token_cache_t *cache);

/*
 * Look up a token in the cache
 * Returns true if found and valid, false otherwise
 * If found, entry is populated with cached data
 */
bool cache_lookup(token_cache_t *cache,
                  const char *token,
                  const char *user,
                  cache_entry_t *entry);

/*
 * Store a token validation result in cache
 * Returns 0 on success, -1 on error
 */
int cache_store(token_cache_t *cache,
                const char *token,
                const char *user,
                bool authorized,
                int ttl);

/*
 * Invalidate a specific token
 */
void cache_invalidate(token_cache_t *cache, const char *token);

/*
 * Invalidate all entries for a user
 */
void cache_invalidate_user(token_cache_t *cache, const char *user);

/*
 * Clean up expired entries
 * Returns number of entries removed
 */
int cache_cleanup(token_cache_t *cache);

/*
 * Free cache entry contents
 */
void cache_entry_free(cache_entry_t *entry);

#endif /* TOKEN_CACHE_H */
