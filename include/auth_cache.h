/*
 * auth_cache.h - Authorization cache for offline mode
 *
 * Caches authorization responses from LLNG server for offline use.
 * Uses AES-256-GCM encryption with machine-id derived key.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef AUTH_CACHE_H
#define AUTH_CACHE_H

#include <stdbool.h>
#include <time.h>

/* Authorization cache entry */
typedef struct {
    int version;            /* Cache format version (3) */
    time_t expires_at;      /* Expiration timestamp */
    char *user;             /* Username */
    bool authorized;        /* Authorization result */
    char **groups;          /* User groups */
    size_t groups_count;    /* Number of groups */
    bool sudo_allowed;      /* Sudo permission */
    bool sudo_nopasswd;     /* Sudo without password */
    char *gecos;            /* Full name / GECOS */
    char *shell;            /* Login shell */
    char *home;             /* Home directory */
} auth_cache_entry_t;

/* Authorization cache handle */
typedef struct auth_cache auth_cache_t;

/*
 * Initialize authorization cache
 * cache_dir: Directory for cache files
 * Returns NULL on failure
 */
auth_cache_t *auth_cache_init(const char *cache_dir);

/*
 * Destroy cache and free resources
 */
void auth_cache_destroy(auth_cache_t *cache);

/*
 * Look up cached authorization for a user
 * user: Username to look up
 * server_group: Server group (for cache key)
 * host: Hostname (for cache key binding)
 * entry: Output parameter for cached entry (caller must free with auth_cache_entry_free)
 * Returns true if valid cache entry found, false otherwise
 */
bool auth_cache_lookup(auth_cache_t *cache,
                       const char *user,
                       const char *server_group,
                       const char *host,
                       auth_cache_entry_t *entry);

/*
 * Store authorization result in cache
 * user: Username
 * server_group: Server group (for cache key)
 * host: Hostname (for cache key binding)
 * entry: Entry to store
 * ttl: Time-to-live in seconds
 * Returns 0 on success, -1 on error
 */
int auth_cache_store(auth_cache_t *cache,
                     const char *user,
                     const char *server_group,
                     const char *host,
                     const auth_cache_entry_t *entry,
                     int ttl);

/*
 * Invalidate cache entry for a user
 */
void auth_cache_invalidate(auth_cache_t *cache,
                           const char *user,
                           const char *server_group,
                           const char *host);

/*
 * Check if force-online file exists
 * If file contains usernames, returns true only if user is listed
 * force_online_file: Path to force-online file
 * user: Username to check
 * Returns true if user should skip cache
 */
bool auth_cache_force_online(const char *force_online_file, const char *user);

/*
 * Free cache entry contents
 */
void auth_cache_entry_free(auth_cache_entry_t *entry);

/*
 * Clean up expired entries
 * Returns number of entries removed
 */
int auth_cache_cleanup(auth_cache_t *cache);

#endif /* AUTH_CACHE_H */
