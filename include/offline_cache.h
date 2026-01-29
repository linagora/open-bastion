/*
 * offline_cache.h - Offline credential cache for desktop SSO
 *
 * Caches password verifiers using Argon2id for offline authentication.
 * Data is encrypted with AES-256-GCM using a machine-derived key.
 *
 * This allows users to login when the LLNG server is unreachable,
 * using credentials cached from previous successful authentications.
 *
 * Security:
 * - Argon2id with high memory cost for password verification
 * - AES-256-GCM encryption with random IV for stored data
 * - Machine-id bound encryption key
 * - Configurable TTL and max cache entries
 * - Failed attempt tracking per cached entry
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef OFFLINE_CACHE_H
#define OFFLINE_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Cache format version */
#define OFFLINE_CACHE_VERSION 1

/*
 * Argon2id parameters (OWASP recommended for high security)
 *
 * ARGON2_MEMORY_KB is expressed in KiB (64 MiB = 65536 KiB):
 *   - libsodium/crypto_pwhash: convert to bytes with (size_t)ARGON2_MEMORY_KB * 1024ULL
 *   - OpenSSL Argon2: pass ARGON2_MEMORY_KB directly (expects KiB)
 */
#define ARGON2_MEMORY_KB    65536   /* 64 MiB memory cost, in KiB */
#define ARGON2_ITERATIONS   3       /* Time cost (iterations) */
#define ARGON2_PARALLELISM  4       /* Parallelism factor */
#define ARGON2_HASH_LEN     32      /* Output hash length */
#define ARGON2_SALT_LEN     16      /* Salt length */

/* Protocol constant: prefix prepended by the greeter to offline passwords.
 * Must be kept in sync with lightdm/greeter/greeter.js */
#define OFFLINE_PASSWORD_PREFIX  "OFFLINE:"
#define OFFLINE_PASSWORD_PREFIX_LEN  8

/* Security limits */
#define OFFLINE_CACHE_MAX_FAILED_ATTEMPTS  5     /* Max failed attempts before entry lockout */
#define OFFLINE_CACHE_LOCKOUT_DURATION     300   /* Lockout duration in seconds (5 min) */
#define OFFLINE_CACHE_MAX_ENTRIES          1000  /* Maximum cached users */
#define OFFLINE_CACHE_DEFAULT_TTL          604800 /* 7 days default TTL */

/* Error codes */
#define OFFLINE_CACHE_OK                   0
#define OFFLINE_CACHE_ERR_NOMEM           -1
#define OFFLINE_CACHE_ERR_IO              -2
#define OFFLINE_CACHE_ERR_CRYPTO          -3
#define OFFLINE_CACHE_ERR_NOTFOUND        -4
#define OFFLINE_CACHE_ERR_EXPIRED         -5
#define OFFLINE_CACHE_ERR_LOCKED          -6
#define OFFLINE_CACHE_ERR_INVALID         -7
#define OFFLINE_CACHE_ERR_PASSWORD        -8

/* Offline credential cache entry (stored encrypted) */
typedef struct {
    int version;                    /* Cache format version */
    time_t created_at;              /* When credentials were cached */
    time_t expires_at;              /* Expiration timestamp */
    time_t last_success;            /* Last successful offline auth */
    char *user;                     /* Username */
    unsigned char *password_hash;   /* Argon2id password hash */
    size_t password_hash_len;       /* Hash length */
    unsigned char *salt;            /* Argon2id salt */
    size_t salt_len;                /* Salt length */
    int failed_attempts;            /* Consecutive failed attempts */
    time_t locked_until;            /* Lockout timestamp (0 if not locked) */
    char *gecos;                    /* Cached GECOS for offline use */
    char *shell;                    /* Cached shell */
    char *home;                     /* Cached home directory */
} offline_cache_entry_t;

/* Offline cache handle */
typedef struct offline_cache offline_cache_t;

/*
 * Initialize offline credential cache
 * cache_dir: Directory for cache files (e.g., /var/cache/open-bastion/credentials)
 * key_file: Path to 32-byte secret key file (NULL = use default, fallback to machine-id)
 * Returns NULL on failure
 */
offline_cache_t *offline_cache_init(const char *cache_dir, const char *key_file);

/*
 * Destroy cache and free resources
 * Securely clears sensitive data from memory
 */
void offline_cache_destroy(offline_cache_t *cache);

/*
 * Store user credentials in cache after successful online authentication
 * user: Username
 * password: Plain-text password (will be hashed with Argon2id)
 * ttl: Time-to-live in seconds (0 for default)
 * gecos: Optional GECOS field
 * shell: Optional shell path
 * home: Optional home directory
 * Returns OFFLINE_CACHE_OK on success, error code on failure
 */
int offline_cache_store(offline_cache_t *cache,
                        const char *user,
                        const char *password,
                        int ttl,
                        const char *gecos,
                        const char *shell,
                        const char *home);

/*
 * Verify user password against cached credentials (offline authentication)
 * user: Username
 * password: Password to verify
 * entry: Output parameter for entry details (caller must free with offline_cache_entry_free)
 *        Can be NULL if only verification is needed
 * Returns:
 *   OFFLINE_CACHE_OK       - Password verified successfully
 *   OFFLINE_CACHE_ERR_NOTFOUND - No cached entry for user
 *   OFFLINE_CACHE_ERR_EXPIRED  - Cached entry has expired
 *   OFFLINE_CACHE_ERR_LOCKED   - Entry is locked due to failed attempts
 *   OFFLINE_CACHE_ERR_PASSWORD - Password does not match
 */
int offline_cache_verify(offline_cache_t *cache,
                         const char *user,
                         const char *password,
                         offline_cache_entry_t *entry);

/*
 * Check if valid cached credentials exist for a user
 * user: Username to check
 * Returns true if valid (non-expired, non-locked) entry exists
 */
bool offline_cache_has_entry(offline_cache_t *cache, const char *user);

/*
 * Get cached entry information (without verifying password)
 * user: Username
 * entry: Output parameter (caller must free with offline_cache_entry_free)
 * Returns OFFLINE_CACHE_OK on success, error code on failure
 */
int offline_cache_get_entry(offline_cache_t *cache,
                            const char *user,
                            offline_cache_entry_t *entry);

/*
 * Invalidate (remove) cached credentials for a user
 * Use after password change or account revocation
 */
int offline_cache_invalidate(offline_cache_t *cache, const char *user);

/*
 * Invalidate all cached credentials
 * Use for emergency cache flush
 */
int offline_cache_invalidate_all(offline_cache_t *cache);

/*
 * Reset failed attempt counter for a user
 * Called after successful online authentication
 */
int offline_cache_reset_failures(offline_cache_t *cache, const char *user);

/*
 * Clean up expired entries
 * Returns number of entries removed
 */
int offline_cache_cleanup(offline_cache_t *cache);

/*
 * Get cache statistics
 * total: Total entries
 * active: Non-expired entries
 * locked: Locked entries
 */
int offline_cache_stats(offline_cache_t *cache,
                        int *total,
                        int *active,
                        int *locked);

/*
 * Set secret key file path for cache encryption
 * key_file: Path to 32-byte root-only file (NULL = use default /etc/open-bastion/cache.key)
 * If file is absent or invalid, falls back to machine-id with syslog warning.
 */
void offline_cache_set_key_file(offline_cache_t *cache, const char *key_file);

/*
 * Configure lockout parameters (overrides compile-time defaults)
 * max_failures: Max failed attempts before lockout (0 = default)
 * lockout_duration: Lockout duration in seconds (0 = default)
 */
void offline_cache_set_lockout(offline_cache_t *cache,
                                int max_failures,
                                int lockout_duration);

/*
 * Free entry contents
 * Securely clears sensitive data
 */
void offline_cache_entry_free(offline_cache_entry_t *entry);

/*
 * Convert error code to string
 */
const char *offline_cache_strerror(int err);

#endif /* OFFLINE_CACHE_H */
