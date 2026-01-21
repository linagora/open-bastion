/*
 * jwks_cache.h - JWKS (JSON Web Key Set) cache for JWT verification
 *
 * Downloads and caches public keys from LLNG's JWKS endpoint for
 * verifying RS256-signed JWTs locally without contacting the server.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef JWKS_CACHE_H
#define JWKS_CACHE_H

#include <stdbool.h>
#include <time.h>
#include <openssl/evp.h>

/* Maximum number of keys to cache */
#define JWKS_MAX_KEYS 16

/* JWKS cache handle */
typedef struct jwks_cache jwks_cache_t;

/* JWKS cache configuration */
typedef struct {
    char *jwks_url;         /* URL to fetch JWKS (e.g., https://auth.example.com/.well-known/jwks.json) */
    char *cache_file;       /* Local cache file path */
    int refresh_interval;   /* Seconds between refreshes (default: 3600) */
    int timeout;            /* HTTP timeout in seconds (default: 10) */
    bool verify_ssl;        /* Verify SSL certificates (default: true) */
    char *ca_cert;          /* CA certificate path (optional) */
} jwks_cache_config_t;

/*
 * Initialize JWKS cache
 * Returns NULL on error
 */
jwks_cache_t *jwks_cache_init(const jwks_cache_config_t *config);

/*
 * Destroy JWKS cache
 */
void jwks_cache_destroy(jwks_cache_t *cache);

/*
 * Get public key by key ID (kid)
 *
 * Parameters:
 *   cache - JWKS cache handle
 *   kid   - Key ID to look up (NULL = return first/default key)
 *
 * Returns:
 *   EVP_PKEY pointer (owned by cache, do not free) or NULL if not found
 *
 * This function will:
 * 1. Check in-memory cache
 * 2. If not found or expired, try to load from file cache
 * 3. If still not found or expired, fetch from JWKS URL
 */
EVP_PKEY *jwks_cache_get_key(jwks_cache_t *cache, const char *kid);

/*
 * Force refresh of JWKS from URL
 * Useful when signature verification fails with cached keys
 *
 * Returns:
 *   0 on success, -1 on error
 */
int jwks_cache_refresh(jwks_cache_t *cache);

/*
 * Check if cache needs refresh
 *
 * Returns:
 *   true if refresh is needed, false otherwise
 */
bool jwks_cache_needs_refresh(jwks_cache_t *cache);

/*
 * Get last refresh time
 */
time_t jwks_cache_last_refresh(jwks_cache_t *cache);

/*
 * Get number of cached keys
 */
size_t jwks_cache_key_count(jwks_cache_t *cache);

#ifdef JWKS_CACHE_TEST
/*
 * Test-only functions to verify rate limiting behavior
 */
int jwks_cache_get_min_refresh_interval(void);
time_t jwks_cache_get_last_fetch_attempt(jwks_cache_t *cache);
void jwks_cache_set_last_fetch_attempt(jwks_cache_t *cache, time_t t);
bool jwks_cache_is_rate_limited(jwks_cache_t *cache, time_t now);
#endif

#endif /* JWKS_CACHE_H */
