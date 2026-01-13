/*
 * jti_cache.h - JWT ID (jti) cache for replay detection
 *
 * This module provides a thread-safe cache for storing used JWT IDs (jti claims)
 * to prevent replay attacks on bastion JWT tokens.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef JTI_CACHE_H
#define JTI_CACHE_H

#include <stdbool.h>
#include <time.h>
#include <stddef.h>

/* JTI cache handle */
typedef struct jti_cache jti_cache_t;

/* JTI cache configuration */
typedef struct {
    size_t max_entries;      /* Maximum number of entries (default: 10000) */
    int cleanup_interval;    /* Cleanup expired entries every N seconds (default: 60) */
    const char *persist_path; /* Path to persist cache (NULL = memory only) */
} jti_cache_config_t;

/* Result codes */
typedef enum {
    JTI_CACHE_OK = 0,
    JTI_CACHE_REPLAY_DETECTED,
    JTI_CACHE_FULL,
    JTI_CACHE_INVALID_PARAM,
    JTI_CACHE_INTERNAL_ERROR
} jti_cache_result_t;

/*
 * Create a new JTI cache
 *
 * Parameters:
 *   config - Cache configuration (NULL for defaults)
 *
 * Returns:
 *   Cache handle, or NULL on error
 */
jti_cache_t *jti_cache_create(const jti_cache_config_t *config);

/*
 * Destroy a JTI cache and free resources
 */
void jti_cache_destroy(jti_cache_t *cache);

/*
 * Check if a JTI has been seen and add it if not
 *
 * This is an atomic check-and-add operation to prevent race conditions.
 *
 * Parameters:
 *   cache - Cache handle
 *   jti   - JWT ID to check/add
 *   exp   - Expiration time of the JWT (entries are auto-removed after this)
 *
 * Returns:
 *   JTI_CACHE_OK           - JTI is accepted. This is returned when:
 *                            - JTI was not in cache and has been added
 *                            - JTI was already expired (not cached, accepted)
 *                            - Existing expired entry was reused
 *   JTI_CACHE_REPLAY_DETECTED - JTI was already in cache and not expired (replay attempt)
 *   JTI_CACHE_FULL         - Cache is full and cleanup didn't free space
 *   JTI_CACHE_INVALID_PARAM - Invalid parameters
 */
jti_cache_result_t jti_cache_check_and_add(jti_cache_t *cache,
                                           const char *jti,
                                           time_t exp);

/*
 * Check if a JTI exists in the cache (without adding)
 *
 * Parameters:
 *   cache - Cache handle
 *   jti   - JWT ID to check
 *
 * Returns:
 *   true if JTI exists in cache, false otherwise
 */
bool jti_cache_contains(jti_cache_t *cache, const char *jti);

/*
 * Remove expired entries from the cache
 *
 * This is called automatically based on cleanup_interval,
 * but can be called manually if needed.
 *
 * Parameters:
 *   cache - Cache handle
 *
 * Returns:
 *   Number of entries removed
 */
size_t jti_cache_cleanup(jti_cache_t *cache);

/*
 * Get cache statistics
 *
 * Parameters:
 *   cache       - Cache handle
 *   count       - Output: current number of entries
 *   max_entries - Output: maximum capacity
 *   hits        - Output: number of replay detections
 *   misses      - Output: number of new JTIs added
 */
void jti_cache_stats(jti_cache_t *cache,
                     size_t *count,
                     size_t *max_entries,
                     size_t *hits,
                     size_t *misses);

/*
 * Get human-readable error message
 */
const char *jti_cache_result_str(jti_cache_result_t result);

#endif /* JTI_CACHE_H */
