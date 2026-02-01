/*
 * cache_key.h - Shared PBKDF2 key derivation for cache encryption
 *
 * Provides shared key derivation to avoid duplicate PBKDF2 operations
 * across token_cache and auth_cache.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef CACHE_KEY_H
#define CACHE_KEY_H

#include <stdbool.h>

/* AES-256 key size */
#define CACHE_KEY_SIZE 32

/* PBKDF2 salt size */
#define CACHE_SALT_SIZE 16

/* PBKDF2 iterations (100K = ~50-100ms on modern hardware) */
#define CACHE_PBKDF2_ITERATIONS 100000

/* Pre-derived cache key structure */
typedef struct {
    unsigned char key[CACHE_KEY_SIZE];
    bool derived;
} cache_derived_key_t;

/*
 * Derive encryption key from machine-id with salt from given directory
 * cache_dir: Directory containing the salt file
 * salt_filename: Name of the salt file (e.g., ".auth_salt" or ".cache_salt")
 * out: Output parameter for derived key
 * Returns 0 on success, -1 on failure
 *
 * This function:
 * 1. Reads /etc/machine-id
 * 2. Loads or generates salt from cache_dir/salt_filename
 * 3. Derives AES-256 key using PBKDF2-HMAC-SHA256 with 100K iterations
 */
int cache_derive_key(const char *cache_dir, const char *salt_filename,
                     cache_derived_key_t *out);

#endif /* CACHE_KEY_H */
