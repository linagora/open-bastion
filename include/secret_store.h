/*
 * secret_store.h - Machine-specific secret encryption for PAM module
 *
 * Secrets are encrypted using AES-256-GCM with a key derived from:
 * - /etc/machine-id (unique per machine)
 * - Optional salt from configuration
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef SECRET_STORE_H
#define SECRET_STORE_H

#include <stdbool.h>
#include <stddef.h>

/* Secret store configuration */
typedef struct {
    bool enabled;               /* Enable encryption (default: true) */
    char *store_dir;            /* Directory for encrypted secrets */
    char *salt;                 /* Additional salt for key derivation */
    bool use_keyring;           /* Also store in kernel keyring */
    char *keyring_name;         /* Keyring name (default: "pam_llng") */
} secret_store_config_t;

/* Secret store handle */
typedef struct secret_store secret_store_t;

/*
 * Initialize secret store
 * Returns NULL on failure
 */
secret_store_t *secret_store_init(const secret_store_config_t *config);

/*
 * Destroy secret store
 */
void secret_store_destroy(secret_store_t *store);

/*
 * Store a secret
 * The secret will be encrypted before storage
 * key: identifier for the secret (e.g., "user:refresh_token")
 * secret: the secret value to store
 * secret_len: length of the secret
 * Returns 0 on success, -1 on error
 */
int secret_store_put(secret_store_t *store,
                     const char *key,
                     const void *secret,
                     size_t secret_len);

/*
 * Retrieve a secret
 * secret: output buffer for decrypted secret (allocated by caller)
 * secret_size: size of output buffer
 * actual_len: actual length of secret (output)
 * Returns 0 on success, -1 on error, -2 if not found
 */
int secret_store_get(secret_store_t *store,
                     const char *key,
                     void *secret,
                     size_t secret_size,
                     size_t *actual_len);

/*
 * Delete a secret
 * Returns 0 on success, -1 on error
 */
int secret_store_delete(secret_store_t *store, const char *key);

/*
 * Check if a secret exists
 * Returns true if exists, false otherwise
 */
bool secret_store_exists(secret_store_t *store, const char *key);

/*
 * Rotate the encryption key
 * Re-encrypts all secrets with a new key
 * This should be called if machine-id changes
 * Returns 0 on success, -1 on error
 */
int secret_store_rotate_key(secret_store_t *store);

/*
 * Get last error message
 */
const char *secret_store_error(secret_store_t *store);

#endif /* SECRET_STORE_H */
