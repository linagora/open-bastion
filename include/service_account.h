/*
 * service_account.h - Service account management for Open Bastion PAM module
 *
 * Service accounts are local accounts (ansible, backup, deploy, etc.) that
 * authenticate via SSH key only, without OIDC. Listing one in the local
 * configuration file exempts it from the SSO in the PAM account phase.
 *
 * The Unix account itself is the operator's: created with useradd, resolved
 * by `files`. Open Bastion neither creates it nor manages its sudo rights
 * (#353).
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef SERVICE_ACCOUNT_H
#define SERVICE_ACCOUNT_H

#include <stdbool.h>
#include <stddef.h>

/* Maximum number of service accounts */
#define MAX_SERVICE_ACCOUNTS 64

/* Maximum length for service account fields */
#define MAX_SERVICE_ACCOUNT_NAME 32
#define MAX_SERVICE_ACCOUNT_FINGERPRINT 128

/* Configuration for a single service account */
typedef struct {
    char *name;                 /* Account name (e.g., ansible, backup) */
    char *key_fingerprint;      /* SSH key fingerprint (SHA256:xxx) */
} service_account_t;

/*
 * Keys of the pre-#353 format: they drove on-the-fly account creation and
 * sudo. Still accepted so an upgraded host locks nobody out, but ignored; one
 * bit per key (aliases share their canonical key's bit), set by
 * service_accounts_load() when the file uses it.
 */
#define SA_OBSOLETE_UID           (1u << 0)
#define SA_OBSOLETE_GID           (1u << 1)
#define SA_OBSOLETE_SHELL         (1u << 2)
#define SA_OBSOLETE_HOME          (1u << 3)
#define SA_OBSOLETE_GECOS         (1u << 4)
#define SA_OBSOLETE_SUDO_ALLOWED  (1u << 5)
#define SA_OBSOLETE_SUDO_NOPASSWD (1u << 6)

/* Collection of service accounts */
typedef struct {
    service_account_t *accounts;
    size_t count;
    size_t capacity;
    unsigned int obsolete_keys; /* SA_OBSOLETE_* seen by the last load */
} service_accounts_t;

/*
 * Initialize service accounts structure
 */
void service_accounts_init(service_accounts_t *sa);

/*
 * Free service accounts structure
 */
void service_accounts_free(service_accounts_t *sa);

/*
 * Load service accounts from configuration file
 *
 * File format (INI-style):
 *   [accountname]
 *   key_fingerprint = SHA256:abc123...
 *
 * `fingerprint` and `ssh_key` are aliases of key_fingerprint. The obsolete
 * keys uid, gid, shell, home/home_dir, gecos/description, sudo_allowed/sudo
 * and sudo_nopasswd/nopasswd are ignored; their presence is recorded in
 * sa->obsolete_keys and logged once per load.
 *
 * Returns 0 on success, negative on error:
 *   0:  Success (file loaded, or file does not exist which is OK)
 *   -1: Cannot open file or NULL parameters
 *   -2: File not owned by root
 *   -3: File permissions too open
 *   -4: Not a regular file
 *
 * Note: Malformed lines within the file are logged and skipped.
 * Invalid accounts (bad name, missing or malformed fingerprint) are
 * validated and dropped after loading.
 */
int service_accounts_load(const char *filename, service_accounts_t *sa);

/*
 * Find a service account by name
 *
 * Returns pointer to account if found, NULL otherwise.
 * The returned pointer is valid until service_accounts_free() is called.
 */
const service_account_t *service_accounts_find(const service_accounts_t *sa,
                                                const char *name);

/*
 * Check if a user is a service account
 *
 * Returns true if the username matches a configured service account.
 */
bool service_accounts_is_service_account(const service_accounts_t *sa,
                                          const char *username);

/*
 * Validate SSH key fingerprint for a service account
 *
 * Compares the provided fingerprint with the configured fingerprint
 * for the service account.
 *
 * Returns:
 *   0: Fingerprint matches
 *  -1: Account not found
 *  -2: Fingerprint mismatch
 *  -3: No fingerprint configured for account
 */
int service_accounts_validate_key(const service_accounts_t *sa,
                                   const char *username,
                                   const char *fingerprint);

/*
 * Validate service account configuration
 *
 * Checks that the name and the key fingerprint are present and well formed.
 *
 * Returns 0 if valid, negative on error.
 */
int service_account_validate(const service_account_t *account);

#endif /* SERVICE_ACCOUNT_H */
