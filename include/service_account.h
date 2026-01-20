/*
 * service_account.h - Service account management for Open Bastion PAM module
 *
 * Service accounts are local accounts (ansible, backup, deploy, etc.) that
 * authenticate via SSH key only, without OIDC. They are defined in a local
 * configuration file and authorized based on their presence in that file.
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
#define MAX_SERVICE_ACCOUNT_GECOS 256
#define MAX_SERVICE_ACCOUNT_PATH 256

/* Configuration for a single service account */
typedef struct {
    char *name;                 /* Account name (e.g., ansible, backup) */
    char *key_fingerprint;      /* SSH key fingerprint (SHA256:xxx) */
    bool sudo_allowed;          /* Allow sudo access */
    bool sudo_nopasswd;         /* Allow sudo without password */

    /* User attributes for automatic account creation */
    char *gecos;                /* User description (e.g., "Ansible Automation") */
    char *shell;                /* Login shell (e.g., /bin/bash) */
    char *home;                 /* Home directory (e.g., /var/lib/ansible) */
    int uid;                    /* Fixed UID (0 = auto-assign) */
    int gid;                    /* Fixed GID (0 = auto-assign) */
} service_account_t;

/* Collection of service accounts */
typedef struct {
    service_account_t *accounts;
    size_t count;
    size_t capacity;
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
 *   sudo_allowed = true
 *   sudo_nopasswd = false
 *   gecos = Service Account Description
 *   shell = /bin/bash
 *   home = /var/lib/accountname
 *   uid = 0
 *   gid = 0
 *
 * Returns 0 on success, negative on error:
 *   0:  Success (file loaded, or file does not exist which is OK)
 *   -1: Cannot open file or NULL parameters
 *   -2: File not owned by root
 *   -3: File permissions too open
 *   -4: Not a regular file
 *
 * Note: Malformed lines within the file are logged and skipped.
 * Invalid accounts (missing fingerprint, unapproved shell, etc.)
 * are validated and dropped after loading.
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
 * Get authorization response for a service account
 *
 * Populates the provided fields with authorization information.
 * All output parameters are optional (can be NULL).
 *
 * Returns:
 *   0: Account found and authorized
 *  -1: Account not found
 */
int service_accounts_get_authorization(const service_accounts_t *sa,
                                        const char *username,
                                        bool *sudo_allowed,
                                        bool *sudo_nopasswd,
                                        const char **gecos,
                                        const char **shell,
                                        const char **home,
                                        int *uid,
                                        int *gid);

/*
 * Validate service account configuration
 *
 * Checks that all required fields are present and valid.
 *
 * Returns 0 if valid, negative on error.
 */
int service_account_validate(const service_account_t *account,
                              const char *approved_shells,
                              const char *approved_home_prefixes);

#endif /* SERVICE_ACCOUNT_H */
