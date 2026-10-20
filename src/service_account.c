/*
 * service_account.c - Service account management for Open Bastion PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include "service_account.h"
#include "str_utils.h"

/* Initial capacity for accounts array */
#define INITIAL_CAPACITY 8

/* The only owner the file is accepted from. Overridable so the unit test,
 * which includes this file, can load files it owns. */
#ifndef SA_TRUSTED_UID
#define SA_TRUSTED_UID ((uid_t)0)
#endif

/*
 * Security: check file permissions for sensitive files.
 * Uses fstat on already-opened fd to avoid TOCTOU.
 * Returns 0 on OK, negative on error.
 */
static int check_file_permissions_fd(int fd)
{
    struct stat st;

    if (fstat(fd, &st) != 0) {
        return -1;  /* Can't stat */
    }

    /* File must be owned by root (uid 0) */
    if (st.st_uid != SA_TRUSTED_UID) {
        return -2;  /* Not owned by root */
    }

    /* File must not be readable by group or others */
    if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
        return -3;  /* Permissions too open */
    }

    /* Must be a regular file, not a symlink or device */
    if (!S_ISREG(st.st_mode)) {
        return -4;  /* Not a regular file */
    }

    return 0;  /* OK */
}

/* Use shared string utilities from str_utils.h */
#define trim str_trim

/*
 * The pre-#353 keys. Open Bastion used them to create the account on first
 * login and to grant it sudo; both are now the operator's (useradd, sudoers).
 * They are recognised so that a file written for an older release keeps
 * loading -- refusing it would lock the account out on upgrade -- and so that
 * the operator is told, once, that they no longer do anything.
 */
static const struct {
    const char *key;
    unsigned int flag;
} obsolete_keys[] = {
    { "uid",           SA_OBSOLETE_UID },
    { "gid",           SA_OBSOLETE_GID },
    { "shell",         SA_OBSOLETE_SHELL },
    { "home",          SA_OBSOLETE_HOME },
    { "home_dir",      SA_OBSOLETE_HOME },
    { "gecos",         SA_OBSOLETE_GECOS },
    { "description",   SA_OBSOLETE_GECOS },
    { "sudo_allowed",  SA_OBSOLETE_SUDO_ALLOWED },
    { "sudo",          SA_OBSOLETE_SUDO_ALLOWED },
    { "sudo_nopasswd", SA_OBSOLETE_SUDO_NOPASSWD },
    { "nopasswd",      SA_OBSOLETE_SUDO_NOPASSWD },
};

#define N_OBSOLETE_KEYS (sizeof(obsolete_keys) / sizeof(obsolete_keys[0]))

/*
 * One warning per load naming every obsolete key the file uses, rather than
 * one per line: a generated file repeats the same keys in every section.
 */
static void log_obsolete_keys(const char *filename, unsigned int seen)
{
    char names[256] = "";
    unsigned int listed = 0;

    if (!seen) return;

    for (size_t i = 0; i < N_OBSOLETE_KEYS; i++) {
        /* Aliases share a bit: name each bit once, by its canonical key. */
        if (!(seen & obsolete_keys[i].flag) || (listed & obsolete_keys[i].flag))
            continue;
        listed |= obsolete_keys[i].flag;
        size_t len = strlen(names);
        snprintf(names + len, sizeof(names) - len, "%s%s",
                 len ? ", " : "", obsolete_keys[i].key);
    }

    syslog(LOG_WARNING, "open-bastion: service_accounts: %s: ignoring obsolete "
           "key(s) %s. Open Bastion no longer creates service accounts nor "
           "grants them sudo: create the account with useradd, grant sudo in "
           "sudoers (#353)", filename, names);
}

/*
 * Validate username format
 * Returns 0 if valid, -1 if invalid
 */
static int validate_username(const char *name)
{
    if (!name || !*name) return -1;

    size_t len = strlen(name);
    if (len > MAX_SERVICE_ACCOUNT_NAME) return -1;

    /* First character must be lowercase letter or underscore */
    if (!islower((unsigned char)name[0]) && name[0] != '_') {
        return -1;
    }

    /* Remaining characters: lowercase, digits, underscore, hyphen */
    for (size_t i = 1; i < len; i++) {
        char c = name[i];
        if (!islower((unsigned char)c) && !isdigit((unsigned char)c) &&
            c != '_' && c != '-') {
            return -1;
        }
    }

    return 0;
}

/*
 * Validate SSH key fingerprint format
 * Expected format: SHA256:base64string or MD5:hex:string
 */
static int validate_fingerprint(const char *fp)
{
    if (!fp || !*fp) return -1;

    size_t len = strlen(fp);
    if (len > MAX_SERVICE_ACCOUNT_FINGERPRINT) return -1;

    /* Must start with SHA256: or MD5: */
    if (strncmp(fp, "SHA256:", 7) != 0 && strncmp(fp, "MD5:", 4) != 0) {
        return -1;
    }

    /* Check for dangerous characters */
    for (const char *p = fp; *p; p++) {
        unsigned char c = (unsigned char)*p;
        /* Allow: alphanumeric, :, +, /, = (base64 chars) */
        if (!isalnum(c) && c != ':' && c != '+' && c != '/' && c != '=') {
            return -1;
        }
    }

    return 0;
}

void service_accounts_init(service_accounts_t *sa)
{
    if (!sa) return;

    sa->accounts = NULL;
    sa->count = 0;
    sa->capacity = 0;
    sa->obsolete_keys = 0;
}

static void service_account_free(service_account_t *account)
{
    if (!account) return;

    free(account->name);
    free(account->key_fingerprint);

    memset(account, 0, sizeof(*account));
}

void service_accounts_free(service_accounts_t *sa)
{
    if (!sa) return;

    for (size_t i = 0; i < sa->count; i++) {
        service_account_free(&sa->accounts[i]);
    }

    free(sa->accounts);
    sa->accounts = NULL;
    sa->count = 0;
    sa->capacity = 0;
    sa->obsolete_keys = 0;
}

/*
 * Ensure capacity for at least one more account
 */
static int ensure_capacity(service_accounts_t *sa)
{
    if (sa->count < sa->capacity) {
        return 0;  /* Already have space */
    }

    if (sa->count >= MAX_SERVICE_ACCOUNTS) {
        return -1;  /* Maximum reached */
    }

    size_t new_capacity = sa->capacity == 0 ? INITIAL_CAPACITY : sa->capacity * 2;
    if (new_capacity > MAX_SERVICE_ACCOUNTS) {
        new_capacity = MAX_SERVICE_ACCOUNTS;
    }

    service_account_t *new_accounts = realloc(sa->accounts,
                                               new_capacity * sizeof(service_account_t));
    if (!new_accounts) {
        return -1;
    }

    /* Zero-initialize new entries */
    memset(&new_accounts[sa->capacity], 0,
           (new_capacity - sa->capacity) * sizeof(service_account_t));

    sa->accounts = new_accounts;
    sa->capacity = new_capacity;

    return 0;
}

/*
 * Helper macro to safely duplicate a string field.
 * On strdup failure, keeps the existing value and logs a warning.
 */
#define SAFE_STRDUP_FIELD(field, val) do { \
    char *_new = strdup(val); \
    if (_new) { \
        free(field); \
        (field) = _new; \
    } else { \
        syslog(LOG_WARNING, "open-bastion: service_accounts: " \
               "strdup failed for %s (out of memory)", #field); \
    } \
} while(0)

/*
 * Parse a line within a section. Returns the SA_OBSOLETE_* bit of an obsolete
 * key, 0 otherwise.
 */
static unsigned int parse_account_line(const char *key, const char *value,
                                        service_account_t *account)
{
    if (strcmp(key, "key_fingerprint") == 0 ||
        strcmp(key, "fingerprint") == 0 ||
        strcmp(key, "ssh_key") == 0) {
        SAFE_STRDUP_FIELD(account->key_fingerprint, value);
        return 0;
    }
    for (size_t i = 0; i < N_OBSOLETE_KEYS; i++) {
        if (strcmp(key, obsolete_keys[i].key) == 0)
            return obsolete_keys[i].flag;
    }
    /* Unknown keys are silently ignored */
    return 0;
}

#undef SAFE_STRDUP_FIELD

int service_accounts_load(const char *filename, service_accounts_t *sa)
{
    if (!filename || !sa) return -1;

    /*
     * Security: open file with O_NOFOLLOW to prevent symlink attacks,
     * then check permissions on the opened fd to avoid TOCTOU.
     */
    int fd = open(filename, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) {
            /* File doesn't exist - this is OK, just no service accounts */
            return 0;
        }
        return -1;
    }

    int perm_check = check_file_permissions_fd(fd);
    if (perm_check < 0) {
        close(fd);
        return perm_check;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return -1;
    }

    service_accounts_init(sa);

    char line[1024];
    service_account_t *current_account = NULL;
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }

        /* Check for section header [accountname] */
        if (*trimmed == '[') {
            char *end_bracket = strchr(trimmed, ']');
            if (!end_bracket) {
                syslog(LOG_WARNING, "open-bastion: service_accounts: "
                       "malformed section at line %d", line_num);
                continue;
            }

            *end_bracket = '\0';
            char *section_name = trim(trimmed + 1);

            /* Validate account name */
            if (validate_username(section_name) != 0) {
                syslog(LOG_WARNING, "open-bastion: service_accounts: "
                       "invalid account name '%s' at line %d",
                       section_name, line_num);
                continue;
            }

            /* Check if account already exists - skip duplicate sections */
            bool is_duplicate = false;
            for (size_t i = 0; i < sa->count; i++) {
                if (strcmp(sa->accounts[i].name, section_name) == 0) {
                    syslog(LOG_WARNING, "open-bastion: service_accounts: "
                           "duplicate account '%s' at line %d (ignoring)",
                           section_name, line_num);
                    is_duplicate = true;
                    break;
                }
            }
            if (is_duplicate) {
                /* Set current_account to NULL to skip all lines until next section */
                current_account = NULL;
                continue;
            }

            /* Add new account */
            if (ensure_capacity(sa) != 0) {
                syslog(LOG_ERR, "open-bastion: service_accounts: "
                       "too many accounts (max %d)", MAX_SERVICE_ACCOUNTS);
                current_account = NULL;
                continue;
            }

            current_account = &sa->accounts[sa->count];
            memset(current_account, 0, sizeof(*current_account));
            current_account->name = strdup(section_name);
            if (!current_account->name) {
                current_account = NULL;
                continue;
            }
            sa->count++;
            continue;
        }

        /* Parse key=value if we're in a section */
        if (!current_account) {
            continue;  /* Ignore lines outside sections */
        }

        char *eq = strchr(trimmed, '=');
        if (!eq) {
            continue;  /* Skip malformed lines */
        }

        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);

        /* Remove quotes from value */
        if (*value == '"' || *value == '\'') {
            char quote = *value;
            value++;
            char *end = strrchr(value, quote);
            if (end) *end = '\0';
        }

        sa->obsolete_keys |= parse_account_line(key, value, current_account);
    }

    fclose(f);

    log_obsolete_keys(filename, sa->obsolete_keys);

    /*
     * Validate all loaded accounts and remove invalid ones: a missing or
     * malformed fingerprint, or a bad name, is rejected at load time. The
     * obsolete keys never make an account invalid (#353).
     */
    size_t i = 0;
    while (i < sa->count) {
        service_account_t *acct = &sa->accounts[i];

        if (service_account_validate(acct) != 0) {
            syslog(LOG_WARNING, "open-bastion: service_accounts: "
                   "dropping invalid account '%s'",
                   acct->name ? acct->name : "(unnamed)");

            /* Free the invalid account's resources */
            service_account_free(acct);

            /* Shift remaining accounts down */
            if (i + 1 < sa->count) {
                memmove(&sa->accounts[i], &sa->accounts[i + 1],
                        (sa->count - i - 1) * sizeof(service_account_t));
            }
            sa->count--;
            /* Don't increment i - next account is now at position i */
            continue;
        }
        i++;
    }

    return 0;
}

const service_account_t *service_accounts_find(const service_accounts_t *sa,
                                                const char *name)
{
    if (!sa || !name) return NULL;

    for (size_t i = 0; i < sa->count; i++) {
        if (sa->accounts[i].name &&
            strcmp(sa->accounts[i].name, name) == 0) {
            return &sa->accounts[i];
        }
    }

    return NULL;
}

bool service_accounts_is_service_account(const service_accounts_t *sa,
                                          const char *username)
{
    return service_accounts_find(sa, username) != NULL;
}

int service_accounts_validate_key(const service_accounts_t *sa,
                                   const char *username,
                                   const char *fingerprint)
{
    const service_account_t *account = service_accounts_find(sa, username);
    if (!account) {
        return -1;  /* Account not found */
    }

    if (!account->key_fingerprint || !*account->key_fingerprint) {
        return -3;  /* No fingerprint configured */
    }

    if (!fingerprint || !*fingerprint) {
        return -2;  /* No fingerprint provided */
    }

    /* Compare fingerprints (case-sensitive for base64) */
    if (strcmp(account->key_fingerprint, fingerprint) != 0) {
        return -2;  /* Fingerprint mismatch */
    }

    return 0;  /* Match */
}

int service_account_validate(const service_account_t *account)
{
    if (!account) return -1;

    /* Name is required */
    if (!account->name || validate_username(account->name) != 0) {
        return -1;
    }

    /* Key fingerprint is required and must be valid format */
    if (!account->key_fingerprint ||
        validate_fingerprint(account->key_fingerprint) != 0) {
        syslog(LOG_WARNING, "open-bastion: service account '%s' has "
               "invalid or missing key_fingerprint", account->name);
        return -2;
    }

    return 0;
}
