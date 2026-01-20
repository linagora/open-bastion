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
#include "config.h"

/* Initial capacity for accounts array */
#define INITIAL_CAPACITY 8

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
    if (st.st_uid != 0) {
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

/* Trim whitespace from string */
static char *trim(char *str)
{
    if (!str) return NULL;

    /* Trim leading */
    while (isspace((unsigned char)*str)) str++;

    if (*str == '\0') return str;

    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

/*
 * Helper to parse boolean values.
 * Returns true for: "true", "yes", "1", "on"
 * Returns false for: "false", "no", "0", "off", and any other value
 */
static bool parse_bool(const char *value)
{
    if (!value) return false;

    if (strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0 ||
        strcmp(value, "on") == 0) {
        return true;
    }

    return false;
}

/*
 * Safe integer parsing with validation.
 */
static int parse_int(const char *value, int default_val)
{
    if (!value || !*value) return default_val;

    char *endptr;
    errno = 0;
    long result = strtol(value, &endptr, 10);

    if (errno != 0 || endptr == value || *endptr != '\0') {
        return default_val;
    }

    if (result < 0 || result > 65535) {
        return default_val;
    }

    return (int)result;
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
}

static void service_account_free(service_account_t *account)
{
    if (!account) return;

    free(account->name);
    free(account->key_fingerprint);
    free(account->gecos);
    free(account->shell);
    free(account->home);

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
 * Parse a line within a section
 */
static void parse_account_line(const char *key, const char *value,
                                service_account_t *account)
{
    if (strcmp(key, "key_fingerprint") == 0 ||
        strcmp(key, "fingerprint") == 0 ||
        strcmp(key, "ssh_key") == 0) {
        free(account->key_fingerprint);
        account->key_fingerprint = strdup(value);
    }
    else if (strcmp(key, "sudo_allowed") == 0 || strcmp(key, "sudo") == 0) {
        account->sudo_allowed = parse_bool(value);
    }
    else if (strcmp(key, "sudo_nopasswd") == 0 || strcmp(key, "nopasswd") == 0) {
        account->sudo_nopasswd = parse_bool(value);
    }
    else if (strcmp(key, "gecos") == 0 || strcmp(key, "description") == 0) {
        free(account->gecos);
        account->gecos = strdup(value);
    }
    else if (strcmp(key, "shell") == 0) {
        free(account->shell);
        account->shell = strdup(value);
    }
    else if (strcmp(key, "home") == 0 || strcmp(key, "home_dir") == 0) {
        free(account->home);
        account->home = strdup(value);
    }
    else if (strcmp(key, "uid") == 0) {
        account->uid = parse_int(value, 0);
    }
    else if (strcmp(key, "gid") == 0) {
        account->gid = parse_int(value, 0);
    }
    /* Unknown keys are silently ignored */
}

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

            /* Check if account already exists */
            for (size_t i = 0; i < sa->count; i++) {
                if (strcmp(sa->accounts[i].name, section_name) == 0) {
                    syslog(LOG_WARNING, "open-bastion: service_accounts: "
                           "duplicate account '%s' at line %d",
                           section_name, line_num);
                    current_account = &sa->accounts[i];
                    goto next_line;
                }
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

        parse_account_line(key, value, current_account);

next_line:
        continue;
    }

    fclose(f);
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

int service_accounts_get_authorization(const service_accounts_t *sa,
                                        const char *username,
                                        bool *sudo_allowed,
                                        bool *sudo_nopasswd,
                                        const char **gecos,
                                        const char **shell,
                                        const char **home,
                                        int *uid,
                                        int *gid)
{
    const service_account_t *account = service_accounts_find(sa, username);
    if (!account) {
        return -1;
    }

    if (sudo_allowed) *sudo_allowed = account->sudo_allowed;
    if (sudo_nopasswd) *sudo_nopasswd = account->sudo_nopasswd;
    if (gecos) *gecos = account->gecos;
    if (shell) *shell = account->shell;
    if (home) *home = account->home;
    if (uid) *uid = account->uid;
    if (gid) *gid = account->gid;

    return 0;
}

int service_account_validate(const service_account_t *account,
                              const char *approved_shells,
                              const char *approved_home_prefixes)
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

    /* Shell must be in approved list if specified */
    if (account->shell && *account->shell) {
        if (config_validate_shell(account->shell, approved_shells) != 0) {
            syslog(LOG_WARNING, "open-bastion: service account '%s' has "
                   "unapproved shell '%s'", account->name, account->shell);
            return -3;
        }
    }

    /* Home must be in approved prefixes if specified */
    if (account->home && *account->home) {
        if (config_validate_home(account->home, approved_home_prefixes) != 0) {
            syslog(LOG_WARNING, "open-bastion: service account '%s' has "
                   "unapproved home '%s'", account->name, account->home);
            return -4;
        }
    }

    /* UID/GID must be in valid range if specified */
    if (account->uid < 0 || account->uid > 65534) {
        return -5;
    }
    if (account->gid < 0 || account->gid > 65534) {
        return -5;
    }

    return 0;
}
