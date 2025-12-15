/*
 * path_validator.h - Shared path validation functions
 *
 * This header provides path validation functions that can be used by both
 * the PAM module and the NSS module. Functions are defined as static inline
 * to avoid linking issues between the two separate modules.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef PATH_VALIDATOR_H
#define PATH_VALIDATOR_H

#include <string.h>
#include <ctype.h>

/* Default approved shells */
#define PATH_VALIDATOR_DEFAULT_SHELLS \
    "/bin/bash:/bin/sh:/usr/bin/bash:/usr/bin/sh:" \
    "/bin/zsh:/usr/bin/zsh:/bin/dash:/usr/bin/dash:" \
    "/bin/fish:/usr/bin/fish"

/* Default approved home prefixes */
#define PATH_VALIDATOR_DEFAULT_HOME_PREFIXES "/home:/var/home"

/*
 * Check if a path contains dangerous patterns.
 * Returns 1 if dangerous, 0 if safe.
 *
 * Checks for:
 * - Non-absolute paths
 * - Path traversal (..)
 * - Double slashes (//)
 * - Hidden paths (/.)
 * - Shell metacharacters
 */
static inline int path_validator_is_dangerous(const char *path)
{
    if (!path || !*path) return 1;

    /* Must be absolute path */
    if (path[0] != '/') return 1;

    /* Check for path traversal attempts */
    if (strstr(path, "..") != NULL) return 1;

    /* Check for multiple consecutive slashes */
    if (strstr(path, "//") != NULL) return 1;

    /* Check for hidden paths (starting with dot after slash) */
    if (strstr(path, "/.") != NULL) return 1;

    /* Check for dangerous characters */
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char)*p;
        /* Allow: alphanumeric, /, -, _, . */
        if (!isalnum(c) && c != '/' && c != '-' && c != '_' && c != '.') {
            return 1;
        }
    }

    return 0;
}

/*
 * Validate shell path against a colon-separated list of approved shells.
 * If approved_shells is NULL, uses PATH_VALIDATOR_DEFAULT_SHELLS.
 * Returns 0 if valid, -1 if invalid.
 */
static inline int path_validator_check_shell(const char *shell, const char *approved_shells)
{
    if (!shell || !*shell) return -1;

    /* Check for dangerous patterns first */
    if (path_validator_is_dangerous(shell)) return -1;

    /* Use default if no approved list provided */
    const char *list = approved_shells ? approved_shells : PATH_VALIDATOR_DEFAULT_SHELLS;

    /* Search for shell in colon-separated list */
    size_t shell_len = strlen(shell);
    const char *p = list;

    while (*p) {
        /* Find end of current entry */
        const char *colon = strchr(p, ':');
        size_t entry_len = colon ? (size_t)(colon - p) : strlen(p);

        /* Compare */
        if (entry_len == shell_len && strncmp(p, shell, shell_len) == 0) {
            return 0;  /* Found */
        }

        /* Move to next entry */
        if (colon) {
            p = colon + 1;
        } else {
            break;
        }
    }

    return -1;  /* Not found */
}

/*
 * Validate home directory path against a colon-separated list of approved prefixes.
 * If approved_prefixes is NULL, uses PATH_VALIDATOR_DEFAULT_HOME_PREFIXES.
 * Returns 0 if valid, -1 if invalid.
 */
static inline int path_validator_check_home(const char *home, const char *approved_prefixes)
{
    if (!home || !*home) return -1;

    /* Check for dangerous patterns first */
    if (path_validator_is_dangerous(home)) return -1;

    /* Use default if no approved list provided */
    const char *list = approved_prefixes ? approved_prefixes : PATH_VALIDATOR_DEFAULT_HOME_PREFIXES;

    /* Search for matching prefix in colon-separated list */
    const char *p = list;

    while (*p) {
        /* Find end of current entry */
        const char *colon = strchr(p, ':');
        size_t prefix_len = colon ? (size_t)(colon - p) : strlen(p);

        /* Check if home starts with this prefix */
        if (strncmp(home, p, prefix_len) == 0) {
            /* Home must be followed by / or end (prefix itself is not valid) */
            char next = home[prefix_len];
            if (next == '/') {
                return 0;  /* Valid */
            }
        }

        /* Move to next entry */
        if (colon) {
            p = colon + 1;
        } else {
            break;
        }
    }

    return -1;  /* Not found */
}

#endif /* PATH_VALIDATOR_H */
