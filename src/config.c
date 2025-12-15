/*
 * config.c - Configuration parsing for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>

#include "config.h"

/* Security: check file permissions for sensitive files */
static int check_file_permissions(const char *filename)
{
    struct stat st;

    if (stat(filename, &st) != 0) {
        return -1;  /* File doesn't exist or can't be accessed */
    }

    /* File must be owned by root (uid 0) */
    if (st.st_uid != 0) {
        return -2;  /* Not owned by root */
    }

    /* File must not be readable by group or others */
    if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
        return -3;  /* Permissions too open */
    }

    return 0;  /* OK */
}

/* Default values */
#define DEFAULT_TIMEOUT                 10
#define DEFAULT_CACHE_TTL               300
#define DEFAULT_CACHE_TTL_HIGH_RISK     60
#define DEFAULT_CACHE_DIR               "/var/cache/pam_llng"
#define DEFAULT_SERVER_GROUP            "default"
#define DEFAULT_AUDIT_LOG_FILE          "/var/log/pam_llng/audit.json"
#define DEFAULT_RATE_LIMIT_STATE_DIR    "/var/lib/pam_llng/ratelimit"
#define DEFAULT_KEYRING_NAME            "pam_llng"

void config_init(pam_llng_config_t *config)
{
    memset(config, 0, sizeof(*config));

    /* Basic settings */
    config->timeout = DEFAULT_TIMEOUT;
    config->verify_ssl = true;
    config->log_level = 1;  /* warn */

    /* Cache settings */
    config->cache_enabled = true;
    config->cache_ttl = DEFAULT_CACHE_TTL;
    config->cache_ttl_high_risk = DEFAULT_CACHE_TTL_HIGH_RISK;
    config->cache_dir = strdup(DEFAULT_CACHE_DIR);

    /* Server settings */
    config->server_group = strdup(DEFAULT_SERVER_GROUP);

    /* Audit settings */
    config->audit_enabled = true;
    config->audit_log_file = strdup(DEFAULT_AUDIT_LOG_FILE);
    config->audit_to_syslog = true;
    config->audit_level = 1;  /* auth events */

    /* Rate limiting settings */
    config->rate_limit_enabled = true;
    config->rate_limit_state_dir = strdup(DEFAULT_RATE_LIMIT_STATE_DIR);
    config->rate_limit_max_attempts = 5;
    config->rate_limit_initial_lockout = 30;
    config->rate_limit_max_lockout = 3600;
    config->rate_limit_backoff_mult = 2.0;

    /* Token binding - secure defaults */
    config->token_bind_ip = true;
    config->token_bind_fingerprint = false;
    config->token_check_revocation = false;
    config->token_rotate_refresh = true;

    /* Secret storage - secure defaults */
    config->secrets_encrypted = true;
    config->secrets_use_keyring = true;
    config->secrets_keyring_name = strdup(DEFAULT_KEYRING_NAME);

    /* Webhooks - disabled by default */
    config->notify_enabled = false;

    /* User creation - disabled by default */
    config->create_user_enabled = false;
    config->create_user_home_base = strdup("/home");
    config->create_user_skel = strdup("/etc/skel");

    /* Path validation - secure defaults */
    config->approved_shells = strdup(DEFAULT_APPROVED_SHELLS);
    config->approved_home_prefixes = strdup(DEFAULT_APPROVED_HOME_PREFIXES);
}

/* Secure free: zero memory before freeing */
static void secure_free_str(char *ptr)
{
    if (ptr) {
        explicit_bzero(ptr, strlen(ptr));
        free(ptr);
    }
}

void config_free(pam_llng_config_t *config)
{
    if (!config) return;

    /* Basic settings */
    free(config->portal_url);
    free(config->client_id);
    secure_free_str(config->client_secret);
    free(config->server_token_file);
    free(config->server_group);
    free(config->ca_cert);

    /* Cache settings */
    free(config->cache_dir);
    free(config->high_risk_services);

    /* Audit settings */
    free(config->audit_log_file);

    /* Rate limiting settings */
    free(config->rate_limit_state_dir);

    /* Secret storage */
    free(config->secrets_keyring_name);

    /* Webhooks */
    free(config->notify_url);
    secure_free_str(config->notify_secret);

    /* User creation */
    free(config->create_user_shell);
    free(config->create_user_groups);
    free(config->create_user_home_base);
    free(config->create_user_skel);

    /* Path validation */
    free(config->approved_shells);
    free(config->approved_home_prefixes);

    explicit_bzero(config, sizeof(*config));
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

    /* Explicit true values */
    if (strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0 ||
        strcmp(value, "on") == 0) {
        return true;
    }

    /* All other values including "false", "no", "0", "off" return false */
    return false;
}

/* Parse a single config line */
static int parse_line(const char *key, const char *value, pam_llng_config_t *config)
{
    /* Basic settings */
    if (strcmp(key, "portal_url") == 0 || strcmp(key, "portal") == 0) {
        free(config->portal_url);
        config->portal_url = strdup(value);
    }
    else if (strcmp(key, "client_id") == 0) {
        free(config->client_id);
        config->client_id = strdup(value);
    }
    else if (strcmp(key, "client_secret") == 0) {
        free(config->client_secret);
        config->client_secret = strdup(value);
    }
    else if (strcmp(key, "server_token_file") == 0 || strcmp(key, "token_file") == 0) {
        free(config->server_token_file);
        config->server_token_file = strdup(value);
    }
    else if (strcmp(key, "server_group") == 0) {
        free(config->server_group);
        config->server_group = strdup(value);
    }
    else if (strcmp(key, "timeout") == 0) {
        config->timeout = atoi(value);
    }
    else if (strcmp(key, "verify_ssl") == 0) {
        config->verify_ssl = parse_bool(value);
    }
    else if (strcmp(key, "ca_cert") == 0) {
        free(config->ca_cert);
        config->ca_cert = strdup(value);
    }
    /* Cache settings */
    else if (strcmp(key, "cache_enabled") == 0 || strcmp(key, "cache") == 0) {
        config->cache_enabled = parse_bool(value);
    }
    else if (strcmp(key, "cache_dir") == 0) {
        free(config->cache_dir);
        config->cache_dir = strdup(value);
    }
    else if (strcmp(key, "cache_ttl") == 0) {
        config->cache_ttl = atoi(value);
    }
    else if (strcmp(key, "cache_ttl_high_risk") == 0) {
        config->cache_ttl_high_risk = atoi(value);
    }
    else if (strcmp(key, "high_risk_services") == 0) {
        free(config->high_risk_services);
        config->high_risk_services = strdup(value);
    }
    /* Authorization mode */
    else if (strcmp(key, "authorize_only") == 0) {
        config->authorize_only = parse_bool(value);
    }
    /* Logging */
    else if (strcmp(key, "log_level") == 0 || strcmp(key, "debug") == 0) {
        if (strcmp(value, "error") == 0) config->log_level = 0;
        else if (strcmp(value, "warn") == 0) config->log_level = 1;
        else if (strcmp(value, "info") == 0) config->log_level = 2;
        else if (strcmp(value, "debug") == 0) config->log_level = 3;
        else config->log_level = atoi(value);
    }
    /* Audit settings */
    else if (strcmp(key, "audit_enabled") == 0 || strcmp(key, "audit") == 0) {
        config->audit_enabled = parse_bool(value);
    }
    else if (strcmp(key, "audit_log_file") == 0 || strcmp(key, "audit_file") == 0) {
        free(config->audit_log_file);
        config->audit_log_file = strdup(value);
    }
    else if (strcmp(key, "audit_to_syslog") == 0 || strcmp(key, "audit_syslog") == 0) {
        config->audit_to_syslog = parse_bool(value);
    }
    else if (strcmp(key, "audit_level") == 0) {
        if (strcmp(value, "critical") == 0) config->audit_level = 0;
        else if (strcmp(value, "auth") == 0) config->audit_level = 1;
        else if (strcmp(value, "all") == 0) config->audit_level = 2;
        else config->audit_level = atoi(value);
    }
    /* Rate limiting settings */
    else if (strcmp(key, "rate_limit_enabled") == 0 || strcmp(key, "rate_limit") == 0) {
        config->rate_limit_enabled = parse_bool(value);
    }
    else if (strcmp(key, "rate_limit_state_dir") == 0) {
        free(config->rate_limit_state_dir);
        config->rate_limit_state_dir = strdup(value);
    }
    else if (strcmp(key, "rate_limit_max_attempts") == 0) {
        config->rate_limit_max_attempts = atoi(value);
    }
    else if (strcmp(key, "rate_limit_initial_lockout") == 0) {
        config->rate_limit_initial_lockout = atoi(value);
    }
    else if (strcmp(key, "rate_limit_max_lockout") == 0) {
        config->rate_limit_max_lockout = atoi(value);
    }
    else if (strcmp(key, "rate_limit_backoff_mult") == 0) {
        config->rate_limit_backoff_mult = atof(value);
    }
    /* Token binding settings */
    else if (strcmp(key, "token_bind_ip") == 0 || strcmp(key, "bind_ip") == 0) {
        config->token_bind_ip = parse_bool(value);
    }
    else if (strcmp(key, "token_bind_fingerprint") == 0 || strcmp(key, "bind_fingerprint") == 0) {
        config->token_bind_fingerprint = parse_bool(value);
    }
    else if (strcmp(key, "token_check_revocation") == 0 || strcmp(key, "check_revocation") == 0) {
        config->token_check_revocation = parse_bool(value);
    }
    else if (strcmp(key, "token_rotate_refresh") == 0 || strcmp(key, "rotate_refresh") == 0) {
        config->token_rotate_refresh = parse_bool(value);
    }
    /* Secret storage settings */
    else if (strcmp(key, "secrets_encrypted") == 0) {
        config->secrets_encrypted = parse_bool(value);
    }
    else if (strcmp(key, "secrets_use_keyring") == 0 || strcmp(key, "use_keyring") == 0) {
        config->secrets_use_keyring = parse_bool(value);
    }
    else if (strcmp(key, "secrets_keyring_name") == 0 || strcmp(key, "keyring_name") == 0) {
        free(config->secrets_keyring_name);
        config->secrets_keyring_name = strdup(value);
    }
    /* Webhook settings */
    else if (strcmp(key, "notify_enabled") == 0 || strcmp(key, "notify") == 0) {
        config->notify_enabled = parse_bool(value);
    }
    else if (strcmp(key, "notify_url") == 0 || strcmp(key, "webhook_url") == 0) {
        free(config->notify_url);
        config->notify_url = strdup(value);
    }
    else if (strcmp(key, "notify_secret") == 0 || strcmp(key, "webhook_secret") == 0) {
        free(config->notify_secret);
        config->notify_secret = strdup(value);
    }
    /* User creation settings */
    else if (strcmp(key, "create_user") == 0 || strcmp(key, "create_user_enabled") == 0) {
        config->create_user_enabled = parse_bool(value);
    }
    else if (strcmp(key, "create_user_shell") == 0) {
        free(config->create_user_shell);
        config->create_user_shell = strdup(value);
    }
    else if (strcmp(key, "create_user_groups") == 0) {
        free(config->create_user_groups);
        config->create_user_groups = strdup(value);
    }
    else if (strcmp(key, "create_user_home_base") == 0 || strcmp(key, "home_base") == 0) {
        free(config->create_user_home_base);
        config->create_user_home_base = strdup(value);
    }
    else if (strcmp(key, "create_user_skel") == 0 || strcmp(key, "skel") == 0) {
        free(config->create_user_skel);
        config->create_user_skel = strdup(value);
    }
    /* Path validation settings */
    else if (strcmp(key, "approved_shells") == 0) {
        free(config->approved_shells);
        config->approved_shells = strdup(value);
    }
    else if (strcmp(key, "approved_home_prefixes") == 0) {
        free(config->approved_home_prefixes);
        config->approved_home_prefixes = strdup(value);
    }
    /* Unknown keys are silently ignored */

    return 0;
}

int config_load(const char *filename, pam_llng_config_t *config)
{
    /* Security check: verify file permissions */
    int perm_check = check_file_permissions(filename);
    if (perm_check == -2) {
        /* File not owned by root - security risk */
        return -2;
    }
    if (perm_check == -3) {
        /* Permissions too open - security risk */
        return -3;
    }

    FILE *f = fopen(filename, "r");
    if (!f) {
        return -1;
    }

    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }

        /* Skip section headers [section] */
        if (*trimmed == '[') {
            continue;
        }

        /* Find = separator */
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

        parse_line(key, value, config);
    }

    fclose(f);
    return 0;
}

int config_parse_args(int argc, const char **argv, pam_llng_config_t *config)
{
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];

        /* Skip conf= as it's handled separately */
        if (strncmp(arg, "conf=", 5) == 0) {
            continue;
        }

        /* Check for key=value */
        const char *eq = strchr(arg, '=');
        if (eq) {
            size_t key_len = eq - arg;
            char key[64];
            if (key_len >= sizeof(key) - 1) {
                continue;  /* Key too long, skip */
            }
            memcpy(key, arg, key_len);
            key[key_len] = '\0';  /* Explicit null termination */

            const char *value = eq + 1;
            parse_line(key, value, config);
        }
        /* Boolean flags */
        else if (strcmp(arg, "debug") == 0) {
            config->log_level = 3;
        }
        else if (strcmp(arg, "authorize_only") == 0) {
            config->authorize_only = true;
        }
        else if (strcmp(arg, "no_cache") == 0 || strcmp(arg, "nocache") == 0) {
            config->cache_enabled = false;
        }
        else if (strcmp(arg, "no_verify_ssl") == 0 || strcmp(arg, "insecure") == 0) {
            config->verify_ssl = false;
        }
        /* Audit flags */
        else if (strcmp(arg, "no_audit") == 0 || strcmp(arg, "noaudit") == 0) {
            config->audit_enabled = false;
        }
        else if (strcmp(arg, "no_syslog") == 0 || strcmp(arg, "nosyslog") == 0) {
            config->audit_to_syslog = false;
        }
        /* Rate limiting flags */
        else if (strcmp(arg, "no_rate_limit") == 0 || strcmp(arg, "noratelimit") == 0) {
            config->rate_limit_enabled = false;
        }
        /* Token binding flags */
        else if (strcmp(arg, "no_bind_ip") == 0 || strcmp(arg, "nobindip") == 0) {
            config->token_bind_ip = false;
        }
        else if (strcmp(arg, "bind_fingerprint") == 0) {
            config->token_bind_fingerprint = true;
        }
        else if (strcmp(arg, "check_revocation") == 0) {
            config->token_check_revocation = true;
        }
        else if (strcmp(arg, "no_rotate_refresh") == 0) {
            config->token_rotate_refresh = false;
        }
        /* Secret storage flags */
        else if (strcmp(arg, "no_encrypt_secrets") == 0) {
            config->secrets_encrypted = false;
        }
        else if (strcmp(arg, "no_keyring") == 0 || strcmp(arg, "nokeyring") == 0) {
            config->secrets_use_keyring = false;
        }
        /* User creation flags */
        else if (strcmp(arg, "create_user") == 0) {
            config->create_user_enabled = true;
        }
        else if (strcmp(arg, "no_create_user") == 0 || strcmp(arg, "nocreateuser") == 0) {
            config->create_user_enabled = false;
        }
    }

    return 0;
}

/* Helper to create parent directory for a file path */
static void ensure_parent_dir(const char *filepath)
{
    if (!filepath) return;

    char *path_copy = strdup(filepath);
    if (!path_copy) return;

    char *parent = dirname(path_copy);
    if (parent && strcmp(parent, ".") != 0 && strcmp(parent, "/") != 0) {
        struct stat st;
        if (stat(parent, &st) != 0) {
            /* Try to create the parent directory with secure permissions */
            if (mkdir(parent, 0750) != 0 && errno != EEXIST) {
                /* Try creating grandparent first */
                char *parent_copy = strdup(parent);
                if (parent_copy) {
                    char *grandparent = dirname(parent_copy);
                    if (grandparent && strcmp(grandparent, ".") != 0) {
                        mkdir(grandparent, 0755);
                    }
                    free(parent_copy);
                }
                mkdir(parent, 0750);
            }
        }
    }

    free(path_copy);
}

int config_validate(const pam_llng_config_t *config)
{
    if (!config->portal_url || strlen(config->portal_url) == 0) {
        return -1;  /* portal_url is required */
    }

    /* Security: require HTTPS unless SSL verification is explicitly disabled */
    if (config->verify_ssl) {
        if (strncmp(config->portal_url, "https://", 8) != 0) {
            return -4;  /* HTTPS required when verify_ssl is enabled */
        }
    }

    /* For authorize endpoint, we need client credentials for introspection */
    if (!config->authorize_only) {
        if (!config->client_id || !config->client_secret) {
            return -1;  /* client_id and client_secret required for token validation */
        }
    }

    /* Create directories for audit log file if needed */
    if (config->audit_enabled && config->audit_log_file) {
        ensure_parent_dir(config->audit_log_file);
    }

    /* For account management, we need a server token */
    /* But it's okay to not have one if only doing authentication */

    return 0;
}

/*
 * Check if a path contains dangerous patterns
 * Returns 1 if dangerous, 0 if safe
 */
static int path_contains_dangerous_patterns(const char *path)
{
    if (!path) return 1;

    /* Must be absolute path */
    if (path[0] != '/') return 1;

    /* Check for path traversal attempts */
    if (strstr(path, "..") != NULL) return 1;

    /* Check for multiple consecutive slashes (could indicate obfuscation) */
    if (strstr(path, "//") != NULL) return 1;

    /* Check for dangerous characters */
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char)*p;
        /* Allow: alphanumeric, /, -, _, . */
        if (!isalnum(c) && c != '/' && c != '-' && c != '_' && c != '.') {
            return 1;
        }
    }

    /* Check for hidden paths (starting with dot after slash) */
    if (strstr(path, "/.") != NULL) return 1;

    return 0;
}

int config_validate_shell(const char *shell, const char *approved_shells)
{
    if (!shell || !*shell) return -1;

    /* Check for dangerous patterns first */
    if (path_contains_dangerous_patterns(shell)) return -1;

    /* Use default if no approved list provided */
    const char *list = approved_shells ? approved_shells : DEFAULT_APPROVED_SHELLS;

    /* Make a mutable copy for tokenization */
    char *list_copy = strdup(list);
    if (!list_copy) return -1;

    int found = 0;
    char *saveptr;
    char *token = strtok_r(list_copy, ":", &saveptr);

    while (token != NULL) {
        if (strcmp(shell, token) == 0) {
            found = 1;
            break;
        }
        token = strtok_r(NULL, ":", &saveptr);
    }

    free(list_copy);
    return found ? 0 : -1;
}

int config_validate_home(const char *home, const char *approved_prefixes)
{
    if (!home || !*home) return -1;

    /* Check for dangerous patterns first */
    if (path_contains_dangerous_patterns(home)) return -1;

    /* Use default if no approved list provided */
    const char *list = approved_prefixes ? approved_prefixes : DEFAULT_APPROVED_HOME_PREFIXES;

    /* Make a mutable copy for tokenization */
    char *list_copy = strdup(list);
    if (!list_copy) return -1;

    int found = 0;
    char *saveptr;
    char *token = strtok_r(list_copy, ":", &saveptr);

    while (token != NULL) {
        size_t prefix_len = strlen(token);
        /* Home must start with prefix and be followed by / or end */
        if (strncmp(home, token, prefix_len) == 0) {
            char next = home[prefix_len];
            if (next == '/' || next == '\0') {
                found = 1;
                break;
            }
        }
        token = strtok_r(NULL, ":", &saveptr);
    }

    free(list_copy);
    return found ? 0 : -1;
}
