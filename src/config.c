/*
 * config.c - Configuration parsing for Open Bastion PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>
#include <syslog.h>

#include "config.h"
#include "str_utils.h"

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

/* Default values */
#define DEFAULT_TIMEOUT                 10
#define DEFAULT_CACHE_TTL               300
#define DEFAULT_CACHE_TTL_HIGH_RISK     60
#define DEFAULT_CACHE_DIR               "/var/cache/open-bastion"
#define DEFAULT_AUTH_CACHE_DIR          "/var/cache/open-bastion/auth"
#define DEFAULT_AUTH_CACHE_FORCE_ONLINE "/etc/open-bastion/force_online"
#define DEFAULT_SERVER_GROUP            "default"
#define DEFAULT_AUDIT_LOG_FILE          "/var/log/open-bastion/audit.json"
#define DEFAULT_RATE_LIMIT_STATE_DIR    "/var/lib/open-bastion/ratelimit"
#define DEFAULT_KEYRING_NAME            "open-bastion"

/* TLS version constants for min_tls_version configuration */
#define TLS_VERSION_1_2 12
#define TLS_VERSION_1_3 13

void config_init(pam_openbastion_config_t *config)
{
    memset(config, 0, sizeof(*config));

    /* Basic settings */
    config->timeout = DEFAULT_TIMEOUT;
    config->verify_ssl = true;
    config->log_level = 1;  /* warn */
    config->min_tls_version = TLS_VERSION_1_3;  /* TLS 1.3 by default */

    /* Cache settings */
    config->cache_enabled = true;
    config->cache_ttl = DEFAULT_CACHE_TTL;
    config->cache_ttl_high_risk = DEFAULT_CACHE_TTL_HIGH_RISK;
    config->cache_dir = strdup(DEFAULT_CACHE_DIR);
    config->cache_encrypted = true;  /* Encrypted by default */
    config->cache_invalidate_on_logout = true;  /* Invalidate on logout by default */

    /* Authorization cache settings (for offline mode) */
    config->auth_cache_enabled = true;
    config->auth_cache_dir = strdup(DEFAULT_AUTH_CACHE_DIR);
    config->auth_cache_force_online = strdup(DEFAULT_AUTH_CACHE_FORCE_ONLINE);

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

    /* Service accounts */
    config->service_accounts_file = strdup(DEFAULT_SERVICE_ACCOUNTS_FILE);

    /* Desktop SSO / OAuth2 token authentication - disabled by default */
    config->oauth2_token_auth = false;
    config->oauth2_token_cache = true;
    config->oauth2_token_min_ttl = 60;  /* 1 minute minimum remaining TTL */

    /* Offline credential cache - disabled by default */
    config->offline_cache_enabled = false;
    config->offline_cache_dir = NULL;  /* Default set in load function */
    config->offline_cache_ttl = 604800;  /* 7 days */
    config->offline_cache_max_failures = 5;
    config->offline_cache_lockout = 300;  /* 5 minutes */

    /* Bastion JWT verification - disabled by default */
    config->bastion_jwt_required = false;
    config->bastion_jwt_verify_local = true;  /* Local verification preferred */
    config->bastion_jwt_cache_ttl = 3600;     /* 1 hour JWKS cache */
    config->bastion_jwt_clock_skew = 60;      /* 1 minute clock skew allowed */

    /* JTI replay detection - enabled by default when bastion JWT is used */
    config->bastion_jwt_replay_detection = true;
    config->bastion_jwt_replay_cache_size = 10000;
    config->bastion_jwt_replay_cleanup_interval = 60;

    /* CrowdSec integration - disabled by default */
    config->crowdsec_enabled = false;
    config->crowdsec_url = strdup("http://127.0.0.1:8080");
    config->crowdsec_timeout = 5;
    config->crowdsec_fail_open = true;
    config->crowdsec_action = strdup("reject");
    config->crowdsec_scenario = strdup("open-bastion/ssh-auth-failure");
    config->crowdsec_send_all_alerts = true;
    config->crowdsec_max_failures = 5;
    config->crowdsec_block_delay = 180;
    config->crowdsec_ban_duration = strdup("4h");

    /* Note: strdup failures for defaults are checked by config_validate() */
}

/* Secure free: zero memory before freeing */
static void secure_free_str(char *ptr)
{
    if (ptr) {
        explicit_bzero(ptr, strlen(ptr));
        free(ptr);
    }
}

void config_free(pam_openbastion_config_t *config)
{
    if (!config) return;

    /* Basic settings */
    free(config->portal_url);
    free(config->client_id);
    secure_free_str(config->client_secret);
    free(config->server_token_file);
    free(config->server_group);
    free(config->ca_cert);
    free(config->cert_pin);

    /* Cache settings */
    free(config->cache_dir);
    free(config->high_risk_services);

    /* Authorization cache settings */
    free(config->auth_cache_dir);
    free(config->auth_cache_force_online);

    /* Offline credential cache */
    free(config->offline_cache_dir);

    /* Audit settings */
    free(config->audit_log_file);

    /* Rate limiting settings */
    free(config->rate_limit_state_dir);

    /* Secret storage */
    free(config->secrets_keyring_name);

    /* Webhooks */
    free(config->notify_url);
    secure_free_str(config->notify_secret);

    /* Request signing */
    secure_free_str(config->request_signing_secret);

    /* User creation */
    free(config->create_user_shell);
    free(config->create_user_groups);
    free(config->create_user_home_base);
    free(config->create_user_skel);

    /* Path validation */
    free(config->approved_shells);
    free(config->approved_home_prefixes);

    /* Service accounts */
    free(config->service_accounts_file);

    /* Bastion JWT verification */
    free(config->bastion_jwt_issuer);
    free(config->bastion_jwt_jwks_url);
    free(config->bastion_jwt_jwks_cache);
    free(config->bastion_jwt_allowed_bastions);

    /* CrowdSec integration */
    free(config->crowdsec_url);
    secure_free_str(config->crowdsec_bouncer_key);
    free(config->crowdsec_action);
    free(config->crowdsec_machine_id);
    secure_free_str(config->crowdsec_password);
    free(config->crowdsec_scenario);
    free(config->crowdsec_ban_duration);

    explicit_bzero(config, sizeof(*config));
}

/* Use shared string utilities from str_utils.h */
#define trim str_trim
#define parse_bool str_parse_bool

/* Maximum lengths for security-sensitive configuration values */
#define MAX_URL_LENGTH 512
#define MAX_TOKEN_FILE_PATH 256

/*
 * Helper macro for safe string field assignment.
 * Duplicates value and assigns to field, freeing the old value.
 * Logs a warning if strdup fails but keeps the old value.
 */
#define SET_STRING_FIELD(field, value, key) do { \
    char *_tmp = strdup(value); \
    if (_tmp) { \
        free(field); \
        (field) = _tmp; \
    } else { \
        syslog(LOG_WARNING, "open-bastion: strdup failed for %s", key); \
    } \
} while (0)

/*
 * Safe integer parsing with validation.
 * Returns the parsed value, or default_val if parsing fails.
 * Unlike atoi(), this detects invalid input and doesn't silently return 0.
 */
static int parse_int(const char *value, int default_val, int min_val, int max_val)
{
    if (!value || !*value) return default_val;

    char *endptr;
    errno = 0;
    long result = strtol(value, &endptr, 10);

    /* Check for conversion errors */
    if (errno != 0 || endptr == value || *endptr != '\0') {
        return default_val;  /* Invalid input */
    }

    /* Check for long-to-int overflow (on 64-bit platforms, long > int) */
    if (result < INT_MIN || result > INT_MAX) {
        return default_val;
    }

    /* Check user-specified range */
    if (result < min_val || result > max_val) {
        return default_val;
    }

    return (int)result;
}

/*
 * Safe double parsing with validation.
 * Returns the parsed value, or default_val if parsing fails.
 */
static double parse_double(const char *value, double default_val, double min_val, double max_val)
{
    if (!value || !*value) return default_val;

    char *endptr;
    errno = 0;
    double result = strtod(value, &endptr);

    /* Check for conversion errors */
    if (errno != 0 || endptr == value || *endptr != '\0') {
        return default_val;  /* Invalid input */
    }

    /* Check range */
    if (result < min_val || result > max_val) {
        return default_val;
    }

    return result;
}

/* Check URL for dangerous characters (injection prevention) */
static int url_contains_dangerous_chars(const char *url)
{
    if (!url) return 1;
    /* Reject URLs with control characters that could enable header injection */
    for (const char *p = url; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || c == 127) {  /* Control characters */
            return 1;
        }
        /*
         * Security: check for URL-encoded CRLF injection (%0d, %0a, %0D, %0A).
         * CURL will decode these, potentially enabling HTTP response splitting.
         */
        if (c == '%' && p[1] && p[2]) {
            char hex[3] = { p[1], p[2], '\0' };
            unsigned int decoded;
            if (sscanf(hex, "%2x", &decoded) == 1) {
                if (decoded < 32 || decoded == 127) {
                    return 1;  /* Encoded control character */
                }
                /* Skip the two hex characters we just processed */
                p += 2;
            }
        }
    }
    return 0;
}

/* Parse a single config line */
static int parse_line(const char *key, const char *value, pam_openbastion_config_t *config)
{
    /* Basic settings */
    if (strcmp(key, "portal_url") == 0 || strcmp(key, "portal") == 0) {
        /* Validate URL length and content */
        if (strlen(value) > MAX_URL_LENGTH) {
            return -1;  /* URL too long */
        }
        if (url_contains_dangerous_chars(value)) {
            return -1;  /* Dangerous characters */
        }
        SET_STRING_FIELD(config->portal_url, value, key);
    }
    else if (strcmp(key, "client_id") == 0) {
        SET_STRING_FIELD(config->client_id, value, key);
    }
    else if (strcmp(key, "client_secret") == 0) {
        SET_STRING_FIELD(config->client_secret, value, key);
    }
    else if (strcmp(key, "server_token_file") == 0 || strcmp(key, "token_file") == 0) {
        SET_STRING_FIELD(config->server_token_file, value, key);
    }
    else if (strcmp(key, "server_group") == 0) {
        SET_STRING_FIELD(config->server_group, value, key);
    }
    else if (strcmp(key, "timeout") == 0) {
        config->timeout = parse_int(value, DEFAULT_TIMEOUT, 1, 300);
    }
    else if (strcmp(key, "verify_ssl") == 0) {
        config->verify_ssl = parse_bool(value);
    }
    else if (strcmp(key, "ca_cert") == 0) {
        SET_STRING_FIELD(config->ca_cert, value, key);
    }
    else if (strcmp(key, "min_tls_version") == 0) {
        config->min_tls_version = parse_int(value, TLS_VERSION_1_3, 0, 99);
        /* Normalize: accept 1.2, 1.3, 12, 13 */
        if (config->min_tls_version == 1) config->min_tls_version = TLS_VERSION_1_2;  /* "1" -> 1.2 legacy */
        else if (config->min_tls_version < TLS_VERSION_1_2) config->min_tls_version = TLS_VERSION_1_3;  /* Invalid -> default */
    }
    else if (strcmp(key, "cert_pin") == 0) {
        SET_STRING_FIELD(config->cert_pin, value, key);
    }
    /* Cache settings */
    else if (strcmp(key, "cache_enabled") == 0 || strcmp(key, "cache") == 0) {
        config->cache_enabled = parse_bool(value);
    }
    else if (strcmp(key, "cache_dir") == 0) {
        SET_STRING_FIELD(config->cache_dir, value, key);
    }
    else if (strcmp(key, "cache_ttl") == 0) {
        config->cache_ttl = parse_int(value, DEFAULT_CACHE_TTL, 0, 86400);
    }
    else if (strcmp(key, "cache_ttl_high_risk") == 0) {
        config->cache_ttl_high_risk = parse_int(value, DEFAULT_CACHE_TTL_HIGH_RISK, 0, 86400);
    }
    else if (strcmp(key, "high_risk_services") == 0) {
        SET_STRING_FIELD(config->high_risk_services, value, key);
    }
    else if (strcmp(key, "cache_encrypted") == 0) {
        config->cache_encrypted = parse_bool(value);
    }
    else if (strcmp(key, "cache_invalidate_on_logout") == 0) {
        config->cache_invalidate_on_logout = parse_bool(value);
    }
    /* Authorization cache settings (offline mode) */
    else if (strcmp(key, "auth_cache_enabled") == 0 || strcmp(key, "auth_cache") == 0) {
        config->auth_cache_enabled = parse_bool(value);
    }
    else if (strcmp(key, "auth_cache_dir") == 0) {
        SET_STRING_FIELD(config->auth_cache_dir, value, key);
    }
    else if (strcmp(key, "auth_cache_force_online") == 0 || strcmp(key, "force_online_file") == 0) {
        SET_STRING_FIELD(config->auth_cache_force_online, value, key);
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
        else config->log_level = parse_int(value, 1, 0, 3);  /* default: warn */
    }
    /* Audit settings */
    else if (strcmp(key, "audit_enabled") == 0 || strcmp(key, "audit") == 0) {
        config->audit_enabled = parse_bool(value);
    }
    else if (strcmp(key, "audit_log_file") == 0 || strcmp(key, "audit_file") == 0) {
        SET_STRING_FIELD(config->audit_log_file, value, key);
    }
    else if (strcmp(key, "audit_to_syslog") == 0 || strcmp(key, "audit_syslog") == 0) {
        config->audit_to_syslog = parse_bool(value);
    }
    else if (strcmp(key, "audit_level") == 0) {
        if (strcmp(value, "critical") == 0) config->audit_level = 0;
        else if (strcmp(value, "auth") == 0) config->audit_level = 1;
        else if (strcmp(value, "all") == 0) config->audit_level = 2;
        else config->audit_level = parse_int(value, 1, 0, 2);  /* default: auth */
    }
    /* Rate limiting settings */
    else if (strcmp(key, "rate_limit_enabled") == 0 || strcmp(key, "rate_limit") == 0) {
        config->rate_limit_enabled = parse_bool(value);
    }
    else if (strcmp(key, "rate_limit_state_dir") == 0) {
        SET_STRING_FIELD(config->rate_limit_state_dir, value, key);
    }
    else if (strcmp(key, "rate_limit_max_attempts") == 0) {
        config->rate_limit_max_attempts = parse_int(value, 5, 1, 100);
    }
    else if (strcmp(key, "rate_limit_initial_lockout") == 0) {
        config->rate_limit_initial_lockout = parse_int(value, 30, 1, 3600);
    }
    else if (strcmp(key, "rate_limit_max_lockout") == 0) {
        config->rate_limit_max_lockout = parse_int(value, 3600, 60, 86400);
    }
    else if (strcmp(key, "rate_limit_backoff_mult") == 0) {
        config->rate_limit_backoff_mult = parse_double(value, 2.0, 1.1, 10.0);
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
        SET_STRING_FIELD(config->secrets_keyring_name, value, key);
    }
    /* Webhook settings */
    else if (strcmp(key, "notify_enabled") == 0 || strcmp(key, "notify") == 0) {
        config->notify_enabled = parse_bool(value);
    }
    else if (strcmp(key, "notify_url") == 0 || strcmp(key, "webhook_url") == 0) {
        SET_STRING_FIELD(config->notify_url, value, key);
    }
    else if (strcmp(key, "notify_secret") == 0 || strcmp(key, "webhook_secret") == 0) {
        SET_STRING_FIELD(config->notify_secret, value, key);
    }
    /* Request signing settings */
    else if (strcmp(key, "request_signing_secret") == 0) {
        SET_STRING_FIELD(config->request_signing_secret, value, key);
    }
    /* User creation settings */
    else if (strcmp(key, "create_user") == 0 || strcmp(key, "create_user_enabled") == 0) {
        config->create_user_enabled = parse_bool(value);
    }
    else if (strcmp(key, "create_user_shell") == 0) {
        SET_STRING_FIELD(config->create_user_shell, value, key);
    }
    else if (strcmp(key, "create_user_groups") == 0) {
        SET_STRING_FIELD(config->create_user_groups, value, key);
    }
    else if (strcmp(key, "create_user_home_base") == 0 || strcmp(key, "home_base") == 0) {
        SET_STRING_FIELD(config->create_user_home_base, value, key);
    }
    else if (strcmp(key, "create_user_skel") == 0 || strcmp(key, "skel") == 0) {
        SET_STRING_FIELD(config->create_user_skel, value, key);
    }
    /* Path validation settings */
    else if (strcmp(key, "approved_shells") == 0) {
        SET_STRING_FIELD(config->approved_shells, value, key);
    }
    else if (strcmp(key, "approved_home_prefixes") == 0) {
        SET_STRING_FIELD(config->approved_home_prefixes, value, key);
    }
    /* Service accounts */
    else if (strcmp(key, "service_accounts_file") == 0 ||
             strcmp(key, "service_accounts") == 0) {
        SET_STRING_FIELD(config->service_accounts_file, value, key);
    }
    /* Desktop SSO / OAuth2 token authentication */
    else if (strcmp(key, "oauth2_token_auth") == 0) {
        config->oauth2_token_auth = parse_bool(value);
    }
    else if (strcmp(key, "oauth2_token_cache") == 0) {
        config->oauth2_token_cache = parse_bool(value);
    }
    else if (strcmp(key, "oauth2_token_min_ttl") == 0) {
        config->oauth2_token_min_ttl = parse_int(value, 60, 0, 3600);
    }
    /* Offline credential cache settings */
    else if (strcmp(key, "offline_cache_enabled") == 0) {
        config->offline_cache_enabled = parse_bool(value);
    }
    else if (strcmp(key, "offline_cache_dir") == 0) {
        SET_STRING_FIELD(config->offline_cache_dir, value, key);
    }
    else if (strcmp(key, "offline_cache_ttl") == 0) {
        config->offline_cache_ttl = parse_int(value, 604800, 3600, 2592000);  /* 1 hour to 30 days */
    }
    else if (strcmp(key, "offline_cache_max_failures") == 0) {
        config->offline_cache_max_failures = parse_int(value, 5, 1, 20);
    }
    else if (strcmp(key, "offline_cache_lockout") == 0) {
        config->offline_cache_lockout = parse_int(value, 300, 60, 86400);  /* 1 min to 24 hours */
    }
    /* Bastion JWT verification settings */
    else if (strcmp(key, "bastion_jwt_required") == 0 || strcmp(key, "require_bastion") == 0) {
        config->bastion_jwt_required = parse_bool(value);
    }
    else if (strcmp(key, "bastion_jwt_verify_local") == 0) {
        config->bastion_jwt_verify_local = parse_bool(value);
    }
    else if (strcmp(key, "bastion_jwt_issuer") == 0) {
        SET_STRING_FIELD(config->bastion_jwt_issuer, value, key);
    }
    else if (strcmp(key, "bastion_jwt_jwks_url") == 0) {
        SET_STRING_FIELD(config->bastion_jwt_jwks_url, value, key);
    }
    else if (strcmp(key, "bastion_jwt_jwks_cache") == 0) {
        SET_STRING_FIELD(config->bastion_jwt_jwks_cache, value, key);
    }
    else if (strcmp(key, "bastion_jwt_cache_ttl") == 0) {
        config->bastion_jwt_cache_ttl = parse_int(value, 3600, 60, 86400);
    }
    else if (strcmp(key, "bastion_jwt_clock_skew") == 0) {
        config->bastion_jwt_clock_skew = parse_int(value, 60, 0, 600);
    }
    else if (strcmp(key, "bastion_jwt_allowed_bastions") == 0 || strcmp(key, "allowed_bastions") == 0) {
        SET_STRING_FIELD(config->bastion_jwt_allowed_bastions, value, key);
    }
    /* JTI replay detection options */
    else if (strcmp(key, "bastion_jwt_replay_detection") == 0) {
        config->bastion_jwt_replay_detection = parse_bool(value);
    }
    else if (strcmp(key, "bastion_jwt_replay_cache_size") == 0) {
        config->bastion_jwt_replay_cache_size = parse_int(value, 10000, 100, 1000000);
    }
    else if (strcmp(key, "bastion_jwt_replay_cleanup_interval") == 0) {
        config->bastion_jwt_replay_cleanup_interval = parse_int(value, 60, 10, 3600);
    }
    /* CrowdSec integration options */
    else if (strcmp(key, "crowdsec_enabled") == 0 || strcmp(key, "crowdsec") == 0) {
        config->crowdsec_enabled = parse_bool(value);
    }
    else if (strcmp(key, "crowdsec_url") == 0) {
        SET_STRING_FIELD(config->crowdsec_url, value, key);
    }
    else if (strcmp(key, "crowdsec_timeout") == 0) {
        config->crowdsec_timeout = parse_int(value, 5, 1, 60);
    }
    else if (strcmp(key, "crowdsec_fail_open") == 0) {
        config->crowdsec_fail_open = parse_bool(value);
    }
    else if (strcmp(key, "crowdsec_bouncer_key") == 0) {
        SET_STRING_FIELD(config->crowdsec_bouncer_key, value, key);
    }
    else if (strcmp(key, "crowdsec_action") == 0) {
        /* Validate: only "reject" or "warn" are valid */
        if (strcmp(value, "reject") == 0 || strcmp(value, "warn") == 0) {
            SET_STRING_FIELD(config->crowdsec_action, value, key);
        }
        /* Invalid values are silently ignored, keeping the default */
    }
    else if (strcmp(key, "crowdsec_machine_id") == 0) {
        SET_STRING_FIELD(config->crowdsec_machine_id, value, key);
    }
    else if (strcmp(key, "crowdsec_password") == 0) {
        SET_STRING_FIELD(config->crowdsec_password, value, key);
    }
    else if (strcmp(key, "crowdsec_scenario") == 0) {
        SET_STRING_FIELD(config->crowdsec_scenario, value, key);
    }
    else if (strcmp(key, "crowdsec_send_all_alerts") == 0) {
        config->crowdsec_send_all_alerts = parse_bool(value);
    }
    else if (strcmp(key, "crowdsec_max_failures") == 0) {
        config->crowdsec_max_failures = parse_int(value, 5, 0, 100);
    }
    else if (strcmp(key, "crowdsec_block_delay") == 0) {
        config->crowdsec_block_delay = parse_int(value, 180, 10, 86400);
    }
    else if (strcmp(key, "crowdsec_ban_duration") == 0) {
        SET_STRING_FIELD(config->crowdsec_ban_duration, value, key);
    }
    /* Unknown keys are silently ignored */

    return 0;
}

int config_load(const char *filename, pam_openbastion_config_t *config)
{
    /*
     * Security: open file with O_NOFOLLOW to prevent symlink attacks,
     * then check permissions on the opened fd to avoid TOCTOU.
     */
    int fd = open(filename, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return -1;  /* File doesn't exist or is a symlink */
    }

    int perm_check = check_file_permissions_fd(fd);
    if (perm_check == -2) {
        /* File not owned by root - security risk */
        close(fd);
        return -2;
    }
    if (perm_check == -3) {
        /* Permissions too open - security risk */
        close(fd);
        return -3;
    }
    if (perm_check == -4) {
        /* Not a regular file */
        close(fd);
        return -4;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
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

int config_parse_args(int argc, const char **argv, pam_openbastion_config_t *config)
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
        else if (strcmp(arg, "no_cache_encrypt") == 0 || strcmp(arg, "nocacheencrypt") == 0) {
            config->cache_encrypted = false;
        }
        else if (strcmp(arg, "no_auth_cache") == 0 || strcmp(arg, "noauthcache") == 0) {
            config->auth_cache_enabled = false;
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
        /* OAuth2 token authentication flags */
        else if (strcmp(arg, "oauth2_token_auth") == 0) {
            config->oauth2_token_auth = true;
        }
        else if (strcmp(arg, "no_oauth2_token_cache") == 0) {
            config->oauth2_token_cache = false;
        }
        /* Offline credential cache flags */
        else if (strcmp(arg, "offline_cache") == 0) {
            config->offline_cache_enabled = true;
        }
        else if (strcmp(arg, "no_offline_cache") == 0) {
            config->offline_cache_enabled = false;
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
                /* Try creating grandparent first with restricted permissions */
                char *parent_copy = strdup(parent);
                if (parent_copy) {
                    char *grandparent = dirname(parent_copy);
                    if (grandparent && strcmp(grandparent, ".") != 0) {
                        mkdir(grandparent, 0750);
                    }
                    free(parent_copy);
                }
                mkdir(parent, 0750);
            }
        }
    }

    free(path_copy);
}

int config_validate(const pam_openbastion_config_t *config)
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

    /* Validate CrowdSec configuration if enabled */
    if (config->crowdsec_enabled) {
        /* These fields must not be NULL if CrowdSec is enabled */
        if (!config->crowdsec_url || !config->crowdsec_scenario ||
            !config->crowdsec_action || !config->crowdsec_ban_duration) {
            return -5;  /* CrowdSec configuration incomplete */
        }
        /* Validate action is "reject" or "warn" */
        if (strcmp(config->crowdsec_action, "reject") != 0 &&
            strcmp(config->crowdsec_action, "warn") != 0) {
            return -5;  /* Invalid crowdsec_action */
        }
    }

    /* For account management, we need a server token */
    /* But it's okay to not have one if only doing authentication */

    return 0;
}

/*
 * Maximum path length to prevent DoS via very long paths.
 * Linux PATH_MAX is 4096, but we use a smaller limit for security.
 */
#define MAX_SAFE_PATH_LENGTH 1024

/*
 * Check if a path contains dangerous patterns
 * Returns 1 if dangerous, 0 if safe
 */
static int path_contains_dangerous_patterns(const char *path)
{
    if (!path) return 1;

    /* Limit path length to prevent DoS - use strnlen to avoid scanning entire string */
    if (strnlen(path, MAX_SAFE_PATH_LENGTH + 1) > MAX_SAFE_PATH_LENGTH) return 1;

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

    /*
     * Parse colon-separated list without strdup/strtok to avoid
     * allocation overhead in the hot path (called on every auth).
     */
    size_t shell_len = strlen(shell);
    const char *current = list;

    while (current && *current) {
        /* Find the end of current token (next ':' or end of string) */
        const char *colon = strchr(current, ':');
        size_t token_len = colon ? (size_t)(colon - current) : strlen(current);

        /* Skip empty tokens (e.g., "::" or leading/trailing ":") */
        if (token_len > 0) {
            /* Compare shell with this token */
            if (token_len == shell_len && strncmp(shell, current, token_len) == 0) {
                return 0;  /* Found */
            }
        }

        /* Move to next token */
        current = colon ? colon + 1 : NULL;
    }

    return -1;  /* Not found */
}

int config_validate_home(const char *home, const char *approved_prefixes)
{
    if (!home || !*home) return -1;

    /* Check for dangerous patterns first */
    if (path_contains_dangerous_patterns(home)) return -1;

    /* Use default if no approved list provided */
    const char *list = approved_prefixes ? approved_prefixes : DEFAULT_APPROVED_HOME_PREFIXES;

    /*
     * Parse colon-separated list without strdup/strtok to avoid
     * allocation overhead in the hot path (called on every auth).
     */
    const char *current = list;

    while (current && *current) {
        /* Find the end of current token (next ':' or end of string) */
        const char *colon = strchr(current, ':');
        size_t prefix_len = colon ? (size_t)(colon - current) : strlen(current);

        /* Skip empty tokens (e.g., "::" or leading/trailing ":") */
        if (prefix_len > 0) {
            /* Home must start with prefix and be followed by / or end */
            if (strncmp(home, current, prefix_len) == 0) {
                char next = home[prefix_len];
                if (next == '/' || next == '\0') {
                    return 0;  /* Found */
                }
            }
        }

        /* Move to next token */
        current = colon ? colon + 1 : NULL;
    }

    return -1;  /* Not found */
}

int config_validate_skel(const char *skel_path)
{
    if (!skel_path || !*skel_path) return -1;

    /* Must be absolute path */
    if (skel_path[0] != '/') return -1;

    /* Check for dangerous patterns */
    if (strstr(skel_path, "..") != NULL) return -1;
    if (strstr(skel_path, "//") != NULL) return -1;

    /* Check if path exists and is a directory */
    struct stat st;
    if (lstat(skel_path, &st) != 0) {
        return -1;  /* Path doesn't exist or can't be accessed */
    }

    /* Must be a directory */
    if (!S_ISDIR(st.st_mode)) {
        return -1;
    }

    /* Must not be a symlink (lstat returns the link itself, not target) */
    if (S_ISLNK(st.st_mode)) {
        return -1;
    }

    /* Should be owned by root for security */
    if (st.st_uid != 0) {
        return -1;
    }

    /* Must be an approved path (only /etc/skel, /usr/share/skel, etc.) */
    const char *approved_skel_prefixes[] = {
        "/etc/skel",
        "/usr/share/skel",
        "/usr/local/etc/skel",
        NULL
    };

    int found = 0;
    for (int i = 0; approved_skel_prefixes[i] != NULL; i++) {
        if (strcmp(skel_path, approved_skel_prefixes[i]) == 0 ||
            (strncmp(skel_path, approved_skel_prefixes[i],
                     strlen(approved_skel_prefixes[i])) == 0 &&
             skel_path[strlen(approved_skel_prefixes[i])] == '/')) {
            found = 1;
            break;
        }
    }

    return found ? 0 : -1;
}
