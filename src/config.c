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
#define DEFAULT_AUTH_CACHE_DIR          "/var/cache/open-bastion/auth"
#define DEFAULT_AUTH_CACHE_FORCE_ONLINE "/etc/open-bastion/force_online"
#define DEFAULT_SERVER_GROUP            "default"
#define DEFAULT_AUDIT_LOG_FILE          "/var/log/open-bastion/audit.json"
#define DEFAULT_RATE_LIMIT_STATE_DIR    "/var/lib/open-bastion/ratelimit"

void config_init(pam_openbastion_config_t *config)
{
    memset(config, 0, sizeof(*config));

    /* Basic settings */
    config->timeout = DEFAULT_TIMEOUT;
    config->verify_ssl = true;
    config->log_level = 1;  /* warn */

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

#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
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
    config->offline_cache_key_file = NULL;  /* Default: /etc/open-bastion/cache.key */

    /* Offline session revalidation - enabled by default */
    config->offline_revalidation_enabled = true;
    config->offline_revalidation_grace = 14400;  /* 4 hours */
    config->offline_max_sso_unreachable = 3600;  /* 1 hour */
#endif /* ENABLE_DESKTOP_SSO */

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

    /* SSH key policy - disabled by default (allows all key types) */
    config->ssh_key_policy_enabled = false;
    config->ssh_key_allowed_types = NULL;  /* NULL means all types allowed */
    config->ssh_key_min_rsa_bits = 2048;   /* NIST recommendation minimum */
    config->ssh_key_min_ecdsa_bits = 256;  /* P-256 minimum */
    config->fingerprint_required = false;  /* opt-in: see #192 */

    /* Cache brute-force protection - disabled by default (#92) */
    config->cache_rate_limit_enabled = false;
    config->cache_rate_limit_max_attempts = 3;      /* Stricter than network rate limit */
    config->cache_rate_limit_lockout_sec = 60;      /* 1 minute initial lockout */
    config->cache_rate_limit_max_lockout_sec = 3600; /* 1 hour max lockout */

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

    /* Authorization cache settings */
    free(config->auth_cache_dir);
    free(config->auth_cache_force_online);

#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
    /* Offline credential cache */
    free(config->offline_cache_dir);
    free(config->offline_cache_key_file);
#endif /* ENABLE_DESKTOP_SSO */

    /* Audit settings */
    free(config->audit_log_file);

    /* Rate limiting settings */
    free(config->rate_limit_state_dir);

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

    /* CrowdSec integration */
    free(config->crowdsec_url);
    secure_free_str(config->crowdsec_bouncer_key);
    free(config->crowdsec_action);
    free(config->crowdsec_machine_id);
    secure_free_str(config->crowdsec_password);
    free(config->crowdsec_scenario);
    free(config->crowdsec_ban_duration);
    free(config->crowdsec_whitelist);

    /* SSH key policy */
    free(config->ssh_key_allowed_types);

    /* Group synchronization */
    free(config->allowed_managed_groups);

    explicit_bzero(config, sizeof(*config));
}

/* Use shared string utilities from str_utils.h */
#define trim str_trim

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
 * Helper macro for boolean field assignment (fail-closed, issue #183).
 *
 * str_parse_bool() used to map every unrecognised value to false. A typo such
 * as "verify_ssl = TRUE" or "verify_ssl = tru" therefore silently turned OFF
 * TLS certificate verification. Only the documented tokens are accepted now;
 * anything else leaves the field at its (safe) default, logs the offending
 * key and value, and latches config->invalid_bool_value so config_validate()
 * refuses the whole configuration rather than running with a guessed value.
 *
 * Must be used inside a function with a `config` pointer in scope.
 */
#define SET_BOOL_FIELD(field, value, key) do { \
    bool _b; \
    if (str_parse_bool_strict((value), &_b)) { \
        (field) = _b; \
    } else { \
        syslog(LOG_ERR, "open-bastion: invalid boolean value for '%s': '%s' " \
               "(expected one of true/yes/1/on or false/no/0/off)", \
               (key), (value) ? (value) : ""); \
        config->invalid_bool_value = true; \
    } \
} while (0)

/*
 * Keys whose value is an opaque secret or a hash: never strip anything from
 * them, since '#' is a perfectly ordinary character in a generated password,
 * an API key or a base64 digest. To put a '#' in any *other* value, quote it.
 */
static bool key_holds_opaque_secret(const char *key)
{
    static const char *const secret_keys[] = {
        "client_secret",
        "notify_secret",
        "webhook_secret",
        "request_signing_secret",
        "crowdsec_bouncer_key",
        "crowdsec_password",
        "cert_pin",
        NULL,
    };

    for (size_t i = 0; secret_keys[i]; i++) {
        if (strcmp(key, secret_keys[i]) == 0) {
            return true;
        }
    }

    return false;
}

/*
 * Remove one layer of matching quotes from a value, in place.
 * Returns a pointer to the unquoted value (possibly offset from `value`).
 * Shared by config_load() and config_parse_args() so a value is understood
 * the same way whether it comes from openbastion.conf or from a pam.d line.
 */
static char *strip_quotes(char *value)
{
    if (!value || (*value != '"' && *value != '\'')) {
        return value;
    }

    char quote = *value;
    value++;
    char *end = strrchr(value, quote);
    if (end) *end = '\0';

    return value;
}

/*
 * Strip a trailing inline comment from an (already trimmed) value, in place.
 *
 * Before the #183 fix an unrecognised value silently meant `false`, so
 * `verify_ssl = true # prod` was merely dangerous. Now it is a fatal -6: the
 * PAM module refuses to start and every SSH and sudo authentication on the
 * host is denied. An upgrade must never be able to lock an operator out of a
 * bastion over a comment, so we recognise inline comments instead.
 *
 * The rule is deliberately narrow so it cannot eat a legitimate value:
 *
 *   - a quoted value is left untouched. The caller's quote stripper ends the
 *     value at the closing quote, which already discards any trailing
 *     comment, so `secret = "a # b"` keeps its '#' and
 *     `verify_ssl = "true" # prod` still parses.
 *   - keys listed in key_holds_opaque_secret() are exempt entirely.
 *   - otherwise, only a '#' that starts the value or is preceded by
 *     whitespace introduces a comment. `url = https://x/#frag` and
 *     `pass = a#b` are therefore preserved; `verify_ssl = true # prod` is not.
 */
static void strip_inline_comment(const char *key, char *value)
{
    if (!key || !value) {
        return;
    }

    /* Quoted: the quote stripper decides where the value ends. */
    if (*value == '"' || *value == '\'') {
        return;
    }

    if (key_holds_opaque_secret(key)) {
        return;
    }

    for (char *p = value; *p; p++) {
        if (*p != '#') {
            continue;
        }
        if (p != value && !isspace((unsigned char)p[-1])) {
            continue;  /* '#' inside a token: part of the value */
        }

        *p = '\0';
        /* Re-trim the whitespace that preceded the '#'. */
        while (p > value && isspace((unsigned char)p[-1])) {
            *--p = '\0';
        }
        return;
    }
}

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

/*
 * Parse a single config line.
 *
 * Returns 0 when the key was recognised and applied, -1 when the value was
 * rejected, and PARSE_LINE_UNKNOWN_KEY when nothing knows the key. Callers
 * reading openbastion.conf turn that last case into a warning: unknown keys
 * are still ignored, but silently ignoring them made every documentation typo
 * invisible (#229).
 */
#define PARSE_LINE_UNKNOWN_KEY 1
/* A Desktop SSO setting read by a build without Desktop SSO: ignored. */
#define PARSE_LINE_DESKTOP_KEY 2

/*
 * The Desktop SSO settings, compiled in every build so that a build without
 * Desktop SSO recognises them instead of reporting them as typos. The desktop
 * build parses them in parse_line() before they get here.
 */
static const char *const desktop_sso_keys[] = {
    "oauth2_token_auth",
    "oauth2_token_cache",
    "oauth2_token_min_ttl",
    "offline_cache_enabled",
    "offline_cache_dir",
    "offline_cache_ttl",
    "offline_cache_max_failures",
    "offline_cache_lockout",
    "offline_cache_key_file",
    "offline_revalidation_enabled",
    "offline_revalidation_grace",
    "offline_max_sso_unreachable",
    NULL
};

/* The Desktop SSO PAM flags (arguments without a value). */
static const char *const desktop_sso_flags[] = {
    "oauth2_token_auth",
    "no_oauth2_token_cache",
    "offline_cache",
    "no_offline_cache",
    NULL
};

static bool in_list(const char *const *list, const char *name)
{
    for (; *list; list++) {
        if (strcmp(*list, name) == 0) {
            return true;
        }
    }
    return false;
}

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
        SET_BOOL_FIELD(config->verify_ssl, value, key);
    }
    else if (strcmp(key, "ca_cert") == 0) {
        SET_STRING_FIELD(config->ca_cert, value, key);
    }
    /*
     * Not a setting: every portal connection requires TLS 1.3. Recognised so
     * that existing files load without an unknown-key warning.
     */
    else if (strcmp(key, "min_tls_version") == 0) {
        if (strcmp(value, "13") != 0 && strcmp(value, "1.3") != 0) {
            syslog(LOG_WARNING,
                   "open-bastion: min_tls_version = %s ignored: TLS 1.3 is "
                   "required towards the portal", value);
        }
    }
    else if (strcmp(key, "cert_pin") == 0) {
        SET_STRING_FIELD(config->cert_pin, value, key);
    }
    /* Authorization cache settings (offline mode) */
    else if (strcmp(key, "auth_cache_enabled") == 0 || strcmp(key, "auth_cache") == 0) {
        SET_BOOL_FIELD(config->auth_cache_enabled, value, key);
    }
    else if (strcmp(key, "auth_cache_dir") == 0) {
        SET_STRING_FIELD(config->auth_cache_dir, value, key);
    }
    else if (strcmp(key, "auth_cache_force_online") == 0 || strcmp(key, "force_online_file") == 0) {
        SET_STRING_FIELD(config->auth_cache_force_online, value, key);
    }
    /* Authorization mode */
    else if (strcmp(key, "authorize_only") == 0) {
        SET_BOOL_FIELD(config->authorize_only, value, key);
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
        SET_BOOL_FIELD(config->audit_enabled, value, key);
    }
    else if (strcmp(key, "audit_log_file") == 0 || strcmp(key, "audit_file") == 0) {
        SET_STRING_FIELD(config->audit_log_file, value, key);
    }
    else if (strcmp(key, "audit_to_syslog") == 0 || strcmp(key, "audit_syslog") == 0) {
        SET_BOOL_FIELD(config->audit_to_syslog, value, key);
    }
    else if (strcmp(key, "audit_level") == 0) {
        if (strcmp(value, "critical") == 0) config->audit_level = 0;
        else if (strcmp(value, "auth") == 0) config->audit_level = 1;
        else if (strcmp(value, "all") == 0) config->audit_level = 2;
        else config->audit_level = parse_int(value, 1, 0, 2);  /* default: auth */
    }
    /* Rate limiting settings */
    else if (strcmp(key, "rate_limit_enabled") == 0 || strcmp(key, "rate_limit") == 0) {
        SET_BOOL_FIELD(config->rate_limit_enabled, value, key);
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
        SET_BOOL_FIELD(config->token_bind_ip, value, key);
    }
    else if (strcmp(key, "token_bind_fingerprint") == 0 || strcmp(key, "bind_fingerprint") == 0) {
        SET_BOOL_FIELD(config->token_bind_fingerprint, value, key);
    }
    else if (strcmp(key, "token_check_revocation") == 0 || strcmp(key, "check_revocation") == 0) {
        SET_BOOL_FIELD(config->token_check_revocation, value, key);
    }
    else if (strcmp(key, "token_rotate_refresh") == 0 || strcmp(key, "rotate_refresh") == 0) {
        SET_BOOL_FIELD(config->token_rotate_refresh, value, key);
    }
    /* Webhook settings */
    else if (strcmp(key, "notify_enabled") == 0 || strcmp(key, "notify") == 0) {
        SET_BOOL_FIELD(config->notify_enabled, value, key);
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
        SET_BOOL_FIELD(config->create_user_enabled, value, key);
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
#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
    /* Desktop SSO / OAuth2 token authentication */
    else if (strcmp(key, "oauth2_token_auth") == 0) {
        SET_BOOL_FIELD(config->oauth2_token_auth, value, key);
    }
    else if (strcmp(key, "oauth2_token_cache") == 0) {
        SET_BOOL_FIELD(config->oauth2_token_cache, value, key);
    }
    else if (strcmp(key, "oauth2_token_min_ttl") == 0) {
        config->oauth2_token_min_ttl = parse_int(value, 60, 0, 3600);
    }
    /* Offline credential cache settings */
    else if (strcmp(key, "offline_cache_enabled") == 0) {
        SET_BOOL_FIELD(config->offline_cache_enabled, value, key);
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
    else if (strcmp(key, "offline_cache_key_file") == 0) {
        SET_STRING_FIELD(config->offline_cache_key_file, value, key);
    }
    else if (strcmp(key, "offline_revalidation_enabled") == 0) {
        SET_BOOL_FIELD(config->offline_revalidation_enabled, value, key);
    }
    else if (strcmp(key, "offline_revalidation_grace") == 0) {
        config->offline_revalidation_grace = parse_int(value, 14400, 600, 86400);  /* 10 min to 24 hours */
    }
    else if (strcmp(key, "offline_max_sso_unreachable") == 0) {
        config->offline_max_sso_unreachable = parse_int(value, 3600, 600, 86400);  /* 10 min to 24 hours */
    }
#endif /* ENABLE_DESKTOP_SSO */
    /* CrowdSec integration options */
    else if (strcmp(key, "crowdsec_enabled") == 0 || strcmp(key, "crowdsec") == 0) {
        SET_BOOL_FIELD(config->crowdsec_enabled, value, key);
    }
    else if (strcmp(key, "crowdsec_url") == 0) {
        SET_STRING_FIELD(config->crowdsec_url, value, key);
    }
    else if (strcmp(key, "crowdsec_timeout") == 0) {
        config->crowdsec_timeout = parse_int(value, 5, 1, 60);
    }
    else if (strcmp(key, "crowdsec_fail_open") == 0) {
        SET_BOOL_FIELD(config->crowdsec_fail_open, value, key);
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
        SET_BOOL_FIELD(config->crowdsec_send_all_alerts, value, key);
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
    else if (strcmp(key, "crowdsec_whitelist") == 0) {
        SET_STRING_FIELD(config->crowdsec_whitelist, value, key);
    }
    /* SSH key policy options */
    else if (strcmp(key, "ssh_key_policy_enabled") == 0 ||
             strcmp(key, "ssh_key_policy") == 0) {
        SET_BOOL_FIELD(config->ssh_key_policy_enabled, value, key);
    }
    else if (strcmp(key, "ssh_key_allowed_types") == 0 ||
             strcmp(key, "ssh_allowed_types") == 0) {
        SET_STRING_FIELD(config->ssh_key_allowed_types, value, key);
    }
    else if (strcmp(key, "ssh_key_min_rsa_bits") == 0 ||
             strcmp(key, "ssh_min_rsa_bits") == 0) {
        /* Valid RSA sizes: 1024 (weak), 2048 (minimum recommended), 3072, 4096 */
        config->ssh_key_min_rsa_bits = parse_int(value, 2048, 1024, 16384);
    }
    else if (strcmp(key, "fingerprint_required") == 0 ||
             strcmp(key, "ssh_fingerprint_required") == 0) {
        SET_BOOL_FIELD(config->fingerprint_required, value, key);
    }
    else if (strcmp(key, "ssh_key_min_ecdsa_bits") == 0 ||
             strcmp(key, "ssh_min_ecdsa_bits") == 0) {
        /* Valid ECDSA sizes: 256 (P-256), 384 (P-384), 521 (P-521) */
        config->ssh_key_min_ecdsa_bits = parse_int(value, 256, 256, 521);
    }
    /* Cache brute-force protection (#92) */
    else if (strcmp(key, "cache_rate_limit_enabled") == 0 ||
             strcmp(key, "cache_rate_limit") == 0) {
        SET_BOOL_FIELD(config->cache_rate_limit_enabled, value, key);
    }
    else if (strcmp(key, "cache_rate_limit_max_attempts") == 0) {
        config->cache_rate_limit_max_attempts = parse_int(value, 3, 1, 100);
    }
    else if (strcmp(key, "cache_rate_limit_lockout_sec") == 0 ||
             strcmp(key, "cache_rate_limit_lockout") == 0) {
        config->cache_rate_limit_lockout_sec = parse_int(value, 60, 1, 86400);
    }
    else if (strcmp(key, "cache_rate_limit_max_lockout_sec") == 0 ||
             strcmp(key, "cache_rate_limit_max_lockout") == 0) {
        config->cache_rate_limit_max_lockout_sec = parse_int(value, 3600, 60, 86400);
    }
    /* Group synchronization (#38) */
    else if (strcmp(key, "allowed_managed_groups") == 0) {
        SET_STRING_FIELD(config->allowed_managed_groups, value, key);
    }
    /*
     * Keys that openbastion.conf legitimately carries for other components.
     * They are not consumed here, but they are not typos either, so they must
     * not be reported as unknown. ob-heartbeat(8) reads these three.
     */
    else if (strcmp(key, "node_role") == 0 ||
             strcmp(key, "report_sessions") == 0 ||
             strcmp(key, "max_reported_sessions") == 0) {
        /* consumed by ob-heartbeat(8) */
    }
    /*
     * Keys this project's own tooling writes into openbastion.conf and that
     * nothing reads back from it. Who writes what, exactly:
     *
     *   ob-backend-setup   all five
     *   ob-bastion-setup   the three cache_* ones
     *   the ansible template  the same three
     *   ob-builder         cache_enabled and cache_ttl, in its heredocs
     *   the shipped example  none of them
     *
     * cache_ttl and default_shell are live settings -- but of the NSS module,
     * read from nss_openbastion.conf, its own file.
     *
     * Reporting them would have made this change worse than the silence it
     * replaces: config_load() runs once per PAM process, so every login on
     * every officially deployed host would emit three to five syslog warnings,
     * drowning the real typo this is meant to surface. Removing them from the
     * generators is a separate change; recognising them here is what keeps the
     * signal usable today.
     */
    else if (strcmp(key, "cache_enabled") == 0 ||
             strcmp(key, "cache_dir") == 0 ||
             strcmp(key, "cache_ttl") == 0 ||
             strcmp(key, "create_home") == 0 ||
             strcmp(key, "default_shell") == 0) {
        /* written by ob-bastion-setup / ob-backend-setup / ob-builder */
    }
    else if (in_list(desktop_sso_keys, key)) {
        return PARSE_LINE_DESKTOP_KEY;
    }
    else {
        return PARSE_LINE_UNKNOWN_KEY;
    }

    return 0;
}

/*
 * Handle one raw line of openbastion.conf. The buffer is modified in place.
 * Split out of config_load() so the line syntax (comments, quotes, inline
 * comments) can be tested without a root-owned file on disk.
 */
static void parse_config_file_line(char *line, pam_openbastion_config_t *config,
                                   const char *filename)
{
    char *trimmed = trim(line);

    /* Skip empty lines and comments */
    if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
        return;
    }

    /* Skip section headers [section] */
    if (*trimmed == '[') {
        return;
    }

    /* Find = separator */
    char *eq = strchr(trimmed, '=');
    if (!eq) {
        return;  /* Skip malformed lines */
    }

    *eq = '\0';
    char *key = trim(trimmed);
    char *value = trim(eq + 1);

    /*
     * Drop an inline comment (`verify_ssl = true # prod`) before the strict
     * boolean parse, which would otherwise reject the whole configuration and
     * lock the host out. Quoted values and secret-bearing keys are exempt;
     * see strip_inline_comment().
     */
    strip_inline_comment(key, value);

    value = strip_quotes(value);

    /*
     * Never log the value: it may be client_secret. The key alone is enough
     * to spot a typo such as auth_cache_offline_ttl for offline_cache_ttl
     * (#229).
     */
    int rc = parse_line(key, value, config);
    if (rc == PARSE_LINE_UNKNOWN_KEY) {
        syslog(LOG_WARNING,
               "open-bastion: unknown configuration key '%s' in %s, ignored",
               key, filename ? filename : "openbastion.conf");
    } else if (rc == PARSE_LINE_DESKTOP_KEY) {
        syslog(LOG_WARNING,
               "open-bastion: '%s' in %s is a Desktop SSO setting, not "
               "supported by this build, ignored",
               key, filename ? filename : "openbastion.conf");
    }
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

    while (fgets(line, sizeof(line), f)) {
        parse_config_file_line(line, config, filename);
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

            /*
             * config_load() strips quotes; do the same here so a pam.d line
             * such as `ssh_cert_aware="true"` is understood identically
             * instead of being rejected as an invalid boolean. PAM arguments
             * carry no comments, so strip_inline_comment() is not applied.
             */
            char *value = strdup(eq + 1);
            if (!value) {
                syslog(LOG_WARNING, "open-bastion: strdup failed for PAM argument %s", key);
                continue;
            }
            if (parse_line(key, strip_quotes(value), config) == PARSE_LINE_DESKTOP_KEY) {
                syslog(LOG_WARNING,
                       "open-bastion: PAM argument '%s' is a Desktop SSO "
                       "setting, not supported by this build, ignored", key);
            }
            free(value);
        }
        /* Boolean flags */
        else if (strcmp(arg, "debug") == 0) {
            config->log_level = 3;
        }
        else if (strcmp(arg, "authorize_only") == 0) {
            config->authorize_only = true;
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
        /* User creation flags */
        else if (strcmp(arg, "create_user") == 0) {
            config->create_user_enabled = true;
        }
        else if (strcmp(arg, "no_create_user") == 0 || strcmp(arg, "nocreateuser") == 0) {
            config->create_user_enabled = false;
        }
#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
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
#endif /* ENABLE_DESKTOP_SSO */
        else if (in_list(desktop_sso_flags, arg)) {
            syslog(LOG_WARNING,
                   "open-bastion: PAM argument '%s' is a Desktop SSO "
                   "setting, not supported by this build, ignored", arg);
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
    /*
     * Security (#183): a boolean setting carried a value that is neither a
     * recognised true nor a recognised false. Refuse the configuration rather
     * than running with a guessed value — "verify_ssl = TRUE" must not end up
     * disabling TLS verification. The offending key and value were already
     * logged by SET_BOOL_FIELD().
     */
    if (config->invalid_bool_value) {
        return -6;  /* Unparseable boolean value in configuration */
    }

    if (!config->portal_url || strlen(config->portal_url) == 0) {
        return -1;  /* portal_url is required */
    }

    /* Security: require HTTPS unless SSL verification is explicitly disabled */
    if (config->verify_ssl) {
        if (strncmp(config->portal_url, "https://", 8) != 0) {
            return -4;  /* HTTPS required when verify_ssl is enabled */
        }
    } else {
        syslog(LOG_WARNING, "open-bastion: WARNING: verify_ssl is disabled - "
               "TLS certificate verification is OFF, connections are vulnerable to MITM attacks");
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
