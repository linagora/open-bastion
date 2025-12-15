/*
 * config.h - Configuration parsing for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

/* Configuration structure */
typedef struct {
    /* Required settings */
    char *portal_url;        /* LLNG portal URL */
    char *client_id;         /* OIDC client ID */
    char *client_secret;     /* OIDC client secret */

    /* Server authentication */
    char *server_token_file; /* Path to file containing server token */
    char *server_group;      /* Server group name (default: "default") */

    /* Optional settings */
    int timeout;             /* HTTP timeout in seconds (default: 10) */
    bool verify_ssl;         /* Verify SSL certificates (default: true) */
    char *ca_cert;           /* CA certificate path */

    /* Cache settings */
    bool cache_enabled;      /* Enable token caching (default: true) */
    char *cache_dir;         /* Cache directory (default: /var/cache/pam_llng) */
    int cache_ttl;           /* Cache TTL in seconds (default: 300) */
    int cache_ttl_high_risk; /* Cache TTL for high-risk services (default: 60) */
    char *high_risk_services; /* Comma-separated list of high-risk PAM services */

    /* Authorization mode */
    bool authorize_only;     /* Only check authorization, no password (for SSH keys) */

    /* Logging */
    int log_level;           /* 0=error, 1=warn, 2=info, 3=debug */

    /* Audit logging */
    bool audit_enabled;      /* Enable structured audit logging (default: true) */
    char *audit_log_file;    /* Path to JSON audit log file */
    bool audit_to_syslog;    /* Also emit audit events to syslog (default: true) */
    int audit_level;         /* 0=critical, 1=auth events, 2=all (default: 1) */

    /* Rate limiting */
    bool rate_limit_enabled;        /* Enable rate limiting (default: true) */
    char *rate_limit_state_dir;     /* State directory (default: /var/lib/pam_llng/ratelimit) */
    int rate_limit_max_attempts;    /* Max failures before lockout (default: 5) */
    int rate_limit_initial_lockout; /* Initial lockout seconds (default: 30) */
    int rate_limit_max_lockout;     /* Maximum lockout seconds (default: 3600) */
    double rate_limit_backoff_mult; /* Exponential backoff multiplier (default: 2.0) */

    /* Token binding and security */
    bool token_bind_ip;             /* Bind tokens to client IP (default: true) */
    bool token_bind_fingerprint;    /* Bind tokens to client fingerprint (default: false) */
    bool token_check_revocation;    /* Check token revocation on each request (default: false) */
    bool token_rotate_refresh;      /* Rotate refresh_token on each refresh (default: true) */

    /* Secret storage */
    bool secrets_encrypted;         /* Encrypt secrets at rest (default: true) */
    bool secrets_use_keyring;       /* Use kernel keyring (default: true) */
    char *secrets_keyring_name;     /* Keyring name (default: "pam_llng") */

    /* Webhook notifications */
    bool notify_enabled;            /* Enable webhook notifications (default: false) */
    char *notify_url;               /* Webhook URL for security events */
    char *notify_secret;            /* HMAC secret for webhook signatures */
} pam_llng_config_t;

/*
 * Load configuration from file
 * Returns 0 on success, -1 on error
 */
int config_load(const char *filename, pam_llng_config_t *config);

/*
 * Parse PAM module arguments
 * Returns 0 on success, -1 on error
 */
int config_parse_args(int argc, const char **argv, pam_llng_config_t *config);

/*
 * Free configuration structure
 */
void config_free(pam_llng_config_t *config);

/*
 * Initialize configuration with defaults
 */
void config_init(pam_llng_config_t *config);

/*
 * Validate configuration
 * Returns 0 if valid, -1 if invalid (with error logged)
 */
int config_validate(const pam_llng_config_t *config);

#endif /* CONFIG_H */
