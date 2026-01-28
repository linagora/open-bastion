/*
 * config.h - Configuration parsing for Open Bastion PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

/* Configuration structure */
typedef struct {
    /* Required settings */
    char *portal_url;        /* Open Bastion portal URL */
    char *client_id;         /* OIDC client ID */
    char *client_secret;     /* OIDC client secret */

    /* Server authentication */
    char *server_token_file; /* Path to file containing server token */
    char *server_group;      /* Server group name (default: "default") */

    /* Optional settings */
    int timeout;             /* HTTP timeout in seconds (default: 10) */
    bool verify_ssl;         /* Verify SSL certificates (default: true) */
    char *ca_cert;           /* CA certificate path */
    int min_tls_version;     /* Minimum TLS version: 12=1.2, 13=1.3 (default: 13) */
    char *cert_pin;          /* Certificate pin (sha256//base64 format, optional) */

    /* Cache settings (for token cache) */
    bool cache_enabled;      /* Enable token caching (default: true) */
    char *cache_dir;         /* Cache directory (default: /var/cache/open-bastion) */
    int cache_ttl;           /* Cache TTL in seconds (default: 300) */
    int cache_ttl_high_risk; /* Cache TTL for high-risk services (default: 60) */
    char *high_risk_services; /* Comma-separated list of high-risk PAM services */
    bool cache_encrypted;    /* Encrypt cache files with AES-256-GCM (default: true) */
    bool cache_invalidate_on_logout; /* Invalidate cache when session closes (default: true) */

    /* Authorization cache settings (for offline mode) */
    bool auth_cache_enabled;        /* Enable authorization caching (default: true) */
    char *auth_cache_dir;           /* Auth cache directory (default: /var/cache/open-bastion/auth) */
    char *auth_cache_force_online;  /* Force-online trigger file (default: /etc/open-bastion/force_online) */

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
    char *rate_limit_state_dir;     /* State directory (default: /var/lib/open-bastion/ratelimit) */
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
    char *secrets_keyring_name;     /* Keyring name (default: "open-bastion") */

    /* Webhook notifications */
    bool notify_enabled;            /* Enable webhook notifications (default: false) */
    char *notify_url;               /* Webhook URL for security events */
    char *notify_secret;            /* HMAC secret for webhook signatures */

    /* Request signing (optional, defense in depth) */
    char *request_signing_secret;   /* HMAC secret for request signatures (optional) */

    /* Auto-create Unix accounts */
    bool create_user_enabled;       /* Enable auto user creation (default: false) */
    char *create_user_shell;        /* Default shell (default: from LLNG or /bin/bash) */
    char *create_user_groups;       /* Additional groups (comma-separated) */
    char *create_user_home_base;    /* Home base directory (default: /home) */
    char *create_user_skel;         /* Skeleton directory (default: /etc/skel) */

    /* Path validation */
    char *approved_shells;          /* Colon-separated approved shells (default: common shells) */
    char *approved_home_prefixes;   /* Colon-separated home prefixes (default: /home:/var/home) */

    /* Service accounts (local accounts like ansible, backup, etc.) */
    char *service_accounts_file;    /* Path to service accounts config (default: /etc/open-bastion/service-accounts.conf) */

    /* Desktop SSO / OAuth2 token authentication (for LightDM greeter) */
    bool oauth2_token_auth;         /* Accept OAuth2 access tokens instead of one-time PAM tokens (default: false) */
    bool oauth2_token_cache;        /* Cache successful OAuth2 token auth for offline mode (default: true) */
    int oauth2_token_min_ttl;       /* Minimum remaining TTL for token acceptance in seconds (default: 60) */

    /* Offline credential cache (for desktop SSO offline mode) */
    bool offline_cache_enabled;     /* Enable offline credential caching (default: false) */
    char *offline_cache_dir;        /* Credential cache directory (default: /var/cache/open-bastion/credentials) */
    int offline_cache_ttl;          /* Credential cache TTL in seconds (default: 604800 = 7 days) */
    int offline_cache_max_failures; /* Max failed attempts before lockout (default: 5) */
    int offline_cache_lockout;      /* Lockout duration in seconds (default: 300) */
    char *offline_cache_key_file;   /* Secret key file for cache encryption (default: /etc/open-bastion/cache.key, mode 0600) */

    /* Bastion JWT verification (for backend servers) */
    bool bastion_jwt_required;      /* Require JWT from bastion (default: false) */
    bool bastion_jwt_verify_local;  /* Verify JWT locally with JWKS (default: true) */
    char *bastion_jwt_issuer;       /* Expected JWT issuer (LLNG portal URL) */
    char *bastion_jwt_jwks_url;     /* JWKS endpoint URL (default: portal_url/.well-known/jwks.json) */
    char *bastion_jwt_jwks_cache;   /* Local JWKS cache path (default: /var/cache/open-bastion/jwks.json) */
    int bastion_jwt_cache_ttl;      /* JWKS cache TTL in seconds (default: 3600) */
    int bastion_jwt_clock_skew;     /* Allowed clock skew in seconds (default: 60) */
    char *bastion_jwt_allowed_bastions; /* Comma-separated list of allowed bastion IDs */

    /* JTI replay detection (for bastion JWT) */
    bool bastion_jwt_replay_detection;     /* Enable JTI replay detection (default: true) */
    int bastion_jwt_replay_cache_size;     /* Max JTI cache entries (default: 10000) */
    int bastion_jwt_replay_cleanup_interval; /* Cleanup interval in seconds (default: 60) */

    /* CrowdSec integration (disabled by default) */
    bool crowdsec_enabled;                 /* Enable CrowdSec integration (default: false) */
    char *crowdsec_url;                    /* LAPI URL (default: http://127.0.0.1:8080) */
    int crowdsec_timeout;                  /* HTTP timeout in seconds (default: 5) */
    bool crowdsec_fail_open;               /* Allow on error (default: true) */

    /* CrowdSec Bouncer (pre-auth check) */
    char *crowdsec_bouncer_key;            /* Bouncer API key from cscli bouncers add */
    char *crowdsec_action;                 /* Action on ban: "reject" or "warn" (default: reject) */

    /* CrowdSec Watcher (post-auth alerts) */
    char *crowdsec_machine_id;             /* Machine ID from cscli machines add */
    char *crowdsec_password;               /* Machine password */
    char *crowdsec_scenario;               /* Scenario name (default: open-bastion/ssh-auth-failure) */
    bool crowdsec_send_all_alerts;         /* Send all alerts or only bans (default: true) */
    int crowdsec_max_failures;             /* Auto-ban after N failures, 0=no auto-ban (default: 5) */
    int crowdsec_block_delay;              /* Time window in seconds for counting (default: 180) */
    char *crowdsec_ban_duration;           /* Ban duration e.g. "4h" (default: 4h) */
} pam_openbastion_config_t;

/*
 * Load configuration from file
 * Returns 0 on success, -1 on error
 */
int config_load(const char *filename, pam_openbastion_config_t *config);

/*
 * Parse PAM module arguments
 * Returns 0 on success, -1 on error
 */
int config_parse_args(int argc, const char **argv, pam_openbastion_config_t *config);

/*
 * Free configuration structure
 */
void config_free(pam_openbastion_config_t *config);

/*
 * Initialize configuration with defaults
 */
void config_init(pam_openbastion_config_t *config);

/*
 * Validate configuration
 * Returns 0 if valid, -1 if invalid (with error logged)
 */
int config_validate(const pam_openbastion_config_t *config);

/*
 * Validate shell path against approved shells list
 * Returns 0 if valid, -1 if invalid
 */
int config_validate_shell(const char *shell, const char *approved_shells);

/*
 * Validate home directory path against approved prefixes
 * Returns 0 if valid, -1 if invalid
 */
int config_validate_home(const char *home, const char *approved_prefixes);

/*
 * Validate skeleton directory path
 * Must be absolute, owned by root, no symlinks in path
 * Returns 0 if valid, -1 if invalid
 */
int config_validate_skel(const char *skel_path);

/* Default approved shells */
#define DEFAULT_APPROVED_SHELLS "/bin/bash:/bin/sh:/usr/bin/bash:/usr/bin/sh:/bin/zsh:/usr/bin/zsh:/bin/dash:/usr/bin/dash:/bin/fish:/usr/bin/fish"

/* Default approved home prefixes */
#define DEFAULT_APPROVED_HOME_PREFIXES "/home:/var/home"

/* Default service accounts configuration file */
#define DEFAULT_SERVICE_ACCOUNTS_FILE "/etc/open-bastion/service-accounts.conf"

#endif /* CONFIG_H */
