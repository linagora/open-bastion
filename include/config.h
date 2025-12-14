/*
 * config.h - Configuration parsing for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: GPL-2.0
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

    /* Authorization mode */
    bool authorize_only;     /* Only check authorization, no password (for SSH keys) */

    /* Logging */
    int log_level;           /* 0=error, 1=warn, 2=info, 3=debug */
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
