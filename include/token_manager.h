/*
 * token_manager.h - Token management with refresh rotation for PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef TOKEN_MANAGER_H
#define TOKEN_MANAGER_H

#include <stdbool.h>
#include <time.h>

/* Token information structure */
typedef struct {
    char *access_token;
    char *refresh_token;
    char *token_type;           /* Usually "Bearer" */
    char *scope;                /* Space-separated scopes */
    int expires_in;             /* Seconds until expiry */
    time_t expires_at;          /* Absolute expiry time */
    time_t issued_at;           /* When token was issued */

    /* Binding information */
    char *client_ip;            /* IP the token was issued for */
    char *fingerprint;          /* Context fingerprint for binding */

    /* Server-side info (from introspection) */
    char *user;                 /* Username from introspection */
    bool active;                /* Token is active */
    time_t server_exp;          /* Server-side expiry */
} token_info_t;

/* Token manager configuration */
typedef struct {
    char *portal_url;           /* LLNG portal URL */
    char *client_id;            /* OIDC client ID */
    char *client_secret;        /* OIDC client secret */
    int timeout;                /* HTTP timeout */
    bool verify_ssl;            /* Verify SSL certificates */
    char *ca_cert;              /* CA certificate path */
    bool rotate_refresh;        /* Rotate refresh_token on refresh (default: true) */
    bool bind_ip;               /* Bind tokens to IP */
    bool bind_fingerprint;      /* Bind tokens to fingerprint */
} token_manager_config_t;

/* Token manager handle */
typedef struct token_manager token_manager_t;

/*
 * Initialize token manager
 * Returns NULL on failure
 */
token_manager_t *token_manager_init(const token_manager_config_t *config);

/*
 * Destroy token manager
 */
void token_manager_destroy(token_manager_t *tm);

/*
 * Refresh an access token using refresh_token
 * If rotate_refresh is enabled, the refresh_token will also be updated
 * new_info will contain the refreshed token information
 * Returns 0 on success, -1 on error
 */
int token_manager_refresh(token_manager_t *tm,
                          const char *refresh_token,
                          token_info_t *new_info);

/*
 * Introspect a token
 * Returns 0 on success, -1 on error
 */
int token_manager_introspect(token_manager_t *tm,
                             const char *access_token,
                             token_info_t *info);

/*
 * Check if token needs refresh (expired or about to expire)
 * threshold_sec: refresh if expiring within this many seconds
 * Returns true if refresh is needed
 */
bool token_manager_needs_refresh(const token_info_t *info, int threshold_sec);

/*
 * Check if token binding matches current context
 * Returns true if binding is valid or binding is not required
 */
bool token_manager_check_binding(token_manager_t *tm,
                                  const token_info_t *info,
                                  const char *client_ip,
                                  const char *fingerprint);

/*
 * Free token info structure contents
 */
void token_info_free(token_info_t *info);

/*
 * Get last error message
 */
const char *token_manager_error(token_manager_t *tm);

/*
 * Load token from JSON file
 * Returns 0 on success, -1 on error
 * Note: Also handles legacy plain-text format (access_token only)
 */
int token_manager_load_file(const char *filepath, token_info_t *info);

/*
 * Save token to JSON file
 * Returns 0 on success, -1 on error
 */
int token_manager_save_file(const char *filepath, const token_info_t *info);

#endif /* TOKEN_MANAGER_H */
