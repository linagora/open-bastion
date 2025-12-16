/*
 * llng_client.h - HTTP client for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#ifndef LLNG_CLIENT_H
#define LLNG_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

/* Permissions structure from /pam/authorize response */
typedef struct {
    bool sudo_allowed;      /* User is allowed to use sudo */
    bool sudo_nopasswd;     /* Sudo without password (future use) */
} llng_permissions_t;

/* Offline settings from /pam/authorize response */
typedef struct {
    bool enabled;           /* Offline mode allowed for this user */
    int ttl;                /* Cache TTL in seconds (0 = no caching) */
} llng_offline_settings_t;

/* SSH certificate info extracted from environment */
typedef struct {
    char *key_id;           /* Certificate key ID */
    char *serial;           /* Certificate serial number */
    char *principals;       /* Comma-separated principals */
    char *ca_fingerprint;   /* CA key fingerprint */
    bool valid;             /* Certificate was validated */
} llng_ssh_cert_info_t;

/* Response structure from LLNG server */
typedef struct {
    bool authorized;
    char *user;
    char **groups;
    size_t groups_count;
    char *reason;
    int expires_in;
    bool active;  /* For introspection */
    char *scope;

    /* User attributes for account creation (from /pam/verify) */
    char *gecos;      /* Full name / GECOS field */
    char *shell;      /* Login shell */
    char *home;       /* Home directory */

    /* Permissions from /pam/authorize */
    llng_permissions_t permissions;
    bool has_permissions;   /* True if permissions object was present */

    /* Offline settings from /pam/authorize */
    llng_offline_settings_t offline;
    bool has_offline;       /* True if offline object was present */
} llng_response_t;

/* Client configuration */
typedef struct {
    char *portal_url;
    char *client_id;
    char *client_secret;
    char *server_token;
    char *server_group;
    int timeout;
    bool verify_ssl;
    char *ca_cert;
    char *signing_secret;  /* Optional HMAC secret for request signing */
    int min_tls_version;   /* Minimum TLS version: 12=1.2, 13=1.3 (default: 13) */
    char *cert_pin;        /* Certificate pin (sha256//base64 format, optional) */
} llng_client_config_t;

/* Client handle */
typedef struct llng_client llng_client_t;

/*
 * Initialize a new LLNG client
 * Returns NULL on failure
 */
llng_client_t *llng_client_init(const llng_client_config_t *config);

/*
 * Destroy client and free resources
 */
void llng_client_destroy(llng_client_t *client);

/*
 * Verify and consume a one-time PAM user token via /pam/verify
 * The token is destroyed after successful verification (single-use).
 * Requires server_token to be set in config.
 * Returns 0 on success, -1 on error
 */
int llng_verify_token(llng_client_t *client,
                      const char *user_token,
                      llng_response_t *response);

/*
 * Introspect an access token via /oauth2/introspect
 * DEPRECATED for user tokens - use llng_verify_token instead.
 * Still useful for server token introspection.
 * Returns 0 on success, -1 on error
 */
int llng_introspect_token(llng_client_t *client,
                          const char *token,
                          llng_response_t *response);

/*
 * Check user authorization via /pam/authorize
 * Returns 0 on success, -1 on error
 */
int llng_authorize_user(llng_client_t *client,
                        const char *user,
                        const char *host,
                        const char *service,
                        llng_response_t *response);

/*
 * Check user authorization with SSH certificate info via /pam/authorize
 * Same as llng_authorize_user but includes SSH certificate details
 * Returns 0 on success, -1 on error
 */
int llng_authorize_user_with_cert(llng_client_t *client,
                                   const char *user,
                                   const char *host,
                                   const char *service,
                                   const llng_ssh_cert_info_t *ssh_cert,
                                   llng_response_t *response);

/*
 * Free SSH certificate info structure contents
 */
void llng_ssh_cert_info_free(llng_ssh_cert_info_t *cert_info);

/*
 * Initialize response structure to safe defaults (all zeros)
 */
void llng_response_init(llng_response_t *response);

/*
 * Free response structure contents
 */
void llng_response_free(llng_response_t *response);

/*
 * Get last error message
 */
const char *llng_client_error(llng_client_t *client);

#endif /* LLNG_CLIENT_H */
