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
 * Free response structure contents
 */
void llng_response_free(llng_response_t *response);

/*
 * Get last error message
 */
const char *llng_client_error(llng_client_t *client);

#endif /* LLNG_CLIENT_H */
