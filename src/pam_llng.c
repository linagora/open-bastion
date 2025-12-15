/*
 * pam_llng.c - PAM module for LemonLDAP::NG authentication
 *
 * This module provides:
 * - pam_sm_authenticate: Validates user password (LLNG access token)
 * - pam_sm_acct_mgmt: Checks user authorization via LLNG server
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config.h"
#include "llng_client.h"
#include "audit_log.h"
#include "rate_limiter.h"
#ifdef ENABLE_CACHE
#include "token_cache.h"
#endif

/* Default configuration file */
#define DEFAULT_CONFIG_FILE "/etc/security/pam_llng.conf"

/* Module data key for storing client between calls */
#define PAM_LLNG_DATA "pam_llng_data"

/* Internal data structure */
typedef struct {
    pam_llng_config_t config;
    llng_client_t *client;
    audit_context_t *audit;
    rate_limiter_t *rate_limiter;
#ifdef ENABLE_CACHE
    token_cache_t *cache;
#endif
} pam_llng_data_t;

/* Logging macros - prefixed to avoid conflict with syslog constants */
#define LLNG_LOG_ERR(handle, fmt, ...) \
    pam_syslog(handle, LOG_ERR, fmt, ##__VA_ARGS__)
#define LLNG_LOG_WARN(handle, fmt, ...) \
    pam_syslog(handle, LOG_WARNING, fmt, ##__VA_ARGS__)
#define LLNG_LOG_INFO(handle, fmt, ...) \
    pam_syslog(handle, LOG_INFO, fmt, ##__VA_ARGS__)
#define LLNG_LOG_DEBUG(handle, fmt, ...) \
    pam_syslog(handle, LOG_DEBUG, fmt, ##__VA_ARGS__)

/* Cleanup function for pam_set_data */
static void cleanup_data(pam_handle_t *pamh, void *data, int error_status)
{
    (void)pamh;
    (void)error_status;

    pam_llng_data_t *llng_data = (pam_llng_data_t *)data;
    if (llng_data) {
#ifdef ENABLE_CACHE
        if (llng_data->cache) {
            cache_destroy(llng_data->cache);
        }
#endif
        if (llng_data->client) {
            llng_client_destroy(llng_data->client);
        }
        if (llng_data->audit) {
            audit_destroy(llng_data->audit);
        }
        if (llng_data->rate_limiter) {
            rate_limiter_destroy(llng_data->rate_limiter);
        }
        config_free(&llng_data->config);
        free(llng_data);
    }
}

/* Initialize module data */
static pam_llng_data_t *init_module_data(pam_handle_t *pamh,
                                         int argc,
                                         const char **argv)
{
    pam_llng_data_t *data = calloc(1, sizeof(pam_llng_data_t));
    if (!data) {
        LLNG_LOG_ERR(pamh, "Failed to allocate memory");
        return NULL;
    }

    /* Initialize config with defaults */
    config_init(&data->config);

    /* Find config file from arguments or use default */
    const char *config_file = DEFAULT_CONFIG_FILE;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "conf=", 5) == 0) {
            config_file = argv[i] + 5;
            break;
        }
    }

    /* Load configuration file */
    int config_result = config_load(config_file, &data->config);
    if (config_result == -2) {
        LLNG_LOG_ERR(pamh, "Security error: config file %s is not owned by root", config_file);
        goto error;
    }
    if (config_result == -3) {
        LLNG_LOG_ERR(pamh, "Security error: config file %s has insecure permissions (must be 0600 or 0700)", config_file);
        goto error;
    }
    if (config_result != 0) {
        LLNG_LOG_WARN(pamh, "Failed to load config file %s, using defaults", config_file);
    }

    /* Override with PAM arguments */
    if (config_parse_args(argc, argv, &data->config) != 0) {
        LLNG_LOG_ERR(pamh, "Failed to parse PAM arguments");
        goto error;
    }

    /* Validate configuration */
    int validate_result = config_validate(&data->config);
    if (validate_result == -4) {
        LLNG_LOG_ERR(pamh, "Security error: portal_url must use HTTPS (use verify_ssl=false to disable)");
        goto error;
    }
    if (validate_result != 0) {
        LLNG_LOG_ERR(pamh, "Invalid configuration");
        goto error;
    }

    /* Initialize LLNG client */
    llng_client_config_t client_config = {
        .portal_url = data->config.portal_url,
        .client_id = data->config.client_id,
        .client_secret = data->config.client_secret,
        .server_token = NULL,  /* Will be loaded from file */
        .server_group = data->config.server_group,
        .timeout = data->config.timeout,
        .verify_ssl = data->config.verify_ssl,
        .ca_cert = data->config.ca_cert,
    };

    /* Load server token from file if specified */
    if (data->config.server_token_file) {
        /* Security check: verify token file permissions */
        struct stat st;
        if (stat(data->config.server_token_file, &st) != 0) {
            LLNG_LOG_ERR(pamh, "Security error: cannot stat token file %s",
                    data->config.server_token_file);
            goto error;
        }
        if (st.st_uid != 0) {
            LLNG_LOG_ERR(pamh, "Security error: token file %s is not owned by root",
                    data->config.server_token_file);
            goto error;
        }
        if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
            LLNG_LOG_ERR(pamh, "Security error: token file %s has insecure permissions",
                    data->config.server_token_file);
            goto error;
        }

        FILE *f = fopen(data->config.server_token_file, "r");
        if (f) {
            char token_buf[4096];
            if (fgets(token_buf, sizeof(token_buf), f)) {
                /* Remove trailing newline */
                size_t len = strlen(token_buf);
                if (len > 0 && token_buf[len-1] == '\n') {
                    token_buf[len-1] = '\0';
                }
                client_config.server_token = strdup(token_buf);
                /* Clear the buffer containing the token */
                explicit_bzero(token_buf, sizeof(token_buf));
            }
            fclose(f);
        } else {
            LLNG_LOG_WARN(pamh, "Failed to read server token file: %s",
                     data->config.server_token_file);
        }
    }

    data->client = llng_client_init(&client_config);
    free((void *)client_config.server_token);

    if (!data->client) {
        LLNG_LOG_ERR(pamh, "Failed to initialize LLNG client");
        goto error;
    }

#ifdef ENABLE_CACHE
    /* Initialize cache if enabled */
    if (data->config.cache_enabled) {
        data->cache = cache_init(data->config.cache_dir,
                                 data->config.cache_ttl);
        if (!data->cache) {
            LLNG_LOG_WARN(pamh, "Failed to initialize cache, continuing without");
        }
    }
#endif

    /* Initialize audit logging */
    if (data->config.audit_enabled) {
        audit_config_t audit_cfg = {
            .enabled = true,
            .log_file = data->config.audit_log_file,
            .log_to_syslog = data->config.audit_to_syslog,
            .level = data->config.audit_level
        };
        data->audit = audit_init(&audit_cfg);
        if (!data->audit) {
            LLNG_LOG_WARN(pamh, "Failed to initialize audit logging, continuing without");
        }
    }

    /* Initialize rate limiter */
    if (data->config.rate_limit_enabled) {
        rate_limiter_config_t rl_cfg = {
            .enabled = true,
            .state_dir = data->config.rate_limit_state_dir,
            .max_attempts = data->config.rate_limit_max_attempts,
            .initial_lockout_sec = data->config.rate_limit_initial_lockout,
            .max_lockout_sec = data->config.rate_limit_max_lockout,
            .backoff_multiplier = data->config.rate_limit_backoff_mult
        };
        data->rate_limiter = rate_limiter_init(&rl_cfg);
        if (!data->rate_limiter) {
            LLNG_LOG_WARN(pamh, "Failed to initialize rate limiter, continuing without");
        }
    }

    /* Store data for later calls */
    if (pam_set_data(pamh, PAM_LLNG_DATA, data, cleanup_data) != PAM_SUCCESS) {
        LLNG_LOG_ERR(pamh, "Failed to store module data");
        goto error;
    }

    return data;

error:
    cleanup_data(pamh, data, 0);
    return NULL;
}

/* Get or create module data */
static pam_llng_data_t *get_module_data(pam_handle_t *pamh,
                                        int argc,
                                        const char **argv)
{
    pam_llng_data_t *data = NULL;

    if (pam_get_data(pamh, PAM_LLNG_DATA, (const void **)&data) == PAM_SUCCESS && data) {
        return data;
    }

    return init_module_data(pamh, argc, argv);
}

/* Get client IP from PAM environment or rhost */
static const char *get_client_ip(pam_handle_t *pamh)
{
    const char *rhost = NULL;
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost) {
        return rhost;
    }
    return "local";
}

/* Get TTY from PAM */
static const char *get_tty(pam_handle_t *pamh)
{
    const char *tty = NULL;
    if (pam_get_item(pamh, PAM_TTY, (const void **)&tty) == PAM_SUCCESS && tty) {
        return tty;
    }
    return NULL;
}

/*
 * pam_sm_authenticate - Authenticate user with LLNG token
 *
 * The password provided by the user is expected to be an LLNG access token
 * generated via the /pam endpoint.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
    (void)flags;

    const char *user = NULL;
    const char *password = NULL;
    const char *service = NULL;
    const char *client_ip = NULL;
    const char *tty = NULL;
    int ret;
    int pam_result = PAM_AUTH_ERR;
    audit_event_t audit_event;
    bool audit_initialized = false;

    /* Get username */
    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS || !user || !*user) {
        LLNG_LOG_ERR(pamh, "Failed to get username");
        return PAM_USER_UNKNOWN;
    }

    LLNG_LOG_DEBUG(pamh, "Authenticating user: %s", user);

    /* Initialize module */
    pam_llng_data_t *data = get_module_data(pamh, argc, argv);
    if (!data) {
        return PAM_SERVICE_ERR;
    }

    /* Get context information for audit and rate limiting */
    client_ip = get_client_ip(pamh);
    tty = get_tty(pamh);
    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS) {
        service = "unknown";
    }

    /* Initialize audit event */
    if (data->audit) {
        audit_event_init(&audit_event, AUDIT_AUTH_FAILURE);  /* Default to failure */
        audit_event.user = user;
        audit_event.service = service;
        audit_event.client_ip = client_ip;
        audit_event.tty = tty;
        audit_initialized = true;
    }

    /* Check rate limiting before attempting authentication */
    if (data->rate_limiter) {
        char rate_key[256];
        rate_limiter_build_key(user, client_ip, rate_key, sizeof(rate_key));

        int lockout_remaining = rate_limiter_check(data->rate_limiter, rate_key);
        if (lockout_remaining > 0) {
            LLNG_LOG_WARN(pamh, "User %s is rate limited for %d seconds", user, lockout_remaining);

            if (audit_initialized) {
                audit_event.event_type = AUDIT_RATE_LIMITED;
                audit_event.result_code = PAM_AUTH_ERR;
                char reason[128];
                snprintf(reason, sizeof(reason), "Rate limited for %d seconds", lockout_remaining);
                audit_event.reason = reason;
                audit_event_set_end_time(&audit_event);
                audit_log_event(data->audit, &audit_event);
            }

            return PAM_AUTH_ERR;
        }
    }

    /* If authorize_only mode, skip password check */
    if (data->config.authorize_only) {
        LLNG_LOG_DEBUG(pamh, "authorize_only mode, skipping password check");
        return PAM_SUCCESS;
    }

    /* Get password (the LLNG token) */
    ret = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (ret != PAM_SUCCESS || !password || !*password) {
        LLNG_LOG_DEBUG(pamh, "No password provided for user %s", user);

        /* Record failure for rate limiting */
        if (data->rate_limiter) {
            char rate_key[256];
            rate_limiter_build_key(user, client_ip, rate_key, sizeof(rate_key));
            rate_limiter_record_failure(data->rate_limiter, rate_key);
        }

        if (audit_initialized) {
            audit_event.result_code = PAM_AUTH_ERR;
            audit_event.reason = "No password provided";
            audit_event_set_end_time(&audit_event);
            audit_log_event(data->audit, &audit_event);
        }

        return PAM_AUTH_ERR;
    }

    /*
     * Verify the one-time PAM token via /pam/verify
     * The token is destroyed after successful verification (single-use).
     * Note: Cache is not used for one-time tokens.
     */
    llng_response_t response = {0};
    if (llng_verify_token(data->client, password, &response) != 0) {
        LLNG_LOG_ERR(pamh, "Token verification failed: %s",
                llng_client_error(data->client));

        if (audit_initialized) {
            audit_event.event_type = AUDIT_SERVER_ERROR;
            audit_event.result_code = PAM_AUTHINFO_UNAVAIL;
            audit_event.reason = llng_client_error(data->client);
            audit_event_set_end_time(&audit_event);
            audit_log_event(data->audit, &audit_event);
        }

        return PAM_AUTHINFO_UNAVAIL;
    }

    /* Check if token is valid (active field from response) */
    if (!response.active) {
        LLNG_LOG_INFO(pamh, "Token is not valid for user %s: %s", user,
                 response.reason ? response.reason : "unknown reason");
        pam_result = PAM_AUTH_ERR;

        if (data->rate_limiter) {
            char rate_key[256];
            rate_limiter_build_key(user, client_ip, rate_key, sizeof(rate_key));
            rate_limiter_record_failure(data->rate_limiter, rate_key);
        }

        if (audit_initialized) {
            audit_event.result_code = PAM_AUTH_ERR;
            audit_event.reason = response.reason ? response.reason : "Token not valid";
            audit_event_set_end_time(&audit_event);
            audit_log_event(data->audit, &audit_event);
        }

        llng_response_free(&response);
        return pam_result;
    }

    /* Verify user matches */
    if (!response.user || strcmp(response.user, user) != 0) {
        LLNG_LOG_WARN(pamh, "Token user mismatch: expected %s, got %s",
                 user, response.user ? response.user : "(null)");
        pam_result = PAM_AUTH_ERR;

        if (data->rate_limiter) {
            char rate_key[256];
            rate_limiter_build_key(user, client_ip, rate_key, sizeof(rate_key));
            rate_limiter_record_failure(data->rate_limiter, rate_key);
        }

        if (audit_initialized) {
            audit_event.event_type = AUDIT_SECURITY_ERROR;
            audit_event.result_code = PAM_AUTH_ERR;
            audit_event.reason = "Token user mismatch";
            audit_event_set_end_time(&audit_event);
            audit_log_event(data->audit, &audit_event);
        }

        llng_response_free(&response);
        return pam_result;
    }

    /* Success - reset rate limiter */
    if (data->rate_limiter) {
        char rate_key[256];
        rate_limiter_build_key(user, client_ip, rate_key, sizeof(rate_key));
        rate_limiter_reset(data->rate_limiter, rate_key);
    }

    /* Log success */
    if (audit_initialized) {
        audit_event.event_type = AUDIT_AUTH_SUCCESS;
        audit_event.result_code = PAM_SUCCESS;
        audit_event_set_end_time(&audit_event);
        audit_log_event(data->audit, &audit_event);
    }

    LLNG_LOG_INFO(pamh, "User %s authenticated successfully via LLNG token", user);
    llng_response_free(&response);
    return PAM_SUCCESS;
}

/*
 * pam_sm_setcred - Set credentials (not used)
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                              int flags,
                              int argc,
                              const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

/*
 * pam_sm_acct_mgmt - Check if user is authorized to access this server
 *
 * This function calls the /pam/authorize endpoint to verify the user
 * has permission to access this server, based on server groups.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv)
{
    (void)flags;

    const char *user = NULL;
    const char *client_ip = NULL;
    const char *tty = NULL;
    int ret;
    audit_event_t audit_event;
    bool audit_initialized = false;

    /* Get username */
    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS || !user || !*user) {
        LLNG_LOG_ERR(pamh, "Failed to get username");
        return PAM_USER_UNKNOWN;
    }

    LLNG_LOG_DEBUG(pamh, "Checking authorization for user: %s", user);

    /* Initialize module */
    pam_llng_data_t *data = get_module_data(pamh, argc, argv);
    if (!data) {
        return PAM_SERVICE_ERR;
    }

    /* Get context information */
    client_ip = get_client_ip(pamh);
    tty = get_tty(pamh);

    /* Get hostname */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "unknown", sizeof(hostname));
    }

    /* Get service name */
    const char *service = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS || !service) {
        service = "unknown";
    }

    /* Initialize audit event */
    if (data->audit) {
        audit_event_init(&audit_event, AUDIT_AUTHZ_DENIED);  /* Default to denied */
        audit_event.user = user;
        audit_event.service = service;
        audit_event.client_ip = client_ip;
        audit_event.tty = tty;
        audit_initialized = true;
    }

    /* Call authorization endpoint */
    llng_response_t response = {0};
    if (llng_authorize_user(data->client, user, hostname, service, &response) != 0) {
        LLNG_LOG_ERR(pamh, "Authorization check failed: %s",
                llng_client_error(data->client));

        if (audit_initialized) {
            audit_event.event_type = AUDIT_SERVER_ERROR;
            audit_event.result_code = PAM_AUTHINFO_UNAVAIL;
            audit_event.reason = llng_client_error(data->client);
            audit_event_set_end_time(&audit_event);
            audit_log_event(data->audit, &audit_event);
        }

        return PAM_AUTHINFO_UNAVAIL;
    }

    /* Check result */
    if (!response.authorized) {
        LLNG_LOG_INFO(pamh, "User %s not authorized: %s", user,
                 response.reason ? response.reason : "no reason given");

        if (audit_initialized) {
            audit_event.result_code = PAM_PERM_DENIED;
            audit_event.reason = response.reason ? response.reason : "Not authorized";
            audit_event_set_end_time(&audit_event);
            audit_log_event(data->audit, &audit_event);
        }

        llng_response_free(&response);
        return PAM_PERM_DENIED;
    }

    /* Success */
    if (audit_initialized) {
        audit_event.event_type = AUDIT_AUTHZ_SUCCESS;
        audit_event.result_code = PAM_SUCCESS;
        audit_event_set_end_time(&audit_event);
        audit_log_event(data->audit, &audit_event);
    }

    LLNG_LOG_INFO(pamh, "User %s authorized for access", user);
    llng_response_free(&response);
    return PAM_SUCCESS;
}
