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
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <ctype.h>
#include <sys/file.h>
#include <fcntl.h>

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

/* Time constants */
#define SECONDS_PER_DAY 86400

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

/* Forward declaration */
static void cleanup_data(pam_handle_t *pamh, void *data, int error_status);

/*
 * Check if a group exists by reading /etc/group directly.
 * This avoids NSS calls which could cause issues.
 * Returns 1 if group exists, 0 otherwise.
 */
static int group_exists_locally(gid_t gid)
{
    FILE *f = fopen("/etc/group", "r");
    if (!f) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* Format: groupname:x:gid:members */
        char *p = line;
        int field = 0;
        char *start = p;

        while (*p && field < 3) {
            if (*p == ':') {
                if (field == 2) {
                    *p = '\0';
                    gid_t local_gid = (gid_t)atoi(start);
                    if (local_gid == gid) {
                        fclose(f);
                        return 1;
                    }
                }
                field++;
                start = p + 1;
            }
            p++;
        }
    }

    fclose(f);
    return 0;
}

/*
 * Invalidate nscd cache for passwd and group databases.
 * This ensures that subsequent NSS lookups see the newly created user.
 */
static void invalidate_nscd_cache(void)
{
    /* Try to invalidate nscd cache - ignore errors if nscd isn't running */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: run nscd --invalidate */
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        execl("/usr/sbin/nscd", "nscd", "--invalidate", "passwd", NULL);
        _exit(0);  /* Exit silently if nscd not found */
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }

    /* Also invalidate group cache */
    pid = fork();
    if (pid == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        execl("/usr/sbin/nscd", "nscd", "--invalidate", "group", NULL);
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

/*
 * Validate username for safe use in /etc/passwd
 * Returns 1 if valid, 0 if invalid
 */
static int validate_username(const char *user)
{
    if (!user || !*user) return 0;

    size_t len = strlen(user);
    /* POSIX username max is typically 32, be conservative */
    if (len > 32 || len == 0) return 0;

    /* First character must be lowercase letter or underscore */
    if (!islower((unsigned char)user[0]) && user[0] != '_') return 0;

    for (size_t i = 0; i < len; i++) {
        char c = user[i];
        /* Allow lowercase, digits, underscore, hyphen */
        if (!islower((unsigned char)c) && !isdigit((unsigned char)c) &&
            c != '_' && c != '-') {
            return 0;
        }
        /* Reject dangerous characters for /etc/passwd */
        if (c == ':' || c == '\n' || c == '\r' || c == '\0' || c == '/') {
            return 0;
        }
    }

    return 1;
}

/* Cleanup function for pam_set_data (strings) */
static void cleanup_string(pam_handle_t *pamh, void *data, int error_status)
{
    (void)pamh;
    (void)error_status;
    free(data);
}

/* Cleanup function for pam_set_data (module data) */
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

/* Check if user exists in local /etc/passwd file (not via NSS) */
static int user_exists_locally(const char *username)
{
    FILE *f = fopen("/etc/passwd", "r");
    if (!f) return 0;

    char line[1024];
    size_t ulen = strlen(username);

    while (fgets(line, sizeof(line), f)) {
        /* Format: username:x:uid:gid:gecos:home:shell */
        /* Check if line starts with "username:" */
        if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
            fclose(f);
            return 1;  /* User found */
        }
    }

    fclose(f);
    return 0;  /* User not found */
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

    /*
     * Build rate limiter key once for reuse throughout the function.
     * The key is declared outside the if block intentionally because it's
     * reused in multiple rate_limiter calls (check, record_failure, reset).
     */
    char rate_key[256];
    if (data->rate_limiter) {
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
        rate_limiter_reset(data->rate_limiter, rate_key);
    }

    /* Store user attributes for pam_sm_open_session (user creation) */
    if (response.gecos) {
        char *gecos_copy = strdup(response.gecos);
        if (gecos_copy) {
            pam_set_data(pamh, "llng_gecos", gecos_copy, cleanup_string);
        }
    }
    if (response.shell) {
        char *shell_copy = strdup(response.shell);
        if (shell_copy) {
            pam_set_data(pamh, "llng_shell", shell_copy, cleanup_string);
        }
    }
    if (response.home) {
        char *home_copy = strdup(response.home);
        if (home_copy) {
            pam_set_data(pamh, "llng_home", home_copy, cleanup_string);
        }
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

/*
 * Create Unix user account by writing directly to /etc/passwd and /etc/shadow
 * This bypasses NSS checks that would otherwise fail because libnss_llng
 * reports the user as already existing.
 *
 * Uses file locking to prevent race conditions with concurrent logins.
 * Returns 0 on success, -1 on error
 */
static int create_unix_user(pam_handle_t *pamh,
                            const char *user,
                            const pam_llng_config_t *config,
                            const char *gecos,
                            const char *shell,
                            const char *home)
{
    uid_t uid = 0;
    gid_t gid = 0;
    char home_dir[512];
    const char *user_shell;
    const char *user_gecos;
    int passwd_fd = -1;
    int shadow_fd = -1;
    FILE *passwd_file = NULL;
    FILE *shadow_file = NULL;
    int ret = -1;

    /* Validate username before any file operations */
    if (!validate_username(user)) {
        LLNG_LOG_ERR(pamh, "Invalid username for user creation: %s", user);
        return -1;
    }

    /* Get UID/GID from NSS (libnss_llng) */
    struct passwd *nss_pw = getpwnam(user);
    if (nss_pw) {
        uid = nss_pw->pw_uid;
        gid = nss_pw->pw_gid;
    } else {
        LLNG_LOG_ERR(pamh, "Cannot get user info from NSS for %s", user);
        return -1;
    }

    /* Verify that the primary group exists */
    if (!group_exists_locally(gid)) {
        LLNG_LOG_ERR(pamh, "Primary group %d does not exist for user %s", gid, user);
        return -1;
    }

    /* Determine and validate home directory */
    if (home && *home && config_validate_home(home, config->approved_home_prefixes) == 0) {
        snprintf(home_dir, sizeof(home_dir), "%s", home);
    } else {
        /* Use default home base if provided path is invalid or empty */
        if (home && *home) {
            LLNG_LOG_WARN(pamh, "Invalid home path '%s' for user %s, using default", home, user);
        }
        if (config->create_user_home_base) {
            snprintf(home_dir, sizeof(home_dir), "%s/%s", config->create_user_home_base, user);
        } else {
            snprintf(home_dir, sizeof(home_dir), "/home/%s", user);
        }
    }

    /* Determine and validate shell */
    user_shell = NULL;
    if (shell && *shell && config_validate_shell(shell, config->approved_shells) == 0) {
        user_shell = shell;
    } else {
        if (shell && *shell) {
            LLNG_LOG_WARN(pamh, "Invalid shell '%s' for user %s, using default", shell, user);
        }
        /* Try config default shell */
        if (config->create_user_shell &&
            config_validate_shell(config->create_user_shell, config->approved_shells) == 0) {
            user_shell = config->create_user_shell;
        }
    }
    /* Final fallback to /bin/bash */
    if (!user_shell || !*user_shell) {
        user_shell = "/bin/bash";
    }

    /* Determine GECOS */
    user_gecos = gecos;
    if (!user_gecos || !*user_gecos) {
        user_gecos = "";
    }

    LLNG_LOG_INFO(pamh, "Creating Unix user: %s (uid=%d, gid=%d)", user, uid, gid);

    /*
     * Open and lock both files before writing to ensure atomicity.
     * This prevents race conditions when multiple sessions try to
     * create the same user simultaneously.
     */
    passwd_fd = open("/etc/passwd", O_RDWR | O_APPEND);
    if (passwd_fd < 0) {
        LLNG_LOG_ERR(pamh, "Cannot open /etc/passwd: %s", strerror(errno));
        goto cleanup;
    }

    shadow_fd = open("/etc/shadow", O_RDWR | O_APPEND);
    if (shadow_fd < 0) {
        LLNG_LOG_ERR(pamh, "Cannot open /etc/shadow: %s", strerror(errno));
        goto cleanup;
    }

    /* Acquire exclusive locks on both files */
    if (flock(passwd_fd, LOCK_EX) < 0) {
        LLNG_LOG_ERR(pamh, "Cannot lock /etc/passwd: %s", strerror(errno));
        goto cleanup;
    }

    if (flock(shadow_fd, LOCK_EX) < 0) {
        LLNG_LOG_ERR(pamh, "Cannot lock /etc/shadow: %s", strerror(errno));
        goto cleanup;
    }

    /* Re-check if user exists after acquiring locks (TOCTOU protection) */
    if (user_exists_locally(user)) {
        LLNG_LOG_DEBUG(pamh, "User %s was created by another process", user);
        ret = 0;  /* Not an error - user exists now */
        goto cleanup;
    }

    /* Convert file descriptors to FILE* for fprintf */
    passwd_file = fdopen(passwd_fd, "a");
    if (!passwd_file) {
        LLNG_LOG_ERR(pamh, "Cannot fdopen /etc/passwd: %s", strerror(errno));
        goto cleanup;
    }
    passwd_fd = -1;  /* fdopen took ownership */

    shadow_file = fdopen(shadow_fd, "a");
    if (!shadow_file) {
        LLNG_LOG_ERR(pamh, "Cannot fdopen /etc/shadow: %s", strerror(errno));
        goto cleanup;
    }
    shadow_fd = -1;  /* fdopen took ownership */

    /* Write to /etc/passwd */
    if (fprintf(passwd_file, "%s:x:%d:%d:%s:%s:%s\n",
                user, uid, gid, user_gecos, home_dir, user_shell) < 0) {
        LLNG_LOG_ERR(pamh, "Cannot write to /etc/passwd: %s", strerror(errno));
        goto cleanup;
    }

    if (fflush(passwd_file) != 0) {
        LLNG_LOG_ERR(pamh, "Cannot flush /etc/passwd: %s", strerror(errno));
        goto cleanup;
    }

    /* Write to /etc/shadow (locked password - login via PAM only) */
    /* Format: username:!:days_since_epoch:0:99999:7::: */
    long days = time(NULL) / SECONDS_PER_DAY;
    if (fprintf(shadow_file, "%s:!:%ld:0:99999:7:::\n", user, days) < 0) {
        LLNG_LOG_ERR(pamh, "Cannot write to /etc/shadow: %s", strerror(errno));
        /* passwd was written but shadow failed - attempt rollback via userdel */
        LLNG_LOG_WARN(pamh, "Attempting rollback of partial user creation");
        pid_t pid = fork();
        if (pid == 0) {
            execl("/usr/sbin/userdel", "userdel", user, NULL);
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
        goto cleanup;
    }

    if (fflush(shadow_file) != 0) {
        LLNG_LOG_ERR(pamh, "Cannot flush /etc/shadow: %s", strerror(errno));
        goto cleanup;
    }

    /* User created successfully in passwd/shadow */
    ret = 0;

    /* Create home directory with secure permissions (0700) */
    if (mkdir(home_dir, 0700) != 0 && errno != EEXIST) {
        LLNG_LOG_WARN(pamh, "Cannot create home directory %s: %s", home_dir, strerror(errno));
        /* Continue anyway - user is created */
    } else {
        /* Copy skeleton files if configured and validated */
        if (config->create_user_skel && access(config->create_user_skel, R_OK) == 0) {
            /* Validate skel path for security */
            if (config_validate_skel(config->create_user_skel) == 0) {
                pid_t pid = fork();
                if (pid == 0) {
                    /* Child: copy skel contents (-P preserves symlinks, doesn't follow them) */
                    execl("/bin/cp", "cp", "-rTP", config->create_user_skel, home_dir, NULL);
                    _exit(127);
                } else if (pid > 0) {
                    int status;
                    waitpid(pid, &status, 0);
                }
            } else {
                LLNG_LOG_WARN(pamh, "Skel path validation failed for %s, skipping",
                              config->create_user_skel);
            }
        }

        /* Set ownership recursively using chown -R uid:gid */
        char owner_str[64];
        snprintf(owner_str, sizeof(owner_str), "%d:%d", uid, gid);
        pid_t pid = fork();
        if (pid == 0) {
            execl("/bin/chown", "chown", "-R", owner_str, home_dir, NULL);
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
    }

    LLNG_LOG_INFO(pamh, "Successfully created Unix user: %s", user);

    /* Invalidate nscd cache so the new user is visible immediately */
    invalidate_nscd_cache();

cleanup:
    /* Close files (also releases locks) */
    if (passwd_file) fclose(passwd_file);
    if (shadow_file) fclose(shadow_file);
    if (passwd_fd >= 0) close(passwd_fd);
    if (shadow_fd >= 0) close(shadow_fd);

    return ret;
}

/*
 * pam_sm_open_session - Open session (create user if needed)
 *
 * If create_user is enabled and the user doesn't exist in /etc/passwd,
 * this function creates the Unix account.
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                    int flags,
                                    int argc,
                                    const char **argv)
{
    (void)flags;

    const char *user = NULL;
    int ret;

    /* Get username */
    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS || !user || !*user) {
        LLNG_LOG_ERR(pamh, "Failed to get username for session");
        return PAM_SESSION_ERR;
    }

    /* Initialize module */
    pam_llng_data_t *data = get_module_data(pamh, argc, argv);
    if (!data) {
        return PAM_SESSION_ERR;
    }

    /* Check if user creation is enabled */
    if (!data->config.create_user_enabled) {
        LLNG_LOG_DEBUG(pamh, "User creation disabled, skipping for %s", user);
        return PAM_SUCCESS;
    }

    /* Check if user already exists in local /etc/passwd (not via NSS)
     * This is important because libnss_llng may report the user as existing
     * even though no local Unix account has been created yet. */
    if (user_exists_locally(user)) {
        LLNG_LOG_DEBUG(pamh, "User %s already exists locally", user);
        return PAM_SUCCESS;
    }

    /* User doesn't exist - get user info from PAM data if available */
    const char *gecos = NULL;
    const char *shell = NULL;
    const char *home = NULL;

    /* Try to get LLNG user info stored during authentication */
    const void *llng_gecos = NULL;
    const void *llng_shell = NULL;
    const void *llng_home = NULL;

    pam_get_data(pamh, "llng_gecos", &llng_gecos);
    pam_get_data(pamh, "llng_shell", &llng_shell);
    pam_get_data(pamh, "llng_home", &llng_home);

    gecos = (const char *)llng_gecos;
    shell = (const char *)llng_shell;
    home = (const char *)llng_home;

    /* Create the user */
    LLNG_LOG_INFO(pamh, "User %s does not exist, creating account", user);

    if (create_unix_user(pamh, user, &data->config, gecos, shell, home) != 0) {
        LLNG_LOG_ERR(pamh, "Failed to create Unix user: %s", user);
        return PAM_SESSION_ERR;
    }

    /* Log success to audit */
    if (data->audit) {
        audit_event_t audit_event;
        audit_event_init(&audit_event, AUDIT_USER_CREATED);
        audit_event.user = user;
        audit_event.result_code = PAM_SUCCESS;
        audit_event.reason = "Unix account created";
        audit_event_set_end_time(&audit_event);
        audit_log_event(data->audit, &audit_event);
    }

    return PAM_SUCCESS;
}

/*
 * pam_sm_close_session - Close session
 *
 * If cache_invalidate_on_logout is enabled, invalidates the user's
 * cached tokens to ensure re-authentication on next login.
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                     int flags,
                                     int argc,
                                     const char **argv)
{
    (void)flags;

    const char *user = NULL;
    int ret;

    /* Get username */
    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS || !user || !*user) {
        /* Can't get user, nothing to invalidate */
        return PAM_SUCCESS;
    }

    /* Initialize module to access cache */
    pam_llng_data_t *data = get_module_data(pamh, argc, argv);
    if (!data) {
        return PAM_SUCCESS;  /* No config, nothing to do */
    }

    /* Invalidate cache for this user if configured */
    if (data->config.cache_invalidate_on_logout && data->cache) {
        LLNG_LOG_DEBUG(pamh, "Invalidating cache for user %s on session close", user);
        cache_invalidate_user(data->cache, user);
    }

    return PAM_SUCCESS;
}
