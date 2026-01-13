/*
 * pam_llng.c - PAM module for LemonLDAP::NG authentication
 *
 * This module provides:
 * - pam_sm_authenticate: Validates user password (LLNG access token)
 * - pam_sm_acct_mgmt: Checks user authorization via LLNG server
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION

/* Mark PAM entry points as visible when using -fvisibility=hidden */
#define PAM_VISIBLE __attribute__((visibility("default")))

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
#include "auth_cache.h"
#include "token_manager.h"
#include "bastion_jwt.h"
#include "jwks_cache.h"
#ifdef ENABLE_CACHE
#include "token_cache.h"
#endif

/* Default configuration file */
#define DEFAULT_CONFIG_FILE "/etc/security/pam_llng.conf"

/* Module data key for storing client between calls */
#define PAM_LLNG_DATA "pam_llng_data"

/* Time constants */
#define SECONDS_PER_DAY 86400
#define DEFAULT_OFFLINE_CACHE_TTL 86400  /* Default 24 hours for offline cache */

/* Internal data structure */
typedef struct {
    pam_llng_config_t config;
    llng_client_t *client;
    audit_context_t *audit;
    rate_limiter_t *rate_limiter;
    auth_cache_t *auth_cache;  /* Authorization cache for offline mode */
    jwks_cache_t *jwks_cache;  /* JWKS cache for bastion JWT verification */
    bastion_jwt_verifier_t *bastion_jwt_verifier;  /* Bastion JWT verifier */
#ifdef ENABLE_CACHE
    token_cache_t *cache;
#endif
    /* Security: Store token file metadata for periodic re-verification (#46) */
    ino_t token_file_inode;
    time_t token_file_mtime;
    time_t last_token_check;
} pam_llng_data_t;

/* How often to re-verify token file permissions (in seconds) */
#define TOKEN_RECHECK_INTERVAL 300  /* 5 minutes */

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
 * Security: Re-verify token file permissions periodically (fixes #46)
 * Returns 0 if OK, -1 if security violation detected
 */
static int verify_token_file_security(pam_handle_t *pamh, pam_llng_data_t *data)
{
    if (!data || !data->config.server_token_file) {
        return 0;  /* No token file configured, nothing to verify */
    }

    time_t now = time(NULL);

    /* Only check periodically to avoid performance impact.
     * Handle clock adjustments: if time() fails or clock moved backward,
     * force a recheck to be safe. */
    if (data->last_token_check > 0 &&
        now != (time_t)-1 &&
        now >= data->last_token_check &&
        (now - data->last_token_check) < TOKEN_RECHECK_INTERVAL) {
        return 0;  /* Recently checked, skip */
    }

    /* Re-verify token file security */
    int token_fd = open(data->config.server_token_file, O_RDONLY | O_NOFOLLOW);
    if (token_fd < 0) {
        LLNG_LOG_ERR(pamh, "Security: token file %s no longer accessible",
                data->config.server_token_file);
        return -1;
    }

    struct stat st;
    if (fstat(token_fd, &st) != 0) {
        LLNG_LOG_ERR(pamh, "Security: cannot stat token file %s",
                data->config.server_token_file);
        close(token_fd);
        return -1;
    }
    close(token_fd);

    /* Check if file was replaced (different inode) */
    if (data->token_file_inode != 0 && st.st_ino != data->token_file_inode) {
        LLNG_LOG_ERR(pamh, "Security: token file %s was replaced (inode changed)",
                data->config.server_token_file);
        return -1;
    }

    /* Check if file was modified */
    if (data->token_file_mtime != 0 && st.st_mtime != data->token_file_mtime) {
        LLNG_LOG_WARN(pamh, "Security: token file %s was modified since startup",
                data->config.server_token_file);
        /* Update mtime but continue - modification alone is not a security violation */
        data->token_file_mtime = st.st_mtime;
    }

    /* Re-verify ownership */
    if (st.st_uid != 0) {
        LLNG_LOG_ERR(pamh, "Security: token file %s ownership changed (not root)",
                data->config.server_token_file);
        return -1;
    }

    /* Re-verify permissions */
    if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
        LLNG_LOG_ERR(pamh, "Security: token file %s permissions changed (too permissive)",
                data->config.server_token_file);
        return -1;
    }

    /* Update last check time */
    data->last_token_check = now;

    return 0;
}

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
                    char *endptr;
                    errno = 0;
                    unsigned long parsed_gid = strtoul(start, &endptr, 10);
                    if (errno != 0 || endptr == start || *endptr != '\0' ||
                        parsed_gid > (unsigned long)((gid_t)-1)) {
                        /* Invalid GID format, skip this line */
                        break;
                    }
                    gid_t local_gid = (gid_t)parsed_gid;
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

/*
 * Sanitize GECOS field to prevent /etc/passwd corruption.
 * Replaces dangerous characters (:, \n, \r, control chars) with spaces.
 * Returns a newly allocated sanitized string (caller must free).
 */
static char *sanitize_gecos(const char *gecos)
{
    if (!gecos || !*gecos) {
        return strdup("");
    }

    /* Limit GECOS length to prevent oversized /etc/passwd entries */
    #define MAX_GECOS_LENGTH 256
    size_t len = strlen(gecos);
    if (len > MAX_GECOS_LENGTH) {
        len = MAX_GECOS_LENGTH;
    }

    char *sanitized = malloc(len + 1);
    if (!sanitized) {
        return strdup("");
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)gecos[i];
        /* Replace dangerous characters with space */
        if (c == ':' || c == '\n' || c == '\r' || c < 32 || c == 127) {
            sanitized[i] = ' ';
        } else {
            sanitized[i] = gecos[i];
        }
    }
    sanitized[len] = '\0';

    return sanitized;
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
        if (llng_data->auth_cache) {
            auth_cache_destroy(llng_data->auth_cache);
        }
        if (llng_data->bastion_jwt_verifier) {
            bastion_jwt_verifier_destroy(llng_data->bastion_jwt_verifier);
        }
        if (llng_data->jwks_cache) {
            jwks_cache_destroy(llng_data->jwks_cache);
        }
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
        /*
         * Security: open with O_NOFOLLOW to prevent symlink attacks,
         * then check permissions on the opened fd to avoid TOCTOU.
         */
        int token_fd = open(data->config.server_token_file, O_RDONLY | O_NOFOLLOW);
        if (token_fd < 0) {
            if (errno == ELOOP) {
                LLNG_LOG_ERR(pamh, "Security error: token file %s is a symlink",
                        data->config.server_token_file);
            } else {
                LLNG_LOG_ERR(pamh, "Security error: cannot open token file %s: %s",
                        data->config.server_token_file, strerror(errno));
            }
            goto error;
        }

        struct stat st;
        if (fstat(token_fd, &st) != 0) {
            LLNG_LOG_ERR(pamh, "Security error: cannot stat token file %s",
                    data->config.server_token_file);
            close(token_fd);
            goto error;
        }
        if (st.st_uid != 0) {
            LLNG_LOG_ERR(pamh, "Security error: token file %s is not owned by root",
                    data->config.server_token_file);
            close(token_fd);
            goto error;
        }
        if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
            LLNG_LOG_ERR(pamh, "Security error: token file %s has insecure permissions",
                    data->config.server_token_file);
            close(token_fd);
            goto error;
        }
        if (!S_ISREG(st.st_mode)) {
            LLNG_LOG_ERR(pamh, "Security error: token file %s is not a regular file",
                    data->config.server_token_file);
            close(token_fd);
            goto error;
        }

        /* Security checks passed - store metadata for periodic re-verification (#46) */
        data->token_file_inode = st.st_ino;
        data->token_file_mtime = st.st_mtime;
        data->last_token_check = time(NULL);

        close(token_fd);

        /* Use token_manager_load_file which supports both JSON and plain text */
        token_info_t token_info = {0};
        if (token_manager_load_file(data->config.server_token_file, &token_info) == 0
            && token_info.access_token) {
            client_config.server_token = token_info.access_token;
            token_info.access_token = NULL;  /* Transfer ownership */
            /* Securely free remaining sensitive fields */
            token_info_free(&token_info);
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

    /* Initialize authorization cache (for offline mode) */
    if (data->config.auth_cache_enabled) {
        data->auth_cache = auth_cache_init(data->config.auth_cache_dir);
        if (!data->auth_cache) {
            LLNG_LOG_WARN(pamh, "Failed to initialize auth cache, offline mode disabled");
        }
    }

    /* Initialize bastion JWT verification if required */
    if (data->config.bastion_jwt_required && data->config.bastion_jwt_verify_local) {
        /* Build JWKS URL from portal_url if not specified */
        char *jwks_url = data->config.bastion_jwt_jwks_url;
        char jwks_url_buf[512] = {0};
        if (!jwks_url && data->config.portal_url) {
            snprintf(jwks_url_buf, sizeof(jwks_url_buf), "%s/.well-known/jwks.json",
                     data->config.portal_url);
            jwks_url = jwks_url_buf;
        }

        /* Build JWKS cache file path if not specified */
        char *jwks_cache_file = data->config.bastion_jwt_jwks_cache;
        char jwks_cache_buf[256] = {0};
        if (!jwks_cache_file) {
            snprintf(jwks_cache_buf, sizeof(jwks_cache_buf),
                     "%s/jwks.json", data->config.cache_dir ? data->config.cache_dir : "/var/cache/pam_llng");
            jwks_cache_file = jwks_cache_buf;
        }

        /* Initialize JWKS cache */
        if (jwks_url) {
            jwks_cache_config_t jwks_cfg = {
                .jwks_url = jwks_url,
                .cache_file = jwks_cache_file,
                .refresh_interval = data->config.bastion_jwt_cache_ttl,
                .timeout = data->config.timeout,
                .verify_ssl = data->config.verify_ssl,
                .ca_cert = data->config.ca_cert
            };
            data->jwks_cache = jwks_cache_init(&jwks_cfg);
            if (!data->jwks_cache) {
                LLNG_LOG_WARN(pamh, "Failed to initialize JWKS cache for bastion JWT");
            }
        }

        /* Initialize bastion JWT verifier */
        if (data->jwks_cache) {
            /* Use portal_url as issuer if not specified */
            char *issuer = data->config.bastion_jwt_issuer;
            if (!issuer) {
                issuer = data->config.portal_url;
            }

            bastion_jwt_config_t jwt_cfg = {
                .issuer = issuer,
                .audience = "pam:bastion-backend",
                .max_clock_skew = data->config.bastion_jwt_clock_skew,
                .allowed_bastions = data->config.bastion_jwt_allowed_bastions,
                .jwks_cache = data->jwks_cache
            };
            data->bastion_jwt_verifier = bastion_jwt_verifier_init(&jwt_cfg);
            if (!data->bastion_jwt_verifier) {
                LLNG_LOG_WARN(pamh, "Failed to initialize bastion JWT verifier");
            }
        }

        if (data->config.bastion_jwt_required && !data->bastion_jwt_verifier) {
            LLNG_LOG_ERR(pamh, "Bastion JWT verification required but failed to initialize");
            goto error;
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

/*
 * Extract SSH certificate info from PAM environment.
 * SSH sets SSH_USER_AUTH environment variable with certificate details.
 * Format: "publickey <algorithm> <fingerprint>:<key_id>:<serial>:<principals>"
 * Or for OpenSSH 8.5+, multiple methods comma-separated.
 *
 * Returns 1 if certificate info was found, 0 otherwise.
 */
static int extract_ssh_cert_info(pam_handle_t *pamh, llng_ssh_cert_info_t *cert_info)
{
    if (!cert_info) return 0;
    memset(cert_info, 0, sizeof(*cert_info));

    /* Get SSH_USER_AUTH from PAM environment */
    const char *ssh_auth = pam_getenv(pamh, "SSH_USER_AUTH");
    if (!ssh_auth || !*ssh_auth) {
        LLNG_LOG_DEBUG(pamh, "No SSH_USER_AUTH in environment");
        return 0;
    }

    /* Security: Check length before processing (fixes #45) */
    #define MAX_SSH_AUTH_LEN 8192
    if (strlen(ssh_auth) >= MAX_SSH_AUTH_LEN) {
        LLNG_LOG_WARN(pamh, "SSH_USER_AUTH too long, ignoring");
        return 0;
    }
    #undef MAX_SSH_AUTH_LEN

    LLNG_LOG_DEBUG(pamh, "SSH_USER_AUTH: %s", ssh_auth);

    /*
     * Check if this is certificate authentication.
     * Certificate auth shows as: "publickey <algo>-cert-v01@openssh.com ..."
     * Regular key auth shows as: "publickey <algo> ..."
     */
    if (strstr(ssh_auth, "-cert-") == NULL) {
        LLNG_LOG_DEBUG(pamh, "SSH authentication is not certificate-based");
        return 0;
    }

    /*
     * Parse SSH_USER_AUTH. The format varies between SSH versions.
     * We try to extract what we can.
     *
     * OpenSSH exposes certificate info via SSH_CERT_* environment variables
     * when ExposeAuthInfo is enabled in sshd_config.
     */
    cert_info->valid = true;

    /* Maximum length for SSH environment variables to prevent DoS */
    #define MAX_SSH_ENV_LEN 4096

    /* Try to get certificate details from SSH_CERT_* environment vars */
    const char *key_id = pam_getenv(pamh, "SSH_CERT_KEY_ID");
    if (key_id && strlen(key_id) < MAX_SSH_ENV_LEN) {
        cert_info->key_id = strdup(key_id);
    }

    const char *serial = pam_getenv(pamh, "SSH_CERT_SERIAL");
    if (serial && strlen(serial) < MAX_SSH_ENV_LEN) {
        cert_info->serial = strdup(serial);
    }

    const char *principals = pam_getenv(pamh, "SSH_CERT_PRINCIPALS");
    if (principals && strlen(principals) < MAX_SSH_ENV_LEN) {
        cert_info->principals = strdup(principals);
    }

    const char *ca_fp = pam_getenv(pamh, "SSH_CERT_CA_KEY_FP");
    if (ca_fp && strlen(ca_fp) < MAX_SSH_ENV_LEN) {
        cert_info->ca_fingerprint = strdup(ca_fp);
    }

    /* If we didn't get any details, try to parse from SSH_USER_AUTH */
    if (!cert_info->key_id && !cert_info->serial) {
        /*
         * Try parsing format: "publickey algo fingerprint:keyid:serial:principals"
         * This is a simplified parser - real format may vary.
         *
         * Security: Apply length limits to all extracted fields (fixes #45)
         */
        #define MAX_SSH_FIELD_LEN 1024  /* Max length for individual parsed fields */

        /*
         * Helper macro to safely duplicate a field with length check.
         * Security improvement: track allocation failures to detect OOM conditions.
         * Under memory pressure, incomplete certificate validation could be a risk.
         */
        int oom_error = 0;
        #define SAFE_FIELD_DUP(dest, src) do { \
            if ((src) && *(src) && strlen(src) < MAX_SSH_FIELD_LEN) { \
                (dest) = strdup(src); \
                if (!(dest)) { \
                    LLNG_LOG_DEBUG(pamh, "strdup failed for SSH cert field (OOM)"); \
                    oom_error = 1; \
                } \
            } \
        } while(0)

        char *auth_copy = strdup(ssh_auth);
        if (auth_copy) {
            /* Skip "publickey " prefix */
            char *p = auth_copy;
            if (strncmp(p, "publickey ", 10) == 0) {
                p += 10;
            }
            /* Skip algorithm */
            char *space = strchr(p, ' ');
            if (space) {
                p = space + 1;
                /* Now p points to fingerprint or other data */
                char *colon = strchr(p, ':');
                if (colon) {
                    /* Extract fingerprint */
                    *colon = '\0';
                    SAFE_FIELD_DUP(cert_info->ca_fingerprint, p);
                    p = colon + 1;

                    /* Try to extract key_id */
                    colon = strchr(p, ':');
                    if (colon) {
                        *colon = '\0';
                        SAFE_FIELD_DUP(cert_info->key_id, p);
                        p = colon + 1;

                        /* Try to extract serial */
                        colon = strchr(p, ':');
                        if (colon) {
                            *colon = '\0';
                            SAFE_FIELD_DUP(cert_info->serial, p);
                            p = colon + 1;
                            SAFE_FIELD_DUP(cert_info->principals, p);
                        } else {
                            SAFE_FIELD_DUP(cert_info->serial, p);
                        }
                    } else {
                        SAFE_FIELD_DUP(cert_info->key_id, p);
                    }
                }
            }
            free(auth_copy);
        } else {
            /* Track OOM on initial SSH auth strdup as well */
            LLNG_LOG_DEBUG(pamh, "strdup failed for ssh_auth during SSH cert parsing (OOM)");
            oom_error = 1;
        }

        /* Security: if OOM occurred during parsing, log warning */
        if (oom_error) {
            LLNG_LOG_WARN(pamh, "Memory allocation failed during SSH cert parsing - "
                          "certificate validation may be incomplete");
        }
        #undef SAFE_FIELD_DUP
        #undef MAX_SSH_FIELD_LEN
    }

    LLNG_LOG_DEBUG(pamh, "SSH cert info: key_id=%s serial=%s principals=%s",
                   cert_info->key_id ? cert_info->key_id : "(none)",
                   cert_info->serial ? cert_info->serial : "(none)",
                   cert_info->principals ? cert_info->principals : "(none)");

    return 1;
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
PAM_VISIBLE PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
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

    /* Security: Periodically re-verify token file permissions (#46) */
    if (verify_token_file_security(pamh, data) != 0) {
        LLNG_LOG_ERR(pamh, "Token file security verification failed, refusing authentication");
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

    /* Security: validate token length to prevent DoS via memory exhaustion */
    #define MAX_TOKEN_LENGTH 8192
    if (strlen(password) > MAX_TOKEN_LENGTH) {
        LLNG_LOG_WARN(pamh, "Token too long (max %d chars)", MAX_TOKEN_LENGTH);

        if (data->rate_limiter) {
            rate_limiter_record_failure(data->rate_limiter, rate_key);
        }

        if (audit_initialized) {
            audit_event.result_code = PAM_AUTH_ERR;
            audit_event.reason = "Token too long";
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
PAM_VISIBLE PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
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
 *
 * For sudo service, it also checks if the user has sudo permissions
 * and stores the result in PAM data for later use.
 */
PAM_VISIBLE PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
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

    /* Security: Periodically re-verify token file permissions (#46) */
    if (verify_token_file_security(pamh, data) != 0) {
        LLNG_LOG_ERR(pamh, "Token file security verification failed, refusing authorization");
        return PAM_SERVICE_ERR;
    }

    /* Get context information */
    client_ip = get_client_ip(pamh);
    tty = get_tty(pamh);

    /* Get hostname - use snprintf for guaranteed null-termination */
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
        snprintf(hostname, sizeof(hostname), "unknown");
    }

    /* Get service name */
    const char *service = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS || !service) {
        service = "unknown";
    }

    /*
     * Bastion JWT verification for backend servers.
     * If bastion_jwt_required is enabled, we require a valid JWT from the bastion
     * server before allowing SSH access. The JWT is passed via the LLNG_BASTION_JWT
     * environment variable (set by SSH's SendEnv/AcceptEnv).
     */
    if (data->config.bastion_jwt_required &&
        (strcmp(service, "sshd") == 0 || strcmp(service, "ssh") == 0)) {

        const char *bastion_jwt = pam_getenv(pamh, "LLNG_BASTION_JWT");

        if (!bastion_jwt || !*bastion_jwt) {
            LLNG_LOG_ERR(pamh, "Bastion JWT required but not provided for user %s", user);

            if (data->audit) {
                audit_event_init(&audit_event, AUDIT_AUTHZ_DENIED);
                audit_event.user = user;
                audit_event.service = service;
                audit_event.client_ip = client_ip;
                audit_event.tty = tty;
                audit_event.result_code = PAM_PERM_DENIED;
                audit_event.reason = "Bastion JWT required but not provided";
                audit_event_set_end_time(&audit_event);
                audit_log_event(data->audit, &audit_event);
            }

            return PAM_PERM_DENIED;
        }

        /* Verify the JWT */
        if (data->bastion_jwt_verifier) {
            bastion_jwt_claims_t claims = {0};
            bastion_jwt_result_t jwt_result = bastion_jwt_verify(
                data->bastion_jwt_verifier, bastion_jwt, &claims);

            if (jwt_result != BASTION_JWT_OK) {
                LLNG_LOG_ERR(pamh, "Bastion JWT verification failed for user %s: %s",
                             user, bastion_jwt_result_str(jwt_result));

                if (data->audit) {
                    audit_event_init(&audit_event, AUDIT_SECURITY_ERROR);
                    audit_event.user = user;
                    audit_event.service = service;
                    audit_event.client_ip = client_ip;
                    audit_event.tty = tty;
                    audit_event.result_code = PAM_PERM_DENIED;
                    audit_event.reason = bastion_jwt_result_str(jwt_result);
                    audit_event_set_end_time(&audit_event);
                    audit_log_event(data->audit, &audit_event);
                }

                bastion_jwt_claims_free(&claims);
                return PAM_PERM_DENIED;
            }

            /* Verify the JWT subject matches the PAM user */
            if (!claims.sub || strcmp(claims.sub, user) != 0) {
                LLNG_LOG_ERR(pamh, "Bastion JWT subject mismatch: expected %s, got %s",
                             user, claims.sub ? claims.sub : "(null)");

                if (data->audit) {
                    /* Use AUDIT_AUTHZ_DENIED for authorization failures,
                     * AUDIT_SECURITY_ERROR is for crypto/verification failures */
                    audit_event_init(&audit_event, AUDIT_AUTHZ_DENIED);
                    audit_event.user = user;
                    audit_event.service = service;
                    audit_event.client_ip = client_ip;
                    audit_event.tty = tty;
                    audit_event.result_code = PAM_PERM_DENIED;
                    audit_event.reason = "Bastion JWT subject mismatch";
                    audit_event_set_end_time(&audit_event);
                    audit_log_event(data->audit, &audit_event);
                }

                bastion_jwt_claims_free(&claims);
                return PAM_PERM_DENIED;
            }

            /* Optionally verify the bastion IP matches the connecting client */
            if (claims.bastion_ip && client_ip && strcmp(client_ip, "local") != 0) {
                if (strcmp(claims.bastion_ip, client_ip) != 0) {
                    LLNG_LOG_WARN(pamh, "Bastion IP mismatch: JWT claims %s, connection from %s",
                                  claims.bastion_ip, client_ip);
                    /* This is a warning, not an error - the bastion might be behind NAT */
                }
            }

            LLNG_LOG_INFO(pamh, "Bastion JWT verified for user %s from bastion %s",
                          user, claims.bastion_id ? claims.bastion_id : "(unknown)");

            /* Store bastion info in PAM environment for potential use */
            if (claims.bastion_id) {
                char env_buf[256];
                int env_len = snprintf(env_buf, sizeof(env_buf),
                                       "LLNG_BASTION_ID=%s", claims.bastion_id);
                if (env_len < 0) {
                    LLNG_LOG_WARN(pamh,
                                  "Failed to format LLNG_BASTION_ID environment variable");
                } else if ((size_t)env_len >= sizeof(env_buf)) {
                    LLNG_LOG_WARN(pamh,
                                  "Truncated LLNG_BASTION_ID (length %d, buffer %zu)",
                                  env_len, sizeof(env_buf));
                }
                pam_putenv(pamh, env_buf);
            }

            bastion_jwt_claims_free(&claims);
        } else {
            /*
             * No local verifier available - this shouldn't happen if
             * bastion_jwt_required is true, but handle it gracefully.
             */
            LLNG_LOG_ERR(pamh, "Bastion JWT required but verifier not initialized");
            return PAM_SERVICE_ERR;
        }
    }

    /*
     * Detect if this is an SSH connection with certificate authentication.
     * Extract certificate info to send to LLNG for authorization.
     */
    llng_ssh_cert_info_t ssh_cert_info = {0};
    bool has_ssh_cert = false;

    if (strcmp(service, "sshd") == 0 || strcmp(service, "ssh") == 0) {
        has_ssh_cert = extract_ssh_cert_info(pamh, &ssh_cert_info);
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

    /*
     * Check if force-online is requested for this user.
     * If the force-online file exists and user is listed, skip cache.
     */
    bool use_cache = (data->auth_cache != NULL);
    if (use_cache && data->config.auth_cache_force_online) {
        if (auth_cache_force_online(data->config.auth_cache_force_online, user)) {
            LLNG_LOG_INFO(pamh, "Force-online requested for user %s, skipping cache", user);
            use_cache = false;
        }
    }

    /* Call authorization endpoint (with or without SSH cert info) */
    llng_response_t response = {0};
    int auth_result;
    bool from_cache = false;

    if (has_ssh_cert) {
        LLNG_LOG_DEBUG(pamh, "Authorizing with SSH certificate info");
        auth_result = llng_authorize_user_with_cert(data->client, user, hostname,
                                                     service, &ssh_cert_info, &response);
        llng_ssh_cert_info_free(&ssh_cert_info);
    } else {
        auth_result = llng_authorize_user(data->client, user, hostname, service, &response);
    }

    if (auth_result != 0) {
        /*
         * Server unreachable - try offline cache if available.
         * This is the core of the offline mode feature (#36).
         */
        if (use_cache) {
            auth_cache_entry_t cache_entry = {0};
            if (auth_cache_lookup(data->auth_cache, user,
                                  data->config.server_group, hostname, &cache_entry)) {
                LLNG_LOG_INFO(pamh, "Server unavailable, using cached authorization for %s", user);

                /* Populate response from cache */
                response.authorized = cache_entry.authorized;
                response.user = cache_entry.user ? strdup(cache_entry.user) : NULL;
                cache_entry.user = NULL;  /* Ownership transferred */

                response.has_permissions = true;
                response.permissions.sudo_allowed = cache_entry.sudo_allowed;
                response.permissions.sudo_nopasswd = cache_entry.sudo_nopasswd;

                /* Copy groups */
                if (cache_entry.groups && cache_entry.groups_count > 0) {
                    response.groups = cache_entry.groups;
                    response.groups_count = cache_entry.groups_count;
                    cache_entry.groups = NULL;  /* Ownership transferred */
                    cache_entry.groups_count = 0;
                }

                /* Copy user attributes */
                response.gecos = cache_entry.gecos ? strdup(cache_entry.gecos) : NULL;
                response.shell = cache_entry.shell ? strdup(cache_entry.shell) : NULL;
                response.home = cache_entry.home ? strdup(cache_entry.home) : NULL;

                auth_cache_entry_free(&cache_entry);
                from_cache = true;
                auth_result = 0;  /* Cache hit is success */
            } else {
                LLNG_LOG_WARN(pamh, "Server unavailable and no valid cache for %s", user);
            }
        }

        if (auth_result != 0) {
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
    }

    /* Check result */
    if (!response.authorized) {
        LLNG_LOG_INFO(pamh, "User %s not authorized%s: %s", user,
                 from_cache ? " (from cache)" : "",
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

    /*
     * Store authorization in cache if:
     * - Not already from cache
     * - Server indicates offline mode is allowed for this user
     * - Cache is available
     */
    if (!from_cache && use_cache && response.has_offline && response.offline.enabled) {
        int ttl = response.offline.ttl > 0 ? response.offline.ttl : DEFAULT_OFFLINE_CACHE_TTL;
        auth_cache_entry_t cache_entry = {
            .version = 3,
            .user = (char *)user,
            .authorized = response.authorized,
            .groups = response.groups,
            .groups_count = response.groups_count,
            .sudo_allowed = response.has_permissions ? response.permissions.sudo_allowed : false,
            .sudo_nopasswd = response.has_permissions ? response.permissions.sudo_nopasswd : false,
            .gecos = response.gecos,
            .shell = response.shell,
            .home = response.home
        };

        if (auth_cache_store(data->auth_cache, user, data->config.server_group,
                             hostname, &cache_entry, ttl) == 0) {
            LLNG_LOG_DEBUG(pamh, "Cached authorization for %s (TTL: %d seconds)", user, ttl);
        } else {
            LLNG_LOG_WARN(pamh, "Failed to cache authorization for %s", user);
        }
    }

    /*
     * Handle sudo authorization.
     * For sudo service, check if the user has sudo_allowed permission.
     * Store the result in PAM environment for sudo to use.
     */
    if (strcmp(service, "sudo") == 0) {
        if (response.has_permissions && !response.permissions.sudo_allowed) {
            LLNG_LOG_INFO(pamh, "User %s authorized for SSH but not for sudo%s", user,
                     from_cache ? " (from cache)" : "");

            if (audit_initialized) {
                audit_event.result_code = PAM_PERM_DENIED;
                audit_event.reason = "Sudo not allowed";
                audit_event_set_end_time(&audit_event);
                audit_log_event(data->audit, &audit_event);
            }

            llng_response_free(&response);
            return PAM_PERM_DENIED;
        }

        /* Store sudo_nopasswd flag if applicable */
        if (response.has_permissions && response.permissions.sudo_nopasswd) {
            pam_putenv(pamh, "LLNG_SUDO_NOPASSWD=1");
            LLNG_LOG_DEBUG(pamh, "User %s granted sudo without password", user);
        }
    }

    /* Store permissions in PAM data for potential use by other modules */
    if (response.has_permissions) {
        if (response.permissions.sudo_allowed) {
            pam_putenv(pamh, "LLNG_SUDO_ALLOWED=1");
        }
    }

    /* Success */
    if (audit_initialized) {
        audit_event.event_type = AUDIT_AUTHZ_SUCCESS;
        audit_event.result_code = PAM_SUCCESS;
        audit_event_set_end_time(&audit_event);
        audit_log_event(data->audit, &audit_event);
    }

    LLNG_LOG_INFO(pamh, "User %s authorized for access%s%s", user,
                  (response.has_permissions && response.permissions.sudo_allowed) ?
                  " (sudo allowed)" : "",
                  from_cache ? " (from cache)" : "");
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
    char *safe_gecos = NULL;  /* Sanitized GECOS (must be freed) */
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

    /* Sanitize GECOS to prevent /etc/passwd corruption */
    safe_gecos = sanitize_gecos(gecos);
    if (!safe_gecos) {
        LLNG_LOG_ERR(pamh, "Failed to sanitize GECOS for user %s", user);
        goto cleanup;
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
                user, uid, gid, safe_gecos, home_dir, user_shell) < 0) {
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

    /*
     * Create home directory with secure permissions (0700).
     * Security: Use fchown on the directory fd to avoid TOCTOU race conditions.
     * This prevents an attacker from replacing the directory between mkdir and chown.
     */
    bool home_dir_safe = false;  /* Track if we verified the directory is safe */

    if (mkdir(home_dir, 0700) != 0 && errno != EEXIST) {
        LLNG_LOG_WARN(pamh, "Cannot create home directory %s: %s", home_dir, strerror(errno));
        /* Continue anyway - user is created */
    } else {
        /* Open directory to get fd for secure ownership change */
        int home_fd = open(home_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (home_fd < 0) {
            LLNG_LOG_WARN(pamh, "Cannot open home directory %s for chown: %s",
                          home_dir, strerror(errno));
            /* Security: don't proceed with skel/chown if we can't verify the directory */
        } else {
            /* Verify we own the directory or it's newly created */
            struct stat st;
            if (fstat(home_fd, &st) == 0) {
                /* Only change ownership if it's root-owned (just created) or already correct */
                if (st.st_uid == 0 || (st.st_uid == (uid_t)uid && st.st_gid == (gid_t)gid)) {
                    /* Security: use fchown on the fd - immune to symlink attacks */
                    if (fchown(home_fd, uid, gid) == 0) {
                        home_dir_safe = true;  /* Directory verified and ownership set */
                    } else {
                        LLNG_LOG_WARN(pamh, "Cannot set ownership of home directory: %s",
                                      strerror(errno));
                    }
                } else {
                    LLNG_LOG_WARN(pamh, "Home directory %s owned by unexpected user %d, skipping chown",
                                  home_dir, st.st_uid);
                }
            }
            close(home_fd);
        }

        /* Only proceed with skel copy and recursive chown if directory is verified safe */
        if (home_dir_safe) {
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

            /*
             * Set ownership of contents recursively.
             * Note: We still need chown -R for the contents copied from skel.
             * The directory itself is already owned by the user (fchown above).
             */
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
    }

    LLNG_LOG_INFO(pamh, "Successfully created Unix user: %s", user);

    /* Invalidate nscd cache so the new user is visible immediately */
    invalidate_nscd_cache();

cleanup:
    /* Free sanitized GECOS */
    free(safe_gecos);

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
PAM_VISIBLE PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
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

    /*
     * Security: Store authenticated user for close_session verification (#49)
     * This prevents cache invalidation attacks where an attacker could
     * invalidate another user's cache by calling close_session with a
     * different username.
     */
    char *session_user = strdup(user);
    if (!session_user) {
        LLNG_LOG_ERR(pamh, "Out of memory storing session user");
        return PAM_BUF_ERR;
    }
    pam_set_data(pamh, "llng_session_user", session_user, cleanup_string);

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
PAM_VISIBLE PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                     int flags,
                                     int argc,
                                     const char **argv)
{
    (void)flags;

    const char *user = NULL;
    const char *session_user = NULL;
    int ret;

    /* Get username */
    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS || !user || !*user) {
        /* Can't get user, nothing to invalidate */
        return PAM_SUCCESS;
    }

    /*
     * Security: Verify this is the same user from open_session (#49)
     * This prevents cache invalidation attacks where close_session could
     * be called with a different username to invalidate another user's cache.
     */
    if (pam_get_data(pamh, "llng_session_user", (const void **)&session_user) == PAM_SUCCESS
        && session_user) {
        if (strcmp(user, session_user) != 0) {
            LLNG_LOG_WARN(pamh,
                "Security: close_session user mismatch (session=%s, request=%s), "
                "refusing cache invalidation",
                session_user, user);
            return PAM_SUCCESS;  /* Don't fail, just skip invalidation */
        }
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
