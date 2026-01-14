/*
 * crowdsec.h - CrowdSec integration for Open Bastion PAM module
 *
 * Provides bouncer (pre-auth IP check) and watcher (post-auth alert reporting)
 * functionality using the CrowdSec Local API (LAPI).
 *
 * Based on LemonLDAP::NG CrowdSec implementation.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef CROWDSEC_H
#define CROWDSEC_H

#include <stdbool.h>

/* Action when a ban decision is detected */
typedef enum {
    CS_ACTION_REJECT,           /* Block access (return PAM_AUTH_ERR) */
    CS_ACTION_WARN              /* Log only, allow access to continue */
} crowdsec_action_t;

/* Result codes for IP check */
typedef enum {
    CS_ALLOW,                   /* No ban decision, allow access */
    CS_DENY,                    /* Active ban decision found */
    CS_ERROR                    /* API error occurred */
} crowdsec_result_t;

/* CrowdSec configuration */
typedef struct {
    bool enabled;               /* Enable CrowdSec integration (default: false) */
    char *url;                  /* LAPI URL (default: http://127.0.0.1:8080) */
    int timeout;                /* HTTP timeout in seconds (default: 5) */
    bool fail_open;             /* Allow on error (default: true) */
    bool verify_ssl;            /* Verify SSL certificates (default: true) */
    char *ca_cert;              /* CA certificate path (optional) */

    /* Bouncer (pre-auth) */
    char *bouncer_key;          /* Bouncer API key from cscli bouncers add */
    crowdsec_action_t action;   /* reject or warn (default: reject) */

    /* Watcher (post-auth) */
    char *machine_id;           /* Machine ID from cscli machines add */
    char *password;             /* Machine password */
    char *scenario;             /* Scenario name (default: open-bastion/ssh-auth-failure) */
    bool send_all_alerts;       /* true = send all alerts, false = only on ban */
    int max_failures;           /* Auto-ban after N failures (0 = no auto-ban) */
    int block_delay;            /* Time window in seconds for counting failures */
    char *ban_duration;         /* Ban duration (e.g., "4h", "1d") */
} crowdsec_config_t;

/* Opaque context handle */
typedef struct crowdsec_context crowdsec_context_t;

/*
 * Initialize CrowdSec context
 *
 * @param config Configuration parameters
 * @return Context handle or NULL on failure
 */
crowdsec_context_t *crowdsec_init(const crowdsec_config_t *config);

/*
 * Destroy CrowdSec context and free resources
 *
 * @param ctx Context handle (safe to pass NULL)
 */
void crowdsec_destroy(crowdsec_context_t *ctx);

/*
 * Check if IP has active ban decision (Bouncer role)
 *
 * Called BEFORE Open Bastion authentication to fail-fast on banned IPs.
 * Uses GET /v1/decisions?ip=X with X-Api-Key header.
 *
 * @param ctx Context handle
 * @param ip Client IP address to check
 * @return CS_ALLOW (no ban), CS_DENY (banned), or CS_ERROR (API error)
 */
crowdsec_result_t crowdsec_check_ip(crowdsec_context_t *ctx, const char *ip);

/*
 * Report authentication failure (Watcher role)
 *
 * Called AFTER Open Bastion authentication failure. Sends alert to CrowdSec LAPI.
 * If failure count reaches max_failures, includes ban decision in alert.
 *
 * @param ctx Context handle
 * @param ip Client IP address
 * @param user Username that attempted authentication
 * @param service PAM service name (e.g., "ssh", "sudo")
 * @return 0 on success, -1 on error
 */
int crowdsec_report_failure(crowdsec_context_t *ctx,
                            const char *ip,
                            const char *user,
                            const char *service);

/*
 * Get last error message
 *
 * @param ctx Context handle
 * @return Error message string (empty if no error)
 */
const char *crowdsec_error(crowdsec_context_t *ctx);

/* Default configuration values */
#define CROWDSEC_DEFAULT_URL "http://127.0.0.1:8080"
#define CROWDSEC_DEFAULT_TIMEOUT 5
#define CROWDSEC_DEFAULT_SCENARIO "open-bastion/ssh-auth-failure"
#define CROWDSEC_DEFAULT_MAX_FAILURES 5
#define CROWDSEC_DEFAULT_BLOCK_DELAY 180
#define CROWDSEC_DEFAULT_BAN_DURATION "4h"

#endif /* CROWDSEC_H */
