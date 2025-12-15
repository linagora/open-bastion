/*
 * client_context.h - Client context collection for PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#ifndef CLIENT_CONTEXT_H
#define CLIENT_CONTEXT_H

#include <stdbool.h>
#include <security/pam_modules.h>

/* Client context structure */
typedef struct {
    char *username;           /* PAM_USER */
    char *service;            /* PAM_SERVICE (e.g., "sshd", "sudo") */
    char *rhost;              /* PAM_RHOST - remote hostname/IP */
    char *tty;                /* PAM_TTY */
    char *ruser;              /* PAM_RUSER - remote username */

    /* Derived fields */
    char *client_ip;          /* Parsed IP from rhost */
    char *fingerprint;        /* SHA256 hash of context for binding */
    char *rate_limit_key;     /* Key for rate limiting (user:ip) */

    /* Flags */
    bool is_local;            /* True if connection is local */
    bool is_high_risk;        /* True if service is high-risk */
} client_context_t;

/*
 * Collect client context from PAM handle
 * Returns allocated context on success, NULL on failure
 */
client_context_t *client_context_collect(pam_handle_t *pamh);

/*
 * Free client context
 */
void client_context_free(client_context_t *ctx);

/*
 * Generate fingerprint from context
 * Combines username, client_ip, and service into a hash
 * Used for token binding
 */
void client_context_generate_fingerprint(client_context_t *ctx);

/*
 * Check if service is in high-risk list
 * high_risk_services is comma-separated list (e.g., "sudo,su,ssh")
 */
bool client_context_is_high_risk(const client_context_t *ctx,
                                  const char *high_risk_services);

/*
 * Get effective cache TTL based on context
 * Returns high_risk_ttl for high-risk services, normal_ttl otherwise
 */
int client_context_get_cache_ttl(const client_context_t *ctx,
                                  int normal_ttl,
                                  int high_risk_ttl,
                                  const char *high_risk_services);

/*
 * Build rate limit key from context
 * Format: "username:client_ip"
 */
void client_context_build_rate_key(client_context_t *ctx);

#endif /* CLIENT_CONTEXT_H */
