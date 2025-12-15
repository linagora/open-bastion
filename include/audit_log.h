/*
 * audit_log.h - Structured JSON audit logging for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <stdbool.h>
#include <time.h>

/* Audit event types */
typedef enum {
    AUDIT_AUTH_SUCCESS,
    AUDIT_AUTH_FAILURE,
    AUDIT_AUTH_DENIED,
    AUDIT_AUTHZ_SUCCESS,
    AUDIT_AUTHZ_DENIED,
    AUDIT_TOKEN_INTROSPECT,
    AUDIT_TOKEN_REFRESH,
    AUDIT_TOKEN_REFRESH_ROTATED,
    AUDIT_CACHE_HIT,
    AUDIT_CACHE_MISS,
    AUDIT_RATE_LIMITED,
    AUDIT_CONFIG_ERROR,
    AUDIT_SECURITY_ERROR,
    AUDIT_SERVER_ERROR,
    AUDIT_ENROLLMENT_START,
    AUDIT_ENROLLMENT_SUCCESS,
    AUDIT_ENROLLMENT_FAILURE
} audit_event_type_t;

/* Audit event structure */
typedef struct {
    audit_event_type_t event_type;
    const char *user;
    const char *service;
    const char *host;
    const char *client_ip;
    const char *tty;
    int result_code;
    const char *reason;
    const char *details;
    struct timespec start_time;
    struct timespec end_time;
    bool cache_hit;
    char correlation_id[37];  /* UUID format: 36 chars + null */
} audit_event_t;

/* Audit configuration */
typedef struct {
    bool enabled;
    char *log_file;           /* Path to JSON audit log file */
    bool log_to_syslog;       /* Also emit to syslog */
    int level;                /* 0=critical, 1=auth events, 2=all */
} audit_config_t;

/* Audit context handle */
typedef struct audit_context audit_context_t;

/*
 * Initialize audit context
 * Returns NULL on failure
 */
audit_context_t *audit_init(const audit_config_t *config);

/*
 * Destroy audit context
 */
void audit_destroy(audit_context_t *ctx);

/*
 * Initialize a new audit event with correlation ID and start time
 */
void audit_event_init(audit_event_t *event, audit_event_type_t type);

/*
 * Set event timing (call after operation completes)
 */
void audit_event_set_end_time(audit_event_t *event);

/*
 * Calculate latency in milliseconds
 */
long audit_event_latency_ms(const audit_event_t *event);

/*
 * Log an audit event
 * Returns 0 on success, -1 on error
 */
int audit_log_event(audit_context_t *ctx, const audit_event_t *event);

/*
 * Convenience function: log with auto-generated event
 */
int audit_log(audit_context_t *ctx,
              audit_event_type_t type,
              const char *user,
              const char *service,
              const char *client_ip,
              int result_code,
              const char *reason);

/*
 * Get event type as string
 */
const char *audit_event_type_str(audit_event_type_t type);

/*
 * Generate a new UUID for correlation
 */
void audit_generate_correlation_id(char *buf, size_t buf_size);

#endif /* AUDIT_LOG_H */
