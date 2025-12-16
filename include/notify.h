/*
 * notify.h - Webhook notifications for security events
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef NOTIFY_H
#define NOTIFY_H

#include <stdbool.h>
#include "audit_log.h"

/* Notification configuration */
typedef struct {
    bool enabled;
    char *webhook_url;          /* HTTPS URL for webhooks */
    char *hmac_secret;          /* Secret for HMAC-SHA256 signature */
    int timeout;                /* HTTP timeout in seconds */
    bool verify_ssl;            /* Verify SSL certificate */
    int retry_count;            /* Number of retries on failure */
    int retry_delay_ms;         /* Delay between retries in milliseconds */
} notify_config_t;

/* Notification handle */
typedef struct notify_context notify_context_t;

/*
 * Initialize notification context
 * Returns NULL on failure
 */
notify_context_t *notify_init(const notify_config_t *config);

/*
 * Destroy notification context
 */
void notify_destroy(notify_context_t *ctx);

/*
 * Send security event notification
 * This is typically called for critical events like:
 * - Rate limiting triggered
 * - Security errors
 * - Multiple authentication failures
 * Returns 0 on success, -1 on error
 */
int notify_send_event(notify_context_t *ctx, const audit_event_t *event);

/*
 * Send custom notification
 * json_payload must be a valid JSON string
 * Returns 0 on success, -1 on error
 */
int notify_send_json(notify_context_t *ctx, const char *json_payload);

/*
 * Check if event type should trigger notification
 * Only critical security events are notified by default
 */
bool notify_should_send(audit_event_type_t event_type);

/*
 * Get last error message
 */
const char *notify_error(notify_context_t *ctx);

#endif /* NOTIFY_H */
