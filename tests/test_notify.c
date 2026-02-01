/*
 * test_notify.c - Unit tests for webhook notifications
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "notify.h"
#include "audit_log.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    tests_run++; \
    if (test_##name()) { \
        printf("PASS\n"); \
        tests_passed++; \
    } else { \
        printf("FAIL\n"); \
    } \
} while(0)

/* Test initialization with NULL config */
static int test_init_null_config(void)
{
    notify_context_t *ctx = notify_init(NULL);
    if (ctx != NULL) {
        notify_destroy(ctx);
        return 0;
    }
    return 1;
}

/* Test initialization with NULL webhook URL */
static int test_init_null_url(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = NULL,
        .hmac_secret = NULL,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (ctx != NULL) {
        notify_destroy(ctx);
        return 0;
    }
    return 1;
}

/* Test successful initialization */
static int test_init_valid(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = "test-secret",
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) {
        return 0;
    }

    notify_destroy(ctx);
    return 1;
}

/* Test initialization with default values (timeout=0, retry_count=0, retry_delay_ms=0) */
static int test_init_defaults(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = NULL,
        .timeout = 0,           /* Should default to 30 */
        .verify_ssl = false,
        .retry_count = 0,       /* Should default to 2 */
        .retry_delay_ms = 0     /* Should default to 1000 */
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) {
        return 0;
    }

    notify_destroy(ctx);
    return 1;
}

/* Test destroying NULL context */
static int test_destroy_null(void)
{
    notify_destroy(NULL);
    return 1;  /* Should not crash */
}

/* Test should_send for critical events */
static int test_should_send_critical_events(void)
{
    int result = 1;

    if (!notify_should_send(AUDIT_RATE_LIMITED)) result = 0;
    if (!notify_should_send(AUDIT_SECURITY_ERROR)) result = 0;
    if (!notify_should_send(AUDIT_CONFIG_ERROR)) result = 0;
    if (!notify_should_send(AUDIT_AUTH_DENIED)) result = 0;
    if (!notify_should_send(AUDIT_AUTHZ_DENIED)) result = 0;

    return result;
}

/* Test should_send for non-critical events */
static int test_should_send_non_critical_events(void)
{
    int result = 1;

    if (notify_should_send(AUDIT_AUTH_SUCCESS)) result = 0;
    if (notify_should_send(AUDIT_AUTHZ_SUCCESS)) result = 0;
    if (notify_should_send(AUDIT_CACHE_HIT)) result = 0;
    if (notify_should_send(AUDIT_CACHE_MISS)) result = 0;
    if (notify_should_send(AUDIT_TOKEN_INTROSPECT)) result = 0;
    if (notify_should_send(AUDIT_USER_CREATED)) result = 0;
    if (notify_should_send(AUDIT_ENROLLMENT_SUCCESS)) result = 0;

    return result;
}

/* Test send_json with NULL context */
static int test_send_json_null_ctx(void)
{
    int ret = notify_send_json(NULL, "{}");
    return (ret == -1) ? 1 : 0;
}

/* Test send_json with NULL payload */
static int test_send_json_null_payload(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = NULL,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    int ret = notify_send_json(ctx, NULL);
    notify_destroy(ctx);

    return (ret == -1) ? 1 : 0;
}

/* Test send_json when notifications are disabled */
static int test_send_json_disabled(void)
{
    notify_config_t config = {
        .enabled = false,  /* Disabled */
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = NULL,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    int ret = notify_send_json(ctx, "{\"test\":\"data\"}");
    notify_destroy(ctx);

    return (ret == -1) ? 1 : 0;
}

/* Test send_event with NULL context */
static int test_send_event_null_ctx(void)
{
    audit_event_t event = {
        .event_type = AUDIT_SECURITY_ERROR,
        .correlation_id = "test-123",
        .user = "testuser",
        .service = "ssh",
        .client_ip = "127.0.0.1",
        .result_code = 1,
        .reason = "Test error"
    };

    int ret = notify_send_event(NULL, &event);
    return (ret == -1) ? 1 : 0;
}

/* Test send_event with NULL event */
static int test_send_event_null_event(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = NULL,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    int ret = notify_send_event(ctx, NULL);
    notify_destroy(ctx);

    return (ret == -1) ? 1 : 0;
}

/* Test send_event with filtered event (non-critical) */
static int test_send_event_filtered(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = NULL,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    audit_event_t event = {
        .event_type = AUDIT_AUTH_SUCCESS,  /* Non-critical, should be filtered */
        .correlation_id = "test-123",
        .user = "testuser",
        .service = "ssh",
        .client_ip = "127.0.0.1",
        .result_code = 0,
        .reason = "Success"
    };

    int ret = notify_send_event(ctx, &event);
    notify_destroy(ctx);

    return (ret == 0) ? 1 : 0;  /* 0 means filtered, not error */
}

/* Test send_event when disabled */
static int test_send_event_disabled(void)
{
    notify_config_t config = {
        .enabled = false,  /* Disabled */
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = NULL,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    audit_event_t event = {
        .event_type = AUDIT_SECURITY_ERROR,
        .correlation_id = "test-123",
        .user = "testuser",
        .service = "ssh",
        .client_ip = "127.0.0.1",
        .result_code = 1,
        .reason = "Test error"
    };

    int ret = notify_send_event(ctx, &event);
    notify_destroy(ctx);

    return (ret == -1) ? 1 : 0;
}

/* Test error message with NULL context */
static int test_error_null_ctx(void)
{
    const char *err = notify_error(NULL);
    return (strcmp(err, "NULL notify context") == 0) ? 1 : 0;
}

/* Test error message after initialization (should be empty) */
static int test_error_after_init(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "https://example.com/webhook",
        .hmac_secret = NULL,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    const char *err = notify_error(ctx);
    int result = (strlen(err) == 0) ? 1 : 0;

    notify_destroy(ctx);
    return result;
}

/* Test send_json to bad URL (connection refused) */
static int test_send_json_to_bad_url(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "http://127.0.0.1:1",  /* Invalid port */
        .hmac_secret = NULL,
        .timeout = 1,           /* Short timeout */
        .verify_ssl = false,
        .retry_count = 0,       /* No retries */
        .retry_delay_ms = 0
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    int ret = notify_send_json(ctx, "{\"test\":\"data\"}");
    const char *err = notify_error(ctx);

    /* Should fail and have error message */
    int result = (ret == -1 && strlen(err) > 0) ? 1 : 0;

    notify_destroy(ctx);
    return result;
}

/* Test send_event to bad URL */
static int test_send_event_to_bad_url(void)
{
    notify_config_t config = {
        .enabled = true,
        .webhook_url = "http://127.0.0.1:1",  /* Invalid port */
        .hmac_secret = NULL,
        .timeout = 1,           /* Short timeout */
        .verify_ssl = false,
        .retry_count = 0,       /* No retries */
        .retry_delay_ms = 0
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) return 0;

    audit_event_t event = {
        .event_type = AUDIT_SECURITY_ERROR,  /* Critical event */
        .correlation_id = "test-123",
        .user = "testuser",
        .service = "ssh",
        .client_ip = "127.0.0.1",
        .result_code = 1,
        .reason = "Test error"
    };

    int ret = notify_send_event(ctx, &event);
    const char *err = notify_error(ctx);

    /* Should fail and have error message */
    int result = (ret == -1 && strlen(err) > 0) ? 1 : 0;

    notify_destroy(ctx);
    return result;
}

/* Test that config is properly copied (strings don't alias original) */
static int test_config_copied(void)
{
    char *url = strdup("https://example.com/webhook");
    char *secret = strdup("test-secret-123");

    notify_config_t config = {
        .enabled = true,
        .webhook_url = url,
        .hmac_secret = secret,
        .timeout = 30,
        .verify_ssl = false,
        .retry_count = 2,
        .retry_delay_ms = 1000
    };

    notify_context_t *ctx = notify_init(&config);
    if (!ctx) {
        free(url);
        free(secret);
        return 0;
    }

    /* Free the original strings */
    free(url);
    free(secret);

    /* Context should still work with a simple operation */
    const char *err = notify_error(ctx);
    int result = (strlen(err) == 0) ? 1 : 0;

    notify_destroy(ctx);
    return result;
}

int main(void)
{
    printf("Running webhook notification tests...\n");

    /* Initialization tests */
    TEST(init_null_config);
    TEST(init_null_url);
    TEST(init_valid);
    TEST(init_defaults);
    TEST(destroy_null);

    /* Event filtering tests */
    TEST(should_send_critical_events);
    TEST(should_send_non_critical_events);

    /* send_json tests */
    TEST(send_json_null_ctx);
    TEST(send_json_null_payload);
    TEST(send_json_disabled);

    /* send_event tests */
    TEST(send_event_null_ctx);
    TEST(send_event_null_event);
    TEST(send_event_filtered);
    TEST(send_event_disabled);

    /* Error handling tests */
    TEST(error_null_ctx);
    TEST(error_after_init);
    TEST(send_json_to_bad_url);
    TEST(send_event_to_bad_url);

    /* Config copy test */
    TEST(config_copied);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
