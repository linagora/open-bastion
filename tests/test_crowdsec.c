/*
 * test_crowdsec.c - Unit tests for CrowdSec integration
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crowdsec.h"

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
    crowdsec_context_t *ctx = crowdsec_init(NULL);
    if (ctx != NULL) {
        crowdsec_destroy(ctx);
        return 0;
    }
    return 1;
}

/* Test initialization when disabled */
static int test_init_disabled(void)
{
    crowdsec_config_t config = {
        .enabled = false,
        .url = NULL,
        .timeout = 5,
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = NULL,
        .machine_id = NULL,
        .password = NULL,
        .scenario = NULL,
        .max_failures = 5,
        .block_delay = 180,
        .ban_duration = NULL
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    if (!ctx) return 0;

    /* Even when disabled, check_ip should return ALLOW */
    crowdsec_result_t result = crowdsec_check_ip(ctx, "192.168.1.1");
    if (result != CS_ALLOW) {
        crowdsec_destroy(ctx);
        return 0;
    }

    crowdsec_destroy(ctx);
    return 1;
}

/* Test initialization with default values */
static int test_init_defaults(void)
{
    crowdsec_config_t config = {
        .enabled = true,
        .url = NULL,  /* Should use default */
        .timeout = 0,  /* Should use default */
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = NULL,
        .machine_id = NULL,
        .password = NULL,
        .scenario = NULL,  /* Should use default */
        .max_failures = 0,  /* Should use default */
        .block_delay = 0,   /* Should use default */
        .ban_duration = NULL  /* Should use default */
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    if (!ctx) return 0;

    crowdsec_destroy(ctx);
    return 1;
}

/* Test check_ip returns ALLOW when no bouncer key is configured */
static int test_check_ip_no_bouncer_key(void)
{
    crowdsec_config_t config = {
        .enabled = true,
        .url = "http://localhost:8080",
        .timeout = 5,
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = NULL,  /* No bouncer key */
        .machine_id = NULL,
        .password = NULL,
        .scenario = "test-scenario",
        .max_failures = 5,
        .block_delay = 180,
        .ban_duration = "4h"
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    if (!ctx) return 0;

    /* Without bouncer key, should return ALLOW */
    crowdsec_result_t result = crowdsec_check_ip(ctx, "192.168.1.1");
    if (result != CS_ALLOW) {
        crowdsec_destroy(ctx);
        return 0;
    }

    crowdsec_destroy(ctx);
    return 1;
}

/* Test check_ip with NULL IP */
static int test_check_ip_null_ip(void)
{
    crowdsec_config_t config = {
        .enabled = true,
        .url = "http://localhost:8080",
        .timeout = 5,
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = "test-key",
        .machine_id = NULL,
        .password = NULL,
        .scenario = "test-scenario",
        .max_failures = 5,
        .block_delay = 180,
        .ban_duration = "4h"
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    if (!ctx) return 0;

    /* NULL IP should return ALLOW (graceful handling) */
    crowdsec_result_t result = crowdsec_check_ip(ctx, NULL);
    if (result != CS_ALLOW) {
        crowdsec_destroy(ctx);
        return 0;
    }

    crowdsec_destroy(ctx);
    return 1;
}

/* Test check_ip with NULL context */
static int test_check_ip_null_context(void)
{
    crowdsec_result_t result = crowdsec_check_ip(NULL, "192.168.1.1");
    return result == CS_ALLOW;
}

/* Test report_failure returns 0 when no credentials */
static int test_report_no_credentials(void)
{
    crowdsec_config_t config = {
        .enabled = true,
        .url = "http://localhost:8080",
        .timeout = 5,
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = NULL,
        .machine_id = NULL,  /* No machine_id */
        .password = NULL,    /* No password */
        .scenario = "test-scenario",
        .send_all_alerts = true,
        .max_failures = 5,
        .block_delay = 180,
        .ban_duration = "4h"
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    if (!ctx) return 0;

    /* Without credentials, should return 0 (silent no-op) */
    int result = crowdsec_report_failure(ctx, "192.168.1.1", "testuser", "ssh");
    if (result != 0) {
        crowdsec_destroy(ctx);
        return 0;
    }

    crowdsec_destroy(ctx);
    return 1;
}

/* Test report_failure with NULL context */
static int test_report_null_context(void)
{
    int result = crowdsec_report_failure(NULL, "192.168.1.1", "testuser", "ssh");
    return result == 0;
}

/* Test report_failure when disabled */
static int test_report_disabled(void)
{
    crowdsec_config_t config = {
        .enabled = false,  /* Disabled */
        .url = "http://localhost:8080",
        .timeout = 5,
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = NULL,
        .machine_id = "machine",
        .password = "password",
        .scenario = "test-scenario",
        .send_all_alerts = true,
        .max_failures = 5,
        .block_delay = 180,
        .ban_duration = "4h"
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    if (!ctx) return 0;

    /* When disabled, should return 0 (silent no-op) */
    int result = crowdsec_report_failure(ctx, "192.168.1.1", "testuser", "ssh");
    if (result != 0) {
        crowdsec_destroy(ctx);
        return 0;
    }

    crowdsec_destroy(ctx);
    return 1;
}

/* Test destroy with NULL */
static int test_destroy_null(void)
{
    /* Should not crash */
    crowdsec_destroy(NULL);
    return 1;
}

/* Test error function */
static int test_error_function(void)
{
    crowdsec_config_t config = {
        .enabled = true,
        .url = "http://localhost:8080",
        .timeout = 5,
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = NULL,
        .machine_id = NULL,
        .password = NULL,
        .scenario = NULL,
        .max_failures = 5,
        .block_delay = 180,
        .ban_duration = NULL
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    if (!ctx) return 0;

    const char *error = crowdsec_error(ctx);
    if (!error) {
        crowdsec_destroy(ctx);
        return 0;
    }

    /* Initially error should be empty */
    if (strlen(error) != 0) {
        crowdsec_destroy(ctx);
        return 0;
    }

    crowdsec_destroy(ctx);
    return 1;
}

/* Test error with NULL context */
static int test_error_null_context(void)
{
    const char *error = crowdsec_error(NULL);
    return error != NULL && strcmp(error, "NULL context") == 0;
}

int main(void)
{
    printf("CrowdSec Integration Tests\n");
    printf("==========================\n\n");

    printf("Initialization tests:\n");
    TEST(init_null_config);
    TEST(init_disabled);
    TEST(init_defaults);

    printf("\nBouncer (check_ip) tests:\n");
    TEST(check_ip_no_bouncer_key);
    TEST(check_ip_null_ip);
    TEST(check_ip_null_context);

    printf("\nWatcher (report_failure) tests:\n");
    TEST(report_no_credentials);
    TEST(report_null_context);
    TEST(report_disabled);

    printf("\nUtility tests:\n");
    TEST(destroy_null);
    TEST(error_function);
    TEST(error_null_context);

    printf("\n==========================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return tests_passed == tests_run ? 0 : 1;
}
