/*
 * test_crowdsec.c - Unit tests for CrowdSec integration
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

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
        .action = CS_ACTION_REJECT,
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
        .action = CS_ACTION_REJECT,
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
        .action = CS_ACTION_REJECT,
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
        .action = CS_ACTION_REJECT,
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
        .action = CS_ACTION_REJECT,
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
        .action = CS_ACTION_REJECT,
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
        .action = CS_ACTION_REJECT,
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

/* Whitelist tests */

/* Test parsing empty whitelist */
static int test_whitelist_parse_empty(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    int result = crowdsec_parse_whitelist("", &entries, &count);
    if (result != 0 || count != 0 || entries != NULL) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    result = crowdsec_parse_whitelist(NULL, &entries, &count);
    if (result != 0 || count != 0) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    return 1;
}

/* Test parsing single IPv4 */
static int test_whitelist_parse_ipv4_single(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    int result = crowdsec_parse_whitelist("192.168.1.1", &entries, &count);
    if (result != 0 || count != 1) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    if (entries[0].family != AF_INET || entries[0].prefix_len != 32) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    crowdsec_free_whitelist(entries);
    return 1;
}

/* Test parsing IPv4 CIDR */
static int test_whitelist_parse_ipv4_cidr(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    int result = crowdsec_parse_whitelist("10.0.0.0/8", &entries, &count);
    if (result != 0 || count != 1) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    if (entries[0].family != AF_INET || entries[0].prefix_len != 8) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    crowdsec_free_whitelist(entries);
    return 1;
}

/* Test parsing single IPv6 */
static int test_whitelist_parse_ipv6_single(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    int result = crowdsec_parse_whitelist("::1", &entries, &count);
    if (result != 0 || count != 1) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    if (entries[0].family != AF_INET6 || entries[0].prefix_len != 128) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    crowdsec_free_whitelist(entries);
    return 1;
}

/* Test parsing IPv6 CIDR */
static int test_whitelist_parse_ipv6_cidr(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    int result = crowdsec_parse_whitelist("2001:db8::/32", &entries, &count);
    if (result != 0 || count != 1) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    if (entries[0].family != AF_INET6 || entries[0].prefix_len != 32) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    crowdsec_free_whitelist(entries);
    return 1;
}

/* Test parsing mixed list */
static int test_whitelist_parse_mixed(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    int result = crowdsec_parse_whitelist("192.168.1.0/24, 10.0.0.1, 2001:db8::/32, ::1", &entries, &count);
    if (result != 0 || count != 4) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    /* Check IPv4 CIDR */
    if (entries[0].family != AF_INET || entries[0].prefix_len != 24) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    /* Check single IPv4 */
    if (entries[1].family != AF_INET || entries[1].prefix_len != 32) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    /* Check IPv6 CIDR */
    if (entries[2].family != AF_INET6 || entries[2].prefix_len != 32) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    /* Check single IPv6 */
    if (entries[3].family != AF_INET6 || entries[3].prefix_len != 128) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    crowdsec_free_whitelist(entries);
    return 1;
}

/* Test whitelist matching */
static int test_whitelist_match(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    int result = crowdsec_parse_whitelist("192.168.1.0/24, 10.0.0.1, 2001:db8::/32", &entries, &count);
    if (result != 0 || count != 3) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    crowdsec_config_t config = {
        .enabled = true,
        .url = "http://localhost:8080",
        .timeout = 5,
        .fail_open = true,
        .verify_ssl = false,
        .bouncer_key = "test-key",
        .action = CS_ACTION_REJECT,
        .whitelist = entries,
        .whitelist_count = count
    };

    crowdsec_context_t *ctx = crowdsec_init(&config);
    /* Free original entries - crowdsec_init made a deep copy */
    crowdsec_free_whitelist(entries);
    if (!ctx) {
        return 0;
    }

    /* Test matching IPs */
    if (!crowdsec_is_whitelisted(ctx, "192.168.1.100")) {
        crowdsec_destroy(ctx);
        return 0;
    }
    if (!crowdsec_is_whitelisted(ctx, "10.0.0.1")) {
        crowdsec_destroy(ctx);
        return 0;
    }
    if (!crowdsec_is_whitelisted(ctx, "2001:db8::1")) {
        crowdsec_destroy(ctx);
        return 0;
    }

    /* Test non-matching IPs */
    if (crowdsec_is_whitelisted(ctx, "192.168.2.1")) {
        crowdsec_destroy(ctx);
        return 0;
    }
    if (crowdsec_is_whitelisted(ctx, "10.0.0.2")) {
        crowdsec_destroy(ctx);
        return 0;
    }
    if (crowdsec_is_whitelisted(ctx, "2001:db9::1")) {
        crowdsec_destroy(ctx);
        return 0;
    }

    crowdsec_destroy(ctx);
    return 1;
}

/* Test invalid entries are skipped */
static int test_whitelist_invalid_entries(void)
{
    crowdsec_whitelist_entry_t *entries = NULL;
    int count = 0;

    /* Mix of valid and invalid entries */
    int result = crowdsec_parse_whitelist("192.168.1.1, invalid, 10.0.0.1, not.an.ip, ::1", &entries, &count);
    if (result != 0) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    /* Should have parsed 3 valid entries */
    if (count != 3) {
        crowdsec_free_whitelist(entries);
        return 0;
    }

    crowdsec_free_whitelist(entries);
    return 1;
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

    printf("\nWhitelist tests:\n");
    TEST(whitelist_parse_empty);
    TEST(whitelist_parse_ipv4_single);
    TEST(whitelist_parse_ipv4_cidr);
    TEST(whitelist_parse_ipv6_single);
    TEST(whitelist_parse_ipv6_cidr);
    TEST(whitelist_parse_mixed);
    TEST(whitelist_match);
    TEST(whitelist_invalid_entries);

    printf("\n==========================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return tests_passed == tests_run ? 0 : 1;
}
