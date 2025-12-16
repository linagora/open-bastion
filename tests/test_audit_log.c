/*
 * test_audit_log.c - Unit tests for audit logging
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

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

static const char *test_log_file = "/tmp/test_pam_llng_audit.json";

/* Cleanup */
static void cleanup(void)
{
    unlink(test_log_file);
}

/* Test event type strings */
static int test_event_type_str(void)
{
    int ok = 1;

    ok = ok && (strcmp(audit_event_type_str(AUDIT_AUTH_SUCCESS), "AUTH_SUCCESS") == 0);
    ok = ok && (strcmp(audit_event_type_str(AUDIT_AUTH_FAILURE), "AUTH_FAILURE") == 0);
    ok = ok && (strcmp(audit_event_type_str(AUDIT_RATE_LIMITED), "RATE_LIMITED") == 0);
    ok = ok && (strcmp(audit_event_type_str(AUDIT_SECURITY_ERROR), "SECURITY_ERROR") == 0);
    ok = ok && (strcmp(audit_event_type_str((audit_event_type_t)999), "UNKNOWN") == 0);

    return ok;
}

/* Test correlation ID generation */
static int test_correlation_id(void)
{
    char id1[37] = {0};
    char id2[37] = {0};

    audit_generate_correlation_id(id1, sizeof(id1));
    audit_generate_correlation_id(id2, sizeof(id2));

    /* Check format: 8-4-4-4-12 */
    int ok = 1;
    ok = ok && (strlen(id1) == 36);
    ok = ok && (id1[8] == '-');
    ok = ok && (id1[13] == '-');
    ok = ok && (id1[18] == '-');
    ok = ok && (id1[23] == '-');

    /* IDs should be different */
    ok = ok && (strcmp(id1, id2) != 0);

    return ok;
}

/* Test buffer too small for correlation ID */
static int test_correlation_id_small_buffer(void)
{
    char id[10] = "unchanged";

    audit_generate_correlation_id(id, sizeof(id));

    /* Should set to empty string when buffer too small */
    return (id[0] == '\0');
}

/* Test audit context initialization */
static int test_init(void)
{
    audit_config_t config = {
        .enabled = true,
        .log_file = (char *)test_log_file,
        .log_to_syslog = false,
        .level = 2
    };

    audit_context_t *ctx = audit_init(&config);
    if (!ctx) return 0;

    audit_destroy(ctx);
    return 1;
}

/* Test event initialization */
static int test_event_init(void)
{
    audit_event_t event;
    audit_event_init(&event, AUDIT_AUTH_SUCCESS);

    int ok = 1;
    ok = ok && (event.event_type == AUDIT_AUTH_SUCCESS);
    ok = ok && (strlen(event.correlation_id) == 36);
    ok = ok && (event.start_time.tv_sec > 0);

    return ok;
}

/* Test latency calculation */
static int test_latency(void)
{
    audit_event_t event;
    audit_event_init(&event, AUDIT_AUTH_SUCCESS);

    /* Simulate some time passing */
    usleep(50000);  /* 50ms */

    audit_event_set_end_time(&event);

    long latency = audit_event_latency_ms(&event);

    /* Should be at least 50ms but less than 500ms */
    return (latency >= 40 && latency < 500);
}

/* Test logging to file */
static int test_log_to_file(void)
{
    cleanup();

    audit_config_t config = {
        .enabled = true,
        .log_file = (char *)test_log_file,
        .log_to_syslog = false,
        .level = 2
    };

    audit_context_t *ctx = audit_init(&config);
    if (!ctx) return 0;

    audit_event_t event;
    audit_event_init(&event, AUDIT_AUTH_SUCCESS);
    event.user = "testuser";
    event.service = "sshd";
    event.client_ip = "192.168.1.100";
    event.result_code = 0;
    audit_event_set_end_time(&event);

    int ret = audit_log_event(ctx, &event);
    audit_destroy(ctx);

    if (ret != 0) return 0;

    /* Check file was created and contains JSON */
    FILE *f = fopen(test_log_file, "r");
    if (!f) return 0;

    char line[4096];
    int ok = 0;
    if (fgets(line, sizeof(line), f)) {
        /* Check for key JSON fields */
        ok = (strstr(line, "\"event_type\":\"AUTH_SUCCESS\"") != NULL);
        ok = ok && (strstr(line, "\"user\":\"testuser\"") != NULL);
        ok = ok && (strstr(line, "\"service\":\"sshd\"") != NULL);
        ok = ok && (strstr(line, "\"client_ip\":\"192.168.1.100\"") != NULL);
    }
    fclose(f);

    cleanup();
    return ok;
}

/* Test level filtering */
static int test_level_filtering(void)
{
    cleanup();

    audit_config_t config = {
        .enabled = true,
        .log_file = (char *)test_log_file,
        .log_to_syslog = false,
        .level = 0  /* Only critical events */
    };

    audit_context_t *ctx = audit_init(&config);
    if (!ctx) return 0;

    /* AUTH_SUCCESS is level 1, should be filtered */
    audit_event_t event;
    audit_event_init(&event, AUDIT_AUTH_SUCCESS);
    event.user = "testuser";
    audit_event_set_end_time(&event);

    audit_log_event(ctx, &event);
    audit_destroy(ctx);

    /* File should not exist or be empty (event filtered) */
    struct stat st;
    int ok = (stat(test_log_file, &st) != 0 || st.st_size == 0);

    cleanup();
    return ok;
}

/* Test disabled audit */
static int test_disabled(void)
{
    cleanup();

    audit_config_t config = {
        .enabled = false,
        .log_file = (char *)test_log_file,
        .log_to_syslog = false,
        .level = 2
    };

    audit_context_t *ctx = audit_init(&config);
    if (!ctx) return 0;

    audit_event_t event;
    audit_event_init(&event, AUDIT_AUTH_SUCCESS);
    event.user = "testuser";
    audit_event_set_end_time(&event);

    int ret = audit_log_event(ctx, &event);
    audit_destroy(ctx);

    /* Should return 0 (success) but not write anything */
    if (ret != 0) return 0;

    struct stat st;
    int ok = (stat(test_log_file, &st) != 0);  /* File should not exist */

    cleanup();
    return ok;
}

/* Test convenience function */
static int test_audit_log_convenience(void)
{
    cleanup();

    audit_config_t config = {
        .enabled = true,
        .log_file = (char *)test_log_file,
        .log_to_syslog = false,
        .level = 2
    };

    audit_context_t *ctx = audit_init(&config);
    if (!ctx) return 0;

    int ret = audit_log(ctx, AUDIT_AUTH_FAILURE, "alice", "sudo",
                        "10.0.0.50", 1, "Invalid token");
    audit_destroy(ctx);

    if (ret != 0) return 0;

    /* Check file content */
    FILE *f = fopen(test_log_file, "r");
    if (!f) return 0;

    char line[4096];
    int ok = 0;
    if (fgets(line, sizeof(line), f)) {
        ok = (strstr(line, "\"event_type\":\"AUTH_FAILURE\"") != NULL);
        ok = ok && (strstr(line, "\"user\":\"alice\"") != NULL);
        ok = ok && (strstr(line, "\"reason\":\"Invalid token\"") != NULL);
    }
    fclose(f);

    cleanup();
    return ok;
}

int main(void)
{
    printf("Running audit log tests...\n\n");

    cleanup();

    TEST(event_type_str);
    TEST(correlation_id);
    TEST(correlation_id_small_buffer);
    TEST(init);
    TEST(event_init);
    TEST(latency);
    TEST(log_to_file);
    TEST(level_filtering);
    TEST(disabled);
    TEST(audit_log_convenience);

    cleanup();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
