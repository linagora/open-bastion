/*
 * test_client_context.c - Unit tests for client context
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client_context.h"

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

/* Test high risk service detection */
static int test_high_risk_single(void)
{
    client_context_t ctx = {0};
    ctx.service = strdup("sudo");

    bool result = client_context_is_high_risk(&ctx, "sudo");

    free(ctx.service);
    return result == true;
}

static int test_high_risk_list(void)
{
    client_context_t ctx = {0};
    ctx.service = strdup("su");

    bool result = client_context_is_high_risk(&ctx, "sudo,su,ssh");

    free(ctx.service);
    return result == true;
}

static int test_high_risk_not_in_list(void)
{
    client_context_t ctx = {0};
    ctx.service = strdup("login");

    bool result = client_context_is_high_risk(&ctx, "sudo,su,ssh");

    free(ctx.service);
    return result == false;
}

static int test_high_risk_with_spaces(void)
{
    client_context_t ctx = {0};
    ctx.service = strdup("ssh");

    bool result = client_context_is_high_risk(&ctx, "sudo, su, ssh");

    free(ctx.service);
    return result == true;
}

static int test_high_risk_null_service(void)
{
    client_context_t ctx = {0};
    ctx.service = NULL;

    bool result = client_context_is_high_risk(&ctx, "sudo,su");

    return result == false;
}

static int test_high_risk_null_list(void)
{
    client_context_t ctx = {0};
    ctx.service = strdup("sudo");

    bool result = client_context_is_high_risk(&ctx, NULL);

    free(ctx.service);
    return result == false;
}

/* Test cache TTL selection */
static int test_cache_ttl_normal(void)
{
    client_context_t ctx = {0};
    ctx.service = strdup("login");

    int ttl = client_context_get_cache_ttl(&ctx, 300, 60, "sudo,su");

    free(ctx.service);
    return (ttl == 300);
}

static int test_cache_ttl_high_risk(void)
{
    client_context_t ctx = {0};
    ctx.service = strdup("sudo");

    int ttl = client_context_get_cache_ttl(&ctx, 300, 60, "sudo,su");

    free(ctx.service);
    return (ttl == 60);
}

/* Test rate key building */
static int test_build_rate_key(void)
{
    client_context_t ctx = {0};
    ctx.username = strdup("alice");
    ctx.client_ip = strdup("192.168.1.100");

    client_context_build_rate_key(&ctx);

    int ok = (ctx.rate_limit_key != NULL &&
              strcmp(ctx.rate_limit_key, "alice:192.168.1.100") == 0);

    free(ctx.username);
    free(ctx.client_ip);
    free(ctx.rate_limit_key);
    return ok;
}

static int test_build_rate_key_null_user(void)
{
    client_context_t ctx = {0};
    ctx.username = NULL;
    ctx.client_ip = strdup("10.0.0.1");

    client_context_build_rate_key(&ctx);

    int ok = (ctx.rate_limit_key != NULL &&
              strcmp(ctx.rate_limit_key, "unknown:10.0.0.1") == 0);

    free(ctx.client_ip);
    free(ctx.rate_limit_key);
    return ok;
}

static int test_build_rate_key_null_ip(void)
{
    client_context_t ctx = {0};
    ctx.username = strdup("bob");
    ctx.client_ip = NULL;

    client_context_build_rate_key(&ctx);

    int ok = (ctx.rate_limit_key != NULL &&
              strcmp(ctx.rate_limit_key, "bob:local") == 0);

    free(ctx.username);
    free(ctx.rate_limit_key);
    return ok;
}

/* Test fingerprint generation */
static int test_fingerprint_generation(void)
{
    client_context_t ctx = {0};
    ctx.username = strdup("testuser");
    ctx.client_ip = strdup("192.168.1.1");
    ctx.service = strdup("sshd");

    client_context_generate_fingerprint(&ctx);

    int ok = (ctx.fingerprint != NULL && strlen(ctx.fingerprint) == 64);

    free(ctx.username);
    free(ctx.client_ip);
    free(ctx.service);
    free(ctx.fingerprint);
    return ok;
}

static int test_fingerprint_deterministic(void)
{
    /* Same input should produce same fingerprint */
    client_context_t ctx1 = {0};
    ctx1.username = strdup("testuser");
    ctx1.client_ip = strdup("192.168.1.1");
    ctx1.service = strdup("sshd");
    client_context_generate_fingerprint(&ctx1);

    client_context_t ctx2 = {0};
    ctx2.username = strdup("testuser");
    ctx2.client_ip = strdup("192.168.1.1");
    ctx2.service = strdup("sshd");
    client_context_generate_fingerprint(&ctx2);

    int ok = (ctx1.fingerprint != NULL && ctx2.fingerprint != NULL &&
              strcmp(ctx1.fingerprint, ctx2.fingerprint) == 0);

    free(ctx1.username);
    free(ctx1.client_ip);
    free(ctx1.service);
    free(ctx1.fingerprint);
    free(ctx2.username);
    free(ctx2.client_ip);
    free(ctx2.service);
    free(ctx2.fingerprint);
    return ok;
}

static int test_fingerprint_different_input(void)
{
    /* Different input should produce different fingerprint */
    client_context_t ctx1 = {0};
    ctx1.username = strdup("alice");
    ctx1.client_ip = strdup("192.168.1.1");
    ctx1.service = strdup("sshd");
    client_context_generate_fingerprint(&ctx1);

    client_context_t ctx2 = {0};
    ctx2.username = strdup("bob");
    ctx2.client_ip = strdup("192.168.1.1");
    ctx2.service = strdup("sshd");
    client_context_generate_fingerprint(&ctx2);

    int ok = (ctx1.fingerprint != NULL && ctx2.fingerprint != NULL &&
              strcmp(ctx1.fingerprint, ctx2.fingerprint) != 0);

    free(ctx1.username);
    free(ctx1.client_ip);
    free(ctx1.service);
    free(ctx1.fingerprint);
    free(ctx2.username);
    free(ctx2.client_ip);
    free(ctx2.service);
    free(ctx2.fingerprint);
    return ok;
}

/* Test context free */
static int test_context_free_null(void)
{
    /* Should not crash */
    client_context_free(NULL);
    return 1;
}

int main(void)
{
    printf("Running client context tests...\n\n");

    TEST(high_risk_single);
    TEST(high_risk_list);
    TEST(high_risk_not_in_list);
    TEST(high_risk_with_spaces);
    TEST(high_risk_null_service);
    TEST(high_risk_null_list);
    TEST(cache_ttl_normal);
    TEST(cache_ttl_high_risk);
    TEST(build_rate_key);
    TEST(build_rate_key_null_user);
    TEST(build_rate_key_null_ip);
    TEST(fingerprint_generation);
    TEST(fingerprint_deterministic);
    TEST(fingerprint_different_input);
    TEST(context_free_null);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
