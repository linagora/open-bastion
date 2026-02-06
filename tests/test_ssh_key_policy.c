/*
 * test_ssh_key_policy.c - Unit tests for SSH key policy enforcement
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssh_key_policy.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running %s... ", #name); \
    test_##name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAILED at %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
        tests_failed++; \
        return; \
    } \
} while(0)

/* Test policy initialization */
TEST(policy_init)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);

    /* Default: all modern types allowed */
    ASSERT(policy.allow_rsa == true);
    ASSERT(policy.allow_ed25519 == true);
    ASSERT(policy.allow_ecdsa == true);
    ASSERT(policy.allow_dsa == false);  /* DSA deprecated */
    ASSERT(policy.allow_sk == true);
    ASSERT(policy.min_rsa_bits == 2048);
    ASSERT(policy.min_ecdsa_bits == 256);
    ASSERT(policy.enabled == false);  /* Disabled by default */
}

/* Test parsing allowed types */
TEST(parse_types_single)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);

    /* Parse single type */
    ASSERT(ssh_key_policy_parse_types(&policy, "ed25519") == 0);
    ASSERT(policy.allow_ed25519 == true);
    ASSERT(policy.allow_rsa == false);
    ASSERT(policy.allow_ecdsa == false);
}

TEST(parse_types_multiple)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);

    /* Parse multiple types */
    ASSERT(ssh_key_policy_parse_types(&policy, "ed25519,ecdsa,rsa") == 0);
    ASSERT(policy.allow_ed25519 == true);
    ASSERT(policy.allow_rsa == true);
    ASSERT(policy.allow_ecdsa == true);
    ASSERT(policy.allow_dsa == false);
}

TEST(parse_types_all)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);

    /* Parse "all" */
    ASSERT(ssh_key_policy_parse_types(&policy, "all") == 0);
    ASSERT(policy.allow_ed25519 == true);
    ASSERT(policy.allow_rsa == true);
    ASSERT(policy.allow_ecdsa == true);
    ASSERT(policy.allow_sk == true);
    ASSERT(policy.allow_dsa == false);  /* all does not include DSA */
}

TEST(parse_types_with_dsa)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);

    /* Explicit DSA */
    ASSERT(ssh_key_policy_parse_types(&policy, "dsa,rsa") == 0);
    ASSERT(policy.allow_dsa == true);
    ASSERT(policy.allow_rsa == true);
    ASSERT(policy.allow_ed25519 == false);
}

TEST(parse_types_fido2)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);

    /* FIDO2/Security keys */
    ASSERT(ssh_key_policy_parse_types(&policy, "sk") == 0);
    ASSERT(policy.allow_sk == true);
    ASSERT(policy.allow_ed25519 == false);

    /* Alias fido2 */
    ssh_key_policy_init(&policy);
    ASSERT(ssh_key_policy_parse_types(&policy, "fido2,ed25519") == 0);
    ASSERT(policy.allow_sk == true);
    ASSERT(policy.allow_ed25519 == true);
}

TEST(parse_types_whitespace)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);

    /* Handle whitespace */
    ASSERT(ssh_key_policy_parse_types(&policy, " ed25519 , rsa , ecdsa ") == 0);
    ASSERT(policy.allow_ed25519 == true);
    ASSERT(policy.allow_rsa == true);
    ASSERT(policy.allow_ecdsa == true);
}

/* Test algorithm parsing */
TEST(parse_algorithm_ed25519)
{
    ASSERT(ssh_key_parse_algorithm("ssh-ed25519") == SSH_KEY_TYPE_ED25519);
}

TEST(parse_algorithm_rsa)
{
    ASSERT(ssh_key_parse_algorithm("ssh-rsa") == SSH_KEY_TYPE_RSA);
    ASSERT(ssh_key_parse_algorithm("rsa-sha2-256") == SSH_KEY_TYPE_RSA);
    ASSERT(ssh_key_parse_algorithm("rsa-sha2-512") == SSH_KEY_TYPE_RSA);
}

TEST(parse_algorithm_ecdsa)
{
    ASSERT(ssh_key_parse_algorithm("ecdsa-sha2-nistp256") == SSH_KEY_TYPE_ECDSA_256);
    ASSERT(ssh_key_parse_algorithm("ecdsa-sha2-nistp384") == SSH_KEY_TYPE_ECDSA_384);
    ASSERT(ssh_key_parse_algorithm("ecdsa-sha2-nistp521") == SSH_KEY_TYPE_ECDSA_521);
}

TEST(parse_algorithm_dsa)
{
    ASSERT(ssh_key_parse_algorithm("ssh-dss") == SSH_KEY_TYPE_DSA);
}

TEST(parse_algorithm_fido2)
{
    ASSERT(ssh_key_parse_algorithm("sk-ssh-ed25519@openssh.com") == SSH_KEY_TYPE_SK_ED25519);
    ASSERT(ssh_key_parse_algorithm("sk-ecdsa-sha2-nistp256@openssh.com") == SSH_KEY_TYPE_SK_ECDSA);
}

TEST(parse_algorithm_cert)
{
    /* Certificate types should extract base algorithm */
    ASSERT(ssh_key_parse_algorithm("ssh-ed25519-cert-v01@openssh.com") == SSH_KEY_TYPE_ED25519);
    ASSERT(ssh_key_parse_algorithm("ssh-rsa-cert-v01@openssh.com") == SSH_KEY_TYPE_RSA);
    ASSERT(ssh_key_parse_algorithm("ecdsa-sha2-nistp256-cert-v01@openssh.com") == SSH_KEY_TYPE_ECDSA_256);
}

TEST(parse_algorithm_unknown)
{
    ASSERT(ssh_key_parse_algorithm("unknown-algo") == SSH_KEY_TYPE_UNKNOWN);
    ASSERT(ssh_key_parse_algorithm("") == SSH_KEY_TYPE_UNKNOWN);
    ASSERT(ssh_key_parse_algorithm(NULL) == SSH_KEY_TYPE_UNKNOWN);
}

/* Test key type bits */
TEST(key_type_bits)
{
    ASSERT(ssh_key_type_bits(SSH_KEY_TYPE_ED25519) == 256);
    ASSERT(ssh_key_type_bits(SSH_KEY_TYPE_ECDSA_256) == 256);
    ASSERT(ssh_key_type_bits(SSH_KEY_TYPE_ECDSA_384) == 384);
    ASSERT(ssh_key_type_bits(SSH_KEY_TYPE_ECDSA_521) == 521);
    ASSERT(ssh_key_type_bits(SSH_KEY_TYPE_DSA) == 1024);
    ASSERT(ssh_key_type_bits(SSH_KEY_TYPE_RSA) == 0);  /* Unknown for RSA */
    ASSERT(ssh_key_type_bits(SSH_KEY_TYPE_UNKNOWN) == 0);
}

/* Test key type names */
TEST(key_type_name)
{
    ASSERT_STR_EQ(ssh_key_type_name(SSH_KEY_TYPE_ED25519), "Ed25519");
    ASSERT_STR_EQ(ssh_key_type_name(SSH_KEY_TYPE_RSA), "RSA");
    ASSERT_STR_EQ(ssh_key_type_name(SSH_KEY_TYPE_ECDSA_256), "ECDSA-256");
    ASSERT_STR_EQ(ssh_key_type_name(SSH_KEY_TYPE_DSA), "DSA");
    ASSERT_STR_EQ(ssh_key_type_name(SSH_KEY_TYPE_SK_ED25519), "SK-Ed25519");
    ASSERT_STR_EQ(ssh_key_type_name(SSH_KEY_TYPE_UNKNOWN), "Unknown");
}

/* Test policy checking */
TEST(policy_check_disabled)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = false;  /* Policy disabled */

    /* When disabled, everything should be allowed */
    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa", &result) == true);
    ASSERT(result.valid == true);

    ASSERT(ssh_key_policy_check(&policy, "ssh-dss", &result) == true);
    ASSERT(result.valid == true);
}

TEST(policy_check_ed25519_allowed)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-ed25519", &result) == true);
    ASSERT(result.valid == true);
    ASSERT(result.type == SSH_KEY_TYPE_ED25519);
    ASSERT(result.key_bits == 256);
}

TEST(policy_check_ed25519_denied)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.allow_ed25519 = false;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-ed25519", &result) == false);
    ASSERT(result.valid == false);
    ASSERT(result.error != NULL);
}

TEST(policy_check_rsa_allowed)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa", &result) == true);
    ASSERT(result.valid == true);
    ASSERT(result.type == SSH_KEY_TYPE_RSA);
}

TEST(policy_check_rsa_denied)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.allow_rsa = false;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa", &result) == false);
    ASSERT(result.valid == false);
    ASSERT(result.error != NULL);
}

TEST(policy_check_ecdsa_min_bits)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.min_ecdsa_bits = 384;  /* Require P-384 or higher */

    ssh_key_validation_result_t result;

    /* P-256 should fail */
    ASSERT(ssh_key_policy_check(&policy, "ecdsa-sha2-nistp256", &result) == false);
    ASSERT(result.valid == false);

    /* P-384 should pass */
    ASSERT(ssh_key_policy_check(&policy, "ecdsa-sha2-nistp384", &result) == true);
    ASSERT(result.valid == true);

    /* P-521 should pass */
    ASSERT(ssh_key_policy_check(&policy, "ecdsa-sha2-nistp521", &result) == true);
    ASSERT(result.valid == true);
}

TEST(policy_check_dsa_denied_by_default)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-dss", &result) == false);
    ASSERT(result.valid == false);
    ASSERT(result.error != NULL);
}

TEST(policy_check_fido2_allowed)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "sk-ssh-ed25519@openssh.com", &result) == true);
    ASSERT(result.valid == true);
    ASSERT(result.type == SSH_KEY_TYPE_SK_ED25519);

    ASSERT(ssh_key_policy_check(&policy, "sk-ecdsa-sha2-nistp256@openssh.com", &result) == true);
    ASSERT(result.valid == true);
    ASSERT(result.type == SSH_KEY_TYPE_SK_ECDSA);
}

TEST(policy_check_fido2_denied)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.allow_sk = false;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "sk-ssh-ed25519@openssh.com", &result) == false);
    ASSERT(result.valid == false);
}

TEST(policy_check_certificate)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ssh_key_validation_result_t result;

    /* Ed25519 certificate should be allowed */
    ASSERT(ssh_key_policy_check(&policy, "ssh-ed25519-cert-v01@openssh.com", &result) == true);
    ASSERT(result.valid == true);
    ASSERT(result.type == SSH_KEY_TYPE_ED25519);

    /* RSA certificate should be allowed */
    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa-cert-v01@openssh.com", &result) == true);
    ASSERT(result.valid == true);
    ASSERT(result.type == SSH_KEY_TYPE_RSA);
}

TEST(policy_check_unknown_rejected)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "unknown-algorithm", &result) == false);
    ASSERT(result.valid == false);
    ASSERT(result.type == SSH_KEY_TYPE_UNKNOWN);
}

TEST(policy_check_null_result)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;

    /* Should work with NULL result */
    ASSERT(ssh_key_policy_check(&policy, "ssh-ed25519", NULL) == true);
    ASSERT(ssh_key_policy_check(&policy, "ssh-dss", NULL) == false);
}

TEST(rsa_size_check)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.min_rsa_bits = 3072;

    ASSERT(ssh_key_policy_check_rsa_size(&policy, 2048) == false);
    ASSERT(ssh_key_policy_check_rsa_size(&policy, 3072) == true);
    ASSERT(ssh_key_policy_check_rsa_size(&policy, 4096) == true);
}

/* Test real-world scenarios */
TEST(scenario_strict_modern)
{
    /* Strict modern policy: only Ed25519 */
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    ssh_key_policy_parse_types(&policy, "ed25519");

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-ed25519", &result) == true);
    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa", &result) == false);
    ASSERT(ssh_key_policy_check(&policy, "ecdsa-sha2-nistp256", &result) == false);
}

TEST(scenario_no_rsa)
{
    /* Allow everything except RSA */
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    ssh_key_policy_parse_types(&policy, "ed25519,ecdsa,sk");

    ssh_key_validation_result_t result;
    ASSERT(ssh_key_policy_check(&policy, "ssh-ed25519", &result) == true);
    ASSERT(ssh_key_policy_check(&policy, "ecdsa-sha2-nistp256", &result) == true);
    ASSERT(ssh_key_policy_check(&policy, "sk-ssh-ed25519@openssh.com", &result) == true);
    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa", &result) == false);
}

TEST(scenario_enterprise_fips)
{
    /* FIPS-like policy: ECDSA P-384+ or RSA 3072+ */
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    ssh_key_policy_parse_types(&policy, "ecdsa,rsa");
    policy.min_ecdsa_bits = 384;
    policy.min_rsa_bits = 3072;

    ssh_key_validation_result_t result;

    /* Ed25519 rejected (not in allowed types) */
    ASSERT(ssh_key_policy_check(&policy, "ssh-ed25519", &result) == false);

    /* P-256 rejected (too small) */
    ASSERT(ssh_key_policy_check(&policy, "ecdsa-sha2-nistp256", &result) == false);

    /* P-384 allowed */
    ASSERT(ssh_key_policy_check(&policy, "ecdsa-sha2-nistp384", &result) == true);

    /* RSA allowed (size check done separately for RSA) */
    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa", &result) == true);
}

int main(void)
{
    printf("SSH Key Policy Tests\n");
    printf("====================\n\n");

    /* Policy initialization */
    RUN_TEST(policy_init);

    /* Type parsing */
    RUN_TEST(parse_types_single);
    RUN_TEST(parse_types_multiple);
    RUN_TEST(parse_types_all);
    RUN_TEST(parse_types_with_dsa);
    RUN_TEST(parse_types_fido2);
    RUN_TEST(parse_types_whitespace);

    /* Algorithm parsing */
    RUN_TEST(parse_algorithm_ed25519);
    RUN_TEST(parse_algorithm_rsa);
    RUN_TEST(parse_algorithm_ecdsa);
    RUN_TEST(parse_algorithm_dsa);
    RUN_TEST(parse_algorithm_fido2);
    RUN_TEST(parse_algorithm_cert);
    RUN_TEST(parse_algorithm_unknown);

    /* Key type bits and names */
    RUN_TEST(key_type_bits);
    RUN_TEST(key_type_name);

    /* Policy checking */
    RUN_TEST(policy_check_disabled);
    RUN_TEST(policy_check_ed25519_allowed);
    RUN_TEST(policy_check_ed25519_denied);
    RUN_TEST(policy_check_rsa_allowed);
    RUN_TEST(policy_check_rsa_denied);
    RUN_TEST(policy_check_ecdsa_min_bits);
    RUN_TEST(policy_check_dsa_denied_by_default);
    RUN_TEST(policy_check_fido2_allowed);
    RUN_TEST(policy_check_fido2_denied);
    RUN_TEST(policy_check_certificate);
    RUN_TEST(policy_check_unknown_rejected);
    RUN_TEST(policy_check_null_result);

    /* RSA size check */
    RUN_TEST(rsa_size_check);

    /* Real-world scenarios */
    RUN_TEST(scenario_strict_modern);
    RUN_TEST(scenario_no_rsa);
    RUN_TEST(scenario_enterprise_fips);

    printf("\n====================\n");
    printf("Tests: %d passed, %d failed\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
