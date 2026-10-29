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

/* Test SK_ECDSA respects min_ecdsa_bits (Copilot review feedback) */
TEST(policy_check_sk_ecdsa_min_bits)
{
    ssh_key_policy_t policy;
    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.min_ecdsa_bits = 384;  /* Require P-384 or higher */

    ssh_key_validation_result_t result;
    /* SK_ECDSA is always P-256 (256 bits), should fail with min_ecdsa_bits=384 */
    ASSERT(ssh_key_policy_check(&policy, "sk-ecdsa-sha2-nistp256@openssh.com", &result) == false);
    ASSERT(result.valid == false);
    ASSERT(result.type == SSH_KEY_TYPE_SK_ECDSA);
    ASSERT(result.key_bits == 256);

    /* With min_ecdsa_bits=256, SK_ECDSA should pass */
    policy.min_ecdsa_bits = 256;
    ASSERT(ssh_key_policy_check(&policy, "sk-ecdsa-sha2-nistp256@openssh.com", &result) == true);
    ASSERT(result.valid == true);
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


/* ----------------------------------------------------------------------- *
 * Real key/certificate blobs, as sshd passes them via %k.
 * Generated with ssh-keygen; sizes verified with `ssh-keygen -lf`.
 * ----------------------------------------------------------------------- */

/* ssh-keygen -t rsa -b 2048 */
static const char BLOB_RSA_2048[] =
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQCsIF+rKMSyTSilKcq0vCzGmlKuI5W2c2V1NkXR"
    "+MXl03GL3gON7PIQZ4R85gN6/4xjwE8obd4L7Zf75343Hk43j4z2HUK6/FcIaq4ja2a/"
    "vb1bXG3YvOY1KsTcL6qttSORbSi06OpZVuOWnfyyzDgiGWFC3G47RjyuMJRvEwIFRQDz"
    "ZFxuPWSe/LJTqXUkLPj72PuZacR6deQuQ71ar0yq9hB7A9MzFLHukP6I5Ea+K1t46HgZ"
    "TYDMc992gd5bGTMRakJOGI3J75Qk1jauC3ytzDSmXkV9gTHrTTm1YCvOStEnR/MEBM/v"
    "G6OFnl+6UvaPjBqtcXGu5c3xeZabMuOt";

/* ssh-keygen -t rsa -b 1024 (below the 2048 default minimum) */
static const char BLOB_RSA_1024[] =
    "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDOGb73dzqJzjgpOyvDx/K85l5FDaEL/7j3LFr5"
    "s+4tG2bv4mJ74p7qmTcOhtqH6Q1K75wVghkW82GojH3apk5zJfRb5clWD1l2stLrIpW0"
    "aMgQHPDNXeuw9yyC5eLCXTX5iA4tO8d7byx3Y+xYySpeF2rDkU4qSLOTk4FUmjXbkw==";

/* ssh-keygen -t ed25519 */
static const char BLOB_ED25519[] =
    "AAAAC3NzaC1lZDI1NTE5AAAAILsowx9DXYSSOCdnpC+9upU7TbW6thHwXvHY/128Qfrg";

/* ssh-keygen -t ecdsa -b 256 */
static const char BLOB_ECDSA_256[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKqVK1kE/jZnfx0/"
    "yx8yNWzuKCSspB0KOpSS2RHbAW+U6TbfK3R0HvG7+bQo8qLwFsvVxGqZTjekvRfsi5nU"
    "hU8=";

/* ssh-keygen -t ecdsa -b 521 */
static const char BLOB_ECDSA_521[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAuT8vxg+KxrH8E"
    "WRJ6eocXDsnBrLZNVr6zDI7rxzvd+/sa7KeIGJDTCXTwbXD8gEA2FzFGMW/4qL82FrWF"
    "dsgPHwEku6zKmzJFWZ4BMruWiIM+BrGJYYOitZjj3GMOJ7MFzrnpB/J3r9gR+J4xeiIu"
    "uQfPHNoc5VxlgrWPCMYqZT8GbA==";

/* RSA-2048 key signed into a certificate */
static const char BLOB_RSA_2048_CERT[] =
    "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgUryn8Ne+yHgGr0MP4wO8"
    "vHhz2i43v3uDLamQ6/4x+a4AAAADAQABAAABAQCsIF+rKMSyTSilKcq0vCzGmlKuI5W2"
    "c2V1NkXR+MXl03GL3gON7PIQZ4R85gN6/4xjwE8obd4L7Zf75343Hk43j4z2HUK6/FcI"
    "aq4ja2a/vb1bXG3YvOY1KsTcL6qttSORbSi06OpZVuOWnfyyzDgiGWFC3G47RjyuMJRv"
    "EwIFRQDzZFxuPWSe/LJTqXUkLPj72PuZacR6deQuQ71ar0yq9hB7A9MzFLHukP6I5Ea+"
    "K1t46HgZTYDMc992gd5bGTMRakJOGI3J75Qk1jauC3ytzDSmXkV9gTHrTTm1YCvOStEn"
    "R/MEBM/vG6OFnl+6UvaPjBqtcXGu5c3xeZabMuOtAAAAAAAAAAAAAAABAAAACXVzZXI9"
    "ZHdobwAAAAgAAAAEZHdobwAAAABqnBxkAAAAAGqcHfcAAAAAAAAAggAAABVwZXJtaXQt"
    "WDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAA"
    "ABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5w"
    "ZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCHFpmV908+"
    "+iM0ufEo7Nt+rX9Md2WoxJWEaMGnVzXb9AAAAFMAAAALc3NoLWVkMjU1MTkAAABAiOFK"
    "HVLY0aum9hh2KxTX+Lsnn2p05S3VSyZBfBQMacp6eq/FS+rxEu/50DGN1jYMoFHc63Ue"
    "5Wk1x3e7toesCg==";

/* Ed25519 key signed into a certificate */
static const char BLOB_ED25519_CERT[] =
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAICtgCu9HkdyTX1Ca"
    "E0MwPqHscltZrGqwI3B9UiJe71OWAAAAILsowx9DXYSSOCdnpC+9upU7TbW6thHwXvHY"
    "/128QfrgAAAAAAAAAAAAAAABAAAACXVzZXI9ZHdobwAAAAgAAAAEZHdobwAAAABqnBxk"
    "AAAAAGqcHfcAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Bl"
    "cm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5n"
    "AAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAA"
    "MwAAAAtzc2gtZWQyNTUxOQAAACCHFpmV908++iM0ufEo7Nt+rX9Md2WoxJWEaMGnVzXb"
    "9AAAAFMAAAALc3NoLWVkMjU1MTkAAABAUxtkh1L5b4++3ptPrwZ/qg5CpyQiCRR4Az0y"
    "Eo58YMswQ4UYKSMRcVVzafe0+8medJvUE6GZ/ZUxVHhL0VVJCA==";

/* ===================================================================== *
 * Key-blob decoding (issue #181): the RSA modulus size is only available
 * from the key material, never from the algorithm name.
 * ===================================================================== */

TEST(blob_info_rsa_2048)
{
    char algo[128];
    ssh_key_type_t type;
    int bits;

    ASSERT(ssh_key_blob_info(BLOB_RSA_2048, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ssh-rsa");
    ASSERT(type == SSH_KEY_TYPE_RSA);
    ASSERT(bits == 2048);
}

TEST(blob_info_rsa_1024)
{
    char algo[128];
    ssh_key_type_t type;
    int bits;

    ASSERT(ssh_key_blob_info(BLOB_RSA_1024, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ssh-rsa");
    ASSERT(type == SSH_KEY_TYPE_RSA);
    ASSERT(bits == 1024);
}

TEST(blob_info_ed25519)
{
    char algo[128];
    ssh_key_type_t type;
    int bits;

    ASSERT(ssh_key_blob_info(BLOB_ED25519, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ssh-ed25519");
    ASSERT(type == SSH_KEY_TYPE_ED25519);
    ASSERT(bits == 256);
}

TEST(blob_info_ecdsa)
{
    char algo[128];
    ssh_key_type_t type;
    int bits;

    ASSERT(ssh_key_blob_info(BLOB_ECDSA_256, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ecdsa-sha2-nistp256");
    ASSERT(type == SSH_KEY_TYPE_ECDSA_256);
    ASSERT(bits == 256);

    ASSERT(ssh_key_blob_info(BLOB_ECDSA_521, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ecdsa-sha2-nistp521");
    ASSERT(type == SSH_KEY_TYPE_ECDSA_521);
    ASSERT(bits == 521);
}

/* Certificates carry a nonce before the key material; the size must still
 * come out right (this is what the bastion actually presents). */
TEST(blob_info_certificate)
{
    char algo[128];
    ssh_key_type_t type;
    int bits;

    ASSERT(ssh_key_blob_info(BLOB_RSA_2048_CERT, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ssh-rsa-cert-v01@openssh.com");
    ASSERT(type == SSH_KEY_TYPE_RSA);
    ASSERT(bits == 2048);

    ASSERT(ssh_key_blob_info(BLOB_ED25519_CERT, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ssh-ed25519-cert-v01@openssh.com");
    ASSERT(type == SSH_KEY_TYPE_ED25519);
    ASSERT(bits == 256);
}

TEST(blob_info_rejects_garbage)
{
    char algo[128];
    ssh_key_type_t type = SSH_KEY_TYPE_RSA;
    int bits = 4096;

    /* NULL / empty */
    ASSERT(!ssh_key_blob_info(NULL, algo, sizeof(algo), &type, &bits));
    ASSERT(!ssh_key_blob_info("", algo, sizeof(algo), &type, &bits));

    /* Not base64 at all */
    ASSERT(!ssh_key_blob_info("not base64!!", algo, sizeof(algo), &type, &bits));

    /* Base64 alphabet but length not a multiple of 4 */
    ASSERT(!ssh_key_blob_info("AAAAB3NzaC1yc2E", algo, sizeof(algo), &type, &bits));

    /* Whitespace is refused (the spool writer never emits any) */
    ASSERT(!ssh_key_blob_info("AAAA AAAA", algo, sizeof(algo), &type, &bits));

    /* Valid base64, but the blob is truncated right after the type string */
    ASSERT(!ssh_key_blob_info("AAAAB3NzaC1yc2EA", algo, sizeof(algo), &type, &bits));

    /* Well-formed blob whose type is not a key type we know */
    ASSERT(!ssh_key_blob_info("AAAABG5vcGU=", algo, sizeof(algo), &type, &bits));

    /* Outputs are reset even on failure - no stale value can leak through */
    ASSERT(type == SSH_KEY_TYPE_UNKNOWN);
    ASSERT(bits == 0);
    ASSERT(algo[0] == '\0');
}

/* P-384 and P-521 plain keys, and an sk-ecdsa key built from the P-256
 * material above (ssh-keygen -t ecdsa). */
static const char BLOB_ECDSA_384[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBICFCaQx6tiHJCZI"
    "wGY2ar1TtaQqjxFmAL0qXq9KLooUmmtT7DlfL/kM3SQU/ufjp5uxMXggEfvBeulIy1iY"
    "LogeAVfa77Z/nvaKHoD5tn+VJpnD1UkSQ9qVqISUYEyybA==";

/* ssh-keygen -s ... -h: a host certificate over a P-256 key */
static const char BLOB_ECDSA_256_CERT[] =
    "AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgIXTI"
    "RHQhpLAb7ZdIxJ4yUxHqibnB6Y5JP7+YB7bs3XwAAAAIbmlzdHAyNTYAAABBBD7grCRd"
    "qHWaqqMkCuo+/iX1B5vUnKfFteXB8djt7G/Q5FCYND1S38vKaH1LVMcFZhLvK43asy8s"
    "PUKXWxUWQzUAAAAAAAAAAAAAAAIAAAABdAAAAAUAAAABdQAAAAAAAAAA//////////8A"
    "AAAAAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYA"
    "AABBBD+4oFKUmp7ShP35WCzL4wE/gIKW8Hw6HLBzGgEed0o7HI4ADeRFlgwnDOrmkguV"
    "B5nwg2/HQ0KF4abQAlPHuXgAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAA"
    "IBwu88hR+kFrq+01nwu783DGctF5/Hkh2a4ZL+oePdE1AAAAIQDLrFQb20jGgH7sbj33"
    "GOIGkoDv0fjMy05o4ow5jlFYOQ==";

static const char BLOB_SK_ECDSA[] =
    "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYA"
    "AABBBNdik4NzxlsdXc5+WCKB5JFjXlz6YhyNb3lijXHynBjD8vzLX3R9w9otpO1FWRCS"
    "11vOnyFarCJRrdf88F2v+MMAAAAEc3NoOg==";

/* The same keys with one field altered: the curve name disagrees with the
 * algorithm name, the point is one byte short or long, or the point is the
 * compressed (0x02/0x03) form OpenSSH does not accept for SSH keys. ssh-keygen
 * refuses every one of them as "not a public key file". */
static const char BLOB_ECDSA_256_WRONG_CURVE[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAzODQAAABBBNdik4NzxlsdXc5+"
    "WCKB5JFjXlz6YhyNb3lijXHynBjD8vzLX3R9w9otpO1FWRCS11vOnyFarCJRrdf88F2v"
    "+MM=";

static const char BLOB_ECDSA_384_WRONG_CURVE[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHA1MjEAAABhBICFCaQx6tiHJCZI"
    "wGY2ar1TtaQqjxFmAL0qXq9KLooUmmtT7DlfL/kM3SQU/ufjp5uxMXggEfvBeulIy1iY"
    "LogeAVfa77Z/nvaKHoD5tn+VJpnD1UkSQ9qVqISUYEyybA==";

static const char BLOB_ECDSA_521_WRONG_CURVE[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHAyNTYAAACFBAGJxwFndWmLqXGV"
    "aY6nKdRCLbPjEJdMOJAhxPyWAElPXBXZlt2Lg/JIgpUpJu4R03VMTadRLKox9XIfkNgT"
    "5tO+tAEkYQREPPWa1kquJamBmI78T7l3EB9NxIUYR0+i9XJOLe1bi1hZLMYgtOlw9Vge"
    "/AwNNnsWaHuJjr41DujV2JcerA==";

/* The real P-256 certificate above, its curve field changed to nistp384 */
static const char BLOB_ECDSA_256_CERT_WRONG_CURVE[] =
    "AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgTk5O"
    "Tk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk4AAAAIbmlzdHAzODQAAABBBD7grCRd"
    "qHWaqqMkCuo+/iX1B5vUnKfFteXB8djt7G/Q5FCYND1S38vKaH1LVMcFZhLvK43asy8s"
    "PUKXWxUWQzU=";

static const char BLOB_SK_ECDSA_WRONG_CURVE[] =
    "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAzODQA"
    "AABBBNdik4NzxlsdXc5+WCKB5JFjXlz6YhyNb3lijXHynBjD8vzLX3R9w9otpO1FWRCS"
    "11vOnyFarCJRrdf88F2v+MMAAAAEc3NoOg==";

static const char BLOB_ECDSA_256_SHORT_POINT[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABABNdik4NzxlsdXc5+"
    "WCKB5JFjXlz6YhyNb3lijXHynBjD8vzLX3R9w9otpO1FWRCS11vOnyFarCJRrdf88F2v"
    "+A==";

static const char BLOB_ECDSA_256_LONG_POINT[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABCBNdik4NzxlsdXc5+"
    "WCKB5JFjXlz6YhyNb3lijXHynBjD8vzLX3R9w9otpO1FWRCS11vOnyFarCJRrdf88F2v"
    "+MMA";

static const char BLOB_ECDSA_384_SHORT_POINT[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABgBICFCaQx6tiHJCZI"
    "wGY2ar1TtaQqjxFmAL0qXq9KLooUmmtT7DlfL/kM3SQU/ufjp5uxMXggEfvBeulIy1iY"
    "LogeAVfa77Z/nvaKHoD5tn+VJpnD1UkSQ9qVqISUYEyy";

static const char BLOB_ECDSA_521_LONG_POINT[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACGBAGJxwFndWmLqXGV"
    "aY6nKdRCLbPjEJdMOJAhxPyWAElPXBXZlt2Lg/JIgpUpJu4R03VMTadRLKox9XIfkNgT"
    "5tO+tAEkYQREPPWa1kquJamBmI78T7l3EB9NxIUYR0+i9XJOLe1bi1hZLMYgtOlw9Vge"
    "/AwNNnsWaHuJjr41DujV2JcerAA=";

static const char BLOB_ECDSA_256_COMPRESSED[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAAhA9dik4NzxlsdXc5+"
    "WCKB5JFjXlz6YhyNb3lijXHynBjD";

static const char BLOB_ECDSA_384_COMPRESSED[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAAAhAoCFCaQx6tiHJCZI"
    "wGY2ar1TtaQqjxFmAL0qXq9KLooU";

static const char BLOB_ECDSA_521_COMPRESSED[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAAAhAgGJxwFndWmLqXGV"
    "aY6nKdRCLbPjEJdMOJAhxPyWAElP";

static bool blob_refused(const char *blob)
{
    char algo[128];
    ssh_key_type_t type;
    int bits;
    return !ssh_key_blob_info(blob, algo, sizeof(algo), &type, &bits);
}

TEST(blob_info_ecdsa_all_curves)
{
    char algo[128];
    ssh_key_type_t type;
    int bits;

    ASSERT(ssh_key_blob_info(BLOB_ECDSA_384, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ecdsa-sha2-nistp384");
    ASSERT(type == SSH_KEY_TYPE_ECDSA_384);
    ASSERT(bits == 384);

    ASSERT(ssh_key_blob_info(BLOB_ECDSA_256_CERT, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "ecdsa-sha2-nistp256-cert-v01@openssh.com");
    ASSERT(type == SSH_KEY_TYPE_ECDSA_256);
    ASSERT(bits == 256);

    ASSERT(ssh_key_blob_info(BLOB_SK_ECDSA, algo, sizeof(algo), &type, &bits));
    ASSERT_STR_EQ(algo, "sk-ecdsa-sha2-nistp256@openssh.com");
    ASSERT(type == SSH_KEY_TYPE_SK_ECDSA);
    ASSERT(bits == 256);
}

/* The curve name the blob carries must be the one its algorithm name implies:
 * the reported size comes from the name, so a mismatch would grade the key
 * against material it does not hold (issue #401). */
TEST(blob_info_ecdsa_curve_mismatch_refused)
{
    ASSERT(blob_refused(BLOB_ECDSA_256_WRONG_CURVE));
    ASSERT(blob_refused(BLOB_ECDSA_384_WRONG_CURVE));
    ASSERT(blob_refused(BLOB_ECDSA_521_WRONG_CURVE));
    ASSERT(blob_refused(BLOB_ECDSA_256_CERT_WRONG_CURVE));
    ASSERT(blob_refused(BLOB_SK_ECDSA_WRONG_CURVE));
}

/* The point must be the uncompressed encoding of the curve's size. */
TEST(blob_info_ecdsa_point_shape_refused)
{
    ASSERT(blob_refused(BLOB_ECDSA_256_SHORT_POINT));
    ASSERT(blob_refused(BLOB_ECDSA_256_LONG_POINT));
    ASSERT(blob_refused(BLOB_ECDSA_384_SHORT_POINT));
    ASSERT(blob_refused(BLOB_ECDSA_521_LONG_POINT));
    ASSERT(blob_refused(BLOB_ECDSA_256_COMPRESSED));
    ASSERT(blob_refused(BLOB_ECDSA_384_COMPRESSED));
    ASSERT(blob_refused(BLOB_ECDSA_521_COMPRESSED));
}

/* An oversized blob is refused rather than allocated. */
TEST(blob_info_rejects_oversized)
{
    char *huge = malloc(SSH_KEY_BLOB_B64_MAX + 5);
    ASSERT(huge != NULL);
    memset(huge, 'A', SSH_KEY_BLOB_B64_MAX + 4);
    huge[SSH_KEY_BLOB_B64_MAX + 4] = '\0';
    ASSERT(!ssh_key_blob_info(huge, NULL, 0, NULL, NULL));
    free(huge);
}

/* ===================================================================== *
 * ssh_key_policy_check_key(): the RSA size check is finally wired up.
 * ===================================================================== */

TEST(check_key_rsa_size_enforced)
{
    ssh_key_policy_t policy;
    ssh_key_validation_result_t result;

    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.min_rsa_bits = 2048;

    /* Too small -> rejected (this is what R-S11 is about) */
    ASSERT(!ssh_key_policy_check_key(&policy, "ssh-rsa", 1024, &result));
    ASSERT(result.valid == false);
    ASSERT(result.key_bits == 1024);
    ASSERT(result.error != NULL);

    /* Exactly the minimum -> accepted */
    ASSERT(ssh_key_policy_check_key(&policy, "ssh-rsa", 2048, &result));
    ASSERT(result.valid == true);
    ASSERT(result.key_bits == 2048);

    /* Above the minimum -> accepted */
    ASSERT(ssh_key_policy_check_key(&policy, "ssh-rsa", 4096, &result));
    ASSERT(result.valid == true);

    /* A stricter deployment minimum is honoured */
    policy.min_rsa_bits = 3072;
    ASSERT(!ssh_key_policy_check_key(&policy, "ssh-rsa", 2048, &result));
    ASSERT(ssh_key_policy_check_key(&policy, "ssh-rsa", 3072, &result));
}

/* THE regression guard for #181: an RSA key whose size we cannot measure must
 * be DENIED, not waved through. */
TEST(check_key_rsa_unknown_size_fails_closed)
{
    ssh_key_policy_t policy;
    ssh_key_validation_result_t result;

    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ASSERT(!ssh_key_policy_check_key(&policy, "ssh-rsa", 0, &result));
    ASSERT(result.valid == false);
    ASSERT(result.type == SSH_KEY_TYPE_RSA);
    ASSERT(result.error != NULL);
    ASSERT(strstr(result.error, "could not be determined") != NULL);

    /* Same for a certificate over an RSA key */
    ASSERT(!ssh_key_policy_check_key(&policy, "ssh-rsa-cert-v01@openssh.com",
                                     0, &result));
    ASSERT(result.valid == false);
}

/* Fixed-size types need no external size information. */
TEST(check_key_fixed_size_types)
{
    ssh_key_policy_t policy;
    ssh_key_validation_result_t result;

    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ASSERT(ssh_key_policy_check_key(&policy, "ssh-ed25519", 0, &result));
    ASSERT(result.key_bits == 256);

    ASSERT(ssh_key_policy_check_key(&policy, "ecdsa-sha2-nistp384", 0, &result));
    ASSERT(result.key_bits == 384);

    /* min_ecdsa_bits is still enforced */
    policy.min_ecdsa_bits = 384;
    ASSERT(!ssh_key_policy_check_key(&policy, "ecdsa-sha2-nistp256", 0, &result));
    ASSERT(ssh_key_policy_check_key(&policy, "ecdsa-sha2-nistp384", 0, &result));
}

/* A disabled policy must behave exactly as before: allow everything, including
 * an RSA key of unknown size. This is the default configuration. */
TEST(check_key_disabled_policy_unchanged)
{
    ssh_key_policy_t policy;
    ssh_key_validation_result_t result;

    ssh_key_policy_init(&policy);
    ASSERT(policy.enabled == false);

    ASSERT(ssh_key_policy_check_key(&policy, "ssh-rsa", 0, &result));
    ASSERT(result.valid == true);
    ASSERT(ssh_key_policy_check_key(&policy, "ssh-dss", 0, &result));
    ASSERT(result.valid == true);
    ASSERT(ssh_key_policy_check_key(&policy, "some-unknown-algo", 0, &result));
    ASSERT(result.valid == true);
}

/* Missing/empty algorithm is a denial when the policy is on (fail closed). */
TEST(check_key_no_algorithm_denied)
{
    ssh_key_policy_t policy;
    ssh_key_validation_result_t result;

    ssh_key_policy_init(&policy);
    policy.enabled = true;

    ASSERT(!ssh_key_policy_check_key(&policy, NULL, 0, &result));
    ASSERT(!ssh_key_policy_check_key(&policy, "", 0, &result));
    ASSERT(!ssh_key_policy_check_key(&policy, "some-unknown-algo", 0, &result));
}

/* Contract pin: ssh_key_policy_check() is the TYPE-ONLY entry point and does
 * NOT enforce min_rsa_bits. Production code must use _check_key(); this test
 * exists so the difference stays deliberate. */
TEST(check_type_only_does_not_enforce_rsa_size)
{
    ssh_key_policy_t policy;
    ssh_key_validation_result_t result;

    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.min_rsa_bits = 4096;

    ASSERT(ssh_key_policy_check(&policy, "ssh-rsa", &result));
    ASSERT(!ssh_key_policy_check_key(&policy, "ssh-rsa", 2048, &result));
}

/* End to end: the blob sshd hands us decides whether the login is allowed. */
TEST(scenario_blob_to_policy_decision)
{
    ssh_key_policy_t policy;
    ssh_key_validation_result_t result;
    char algo[128];
    ssh_key_type_t type;
    int bits;

    ssh_key_policy_init(&policy);
    policy.enabled = true;
    policy.min_rsa_bits = 2048;

    /* RSA-1024 presented -> denied on size */
    ASSERT(ssh_key_blob_info(BLOB_RSA_1024, algo, sizeof(algo), &type, &bits));
    ASSERT(!ssh_key_policy_check_key(&policy, algo, bits, &result));

    /* RSA-2048 presented -> allowed */
    ASSERT(ssh_key_blob_info(BLOB_RSA_2048, algo, sizeof(algo), &type, &bits));
    ASSERT(ssh_key_policy_check_key(&policy, algo, bits, &result));

    /* Ed25519-only deployment: the RSA certificate is denied on type */
    ASSERT(ssh_key_policy_parse_types(&policy, "ed25519") == 0);
    ASSERT(ssh_key_blob_info(BLOB_RSA_2048_CERT, algo, sizeof(algo), &type, &bits));
    ASSERT(!ssh_key_policy_check_key(&policy, algo, bits, &result));
    ASSERT(ssh_key_blob_info(BLOB_ED25519_CERT, algo, sizeof(algo), &type, &bits));
    ASSERT(ssh_key_policy_check_key(&policy, algo, bits, &result));
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
    RUN_TEST(policy_check_sk_ecdsa_min_bits);
    RUN_TEST(policy_check_certificate);
    RUN_TEST(policy_check_unknown_rejected);
    RUN_TEST(policy_check_null_result);

    /* RSA size check */
    RUN_TEST(rsa_size_check);

    /* Real-world scenarios */
    RUN_TEST(scenario_strict_modern);
    RUN_TEST(scenario_no_rsa);
    RUN_TEST(scenario_enterprise_fips);

    /* Key blob decoding (#181) */
    RUN_TEST(blob_info_rsa_2048);
    RUN_TEST(blob_info_rsa_1024);
    RUN_TEST(blob_info_ed25519);
    RUN_TEST(blob_info_ecdsa);
    RUN_TEST(blob_info_ecdsa_all_curves);
    RUN_TEST(blob_info_ecdsa_curve_mismatch_refused);
    RUN_TEST(blob_info_ecdsa_point_shape_refused);
    RUN_TEST(blob_info_certificate);
    RUN_TEST(blob_info_rejects_garbage);
    RUN_TEST(blob_info_rejects_oversized);

    /* Enforced (fail-closed) policy check (#181) */
    RUN_TEST(check_key_rsa_size_enforced);
    RUN_TEST(check_key_rsa_unknown_size_fails_closed);
    RUN_TEST(check_key_fixed_size_types);
    RUN_TEST(check_key_disabled_policy_unchanged);
    RUN_TEST(check_key_no_algorithm_denied);
    RUN_TEST(check_type_only_does_not_enforce_rsa_size);
    RUN_TEST(scenario_blob_to_policy_decision);

    printf("\n====================\n");
    printf("Tests: %d passed, %d failed\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
