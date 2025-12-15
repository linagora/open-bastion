/*
 * test_config.c - Unit tests for configuration parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config.h"

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

/* Test default initialization */
static int test_init_defaults(void)
{
    pam_llng_config_t config;
    config_init(&config);

    int ok = 1;
    ok = ok && (config.timeout == 10);
    ok = ok && (config.verify_ssl == true);
    ok = ok && (config.cache_enabled == true);
    ok = ok && (config.cache_ttl == 300);
    ok = ok && (config.server_group != NULL && strcmp(config.server_group, "default") == 0);

    config_free(&config);
    return ok;
}

/* Test argument parsing */
static int test_parse_args(void)
{
    pam_llng_config_t config;
    config_init(&config);

    const char *argv[] = {
        "portal_url=https://test.example.com",
        "client_id=test-client",
        "timeout=30",
        "debug",
        "no_cache"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = config_parse_args(argc, argv, &config);

    int ok = 1;
    ok = ok && (ret == 0);
    ok = ok && (config.portal_url != NULL && strcmp(config.portal_url, "https://test.example.com") == 0);
    ok = ok && (config.client_id != NULL && strcmp(config.client_id, "test-client") == 0);
    ok = ok && (config.timeout == 30);
    ok = ok && (config.log_level == 3);  /* debug */
    ok = ok && (config.cache_enabled == false);

    config_free(&config);
    return ok;
}

/* Test configuration validation */
static int test_validate_missing_portal(void)
{
    pam_llng_config_t config;
    config_init(&config);

    /* Missing portal_url should fail validation */
    int ret = config_validate(&config);

    config_free(&config);
    return (ret != 0);  /* Should return error */
}

static int test_validate_missing_credentials(void)
{
    pam_llng_config_t config;
    config_init(&config);

    config.portal_url = strdup("https://test.example.com");
    /* Missing client_id/secret - should fail unless authorize_only */

    int ret = config_validate(&config);

    config_free(&config);
    return (ret != 0);  /* Should return error */
}

static int test_validate_authorize_only(void)
{
    pam_llng_config_t config;
    config_init(&config);

    config.portal_url = strdup("https://test.example.com");
    config.authorize_only = true;
    /* In authorize_only mode, client credentials not required */

    int ret = config_validate(&config);

    config_free(&config);
    return (ret == 0);  /* Should succeed */
}

static int test_validate_complete(void)
{
    pam_llng_config_t config;
    config_init(&config);

    config.portal_url = strdup("https://test.example.com");
    config.client_id = strdup("test-client");
    config.client_secret = strdup("test-secret");

    int ret = config_validate(&config);

    config_free(&config);
    return (ret == 0);  /* Should succeed */
}

/* Test HTTPS requirement */
static int test_validate_https_required(void)
{
    pam_llng_config_t config;
    config_init(&config);

    config.portal_url = strdup("http://test.example.com");  /* HTTP, not HTTPS */
    config.client_id = strdup("test-client");
    config.client_secret = strdup("test-secret");
    config.verify_ssl = true;  /* SSL verification enabled */

    int ret = config_validate(&config);

    config_free(&config);
    return (ret == -4);  /* Should fail with -4 (HTTPS required) */
}

static int test_validate_http_allowed_insecure(void)
{
    pam_llng_config_t config;
    config_init(&config);

    config.portal_url = strdup("http://test.example.com");  /* HTTP */
    config.client_id = strdup("test-client");
    config.client_secret = strdup("test-secret");
    config.verify_ssl = false;  /* SSL verification disabled */

    int ret = config_validate(&config);

    config_free(&config);
    return (ret == 0);  /* Should succeed when verify_ssl=false */
}

/* Test create_user defaults */
static int test_create_user_defaults(void)
{
    pam_llng_config_t config;
    config_init(&config);

    int ok = 1;
    ok = ok && (config.create_user_enabled == false);
    ok = ok && (config.create_user_home_base != NULL && strcmp(config.create_user_home_base, "/home") == 0);
    ok = ok && (config.create_user_skel != NULL && strcmp(config.create_user_skel, "/etc/skel") == 0);
    ok = ok && (config.create_user_shell == NULL);
    ok = ok && (config.create_user_groups == NULL);

    config_free(&config);
    return ok;
}

/* Test create_user argument parsing */
static int test_parse_create_user_args(void)
{
    pam_llng_config_t config;
    config_init(&config);

    const char *argv[] = {
        "portal_url=https://test.example.com",
        "create_user",
        "create_user_shell=/bin/zsh",
        "create_user_groups=users,docker"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = config_parse_args(argc, argv, &config);

    int ok = 1;
    ok = ok && (ret == 0);
    ok = ok && (config.create_user_enabled == true);
    ok = ok && (config.create_user_shell != NULL && strcmp(config.create_user_shell, "/bin/zsh") == 0);
    ok = ok && (config.create_user_groups != NULL && strcmp(config.create_user_groups, "users,docker") == 0);

    config_free(&config);
    return ok;
}

/* Test no_create_user flag */
static int test_parse_no_create_user(void)
{
    pam_llng_config_t config;
    config_init(&config);
    config.create_user_enabled = true;  /* Enable first */

    const char *argv[] = {
        "no_create_user"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    config_parse_args(argc, argv, &config);

    int ok = (config.create_user_enabled == false);

    config_free(&config);
    return ok;
}

/* Test config file loading
 * Note: This test verifies file permission checks when running as root,
 * or skips permission tests when running as non-root user.
 */
static int test_load_config_file(void)
{
    /* Create a temp config file */
    const char *filename = "/tmp/test_pam_llng.conf";
    FILE *f = fopen(filename, "w");
    if (!f) return 0;

    fprintf(f, "# Test config\n");
    fprintf(f, "portal_url = https://auth.example.com\n");
    fprintf(f, "client_id = test-client\n");
    fprintf(f, "client_secret = \"test-secret\"\n");
    fprintf(f, "server_group = production\n");
    fprintf(f, "timeout = 15\n");
    fprintf(f, "verify_ssl = false\n");
    fclose(f);

    /* Set secure permissions */
    chmod(filename, 0600);

    pam_llng_config_t config;
    config_init(&config);

    int ret = config_load(filename, &config);
    unlink(filename);

    /* When not running as root, config_load will fail with -2 (not owned by root)
     * This is expected security behavior */
    if (getuid() != 0) {
        config_free(&config);
        return (ret == -2);  /* Expected: file not owned by root */
    }

    /* When running as root, full test */
    int ok = 1;
    ok = ok && (ret == 0);
    ok = ok && (config.portal_url && strcmp(config.portal_url, "https://auth.example.com") == 0);
    ok = ok && (config.client_id && strcmp(config.client_id, "test-client") == 0);
    ok = ok && (config.client_secret && strcmp(config.client_secret, "test-secret") == 0);
    ok = ok && (config.server_group && strcmp(config.server_group, "production") == 0);
    ok = ok && (config.timeout == 15);
    ok = ok && (config.verify_ssl == false);

    config_free(&config);
    return ok;
}

int main(void)
{
    printf("Running configuration tests...\n\n");

    TEST(init_defaults);
    TEST(parse_args);
    TEST(validate_missing_portal);
    TEST(validate_missing_credentials);
    TEST(validate_authorize_only);
    TEST(validate_complete);
    TEST(validate_https_required);
    TEST(validate_http_allowed_insecure);
    TEST(create_user_defaults);
    TEST(parse_create_user_args);
    TEST(parse_no_create_user);
    TEST(load_config_file);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
