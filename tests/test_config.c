/*
 * test_config.c - Unit tests for configuration parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"
#include "ob_jws.h"

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
    pam_openbastion_config_t config;
    config_init(&config);

    int ok = 1;
    ok = ok && (config.timeout == 10);
    ok = ok && (config.verify_ssl == true);
    ok = ok && (config.server_group != NULL && strcmp(config.server_group, "default") == 0);

    config_free(&config);
    return ok;
}

/* Test argument parsing */
static int test_parse_args(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = {
        "portal_url=https://test.example.com",
        "client_id=test-client",
        "timeout=30",
        "debug"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = config_parse_args(argc, argv, &config);

    int ok = 1;
    ok = ok && (ret == 0);
    ok = ok && (config.portal_url != NULL && strcmp(config.portal_url, "https://test.example.com") == 0);
    ok = ok && (config.client_id != NULL && strcmp(config.client_id, "test-client") == 0);
    ok = ok && (config.timeout == 30);
    ok = ok && (config.log_level == 3);  /* debug */

    config_free(&config);
    return ok;
}

/* Test configuration validation */
static int test_validate_missing_portal(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    /* Missing portal_url should fail validation */
    int ret = config_validate(&config);

    config_free(&config);
    return (ret != 0);  /* Should return error */
}

static int test_validate_missing_credentials(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    config.portal_url = strdup("https://test.example.com");
    /* Missing client_id/secret - should fail unless authorize_only */

    int ret = config_validate(&config);

    config_free(&config);
    return (ret != 0);  /* Should return error */
}

static int test_validate_authorize_only(void)
{
    pam_openbastion_config_t config;
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
    pam_openbastion_config_t config;
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
    pam_openbastion_config_t config;
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
    pam_openbastion_config_t config;
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
    pam_openbastion_config_t config;
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
    pam_openbastion_config_t config;
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
    pam_openbastion_config_t config;
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

/* Test cache rate limit defaults (#92) */
static int test_cache_rate_limit_defaults(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    int ok = 1;
    ok = ok && (config.cache_rate_limit_enabled == false);
    ok = ok && (config.cache_rate_limit_max_attempts == 3);
    ok = ok && (config.cache_rate_limit_lockout_sec == 60);
    ok = ok && (config.cache_rate_limit_max_lockout_sec == 3600);

    config_free(&config);
    return ok;
}

/* Test cache rate limit argument parsing (#92) */
static int test_parse_cache_rate_limit_args(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = {
        "portal_url=https://test.example.com",
        "cache_rate_limit_enabled=true",
        "cache_rate_limit_max_attempts=5",
        "cache_rate_limit_lockout_sec=120",
        "cache_rate_limit_max_lockout_sec=7200"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = config_parse_args(argc, argv, &config);

    int ok = 1;
    ok = ok && (ret == 0);
    ok = ok && (config.cache_rate_limit_enabled == true);
    ok = ok && (config.cache_rate_limit_max_attempts == 5);
    ok = ok && (config.cache_rate_limit_lockout_sec == 120);
    ok = ok && (config.cache_rate_limit_max_lockout_sec == 7200);

    config_free(&config);
    return ok;
}

/* Test cache rate limit bounds validation (#92) */
static int test_cache_rate_limit_bounds(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    /* Test that out-of-bounds values are clamped.
     * Bounds: max_attempts [1,100], lockout_sec [1,86400], max_lockout_sec [60,86400] */
    const char *argv[] = {
        "portal_url=https://test.example.com",
        "cache_rate_limit_max_attempts=0",   /* Below minimum (1) */
        "cache_rate_limit_lockout_sec=0",    /* Below minimum (1) */
        "cache_rate_limit_max_lockout_sec=100000"  /* Above maximum (86400) */
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    config_parse_args(argc, argv, &config);

    int ok = 1;
    ok = ok && (config.cache_rate_limit_max_attempts >= 1);
    ok = ok && (config.cache_rate_limit_lockout_sec >= 1);
    ok = ok && (config.cache_rate_limit_max_lockout_sec <= 86400);

    config_free(&config);
    return ok;
}

/* Test that verify_ssl=false allows HTTP and triggers validation path */
static int test_validate_verify_ssl_false_allows_http(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    config.portal_url = strdup("http://test.example.com");
    config.client_id = strdup("test-client");
    config.client_secret = strdup("test-secret");
    config.verify_ssl = false;

    /* Should succeed - HTTP allowed when verify_ssl=false */
    int ret = config_validate(&config);

    config_free(&config);
    return (ret == 0);
}

/* Test that verify_ssl=true rejects HTTP URLs */
static int test_validate_verify_ssl_true_rejects_http(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    config.portal_url = strdup("http://test.example.com");
    config.client_id = strdup("test-client");
    config.client_secret = strdup("test-secret");
    config.verify_ssl = true;

    /* Should fail - HTTP not allowed when verify_ssl=true */
    int ret = config_validate(&config);

    config_free(&config);
    return (ret == -4);
}

/*
 * Issue #183: a boolean value that is neither a recognised true nor a
 * recognised false used to be silently treated as false. For verify_ssl that
 * meant "verify_ssl = TRUE" quietly turned TLS verification OFF. It must now
 * leave the (safe) default alone and make config_validate() fail with -6.
 */
static int test_bad_bool_is_fatal(void)
{
    static const char *bad_values[] = {
        "verify_ssl=TRUE", "verify_ssl=tru", "verify_ssl=True",
        "verify_ssl=", "verify_ssl=enabled", "verify_ssl=2",
    };
    int ok = 1;

    for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
        pam_openbastion_config_t config;
        config_init(&config);

        config.portal_url = strdup("https://test.example.com");
        config.client_id = strdup("test-client");
        config.client_secret = strdup("test-secret");

        const char *argv[] = { bad_values[i] };
        config_parse_args(1, argv, &config);

        /* Fail-closed: the safe default must survive, and validation must fail */
        ok = ok && (config.verify_ssl == true);
        ok = ok && (config.invalid_bool_value == true);
        ok = ok && (config_validate(&config) == -6);

        config_free(&config);
    }

    return ok;
}

/* Both spellings of false must still be accepted (and stay non-fatal) */
static int test_good_bool_values_accepted(void)
{
    static const struct { const char *arg; bool expected; } cases[] = {
        { "verify_ssl=true",  true  }, { "verify_ssl=yes", true  },
        { "verify_ssl=1",     true  }, { "verify_ssl=on",  true  },
        { "verify_ssl=false", false }, { "verify_ssl=no",  false },
        { "verify_ssl=0",     false }, { "verify_ssl=off", false },
    };
    int ok = 1;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pam_openbastion_config_t config;
        config_init(&config);

        config.portal_url = strdup("https://test.example.com");
        config.client_id = strdup("test-client");
        config.client_secret = strdup("test-secret");

        const char *argv[] = { cases[i].arg };
        config_parse_args(1, argv, &config);

        ok = ok && (config.verify_ssl == cases[i].expected);
        ok = ok && (config.invalid_bool_value == false);
        ok = ok && (config_validate(&config) == 0);

        config_free(&config);
    }

    return ok;
}

/* A typo on any other boolean key must be fatal too, not just verify_ssl */
static int test_bad_bool_other_key_is_fatal(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    config.portal_url = strdup("https://test.example.com");
    config.client_id = strdup("test-client");
    config.client_secret = strdup("test-secret");

    const char *argv[] = { "audit_enabled=Yes" };
    config_parse_args(1, argv, &config);

    int ok = (config.audit_enabled == true);          /* default preserved */
    ok = ok && (config_validate(&config) == -6);

    config_free(&config);
    return ok;
}

/* Signed answers: off by default, the JWKS path, no issuer override */
static int test_response_signing_defaults(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    int ok = (config.response_signing == OB_RESPONSE_SIGNING_OFF);
    ok = ok && config.sso_jwks_file
            && strcmp(config.sso_jwks_file, "/etc/open-bastion/sso-jwks.json") == 0;
    ok = ok && (config.sso_issuer == NULL);

    config_free(&config);
    return ok;
}

static int test_parse_response_signing(void)
{
    static const struct { const char *arg; int expected; } cases[] = {
        { "response_signing=off",      OB_RESPONSE_SIGNING_OFF },
        { "response_signing=prefer",   OB_RESPONSE_SIGNING_PREFER },
        { "response_signing=required", OB_RESPONSE_SIGNING_REQUIRED },
    };
    int ok = 1;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pam_openbastion_config_t config;
        config_init(&config);
        config.portal_url = strdup("https://test.example.com");
        config.client_id = strdup("test-client");
        config.client_secret = strdup("test-secret");

        const char *argv[] = { cases[i].arg, "sso_jwks_file=/etc/x/jwks.json",
                               "sso_issuer=https://issuer.example.com" };
        config_parse_args(3, argv, &config);

        ok = ok && (config.response_signing == cases[i].expected);
        ok = ok && (config_validate(&config) == 0);
        ok = ok && strcmp(config.sso_jwks_file, "/etc/x/jwks.json") == 0;
        ok = ok && strcmp(config.sso_issuer, "https://issuer.example.com") == 0;

        config_free(&config);
    }
    return ok;
}

/*
 * A mistyped mode must not run with signatures off: like an invalid boolean
 * (#183), it makes the whole configuration invalid.
 */
static int test_bad_response_signing_is_fatal(void)
{
    static const char *bad_values[] = {
        "response_signing=requried", "response_signing=Required",
        "response_signing=", "response_signing=true", "response_signing=on",
    };
    int ok = 1;

    for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
        pam_openbastion_config_t config;
        config_init(&config);
        config.portal_url = strdup("https://test.example.com");
        config.client_id = strdup("test-client");
        config.client_secret = strdup("test-secret");

        const char *argv[] = { bad_values[i] };
        config_parse_args(1, argv, &config);

        ok = ok && config.invalid_response_signing;
        ok = ok && (config_validate(&config) == -7);

        config_free(&config);
    }
    return ok;
}

/* What the PAM module hands to ob_client_init() */
static int test_client_settings(void)
{
    pam_openbastion_config_t config;
    config_init(&config);
    config.portal_url = strdup("https://test.example.com");
    config.client_id = strdup("test-client");
    config.client_secret = strdup("test-secret");
    const char *argv[] = { "response_signing=required", "timeout=7" };
    config_parse_args(2, argv, &config);

    ob_client_config_t client;
    config_client_settings(&config, &client);

    int ok = client.portal_url == config.portal_url
          && client.client_id == config.client_id
          && client.client_secret == config.client_secret
          && client.timeout == 7
          && client.verify_ssl
          && client.response_signing == OB_RESPONSE_SIGNING_REQUIRED
          && client.sso_jwks_file == config.sso_jwks_file
          && client.sso_issuer == NULL
          && client.server_token == NULL;

    config_free(&config);
    return ok;
}

/* Test insecure PAM flag disables SSL verification */
static int test_parse_insecure_flag(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    int ok = (config.verify_ssl == true);  /* Default should be true */

    const char *argv[] = { "insecure" };
    config_parse_args(1, argv, &config);

    ok = ok && (config.verify_ssl == false);  /* Should now be false */

    config_free(&config);
    return ok;
}

#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
/* Test OAuth2 token auth defaults */
static int test_oauth2_token_auth_defaults(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    int ok = 1;
    ok = ok && (config.oauth2_token_auth == false);  /* Disabled by default */
    ok = ok && (config.oauth2_token_cache == true);  /* Enabled by default */
    ok = ok && (config.oauth2_token_min_ttl == 60);  /* 60 seconds by default */

    config_free(&config);
    return ok;
}

/* Test OAuth2 token auth argument parsing */
static int test_parse_oauth2_token_auth_args(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = {
        "portal_url=https://test.example.com",
        "oauth2_token_auth",
        "oauth2_token_min_ttl=120"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = config_parse_args(argc, argv, &config);

    int ok = 1;
    ok = ok && (ret == 0);
    ok = ok && (config.oauth2_token_auth == true);
    ok = ok && (config.oauth2_token_min_ttl == 120);

    config_free(&config);
    return ok;
}

/* Test OAuth2 token auth config file parsing */
static int test_parse_oauth2_token_auth_config(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = {
        "oauth2_token_auth=true",
        "oauth2_token_cache=false",
        "oauth2_token_min_ttl=300"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = config_parse_args(argc, argv, &config);

    int ok = 1;
    ok = ok && (ret == 0);
    ok = ok && (config.oauth2_token_auth == true);
    ok = ok && (config.oauth2_token_cache == false);
    ok = ok && (config.oauth2_token_min_ttl == 300);

    config_free(&config);
    return ok;
}

/* Test no_oauth2_token_cache flag */
static int test_parse_no_oauth2_token_cache(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = {
        "no_oauth2_token_cache"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    config_parse_args(argc, argv, &config);

    int ok = (config.oauth2_token_cache == false);

    config_free(&config);
    return ok;
}

/* Test OAuth2 token min_ttl bounds */
static int test_oauth2_token_min_ttl_bounds(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    /* Test value above max (3600) - should use default */
    const char *argv1[] = { "oauth2_token_min_ttl=9999" };
    config_parse_args(1, argv1, &config);
    int ok = (config.oauth2_token_min_ttl == 60);  /* Default value */

    /* Test value at max boundary */
    config_free(&config);
    config_init(&config);
    const char *argv2[] = { "oauth2_token_min_ttl=3600" };
    config_parse_args(1, argv2, &config);
    ok = ok && (config.oauth2_token_min_ttl == 3600);

    /* Test value of 0 (valid) */
    config_free(&config);
    config_init(&config);
    const char *argv3[] = { "oauth2_token_min_ttl=0" };
    config_parse_args(1, argv3, &config);
    ok = ok && (config.oauth2_token_min_ttl == 0);

    config_free(&config);
    return ok;
}
#endif /* ENABLE_DESKTOP_SSO */

/* Test config file loading
 * Note: This test verifies file permission checks when running as root,
 * or skips permission tests when running as non-root user.
 */
static int test_load_config_file(void)
{
    /* Create a temp config file with secure permissions from the start */
    const char *filename = "/tmp/test_openbastion.conf";
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return 0;
    }

    fprintf(f, "# Test config\n");
    fprintf(f, "portal_url = https://auth.example.com\n");
    fprintf(f, "client_id = test-client\n");
    fprintf(f, "client_secret = \"test-secret\"\n");
    fprintf(f, "server_group = production\n");
    fprintf(f, "timeout = 15\n");
    fprintf(f, "verify_ssl = false\n");
    fclose(f);  /* Also closes fd */

    pam_openbastion_config_t config;
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

/*
 * fingerprint_required (#192): off by default, settable from the config file
 * and from a pam.d argument, under either spelling.
 */
static int test_fingerprint_required_default_off(void)
{
    pam_openbastion_config_t config;
    config_init(&config);
    int ok = (config.fingerprint_required == false);
    config_free(&config);
    return ok;
}

static int test_parse_fingerprint_required(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = { "fingerprint_required=true" };
    config_parse_args(1, argv, &config);
    int ok = (config.fingerprint_required == true);
    config_free(&config);

    config_init(&config);
    const char *alias[] = { "ssh_fingerprint_required=true" };
    config_parse_args(1, alias, &config);
    ok = ok && (config.fingerprint_required == true);
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
    TEST(validate_verify_ssl_false_allows_http);
    TEST(validate_verify_ssl_true_rejects_http);
    TEST(bad_bool_is_fatal);
    TEST(good_bool_values_accepted);
    TEST(bad_bool_other_key_is_fatal);
    TEST(response_signing_defaults);
    TEST(parse_response_signing);
    TEST(bad_response_signing_is_fatal);
    TEST(client_settings);
    TEST(parse_insecure_flag);
    TEST(create_user_defaults);
    TEST(parse_create_user_args);
    TEST(parse_no_create_user);
    TEST(cache_rate_limit_defaults);
    TEST(parse_cache_rate_limit_args);
    TEST(cache_rate_limit_bounds);
    TEST(fingerprint_required_default_off);
    TEST(parse_fingerprint_required);
#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
    TEST(oauth2_token_auth_defaults);
    TEST(parse_oauth2_token_auth_args);
    TEST(parse_oauth2_token_auth_config);
    TEST(parse_no_oauth2_token_cache);
    TEST(oauth2_token_min_ttl_bounds);
#endif /* ENABLE_DESKTOP_SSO */
    TEST(load_config_file);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
