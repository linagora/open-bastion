/*
 * test_ob_client.c - Tests for ob_client functions
 *
 * Tests the new structures and functions:
 * - ob_permissions_t parsing
 * - ob_ssh_cert_info_t handling
 * - ob_ssh_cert_info_free()
 *
 * Note: Full integration tests require a running Open Bastion instance.
 * These tests focus on unit testing the structures and helper functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ob_client.h"

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", name); \
    tests_run++; \
} while(0)

#define PASS() do { \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define FAIL(msg) do { \
    printf("FAILED: %s\n", msg); \
} while(0)

/*
 * Test ob_ssh_cert_info_free with populated structure
 */
static void test_ssh_cert_info_free_populated(void)
{
    TEST("ssh_cert_info_free with populated struct");

    ob_ssh_cert_info_t cert = {0};
    cert.key_id = strdup("user@llng-123456");
    cert.serial = strdup("42");
    cert.principals = strdup("user,admin");
    cert.ca_fingerprint = strdup("SHA256:abc123");
    cert.valid = true;

    /* Should not crash and should zero the structure */
    ob_ssh_cert_info_free(&cert);

    if (cert.key_id == NULL && cert.serial == NULL &&
        cert.principals == NULL && cert.ca_fingerprint == NULL &&
        cert.valid == false) {
        PASS();
    } else {
        FAIL("Structure not properly zeroed after free");
    }
}

/*
 * Test ob_ssh_cert_info_free with empty structure
 */
static void test_ssh_cert_info_free_empty(void)
{
    TEST("ssh_cert_info_free with empty struct");

    ob_ssh_cert_info_t cert = {0};

    /* Should not crash */
    ob_ssh_cert_info_free(&cert);

    PASS();
}

/*
 * Test ob_ssh_cert_info_free with NULL
 */
static void test_ssh_cert_info_free_null(void)
{
    TEST("ssh_cert_info_free with NULL");

    /* Should not crash */
    ob_ssh_cert_info_free(NULL);

    PASS();
}

/*
 * Test ob_response_free with permissions
 */
static void test_response_free_with_permissions(void)
{
    TEST("response_free with permissions");

    ob_response_t response = {0};
    response.authorized = true;
    response.user = strdup("testuser");
    response.reason = strdup("test reason");
    response.has_permissions = true;
    response.permissions.sudo_allowed = true;
    response.permissions.sudo_nopasswd = false;

    /* Allocate groups */
    response.groups_count = 2;
    response.groups = calloc(3, sizeof(char *));
    response.groups[0] = strdup("group1");
    response.groups[1] = strdup("group2");

    /* Should not crash and should zero the structure */
    ob_response_free(&response);

    if (response.user == NULL && response.reason == NULL &&
        response.groups == NULL && response.groups_count == 0 &&
        response.has_permissions == false) {
        PASS();
    } else {
        FAIL("Structure not properly zeroed after free");
    }
}

/*
 * Test permissions structure initialization
 */
static void test_permissions_default_values(void)
{
    TEST("permissions default values");

    ob_permissions_t perms = {0};

    if (perms.sudo_allowed == false && perms.sudo_nopasswd == false) {
        PASS();
    } else {
        FAIL("Default values should be false");
    }
}

/*
 * Test response structure with has_permissions flag
 */
static void test_response_has_permissions_flag(void)
{
    TEST("response has_permissions flag");

    ob_response_t response = {0};

    /* Initially should be false */
    if (response.has_permissions != false) {
        FAIL("has_permissions should default to false");
        return;
    }

    /* Set it to true */
    response.has_permissions = true;
    response.permissions.sudo_allowed = true;

    if (response.has_permissions == true &&
        response.permissions.sudo_allowed == true) {
        PASS();
    } else {
        FAIL("Failed to set permissions");
    }
}

/*
 * Test ssh_cert_info structure size and alignment
 */
static void test_ssh_cert_info_structure(void)
{
    TEST("ssh_cert_info structure layout");

    ob_ssh_cert_info_t cert = {0};

    /* Verify we can access all fields */
    cert.key_id = NULL;
    cert.serial = NULL;
    cert.principals = NULL;
    cert.ca_fingerprint = NULL;
    cert.valid = false;

    /* Structure should be reasonable size */
    if (sizeof(ob_ssh_cert_info_t) >= sizeof(char *) * 4 + sizeof(bool)) {
        PASS();
    } else {
        FAIL("Structure size seems wrong");
    }
}

/*
 * Test that client init fails with NULL config
 */
static void test_client_init_null_config(void)
{
    TEST("client_init with NULL config");

    ob_client_t *client = ob_client_init(NULL);

    if (client == NULL) {
        PASS();
    } else {
        FAIL("Should return NULL for NULL config");
        ob_client_destroy(client);
    }
}

/*
 * Test that client init fails with missing portal_url
 */
static void test_client_init_no_portal(void)
{
    TEST("client_init without portal_url");

    ob_client_config_t config = {0};
    config.portal_url = NULL;

    ob_client_t *client = ob_client_init(&config);

    if (client == NULL) {
        PASS();
    } else {
        FAIL("Should return NULL when portal_url is missing");
        ob_client_destroy(client);
    }
}

/*
 * Test client init with valid config
 */
static void test_client_init_valid(void)
{
    TEST("client_init with valid config");

    ob_client_config_t config = {0};
    config.portal_url = "https://auth.example.com";
    config.client_id = "test-client";
    config.client_secret = "secret";
    config.timeout = 10;
    config.verify_ssl = true;

    ob_client_t *client = ob_client_init(&config);

    if (client != NULL) {
        ob_client_destroy(client);
        PASS();
    } else {
        FAIL("Should succeed with valid config");
    }
}

/*
 * Test client error function with NULL client
 */
static void test_client_error_null(void)
{
    TEST("client_error with NULL client");

    const char *error = ob_client_error(NULL);

    if (error != NULL && strcmp(error, "No client") == 0) {
        PASS();
    } else {
        FAIL("Should return 'No client' for NULL");
    }
}

#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
/*
 * Test introspect_token with NULL parameters
 */
static void test_introspect_token_null_params(void)
{
    TEST("introspect_token with NULL params");

    ob_client_config_t config = {0};
    config.portal_url = "https://auth.example.com";
    config.client_id = "test-client";
    config.client_secret = "secret";
    config.timeout = 1;
    config.verify_ssl = false;

    ob_client_t *client = ob_client_init(&config);
    if (!client) {
        FAIL("Failed to init client");
        return;
    }

    ob_response_t response = {0};

    /* NULL client should fail */
    int ret = ob_introspect_token(NULL, "token", &response);
    if (ret != -1) {
        FAIL("Should fail with NULL client");
        ob_client_destroy(client);
        return;
    }

    /* NULL token should fail */
    ret = ob_introspect_token(client, NULL, &response);
    if (ret != -1) {
        FAIL("Should fail with NULL token");
        ob_client_destroy(client);
        return;
    }

    /* NULL response should fail */
    ret = ob_introspect_token(client, "token", NULL);
    if (ret != -1) {
        FAIL("Should fail with NULL response");
        ob_client_destroy(client);
        return;
    }

    ob_client_destroy(client);
    PASS();
}

/*
 * Test introspect_token error handling (no server)
 * This verifies JWT generation and request building work correctly,
 * even though the request will fail (no server to respond).
 * JWT generation itself is thoroughly tested in test_token_manager.c
 */
static void test_introspect_token_no_server(void)
{
    TEST("introspect_token builds JWT request (no server)");

    ob_client_config_t config = {0};
    config.portal_url = "https://localhost:1"; /* Invalid port, will fail quickly */
    config.client_id = "test-client";
    config.client_secret = "test-secret";
    config.timeout = 1;
    config.verify_ssl = false;

    ob_client_t *client = ob_client_init(&config);
    if (!client) {
        FAIL("Failed to init client");
        return;
    }

    ob_response_t response = {0};
    int ret = ob_introspect_token(client, "test-token", &response);

    /* Should fail (no server) but not crash */
    /* The error should be a curl error, not a JWT generation error */
    const char *error = ob_client_error(client);
    if (ret == -1 && error != NULL && strstr(error, "Curl") != NULL) {
        /* Good: failed with curl error, meaning JWT was generated successfully */
        PASS();
    } else if (ret == -1 && error != NULL && strstr(error, "JWT") != NULL) {
        /* Bad: JWT generation failed */
        FAIL("JWT generation should not fail with valid credentials");
    } else {
        PASS(); /* Any failure is acceptable here since there's no server */
    }

    ob_client_destroy(client);
}

/*
 * Regression test for the introspection POST-data stack overflow.
 *
 * ob_introspect_token() builds "token=<url-encoded token>" into an 8 KiB stack
 * buffer with snprintf(), which returns the length the result WOULD have had.
 * That return value was used unchecked as an offset for the client_assertion
 * append: an over-long token made the offset point past the buffer and made
 * the remaining-size argument (sizeof(postdata) - len) wrap around to a huge
 * size_t, so the append wrote outside the stack frame. The upstream PAM cap of
 * 8192 raw characters does not prevent this because curl_easy_escape() expands
 * reserved characters 3x ("#" -> "%23").
 *
 * A token of 4096 '#' characters encodes to 12288 bytes, which cannot fit. The
 * call must fail cleanly with a "too long" error, before any HTTP request.
 */
static void test_introspect_token_oversized_token(void)
{
    TEST("introspect_token rejects an oversized token");

    ob_client_config_t config = {0};
    config.portal_url = "https://localhost:1"; /* Invalid port, would fail fast */
    config.client_id = "test-client";
    config.client_secret = "test-secret";
    config.timeout = 1;
    config.verify_ssl = false;

    ob_client_t *client = ob_client_init(&config);
    if (!client) {
        FAIL("Failed to init client");
        return;
    }

    /* 4096 reserved chars -> 12288 bytes once URL-encoded (> 8192) */
    const size_t token_len = 4096;
    char *token = malloc(token_len + 1);
    if (!token) {
        FAIL("Out of memory");
        ob_client_destroy(client);
        return;
    }
    memset(token, '#', token_len);
    token[token_len] = '\0';

    ob_response_t response = {0};
    int ret = ob_introspect_token(client, token, &response);
    free(token);

    const char *error = ob_client_error(client);

    if (ret != -1) {
        FAIL("Oversized token must be rejected");
    } else if (!error || strstr(error, "too long") == NULL) {
        /* A curl error here would mean the request was sent anyway, i.e. the
         * body was built from a truncated/overflowed buffer. */
        FAIL("Should fail with a 'POST data too long' error");
    } else {
        PASS();
    }

    ob_response_free(&response);
    ob_client_destroy(client);
}
#endif /* ENABLE_DESKTOP_SSO */

/*
 * /pam/verify response-contract tests.
 *
 * Regression for the "sudo after a long wait fails" bug: when the user's
 * one-time PAM token (OTP) has expired, the pam-access plugin answers
 * {"valid":false,"error":"Token expired"} with NO 'user' field. The parser
 * used to require 'user' unconditionally and reported a hard
 * "Missing required 'user' field" error (PAM_AUTHINFO_UNAVAIL), masking the
 * expiry. It must instead return success with active=false and the reason.
 */
static void test_verify_expired_token_no_user(void)
{
    TEST("verify response: valid:false without user (expired OTP)");

    ob_response_t r;
    char err[256] = {0};
    int rc = ob_parse_verify_response(
        "{\"valid\":false,\"error\":\"Token expired\"}", &r, err, sizeof(err));

    if (rc != 0) {
        FAIL("expired-token response should parse successfully (rc=0)");
        return;
    }
    if (r.active) {
        FAIL("expired token must yield active=false");
        ob_response_free(&r);
        return;
    }
    if (r.user != NULL) {
        FAIL("expired token must not set user");
        ob_response_free(&r);
        return;
    }
    if (!r.reason || strcmp(r.reason, "Token expired") != 0) {
        FAIL("reason should carry the plugin's error message");
        ob_response_free(&r);
        return;
    }
    ob_response_free(&r);
    PASS();
}

static void test_verify_active_requires_user(void)
{
    TEST("verify response: valid:true still requires user");

    ob_response_t r;
    char err[256] = {0};
    int rc = ob_parse_verify_response("{\"valid\":true}", &r, err, sizeof(err));

    if (rc == 0) {
        FAIL("active response without user must fail");
        ob_response_free(&r);
        return;
    }
    PASS();
}

static void test_verify_active_with_user(void)
{
    TEST("verify response: valid:true with user");

    ob_response_t r;
    char err[256] = {0};
    int rc = ob_parse_verify_response(
        "{\"valid\":true,\"user\":\"xguimard\"}", &r, err, sizeof(err));

    if (rc != 0 || !r.active || !r.user || strcmp(r.user, "xguimard") != 0) {
        FAIL("valid active response should parse user");
        ob_response_free(&r);
        return;
    }
    ob_response_free(&r);
    PASS();
}

static void test_verify_missing_valid(void)
{
    TEST("verify response: missing 'valid' field is rejected");

    ob_response_t r;
    char err[256] = {0};
    int rc = ob_parse_verify_response(
        "{\"user\":\"xguimard\"}", &r, err, sizeof(err));

    if (rc == 0) {
        FAIL("response without 'valid' must fail");
        ob_response_free(&r);
        return;
    }
    PASS();
}

/*
 * /pam/authorize response contract.
 *
 * Regression for #318: the 'offline' object was parsed only in the Desktop SSO
 * build, so a core build never saw offline.enabled and never wrote the
 * authorization cache. enabled/ttl must parse in every build.
 */
static void test_authorize_offline_settings(void)
{
    TEST("authorize response: offline enabled/ttl parsed in every build");

    ob_response_t r;
    char err[256] = {0};
    int rc = ob_parse_authorize_response(
        "{\"authorized\":true,\"user\":\"jdoe\","
        "\"offline\":{\"enabled\":true,\"ttl\":3600}}",
        &r, err, sizeof(err));

    if (rc != 0) {
        FAIL(err);
        return;
    }
    if (!r.authorized || !r.has_offline || !r.offline.enabled ||
        r.offline.ttl != 3600) {
        FAIL("offline settings not parsed");
        ob_response_free(&r);
        return;
    }
    ob_response_free(&r);
    PASS();
}

static void test_authorize_without_offline(void)
{
    TEST("authorize response: no offline object leaves the cache off");

    ob_response_t r;
    char err[256] = {0};
    int rc = ob_parse_authorize_response(
        "{\"authorized\":true,\"user\":\"jdoe\"}", &r, err, sizeof(err));

    if (rc != 0) {
        FAIL(err);
        return;
    }
    if (r.has_offline || r.offline.enabled) {
        FAIL("offline must stay unset when the portal sends none");
        ob_response_free(&r);
        return;
    }
    ob_response_free(&r);
    PASS();
}

static void test_authorize_missing_authorized(void)
{
    TEST("authorize response: missing 'authorized' field is rejected");

    ob_response_t r;
    char err[256] = {0};
    int rc = ob_parse_authorize_response("{\"user\":\"jdoe\"}", &r, err,
                                         sizeof(err));
    if (rc == 0) {
        FAIL("a response without 'authorized' must not parse");
        ob_response_free(&r);
        return;
    }
    PASS();
}

int main(void)
{
    printf("Running ob_client tests...\n\n");

    /* SSH cert info tests */
    test_ssh_cert_info_free_populated();
    test_ssh_cert_info_free_empty();
    test_ssh_cert_info_free_null();
    test_ssh_cert_info_structure();

    /* Response and permissions tests */
    test_response_free_with_permissions();
    test_permissions_default_values();
    test_response_has_permissions_flag();

    /* Client init tests */
    test_client_init_null_config();
    test_client_init_no_portal();
    test_client_init_valid();
    test_client_error_null();

    /* /pam/verify response contract (expired-OTP regression) */
    test_verify_expired_token_no_user();
    test_verify_active_requires_user();
    test_verify_active_with_user();
    test_verify_missing_valid();

    /* /pam/authorize response contract (#318) */
    test_authorize_offline_settings();
    test_authorize_without_offline();
    test_authorize_missing_authorized();

#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO features only: see CONTRIBUTING.md */
    /* Introspection tests (JWT client assertion) */
    test_introspect_token_null_params();
    test_introspect_token_no_server();
    test_introspect_token_oversized_token();
#endif /* ENABLE_DESKTOP_SSO */

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
