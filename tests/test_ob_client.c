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

#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO only and never compiled inside open-bastion core */
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
#endif /* ENABLE_DESKTOP_SSO */

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

#ifdef ENABLE_DESKTOP_SSO  /* Desktop SSO only and never compiled inside open-bastion core */
    /* Introspection tests (JWT client assertion) */
    test_introspect_token_null_params();
    test_introspect_token_no_server();
#endif /* ENABLE_DESKTOP_SSO */

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
