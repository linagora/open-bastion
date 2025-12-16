/*
 * test_llng_client.c - Tests for llng_client functions
 *
 * Tests the new structures and functions:
 * - llng_permissions_t parsing
 * - llng_ssh_cert_info_t handling
 * - llng_ssh_cert_info_free()
 *
 * Note: Full integration tests require a running LLNG instance.
 * These tests focus on unit testing the structures and helper functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "llng_client.h"

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
 * Test llng_ssh_cert_info_free with populated structure
 */
static void test_ssh_cert_info_free_populated(void)
{
    TEST("ssh_cert_info_free with populated struct");

    llng_ssh_cert_info_t cert = {0};
    cert.key_id = strdup("user@llng-123456");
    cert.serial = strdup("42");
    cert.principals = strdup("user,admin");
    cert.ca_fingerprint = strdup("SHA256:abc123");
    cert.valid = true;

    /* Should not crash and should zero the structure */
    llng_ssh_cert_info_free(&cert);

    if (cert.key_id == NULL && cert.serial == NULL &&
        cert.principals == NULL && cert.ca_fingerprint == NULL &&
        cert.valid == false) {
        PASS();
    } else {
        FAIL("Structure not properly zeroed after free");
    }
}

/*
 * Test llng_ssh_cert_info_free with empty structure
 */
static void test_ssh_cert_info_free_empty(void)
{
    TEST("ssh_cert_info_free with empty struct");

    llng_ssh_cert_info_t cert = {0};

    /* Should not crash */
    llng_ssh_cert_info_free(&cert);

    PASS();
}

/*
 * Test llng_ssh_cert_info_free with NULL
 */
static void test_ssh_cert_info_free_null(void)
{
    TEST("ssh_cert_info_free with NULL");

    /* Should not crash */
    llng_ssh_cert_info_free(NULL);

    PASS();
}

/*
 * Test llng_response_free with permissions
 */
static void test_response_free_with_permissions(void)
{
    TEST("response_free with permissions");

    llng_response_t response = {0};
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
    llng_response_free(&response);

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

    llng_permissions_t perms = {0};

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

    llng_response_t response = {0};

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

    llng_ssh_cert_info_t cert = {0};

    /* Verify we can access all fields */
    cert.key_id = NULL;
    cert.serial = NULL;
    cert.principals = NULL;
    cert.ca_fingerprint = NULL;
    cert.valid = false;

    /* Structure should be reasonable size */
    if (sizeof(llng_ssh_cert_info_t) >= sizeof(char *) * 4 + sizeof(bool)) {
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

    llng_client_t *client = llng_client_init(NULL);

    if (client == NULL) {
        PASS();
    } else {
        FAIL("Should return NULL for NULL config");
        llng_client_destroy(client);
    }
}

/*
 * Test that client init fails with missing portal_url
 */
static void test_client_init_no_portal(void)
{
    TEST("client_init without portal_url");

    llng_client_config_t config = {0};
    config.portal_url = NULL;

    llng_client_t *client = llng_client_init(&config);

    if (client == NULL) {
        PASS();
    } else {
        FAIL("Should return NULL when portal_url is missing");
        llng_client_destroy(client);
    }
}

/*
 * Test client init with valid config
 */
static void test_client_init_valid(void)
{
    TEST("client_init with valid config");

    llng_client_config_t config = {0};
    config.portal_url = "https://auth.example.com";
    config.client_id = "test-client";
    config.client_secret = "secret";
    config.timeout = 10;
    config.verify_ssl = true;

    llng_client_t *client = llng_client_init(&config);

    if (client != NULL) {
        llng_client_destroy(client);
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

    const char *error = llng_client_error(NULL);

    if (error != NULL && strcmp(error, "No client") == 0) {
        PASS();
    } else {
        FAIL("Should return 'No client' for NULL");
    }
}

int main(void)
{
    printf("Running llng_client tests...\n\n");

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

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
