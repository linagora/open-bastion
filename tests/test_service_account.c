/*
 * test_service_account.c - Unit tests for service account management
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "service_account.h"
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

/* Helper: create a temporary config file with proper permissions */
static char *create_temp_config(const char *content)
{
    char template[] = "/tmp/service_accounts_test_XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        perror("mkstemp");
        return NULL;
    }

    /* Write content */
    if (write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
        perror("write");
        close(fd);
        unlink(template);
        return NULL;
    }

    /* Set proper permissions (root owned, 0600) */
    if (fchmod(fd, 0600) != 0) {
        perror("fchmod");
        close(fd);
        unlink(template);
        return NULL;
    }

    close(fd);
    return strdup(template);
}

/* Helper: cleanup temporary file */
static void cleanup_temp_file(char *path)
{
    if (path) {
        unlink(path);
        free(path);
    }
}

/* Test initialization */
static int test_init(void)
{
    service_accounts_t sa;
    service_accounts_init(&sa);

    int ok = 1;
    ok = ok && (sa.accounts == NULL);
    ok = ok && (sa.count == 0);
    ok = ok && (sa.capacity == 0);

    service_accounts_free(&sa);
    return ok;
}

/* Test loading non-existent file (should succeed with empty list) */
static int test_load_nonexistent(void)
{
    service_accounts_t sa;
    service_accounts_init(&sa);

    int ret = service_accounts_load("/nonexistent/path/service-accounts.conf", &sa);

    int ok = 1;
    ok = ok && (ret == 0);  /* Non-existent file is OK */
    ok = ok && (sa.count == 0);

    service_accounts_free(&sa);
    return ok;
}

/* Test loading a valid configuration file */
static int test_load_valid_config(void)
{
    const char *config_content =
        "# Service accounts configuration\n"
        "\n"
        "[ansible]\n"
        "key_fingerprint = SHA256:abc123def456\n"
        "sudo_allowed = true\n"
        "sudo_nopasswd = true\n"
        "gecos = Ansible Automation\n"
        "shell = /bin/bash\n"
        "home = /var/lib/ansible\n"
        "\n"
        "[backup]\n"
        "key_fingerprint = SHA256:xyz789\n"
        "sudo_allowed = false\n"
        "gecos = Backup Service\n"
        "shell = /bin/sh\n"
        "home = /var/lib/backup\n";

    char *config_path = create_temp_config(config_content);
    if (!config_path) {
        printf("(skipped - cannot create temp file as non-root) ");
        return 1;  /* Skip test if we can't create file */
    }

    service_accounts_t sa;
    service_accounts_init(&sa);

    /* Note: This will fail if not running as root due to ownership check */
    int ret = service_accounts_load(config_path, &sa);

    int ok = 1;
    if (ret == -2) {
        /* Expected if not running as root */
        printf("(skipped - not root) ");
        ok = 1;
    } else if (ret == 0) {
        ok = ok && (sa.count == 2);

        /* Check ansible account */
        const service_account_t *ansible = service_accounts_find(&sa, "ansible");
        ok = ok && (ansible != NULL);
        if (ansible) {
            ok = ok && (strcmp(ansible->name, "ansible") == 0);
            ok = ok && (ansible->key_fingerprint != NULL);
            ok = ok && (strcmp(ansible->key_fingerprint, "SHA256:abc123def456") == 0);
            ok = ok && (ansible->sudo_allowed == true);
            ok = ok && (ansible->sudo_nopasswd == true);
            ok = ok && (ansible->gecos != NULL);
            ok = ok && (strcmp(ansible->gecos, "Ansible Automation") == 0);
            ok = ok && (ansible->shell != NULL);
            ok = ok && (strcmp(ansible->shell, "/bin/bash") == 0);
            ok = ok && (ansible->home != NULL);
            ok = ok && (strcmp(ansible->home, "/var/lib/ansible") == 0);
        }

        /* Check backup account */
        const service_account_t *backup = service_accounts_find(&sa, "backup");
        ok = ok && (backup != NULL);
        if (backup) {
            ok = ok && (strcmp(backup->name, "backup") == 0);
            ok = ok && (backup->sudo_allowed == false);
            ok = ok && (backup->sudo_nopasswd == false);
        }
    } else {
        ok = 0;
    }

    service_accounts_free(&sa);
    cleanup_temp_file(config_path);
    return ok;
}

/* Test find function */
static int test_find(void)
{
    service_accounts_t sa;
    service_accounts_init(&sa);

    /* Find in empty list should return NULL */
    const service_account_t *found = service_accounts_find(&sa, "ansible");
    int ok = (found == NULL);

    service_accounts_free(&sa);
    return ok;
}

/* Test is_service_account function */
static int test_is_service_account(void)
{
    service_accounts_t sa;
    service_accounts_init(&sa);

    /* Empty list should return false */
    int ok = (service_accounts_is_service_account(&sa, "ansible") == false);

    service_accounts_free(&sa);
    return ok;
}

/* Test key validation with empty list */
static int test_validate_key_not_found(void)
{
    service_accounts_t sa;
    service_accounts_init(&sa);

    int ret = service_accounts_validate_key(&sa, "ansible", "SHA256:test");

    int ok = (ret == -1);  /* Account not found */

    service_accounts_free(&sa);
    return ok;
}

/* Helper to create a test service account structure */
static void create_test_account(service_accounts_t *sa, const char *name,
                                 const char *fingerprint)
{
    service_accounts_init(sa);
    sa->accounts = malloc(sizeof(service_account_t));
    if (sa->accounts) {
        memset(sa->accounts, 0, sizeof(service_account_t));
        sa->accounts[0].name = strdup(name);
        sa->accounts[0].key_fingerprint = fingerprint ? strdup(fingerprint) : NULL;
        sa->count = 1;
        sa->capacity = 1;
    }
}

/* Test key validation: fingerprint matches */
static int test_validate_key_match(void)
{
    service_accounts_t sa;
    create_test_account(&sa, "ansible", "SHA256:abc123def456");

    int ret = service_accounts_validate_key(&sa, "ansible", "SHA256:abc123def456");

    int ok = (ret == 0);  /* Fingerprint matches */

    service_accounts_free(&sa);
    return ok;
}

/* Test key validation: fingerprint mismatch */
static int test_validate_key_mismatch(void)
{
    service_accounts_t sa;
    create_test_account(&sa, "ansible", "SHA256:abc123def456");

    int ret = service_accounts_validate_key(&sa, "ansible", "SHA256:wrongfingerprint");

    int ok = (ret == -2);  /* Fingerprint mismatch */

    service_accounts_free(&sa);
    return ok;
}

/* Test key validation: no fingerprint configured */
static int test_validate_key_no_config(void)
{
    service_accounts_t sa;
    create_test_account(&sa, "ansible", NULL);

    int ret = service_accounts_validate_key(&sa, "ansible", "SHA256:abc123def456");

    int ok = (ret == -3);  /* No fingerprint configured */

    service_accounts_free(&sa);
    return ok;
}

/* Test key validation: no fingerprint provided */
static int test_validate_key_no_provided(void)
{
    service_accounts_t sa;
    create_test_account(&sa, "ansible", "SHA256:abc123def456");

    int ret = service_accounts_validate_key(&sa, "ansible", NULL);

    int ok = (ret == -2);  /* No fingerprint provided */

    service_accounts_free(&sa);
    return ok;
}

/* Test get_authorization with empty list */
static int test_get_authorization_not_found(void)
{
    service_accounts_t sa;
    service_accounts_init(&sa);

    bool sudo_allowed = true;
    bool sudo_nopasswd = true;
    int ret = service_accounts_get_authorization(&sa, "ansible",
                                                  &sudo_allowed, &sudo_nopasswd,
                                                  NULL, NULL, NULL, NULL, NULL);

    int ok = (ret == -1);  /* Account not found */

    service_accounts_free(&sa);
    return ok;
}

/* Test account validation */
static int test_account_validate_valid(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = "SHA256:abc123def456",
        .sudo_allowed = true,
        .sudo_nopasswd = false,
        .gecos = "Ansible Automation",
        .shell = "/bin/bash",
        .home = "/home/ansible",
        .uid = 0,
        .gid = 0
    };

    int ret = service_account_validate(&account,
                                        DEFAULT_APPROVED_SHELLS,
                                        DEFAULT_APPROVED_HOME_PREFIXES);

    return (ret == 0);
}

/* Test account validation with invalid username */
static int test_account_validate_invalid_name(void)
{
    service_account_t account = {
        .name = "Invalid-Name",  /* Uppercase not allowed */
        .key_fingerprint = "SHA256:abc123",
        .sudo_allowed = false,
        .sudo_nopasswd = false,
        .gecos = NULL,
        .shell = NULL,
        .home = NULL,
        .uid = 0,
        .gid = 0
    };

    int ret = service_account_validate(&account, NULL, NULL);

    return (ret != 0);  /* Should fail */
}

/* Test account validation with missing fingerprint */
static int test_account_validate_missing_fingerprint(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = NULL,  /* Missing fingerprint */
        .sudo_allowed = false,
        .sudo_nopasswd = false,
        .gecos = NULL,
        .shell = NULL,
        .home = NULL,
        .uid = 0,
        .gid = 0
    };

    int ret = service_account_validate(&account, NULL, NULL);

    return (ret != 0);  /* Should fail */
}

/* Test account validation with invalid fingerprint format */
static int test_account_validate_invalid_fingerprint(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = "invalid-format",  /* Must start with SHA256: or MD5: */
        .sudo_allowed = false,
        .sudo_nopasswd = false,
        .gecos = NULL,
        .shell = NULL,
        .home = NULL,
        .uid = 0,
        .gid = 0
    };

    int ret = service_account_validate(&account, NULL, NULL);

    return (ret != 0);  /* Should fail */
}

/* Test account validation with unapproved shell */
static int test_account_validate_unapproved_shell(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = "SHA256:abc123",
        .sudo_allowed = false,
        .sudo_nopasswd = false,
        .gecos = NULL,
        .shell = "/usr/bin/malicious",  /* Not in approved list */
        .home = NULL,
        .uid = 0,
        .gid = 0
    };

    int ret = service_account_validate(&account,
                                        DEFAULT_APPROVED_SHELLS,
                                        DEFAULT_APPROVED_HOME_PREFIXES);

    return (ret != 0);  /* Should fail */
}

/* Test account validation with unapproved home prefix */
static int test_account_validate_unapproved_home(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = "SHA256:abc123",
        .sudo_allowed = false,
        .sudo_nopasswd = false,
        .gecos = NULL,
        .shell = "/bin/bash",
        .home = "/etc/ansible",  /* Not in approved prefixes */
        .uid = 0,
        .gid = 0
    };

    int ret = service_account_validate(&account,
                                        DEFAULT_APPROVED_SHELLS,
                                        DEFAULT_APPROVED_HOME_PREFIXES);

    return (ret != 0);  /* Should fail */
}

/* Test NULL handling */
static int test_null_handling(void)
{
    int ok = 1;

    /* These should not crash with NULL inputs */
    service_accounts_init(NULL);
    service_accounts_free(NULL);

    ok = ok && (service_accounts_find(NULL, "test") == NULL);
    ok = ok && (service_accounts_find(NULL, NULL) == NULL);

    ok = ok && (service_accounts_is_service_account(NULL, "test") == false);
    ok = ok && (service_accounts_is_service_account(NULL, NULL) == false);

    ok = ok && (service_accounts_validate_key(NULL, "test", "fp") == -1);
    ok = ok && (service_accounts_get_authorization(NULL, "test", NULL, NULL,
                                                    NULL, NULL, NULL, NULL, NULL) == -1);

    ok = ok && (service_account_validate(NULL, NULL, NULL) == -1);

    return ok;
}

int main(void)
{
    printf("Running service_account tests...\n");

    TEST(init);
    TEST(load_nonexistent);
    TEST(load_valid_config);
    TEST(find);
    TEST(is_service_account);
    TEST(validate_key_not_found);
    TEST(validate_key_match);
    TEST(validate_key_mismatch);
    TEST(validate_key_no_config);
    TEST(validate_key_no_provided);
    TEST(get_authorization_not_found);
    TEST(account_validate_valid);
    TEST(account_validate_invalid_name);
    TEST(account_validate_missing_fingerprint);
    TEST(account_validate_invalid_fingerprint);
    TEST(account_validate_unapproved_shell);
    TEST(account_validate_unapproved_home);
    TEST(null_handling);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
