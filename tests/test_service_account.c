/*
 * test_service_account.c - Unit tests for service account management
 *
 * The parser is included rather than linked, as the NSS tests do, so that the
 * owner check can be pointed at the test's own uid (SA_TRUSTED_UID): every
 * load test then runs unprivileged instead of skipping off root.
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

#define SA_TRUSTED_UID (getuid())
#include "../src/service_account.c"

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

/* Helper: create a temporary config file with the given mode */
static char *create_temp_config_mode(const char *content, mode_t mode)
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

    if (fchmod(fd, mode) != 0) {
        perror("fchmod");
        close(fd);
        unlink(template);
        return NULL;
    }

    close(fd);
    return strdup(template);
}

/* Helper: a config file as the module accepts it (owner-only) */
static char *create_temp_config(const char *content)
{
    return create_temp_config_mode(content, 0600);
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
    ok = ok && (sa.obsolete_keys == 0);

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

/* Test loading a configuration file in the current format */
static int test_load_valid_config(void)
{
    const char *config_content =
        "# Service accounts configuration\n"
        "\n"
        "[ansible]\n"
        "key_fingerprint = SHA256:abc123def456\n"
        "\n"
        "[backup]\n"
        "fingerprint = \"SHA256:xyz789\"\n"
        "\n"
        "[deploy]\n"
        "ssh_key = SHA256:deploy42\n";

    char *config_path = create_temp_config(config_content);
    if (!config_path) return 0;

    service_accounts_t sa;
    service_accounts_init(&sa);
    int ret = service_accounts_load(config_path, &sa);

    int ok = (ret == 0) && (sa.count == 3);
    const service_account_t *ansible = service_accounts_find(&sa, "ansible");
    const service_account_t *backup = service_accounts_find(&sa, "backup");
    const service_account_t *deploy = service_accounts_find(&sa, "deploy");
    ok = ok && ansible && strcmp(ansible->key_fingerprint, "SHA256:abc123def456") == 0;
    /* Aliases, and the quotes around a value */
    ok = ok && backup && strcmp(backup->key_fingerprint, "SHA256:xyz789") == 0;
    ok = ok && deploy && strcmp(deploy->key_fingerprint, "SHA256:deploy42") == 0;
    ok = ok && (sa.obsolete_keys == 0);

    service_accounts_free(&sa);
    cleanup_temp_file(config_path);
    return ok;
}

/*
 * #353: a file written for an older release keeps every account. The keys that
 * used to drive account creation and sudo are ignored and recorded -- even with
 * values the old validator refused (an unapproved shell or home dropped the
 * account), since refusing them now would lock the account out on upgrade.
 */
static int test_load_obsolete_keys_ignored(void)
{
    const char *config_content =
        "[ansible]\n"
        "key_fingerprint = SHA256:abc123def456\n"
        "sudo_allowed = true\n"
        "sudo_nopasswd = true\n"
        "gecos = Ansible Automation\n"
        "shell = /bin/bash\n"
        "home = /var/lib/ansible\n"
        "uid = 990\n"
        "gid = 990\n"
        "\n"
        "[backup]\n"
        "key_fingerprint = SHA256:xyz789\n"
        "sudo = yes\n"
        "nopasswd = yes\n"
        "description = Backup Service\n"
        "shell = /usr/bin/malicious\n"
        "home_dir = /etc/backup\n"
        "uid = not-a-number\n"
        "gid = 99999999\n";

    char *config_path = create_temp_config(config_content);
    if (!config_path) return 0;

    service_accounts_t sa;
    service_accounts_init(&sa);
    int ret = service_accounts_load(config_path, &sa);

    int ok = (ret == 0) && (sa.count == 2);
    const service_account_t *ansible = service_accounts_find(&sa, "ansible");
    const service_account_t *backup = service_accounts_find(&sa, "backup");
    ok = ok && ansible && strcmp(ansible->key_fingerprint, "SHA256:abc123def456") == 0;
    ok = ok && backup && strcmp(backup->key_fingerprint, "SHA256:xyz789") == 0;
    ok = ok && (sa.obsolete_keys == (SA_OBSOLETE_UID | SA_OBSOLETE_GID |
                                     SA_OBSOLETE_SHELL | SA_OBSOLETE_HOME |
                                     SA_OBSOLETE_GECOS |
                                     SA_OBSOLETE_SUDO_ALLOWED |
                                     SA_OBSOLETE_SUDO_NOPASSWD));

    service_accounts_free(&sa);
    ok = ok && (sa.obsolete_keys == 0);
    cleanup_temp_file(config_path);
    return ok;
}

/* Each obsolete key is recorded under its own bit, aliases included */
static int test_load_obsolete_key_bits(void)
{
    static const struct { const char *line; unsigned int bit; } cases[] = {
        { "uid = 1\n",            SA_OBSOLETE_UID },
        { "gid = 1\n",            SA_OBSOLETE_GID },
        { "shell = /bin/sh\n",    SA_OBSOLETE_SHELL },
        { "home = /home/x\n",     SA_OBSOLETE_HOME },
        { "home_dir = /home/x\n", SA_OBSOLETE_HOME },
        { "gecos = x\n",          SA_OBSOLETE_GECOS },
        { "description = x\n",    SA_OBSOLETE_GECOS },
        { "sudo_allowed = 1\n",   SA_OBSOLETE_SUDO_ALLOWED },
        { "sudo = 1\n",           SA_OBSOLETE_SUDO_ALLOWED },
        { "sudo_nopasswd = 1\n",  SA_OBSOLETE_SUDO_NOPASSWD },
        { "nopasswd = 1\n",       SA_OBSOLETE_SUDO_NOPASSWD },
        { "unknown_key = 1\n",    0 },
    };
    int ok = 1;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char content[256];
        snprintf(content, sizeof(content),
                 "[svc]\nkey_fingerprint = SHA256:abc\n%s", cases[i].line);
        char *config_path = create_temp_config(content);
        if (!config_path) return 0;

        service_accounts_t sa;
        service_accounts_init(&sa);
        int ret = service_accounts_load(config_path, &sa);
        if (ret != 0 || sa.count != 1 || sa.obsolete_keys != cases[i].bit) {
            printf("\n    %.*s: ret=%d count=%zu bits=%#x ", (int)strcspn(cases[i].line, "\n"),
                   cases[i].line, ret, sa.count, sa.obsolete_keys);
            ok = 0;
        }
        service_accounts_free(&sa);
        cleanup_temp_file(config_path);
    }
    return ok;
}

/* An account without a usable fingerprint is dropped, the others stay */
static int test_load_drops_invalid_account(void)
{
    const char *config_content =
        "[nofp]\n"
        "uid = 990\n"
        "\n"
        "[badfp]\n"
        "key_fingerprint = not-a-fingerprint\n"
        "\n"
        "[good]\n"
        "key_fingerprint = SHA256:abc\n";

    char *config_path = create_temp_config(config_content);
    if (!config_path) return 0;

    service_accounts_t sa;
    service_accounts_init(&sa);
    int ret = service_accounts_load(config_path, &sa);

    int ok = (ret == 0) && (sa.count == 1);
    ok = ok && service_accounts_is_service_account(&sa, "good");
    ok = ok && !service_accounts_is_service_account(&sa, "nofp");
    ok = ok && !service_accounts_is_service_account(&sa, "badfp");

    service_accounts_free(&sa);
    cleanup_temp_file(config_path);
    return ok;
}

/* A file others can read is refused whole */
static int test_load_refuses_open_permissions(void)
{
    char *config_path = create_temp_config_mode("[svc]\nkey_fingerprint = SHA256:abc\n",
                                                0640);
    if (!config_path) return 0;

    service_accounts_t sa;
    service_accounts_init(&sa);
    int ret = service_accounts_load(config_path, &sa);
    int ok = (ret == -3) && (sa.count == 0);

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

/* Test account validation */
static int test_account_validate_valid(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = "SHA256:abc123def456",
    };

    return (service_account_validate(&account) == 0);
}

/* Test account validation with invalid username */
static int test_account_validate_invalid_name(void)
{
    service_account_t account = {
        .name = "Invalid-Name",  /* Uppercase not allowed */
        .key_fingerprint = "SHA256:abc123",
    };

    return (service_account_validate(&account) != 0);  /* Should fail */
}

/* Test account validation with missing fingerprint */
static int test_account_validate_missing_fingerprint(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = NULL,  /* Missing fingerprint */
    };

    return (service_account_validate(&account) != 0);  /* Should fail */
}

/* Test account validation with invalid fingerprint format */
static int test_account_validate_invalid_fingerprint(void)
{
    service_account_t account = {
        .name = "ansible",
        .key_fingerprint = "invalid-format",  /* Must start with SHA256: or MD5: */
    };

    return (service_account_validate(&account) != 0);  /* Should fail */
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

    ok = ok && (service_account_validate(NULL) == -1);

    return ok;
}

/* ---------------------------------------------------------------------------
 * key_fingerprint against the keys themselves (#358). Vectors from
 * `ssh-keygen -l` and `ssh-keygen -E md5 -l` on the keys below.
 * ------------------------------------------------------------------------ */

#define KEY_A_BLOB "AAAAC3NzaC1lZDI1NTE5AAAAIC900KjDRAzVlZr3rDQ9XXeJQZiSIUyziBCho1uOtq1K"
#define KEY_A_SHA256 "SHA256:Z5nlcWmfGvIbemPetkhxnentYaDYsHjOAstACMVb4SI"
#define KEY_A_MD5 "MD5:66:cf:8c:10:72:08:3e:59:82:bc:7b:c9:11:2e:4d:30"
#define KEY_B_BLOB "AAAAC3NzaC1lZDI1NTE5AAAAIIXLxJxwudMwBiK9k15FMh7wLJb1ZtENI0rc9pVZVGAe"
#define KEY_B_SHA256 "SHA256:BwQyoPyP3rzSOWVEpanRNsaYR6TKIwj29E1EadeGR9I"
#define KEY_R_BLOB "AAAAB3NzaC1yc2EAAAADAQABAAABAQCKaA4/f2eWOIaNYiBEUmnjHvPDUaK1drfgja5WvNbz20Ehyum5q1l0MmlnsW7wJvA0Nv2gkjxGUf+4g0QBHYVUDiwoJE5T46nMBCr0g4ZVRKcIdzSLKQ26EItCtrB/1SE+kLEBgrVLjb5/Y7OXm0L3oEIrc9qGTdOHKTmITeiDRdm3MuTwrf0Qq9fGnNb3mjZBohnLrxIk5N78nq/TImNSfo9Glqh1m+JYCYF5xzXLan1hAKwVI4p7/4DKXRY2QKTA2wI6NANMmaVrmT64S8Qsj8JGEz4vE0kBnnjtF2X90bxGHTUmfp8rXUp0hEwv3xePVSHfXUAHquYqXxkRUBlD"
#define KEY_R_SHA256 "SHA256:BEhv9DDiv0B29G4T9M0S7t/6BDDD7T9MP8Ayksia9Mw"
#define KEY_R_MD5 "MD5:c4:4b:04:7d:5d:bd:ec:f5:68:9a:b6:2c:ab:52:f0:b4"

static int test_blob_fingerprint_vectors(void)
{
    char type[64], fp[128];
    int ok = 1;
    ok = ok && ssh_key_blob_fingerprint(KEY_A_BLOB, "SHA256", type, sizeof(type),
                                        fp, sizeof(fp))
            && strcmp(type, "ssh-ed25519") == 0 && strcmp(fp, KEY_A_SHA256) == 0;
    ok = ok && ssh_key_blob_fingerprint(KEY_A_BLOB, "MD5", NULL, 0, fp, sizeof(fp))
            && strcmp(fp, KEY_A_MD5) == 0;
    ok = ok && ssh_key_blob_fingerprint(KEY_R_BLOB, "SHA256", type, sizeof(type),
                                        fp, sizeof(fp))
            && strcmp(type, "ssh-rsa") == 0 && strcmp(fp, KEY_R_SHA256) == 0;
    ok = ok && ssh_key_blob_fingerprint(KEY_R_BLOB, "MD5", NULL, 0, fp, sizeof(fp))
            && strcmp(fp, KEY_R_MD5) == 0;
    /* not base64, unknown hash, buffer too small */
    ok = ok && !ssh_key_blob_fingerprint("not*base64", "SHA256", NULL, 0, fp, sizeof(fp));
    ok = ok && !ssh_key_blob_fingerprint(KEY_A_BLOB, "SHA1", NULL, 0, fp, sizeof(fp));
    ok = ok && !ssh_key_blob_fingerprint(KEY_A_BLOB, "SHA256", NULL, 0, fp, 20);
    return ok;
}

static int test_fingerprint_equal(void)
{
    int ok = 1;
    ok = ok && service_account_fingerprint_equal(KEY_A_SHA256, KEY_A_SHA256);
    ok = ok && service_account_fingerprint_equal(KEY_A_SHA256 "=", KEY_A_SHA256);
    ok = ok && !service_account_fingerprint_equal(KEY_A_SHA256, KEY_B_SHA256);
    /* base64 is case-sensitive, MD5 hex is not */
    ok = ok && !service_account_fingerprint_equal(
        "SHA256:z5nlcWmfGvIbemPetkhxnentYaDYsHjOAstACMVb4SI", KEY_A_SHA256);
    ok = ok && service_account_fingerprint_equal(
        "MD5:66:CF:8C:10:72:08:3E:59:82:BC:7B:C9:11:2E:4D:30", KEY_A_MD5);
    ok = ok && !service_account_fingerprint_equal(KEY_A_SHA256, KEY_A_MD5);
    ok = ok && !service_account_fingerprint_equal(NULL, KEY_A_SHA256);
    return ok;
}

/* Key file helper: a file the test owns (SA_TRUSTED_UID is getuid()). */
static int key_file_result(const char *content, const char *expected,
                           char *got, size_t got_sz)
{
    char *path = create_temp_config_mode(content, 0644);
    if (!path) return 99;
    int r = service_account_check_key_file(path, expected, got, got_sz);
    cleanup_temp_file(path);
    return r;
}

static int test_key_file_match(void)
{
    int ok = 1;
    ok = ok && key_file_result("ssh-ed25519 " KEY_A_BLOB " ci@ops\n",
                               KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_OK;
    /* comments, blank lines, CRLF, authorized_keys options with a quoted space */
    ok = ok && key_file_result("# deploy key\n\n"
                               "from=\"10.0.0.1\",command=\"/usr/bin/run a b\" "
                               "ssh-ed25519 " KEY_A_BLOB " ci@ops\r\n",
                               KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_OK;
    ok = ok && key_file_result("ssh-rsa " KEY_R_BLOB "\n",
                               KEY_R_MD5, NULL, 0) == SA_KEYCHECK_OK;
    return ok;
}

static int test_key_file_extra_key_refused(void)
{
    char got[128] = "";
    int ok = key_file_result("ssh-ed25519 " KEY_A_BLOB " a\n"
                             "ssh-ed25519 " KEY_B_BLOB " b\n",
                             KEY_A_SHA256, got, sizeof(got)) == SA_KEYCHECK_MISMATCH;
    return ok && strcmp(got, KEY_B_SHA256) == 0;
}

static int test_key_file_malformed_refused(void)
{
    int ok = 1;
    /* a line that sshd might read but this cannot */
    ok = ok && key_file_result("ssh-ed25519 " KEY_A_BLOB "\ngarbage line\n",
                               KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_MALFORMED;
    /* the blob carries another type than the one written before it */
    ok = ok && key_file_result("ssh-rsa " KEY_A_BLOB "\n",
                               KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_MALFORMED;
    ok = ok && key_file_result("ssh-ed25519 AAAA!!!!\n",
                               KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_MALFORMED;
    return ok;
}

static int test_key_file_nothing_served(void)
{
    int ok = 1;
    ok = ok && service_account_check_key_file("/nonexistent/ci.pub", KEY_A_SHA256,
                                              NULL, 0) == SA_KEYCHECK_NONE;
    ok = ok && service_account_check_key_file("/tmp", KEY_A_SHA256,
                                              NULL, 0) == SA_KEYCHECK_NONE;
    ok = ok && key_file_result("# no key yet\n", KEY_A_SHA256, NULL, 0)
               == SA_KEYCHECK_NONE;
    return ok;
}

static int test_auth_info_match(void)
{
    int ok = 1;
    ok = ok && service_account_check_auth_info(
        "publickey ssh-ed25519 " KEY_A_BLOB "\n", KEY_A_SHA256, NULL, 0)
        == SA_KEYCHECK_OK;
    ok = ok && service_account_check_auth_info(
        "publickey ssh-rsa " KEY_R_BLOB "\n", KEY_R_MD5, NULL, 0)
        == SA_KEYCHECK_OK;
    /* a second method after the key */
    ok = ok && service_account_check_auth_info(
        "publickey ssh-ed25519 " KEY_A_BLOB "\nkeyboard-interactive/pam\n",
        KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_OK;
    return ok;
}

static int test_auth_info_other_key_refused(void)
{
    char got[128] = "";
    int ok = service_account_check_auth_info(
        "publickey ssh-ed25519 " KEY_B_BLOB "\n", KEY_A_SHA256, got, sizeof(got))
        == SA_KEYCHECK_MISMATCH && strcmp(got, KEY_B_SHA256) == 0;
    /* every key must match, not only the first or the last */
    ok = ok && service_account_check_auth_info(
        "publickey ssh-ed25519 " KEY_A_BLOB "\npublickey ssh-ed25519 " KEY_B_BLOB "\n",
        KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_MISMATCH;
    ok = ok && service_account_check_auth_info(
        "publickey ssh-ed25519 " KEY_B_BLOB "\npublickey ssh-ed25519 " KEY_A_BLOB "\n",
        KEY_A_SHA256, NULL, 0) == SA_KEYCHECK_MISMATCH;
    return ok;
}

static int test_auth_info_no_plain_key(void)
{
    int ok = 1;
    ok = ok && service_account_check_auth_info(NULL, KEY_A_SHA256, NULL, 0)
               == SA_KEYCHECK_NONE;
    ok = ok && service_account_check_auth_info("", KEY_A_SHA256, NULL, 0)
               == SA_KEYCHECK_NONE;
    ok = ok && service_account_check_auth_info("password\n", KEY_A_SHA256, NULL, 0)
               == SA_KEYCHECK_NONE;
    /* a certificate is bound in the account phase, through the spool */
    ok = ok && service_account_check_auth_info(
        "publickey ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQ= "
        "ID ci (serial 7) CA ED25519 SHA256:x\n", KEY_A_SHA256, NULL, 0)
        == SA_KEYCHECK_NONE;
    return ok;
}

static int test_auth_info_malformed_refused(void)
{
    int ok = 1;
    ok = ok && service_account_check_auth_info("publickey ssh-ed25519\n",
                                               KEY_A_SHA256, NULL, 0)
               == SA_KEYCHECK_MALFORMED;
    ok = ok && service_account_check_auth_info(
        "publickey ssh-rsa " KEY_A_BLOB "\n", KEY_A_SHA256, NULL, 0)
        == SA_KEYCHECK_MALFORMED;
    return ok;
}

int main(void)
{
    printf("Running service_account tests...\n");

    TEST(init);
    TEST(load_nonexistent);
    TEST(load_valid_config);
    TEST(load_obsolete_keys_ignored);
    TEST(load_obsolete_key_bits);
    TEST(load_drops_invalid_account);
    TEST(load_refuses_open_permissions);
    TEST(find);
    TEST(is_service_account);
    TEST(validate_key_not_found);
    TEST(validate_key_match);
    TEST(validate_key_mismatch);
    TEST(validate_key_no_config);
    TEST(validate_key_no_provided);
    TEST(account_validate_valid);
    TEST(account_validate_invalid_name);
    TEST(account_validate_missing_fingerprint);
    TEST(account_validate_invalid_fingerprint);
    TEST(null_handling);
    TEST(blob_fingerprint_vectors);
    TEST(fingerprint_equal);
    TEST(key_file_match);
    TEST(key_file_extra_key_refused);
    TEST(key_file_malformed_refused);
    TEST(key_file_nothing_served);
    TEST(auth_info_match);
    TEST(auth_info_other_key_refused);
    TEST(auth_info_no_plain_key);
    TEST(auth_info_malformed_refused);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
