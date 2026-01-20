/*
 * test_path_validator.c - Unit tests for path validation functions
 *
 * Tests the shell and home directory validation to prevent
 * path traversal and injection attacks.
 */

#include <stdio.h>
#include <string.h>

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

/* Test valid shells are accepted */
static int test_valid_shells(void)
{
    /* All default shells should be valid */
    if (config_validate_shell("/bin/bash", NULL) != 0) return 0;
    if (config_validate_shell("/bin/sh", NULL) != 0) return 0;
    if (config_validate_shell("/usr/bin/bash", NULL) != 0) return 0;
    if (config_validate_shell("/bin/zsh", NULL) != 0) return 0;
    if (config_validate_shell("/bin/dash", NULL) != 0) return 0;
    return 1;
}

/* Test invalid shells are rejected */
static int test_invalid_shells(void)
{
    /* Not in default list */
    if (config_validate_shell("/bin/custom_shell", NULL) == 0) return 0;
    if (config_validate_shell("/usr/local/bin/bash", NULL) == 0) return 0;
    return 1;
}

/* Test path traversal in shells is rejected */
static int test_shell_path_traversal(void)
{
    if (config_validate_shell("/bin/../bin/bash", NULL) == 0) return 0;
    if (config_validate_shell("/../bin/bash", NULL) == 0) return 0;
    if (config_validate_shell("/bin/bash/..", NULL) == 0) return 0;
    return 1;
}

/* Test relative paths in shells are rejected */
static int test_shell_relative_path(void)
{
    if (config_validate_shell("bin/bash", NULL) == 0) return 0;
    if (config_validate_shell("./bin/bash", NULL) == 0) return 0;
    if (config_validate_shell("bash", NULL) == 0) return 0;
    return 1;
}

/* Test special characters in shells are rejected */
static int test_shell_special_chars(void)
{
    if (config_validate_shell("/bin/bash;id", NULL) == 0) return 0;
    if (config_validate_shell("/bin/bash|cat", NULL) == 0) return 0;
    if (config_validate_shell("/bin/bash`id`", NULL) == 0) return 0;
    if (config_validate_shell("/bin/bash$(id)", NULL) == 0) return 0;
    if (config_validate_shell("/bin/ba sh", NULL) == 0) return 0;
    if (config_validate_shell("/bin/bash\n", NULL) == 0) return 0;
    return 1;
}

/* Test custom approved shells list */
static int test_custom_shells_list(void)
{
    const char *custom = "/usr/local/bin/mybash:/opt/shell";

    /* Custom shells should be valid */
    if (config_validate_shell("/usr/local/bin/mybash", custom) != 0) return 0;
    if (config_validate_shell("/opt/shell", custom) != 0) return 0;

    /* Default shells should NOT be valid with custom list */
    if (config_validate_shell("/bin/bash", custom) == 0) return 0;

    return 1;
}

/* Test valid home directories */
static int test_valid_home(void)
{
    if (config_validate_home("/home/user", NULL) != 0) return 0;
    if (config_validate_home("/home/user123", NULL) != 0) return 0;
    if (config_validate_home("/home/test-user", NULL) != 0) return 0;
    if (config_validate_home("/home/test_user", NULL) != 0) return 0;
    if (config_validate_home("/var/home/user", NULL) != 0) return 0;
    return 1;
}

/* Test invalid home directories */
static int test_invalid_home(void)
{
    /* Not under approved prefixes */
    if (config_validate_home("/root", NULL) == 0) return 0;
    if (config_validate_home("/tmp/user", NULL) == 0) return 0;
    if (config_validate_home("/etc/passwd", NULL) == 0) return 0;
    return 1;
}

/* Test path traversal in home is rejected */
static int test_home_path_traversal(void)
{
    if (config_validate_home("/home/../etc/passwd", NULL) == 0) return 0;
    if (config_validate_home("/home/user/..", NULL) == 0) return 0;
    if (config_validate_home("/home/user/../../root", NULL) == 0) return 0;
    return 1;
}

/* Test relative paths in home are rejected */
static int test_home_relative_path(void)
{
    if (config_validate_home("home/user", NULL) == 0) return 0;
    if (config_validate_home("./home/user", NULL) == 0) return 0;
    if (config_validate_home("user", NULL) == 0) return 0;
    return 1;
}

/* Test hidden paths in home are rejected */
static int test_home_hidden_path(void)
{
    if (config_validate_home("/home/.hidden", NULL) == 0) return 0;
    if (config_validate_home("/home/user/.ssh", NULL) == 0) return 0;
    return 1;
}

/* Test special characters in home are rejected */
static int test_home_special_chars(void)
{
    if (config_validate_home("/home/user;id", NULL) == 0) return 0;
    if (config_validate_home("/home/user|cat", NULL) == 0) return 0;
    if (config_validate_home("/home/user`id`", NULL) == 0) return 0;
    if (config_validate_home("/home/user$(id)", NULL) == 0) return 0;
    if (config_validate_home("/home/us er", NULL) == 0) return 0;
    return 1;
}

/* Test custom approved home prefixes */
static int test_custom_home_prefixes(void)
{
    const char *custom = "/data/users:/srv/home";

    /* Custom prefixes should work */
    if (config_validate_home("/data/users/bob", custom) != 0) return 0;
    if (config_validate_home("/srv/home/alice", custom) != 0) return 0;

    /* Default prefix should NOT work with custom list */
    if (config_validate_home("/home/user", custom) == 0) return 0;

    return 1;
}

/* Test null and empty inputs */
static int test_null_empty_inputs(void)
{
    if (config_validate_shell(NULL, NULL) == 0) return 0;
    if (config_validate_shell("", NULL) == 0) return 0;
    if (config_validate_home(NULL, NULL) == 0) return 0;
    if (config_validate_home("", NULL) == 0) return 0;
    return 1;
}

/* Test double slashes are rejected */
static int test_double_slashes(void)
{
    if (config_validate_shell("//bin/bash", NULL) == 0) return 0;
    if (config_validate_shell("/bin//bash", NULL) == 0) return 0;
    if (config_validate_home("/home//user", NULL) == 0) return 0;
    if (config_validate_home("//home/user", NULL) == 0) return 0;
    return 1;
}

/* Test that excessively long paths are rejected (DoS prevention) */
static int test_path_length_limit(void)
{
    /* Create a path longer than MAX_SAFE_PATH_LENGTH (1024) */
    char long_path[2048];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';

    /* Very long paths should be rejected */
    if (config_validate_shell(long_path, long_path) == 0) return 0;
    if (config_validate_home(long_path, long_path) == 0) return 0;

    return 1;
}

int main(void)
{
    printf("Path Validator Tests\n");
    printf("====================\n\n");

    printf("Shell validation:\n");
    TEST(valid_shells);
    TEST(invalid_shells);
    TEST(shell_path_traversal);
    TEST(shell_relative_path);
    TEST(shell_special_chars);
    TEST(custom_shells_list);

    printf("\nHome validation:\n");
    TEST(valid_home);
    TEST(invalid_home);
    TEST(home_path_traversal);
    TEST(home_relative_path);
    TEST(home_hidden_path);
    TEST(home_special_chars);
    TEST(custom_home_prefixes);

    printf("\nEdge cases:\n");
    TEST(null_empty_inputs);
    TEST(double_slashes);
    TEST(path_length_limit);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
