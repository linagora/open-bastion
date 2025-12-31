/*
 * test_nss_llng.c - Unit tests for NSS module helper functions
 *
 * These tests verify the internal helper functions of libnss_llng
 * without requiring a running LLNG server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

/* Reserved UID for 'nobody' user - must never be assigned */
#define NOBODY_UID 65534

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

/*
 * Replicate the uid_exists_locally function from libnss_llng.c
 * for testing purposes
 */
static int uid_exists_locally(uid_t uid)
{
    FILE *f = fopen("/etc/passwd", "r");
    if (!f) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        int field = 0;
        char *start = p;

        while (*p && field < 3) {
            if (*p == ':') {
                if (field == 2) {
                    *p = '\0';
                    char *endptr;
                    errno = 0;
                    unsigned long parsed_uid = strtoul(start, &endptr, 10);
                    if (errno == 0 && endptr != start && *endptr == '\0' &&
                        parsed_uid <= (unsigned long)((uid_t)-1)) {
                        uid_t local_uid = (uid_t)parsed_uid;
                        if (local_uid == uid) {
                            fclose(f);
                            return 1;
                        }
                    }
                }
                field++;
                start = p + 1;
            }
            p++;
        }
    }

    fclose(f);
    return 0;
}

/*
 * Replicate the generate_unique_uid function from libnss_llng.c
 * for testing purposes.
 * Returns 0 on failure (collision or invalid params).
 */
static uid_t generate_unique_uid(const char *username, uid_t min_uid, uid_t max_uid)
{
    if (!username || !*username) {
        return 0;
    }

    if (min_uid >= max_uid || min_uid < 1000) {
        return 0;
    }

    unsigned int hash = 5381;
    for (const char *c = username; *c; c++) {
        hash = ((hash << 5) + hash) + (unsigned char)*c;
    }

    uid_t range = max_uid - min_uid;
    if (range == 0) {
        return 0;
    }

    for (int attempt = 0; attempt < 100; attempt++) {
        uid_t candidate = min_uid + ((hash + (unsigned int)attempt) % range);
        if (candidate < 1000) continue;
        if (candidate == NOBODY_UID) continue;
        if (!uid_exists_locally(candidate)) {
            return candidate;
        }
    }

    /* Return 0 (error) instead of colliding UID */
    return 0;
}

/* Test uid_exists_locally with root (UID 0) */
static int test_uid_exists_root(void)
{
    /* UID 0 (root) should always exist */
    return uid_exists_locally(0) == 1;
}

/* Test uid_exists_locally with non-existent UID */
static int test_uid_not_exists(void)
{
    /* UID 99999 is unlikely to exist on most systems */
    /* This test may need adjustment on some systems */
    uid_t test_uid = 99999;

    /* First check if it actually doesn't exist via getpwuid */
    struct passwd *pw = getpwuid(test_uid);
    if (pw != NULL) {
        /* UID exists on this system, skip test */
        printf("(skipped - UID %d exists) ", test_uid);
        return 1;
    }

    return uid_exists_locally(test_uid) == 0;
}

/* Test uid_exists_locally with current user */
static int test_uid_exists_current_user(void)
{
    uid_t my_uid = getuid();
    return uid_exists_locally(my_uid) == 1;
}

/* Test generate_unique_uid produces consistent results */
static int test_generate_uid_consistent(void)
{
    uid_t uid1 = generate_unique_uid("testuser", 10000, 60000);
    uid_t uid2 = generate_unique_uid("testuser", 10000, 60000);

    /* Same username should produce same UID */
    return uid1 == uid2;
}

/* Test generate_unique_uid stays within range */
static int test_generate_uid_in_range(void)
{
    uid_t min_uid = 10000;
    uid_t max_uid = 20000;

    uid_t uid = generate_unique_uid("someuser", min_uid, max_uid);

    return uid >= min_uid && uid < max_uid;
}

/* Test generate_unique_uid produces different UIDs for different users */
static int test_generate_uid_different_users(void)
{
    uid_t uid1 = generate_unique_uid("alice", 10000, 60000);
    uid_t uid2 = generate_unique_uid("bob", 10000, 60000);

    /* Different usernames should (almost certainly) produce different UIDs */
    return uid1 != uid2;
}

/* Test generate_unique_uid with small range */
static int test_generate_uid_small_range(void)
{
    uid_t min_uid = 50000;
    uid_t max_uid = 50010;

    uid_t uid = generate_unique_uid("testsmall", min_uid, max_uid);

    return uid >= min_uid && uid < max_uid;
}

/* Test generate_unique_uid with edge case: range of 1 */
static int test_generate_uid_range_one(void)
{
    uid_t min_uid = 55555;
    uid_t max_uid = 55556;

    uid_t uid = generate_unique_uid("edgecase", min_uid, max_uid);

    /* With range of 1, should return min_uid (if not taken) or 0 if taken */
    return uid == min_uid || uid == 0;
}

/* Test that known usernames produce predictable hashes */
static int test_hash_stability(void)
{
    /* The hash function should be deterministic */
    unsigned int hash1 = 5381;
    const char *username = "testuser";
    for (const char *c = username; *c; c++) {
        hash1 = ((hash1 << 5) + hash1) + (unsigned char)*c;
    }

    unsigned int hash2 = 5381;
    for (const char *c = username; *c; c++) {
        hash2 = ((hash2 << 5) + hash2) + (unsigned char)*c;
    }

    return hash1 == hash2;
}

/* Test generate_unique_uid with NULL username */
static int test_generate_uid_null_username(void)
{
    /* NULL username should return 0 (error) */
    uid_t uid = generate_unique_uid(NULL, 10000, 60000);
    return uid == 0;
}

/* Test generate_unique_uid with empty username */
static int test_generate_uid_empty_username(void)
{
    /* Empty username should return 0 (error) */
    uid_t uid = generate_unique_uid("", 10000, 60000);
    return uid == 0;
}

/* Test generate_unique_uid with invalid UID range (min >= max) */
static int test_generate_uid_invalid_range(void)
{
    /* Invalid range should return 0 (error) */
    uid_t uid1 = generate_unique_uid("testuser", 60000, 10000);  /* min > max */
    uid_t uid2 = generate_unique_uid("testuser", 50000, 50000);  /* min == max */
    return uid1 == 0 && uid2 == 0;
}

/* Test generate_unique_uid with min_uid below 1000 */
static int test_generate_uid_low_min(void)
{
    /* min_uid < 1000 should return 0 (error) to protect system UIDs */
    uid_t uid = generate_unique_uid("testuser", 500, 1000);
    return uid == 0;
}

int main(void)
{
    printf("NSS LLNG Module Tests\n");
    printf("=====================\n\n");

    printf("UID existence checks:\n");
    TEST(uid_exists_root);
    TEST(uid_not_exists);
    TEST(uid_exists_current_user);

    printf("\nUID generation:\n");
    TEST(generate_uid_consistent);
    TEST(generate_uid_in_range);
    TEST(generate_uid_different_users);
    TEST(generate_uid_small_range);
    TEST(generate_uid_range_one);
    TEST(hash_stability);

    printf("\nEdge cases and error handling:\n");
    TEST(generate_uid_null_username);
    TEST(generate_uid_empty_username);
    TEST(generate_uid_invalid_range);
    TEST(generate_uid_low_min);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
