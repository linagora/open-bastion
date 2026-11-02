/*
 * test_home_dir.c - Unit tests for the staged home directory helpers
 *
 * The home of a created account is assembled in a private sibling directory
 * and renamed into place once complete (issue #414). These tests cover the
 * naming of that staging directory and the refusal to replace an occupied
 * final path.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "home_dir.h"

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

static int make_base(char *dir, size_t size)
{
    snprintf(dir, size, "/tmp/ob-home-dir-XXXXXX");
    return mkdtemp(dir) != NULL;
}

static void remove_base(const char *dir)
{
    char cmd[PATH_MAX + 16];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) {
        fprintf(stderr, "cannot remove %s\n", dir);
    }
}

static int write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");

    if (!f) {
        return 0;
    }
    if (fputs(content, f) == EOF) {
        fclose(f);
        return 0;
    }
    return fclose(f) == 0;
}

static int read_file(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "r");
    size_t n;

    if (!f) {
        return 0;
    }
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return 1;
}

/* The staging directory is a hidden sibling of the home. */
static int test_temp_template(void)
{
    char out[PATH_MAX];

    if (home_dir_temp_template("/home/alice", out, sizeof(out)) != 0) return 0;
    if (strcmp(out, "/home/.ob-home.XXXXXX") != 0) return 0;

    if (home_dir_temp_template("/var/home/alice", out, sizeof(out)) != 0) return 0;
    if (strcmp(out, "/var/home/.ob-home.XXXXXX") != 0) return 0;

    /* A trailing slash is ignored: the home is not its own staging parent. */
    if (home_dir_temp_template("/home/alice/", out, sizeof(out)) != 0) return 0;
    if (strcmp(out, "/home/.ob-home.XXXXXX") != 0) return 0;

    /* A base ending in '/' yields "//"; the template stays a clean sibling. */
    if (home_dir_temp_template("/home//alice", out, sizeof(out)) != 0) return 0;
    if (strcmp(out, "/home/.ob-home.XXXXXX") != 0) return 0;
    if (home_dir_temp_template("/home///alice/", out, sizeof(out)) != 0) return 0;
    if (strcmp(out, "/home/.ob-home.XXXXXX") != 0) return 0;

    /* No parent to stage in. */
    if (home_dir_temp_template("/alice", out, sizeof(out)) == 0) return 0;
    if (home_dir_temp_template("//alice", out, sizeof(out)) == 0) return 0;
    if (home_dir_temp_template("alice", out, sizeof(out)) == 0) return 0;
    if (home_dir_temp_template("alice/bob", out, sizeof(out)) == 0) return 0;
    if (home_dir_temp_template("", out, sizeof(out)) == 0) return 0;
    if (home_dir_temp_template(NULL, out, sizeof(out)) == 0) return 0;

    /* Buffer too small for the template. */
    if (home_dir_temp_template("/home/alice", out, 8) == 0) return 0;

    return 1;
}

/* mkdtemp() on the template yields a private directory beside the home. */
static int test_staging_directory(void)
{
    char base[] = "/tmp/ob-home-dir-XXXXXX";
    char home[PATH_MAX];
    char tmp[PATH_MAX];
    struct stat st;
    int ok = 1;

    if (!mkdtemp(base)) return 0;
    snprintf(home, sizeof(home), "%s/alice", base);

    if (home_dir_temp_template(home, tmp, sizeof(tmp)) != 0) {
        ok = 0;
    } else if (!mkdtemp(tmp)) {
        ok = 0;
    } else if (lstat(tmp, &st) != 0) {
        ok = 0;
    } else {
        if (!S_ISDIR(st.st_mode)) ok = 0;
        if ((st.st_mode & 0777) != 0700) ok = 0;
        if (strncmp(tmp, base, strlen(base)) != 0) ok = 0;
        if (strstr(tmp, "/.ob-home.") == NULL) ok = 0;
        if (lstat(home, &st) == 0) ok = 0;  /* nothing at the final path yet */
    }

    remove_base(base);
    return ok;
}

/* A complete staged tree reaches the final path in one step. */
static int test_commit_into_place(void)
{
    char base[] = "/tmp/ob-home-dir-XXXXXX";
    char home[PATH_MAX];
    char tmp[PATH_MAX];
    char file[PATH_MAX];
    char content[32];
    struct stat st;
    int ok = 1;

    if (!mkdtemp(base)) return 0;
    snprintf(home, sizeof(home), "%s/alice", base);

    if (home_dir_temp_template(home, tmp, sizeof(tmp)) != 0 || !mkdtemp(tmp)) {
        remove_base(base);
        return 0;
    }

    snprintf(file, sizeof(file), "%s/.profile", tmp);
    if (!write_file(file, "staged\n")) ok = 0;

    if (ok && home_dir_commit(tmp, home) != 0) ok = 0;

    if (ok) {
        snprintf(file, sizeof(file), "%s/.profile", home);
        if (lstat(home, &st) != 0 || !S_ISDIR(st.st_mode)) ok = 0;
        else if (!read_file(file, content, sizeof(content))) ok = 0;
        else if (strcmp(content, "staged\n") != 0) ok = 0;
        else if (lstat(tmp, &st) == 0) ok = 0;  /* staging name is gone */
    }

    remove_base(base);
    return ok;
}

/* A non-empty directory that appeared meanwhile is refused, not replaced. */
static int test_commit_refuses_occupied(void)
{
    char base[] = "/tmp/ob-home-dir-XXXXXX";
    char home[PATH_MAX];
    char tmp[PATH_MAX];
    char file[PATH_MAX];
    char content[32];
    struct stat st;
    int ok = 1;

    if (!mkdtemp(base)) return 0;
    snprintf(home, sizeof(home), "%s/alice", base);
    if (mkdir(home, 0700) != 0) {
        remove_base(base);
        return 0;
    }
    snprintf(file, sizeof(file), "%s/keep", home);
    if (!write_file(file, "keep\n")) ok = 0;

    if (ok && (home_dir_temp_template(home, tmp, sizeof(tmp)) != 0 || !mkdtemp(tmp))) ok = 0;

    if (ok) {
        errno = 0;
        if (home_dir_commit(tmp, home) == 0) ok = 0;
        if (errno != ENOTEMPTY && errno != EEXIST) ok = 0;
    }

    if (ok) {
        snprintf(file, sizeof(file), "%s/keep", home);
        if (!read_file(file, content, sizeof(content))) ok = 0;
        else if (strcmp(content, "keep\n") != 0) ok = 0;
        else if (lstat(tmp, &st) != 0) ok = 0;  /* caller still owns the staging tree */
    }

    remove_base(base);
    return ok;
}

/* A regular file at the home path is refused too. */
static int test_commit_refuses_file(void)
{
    char base[] = "/tmp/ob-home-dir-XXXXXX";
    char home[PATH_MAX];
    char tmp[PATH_MAX];
    struct stat st;
    int ok = 1;

    if (!mkdtemp(base)) return 0;
    snprintf(home, sizeof(home), "%s/alice", base);
    if (!write_file(home, "not a home\n")) {
        remove_base(base);
        return 0;
    }

    if (home_dir_temp_template(home, tmp, sizeof(tmp)) != 0 || !mkdtemp(tmp)) ok = 0;

    if (ok) {
        errno = 0;
        if (home_dir_commit(tmp, home) == 0) ok = 0;
        if (errno != ENOTDIR && errno != EEXIST) ok = 0;
        if (lstat(home, &st) != 0 || !S_ISREG(st.st_mode)) ok = 0;
    }

    remove_base(base);
    return ok;
}

int main(void)
{
    printf("Home Directory Tests\n");
    printf("====================\n\n");

    TEST(temp_template);
    TEST(staging_directory);
    TEST(commit_into_place);
    TEST(commit_refuses_occupied);
    TEST(commit_refuses_file);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
