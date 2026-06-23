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
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

/* Reserved UID for 'nobody' user - must never be assigned */
#define NOBODY_UID 65534

/* TTL used by the name-cache tests (mirrors g_config.cache_ttl in production) */
#define TEST_CACHE_TTL 300

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

/* ------------------------------------------------------------------------
 * Name-keyed file cache tests
 *
 * These replicate the production helpers from libnss_openbastion.c
 * (valid_cache_name / file_cache_write_atomic / file_cache_load_by_name),
 * parameterized on a temp directory so the hardcoded secure CACHE_DIR_BYNAME
 * path in production is NOT weakened. The replicated copies must stay
 * byte-for-byte equivalent in logic to the production functions.
 * ------------------------------------------------------------------------ */

/* Replicated from libnss_openbastion.c: valid_cache_name() */
static int t_valid_cache_name(const char *name)
{
    if (!name || name[0] == '\0') return -1;
    if (name[0] == '.') return -1;
    for (const char *c = name; *c; c++) {
        unsigned char ch = (unsigned char)*c;
        if (ch == '/') return -1;
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '-')) {
            return -1;
        }
    }
    return 0;
}

/* Replicated safe_strcpy from libnss_openbastion.c */
static int t_safe_strcpy(char **dst, size_t *remaining, const char *src)
{
    if (!dst || !*dst || !remaining || *remaining == 0) return -1;
    const char *source = src ? src : "";
    size_t src_len = strlen(source);
    if (src_len >= *remaining) return -1;
    memcpy(*dst, source, src_len);
    (*dst)[src_len] = '\0';
    *dst += src_len + 1;
    *remaining -= src_len + 1;
    return 0;
}

static int t_safe_parse_uid(const char *str, uid_t *result)
{
    if (!str || !result) return -1;
    char *endptr;
    errno = 0;
    unsigned long val = strtoul(str, &endptr, 10);
    if (errno != 0 || endptr == str || *endptr != '\0') return -1;
    if (val > (unsigned long)((uid_t)-1)) return -1;
    *result = (uid_t)val;
    return 0;
}

static int t_safe_parse_gid(const char *str, gid_t *result)
{
    if (!str || !result) return -1;
    char *endptr;
    errno = 0;
    unsigned long val = strtoul(str, &endptr, 10);
    if (errno != 0 || endptr == str || *endptr != '\0') return -1;
    if (val > (unsigned long)((gid_t)-1)) return -1;
    *result = (gid_t)val;
    return 0;
}

/*
 * Replicated split_cache_line() from libnss_openbastion.c: split into EXACTLY
 * 7 fields on ':' WITHOUT collapsing consecutive delimiters (so empty fields,
 * e.g. an empty GECOS, are preserved). Returns 0 iff exactly 7 fields.
 */
static int t_split_cache_line(char *line, char *out[7])
{
    int n = 0;
    char *field = line;
    for (char *p = line; ; p++) {
        if (*p == ':' || *p == '\0') {
            int end = (*p == '\0');
            if (n >= 7) return -1;
            *p = '\0';
            out[n++] = field;
            if (end) break;
            field = p + 1;
        }
    }
    if (n != 7) return -1;
    char *last = out[6];
    size_t llen = strlen(last);
    while (llen > 0 && (last[llen - 1] == '\n' || last[llen - 1] == '\r')) {
        last[--llen] = '\0';
    }
    return 0;
}

/*
 * Replicated open_cache_dir_verified(), but parameterized on the owner uid we
 * require (production hardcodes 0). Tests running as a non-root user pass their
 * own uid so the positive paths work, while still exercising the mode-based
 * (group/world-writable) rejection that does not depend on ownership.
 * Returns a dir fd on success, -1 otherwise.
 */
static int t_open_cache_dir_verified(const char *dir, uid_t want_owner)
{
    if (mkdir(dir, 0755) == -1 && errno != EEXIST) return -1;
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dfd < 0) return -1;
    struct stat st;
    if (fstat(dfd, &st) != 0) { close(dfd); return -1; }
    if (!S_ISDIR(st.st_mode) || st.st_uid != want_owner ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(dfd);
        return -1;
    }
    return dfd;
}

/*
 * Replicated open_cache_file_verified(), parameterized on the required owner.
 * Returns a FILE* opened for reading on success, NULL otherwise.
 */
static FILE *t_open_cache_file_verified(int dirfd, const char *leaf, uid_t want_owner)
{
    int fd = openat(dirfd, leaf, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    if (!S_ISREG(st.st_mode) || st.st_uid != want_owner ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(fd);
        return NULL;
    }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return NULL; }
    return f;
}

/*
 * Replicated save (write_atomic_at + save_by_name) parameterized on a dir and
 * the owner uid the verify step requires. The `ts` argument lets tests forge
 * the stored timestamp (production always uses time(NULL)); negative ts = now.
 * Returns 0 on success, -1 otherwise.
 */
static int t_save_by_name(const char *dir, uid_t want_owner,
                          const struct passwd *pw, long ts)
{
    if (!pw || !pw->pw_name) return -1;
    if (t_valid_cache_name(pw->pw_name) != 0) return -1;

    int dirfd = t_open_cache_dir_verified(dir, want_owner);
    if (dirfd < 0) return -1;

    char tmpleaf[128];
    int tlen = snprintf(tmpleaf, sizeof(tmpleaf), ".tmp.%s.%ld",
                        pw->pw_name, (long)getpid());
    if (tlen < 0 || (size_t)tlen >= sizeof(tmpleaf)) { close(dirfd); return -1; }

    int fd = openat(dirfd, tmpleaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { close(dirfd); return -1; }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlinkat(dirfd, tmpleaf, 0); close(dirfd); return -1; }

    fprintf(f, "%s:%u:%u:%s:%s:%s:%ld\n",
            pw->pw_name,
            (unsigned)pw->pw_uid,
            (unsigned)pw->pw_gid,
            pw->pw_gecos ? pw->pw_gecos : "",
            pw->pw_dir ? pw->pw_dir : "",
            pw->pw_shell ? pw->pw_shell : "",
            ts < 0 ? (long)time(NULL) : ts);

    if (fchmod(fileno(f), 0644) != 0 || fflush(f) != 0 || ferror(f)) {
        fclose(f); unlinkat(dirfd, tmpleaf, 0); close(dirfd); return -1;
    }
    if (fclose(f) != 0) { unlinkat(dirfd, tmpleaf, 0); close(dirfd); return -1; }
    if (renameat(dirfd, tmpleaf, dirfd, pw->pw_name) != 0) {
        unlinkat(dirfd, tmpleaf, 0); close(dirfd); return -1;
    }
    close(dirfd);
    return 0;
}

/*
 * Replicated load (file_cache_load_by_name + parse_into), parameterized on a
 * dir, the required owner, and TTL. Uses the non-collapsing splitter and the
 * dir/file verification. Returns 0 on success, -1 otherwise.
 */
static int t_load_by_name(const char *dir, uid_t want_owner, const char *name,
                          int ttl, struct passwd *pw, char *buffer, size_t buflen)
{
    if (t_valid_cache_name(name) != 0) return -1;

    int dirfd = t_open_cache_dir_verified(dir, want_owner);
    if (dirfd < 0) return -1;

    FILE *f = t_open_cache_file_verified(dirfd, name, want_owner);
    if (!f) { close(dirfd); return -1; }
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); close(dirfd); return -1; }
    fclose(f);

    char *fields[7];
    if (t_split_cache_line(line, fields) != 0) { close(dirfd); return -1; }
    char *username_str  = fields[0];
    char *uid_str       = fields[1];
    char *gid_str       = fields[2];
    char *gecos_str     = fields[3];
    char *home_str      = fields[4];
    char *shell_str     = fields[5];
    char *timestamp_str = fields[6];

    if (username_str[0] == '\0' || uid_str[0] == '\0' ||
        gid_str[0] == '\0' || timestamp_str[0] == '\0') {
        close(dirfd); return -1;
    }

    char *endptr;
    errno = 0;
    long timestamp = strtol(timestamp_str, &endptr, 10);
    while (*endptr != '\0' && isspace((unsigned char)*endptr)) endptr++;
    if (errno != 0 || endptr == timestamp_str || *endptr != '\0') {
        close(dirfd); return -1;
    }
    if (time(NULL) - timestamp > ttl) {
        unlinkat(dirfd, name, 0);
        close(dirfd); return -1;
    }

    if (strcmp(username_str, name) != 0) { close(dirfd); return -1; }

    uid_t file_uid;
    if (t_safe_parse_uid(uid_str, &file_uid) != 0) { close(dirfd); return -1; }
    gid_t file_gid;
    if (t_safe_parse_gid(gid_str, &file_gid) != 0) { close(dirfd); return -1; }

    char *p = buffer;
    size_t remaining = buflen;
    pw->pw_name = p;
    if (t_safe_strcpy(&p, &remaining, username_str) != 0) { close(dirfd); return -1; }
    pw->pw_passwd = p;
    if (t_safe_strcpy(&p, &remaining, "x") != 0) { close(dirfd); return -1; }
    pw->pw_uid = file_uid;
    pw->pw_gid = file_gid;
    pw->pw_gecos = p;
    if (t_safe_strcpy(&p, &remaining, gecos_str) != 0) { close(dirfd); return -1; }
    pw->pw_dir = p;
    if (t_safe_strcpy(&p, &remaining, home_str) != 0) { close(dirfd); return -1; }
    pw->pw_shell = p;
    if (t_safe_strcpy(&p, &remaining, shell_str) != 0) { close(dirfd); return -1; }
    close(dirfd);
    return 0;
}

/* Build a unique temp directory for a test; caller must rm it. */
static int make_tmpdir(char *out, size_t outlen)
{
    snprintf(out, outlen, "/tmp/nss_ob_test_%d_%ld", (int)getpid(), (long)time(NULL));
    /* Add a counter suffix in case of collisions within the same second. */
    static int counter = 0;
    char full[512];
    snprintf(full, sizeof(full), "%s_%d", out, counter++);
    if (mkdir(full, 0755) != 0 && errno != EEXIST) return -1;
    snprintf(out, outlen, "%s", full);
    return 0;
}

static void rm_rf_files(const char *dir)
{
    /* The cache dir only ever contains flat files (no subdirs), so a shallow
     * cleanup via a glob-free approach is enough for tests. */
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) {
        /* best-effort cleanup; ignore */
    }
}

/* (a) filename validation rejects traversal / leading dot / out-of-charset */
static int test_name_validation_rejects(void)
{
    if (t_valid_cache_name(NULL) == 0) return 0;
    if (t_valid_cache_name("") == 0) return 0;
    if (t_valid_cache_name("/etc/passwd") == 0) return 0;
    if (t_valid_cache_name("foo/bar") == 0) return 0;
    if (t_valid_cache_name("../escape") == 0) return 0;
    if (t_valid_cache_name(".hidden") == 0) return 0;
    if (t_valid_cache_name(".") == 0) return 0;
    if (t_valid_cache_name("..") == 0) return 0;
    if (t_valid_cache_name("UPPER") == 0) return 0;     /* uppercase rejected */
    if (t_valid_cache_name("white space") == 0) return 0;
    if (t_valid_cache_name("co:lon") == 0) return 0;
    if (t_valid_cache_name("new\nline") == 0) return 0;
    if (t_valid_cache_name("na\\me") == 0) return 0;
    return 1;
}

/* filename validation accepts legitimate usernames */
static int test_name_validation_accepts(void)
{
    if (t_valid_cache_name("alice") != 0) return 0;
    if (t_valid_cache_name("bob123") != 0) return 0;
    if (t_valid_cache_name("svc_account") != 0) return 0;
    if (t_valid_cache_name("with-dash") != 0) return 0;
    if (t_valid_cache_name("a") != 0) return 0;
    if (t_valid_cache_name("0digitstart") != 0) return 0;  /* charset OK here */
    return 1;
}

/* The verify helpers require the cache dir/files be owned by a specific uid.
 * Production hardcodes root (0); tests run unprivileged, so they require the
 * test process's own uid (the owner of the files it creates in /tmp). This
 * still exercises the mode-based (group/world-writable) rejection, which is
 * independent of ownership. */
#define TEST_OWNER (getuid())

/* (b) round-trip save_by_name -> load_by_name preserves all fields */
static int test_name_roundtrip(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    struct passwd in = {0};
    in.pw_name = "alice";
    in.pw_passwd = "x";
    in.pw_uid = 12345;
    in.pw_gid = 100;
    in.pw_gecos = "Alice Example";
    in.pw_dir = "/home/alice";
    in.pw_shell = "/bin/bash";

    int ok = 1;
    if (t_save_by_name(dir, TEST_OWNER, &in, -1) != 0) ok = 0;

    struct passwd out = {0};
    char buf[1024];
    if (ok && t_load_by_name(dir, TEST_OWNER, "alice", TEST_CACHE_TTL, &out, buf, sizeof(buf)) != 0) ok = 0;

    if (ok) {
        if (strcmp(out.pw_name, "alice") != 0) ok = 0;
        if (strcmp(out.pw_passwd, "x") != 0) ok = 0;
        if (out.pw_uid != 12345) ok = 0;
        if (out.pw_gid != 100) ok = 0;
        if (strcmp(out.pw_gecos, "Alice Example") != 0) ok = 0;
        if (strcmp(out.pw_dir, "/home/alice") != 0) ok = 0;
        if (strcmp(out.pw_shell, "/bin/bash") != 0) ok = 0;
    }

    rm_rf_files(dir);
    return ok;
}

/* round-trip with an EMPTY gecos now succeeds: the non-collapsing splitter
 * preserves the empty field instead of shifting later fields left. This is the
 * MEDIUM fix — empty-gecos users must hit the cache, not fall through. */
static int test_name_roundtrip_empty_gecos(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    struct passwd in = {0};
    in.pw_name = "svc_deploy";
    in.pw_uid = 20001;
    in.pw_gid = 20001;
    in.pw_gecos = "";   /* empty GECOS */
    in.pw_dir = "/home/svc_deploy";
    in.pw_shell = "/bin/sh";

    int ok = 1;
    if (t_save_by_name(dir, TEST_OWNER, &in, -1) != 0) ok = 0;

    struct passwd out = {0};
    char buf[1024];
    if (ok && t_load_by_name(dir, TEST_OWNER, "svc_deploy", TEST_CACHE_TTL, &out, buf, sizeof(buf)) != 0) ok = 0;
    if (ok && (out.pw_uid != 20001 || out.pw_gid != 20001)) ok = 0;
    if (ok && strcmp(out.pw_gecos, "") != 0) ok = 0;
    if (ok && strcmp(out.pw_dir, "/home/svc_deploy") != 0) ok = 0;
    if (ok && strcmp(out.pw_shell, "/bin/sh") != 0) ok = 0;

    rm_rf_files(dir);
    return ok;
}

/* (c) an entry older than TTL is rejected (and unlinked) */
static int test_name_expired_rejected(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    struct passwd in = {0};
    in.pw_name = "stale";
    in.pw_uid = 30000;
    in.pw_gid = 100;
    in.pw_gecos = "Stale User";
    in.pw_dir = "/home/stale";
    in.pw_shell = "/bin/bash";

    /* Forge a timestamp well beyond the TTL. */
    long old_ts = (long)time(NULL) - (TEST_CACHE_TTL + 60);

    int ok = 1;
    if (t_save_by_name(dir, TEST_OWNER, &in, old_ts) != 0) ok = 0;

    struct passwd out = {0};
    char buf[1024];
    /* Expired -> must fail to load. */
    if (ok && t_load_by_name(dir, TEST_OWNER, "stale", TEST_CACHE_TTL, &out, buf, sizeof(buf)) == 0) ok = 0;

    /* And the expired file must have been unlinked. */
    if (ok) {
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/stale", dir);
        if (access(filepath, F_OK) == 0) ok = 0;
    }

    rm_rf_files(dir);
    return ok;
}

/* A name mismatch (file content differs from requested key) is rejected. */
static int test_name_mismatch_rejected(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    /* Write a file named "alice" but containing a "mallory" record by hand. */
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/alice", dir);
    FILE *f = fopen(filepath, "w");
    int ok = 1;
    if (!f) { rm_rf_files(dir); return 0; }
    fprintf(f, "mallory:0:0:root:/root:/bin/bash:%ld\n", (long)time(NULL));
    fclose(f);
    /* Make sure the file is not group/world-writable so the trust check (which
     * we are NOT testing here) does not pre-empt the name-mismatch check. */
    chmod(filepath, 0644);

    struct passwd out = {0};
    char buf[1024];
    /* Stored username "mallory" != requested "alice" -> reject. */
    if (t_load_by_name(dir, TEST_OWNER, "alice", TEST_CACHE_TTL, &out, buf, sizeof(buf)) == 0) ok = 0;

    rm_rf_files(dir);
    return ok;
}

/* load_by_name on a missing entry returns -1 (no crash). */
static int test_name_missing(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;
    struct passwd out = {0};
    char buf[1024];
    int ok = (t_load_by_name(dir, TEST_OWNER, "nobody_here", TEST_CACHE_TTL, &out, buf, sizeof(buf)) != 0);
    rm_rf_files(dir);
    return ok;
}

/* save refuses unsafe names (no file is created). */
static int test_name_save_rejects_unsafe(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    struct passwd in = {0};
    in.pw_name = "../evil";
    in.pw_uid = 40000;
    in.pw_gid = 100;
    in.pw_gecos = "";
    in.pw_dir = "/home/evil";
    in.pw_shell = "/bin/bash";

    /* save must refuse and create nothing. */
    int ok = (t_save_by_name(dir, TEST_OWNER, &in, -1) != 0);

    rm_rf_files(dir);
    return ok;
}

/* SECURITY: a group/world-writable cache file is rejected by the load path,
 * even though its content is otherwise valid. This is the anti cache-poisoning
 * trust check (mode component, which is independent of ownership). */
static int test_name_load_rejects_writable_file(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    /* First write a perfectly valid entry, then loosen its mode. */
    struct passwd in = {0};
    in.pw_name = "victim";
    in.pw_uid = 12345;
    in.pw_gid = 100;
    in.pw_gecos = "Victim";
    in.pw_dir = "/home/victim";
    in.pw_shell = "/bin/bash";

    int ok = 1;
    if (t_save_by_name(dir, TEST_OWNER, &in, -1) != 0) ok = 0;

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/victim", dir);

    /* Sanity: it loads while mode is 0644. */
    struct passwd out = {0};
    char buf[1024];
    if (ok && t_load_by_name(dir, TEST_OWNER, "victim", TEST_CACHE_TTL, &out, buf, sizeof(buf)) != 0) ok = 0;

    /* Now make it group+world writable: load MUST refuse. */
    if (ok && chmod(filepath, 0666) != 0) ok = 0;
    if (ok && t_load_by_name(dir, TEST_OWNER, "victim", TEST_CACHE_TTL, &out, buf, sizeof(buf)) == 0) ok = 0;

    rm_rf_files(dir);
    return ok;
}

/* SECURITY: a group/world-writable cache DIRECTORY is rejected outright, so an
 * attacker who can write the directory cannot get the loader to read any file
 * in it (anti cache-poisoning, dir component). */
static int test_name_load_rejects_writable_dir(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    struct passwd in = {0};
    in.pw_name = "victim";
    in.pw_uid = 12345;
    in.pw_gid = 100;
    in.pw_gecos = "Victim";
    in.pw_dir = "/home/victim";
    in.pw_shell = "/bin/bash";

    int ok = 1;
    if (t_save_by_name(dir, TEST_OWNER, &in, -1) != 0) ok = 0;

    /* Make the directory itself group+world writable: load MUST refuse before
     * even opening the (still 0644) entry inside it. */
    if (ok && chmod(dir, 0777) != 0) ok = 0;

    struct passwd out = {0};
    char buf[1024];
    if (ok && t_load_by_name(dir, TEST_OWNER, "victim", TEST_CACHE_TTL, &out, buf, sizeof(buf)) == 0) ok = 0;

    /* Restore a sane mode so cleanup works, then remove. */
    chmod(dir, 0755);
    rm_rf_files(dir);
    return ok;
}

/* SECURITY: save into a group/world-writable directory is refused (never falls
 * back to a path-based write). */
static int test_name_save_rejects_writable_dir(void)
{
    char dir[256];
    if (make_tmpdir(dir, sizeof(dir)) != 0) return 0;

    int ok = 1;
    if (chmod(dir, 0777) != 0) ok = 0;

    struct passwd in = {0};
    in.pw_name = "victim";
    in.pw_uid = 12345;
    in.pw_gid = 100;
    in.pw_gecos = "Victim";
    in.pw_dir = "/home/victim";
    in.pw_shell = "/bin/bash";

    /* save must refuse on an untrusted dir. */
    if (ok && t_save_by_name(dir, TEST_OWNER, &in, -1) == 0) ok = 0;

    /* And no entry file must have been created. */
    if (ok) {
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/victim", dir);
        if (access(filepath, F_OK) == 0) ok = 0;
    }

    chmod(dir, 0755);
    rm_rf_files(dir);
    return ok;
}

/* The non-collapsing splitter rejects records that don't have exactly 7
 * fields (truncated/garbage records can never be partially interpreted). */
static int test_split_field_count(void)
{
    char buf[7][128];
    char *out[7];
    int ok = 1;

    /* Too few fields. */
    strcpy(buf[0], "a:b:c");
    if (t_split_cache_line(buf[0], out) == 0) ok = 0;

    /* Too many fields. */
    strcpy(buf[1], "a:b:c:d:e:f:g:h");
    if (t_split_cache_line(buf[1], out) == 0) ok = 0;

    /* Exactly 7 with an empty field preserved. */
    strcpy(buf[2], "name:1000:1000::/home/n:/bin/sh:123\n");
    if (t_split_cache_line(buf[2], out) != 0) ok = 0;
    if (ok && strcmp(out[0], "name") != 0) ok = 0;
    if (ok && out[3][0] != '\0') ok = 0;        /* empty gecos preserved */
    if (ok && strcmp(out[4], "/home/n") != 0) ok = 0;
    if (ok && strcmp(out[6], "123") != 0) ok = 0; /* trailing newline stripped */

    return ok;
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

    printf("\nName-keyed file cache:\n");
    TEST(name_validation_rejects);
    TEST(name_validation_accepts);
    TEST(name_roundtrip);
    TEST(name_roundtrip_empty_gecos);
    TEST(name_expired_rejected);
    TEST(name_mismatch_rejected);
    TEST(name_missing);
    TEST(name_save_rejects_unsafe);
    TEST(split_field_count);

    printf("\nCache trust checks (anti cache-poisoning):\n");
    TEST(name_load_rejects_writable_file);
    TEST(name_load_rejects_writable_dir);
    TEST(name_save_rejects_writable_dir);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
