/*
 * test_nss_cache.c - Regression test for the in-memory LRU cache of the
 * NSS module (libnss_openbastion.c).
 *
 * Reproduces the double-free that crashed nscd (SIGABRT,
 * "double free or corruption (out)") roughly every 4-5h on bastions:
 *
 *   - cache_find()/cache_find_by_uid() free an expired entry's pw_buffer
 *     but (before the fix) leave the pointer dangling, only nulling username.
 *   - The slot stays within [0, count) as a hole with its old (oldest)
 *     timestamp.
 *   - cache_add(), once the cache is full, evicts the oldest entry and frees
 *     username + pw_buffer again => double free of the dangling pw_buffer.
 *
 * This only fires in a long-lived consumer whose cache reaches capacity
 * (nscd); short-lived callers (ls/id/sudo/sshd) exit first, which is why it
 * went unnoticed.
 *
 * We include the module source directly to drive the static cache helpers
 * (init_cache/cache_add/cache_find) against the real g_cache/g_config state.
 */

/* ---------------------------------------------------------------------------
 * Harness overrides. These MUST precede the #include of the module: they are
 * the only reason a unit test can drive the real file-cache helpers instead of
 * a hand-written copy of them.
 * ------------------------------------------------------------------------- */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Point the on-disk cache at a throwaway directory: the module must never
 * touch the real /var/cache/nss_llng from a unit test. Function-valued rather
 * than a literal so each run gets a private mkdtemp() root — two ctest jobs
 * running in parallel must not share cache state, and a fixed /tmp path is a
 * symlink target an unrelated local user could pre-create. */
const char *test_cache_root(void);
const char *test_cache_byname(void);
#define CACHE_DIR        test_cache_root()
#define CACHE_DIR_BYNAME test_cache_byname()

/*
 * The module refuses any cache directory or entry not owned by
 * CACHE_TRUSTED_UID, and refuses to write the cache at all unless it is
 * running as that uid. In production that is root, which is exactly the point.
 * The tests run unprivileged and own the temp directory they created, so they
 * substitute their own uid here. Everything else about the trust check - the
 * S_ISDIR/S_ISREG type check and the group/world-writable rejection, which are
 * what the cache-poisoning tests below exercise - is unchanged and is the
 * shipped code.
 */
#define CACHE_TRUSTED_UID (getuid())

#include "../nss/libnss_openbastion.c"

#include <assert.h>

static char g_test_base[128];

static const char *test_base(void)
{
    if (g_test_base[0] == '\0') {
        snprintf(g_test_base, sizeof(g_test_base), "/tmp/ob_nss_cache_test_XXXXXX");
        if (!mkdtemp(g_test_base)) {
            perror("mkdtemp");
            exit(1);
        }
    }
    return g_test_base;
}

/* The cache root itself is NOT pre-created: the privilege test asserts that an
 * unprivileged file_cache_save() leaves a missing directory missing. */
const char *test_cache_root(void)
{
    static char path[192];
    snprintf(path, sizeof(path), "%s/cache", test_base());
    return path;
}

static void rm_rf(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) {
        /* best-effort cleanup */
    }
}

/* Release everything init_cache()/cache_add() allocated, so the test leaves
 * no leaks under LeakSanitizer (free() is NULL-safe for expired holes). */
static void cache_teardown(void)
{
    if (!g_cache.entries) {
        return;
    }
    for (size_t i = 0; i < g_cache.count; i++) {
        free(g_cache.entries[i].username);
        free(g_cache.entries[i].pw_buffer);
    }
    free(g_cache.entries);
    g_cache.entries = NULL;
    g_cache.count = 0;
    g_cache.capacity = 0;
}

static struct passwd make_pw(const char *name, uid_t uid)
{
    struct passwd pw;
    pw.pw_name = (char *)name;
    pw.pw_passwd = (char *)"x";
    pw.pw_uid = uid;
    pw.pw_gid = uid;
    pw.pw_gecos = (char *)"";
    pw.pw_dir = (char *)"/home/x";
    pw.pw_shell = (char *)"/bin/bash";
    return pw;
}

/*
 * Fill the cache to capacity, expire+find one entry (creating a dangling
 * pw_buffer hole in the buggy code), then force an eviction that lands on
 * that hole. The buggy code double-frees here and aborts; the fixed code
 * survives because pw_buffer was nulled.
 */
static int test_expire_then_evict_no_double_free(void)
{
    if (init_cache() != 0) {
        fprintf(stderr, "init_cache failed\n");
        return 0;
    }
    /* Long TTL so entries don't expire on their own; we backdate manually. */
    g_config.cache_ttl = 1000000;

    char name[32];
    for (size_t i = 0; i < g_cache.capacity; i++) {
        snprintf(name, sizeof(name), "user%zu", i);
        struct passwd pw = make_pw(name, (uid_t)(100000 + i));
        cache_add(name, &pw, 1);
    }
    assert(g_cache.count == g_cache.capacity);

    /* Make slot 0 both expired and the oldest entry. */
    g_cache.entries[0].timestamp = time(NULL) - (g_config.cache_ttl + 100);

    /* Look it up: expired => freed. Buggy code leaves pw_buffer dangling. */
    cache_entry_t *e = cache_find("user0");
    assert(e == NULL);

    /* Adding one more triggers eviction of the oldest = slot 0. The buggy
     * code frees the dangling pw_buffer a second time -> SIGABRT here. */
    struct passwd extra = make_pw("newcomer", 200000);
    cache_add("newcomer", &extra, 1);

    /* If we reach this line, no double free occurred. */
    cache_teardown();
    return 1;
}

/* Same scenario through the UID lookup path. */
static int test_expire_by_uid_then_evict_no_double_free(void)
{
    if (init_cache() != 0) {
        fprintf(stderr, "init_cache failed\n");
        return 0;
    }
    g_config.cache_ttl = 1000000;

    char name[32];
    for (size_t i = 0; i < g_cache.capacity; i++) {
        snprintf(name, sizeof(name), "u%zu", i);
        struct passwd pw = make_pw(name, (uid_t)(300000 + i));
        cache_add(name, &pw, 1);
    }
    assert(g_cache.count == g_cache.capacity);

    g_cache.entries[0].timestamp = time(NULL) - (g_config.cache_ttl + 100);

    cache_entry_t *e = cache_find_by_uid(300000);
    assert(e == NULL);

    struct passwd extra = make_pw("uidnewcomer", 400000);
    cache_add("uidnewcomer", &extra, 1);

    cache_teardown();
    return 1;
}

/* ===========================================================================
 * Name-keyed cross-process file cache
 *
 * These drive the REAL helpers from libnss_openbastion.c (valid_cache_name,
 * split_cache_line, open_cache_dir_read/write, open_cache_file_verified,
 * file_cache_save/_by_name, file_cache_load_by_uid/_by_name) through the
 * #include above, redirected at a temp directory by the CACHE_DIR /
 * CACHE_TRUSTED_UID overrides. Nothing here is a re-implementation: a test
 * that passes against a copy proves nothing about the shipped module.
 * ========================================================================= */

const char *test_cache_byname(void)
{
    static char path[224];
    snprintf(path, sizeof(path), "%s/byname", test_cache_root());
    return path;
}

/* Every test starts from "no cache directory at all". */
static void reset_cache_dirs(void)
{
    /* chmod back first: a test may have left the dir unreadable on purpose. */
    chmod(test_cache_byname(), 0755);
    chmod(test_cache_root(), 0755);
    rm_rf(test_cache_root());
    g_config.cache_ttl = CACHE_TTL;
}

static struct passwd make_user(const char *name, uid_t uid, const char *gecos)
{
    static char home[256];
    struct passwd pw;
    snprintf(home, sizeof(home), "/home/%s", name);
    pw.pw_name = (char *)name;
    pw.pw_passwd = (char *)"x";
    pw.pw_uid = uid;
    pw.pw_gid = 100;
    pw.pw_gecos = (char *)gecos;
    pw.pw_dir = home;
    pw.pw_shell = (char *)"/bin/bash";
    return pw;
}

/*
 * Hand-write a raw record the module itself would never produce (forged
 * timestamp, mismatched key). Creates the directories the way the module does.
 *
 * fchmod() on the descriptor rather than chmod() on the path: naming the file
 * a second time after creating it is a check-then-act on a name that could be
 * swapped underneath us (cpp/toctou-race-condition).
 */
static int write_raw_entry(const char *dir, const char *leaf, const char *content)
{
    if (mkdir(test_cache_root(), 0711) != 0 && errno != EEXIST) return -1;
    if (mkdir(dir, 0711) != 0 && errno != EEXIST) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, leaf);
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    if (fputs(content, f) == EOF) { fclose(f); return -1; }
    if (fchmod(fileno(f), 0644) != 0) { fclose(f); return -1; }
    if (fclose(f) != 0) return -1;
    return 0;
}

static int entry_mode(const char *dir, const char *leaf, mode_t *out)
{
    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", dir, leaf);
    if (stat(path, &st) != 0) return -1;
    *out = st.st_mode & 07777;
    return 0;
}

/*
 * valid_cache_name() must accept exactly what validate_username()
 * (src/pam_openbastion.c) accepts: `[a-z_][a-z0-9_-]{0,31}`. A name only one
 * of the two accepts would be written to the cache and then never invalidated
 * by the PAM side, leaving a stale record no code path can clear.
 */
static int test_valid_cache_name_matches_pam_validator(void)
{
    /* Accepted by both. */
    if (valid_cache_name("alice") != 0) return 0;
    if (valid_cache_name("bob123") != 0) return 0;
    if (valid_cache_name("svc_account") != 0) return 0;
    if (valid_cache_name("with-dash") != 0) return 0;
    if (valid_cache_name("_underscore") != 0) return 0;
    if (valid_cache_name("a") != 0) return 0;

    /* Path traversal / charset. */
    if (valid_cache_name(NULL) == 0) return 0;
    if (valid_cache_name("") == 0) return 0;
    if (valid_cache_name("/etc/passwd") == 0) return 0;
    if (valid_cache_name("foo/bar") == 0) return 0;
    if (valid_cache_name("../escape") == 0) return 0;
    if (valid_cache_name(".hidden") == 0) return 0;
    if (valid_cache_name(".") == 0) return 0;
    if (valid_cache_name("..") == 0) return 0;
    if (valid_cache_name("UPPER") == 0) return 0;
    if (valid_cache_name("white space") == 0) return 0;
    if (valid_cache_name("co:lon") == 0) return 0;
    if (valid_cache_name("new\nline") == 0) return 0;

    /* Rejected specifically because validate_username() rejects them: a
     * leading digit or hyphen, and anything over 32 characters. */
    if (valid_cache_name("0digitstart") == 0) return 0;
    if (valid_cache_name("-dashstart") == 0) return 0;

    char maxlen[CACHE_NAME_MAX + 1];
    memset(maxlen, 'a', CACHE_NAME_MAX);
    maxlen[CACHE_NAME_MAX] = '\0';
    if (valid_cache_name(maxlen) != 0) return 0;       /* exactly 32: OK */

    char toolong[CACHE_NAME_MAX + 2];
    memset(toolong, 'a', CACHE_NAME_MAX + 1);
    toolong[CACHE_NAME_MAX + 1] = '\0';
    if (valid_cache_name(toolong) == 0) return 0;      /* 33: rejected */

    return 1;
}

/* Round-trip through the real save/load: every passwd field survives. */
static int test_name_roundtrip(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("alice", 12345, "Alice Example");
    file_cache_save_by_name(&in);

    struct passwd out = {0};
    char buf[1024];
    if (file_cache_load_by_name("alice", &out, buf, sizeof(buf), NULL) != 0) return 0;
    if (strcmp(out.pw_name, "alice") != 0) return 0;
    if (strcmp(out.pw_passwd, "x") != 0) return 0;
    if (out.pw_uid != 12345 || out.pw_gid != 100) return 0;
    if (strcmp(out.pw_gecos, "Alice Example") != 0) return 0;
    if (strcmp(out.pw_dir, "/home/alice") != 0) return 0;
    if (strcmp(out.pw_shell, "/bin/bash") != 0) return 0;
    return 1;
}

/*
 * An EMPTY gecos must round-trip: split_cache_line() does not collapse
 * consecutive ':' the way strtok_r() would, so the empty field is preserved
 * instead of shifting home/shell/timestamp one place left.
 */
static int test_name_roundtrip_empty_gecos(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("nogecos", 20001, "");
    file_cache_save_by_name(&in);

    struct passwd out = {0};
    char buf[1024];
    if (file_cache_load_by_name("nogecos", &out, buf, sizeof(buf), NULL) != 0) return 0;
    if (out.pw_uid != 20001 || out.pw_gid != 100) return 0;
    if (strcmp(out.pw_gecos, "") != 0) return 0;
    if (strcmp(out.pw_dir, "/home/nogecos") != 0) return 0;
    if (strcmp(out.pw_shell, "/bin/bash") != 0) return 0;
    return 1;
}

/* The uid-keyed cache still round-trips, and its key-consistency check
 * rejects a record filed under the wrong uid. */
static int test_uid_roundtrip_and_key_check(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("byuid", 31337, "By Uid");
    file_cache_save(&in);

    struct passwd out = {0};
    char buf[1024];
    if (file_cache_load_by_uid(31337, &out, buf, sizeof(buf), NULL) != 0) return 0;
    if (strcmp(out.pw_name, "byuid") != 0) return 0;

    /* File named "999" but claiming uid 31337: the key check must reject it. */
    char rec[256];
    snprintf(rec, sizeof(rec), "byuid:31337:100:By Uid:/home/byuid:/bin/bash:%ld\n",
             (long)time(NULL));
    if (write_raw_entry(test_cache_root(), "999", rec) != 0) return 0;
    if (file_cache_load_by_uid(999, &out, buf, sizeof(buf), NULL) == 0) return 0;
    return 1;
}

/* An entry older than the TTL is refused AND unlinked. */
static int test_name_expired_rejected_and_unlinked(void)
{
    reset_cache_dirs();
    char rec[256];
    snprintf(rec, sizeof(rec), "stale:30000:100:Stale:/home/stale:/bin/bash:%ld\n",
             (long)time(NULL) - (g_config.cache_ttl + 60));
    if (write_raw_entry(test_cache_byname(), "stale", rec) != 0) return 0;

    struct passwd out = {0};
    char buf[1024];
    if (file_cache_load_by_name("stale", &out, buf, sizeof(buf), NULL) == 0) return 0;

    char path[512];
    snprintf(path, sizeof(path), "%s/stale", test_cache_byname());
    if (access(path, F_OK) == 0) return 0;   /* must have been unlinked */
    return 1;
}

/* A record whose stored username differs from the requested key is refused,
 * so a file planted as "alice" cannot answer with a "mallory" (or root) record. */
static int test_name_mismatch_rejected(void)
{
    reset_cache_dirs();
    char rec[256];
    snprintf(rec, sizeof(rec), "mallory:0:0:root:/root:/bin/bash:%ld\n", (long)time(NULL));
    if (write_raw_entry(test_cache_byname(), "alice", rec) != 0) return 0;

    struct passwd out = {0};
    char buf[1024];
    return file_cache_load_by_name("alice", &out, buf, sizeof(buf), NULL) != 0;
}

/* A missing entry simply misses - no crash, no directory creation. */
static int test_name_missing(void)
{
    reset_cache_dirs();
    struct passwd out = {0};
    char buf[1024];
    return file_cache_load_by_name("nobody_here", &out, buf, sizeof(buf), NULL) != 0;
}

/* ------------------------------------------------------------------------
 * Bounded write / unlink-on-corruption
 *
 * The readers use a 1024-byte fgets() buffer. Before build_cache_line(), the
 * writer fprintf()'d the record unbounded: a gecos over ~1000 bytes, or one
 * containing ':', produced a line that could NEVER be parsed back. Because the
 * read path only unlinked on TTL expiry, that entry stayed forever: every
 * lookup failed at parse, fell back to an HTTPS query to LLNG, and the
 * root-side rewrite reproduced the same unreadable line.
 * ------------------------------------------------------------------------ */

/* A huge gecos must not poison the entry: it is trimmed so the record still
 * parses, and the load-bearing fields survive untouched. */
static int test_oversized_gecos_is_trimmed_not_poisoned(void)
{
    reset_cache_dirs();
    char huge[5000];
    memset(huge, 'G', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';

    struct passwd in = make_user("bigg", 70001, huge);
    file_cache_save_by_name(&in);

    struct passwd out = {0};
    char buf[4096];
    if (file_cache_load_by_name("bigg", &out, buf, sizeof(buf), NULL) != 0) return 0;
    if (out.pw_uid != 70001) return 0;
    if (strlen(out.pw_gecos) == 0) return 0;
    if (strlen(out.pw_gecos) > CACHE_LINE_MAX) return 0;
    /* home and shell are load-bearing and must come back byte-exact. */
    if (strcmp(out.pw_dir, "/home/bigg") != 0) return 0;
    if (strcmp(out.pw_shell, "/bin/bash") != 0) return 0;

    /* And the stored line really is within the readers' buffer. */
    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), "%s/bigg", test_cache_byname());
    if (stat(path, &st) != 0) return 0;
    if (st.st_size > CACHE_LINE_MAX) return 0;
    return 1;
}

/* A ':' in gecos would make an 8-field line, which split_cache_line() rejects
 * forever. gecos is cosmetic, so it is folded to a space and the record stays
 * readable. CR/LF (which would fake a second record) go the same way. */
static int test_separator_in_gecos_is_folded(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("colon", 70002, "Doe:John\nx:y");
    file_cache_save_by_name(&in);

    struct passwd out = {0};
    char buf[1024];
    if (file_cache_load_by_name("colon", &out, buf, sizeof(buf), NULL) != 0) return 0;
    if (strchr(out.pw_gecos, ':') != NULL) return 0;
    if (strchr(out.pw_gecos, '\n') != NULL) return 0;
    if (strcmp(out.pw_gecos, "Doe John x y") != 0) return 0;
    if (out.pw_uid != 70002) return 0;
    if (strcmp(out.pw_dir, "/home/colon") != 0) return 0;
    return 1;
}

/* Multi-byte gecos: trimming must land on a character boundary, never leave a
 * half-written UTF-8 sequence in the cache. */
static int test_gecos_trim_keeps_utf8_valid(void)
{
    reset_cache_dirs();
    char accents[4096];
    size_t n = 0;
    while (n + 2 < sizeof(accents) - 1) {          /* U+00E9, 2 bytes */
        accents[n++] = (char)0xC3;
        accents[n++] = (char)0xA9;
    }
    accents[n] = '\0';

    struct passwd in = make_user("accent", 70003, accents);
    file_cache_save_by_name(&in);

    struct passwd out = {0};
    char buf[4096];
    if (file_cache_load_by_name("accent", &out, buf, sizeof(buf), NULL) != 0) return 0;
    size_t len = strlen(out.pw_gecos);
    if (len == 0 || (len % 2) != 0) return 0;      /* whole 2-byte chars only */
    for (size_t i = 0; i < len; i += 2) {
        if ((unsigned char)out.pw_gecos[i] != 0xC3) return 0;
        if ((unsigned char)out.pw_gecos[i + 1] != 0xA9) return 0;
    }
    return 1;
}

/*
 * trim() used to compute `str + strlen(str) - 1` before looking at the string,
 * which is undefined behaviour (a pointer before the start of the object) for
 * an empty or all-blank value - exactly what a "key =" line in
 * nss_openbastion.conf produces. Detected by UBSan/ASan; here we simply assert
 * the result is a well-formed empty string.
 */
static int test_trim_empty_is_not_ub(void)
{
    char empty[] = "";
    char blanks[] = "   \t";
    char value[] = "  hello  ";

    if (strcmp(trim(empty), "") != 0) return 0;
    if (strcmp(trim(blanks), "") != 0) return 0;
    if (strcmp(trim(value), "hello") != 0) return 0;
    return 1;
}

/*
 * Regression test for the review of PR #222: a server-supplied gid must not be
 * validated against the *synthetic UID* range. An ordinary LDAP gidNumber
 * (1000 = a Debian user-private group, 5000, ...) falls outside
 * [min_uid, max_uid] = [10000, 60000] and used to be silently replaced by
 * default_gid - a silent permission change on shared files.
 *
 * Drives the shipped select_primary_gid() through the real g_config.
 */
static int check_gid(const char *json_text, gid_t expect, const char *what)
{
    struct json_object *json = json_tokener_parse(json_text);
    if (!json) {
        fprintf(stderr, "\n    %s: unparseable test JSON\n", what);
        return 0;
    }
    gid_t got = select_primary_gid(json, "someuser");
    json_object_put(json);
    if (got != expect) {
        fprintf(stderr, "\n    %s: got gid %u, expected %u\n",
                what, (unsigned)got, (unsigned)expect);
        return 0;
    }
    return 1;
}

/* home and shell are NOT cosmetic: a value that cannot round-trip must make
 * the write be refused outright rather than be silently mangled. Nothing is
 * left in the directory, not even a temp file. */
static int test_unrepresentable_home_refuses_write(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("weird", 70004, "Weird");
    in.pw_dir = (char *)"/home/we:ird";
    file_cache_save_by_name(&in);

    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), "%s/weird", test_cache_byname());
    if (stat(path, &st) == 0) return 0;            /* nothing must be published */

    /* No temp leaf either. */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s/.tmp.weird.%ld", test_cache_byname(), (long)getpid());
    if (stat(tmp, &st) == 0) return 0;

    /* Same rule for the uid-keyed cache. */
    file_cache_save(&in);
    snprintf(path, sizeof(path), "%s/70004", test_cache_root());
    if (stat(path, &st) == 0) return 0;
    return 1;
}

/* A record whose fixed fields alone overflow the line budget is refused: the
 * only alternative would be truncating a home directory. */
static int test_oversized_home_refuses_write(void)
{
    reset_cache_dirs();
    static char longhome[CACHE_LINE_MAX + 100];
    memset(longhome, 'h', sizeof(longhome) - 1);
    longhome[0] = '/';
    longhome[sizeof(longhome) - 1] = '\0';

    struct passwd in = make_user("longhome", 70005, "");
    in.pw_dir = longhome;
    file_cache_save_by_name(&in);

    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), "%s/longhome", test_cache_byname());
    return stat(path, &st) != 0;
}

/*
 * An entry that cannot be parsed is unlinked, exactly like an expired one.
 * Without this, a single bad record (left by an older version, a truncated
 * write, or a poisoning attempt) means one HTTPS round trip to LLNG per
 * lookup of that user, for as long as the file exists.
 */
/* A record the reader always refuses must not be written: an empty user name
 * parses as `corrupt`, so the entry is unlinked and every lookup of that uid
 * pays a portal round trip, forever. */
static int test_build_refuses_empty_name(void)
{
    struct passwd pw = { .pw_name = "", .pw_passwd = "x", .pw_uid = 20001,
                         .pw_gid = 20001, .pw_gecos = "", .pw_dir = "/home/dwho",
                         .pw_shell = "/bin/bash" };
    char line[CACHE_LINE_MAX + 1];

    return build_cache_line(line, sizeof(line), &pw, time(NULL)) == -1;
}

/* A negative timestamp underflowed "now - timestamp" (UB), and a far-future
 * one made the record look fresh for centuries. Both are corrupt. */
static int test_extreme_timestamps_are_refused(void)
{
    static const char *const stamps[] = {
        "-9223372036854775808", "9223372036854775807", "-1", NULL,
    };
    struct passwd out;
    char buf[2048];

    for (size_t i = 0; stamps[i]; i++) {
        char rec[256];
        reset_cache_dirs();
        snprintf(rec, sizeof(rec),
                 "dwho:20001:20001:D Who:/home/dwho:/bin/bash:%s\n", stamps[i]);
        if (write_raw_entry(test_cache_byname(), "dwho", rec) != 0) return 0;
        if (file_cache_load_by_name("dwho", &out, buf, sizeof(buf), NULL) == 0) return 0;
    }

    return 1;
}

static int test_unparsable_entry_is_unlinked(void)
{
    struct passwd out = {0};
    char buf[2048];
    char path[512];
    struct stat st;

    /* (a) too few fields */
    reset_cache_dirs();
    if (write_raw_entry(test_cache_byname(), "broken", "not-a-record\n") != 0) return 0;
    if (file_cache_load_by_name("broken", &out, buf, sizeof(buf), NULL) == 0) return 0;
    snprintf(path, sizeof(path), "%s/broken", test_cache_byname());
    if (stat(path, &st) == 0) return 0;

    /* (b) a line longer than the readers' fgets() buffer: it comes back
     *     truncated, so the field count is wrong. This is exactly what the
     *     unbounded fprintf() used to produce. */
    reset_cache_dirs();
    char big[2048];
    int off = snprintf(big, sizeof(big), "toolong:70006:100:");
    memset(big + off, 'X', 1500);
    snprintf(big + off + 1500, sizeof(big) - off - 1500,
             ":/home/toolong:/bin/bash:%ld\n", (long)time(NULL));
    if (write_raw_entry(test_cache_byname(), "toolong", big) != 0) return 0;
    if (file_cache_load_by_name("toolong", &out, buf, sizeof(buf), NULL) == 0) return 0;
    snprintf(path, sizeof(path), "%s/toolong", test_cache_byname());
    if (stat(path, &st) == 0) return 0;

    /* (c) an unparsable timestamp, and (d) a record filed under the wrong key:
     *     both are permanently unusable, both must be cleared. */
    reset_cache_dirs();
    if (write_raw_entry(test_cache_byname(), "badts",
                        "badts:70007:100::/home/badts:/bin/sh:not-a-number\n") != 0) return 0;
    if (file_cache_load_by_name("badts", &out, buf, sizeof(buf), NULL) == 0) return 0;
    snprintf(path, sizeof(path), "%s/badts", test_cache_byname());
    if (stat(path, &st) == 0) return 0;

    reset_cache_dirs();
    char rec[256];
    snprintf(rec, sizeof(rec), "someone_else:70008:100::/home/x:/bin/sh:%ld\n",
             (long)time(NULL));
    if (write_raw_entry(test_cache_byname(), "claimed", rec) != 0) return 0;
    if (file_cache_load_by_name("claimed", &out, buf, sizeof(buf), NULL) == 0) return 0;
    snprintf(path, sizeof(path), "%s/claimed", test_cache_byname());
    if (stat(path, &st) == 0) return 0;
    return 1;
}

/*
 * Promotion file -> memory must carry the record's ORIGINAL write time.
 * Stamping the memory copy with time(NULL) would let a long-lived process
 * serve a record until ~T0 + 2*cache_ttl after the last LLNG contact, against
 * the module's "never serves stale data" doctrine.
 */
static int test_file_promotion_keeps_record_age(void)
{
    reset_cache_dirs();
    g_config.cache_ttl = 100;
    time_t t0 = time(NULL) - 95;                   /* written nearly a TTL ago */

    char rec[256];
    snprintf(rec, sizeof(rec), "aging:70009:100:Aging:/home/aging:/bin/bash:%ld\n",
             (long)t0);
    if (write_raw_entry(test_cache_byname(), "aging", rec) != 0) return 0;

    struct passwd out = {0};
    char buf[1024];
    time_t created = 0;
    if (file_cache_load_by_name("aging", &out, buf, sizeof(buf), &created) != 0) return 0;
    if (created != t0) return 0;                   /* the file's own timestamp */

    cache_teardown();
    if (init_cache() != 0) return 0;
    g_config.cache_ttl = 100;
    cache_add_at("aging", &out, 1, created);
    if (g_cache.entries[0].timestamp != t0) { cache_teardown(); return 0; }

    /* Still live at ttl=100 (age 95)... */
    if (cache_find("aging") == NULL) { cache_teardown(); return 0; }
    /* ...and gone at ttl=90, which it would NOT be had the promotion reset the
     * age to time(NULL). */
    g_config.cache_ttl = 90;
    int ok = (cache_find("aging") == NULL);
    cache_teardown();
    g_config.cache_ttl = CACHE_TTL;
    return ok;
}

static int test_server_gid_policy(void)
{
    /* Production defaults, as load_config() would set them. */
    g_config.min_uid = DEFAULT_MIN_UID;      /* 10000 */
    g_config.max_uid = DEFAULT_MAX_UID;      /* 60000 */
    g_config.min_gid = DEFAULT_MIN_GID;      /* 1000  */
    g_config.max_gid = DEFAULT_MAX_GID;      /* 65533 */
    g_config.default_gid = 100;

    int ok = 1;

    /* THE regression: an ordinary gidNumber survives unchanged even though it
     * is far outside the synthetic UID range. */
    ok &= check_gid("{\"gid\":1000}", 1000, "gidNumber 1000 survives");
    ok &= check_gid("{\"gid\":5000}", 5000, "gidNumber 5000 survives");
    /* Inside the UID range too - must still be taken verbatim. */
    ok &= check_gid("{\"gid\":50000}", 50000, "gidNumber 50000 survives");
    /* Upper bound of the policy. */
    ok &= check_gid("{\"gid\":65533}", 65533, "max_gid boundary survives");

    /* What the check actually exists for. */
    ok &= check_gid("{\"gid\":0}", 100, "gid 0 (root) refused");
    ok &= check_gid("{\"gid\":27}", 100, "gid 27 (sudo) refused");
    ok &= check_gid("{\"gid\":10}", 100, "gid 10 (wheel) refused");
    ok &= check_gid("{\"gid\":998}", 100, "dynamic system gid (docker) refused");
    ok &= check_gid("{\"gid\":65534}", 100, "gid 65534 (nogroup) refused");
    ok &= check_gid("{\"gid\":-1}", 100, "negative gid refused");

    /* Absent or non-integer gid keeps the pre-existing fallback. */
    ok &= check_gid("{}", 100, "missing gid falls back to default_gid");
    ok &= check_gid("{\"gid\":\"users\"}", 100, "string gid falls back to default_gid");

    /* gid 0 is refused even if an admin widens min_gid all the way down. */
    g_config.min_gid = 0;
    ok &= check_gid("{\"gid\":0}", 100, "gid 0 refused even with min_gid=0");
    /* min_gid=0 is nonsense and must not mean "reject everything": the
     * compiled policy applies instead, so 1000 still survives. */
    ok &= check_gid("{\"gid\":1000}", 1000, "gidNumber 1000 survives min_gid=0");

    /* A site that legitimately exports gid 100 (users) can lower the floor. */
    g_config.min_gid = 100;
    g_config.default_gid = 65533;   /* distinct, so a fallback is visible */
    ok &= check_gid("{\"gid\":100}", 100, "min_gid=100 admits gid 100");
    ok &= check_gid("{\"gid\":27}", 65533, "min_gid=100 still refuses gid 27");

    g_config.min_gid = DEFAULT_MIN_GID;
    g_config.default_gid = 100;
    return ok;
}

/*
 * The READ path must never mkdir() and must never warn on an absent cache.
 * On a host where /var/cache/nss_llng does not exist, every unprivileged
 * getpwnam()/getpwuid() - an ordinary `ls -l` - would otherwise turn into an
 * EACCES plus a syslog warning, i.e. a log flood.
 */
static int test_read_path_never_creates_dirs(void)
{
    reset_cache_dirs();
    struct passwd out = {0};
    char buf[1024];
    struct stat st;

    if (file_cache_load_by_name("ghost", &out, buf, sizeof(buf), NULL) == 0) return 0;
    if (file_cache_load_by_uid(4242, &out, buf, sizeof(buf), NULL) == 0) return 0;

    if (stat(test_cache_root(), &st) == 0) return 0;     /* must still not exist */
    if (stat(test_cache_byname(), &st) == 0) return 0;
    return 1;
}

/* save refuses an unsafe name outright: no file, no directory. */
static int test_name_save_rejects_unsafe(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("../evil", 40000, "");
    in.pw_dir = (char *)"/home/evil";
    file_cache_save_by_name(&in);

    struct stat st;
    if (stat(test_cache_byname(), &st) == 0) {
        /* If the dir somehow exists it must at least be empty of the entry. */
        char path[512];
        snprintf(path, sizeof(path), "%s/../evil", test_cache_byname());
        if (access(path, F_OK) == 0) return 0;
    }
    return 1;
}

/*
 * SECURITY (cache poisoning): a group/world-writable ENTRY is refused even
 * though its content is valid. Without this, any local user who can write the
 * file feeds root a `uid 0` passwd record.
 */
static int test_load_rejects_writable_file(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("victim", 12345, "Victim");
    file_cache_save_by_name(&in);

    struct passwd out = {0};
    char buf[1024];
    /* Sanity: it loads while the mode is 0644. */
    if (file_cache_load_by_name("victim", &out, buf, sizeof(buf), NULL) != 0) return 0;

    char path[512];
    snprintf(path, sizeof(path), "%s/victim", test_cache_byname());
    if (chmod(path, 0666) != 0) return 0;
    /* Now group+world writable: MUST be refused. */
    return file_cache_load_by_name("victim", &out, buf, sizeof(buf), NULL) != 0;
}

/*
 * SECURITY (cache poisoning): a group/world-writable DIRECTORY is refused
 * before any entry inside it is even opened - an attacker who can write the
 * directory can replace entries at will.
 */
static int test_load_rejects_writable_dir(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("victim", 12345, "Victim");
    file_cache_save_by_name(&in);

    struct passwd out = {0};
    char buf[1024];
    if (file_cache_load_by_name("victim", &out, buf, sizeof(buf), NULL) != 0) return 0;

    if (chmod(test_cache_byname(), 0777) != 0) return 0;
    int refused = (file_cache_load_by_name("victim", &out, buf, sizeof(buf), NULL) != 0);
    chmod(test_cache_byname(), 0711);
    return refused;
}

/* SECURITY: save into an untrusted (world-writable) directory is refused and
 * never falls back to a path-based write. */
static int test_save_rejects_writable_dir(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("victim", 12345, "Victim");
    file_cache_save_by_name(&in);          /* creates the dirs */

    char path[512];
    snprintf(path, sizeof(path), "%s/victim", test_cache_byname());
    if (unlink(path) != 0) return 0;
    if (chmod(test_cache_byname(), 0777) != 0) return 0;

    file_cache_save_by_name(&in);
    int refused = (access(path, F_OK) != 0);
    chmod(test_cache_byname(), 0711);
    return refused;
}

/*
 * Directory mode: 0711 - traversable so an unprivileged getpwnam()/getpwuid()
 * still reaches its entry, but NOT listable, so the SSO user directory cannot
 * be enumerated wholesale by a local account. The byname filenames ARE the
 * login names, which is why this matters here (refs #189). Entries stay 0644:
 * an NSS module serves unprivileged callers from inside their own process.
 */
static int test_cache_dirs_are_0711_entries_0644(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("modecheck", 50000, "Mode Check");
    file_cache_save_by_name(&in);
    file_cache_save(&in);

    struct stat st;
    if (stat(test_cache_root(), &st) != 0) return 0;
    if ((st.st_mode & 07777) != 0711) return 0;
    if (stat(test_cache_byname(), &st) != 0) return 0;
    if ((st.st_mode & 07777) != 0711) return 0;

    mode_t m;
    if (entry_mode(test_cache_byname(), "modecheck", &m) != 0 || m != 0644) return 0;
    if (entry_mode(test_cache_root(), "50000", &m) != 0 || m != 0644) return 0;

    /* Upgrade path: a 0755 directory left by an earlier version is tightened
     * on the next write, not left wide open. */
    if (chmod(test_cache_root(), 0755) != 0) return 0;
    if (chmod(test_cache_byname(), 0755) != 0) return 0;
    file_cache_save_by_name(&in);
    if (stat(test_cache_root(), &st) != 0 || (st.st_mode & 07777) != 0711) return 0;
    if (stat(test_cache_byname(), &st) != 0 || (st.st_mode & 07777) != 0711) return 0;
    return 1;
}

/*
 * A `.tmp.<leaf>.<pid>` left behind by a process killed between openat() and
 * renameat() must not permanently kill caching for that entry: the temp leaf
 * is pid-keyed, so the next process to be handed that pid would hit EEXIST
 * forever. The save path unlinks the leftover and retries once.
 */
static int test_stale_temp_file_does_not_block_save(void)
{
    reset_cache_dirs();
    struct passwd in = make_user("retry", 60001, "Retry");
    file_cache_save_by_name(&in);          /* creates the dirs */

    char entry[512], tmp[512];
    snprintf(entry, sizeof(entry), "%s/retry", test_cache_byname());
    snprintf(tmp, sizeof(tmp), "%s/.tmp.retry.%ld", test_cache_byname(), (long)getpid());
    if (unlink(entry) != 0) return 0;

    /* Forge exactly the debris a SIGKILL mid-write would leave: same pid, so
     * this process is the one that "reuses" it. */
    FILE *f = fopen(tmp, "w");
    if (!f) return 0;
    fputs("garbage-from-a-killed-process\n", f);
    if (fchmod(fileno(f), 0600) != 0) { fclose(f); return 0; }
    fclose(f);

    file_cache_save_by_name(&in);

    /* The entry must have been published... */
    struct passwd out = {0};
    char buf[1024];
    if (file_cache_load_by_name("retry", &out, buf, sizeof(buf), NULL) != 0) return 0;
    if (out.pw_uid != 60001) return 0;
    /* ...and the stale temp must be gone (consumed by the rename). */
    if (access(tmp, F_OK) == 0) return 0;
    return 1;
}

/*
 * split_cache_line() accepts EXACTLY 7 fields, so a truncated or padded record
 * can never be partially interpreted, and empty fields are preserved rather
 * than collapsed.
 */
static int test_split_field_count(void)
{
    char line[128];
    char *out[7];

    snprintf(line, sizeof(line), "a:b:c");
    if (split_cache_line(line, out) == 0) return 0;              /* too few */

    snprintf(line, sizeof(line), "a:b:c:d:e:f:g:h");
    if (split_cache_line(line, out) == 0) return 0;              /* too many */

    snprintf(line, sizeof(line), "name:1000:1000::/home/n:/bin/sh:123\n");
    if (split_cache_line(line, out) != 0) return 0;
    if (strcmp(out[0], "name") != 0) return 0;
    if (out[3][0] != '\0') return 0;                             /* empty gecos kept */
    if (strcmp(out[4], "/home/n") != 0) return 0;
    if (strcmp(out[6], "123") != 0) return 0;                    /* newline stripped */
    return 1;
}

/*
 * file_cache_save() writes the shared uid -> passwd cache under CACHE_DIR.
 * Only the cache owner may do so: an NSS module is loaded into every process
 * that resolves a user, so a caller that is not the owner must never be able
 * to create or rewrite entries the whole host then trusts. In production the
 * owner is root; under the CACHE_TRUSTED_UID override at the top of this file
 * it is the unprivileged user that created the throwaway directory, so the
 * comparison is written against CACHE_TRUSTED_UID rather than a literal 0 and
 * the assertion holds in both cases.
 *
 * When we ARE the owner the refusal cannot be observed, so we check the modes
 * the fix installs instead (directory 0711 = traversable but not listable,
 * entry 0644 owned by the cache owner - it must stay readable, see
 * file_cache_write_atomic_at()).
 */
static int test_file_cache_save_privileges(void)
{
    /* Start from a clean slate. reset_cache_dirs() rather than rmdir(): the
     * cache root now has a byname/ subdirectory, so rmdir() would not empty
     * it and the "must not exist" check below would be meaningless. */
    reset_cache_dirs();

    struct passwd pw = make_pw("cacheduser", 123456);
    char entry[256];
    snprintf(entry, sizeof(entry), "%s/%u", CACHE_DIR, (unsigned)pw.pw_uid);

    file_cache_save(&pw);

    struct stat st;
    if (geteuid() != CACHE_TRUSTED_UID) {
        /* Not the cache owner: nothing at all must have been created. */
        int created = (stat(CACHE_DIR, &st) == 0);
        reset_cache_dirs();
        if (created) {
            fprintf(stderr, "non-owner file_cache_save created %s\n", CACHE_DIR);
            return 0;
        }
        return 1;
    }

    int ok = 1;
    if (stat(CACHE_DIR, &st) != 0 || (st.st_mode & 07777) != 0711) {
        fprintf(stderr, "cache dir mode %04o, expected 0711\n",
                (unsigned)(st.st_mode & 07777));
        ok = 0;
    }
    if (stat(entry, &st) != 0 || (st.st_mode & 07777) != 0644 ||
        st.st_uid != CACHE_TRUSTED_UID) {
        fprintf(stderr, "cache entry mode %04o uid %u, expected 0644 owner %u\n",
                (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid,
                (unsigned)CACHE_TRUSTED_UID);
        ok = 0;
    }
    reset_cache_dirs();
    return ok;
}

int main(void)
{
    int ok = 1;

    printf("  Testing expire_then_evict_no_double_free... ");
    if (test_expire_then_evict_no_double_free()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    printf("  Testing expire_by_uid_then_evict_no_double_free... ");
    if (test_expire_by_uid_then_evict_no_double_free()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

#define RUN(fn) do { \
        printf("  Testing %s... ", #fn); \
        if (fn()) { \
            printf("PASS\n"); \
        } else { \
            printf("FAIL\n"); \
            ok = 0; \
        } \
    } while (0)

    printf("\n  Name-keyed file cache (real implementation):\n");
    RUN(test_valid_cache_name_matches_pam_validator);
    RUN(test_name_roundtrip);
    RUN(test_name_roundtrip_empty_gecos);
    RUN(test_uid_roundtrip_and_key_check);
    RUN(test_name_expired_rejected_and_unlinked);
    RUN(test_name_mismatch_rejected);
    RUN(test_name_missing);
    RUN(test_read_path_never_creates_dirs);
    RUN(test_name_save_rejects_unsafe);
    RUN(test_split_field_count);
    RUN(test_cache_dirs_are_0711_entries_0644);
    RUN(test_stale_temp_file_does_not_block_save);

    printf("\n  Bounded records / unlink on corruption:\n");
    RUN(test_oversized_gecos_is_trimmed_not_poisoned);
    RUN(test_separator_in_gecos_is_folded);
    RUN(test_gecos_trim_keeps_utf8_valid);
    RUN(test_unrepresentable_home_refuses_write);
    RUN(test_oversized_home_refuses_write);
    RUN(test_unparsable_entry_is_unlinked);
    RUN(test_file_promotion_keeps_record_age);
    RUN(test_build_refuses_empty_name);
    RUN(test_extreme_timestamps_are_refused);

    printf("\n  Cache trust checks (anti cache-poisoning):\n");
    RUN(test_load_rejects_writable_file);
    RUN(test_load_rejects_writable_dir);
    RUN(test_save_rejects_writable_dir);
    RUN(test_file_cache_save_privileges);

    printf("\n  Config parsing and server-supplied gid policy:\n");
    RUN(test_trim_empty_is_not_ub);
    RUN(test_server_gid_policy);
#undef RUN

    /* Leave nothing behind in /tmp. */
    if (g_test_base[0] != '\0') {
        chmod(test_cache_byname(), 0755);
        chmod(test_cache_root(), 0755);
        rm_rf(g_test_base);
    }

    printf("\n%s\n", ok ? "All NSS cache tests passed" : "NSS cache tests FAILED");
    return ok ? 0 : 1;
}
