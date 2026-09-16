/*
 * test_cache_key.c - what src/cache_key.c refuses to accept as a key file.
 *
 * `4cbe85c` added six refusals to the offline-cache key file and touched no
 * test (#268): not a regular file, not owned by root, setuid, setgid, any group
 * bit, any other bit. It was the only hardening of the 0.7.0 series with no
 * proof, and it also corrected a real branch-nesting bug -- the ownership test
 * used to sit INSIDE the loose-permissions branch, so a key file that was mode
 * 0600 and owned by some other uid slipped through entirely. That case is the
 * one asserted first below.
 *
 * The checks are exercised through key_file_rejected(), the function
 * read_key_file() calls with owner 0. Passing the running uid instead is what
 * lets the four refusals BELOW the ownership test be reached without root: as
 * an ordinary user every file this test can create fails the uid check first,
 * and a suite that skips in every non-root CI job proves nothing. The root
 * requirement itself is asserted separately, against the shipped value.
 *
 * Including the .c reaches its static functions -- the same thing
 * tests/test_nss_cache.c does for the NSS cache helpers.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/cache_key.c"

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(cond, desc)                                                      \
    do {                                                                       \
        tests_run++;                                                           \
        if (cond) {                                                            \
            tests_passed++;                                                    \
            printf("  ok   %s\n", desc);                                       \
        } else {                                                               \
            printf("  FAIL %s\n", desc);                                       \
        }                                                                      \
    } while (0)

static char dir[] = "/tmp/ob-cachekey-XXXXXX";
static char keypath[256];

/* Write a 32-byte key file at `keypath` with exactly `mode`. */
static int make_key_file(mode_t mode)
{
    unlink(keypath);
    int fd = open(keypath, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;
    unsigned char material[KEY_FILE_SIZE];
    memset(material, 0x5a, sizeof(material));
    if (write(fd, material, sizeof(material)) != (ssize_t)sizeof(material)) {
        close(fd);
        return -1;
    }
    close(fd);
    /* chmod after write: the open above is masked by umask, and the setuid and
     * setgid bits cannot be set through O_CREAT at all. */
    return chmod(keypath, mode);
}

/* Does the module refuse the file currently at `keypath`, given `owner`? */
static int rejected(uid_t owner)
{
    struct stat st;
    if (stat(keypath, &st) != 0) {
        printf("  FAIL stat(%s) failed\n", keypath);
        return -1;
    }
    return key_file_rejected(&st, keypath, owner);
}

int main(void)
{
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    snprintf(keypath, sizeof(keypath), "%s/cache.key", dir);

    const uid_t me = getuid();
    /* A uid the file is definitely NOT owned by, whether the suite runs as an
     * ordinary user or (as in the Rocky container jobs) as root. */
    const uid_t foreign = (me == 0) ? (uid_t)65534 : (uid_t)0;

    /*
     * The bug 4cbe85c fixed. Mode 0600 is exactly what the documentation tells
     * an admin to create, so the permission test says nothing here; only the
     * uid does, and it must be reached.
     */
    printf("ownership:\n");
    if (make_key_file(0600) != 0) { perror("make_key_file"); return 2; }
    CHECK(rejected(foreign) == 1, "0600 but owned by another uid is refused");
    CHECK(rejected(me) == 0, "0600 and owned by the expected uid is accepted");

    /*
     * The acceptance above is what keeps the rest of this file honest: without
     * it every assertion below would also hold if key_file_rejected() refused
     * unconditionally.
     */

    printf("file type:\n");
    unlink(keypath);
    if (mkfifo(keypath, 0600) != 0) { perror("mkfifo"); return 2; }
    CHECK(rejected(me) == 1, "a fifo is refused (not a regular file)");
    /*
     * And read_key_file() must RETURN on it. Opening a fifo read-only blocks
     * until a writer appears, so without O_NONBLOCK the refusal above is
     * unreachable and this call would never come back -- on the PAM path, a
     * login that hangs. There is no writer here, so a regression hangs the
     * suite rather than failing it, which ctest's timeout reports.
     */
    {
        unsigned char buf[KEY_FILE_SIZE];
        CHECK(read_key_file(keypath, buf, sizeof(buf)) == -1,
              "read_key_file returns on a fifo instead of blocking");
    }
    unlink(keypath);

    printf("setuid / setgid:\n");
    if (make_key_file(04600) != 0) { perror("chmod 4600"); return 2; }
    CHECK(rejected(me) == 1, "setuid is refused");
    if (make_key_file(02600) != 0) { perror("chmod 2600"); return 2; }
    CHECK(rejected(me) == 1, "setgid is refused");
    if (make_key_file(06600) != 0) { perror("chmod 6600"); return 2; }
    CHECK(rejected(me) == 1, "setuid+setgid is refused");

    /*
     * Every group and other bit, one at a time. `dd if=/dev/urandom of=... `
     * under root's umask 022 yields 0644, which SECURITY.md documented for a
     * while, so 0640 and 0604 are the modes actually found in the field.
     */
    printf("group and other permission bits:\n");
    static const struct { mode_t mode; const char *desc; } loose[] = {
        { 0640, "group read is refused" },
        { 0620, "group write is refused" },
        { 0610, "group execute is refused" },
        { 0604, "other read is refused" },
        { 0602, "other write is refused" },
        { 0601, "other execute is refused" },
        { 0644, "0644 (root umask 022) is refused" },
    };
    for (size_t i = 0; i < sizeof(loose) / sizeof(loose[0]); i++) {
        if (make_key_file(loose[i].mode) != 0) { perror("chmod"); return 2; }
        CHECK(rejected(me) == 1, loose[i].desc);
    }

    /* 0400 has no group or other bit: readable is all the module needs. */
    if (make_key_file(0400) != 0) { perror("chmod 0400"); return 2; }
    CHECK(rejected(me) == 0, "0400 is accepted (no group or other bit)");

    /*
     * The shipped call site passes 0, not "whoever happens to run". This is the
     * only assertion that pins that value rather than the one the tests choose:
     * unprivileged, a file we own must be refused; as root it must be accepted,
     * which is also the only place the accepting end of read_key_file() -- the
     * short-read loop included -- gets exercised.
     */
    printf("the shipped call site:\n");
    if (make_key_file(0600) != 0) { perror("make_key_file"); return 2; }
    {
        unsigned char buf[KEY_FILE_SIZE];
        int r = read_key_file(keypath, buf, sizeof(buf));
        if (me != 0) {
            CHECK(r == -1, "read_key_file() refuses a key file we own, not root");
        } else {
            unsigned char expect[KEY_FILE_SIZE];
            memset(expect, 0x5a, sizeof(expect));
            CHECK(r == 0 && memcmp(buf, expect, sizeof(buf)) == 0,
                  "read_key_file() accepts a root-owned 0600 file and returns it");
        }
    }

    unlink(keypath);
    rmdir(dir);

    printf("\n%d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
