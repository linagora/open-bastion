/*
 * test_sshd_anchor.c - the sshd anchor walk, over a synthetic /proc.
 *
 * The anchor keys the SSH fingerprint spool (#249): ob-fp-daemon writes
 * /run/open-bastion/ssh-fp/<anchor>.fp after deriving <anchor> from the
 * depositing helper's ancestry, and pam_openbastion reads it after deriving
 * <anchor> from its own. The two run at DIFFERENT depths of the same process
 * tree and must still land on the same pid. Until #268 each had its own copy of
 * the walk and nothing checked they agreed; a divergence breaks the binding
 * silently -- no error at login, simply no drop found, and the reduction that
 * doc/security/99-risk-reduce.rst credits to R-S3 and R-S15 is gone.
 *
 * There is now one implementation (src/sshd_anchor.c) and these tests drive it
 * from both starting points over the same tree, plus the edge cases the walk
 * defines: the depth limit, a non-contiguous sshd-session chain, pid 1, a
 * vanished process, and a self-parenting one.
 *
 * The tree is synthetic: a directory of <pid>/{comm,status} files, which is all
 * the walk reads. Real ancestries cannot be built by a test -- they need sshd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sshd_anchor.h"

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

static char root[] = "/tmp/ob-anchor-XXXXXX";

/* Create <root>/<pid>/{comm,status} for a process named `comm` under `ppid`. */
static void mkproc(pid_t pid, const char *comm, pid_t ppid)
{
    char dir[256], path[320];
    snprintf(dir, sizeof(dir), "%s/%d", root, (int)pid);
    if (mkdir(dir, 0700) != 0 && access(dir, X_OK) != 0) {
        perror("mkdir");
        exit(2);
    }

    snprintf(path, sizeof(path), "%s/comm", dir);
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen comm"); exit(2); }
    fprintf(f, "%s\n", comm);
    fclose(f);

    /*
     * Real /proc/<pid>/status has ~50 lines with PPid several lines in; put
     * something before it so the reader is not accidentally tested against a
     * one-line file.
     */
    snprintf(path, sizeof(path), "%s/status", dir);
    f = fopen(path, "w");
    if (!f) { perror("fopen status"); exit(2); }
    fprintf(f, "Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%d\n"
               "Ngid:\t0\nPid:\t%d\nPPid:\t%d\nTracerPid:\t0\n",
            comm, (int)pid, (int)pid, (int)ppid);
    fclose(f);
}

/* Remove every <pid> subtree between calls, so trees cannot bleed into each
 * other and make a later case pass on an earlier case's processes. */
static void reset_tree(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s/*", root);
    if (system(cmd) != 0) { fprintf(stderr, "cannot clear %s\n", root); exit(2); }
}

static pid_t anchor(pid_t from)
{
    return ob_find_sshd_anchor_in(root, from);
}

/* Create <root>/<pid>/status holding `uid_line` among realistic neighbours
 * (NULL: no Uid line at all). */
static void mkstatus(pid_t pid, const char *uid_line)
{
    char dir[256], path[320];
    snprintf(dir, sizeof(dir), "%s/%d", root, (int)pid);
    if (mkdir(dir, 0700) != 0 && access(dir, X_OK) != 0) {
        perror("mkdir");
        exit(2);
    }
    snprintf(path, sizeof(path), "%s/status", dir);
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen status"); exit(2); }
    fprintf(f, "Name:\tsshd-session\nPid:\t%d\nPPid:\t1\n%s"
               "Gid:\t0\t0\t0\t0\nFDSize:\t64\n",
            (int)pid, uid_line ? uid_line : "");
    fclose(f);
}

/* ob_sshd_anchor_owner_ok_in() with priv_uid 0. */
static int owner_ok(pid_t pid, uid_t *ruid)
{
    return ob_sshd_anchor_owner_ok_in(root, pid, 0, ruid);
}

int main(void)
{
    if (!mkdtemp(root)) { perror("mkdtemp"); return 2; }

    /*
     * OpenSSH >= 9.8. Both the monitor and its unprivileged child are named
     * "sshd-session"; the anchor is the OUTERMOST of the two (900).
     *
     *   1 -- 800 sshd (listener) -- 900 sshd-session (monitor)
     *          -- 950 sshd-session (unpriv child) -- 970 bash
     */
    printf("split OpenSSH (>= 9.8):\n");
    mkproc(800, "sshd", 1);
    mkproc(900, "sshd-session", 800);
    mkproc(950, "sshd-session", 900);
    mkproc(970, "bash", 950);

    CHECK(anchor(970) == 900, "from a leaf under the unprivileged child -> monitor");
    CHECK(anchor(950) == 900, "from the unprivileged child itself -> monitor");
    CHECK(anchor(900) == 900, "from the monitor itself -> monitor");

    /*
     * The property the whole spool rests on. ob-fp-daemon starts at the
     * principals helper's pid, pam_openbastion at its own; the two sit at
     * different depths and must produce the same key.
     */
    CHECK(anchor(970) == anchor(950) && anchor(950) == anchor(900),
          "writer and reader depths agree on the same anchor");

    /* Pre-split OpenSSH (< 9.8, RHEL/Rocky 9): no "sshd-session" at all, the
     * per-connection process is "sshd" and its first occurrence is the anchor.
     * The listener (800) must NOT win. */
    printf("pre-split OpenSSH (< 9.8):\n");
    reset_tree();
    mkproc(800, "sshd", 1);
    mkproc(900, "sshd", 800);
    mkproc(970, "bash", 900);
    CHECK(anchor(970) == 900, "first sshd ancestor, not the listener");

    /*
     * Non-contiguous chain. Only the outermost of the CONTIGUOUS run counts:
     * an sshd-session higher up, separated by something else, belongs to
     * another connection (a nested ssh, an sshd restarted under one) and
     * keying on it would cross sessions.
     *
     *   1 -- 800 sshd -- 850 sshd-session -- 900 bash -- 950 sshd-session -- 970 cat
     */
    printf("non-contiguous sshd-session chain:\n");
    reset_tree();
    mkproc(800, "sshd", 1);
    mkproc(850, "sshd-session", 800);
    mkproc(900, "bash", 850);
    mkproc(950, "sshd-session", 900);
    mkproc(970, "cat", 950);
    CHECK(anchor(970) == 950, "stops at the break, does not climb to the outer one");

    /* The depth limit is 16 examined processes: distance 0..15 from the start.
     * A tree deeper than that yields no anchor rather than an unbounded walk. */
    printf("depth limit (%d):\n", OB_SSHD_ANCHOR_MAX_DEPTH);
    reset_tree();
    for (int i = 0; i < OB_SSHD_ANCHOR_MAX_DEPTH - 1; i++)
        mkproc(1000 + i, "bash", 1000 + i + 1);
    mkproc(1000 + OB_SSHD_ANCHOR_MAX_DEPTH - 1, "sshd-session", 1);
    CHECK(anchor(1000) == 1000 + OB_SSHD_ANCHOR_MAX_DEPTH - 1,
          "an anchor at the last examined depth is still found");

    reset_tree();
    for (int i = 0; i < OB_SSHD_ANCHOR_MAX_DEPTH; i++)
        mkproc(1000 + i, "bash", 1000 + i + 1);
    mkproc(1000 + OB_SSHD_ANCHOR_MAX_DEPTH, "sshd-session", 1);
    CHECK(anchor(1000) == 0, "one hop beyond the limit is not found");

    printf("degenerate trees:\n");
    reset_tree();
    mkproc(800, "systemd", 1);
    mkproc(900, "bash", 800);
    CHECK(anchor(900) == 0, "no sshd anywhere in the ancestry -> 0");

    reset_tree();
    mkproc(1, "systemd", 0);
    CHECK(anchor(1) == 0, "pid 1 is never an anchor");

    /* A process that exited mid-walk: /proc/<pid> is gone. Whatever was found
     * below it still stands; nothing above it can be. */
    reset_tree();
    mkproc(900, "sshd-session", 850);   /* 850 deliberately does not exist */
    mkproc(970, "bash", 900);
    CHECK(anchor(970) == 900, "a vanished parent keeps the anchor found below it");

    reset_tree();
    mkproc(970, "bash", 900);           /* 900 deliberately does not exist */
    CHECK(anchor(970) == 0, "a vanished parent with nothing found yet -> 0");

    /* PPid pointing at itself, or at 0: both must terminate. A synthetic or
     * corrupt tree must not spin. */
    reset_tree();
    mkproc(970, "bash", 970);
    CHECK(anchor(970) == 0, "a self-parenting process terminates the walk");

    reset_tree();
    mkproc(970, "bash", 0);
    CHECK(anchor(970) == 0, "PPid 0 terminates the walk");

    /*
     * The anchor-owner rule: REAL uid must be root. #296: the monitor is
     * seteuid(nobody) while the principals helper deposits.
     */
    printf("anchor owner (real uid):\n");
    reset_tree();
    uid_t ruid = 12345;
    mkstatus(900, "Uid:\t0\t65534\t0\t65534\n");
    CHECK(owner_ok(900, &ruid) == 1 && ruid == 0,
          "real root, effective nobody (monitor during the helper, #296) -> ok");

    mkstatus(901, "Uid:\t0\t0\t0\t0\n");
    CHECK(owner_ok(901, NULL) == 1, "all root -> ok");

    ruid = 0;
    mkstatus(902, "Uid:\t1000\t1000\t1000\t1000\n");
    CHECK(owner_ok(902, &ruid) == 0 && ruid == 1000,
          "a user's process renamed sshd-session -> refused");

    mkstatus(903, "Uid:\t65534\t0\t0\t0\n");
    CHECK(owner_ok(903, NULL) == 0,
          "real non-root, effective root (setuid) -> refused");

    CHECK(ob_sshd_anchor_owner_ok_in(root, 902, 1000, NULL) == 1,
          "priv_uid is honoured (test builds of ob-fp-daemon)");

    CHECK(owner_ok(904, NULL) == -1, "missing status -> refused");

    mkstatus(905, NULL);
    CHECK(owner_ok(905, NULL) == -1, "no Uid line -> refused");

    mkstatus(906, "Uid:\t0\n");
    CHECK(owner_ok(906, NULL) == -1, "truncated Uid line -> refused");

    mkstatus(907, "Uid:\tabc\t0\t0\t0\n");
    CHECK(owner_ok(907, NULL) == -1, "non-numeric real uid -> refused");

    mkstatus(908, "Uid:\t-0\t0\t0\t0\n");
    CHECK(owner_ok(908, NULL) == -1, "signed real uid -> refused");

    mkstatus(909, "Uid:\t0x\t0\t0\t0\n");
    CHECK(owner_ok(909, NULL) == -1, "trailing garbage in a field -> refused");

    mkstatus(910, "Uid:\t99999999999999999999\t0\t0\t0\n");
    CHECK(owner_ok(910, NULL) == -1, "overflowing real uid -> refused");

    mkstatus(911, "Uid:\t0\t0\t0\t0\t0\n");
    CHECK(owner_ok(911, NULL) == -1, "extra field -> refused");

    CHECK(owner_ok(0, NULL) == -1 && owner_ok(-1, NULL) == -1,
          "non-positive pid -> refused");

    reset_tree();
    rmdir(root);

    printf("\n%d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
