/*
 * ob-fp-daemon - socket-activated root sink for the SSH fingerprint spool.
 *
 * Why this exists (#249)
 * ----------------------
 * pam_openbastion recovers the SSH key fingerprint of a session from
 * /run/open-bastion/ssh-fp/<anchor>.fp, because OpenSSH does not export
 * SSH_USER_AUTH to PAM during pam_acct_mgmt. Until now that drop was written
 * directly by the AuthorizedPrincipalsCommand helper, which sshd requires to
 * run unprivileged -- so the spool directory was 0700 nobody, and the
 * integrity of the fingerprint binding rested on the `nobody` account. That
 * is a shared, low-trust identity: code execution as nobody could read every
 * deposited fingerprint and write a well-formed drop at any PID. The checks
 * pam_openbastion already makes (O_NOFOLLOW, nlink == 1, mode 0600, drop owner
 * == directory owner, size bounds) are all aimed at an attacker OUTSIDE the
 * perimeter; none of them helps against an attacker who is nobody.
 *
 * This daemon moves the trust root to root, using the pattern ob-cert-daemon
 * (#145) already uses for the same class of problem: the helper no longer
 * writes the spool, it hands the fingerprint to this daemon over a unix socket
 * and the daemon -- running as root, with a 0700 root spool -- writes it.
 *
 * What the socket actually buys
 * -----------------------------
 * SO_PEERCRED alone would not be enough: the legitimate caller IS nobody, so
 * "the peer is nobody" does not distinguish the real helper from any other
 * nobody process. The load is carried by the second check:
 *
 *   the anchor PID is DERIVED from the peer's own /proc ancestry, never taken
 *   from the request.
 *
 * A client cannot name the session it is depositing for. To place a drop on a
 * given anchor you must already be a descendant of that anchor -- and the
 * anchor must be a live sshd-session monitor with real uid 0. sshd puts exactly
 * one unprivileged thing in that position, the principals helper. A nobody
 * daemon started from init descends from pid 1, not from an sshd-session, and
 * cannot re-parent itself into one; a logged-in user's shell IS under an
 * sshd-session but runs as the user, which the uid check rejects. Forging a
 * binding therefore needs code execution as the helper user *inside the target
 * connection's own process tree*, which is a strictly smaller thing than "code
 * execution as nobody anywhere on the host".
 *
 * Reading is closed outright: the spool becomes 0700 root, so nobody can no
 * longer enumerate the fingerprints of other sessions.
 *
 * Protocol (newline-delimited, read from the socket, at most OB_FP_REQ_MAX):
 *   line 1: fingerprint   "SHA256:<base64>"     (required)
 *   line 2: key algorithm sshd's %t             (may be empty)
 *   line 3: key blob      sshd's %k, base64     (may be empty)
 * Reply: one line, "OK" or "ERR <reason>", so the helper can log something
 * useful instead of failing silently.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "sshd_anchor.h"

#ifndef OB_FP_SPOOL_DIR
#define OB_FP_SPOOL_DIR "/run/open-bastion/ssh-fp"
#endif

#ifndef OB_FP_SOCKET
#define OB_FP_SOCKET "/run/open-bastion/ssh-fp.sock"
#endif

/* Default AuthorizedPrincipalsCommandUser in every shipped setup. */
#define OB_FP_DEFAULT_HELPER_USER "nobody"

/*
 * The uid this daemon considers privileged: the owner an sshd anchor must have,
 * and the owner it gives the spool. In the shipped binary this is literally 0,
 * so the production code carries no test affordance at all. The test build
 * sets OB_FP_PRIV_UID_IS_EUID (tests/CMakeLists.txt), which is what lets the
 * suite exercise these paths without root -- unprivileged user namespaces are
 * restricted on Ubuntu 24.04, so a test that needed one would skip in CI, and a
 * skip reads as a pass.
 */
#ifdef OB_FP_PRIV_UID_IS_EUID
#define OB_FP_PRIV_UID (geteuid())
#else
#define OB_FP_PRIV_UID ((uid_t)0)
#endif

/*
 * Request cap. The largest legitimate payload is an RSA-4096 certificate blob
 * (~2.5 kB of base64) plus two short lines; 20 kB matches the module's own
 * OB_SSH_SPOOL_KEY_MAX so the two ends agree on what is too big.
 */
#define OB_FP_REQ_MAX   20480
#define OB_FP_FP_MAX      512
#define OB_FP_ALG_MAX      64

static void reply(int ok, const char *msg)
{
    /*
     * stdout is the same socket as stdin under Accept=yes. Best effort: the
     * helper may already be gone, and that must not turn into a failed drop.
     */
    if (ok) {
        (void)!write(STDOUT_FILENO, "OK\n", 3);
    } else {
        char line[256];
        int n = snprintf(line, sizeof(line), "ERR %s\n", msg);
        if (n > 0) (void)!write(STDOUT_FILENO, line, (size_t)n);
        syslog(LOG_ERR, "ob-fp-daemon: %s", msg);
    }
}

/* ---------------------------------------------------------------- validation */

/* "SHA256:" followed by standard base64 (no padding in sshd's output). */
static int valid_fingerprint(const char *s)
{
    if (strncmp(s, "SHA256:", 7) != 0) return 0;
    const char *p = s + 7;
    if (!*p) return 0;
    for (; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '+' || *p == '/' || *p == '=')) {
            return 0;
        }
    }
    return 1;
}

/* An OpenSSH algorithm name: ssh-ed25519, rsa-sha2-512-cert-v01@openssh.com. */
static int valid_algorithm(const char *s)
{
    if (!*s) return 0;
    for (const char *p = s; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '@' || *p == '.'
              || *p == '_' || *p == '-')) {
            return 0;
        }
    }
    return 1;
}

static int valid_blob(const char *s)
{
    if (!*s) return 0;
    for (const char *p = s; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '+' || *p == '/' || *p == '=')) {
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------ helper identity */

/*
 * Which uid is allowed to deposit: the owner of the listening socket.
 *
 * That is the one place the answer is already written down. ob-fp.socket sets
 * `SocketUser=nobody`, matching the AuthorizedPrincipalsCommandUser both setup
 * scripts configure, and an admin who changes one and overrides the other in a
 * drop-in gets a daemon that follows rather than one that locks them out.
 *
 * There is deliberately no config key for this. An earlier version read
 * `principals_helper_user` from openbastion.conf, which was a false
 * affordance in three separate ways: config.c does not know the key, so
 * setting it logged "unknown configuration key" at every login; both setups
 * hard-code `AuthorizedPrincipalsCommandUser nobody`; and the socket is
 * `SocketUser=nobody 0600`, so a helper running as anyone else could not have
 * connected in the first place.
 *
 * With SocketMode=0600 the kernel already enforces this, so the check is
 * defence in depth -- it keeps holding if a drop-in loosens the mode.
 */
static uid_t helper_uid(void)
{
    struct stat st;
    if (stat(OB_FP_SOCKET, &st) == 0) {
        return st.st_uid;
    }

    /*
     * The socket we are serving should exist; if it cannot be stat'd, fall
     * back to the shipped default rather than refusing every deposit over a
     * transient error.
     */
    struct passwd pw, *pwp = NULL;
    char buf[4096];
    if (getpwnam_r(OB_FP_DEFAULT_HELPER_USER, &pw, buf, sizeof(buf), &pwp) != 0
        || !pwp) {
        syslog(LOG_ERR, "ob-fp-daemon: cannot stat %s and no '%s' user: "
                        "refusing every deposit",
               OB_FP_SOCKET, OB_FP_DEFAULT_HELPER_USER);
        return (uid_t)-1;
    }
    syslog(LOG_WARNING, "ob-fp-daemon: cannot stat %s, falling back to '%s'",
           OB_FP_SOCKET, OB_FP_DEFAULT_HELPER_USER);
    return pw.pw_uid;
}

/* ---------------------------------------------------------------- proc walking */

/*
 * The anchor is derived by ob_find_sshd_anchor() (src/sshd_anchor.c), the same
 * function pam_openbastion calls. It used to be a second copy of that walk
 * here, kept in step by a comment; the two differ only in their starting point,
 * and that is now the only thing this file says about it -- the module starts
 * at its own pid, this starts at the peer's.
 */

/* ------------------------------------------------------------------- the spool */

/*
 * Make sure the spool exists as 0700 root:root. The daemon owns the directory
 * now, so it asserts that rather than trusting whatever tmpfiles.d or an older
 * setup script left behind -- an upgraded host still has the 0700 *nobody*
 * directory from before #249, and leaving it would keep the old trust root
 * while looking fixed.
 */
static int ensure_spool_dir(void)
{
    if (mkdir(OB_FP_SPOOL_DIR, 0700) != 0 && errno != EEXIST) return -1;

    int dfd = open(OB_FP_SPOOL_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) return -1;

    struct stat st;
    if (fstat(dfd, &st) != 0) { close(dfd); return -1; }
    if (!S_ISDIR(st.st_mode)) { close(dfd); errno = ENOTDIR; return -1; }

    /* Own the directory: the 0700 root spool #249 is about. */
    uid_t want = OB_FP_PRIV_UID;
    if (st.st_uid != want && fchown(dfd, want, (gid_t)-1) != 0) {
        close(dfd);
        return -1;
    }
    if ((st.st_mode & 07777) != 0700 && fchmod(dfd, 0700) != 0) {
        close(dfd);
        return -1;
    }
    return dfd;
}

/* Atomically place `content` at <anchor>.<suffix>, mode 0600, root-owned. */
static int write_drop(int dfd, pid_t anchor, const char *suffix,
                      const char *content)
{
    char tmpl[64], final[64];
    /*
     * mkstemp has no *at form, so name the temporary by hand. Our OWN pid goes
     * in it, not just the anchor's: sshd runs AuthorizedPrincipalsCommand once
     * per candidate key, so two instances can be depositing for the same anchor
     * and suffix at the same time, and a shared temporary name would make them
     * clobber each other's half-written file. With one name per instance,
     * O_EXCL plus the atomic rename below means concurrent deposits can only
     * race on which complete drop wins.
     */
    snprintf(tmpl, sizeof(tmpl), ".%d.%s.%d", (int)anchor, suffix, (int)getpid());
    snprintf(final, sizeof(final), "%d.%s", (int)anchor, suffix);

    int fd = openat(dfd, tmpl, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0 && errno == EEXIST) {
        (void)unlinkat(dfd, tmpl, 0);
        fd = openat(dfd, tmpl, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    }
    if (fd < 0) return -1;

    size_t len = strlen(content);
    ssize_t w = write(fd, content, len);
    if (w < 0 || (size_t)w != len || fchmod(fd, 0600) != 0) {
        close(fd);
        (void)unlinkat(dfd, tmpl, 0);
        return -1;
    }
    close(fd);

    if (renameat(dfd, tmpl, dfd, final) != 0) {
        (void)unlinkat(dfd, tmpl, 0);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------ main */

static char *next_line(char **cursor)
{
    char *s = *cursor;
    if (!s) return NULL;
    char *nl = strchr(s, '\n');
    if (nl) {
        *nl = '\0';
        *cursor = nl + 1;
    } else {
        *cursor = NULL;
    }
    char *end = s + strlen(s);
    while (end > s && end[-1] == '\r') *--end = '\0';
    return s;
}

int main(void)
{
    openlog("ob-fp-daemon", LOG_PID, LOG_AUTHPRIV);

    /*
     * Do not let a stuck client hold a root process open. Under Accept=yes
     * systemd hands us one connection on fd 0/1 and nothing else runs here.
     */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(STDIN_FILENO, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(STDOUT_FILENO, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* 1. Who is on the other end. Kernel-verified, taken at connect() time. */
    struct ucred cred;
    socklen_t clen = sizeof(cred);
    if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0) {
        reply(0, "SO_PEERCRED failed (not a socket?)");
        return 1;
    }

    uid_t allowed = helper_uid();
    if (allowed == (uid_t)-1) {
        reply(0, "cannot determine which uid may deposit");
        return 1;
    }
    if (cred.uid != allowed && cred.uid != 0) {
        char m[160];
        snprintf(m, sizeof(m),
                 "deposit from uid %u refused (expected the principals helper "
                 "uid %u)", (unsigned)cred.uid, (unsigned)allowed);
        reply(0, m);
        return 1;
    }

    /*
     * The peer must still exist for its ancestry to mean anything. This is a
     * liveness check and nothing more: the anchor walk below reopens /proc by
     * path, so holding a descriptor here would not pin the walk against pid
     * recycling. Closing that window properly would mean comparing the peer's
     * start time before and after, and it is not worth it -- to exploit the
     * race an attacker would have to get the depositing pid recycled into a
     * process of their own, under a root sshd-session, in the microseconds
     * between connect() and this read, and the drop they would win is the one
     * for the session they would already have to be inside.
     */
    char peer_proc[64];
    snprintf(peer_proc, sizeof(peer_proc), "/proc/%d", (int)cred.pid);
    if (access(peer_proc, F_OK) != 0) {
        reply(0, "the depositing process is already gone");
        return 1;
    }

    /*
     * 2. The anchor is derived, never received. This is what stops a nobody
     *    process from depositing on a session it is not part of.
     */
    pid_t anchor = ob_find_sshd_anchor(cred.pid);
    if (anchor <= 1) {
        reply(0, "no sshd-session ancestor: refusing a deposit that is not "
                 "part of an SSH connection");
        return 1;
    }

    /*
     * The anchor is chosen by process NAME, and prctl(PR_SET_NAME) takes
     * fifteen characters while "sshd-session" is twelve -- so without this a
     * local user could put a process called sshd-session in their own ancestry
     * and pick which drop gets written. Requiring the anchor's REAL uid to be
     * root excludes every process a user controls. Not its effective uid: the
     * monitor is seteuid() to the helper user while we run; see
     * ob_sshd_anchor_owner_ok_in().
     *
     * OB_FP_PRIV_UID is a literal 0 in the shipped binary; see its definition.
     */
    uid_t anchor_ruid = 0;
    int owner = ob_sshd_anchor_owner_ok(anchor, OB_FP_PRIV_UID, &anchor_ruid);
    if (owner < 0) {
        reply(0, (errno == ENOENT || errno == ESRCH)
                     ? "the sshd anchor vanished mid-deposit"
                     : "cannot read the sshd anchor's real uid: refusing");
        return 1;
    }
    if (owner == 0) {
        char m[160];
        snprintf(m, sizeof(m),
                 "sshd anchor %d has real uid %u, not root: refusing",
                 (int)anchor, (unsigned)anchor_ruid);
        reply(0, m);
        return 1;
    }

    /* 3. The request. */
    char req[OB_FP_REQ_MAX + 1];
    size_t used = 0;
    for (;;) {
        ssize_t r = read(STDIN_FILENO, req + used, sizeof(req) - 1 - used);
        if (r < 0) {
            reply(0, "short read from the depositing process");
            return 1;
        }
        if (r == 0) break;
        used += (size_t)r;
        if (used >= sizeof(req) - 1) {
            reply(0, "request too large");
            return 1;
        }
    }
    req[used] = '\0';
    if (memchr(req, '\0', used) != NULL) {
        reply(0, "request contains a NUL byte");
        return 1;
    }

    char *cursor = req;
    const char *fp  = next_line(&cursor);
    const char *alg = next_line(&cursor);
    const char *key = next_line(&cursor);
    if (!alg) alg = "";
    if (!key) key = "";

    if (!fp || strlen(fp) >= OB_FP_FP_MAX || !valid_fingerprint(fp)) {
        reply(0, "malformed fingerprint");
        return 1;
    }
    /*
     * A bad algorithm or blob drops the .key metadata but must NOT lose the
     * fingerprint: the .fp drop is what the LLNG binding needs, and the shell
     * helper has always degraded the same way rather than failing the login.
     */
    if (*alg && (strlen(alg) >= OB_FP_ALG_MAX || !valid_algorithm(alg))) alg = "";
    if (*key && !valid_blob(key)) key = "";

    /* 4. Write, as root, into a 0700 root spool. */
    int dfd = ensure_spool_dir();
    if (dfd < 0) {
        reply(0, "cannot prepare " OB_FP_SPOOL_DIR);
        return 1;
    }

    char fp_body[OB_FP_FP_MAX + 2];
    snprintf(fp_body, sizeof(fp_body), "%s\n", fp);
    if (write_drop(dfd, anchor, "fp", fp_body) != 0) {
        close(dfd);
        reply(0, "cannot write the fingerprint drop");
        return 1;
    }

    if (*alg) {
        /* v1 key-metadata drop, byte-for-byte what the shell helper wrote. */
        /*
         * strlen(fp) belongs in here: the fingerprint is interpolated too, and
         * leaving it out sized the buffer exactly one fingerprint short, so
         * snprintf silently truncated the tail of the key blob. A truncated
         * blob still parses -- it just decodes to a different key -- which is
         * the kind of thing ssh_key_policy_* would then reject for no visible
         * reason.
         */
        size_t need = strlen(fp) + strlen(alg) + strlen(key) + 64;
        char *body = malloc(need);
        if (body) {
            if (*key) {
                snprintf(body, need, "v=1\nfp=%s\nalg=%s\nkey=%s\n", fp, alg, key);
            } else {
                snprintf(body, need, "v=1\nfp=%s\nalg=%s\n", fp, alg);
            }
            if (write_drop(dfd, anchor, "key", body) != 0) {
                syslog(LOG_WARNING,
                       "ob-fp-daemon: fingerprint recorded for anchor %d but the "
                       "key-metadata drop failed; ssh_key_policy_* will deny",
                       (int)anchor);
            }
            free(body);
        }
    }

    close(dfd);
    syslog(LOG_INFO, "ob-fp-daemon: fingerprint recorded for sshd anchor %d",
           (int)anchor);
    reply(1, NULL);
    return 0;
}
