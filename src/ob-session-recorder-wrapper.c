/*
 * ob-session-recorder-wrapper.c
 *
 * Minimal setgid wrapper for ob-session-recorder.
 *
 * Install as: root:ob-sessions, mode 2755 (setgid)
 *
 * Purpose: create the user's session recording directory with group
 * ob-sessions and the setgid bit, then exec the session recorder script
 * with the user's ORIGINAL privileges (no elevated gid).
 *
 * Architecture:
 *  1. Kernel gives us effective gid = ob-sessions (via setgid bit on binary)
 *  2. We create $SESSIONS_DIR/$USER/ owned by user:ob-sessions, mode 2770
 *     - The directory's setgid bit ensures all files created inside inherit
 *       the ob-sessions group, without the process needing elevated gid
 *  3. We explicitly drop the elevated gid via setregid(orig, orig)
 *     - exec does NOT strip an already-acquired effective/saved gid
 *     - We must drop it ourselves before exec'ing the script
 *  4. We sanitize the environment (LD_PRELOAD, BASH_ENV, etc.)
 *  5. We exec the recorder script with the user's original gid only
 *     - Files created in the session dir still get group ob-sessions
 *       thanks to the directory's setgid bit (mode 2770)
 *
 * Security properties:
 *  - The target path is hard-coded; no user-controlled input affects it.
 *  - The elevated gid is used ONLY for directory creation, then explicitly
 *    dropped via setregid() before exec.
 *  - Dangerous environment variables are stripped before exec.
 *  - No temporary files, no user-controlled paths.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>

/* Hard-coded paths – never derived from user input */
#define SESSION_RECORDER "/usr/sbin/ob-session-recorder"
#define SESSIONS_DIR     "/var/lib/open-bastion/sessions"

/*
 * Validate a username: must match ^[a-z_][a-z0-9_.-]*$
 * Returns 0 if valid, -1 if invalid.
 */
static int validate_username(const char *name)
{
    if (!name || !*name) return -1;

    /* First char: lowercase letter or underscore */
    if (!((*name >= 'a' && *name <= 'z') || *name == '_'))
        return -1;

    for (const char *p = name + 1; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '.' || *p == '-'))
            return -1;
    }
    return 0;
}

/*
 * Sanitize environment: remove variables that the dynamic linker, C library,
 * or shell honour and that could be abused to inject code or alter behaviour.
 *
 * Since we do NOT call setregid(), the kernel will strip LD_PRELOAD etc.
 * on exec of the setgid binary itself. However, we sanitize them anyway as
 * defense-in-depth, and we MUST strip BASH_ENV/ENV which the kernel does
 * not handle (they are processed by the shell interpreter, not the loader).
 */
static void sanitize_environment(void)
{
    static const char *dangerous_vars[] = {
        /* Dynamic linker injection vectors */
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_BIND_NOW",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_DYNAMIC_WEAK",
        "LD_HWCAP_MASK",
        "LD_ORIGIN_PATH",
        "LD_PROFILE",
        "LD_PROFILE_OUTPUT",
        "LD_SHOW_AUXV",
        "LD_USE_LOAD_BIAS",
        /* Shell init vectors – executed before set -euo pipefail */
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "CDPATH",
        /* glibc / locale / resolver side-channels */
        "GCONV_PATH",
        "HOSTALIASES",
        "LOCALDOMAIN",
        "LOCPATH",
        "MALLOC_TRACE",
        "NIS_PATH",
        "NLSPATH",
        "RESOLV_HOST_CONF",
        "RES_OPTIONS",
        /* Miscellaneous */
        "TMPDIR",
        NULL
    };

    for (const char **var = dangerous_vars; *var; var++) {
        unsetenv(*var);
    }

    /*
     * Harden PATH: set a safe, minimal PATH to prevent execution of
     * attacker-supplied binaries via $PATH in the recorder script.
     */
    setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
}

/*
 * Create the user's session recording directory with the proper ownership
 * and permissions. The directory gets the setgid bit so that all files
 * created inside inherit the ob-sessions group.
 *
 * Returns 0 on success or if directory already exists, -1 on error.
 */
static int ensure_user_session_dir(const char *username, uid_t uid, gid_t sessions_gid)
{
    char dirpath[512];
    int len = snprintf(dirpath, sizeof(dirpath), "%s/%s", SESSIONS_DIR, username);
    if (len < 0 || (size_t)len >= sizeof(dirpath)) {
        fprintf(stderr, "ob-session-recorder-wrapper: session dir path too long\n");
        return -1;
    }

    /*
     * Try to open an existing directory first.
     * Use O_NOFOLLOW to prevent symlink attacks.
     * All subsequent checks use the fd to avoid TOCTOU races.
     */
    int fd = open(dirpath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd >= 0) {
        /* Directory exists - validate and repair ownership/mode if needed */
        struct stat st;
        if (fstat(fd, &st) != 0) {
            close(fd);
            return -1;
        }
        /* Ensure correct ownership: user:ob-sessions */
        if (st.st_uid != uid || st.st_gid != sessions_gid) {
            if (fchown(fd, uid, sessions_gid) != 0) {
                fprintf(stderr, "ob-session-recorder-wrapper: "
                        "cannot repair ownership on %s: %s\n",
                        dirpath, strerror(errno));
                close(fd);
                return -1;
            }
        }
        /* Ensure mode 2770 (setgid + rwxrwx---) */
        if ((st.st_mode & 07777) != 02770) {
            fchmod(fd, 02770);
        }
        close(fd);
        return 0;
    }

    /* Directory does not exist - create it. We have effective gid ob-sessions. */
    if (mkdir(dirpath, 02770) != 0) {
        if (errno == EEXIST) {
            /* Race: another process created it between our open and mkdir */
            return 0;
        }
        fprintf(stderr, "ob-session-recorder-wrapper: mkdir(%s) failed: %s\n",
                dirpath, strerror(errno));
        return -1;
    }

    /*
     * Set ownership via fd to avoid TOCTOU between mkdir and chown.
     * Open the directory we just created, then use fchown on the fd.
     */
    fd = open(dirpath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: open(%s) after mkdir failed: %s\n",
                dirpath, strerror(errno));
        rmdir(dirpath);
        return -1;
    }

    if (fchown(fd, uid, sessions_gid) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: fchown(%s, %u, %u) failed: %s\n",
                dirpath, (unsigned)uid, (unsigned)sessions_gid, strerror(errno));
        close(fd);
        rmdir(dirpath);
        return -1;
    }

    /*
     * Re-apply mode after fchown: POSIX allows chown to clear the
     * setgid bit as a security measure. Ensure 2770 is set.
     */
    fchmod(fd, 02770);

    close(fd);
    return 0;
}

int main(int argc __attribute__((unused)), char *argv[])
{
    uid_t real_uid = getuid();
    gid_t sessions_gid = getegid();  /* ob-sessions, from setgid bit */

    /* Get username from real uid */
    struct passwd *pw = getpwuid(real_uid);
    if (!pw || !pw->pw_name) {
        fprintf(stderr, "ob-session-recorder-wrapper: cannot resolve uid %u\n",
                (unsigned)real_uid);
        return 1;
    }

    /* Validate username to prevent path traversal */
    if (validate_username(pw->pw_name) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: invalid username\n");
        return 1;
    }

    /*
     * Create the user's session directory with group ob-sessions and setgid bit.
     * This is the ONLY operation that uses the elevated effective gid.
     */
    if (ensure_user_session_dir(pw->pw_name, real_uid, sessions_gid) != 0) {
        return 1;
    }

    /*
     * Drop the elevated ob-sessions gid now that directory setup is done.
     *
     * The setgid bit on this binary gave us effective gid = ob-sessions.
     * We used it solely to create/chown the session directory above.
     * Now we must explicitly drop it: exec does NOT strip an already-acquired
     * effective/saved gid — it only ignores setgid bits on the exec'd file.
     *
     * After this call: real = effective = saved = user's original gid.
     * The session directory's setgid bit (mode 2770) ensures files created
     * inside still inherit the ob-sessions group.
     */
    gid_t orig_gid = getgid();  /* user's real gid, unchanged by setgid bit */
    if (setregid(orig_gid, orig_gid) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: setregid(%u) failed: %s\n",
                (unsigned)orig_gid, strerror(errno));
        return 1;
    }

    /*
     * Sanitize the environment before exec.
     * Strip LD_*, BASH_ENV, ENV, and harden PATH.
     */
    sanitize_environment();

    /* Verify we can actually exec the recorder (basic sanity check) */
    if (access(SESSION_RECORDER, X_OK) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: cannot execute %s: %s\n",
                SESSION_RECORDER, strerror(errno));
        return 1;
    }

    /*
     * Exec the real session recorder.
     *
     * The elevated gid has been explicitly dropped above via setregid().
     * The script and user's shell run with the user's original gid only.
     * Files inherit the ob-sessions group from the directory's setgid bit.
     *
     * Use execv() so the sanitized in-process environment is inherited.
     */
    execv(SESSION_RECORDER, argv);

    /* execv only returns on error */
    fprintf(stderr, "ob-session-recorder-wrapper: execv(%s) failed: %s\n",
            SESSION_RECORDER, strerror(errno));
    return 1;
}
