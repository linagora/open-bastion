/*
 * ob-session-recorder-wrapper.c
 *
 * Minimal setgid wrapper for ob-session-recorder.
 *
 * Install as: root:ob-sessions, mode 2755 (setgid)
 *
 * Purpose: ensure the session recorder runs with effective gid ob-sessions
 * so that session files are created with group ob-sessions.  The sessions
 * directory is mode 1770 root:ob-sessions (sticky + rwxrwx---), which means
 * only root or a process with effective gid ob-sessions can create files
 * there.  The sticky bit prevents non-root/non-owner processes from deleting
 * files they do not own.
 *
 * Security properties:
 *  - The target path is hard-coded; no user-controlled input affects it.
 *  - Real uid/gid are unchanged; only effective gid comes from the setgid bit.
 *  - Dangerous environment variables (LD_PRELOAD etc.) are stripped before exec
 *    to prevent code injection via dynamic linker when running with elevated gid.
 *  - The user's original real gid is exported as OB_ORIG_GID so the session
 *    recorder can drop back to it before spawning user shells.
 *  - No temporary files, no dynamic allocation, no user-controlled paths.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <grp.h>
#include <errno.h>
#include <string.h>

/* Hard-coded path – never derived from user input */
#define SESSION_RECORDER "/usr/sbin/ob-session-recorder"

/*
 * Sanitize environment: remove variables that the dynamic linker or C library
 * honour and that could be abused to inject code or alter behaviour when
 * running with elevated group privileges.
 *
 * After setregid(), the kernel considers the exec'd process as non-privilege-
 * gaining (real gid == effective gid), so LD_PRELOAD etc. would NOT be
 * stripped automatically by the dynamic linker.  We must do it ourselves
 * before calling execv().
 *
 * We use execv() (not execve()) so that the current process environment—
 * after these unsetenv() calls—is inherited by the child.  Using execve()
 * with the original envp[] snapshot would bypass the sanitisation.
 */
static void sanitize_environment(void)
{
    static const char *dangerous_vars[] = {
        /* Dynamic linker injection vectors */
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_BIND_NOT",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_DYNAMIC_WEAK",
        "LD_HWCAP_MASK",
        "LD_ORIGIN_PATH",
        "LD_PROFILE",
        "LD_PROFILE_OUTPUT",
        "LD_SHOW_AUXV",
        "LD_USE_LOAD_BIAS",
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
}

int main(int argc __attribute__((unused)), char *argv[])
{
    /*
     * Save the user's original real gid before we change it.
     * Export it as OB_ORIG_GID so the session recorder script can drop back
     * to the user's primary group before spawning user shells, limiting the
     * window during which the ob-sessions gid is active.
     */
    gid_t orig_gid = getgid();
    char orig_gid_str[32];
    snprintf(orig_gid_str, sizeof(orig_gid_str), "%u", (unsigned int)orig_gid);
    if (setenv("OB_ORIG_GID", orig_gid_str, 1) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: setenv(OB_ORIG_GID) failed: %s\n",
                strerror(errno));
        return 1;
    }

    /*
     * The kernel has already set our effective gid to ob-sessions via the
     * setgid bit.  Persist it as the real gid so it survives exec of
     * interpreted scripts (#!).
     *
     * Note: after this call, real gid == effective gid == ob-sessions.
     * The kernel will therefore NOT strip LD_PRELOAD etc. on the next exec,
     * which is why sanitize_environment() must be called below.
     */
    gid_t target_gid = getegid();
    if (setregid(target_gid, target_gid) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: setregid(%d) failed: %s\n",
                target_gid, strerror(errno));
        return 1;
    }

    /*
     * Sanitize the environment: strip LD_PRELOAD and all other dynamic-linker
     * variables that a malicious user could set to inject code running with
     * the ob-sessions group.  Must be done AFTER setregid() and BEFORE execv().
     */
    sanitize_environment();

    /* Verify we can actually exec the recorder (basic sanity check) */
    if (access(SESSION_RECORDER, X_OK) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: cannot execute %s: %s\n",
                SESSION_RECORDER, strerror(errno));
        return 1;
    }

    /*
     * Exec the real session recorder, passing through all args.
     * Use execv() (not execve()) so the sanitized current environment—
     * after the unsetenv() calls above—is inherited by the child.
     * execve() with the original envp snapshot would bypass sanitisation.
     */
    execv(SESSION_RECORDER, argv);

    /* execv only returns on error */
    fprintf(stderr, "ob-session-recorder-wrapper: execv(%s) failed: %s\n",
            SESSION_RECORDER, strerror(errno));
    return 1;
}
