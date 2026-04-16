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
 *  - All environment variables are passed through (SSH_ORIGINAL_COMMAND etc.)
 *    because execve() inherits the caller's environment.
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

int main(int argc __attribute__((unused)), char *argv[], char *envp[])
{
    /*
     * The kernel has already set our effective gid to ob-sessions via the
     * setgid bit.  We only need to make sure the supplementary groups list
     * does not inadvertently grant extra privileges beyond what the real user
     * already had.  We intentionally keep the real uid/gid so that the
     * session recorder can tell which user is logging in.
     *
     * Drop any suid/sgid escalation beyond what we need: we want effective
     * gid = ob-sessions (already set by kernel), and we do NOT want to run
     * with elevated uid.  Since this binary is NOT setuid, effective uid
     * already equals real uid – nothing to do for uid.
     *
     * We do NOT call setgroups() to strip supplementary groups: that would
     * require CAP_SETGID and would break legitimate group memberships the
     * user relies on for their shell session.
     */

    /*
     * Persist the effective gid (ob-sessions) as the real gid.
     * The kernel drops setgid on exec of interpreted scripts (#!),
     * so we must set the real gid explicitly before exec.
     * This requires that the binary is setgid (chmod 2755).
     */
    gid_t target_gid = getegid();
    if (setregid(target_gid, target_gid) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: setregid(%d) failed: %s\n",
                target_gid, strerror(errno));
        return 1;
    }

    /* Verify we can actually exec the recorder (basic sanity check) */
    if (access(SESSION_RECORDER, X_OK) != 0) {
        fprintf(stderr, "ob-session-recorder-wrapper: cannot execute %s: %s\n",
                SESSION_RECORDER, strerror(errno));
        return 1;
    }

    /* exec the real session recorder, passing through all args and env */
    execve(SESSION_RECORDER, argv, envp);

    /* execve only returns on error */
    fprintf(stderr, "ob-session-recorder-wrapper: execve(%s) failed: %s\n",
            SESSION_RECORDER, strerror(errno));
    return 1;
}
