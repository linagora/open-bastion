/*
 * sshd_anchor.h - the per-connection sshd "anchor" PID.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 *
 * The SSH fingerprint spool (#249) keys every drop on the anchor: the
 * AuthorizedPrincipalsCommand helper deposits under it (through ob-fp-daemon,
 * which derives it from the helper's own ancestry) and pam_openbastion reads
 * under it. Writer and reader must compute the SAME pid from the SAME process
 * tree, or the module looks for a drop under a key the daemon never wrote --
 * and that failure is silent: no error at login, simply no fingerprint, so the
 * binding doc/security/99-risk-reduce.rst credits with reducing R-S3 and R-S15
 * is gone while everything still appears to work.
 *
 * That is why this is one function rather than a rule two files are asked to
 * obey. Both used to carry their own copy, agreeing only by inspection.
 */

#ifndef OB_SSHD_ANCHOR_H
#define OB_SSHD_ANCHOR_H

#include <sys/types.h>

/*
 * How far up the process tree to walk. sshd puts the anchor two or three hops
 * above PAM; the limit only bounds the walk on a tree that has no anchor.
 */
#define OB_SSHD_ANCHOR_MAX_DEPTH 16

/*
 * The anchor for `pid`: the OUTERMOST contiguous "sshd-session" ancestor, or
 * the first "sshd" ancestor on pre-split OpenSSH. Returns 0 when there is
 * none.
 *
 * OpenSSH >= 9.8 splits each connection into TWO processes both named
 * "sshd-session": the privileged monitor (child of the "sshd" listener) and an
 * unprivileged child under it. PAM and the principals helper may run under
 * EITHER, so stopping at the *first* "sshd-session" would key writer and
 * reader on different pids. Returning the outermost contiguous one converges
 * both on the monitor. On pre-split OpenSSH (< 9.8, e.g. RHEL/Rocky 9's 8.7)
 * there is no "sshd-session" and the first "sshd" ancestor is the anchor.
 *
 * `pid` itself is examined: the caller's own process may be the anchor.
 */
pid_t ob_find_sshd_anchor(pid_t pid);

/*
 * Same walk against `proc_root` instead of /proc, so tests/test_sshd_anchor.c
 * can drive it over a synthetic ancestry. Production callers use
 * ob_find_sshd_anchor(); this exists so the walk above can be tested at all,
 * and it reads only <root>/<pid>/comm and <root>/<pid>/status.
 */
pid_t ob_find_sshd_anchor_in(const char *proc_root, pid_t pid);

#endif /* OB_SSHD_ANCHOR_H */
