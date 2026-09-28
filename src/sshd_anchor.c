/*
 * sshd_anchor.c - the single implementation of the sshd anchor walk.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 *
 * See include/sshd_anchor.h for what the anchor is and why writer and reader
 * must agree on it. This file exists so that "must agree" is a property of the
 * program rather than of two comments.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "sshd_anchor.h"

/* Longest path we build: <proc_root>/<pid>/status. */
#define ANCHOR_PATH_MAX 512

/* Read the first line of `path` into `out`, newline stripped. 0 on success. */
static int read_first_line(const char *path, char *out, size_t out_sz)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)out_sz, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    return 0;
}

/* PPid from <proc_root>/<pid>/status, or 0 when it cannot be read. */
static pid_t read_ppid(const char *proc_root, pid_t pid)
{
    char path[ANCHOR_PATH_MAX], line[256];
    int n = snprintf(path, sizeof(path), "%s/%d/status", proc_root, (int)pid);
    if (n < 0 || n >= (int)sizeof(path)) return 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;
    pid_t ppid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = (pid_t)strtol(line + 5, NULL, 10);
            break;
        }
    }
    fclose(f);
    return ppid;
}

pid_t ob_find_sshd_anchor_in(const char *proc_root, pid_t pid)
{
    pid_t outermost = 0;  /* outermost contiguous sshd-session seen so far */

    /*
     * pid 1 is never an anchor and has no parent worth following, so it also
     * terminates the walk.
     */
    for (int i = 0; i < OB_SSHD_ANCHOR_MAX_DEPTH && pid > 1; i++) {
        char path[ANCHOR_PATH_MAX], comm[256];
        int n = snprintf(path, sizeof(path), "%s/%d/comm", proc_root, (int)pid);
        if (n < 0 || n >= (int)sizeof(path)) return outermost;
        if (read_first_line(path, comm, sizeof(comm)) != 0) return outermost;

        if (strcmp(comm, "sshd-session") == 0) {
            outermost = pid;         /* keep climbing: a parent one outranks it */
        } else if (outermost) {
            return outermost;        /* left the chain: the monitor is behind us */
        } else if (strcmp(comm, "sshd") == 0) {
            return pid;              /* pre-split OpenSSH */
        }

        pid_t ppid = read_ppid(proc_root, pid);
        /*
         * A parent that is its own child cannot happen on a live tree, but a
         * corrupt or synthetic one would loop here until the depth limit; stop
         * on it explicitly so the walk is bounded by the tree, not by luck.
         */
        if (ppid <= 0 || ppid == pid) return outermost;
        pid = ppid;
    }
    return outermost;
}

pid_t ob_find_sshd_anchor(pid_t pid)
{
    return ob_find_sshd_anchor_in("/proc", pid);
}

/* One decimal uid at *p, advancing past it. Strict: no sign, no overflow. */
static int parse_uid_field(const char **p, uid_t *out)
{
    const char *s = *p;
    while (*s == ' ' || *s == '\t') s++;
    if (*s < '0' || *s > '9') return -1;
    errno = 0;
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || (uid_t)v != v || (uid_t)v == (uid_t)-1) return -1;
    *out = (uid_t)v;
    *p = end;
    return 0;
}

int ob_sshd_anchor_owner_ok_in(const char *proc_root, pid_t pid,
                               uid_t priv_uid, uid_t *ruid_out)
{
    char path[ANCHOR_PATH_MAX], line[256];
    int n = snprintf(path, sizeof(path), "%s/%d/status", proc_root, (int)pid);
    if (pid <= 0 || n < 0 || n >= (int)sizeof(path)) {
        errno = EINVAL;
        return -1;
    }

    FILE *f = fopen(path, "r");
    if (!f) return -1;  /* errno from fopen: ENOENT/ESRCH when gone */

    /* Real, effective, saved, filesystem: all four must parse. */
    uid_t ids[4];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) != 0) continue;
        const char *p = line + 4;
        found = 1;
        for (int i = 0; i < 4; i++) {
            if (parse_uid_field(&p, &ids[i]) != 0) {
                found = 0;
                break;
            }
        }
        if (found && *p != '\n' && *p != '\0') found = 0;
        break;
    }
    fclose(f);
    if (!found) {
        errno = EINVAL;
        return -1;
    }

    if (ruid_out) *ruid_out = ids[0];
    return ids[0] == priv_uid ? 1 : 0;
}

int ob_sshd_anchor_owner_ok(pid_t pid, uid_t priv_uid, uid_t *ruid_out)
{
    return ob_sshd_anchor_owner_ok_in("/proc", pid, priv_uid, ruid_out);
}
