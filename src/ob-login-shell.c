/*
 * ob-login-shell - login shell of SSO users on a host that records sessions
 *
 * Handed out by libnss_openbastion (force_shell). It reads no file the user
 * controls and never runs a shell or a command itself: every path ends in an
 * execve() of the session recorder, with an environment built here from
 * scratch. See ob-login-shell(8).
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "path_validator.h"

#define OB_LOGIN_SHELL "/usr/sbin/ob-login-shell"

#ifndef OB_LOGIN_SHELL_TESTBUILD
/* The shipped binary: the packaged recorder, and the packaged NSS
 * configuration, which must be root's. No knob of any kind. */
#define OB_RECORDER "/usr/sbin/ob-session-recorder"
#define OB_NSS_CONF "/etc/open-bastion/nss_openbastion.conf"
#define OB_CONF_TRUSTED_UID ((uid_t)0)
#else
/*
 * Test builds only (tests/CMakeLists.txt, never installed): both paths come
 * from the environment so the suite runs unprivileged. The -strictuid variant
 * still requires a root-owned configuration.
 */
static const char *test_path(const char *var)
{
    const char *v = getenv(var);

    if (!v || !*v) {
        fprintf(stderr, "ob-login-shell-testbuild: %s is not set\n", var);
        exit(3);
    }
    return v;
}
#define OB_RECORDER test_path("OB_TEST_RECORDER")
#define OB_NSS_CONF test_path("OB_TEST_NSS_CONF")
#ifdef OB_LOGIN_SHELL_STRICTUID
#define OB_CONF_TRUSTED_UID ((uid_t)0)
#else
#define OB_CONF_TRUSTED_UID geteuid()
#endif
#endif

#define OB_FALLBACK_SHELL "/bin/bash"
/* What sshd sets for an ordinary user on Debian (--with-default-path). The
 * recorder sets its own PATH anyway; this is the one the real shell starts
 * with, and it must not be the one the user's environment carried. */
#define OB_SESSION_PATH "/usr/local/bin:/usr/bin:/bin:/usr/games"

#define MAX_ENV 48
#define MAX_REC_ARGS 16

static char *g_env[MAX_ENV + 1];
static int g_nenv;

static void die(int code, const char *log_fmt, const char *arg, const char *user_msg)
{
    syslog(LOG_ERR, log_fmt, arg ? arg : "");
    fprintf(stderr, "ob-login-shell: %s\n", user_msg);
    exit(code);
}

/* Non-empty, at most maxlen bytes, only [A-Za-z0-9] and the bytes in extra. */
static int only_chars(const char *s, const char *extra, size_t maxlen)
{
    size_t n = 0;

    if (!s || !*s)
        return 0;
    for (; *s; s++, n++) {
        unsigned char c = (unsigned char)*s;
        if (n >= maxlen)
            return 0;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9'))
            continue;
        if (c && strchr(extra, c))
            continue;
        return 0;
    }
    return 1;
}

static void env_add(const char *name, const char *value)
{
    size_t len = strlen(name) + 1 + strlen(value) + 1;
    char *s;

    if (g_nenv >= MAX_ENV)
        die(1, "environment table full at %s", name,
            "internal error, refusing the session");
    s = malloc(len);
    if (!s)
        die(1, "out of memory at %s", name, "out of memory, refusing the session");
    snprintf(s, len, "%s=%s", name, value);
    g_env[g_nenv++] = s;
    g_env[g_nenv] = NULL;
}

/* Carry NAME over from our environment if it passes ok(); drop it otherwise. */
static void env_keep(const char *name, int (*ok)(const char *))
{
    const char *v = getenv(name);

    if (v && ok(v))
        env_add(name, v);
}

static int ok_term(const char *v)    { return only_chars(v, "._+-", 64); }
static int ok_client(const char *v)  { return only_chars(v, ".:%_ -", 256); }
static int ok_word(const char *v)    { return only_chars(v, "_-", 64); }
/* A locale name, never a path: glibc loads a locale NAMED by an absolute path
 * from that path, i.e. from a file the user may have written. */
static int ok_locale(const char *v)  { return only_chars(v, "._@-", 64); }
static int ok_language(const char *v){ return only_chars(v, "._@:-", 256); }

static int ok_tty(const char *v)
{
    return strncmp(v, "/dev/", 5) == 0 && only_chars(v + 5, "/", 32) &&
           !strstr(v, "..");
}

static int ok_sock(const char *v)
{
    return strlen(v) < 108 && !path_validator_is_dangerous(v);
}

/* sshd passes the client's command through verbatim; the recorder, not us,
 * decides what to make of it. Only a NUL could not be carried, and cannot
 * occur in an environment string. */
static int ok_any(const char *v)     { (void)v; return 1; }

/* Same inode as PATH (both stat()able)? */
static int same_file(const struct stat *st, const char *path)
{
    struct stat o;

    return stat(path, &o) == 0 && o.st_dev == st->st_dev && o.st_ino == st->st_ino;
}

/*
 * Can PATH be the shell the recorder starts? An absolute, plain path to an
 * executable regular file that is neither this program nor the recorder:
 * either would make the recorder start itself inside its own recording.
 */
static int shell_usable(const char *path)
{
    struct stat st;

    if (!path || path_validator_is_dangerous(path))
        return 0;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || access(path, X_OK) != 0)
        return 0;
    if (same_file(&st, "/proc/self/exe") || same_file(&st, OB_LOGIN_SHELL) ||
        same_file(&st, OB_RECORDER))
        return 0;
    return 1;
}

/* Trim blanks and a trailing newline, in place. */
static char *trim(char *s)
{
    char *e;

    while (*s == ' ' || *s == '\t')
        s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r'))
        *--e = '\0';
    return s;
}

/*
 * The last `default_shell` of nss_openbastion.conf, parsed the way
 * libnss_openbastion parses it (surrounding quotes removed), into buf. Returns
 * buf, or NULL when the file is absent, unreadable, not root's, writable by
 * anyone else, or has no such key. Same trust rule as the NSS module: this file
 * decides what the recorded session runs.
 */
static const char *configured_shell(char *buf, size_t buflen)
{
    struct stat st;
    char line[1024];
    int found = 0, fd;
    FILE *f;

    fd = open(OB_NSS_CONF, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != OB_CONF_TRUSTED_UID || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        syslog(LOG_WARNING, "%s is not a root-owned file writable only by root; "
               "ignoring it and starting " OB_FALLBACK_SHELL, OB_NSS_CONF);
        close(fd);
        return NULL;
    }
    f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return NULL;
    }
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line), *eq, *key, *val;
        size_t vlen;

        if (*p == '#' || *p == '\0')
            continue;
        eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        key = trim(p);
        val = trim(eq + 1);
        vlen = strlen(val);
        if (vlen >= 2 && ((val[0] == '"' && val[vlen - 1] == '"') ||
                          (val[0] == '\'' && val[vlen - 1] == '\''))) {
            val[vlen - 1] = '\0';
            val++;
        }
        if (strcmp(key, "default_shell") == 0 && strlen(val) < buflen) {
            memcpy(buf, val, strlen(val) + 1);
            found = 1;
        }
    }
    fclose(f);
    return found ? buf : NULL;
}

static const char *real_shell(void)
{
    static char buf[256];
    const char *s = configured_shell(buf, sizeof(buf));

    if (s && shell_usable(s))
        return s;
    if (s)
        syslog(LOG_WARNING, "default_shell '%s' in %s cannot be the session's "
               "shell (not an executable, or this launcher or the recorder); "
               "starting " OB_FALLBACK_SHELL, s, OB_NSS_CONF);
    if (shell_usable(OB_FALLBACK_SHELL))
        return OB_FALLBACK_SHELL;
    die(1, "no usable shell for the recorded session (%s)", OB_FALLBACK_SHELL,
        "no shell available for this session, access refused");
    return NULL;
}

/*
 * Is CMD the recorder, i.e. sshd running our ForceCommand? The recorder's
 * path, alone or followed by options made of plain characters, split on
 * blanks into args. Anything else -- quoting, a metacharacter, a different
 * program -- is not the ForceCommand, and is handed to the recorder as the
 * command to record instead.
 */
static int recorder_command(const char *cmd, char **args, int *nargs)
{
    size_t rlen = strlen(OB_RECORDER);
    char *copy, *tok, *save = NULL;
    int n = 0;

    if (strncmp(cmd, OB_RECORDER, rlen) != 0)
        return 0;
    if (cmd[rlen] != '\0' && cmd[rlen] != ' ' && cmd[rlen] != '\t')
        return 0;
    copy = strdup(cmd + rlen);
    if (!copy)
        die(1, "out of memory%s", "", "out of memory, refusing the session");
    for (tok = strtok_r(copy, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
        if (n >= MAX_REC_ARGS || !only_chars(tok, "_./=:,+-", 256)) {
            free(copy);
            return 0;
        }
        args[n++] = tok;
    }
    *nargs = n;
    return 1;
}

int main(int argc, char **argv)
{
    char *rec_args[MAX_REC_ARGS];
    char *rec_argv[MAX_REC_ARGS + 2];
    const char *cmd = NULL;
    struct passwd *pw;
    int nrec = 0, i = 1;
    char buf[32];

    openlog("ob-login-shell", LOG_PID, LOG_AUTHPRIV);

    /* Options a login shell is commonly given; none changes what happens. */
    while (i < argc && (strcmp(argv[i], "-l") == 0 ||
                        strcmp(argv[i], "--login") == 0 ||
                        strcmp(argv[i], "-i") == 0))
        i++;
    if (i < argc) {
        if (strcmp(argv[i], "-c") != 0 || i + 1 >= argc || i + 2 < argc)
            die(2, "refused an unsupported invocation (%s)", argv[i],
                "unsupported invocation; this account's shell only starts "
                "recorded sessions (-c COMMAND, or no argument)");
        cmd = argv[i + 1];
    }

    pw = getpwuid(getuid());
    if (!pw || !pw->pw_name || !*pw->pw_name || !pw->pw_dir || !*pw->pw_dir) {
        snprintf(buf, sizeof(buf), "%u", (unsigned)getuid());
        die(1, "cannot resolve uid %s", buf,
            "cannot resolve your account, access refused");
    }

    /* The environment the recorder, and the session after it, will have.
     * Identity from the passwd entry, not from variables anyone could set. */
    g_env[0] = NULL;
    env_add("USER", pw->pw_name);
    env_add("LOGNAME", pw->pw_name);
    env_add("HOME", pw->pw_dir);
    env_add("SHELL", real_shell());
    env_add("PATH", OB_SESSION_PATH);
    env_keep("TERM", ok_term);
    env_keep("SSH_CLIENT", ok_client);
    env_keep("SSH_CONNECTION", ok_client);
    env_keep("SSH_TTY", ok_tty);
    env_keep("SSH_AUTH_SOCK", ok_sock);
    env_keep("LANG", ok_locale);
    env_keep("LANGUAGE", ok_language);
    {
        static const char *const lc[] = {
            "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE",
            "LC_MONETARY", "LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS",
            "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION", NULL
        };
        for (const char *const *p = lc; *p; p++)
            env_keep(*p, ok_locale);
    }
    env_keep("XDG_SESSION_ID", ok_word);
    env_keep("XDG_SESSION_TYPE", ok_word);
    env_keep("XDG_SESSION_CLASS", ok_word);
    {
        const char *v = getenv("XDG_RUNTIME_DIR");
        char want[64];

        snprintf(want, sizeof(want), "/run/user/%u", (unsigned)getuid());
        if (v && strcmp(v, want) == 0)
            env_add("XDG_RUNTIME_DIR", v);
    }

    if (cmd && recorder_command(cmd, rec_args, &nrec)) {
        /* sshd's ForceCommand: the client's command is in our environment. */
        env_keep("SSH_ORIGINAL_COMMAND", ok_any);
    } else if (cmd) {
        /* Someone asked this shell to run a command. The recorder runs it. */
        env_add("SSH_ORIGINAL_COMMAND", cmd);
        syslog(LOG_INFO, "user %s: command handed to the session recorder",
               pw->pw_name);
    }
    /* No command: an interactive session. Whatever SSH_ORIGINAL_COMMAND the
     * caller had (su from inside a session) is not ours and is not passed. */

    rec_argv[0] = (char *)OB_RECORDER;
    for (i = 0; i < nrec; i++)
        rec_argv[i + 1] = rec_args[i];
    rec_argv[nrec + 1] = NULL;

    execve(rec_argv[0], rec_argv, g_env);
    die(1, "cannot execute the session recorder: %s", strerror(errno),
        "cannot start the session recorder, access refused");
    return 1;
}
