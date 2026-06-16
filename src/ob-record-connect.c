/*
 * ob-record-connect - unprivileged connector for the session-recording sink
 *
 * Part of the tamper-evident session recording design
 * (doc/design/tamper-evident-session-recording.md, #151). ob-session-recorder
 * runs this as the logged-in user; it:
 *
 *   1. connect()s the local Unix socket served by ob-record-sink (socket-
 *      activated, runs as root),
 *   2. moves the connected socket to fd 3 (kept open across exec — not CLOEXEC),
 *   3. writes the one-line JSON metadata header to fd 3,
 *   4. exec()s the trailing command (typically `script … /dev/fd/3`), which then
 *      streams the recording straight into the socket.
 *
 * A POSIX shell CANNOT open an AF_UNIX socket (`exec 3<>` opens files/FIFOs),
 * which is exactly why this tiny C helper exists. It carries NO privilege and
 * holds NO secret: ob-record-sink derives the recorded user from the
 * connection's SO_PEERCRED (kernel-verified), so the header here cannot make the
 * sink write under another user's name.
 *
 * Usage:  ob-record-connect HEADER_JSON CMD [ARGS...]
 *   HEADER_JSON  one-line JSON metadata (no embedded newline)
 *   CMD [ARGS]   the command to exec with the socket at /dev/fd/3
 *
 * Env:
 *   OB_RECORD_SOCKET   override the socket path (default /run/open-bastion/rec.sock)
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define DEFAULT_SOCKET "/run/open-bastion/rec.sock"
#define CONN_FD 3

/* Write all of buf to fd (handles short writes / EINTR). Returns 0/-1. */
static int write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s HEADER_JSON CMD [ARGS...]\n", argv[0]);
        return 2;
    }
    const char *header = argv[1];
    char **cmd = &argv[2];

    if (strchr(header, '\n')) {
        fprintf(stderr, "[ob-record-connect] header must not contain a newline\n");
        return 2;
    }

    const char *sock_path = getenv("OB_RECORD_SOCKET");
    if (!sock_path || !*sock_path)
        sock_path = DEFAULT_SOCKET;

    struct sockaddr_un addr;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "[ob-record-connect] socket path too long: %s\n", sock_path);
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[ob-record-connect] socket(): %s\n", strerror(errno));
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "[ob-record-connect] cannot reach the recording sink at %s: %s\n",
                sock_path, strerror(errno));
        fprintf(stderr,
                "[ob-record-connect] is ob-record.socket enabled? (re-run the setup)\n");
        return 1;
    }

    /* Move the connection to a well-known fd so the exec'd command can address it
     * as /dev/fd/3. The socket fd is not CLOEXEC, so it survives the exec. */
    if (fd != CONN_FD) {
        if (dup2(fd, CONN_FD) < 0) {
            fprintf(stderr, "[ob-record-connect] dup2(): %s\n", strerror(errno));
            return 1;
        }
        close(fd);
    }

    /* Send the one-line header, newline-terminated, before the stream begins. */
    size_t hlen = strlen(header);
    if (write_all(CONN_FD, header, hlen) < 0 || write_all(CONN_FD, "\n", 1) < 0) {
        fprintf(stderr, "[ob-record-connect] failed sending header: %s\n", strerror(errno));
        return 1;
    }

    execvp(cmd[0], cmd);
    /* execvp only returns on error. */
    fprintf(stderr, "[ob-record-connect] exec %s: %s\n", cmd[0], strerror(errno));
    return 127;
}
