/*
 * ob-record-connect - unprivileged connector for the session-recording sink
 *
 * Part of the tamper-evident session recording design
 * (doc/design/tamper-evident-session-recording.md, #151). ob-session-recorder
 * runs this as the logged-in user. It:
 *
 *   1. connect()s the local Unix socket served by ob-record-sink (socket-
 *      activated, runs as root). If it cannot connect it exits NON-ZERO BEFORE
 *      reading any stream, so the recorder can fail closed (refuse the session)
 *      before a shell starts.
 *   2. writes the one-line JSON metadata header to the socket,
 *   3. opens STREAM_PATH (a FIFO that `script` writes the typescript to, or
 *      /dev/null for a metadata-only transfer session) and copies it to the
 *      socket until EOF, then half-closes so the sink finalizes the recording.
 *
 * Why a FIFO and not script's typescript=/dev/fd/N: `script(1)` re-open()s its
 * typescript path, and a Unix-domain socket CANNOT be opened via /dev/fd/N
 * (open() returns ENXIO). A real FIFO inode opens fine, so `script` writes to
 * the FIFO and this helper forwards FIFO -> socket.
 *
 * It carries NO privilege and holds NO secret: ob-record-sink derives the
 * recorded user from the connection's SO_PEERCRED (kernel-verified), so the
 * header here cannot make the sink write under another user's name.
 *
 * Usage:  ob-record-connect HEADER_JSON STREAM_PATH
 * Env:    OB_RECORD_SOCKET   override socket path (default /run/open-bastion/rec.sock)
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define DEFAULT_SOCKET "/run/open-bastion/rec.sock"
#define BUF_SZ 65536

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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s HEADER_JSON STREAM_PATH\n", argv[0]);
        return 2;
    }
    const char *header = argv[1];
    const char *stream_path = argv[2];

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

    /* Connect FIRST (fast for a local listening socket). On failure exit
     * non-zero before touching the stream, so the caller fails closed. */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "[ob-record-connect] cannot reach the recording sink at %s: %s\n",
                sock_path, strerror(errno));
        fprintf(stderr,
                "[ob-record-connect] is ob-record.socket enabled? (re-run the setup)\n");
        close(fd);
        return 1;
    }

    /* Send the one-line header, newline-terminated, before the stream. */
    size_t hlen = strlen(header);
    if (write_all(fd, header, hlen) < 0 || write_all(fd, "\n", 1) < 0) {
        fprintf(stderr, "[ob-record-connect] failed sending header: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    /* Open the stream source. For a PTY session this is a FIFO that `script`
     * opens for writing once it starts (so this open blocks until then). For a
     * transfer session it is /dev/null (immediate EOF, metadata only). */
    int in = open(stream_path, O_RDONLY);
    if (in < 0) {
        fprintf(stderr, "[ob-record-connect] open(%s): %s\n", stream_path, strerror(errno));
        close(fd);
        return 1;
    }

    /* Forward stream -> socket. */
    char buf[BUF_SZ];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof(buf))) != 0) {
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[ob-record-connect] read(stream): %s\n", strerror(errno));
            rc = 1;
            break;
        }
        if (write_all(fd, buf, (size_t)n) < 0) {
            fprintf(stderr, "[ob-record-connect] write(socket): %s\n", strerror(errno));
            rc = 1;
            break;
        }
    }

    close(in);
    shutdown(fd, SHUT_WR);
    close(fd);
    return rc;
}
