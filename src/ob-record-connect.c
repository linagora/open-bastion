/*
 * ob-record-connect - unprivileged connector for the session-recording sink
 *
 * Part of the tamper-evident session recording design
 * (doc/design/tamper-evident-session-recording.rst, #151). ob-session-recorder
 * runs this as the logged-in user. It:
 *
 *   1. connect()s the local Unix socket served by ob-record-sink (socket-
 *      activated, runs as root). If it cannot connect it exits NON-ZERO BEFORE
 *      reading any stream, so the recorder can fail closed (refuse the session)
 *      before a shell starts.
 *   2. writes the one-line JSON metadata header to the socket,
 *   3. waits for a one-byte ACK the sink sends only after the session's initial
 *      metadata and recording file exist. No ACK -- the sink rejected the
 *      header (oversized, wrong version, duplicate id) or could not create the
 *      files, and closed -- means the connector exits NON-ZERO before opening
 *      the FIFO, so nothing is ever streamed and the recorder refuses the
 *      session. This closes the window where a rejected header still let the
 *      command run unrecorded (#287): before the ACK, the connector blocked on
 *      the FIFO and looked alive to the recorder even though the sink was gone.
 *   4. once the ACK arrives, prints "OB_READY" on stdout so the recorder knows
 *      the sink accepted, then opens STREAM_PATH (a FIFO that `script` writes
 *      the typescript to, or /dev/null for a metadata-only transfer session)
 *      and copies it to the socket in length-prefixed frames until EOF, then
 *      sends the empty END-OF-STREAM frame and half-closes so the sink
 *      finalizes the recording.
 *
 * The end-of-stream frame is what lets the sink tell a session that ended from
 * a forwarder that was killed (#287, EBIOS MT34): it is sent only after a clean
 * EOF on STREAM_PATH, so a SIGKILL, a crash or a read error leaves the sink
 * with a stream that stops short, which it finalizes as "aborted".
 *
 * SIGHUP, SIGINT and SIGQUIT are ignored. A hang-up is how a session normally
 * ends -- the client goes away, and SIGHUP reaches the whole process group --
 * and the forwarder must outlive it long enough to drain what `script` wrote
 * and send the end-of-stream frame. It still ends as soon
 * as `script` closes the FIFO, and SIGTERM still stops it (the recorder uses
 * that on a forwarder that is stuck).
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
 *         STREAM_PATH may be "-" for a metadata-only session (no payload): the
 *         connector sends the header, waits for the ACK, and sends only the
 *         end-of-stream frame. A transfer uses "-" so it never opens a path,
 *         which also means it can never read back a file it also writes to.
 * Env:    OB_RECORD_SOCKET   override socket path (default /run/open-bastion/rec.sock)
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define DEFAULT_SOCKET "/run/open-bastion/rec.sock"
#define BUF_SZ 65536
/* The sink writes this one byte once the session's metadata and recording file
 * exist. Must match OB_RECORD_ACK in ob-record-sink.c. */
#define OB_RECORD_ACK 0x06 /* ASCII ACK */
/* Bound the wait for that ACK: a sink that accepts the connection but never
 * answers must not hang the caller forever (the transfer path runs this
 * synchronously). Matches the recorder's CONNECT_TIMEOUT for the PTY path.
 * OB_RECORD_ACK_TIMEOUT overrides it (clamped 1..60), for tests; a user-set
 * value can only shorten or slightly lengthen the wait for an unresponsive
 * sink, and the PTY path is bounded by the recorder's own timeout regardless. */
#define ACK_TIMEOUT_SEC 15
#define ACK_TIMEOUT_MAX 60

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

/* One frame: 4-byte big-endian length, then the payload. len 0 is the
 * end-of-stream marker. */
static int write_frame(int fd, const char *buf, size_t len)
{
    unsigned char hdr[4] = {
        (unsigned char)((uint32_t)len >> 24), (unsigned char)((uint32_t)len >> 16),
        (unsigned char)((uint32_t)len >> 8), (unsigned char)len,
    };
    if (write_all(fd, (const char *)hdr, sizeof(hdr)) < 0)
        return -1;
    return len ? write_all(fd, buf, len) : 0;
}

int main(int argc, char **argv)
{
    /* See the header comment: a hang-up must not cost the end-of-stream
     * frame. A write to a closed socket is reported as EPIPE, not a signal. */
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

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

    /* Wait for the sink's ACK: one byte, sent only after it has created this
     * session's metadata and recording file. Anything else -- EOF (the sink
     * rejected the header and closed), a read error, a wrong byte, or no answer
     * within ACK_TIMEOUT_SEC -- means the session is NOT being recorded, so we
     * exit non-zero WITHOUT opening the stream. The recorder then refuses the
     * session. The timeout matters on the transfer path, which runs this
     * synchronously: a sink that accepts but never answers must not hang it. */
    long ack_to = ACK_TIMEOUT_SEC;
    const char *ate = getenv("OB_RECORD_ACK_TIMEOUT");
    if (ate && *ate) {
        char *end = NULL;
        long v = strtol(ate, &end, 10);
        if (end && *end == '\0' && v >= 1 && v <= ACK_TIMEOUT_MAX)
            ack_to = v;
    }
    struct timeval atv = {.tv_sec = ack_to, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &atv, sizeof(atv));
    unsigned char ack = 0;
    ssize_t an = read(fd, &ack, 1);
    while (an < 0 && errno == EINTR)
        an = read(fd, &ack, 1);
    if (an != 1 || ack != OB_RECORD_ACK) {
        fprintf(stderr,
                "[ob-record-connect] the recording sink did not acknowledge the session "
                "(it refused the header, could not create the recording, or did not "
                "answer in time); refusing\n");
        close(fd);
        return 1;
    }
    /* Clear the receive timeout: the stream that follows has none (an idle
     * interactive session is normal; the sink bounds it by liveness). */
    struct timeval zero = {.tv_sec = 0, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

    /* Tell the recorder the sink accepted, so it can start the session only
     * now. A short, fixed token on stdout; the recorder reads one line. */
    if (write_all(STDOUT_FILENO, "OB_READY\n", 9) < 0) {
        /* The recorder is gone; nothing to record for. */
        close(fd);
        return 1;
    }

    /* Open the stream source. For a PTY session this is a FIFO that `script`
     * opens for writing once it starts (so this open blocks until then). A
     * metadata-only session passes "-": there is no stream, so we do not open
     * any path (which is what keeps a transfer from ever reading back a file
     * it also writes to) and send only the end-of-stream frame. */
    int in = -1;
    int rc = 0;
    if (strcmp(stream_path, "-") != 0) {
        in = open(stream_path, O_RDONLY);
        if (in < 0) {
            fprintf(stderr, "[ob-record-connect] open(%s): %s\n", stream_path, strerror(errno));
            close(fd);
            return 1;
        }
        /* Forward stream -> socket, one frame per read. BUF_SZ must not exceed
         * the sink's frame cap (its COPY_BUF, also 64 KiB). */
        char buf[BUF_SZ];
        ssize_t n;
        while ((n = read(in, buf, sizeof(buf))) != 0) {
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                fprintf(stderr, "[ob-record-connect] read(stream): %s\n", strerror(errno));
                rc = 1;
                break;
            }
            if (write_frame(fd, buf, (size_t)n) < 0) {
                fprintf(stderr, "[ob-record-connect] write(socket): %s\n", strerror(errno));
                rc = 1;
                break;
            }
        }
        close(in);
    }
    /* Clean EOF only: vouch that the stream is complete. */
    if (rc == 0 && write_frame(fd, NULL, 0) < 0) {
        fprintf(stderr, "[ob-record-connect] write(socket): %s\n", strerror(errno));
        rc = 1;
    }

    shutdown(fd, SHUT_WR);
    close(fd);
    return rc;
}
