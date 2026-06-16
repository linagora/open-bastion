/*
 * ob-cert-request - unprivileged client for the bastion cert socket
 *
 * Replaces the old `sudo ob-bastion-cert-helper` bridge. ob-ssh / ob-scp run
 * this as the logged-in bastion user; it connects to the local Unix socket
 * served by ob-cert-daemon (socket-activated, runs as root), forwards the
 * request, and prints the LLNG /pam/bastion-cert JSON response on stdout.
 *
 * It carries NO privilege and holds NO secret: the daemon derives the
 * certificate's user from the connection's SO_PEERCRED (kernel-verified), so
 * the request body here cannot be used to mint a certificate for anyone else.
 *
 * Protocol (newline-delimited request written to the socket):
 *   line 1: target_host
 *   line 2: target_group   (may be empty -> daemon defaults to "default")
 *   line 3: voucher        (from $LLNG_BASTION_VOUCHER)
 *   line 4: ephemeral SSH public key
 * Response: the raw LLNG JSON, copied verbatim to stdout.
 *
 * Usage:  ob-cert-request [socket-path]
 *   stdin  = the 4-line request
 *   stdout = the JSON response
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

#define DEFAULT_SOCKET "/run/open-bastion/cert.sock"
#define BUF_SZ 8192

static int copy_all(int from_fd, int to_fd)
{
    char buf[BUF_SZ];
    ssize_t n;
    while ((n = read(from_fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(to_fd, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            off += w;
        }
    }
    return (n < 0) ? -1 : 0;
}

int main(int argc, char **argv)
{
    const char *sock_path = (argc > 1 && argv[1][0]) ? argv[1] : DEFAULT_SOCKET;

    struct sockaddr_un addr;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "[ob-cert-request] socket path too long: %s\n", sock_path);
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[ob-cert-request] socket(): %s\n", strerror(errno));
        return 2;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "[ob-cert-request] cannot reach the bastion cert service at %s: %s\n",
                sock_path, strerror(errno));
        fprintf(stderr,
                "[ob-cert-request] is ob-cert.socket enabled? (re-run ob-bastion-setup)\n");
        close(fd);
        return 1;
    }

    /* Forward the request, then half-close so the daemon sees EOF and replies. */
    if (copy_all(STDIN_FILENO, fd) < 0) {
        fprintf(stderr, "[ob-cert-request] failed sending request: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    if (shutdown(fd, SHUT_WR) < 0) {
        fprintf(stderr, "[ob-cert-request] shutdown(): %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    /* Relay the JSON response. */
    if (copy_all(fd, STDOUT_FILENO) < 0) {
        fprintf(stderr, "[ob-cert-request] failed reading response: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
