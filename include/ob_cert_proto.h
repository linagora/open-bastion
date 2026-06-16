/*
 * ob_cert_proto.h - request parsing/validation for the bastion cert socket
 *
 * Shared by ob-cert-daemon and its unit test. These are the pure, side-effect-
 * free helpers that validate the untrusted request fields and read the
 * newline-delimited protocol, kept separate so they can be tested in isolation.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */
#ifndef OB_CERT_PROTO_H
#define OB_CERT_PROTO_H

#include <sys/types.h> /* ssize_t */
#include <stddef.h>    /* size_t */

/* Field validators (return 1 if acceptable, 0 otherwise). Bounds mirror the
 * per-field request limits enforced by the daemon. */
int ob_valid_username(const char *s);
int ob_valid_host(const char *s);
int ob_valid_group(const char *s);
int ob_valid_pubkey(const char *s);

/* Read one '\n'-terminated line from fd into buf (NUL-terminated, a trailing
 * '\r' and the '\n' stripped). Returns the line length, 0 on clean EOF before
 * any byte, -1 on read error or overflow (line longer than cap-1). */
ssize_t ob_read_line(int fd, char *buf, size_t cap);

#endif /* OB_CERT_PROTO_H */
