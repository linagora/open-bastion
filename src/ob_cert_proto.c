/*
 * ob_cert_proto.c - request parsing/validation for the bastion cert socket
 *
 * See ob_cert_proto.h. Pure helpers (no globals, no logging) so ob-cert-daemon
 * and the unit test share exactly the same parsing/validation logic.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include "ob_cert_proto.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int ob_valid_username(const char *s)
{
    if (!s || !*s || strlen(s) > 32)
        return 0;
    if (!(islower((unsigned char)s[0]) || s[0] == '_'))
        return 0;
    for (const char *p = s + 1; *p; p++)
        if (!(islower((unsigned char)*p) || isdigit((unsigned char)*p) ||
              *p == '.' || *p == '_' || *p == '-'))
            return 0;
    return 1;
}

int ob_valid_host(const char *s)
{
    if (!s || !*s || strlen(s) > 255)
        return 0;
    if (s[0] == '-') /* never let it look like an ssh option */
        return 0;
    for (const char *p = s; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == ':' ||
              *p == '_' || *p == '-' || *p == '[' || *p == ']'))
            return 0;
    return 1;
}

int ob_valid_group(const char *s)
{
    if (!s || !*s || strlen(s) > 64)
        return 0;
    for (const char *p = s; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-'))
            return 0;
    return 1;
}

int ob_valid_pubkey(const char *s)
{
    if (!s || strlen(s) > 4096)
        return 0;
    if (strncmp(s, "ssh-", 4) != 0 && strncmp(s, "ecdsa-sha2-", 11) != 0)
        return 0;
    /* one-line, printable; the CA re-parses it server-side. */
    for (const char *p = s; *p; p++)
        if (*p == '\r' || *p == '\n' || !isprint((unsigned char)*p))
            return 0;
    return 1;
}

ssize_t ob_read_line(int fd, char *buf, size_t cap)
{
    size_t i = 0;
    while (i < cap - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break; /* EOF */
        if (c == '\n') {
            if (i > 0 && buf[i - 1] == '\r') /* tolerate CRLF clients */
                i--;
            buf[i] = '\0';
            return (ssize_t)i;
        }
        buf[i++] = c;
    }
    if (i >= cap - 1)
        return -1; /* line too long */
    buf[i] = '\0';
    return (ssize_t)i;
}
