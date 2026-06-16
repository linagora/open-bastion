/*
 * test_ob_cert_proto.c - unit tests for the bastion cert socket protocol
 *
 * Exercises the real ob_valid_* validators and ob_read_line (CRLF handling,
 * overflow, EOF) from src/ob_cert_proto.c.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ob_cert_proto.h"

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(cond, desc)                                                      \
    do {                                                                       \
        tests_run++;                                                           \
        if (cond) {                                                            \
            tests_passed++;                                                    \
            printf("  ok   %s\n", desc);                                       \
        } else {                                                               \
            printf("  FAIL %s\n", desc);                                       \
        }                                                                      \
    } while (0)

/* Feed `in` through a pipe and read one line with ob_read_line. */
static ssize_t read_one(const char *in, size_t in_len, char *buf, size_t cap)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -2;
    if (write(fds[1], in, in_len) != (ssize_t)in_len) {
        close(fds[0]);
        close(fds[1]);
        return -2;
    }
    close(fds[1]); /* EOF after the data */
    ssize_t r = ob_read_line(fds[0], buf, cap);
    close(fds[0]);
    return r;
}

int main(void)
{
    char buf[64];
    ssize_t r;

    printf("ob_valid_username:\n");
    CHECK(ob_valid_username("french"), "lowercase login accepted");
    CHECK(ob_valid_username("_svc-01.x"), "leading underscore + allowed chars");
    CHECK(!ob_valid_username(""), "empty rejected");
    CHECK(!ob_valid_username("Root"), "uppercase start rejected");
    CHECK(!ob_valid_username("a b"), "space rejected");
    CHECK(!ob_valid_username("a/b"), "slash rejected (passwd injection)");

    printf("ob_valid_host:\n");
    CHECK(ob_valid_host("backend-01.op.com"), "fqdn accepted");
    CHECK(ob_valid_host("[fe80::1]"), "bracketed ipv6 accepted");
    CHECK(!ob_valid_host("-oProxyCommand=x"), "leading dash rejected (option injection)");
    CHECK(!ob_valid_host("a b"), "space rejected");
    CHECK(!ob_valid_host(""), "empty rejected");

    printf("ob_valid_group:\n");
    CHECK(ob_valid_group("secnumcloud"), "group accepted");
    CHECK(!ob_valid_group("bad grp"), "space rejected");
    CHECK(!ob_valid_group(""), "empty rejected");

    printf("ob_valid_pubkey:\n");
    CHECK(ob_valid_pubkey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc comment"),
          "ed25519 key accepted");
    CHECK(ob_valid_pubkey("ecdsa-sha2-nistp256 AAAAE2VjZHNh"), "ecdsa accepted");
    CHECK(!ob_valid_pubkey("not-a-key AAAA"), "missing prefix rejected");
    CHECK(!ob_valid_pubkey("ssh-ed25519 AAAA\nmalicious"), "embedded newline rejected");

    printf("ob_read_line:\n");
    r = read_one("hello\n", 6, buf, sizeof(buf));
    CHECK(r == 5 && strcmp(buf, "hello") == 0, "plain LF line");
    r = read_one("hello\r\n", 7, buf, sizeof(buf));
    CHECK(r == 5 && strcmp(buf, "hello") == 0, "trailing CR stripped (CRLF)");
    r = read_one("\n", 1, buf, sizeof(buf));
    CHECK(r == 0 && buf[0] == '\0', "empty line");
    r = read_one("noeol", 5, buf, sizeof(buf));
    CHECK(r == 5 && strcmp(buf, "noeol") == 0, "EOF without newline returns data");
    r = read_one("", 0, buf, sizeof(buf));
    CHECK(r == 0, "clean EOF returns 0");
    {
        char small[8];
        /* 8 non-newline bytes then newline: exceeds cap-1 (7) -> overflow */
        r = read_one("AAAAAAAA\n", 9, small, sizeof(small));
        CHECK(r == -1, "line longer than buffer rejected (overflow)");
    }

    printf("\n%d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
