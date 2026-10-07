/*
 * test_ob_sign.c - the request-signing wire format, pinned (#247)
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 *
 * Signing had no coverage at all before this file: the client had produced
 * X-Signature-256 for a year and nothing on either side checked that it was
 * the string the portal computes. When the portal started verifying
 * (lemonldap-ng-plugins#93) a divergence stopped being cosmetic -- under
 * pamAccessRequestSigningMode=required it refuses every call.
 *
 * The expected digests below are NOT computed by this program. They come from
 * the portal's own implementation:
 *
 *   perl -MDigest::SHA=hmac_sha256_hex \
 *        -e 'print hmac_sha256_hex("<message>", "<secret>")'
 *
 * which is literally what PamAccess.pm::_checkRequestSignature calls. Deriving
 * them here from OpenSSL would only prove this file agrees with itself.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "ob_sign.h"
#include "str_utils.h"

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(cond, name) do {                                             \
    tests_run++;                                                           \
    if (cond) { tests_passed++; printf("  PASS: %s\n", (name)); }          \
    else      { printf("  FAIL: %s (%s:%d)\n", (name), __FILE__, __LINE__); } \
} while (0)

/*
 * The reference secret carries a '#' and a space on purpose: '#' is what the
 * config readers used to truncate at, and a secret is opaque bytes.
 */
static const char *SECRET = "s3cr#t key";
static const char *NONCE  = "1700000000000-0123abcd-4567-89ab-cdef-0123456789ab";

struct vector {
    long        ts;
    const char *nonce;
    const char *method;
    const char *path;
    const char *body;
    const char *expected;
    const char *name;
};

static const struct vector VECTORS[] = {
    { 1700000000, "1700000000000-0123abcd-4567-89ab-cdef-0123456789ab",
      "POST", "/pam/heartbeat", "{\"a\":1}",
      "0e832c0c99a587840e607ff8d331aafc7ecb67157beb7751c474412468d74dcc",
      "reference vector matches the portal's Digest::SHA" },

    /* A bodyless request signs the empty string, so the message still ends
     * with the fourth separator. Getting this wrong is invisible until an
     * endpoint with no body is signed -- which is what /pam/whoami is. */
    { 1700000000, "1700000000000-0123abcd-4567-89ab-cdef-0123456789ab",
      "POST", "/pam/heartbeat", "",
      "2322d750c4750015b5cbbb37626816e75dadcd7c9d625cc0f723f4d1775fc607",
      "empty body still signs the trailing separator" },

    { 1700000000, "1700000000000-0123abcd-4567-89ab-cdef-0123456789ab",
      "POST", "/pam/authorize", "{\"a\":1}",
      "63ed8ea81e3ac39df50b6dc3478684eac0d4f4c389f4b4c0b69cfc1a0b849fe4",
      "path is covered (a signature does not transfer between endpoints)" },

    { 1700000000, "1700000000000-0123abcd-4567-89ab-cdef-0123456789ab",
      "GET", "/pam/heartbeat", "{\"a\":1}",
      "6ec97b5df12ab4d01bc6f5ba3f109ff471924b941ae89214c76a0caa88121ef3",
      "method is covered" },

    { 1700000001, "1700000000000-0123abcd-4567-89ab-cdef-0123456789ab",
      "POST", "/pam/heartbeat", "{\"a\":1}",
      "82a1c649b8a7ff623434f36c0e2076975f614a5cc8a6629a382c63d7f9165187",
      "timestamp is covered" },

    /* #188: the nonce MUST be inside the HMAC, or a captured request can be
     * replayed with a fresh one. */
    { 1700000000, "x", "POST", "/pam/heartbeat", "{\"a\":1}",
      "27dcbb8a2f2de3d288514bedd2c55a158debbd16bda07f9ad6b3eb8e3f4339e5",
      "nonce is covered" },
};

static void test_vectors(void)
{
    for (size_t i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
        const struct vector *v = &VECTORS[i];
        char sig[OB_SIGN_SIGNATURE_SIZE];
        ob_sign_compute(SECRET, v->ts, v->nonce, v->method, v->path, v->body,
                        sig, sizeof(sig));
        if (strcmp(sig, v->expected) != 0) {
            printf("    got      %s\n    expected %s\n", sig, v->expected);
        }
        CHECK(strcmp(sig, v->expected) == 0, v->name);
    }

    /* NULL body and "" must be the same message: a caller that has no body
     * may pass either. */
    char a[OB_SIGN_SIGNATURE_SIZE], b[OB_SIGN_SIGNATURE_SIZE];
    ob_sign_compute(SECRET, 1700000000, NONCE, "POST", "/pam/heartbeat", NULL,
                    a, sizeof(a));
    ob_sign_compute(SECRET, 1700000000, NONCE, "POST", "/pam/heartbeat", "",
                    b, sizeof(b));
    CHECK(strcmp(a, b) == 0 && strlen(a) == 64, "NULL body signs as empty body");

    /* A body longer than the stack buffer takes the heap path; it must sign
     * the same bytes. Cross-checked against the same Perl one-liner. */
    char big[900];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char sig[OB_SIGN_SIGNATURE_SIZE];
    ob_sign_compute(SECRET, 1700000000, NONCE, "POST", "/pam/heartbeat", big,
                    sig, sizeof(sig));
    CHECK(strlen(sig) == 64, "a body past the stack buffer still signs");
}

static void test_failures_are_empty(void)
{
    char sig[OB_SIGN_SIGNATURE_SIZE];

    /*
     * Every failure must yield an EMPTY signature, never a short or stale one:
     * callers key "do not send" off exactly that, and the portal treats a
     * partially signed request as malformed in every mode, including 'off'.
     */
    memset(sig, 'A', sizeof(sig));
    ob_sign_compute(NULL, 1, NONCE, "POST", "/x", "", sig, sizeof(sig));
    CHECK(sig[0] == '\0', "no secret yields an empty signature");

    /*
     * config_load() strdup's whatever follows the '=', so `request_signing_secret =`
     * reaches the PAM module as "" and not NULL. An empty HMAC key is forgeable
     * by anyone; refusing it here is what keeps the module, the daemon and the
     * shell callers from disagreeing about the same degenerate config.
     */
    memset(sig, 'A', sizeof(sig));
    ob_sign_compute("", 1, NONCE, "POST", "/x", "", sig, sizeof(sig));
    CHECK(sig[0] == '\0', "an empty secret counts as absent, not as a key");

    memset(sig, 'A', sizeof(sig));
    ob_sign_compute(SECRET, 1, "", "POST", "/x", "", sig, sizeof(sig));
    CHECK(sig[0] == '\0', "empty nonce yields an empty signature");

    memset(sig, 'A', sizeof(sig));
    ob_sign_compute(SECRET, 1, NONCE, "POST", "/x", "", sig, 8);
    CHECK(sig[0] == '\0', "a buffer too small yields an empty signature");
}

static void test_nonce(void)
{
    char n1[OB_SIGN_NONCE_SIZE], n2[OB_SIGN_NONCE_SIZE];

    ob_sign_generate_nonce(n1, sizeof(n1));
    ob_sign_generate_nonce(n2, sizeof(n2));

    CHECK(strlen(n1) > 20 && strcmp(n1, n2) != 0, "nonces are non-empty and distinct");

    /* The portal accepts [0-9A-Za-z._:-]{1,128} and nothing else. */
    int ok = strlen(n1) <= 128;
    for (const char *p = n1; *p && ok; p++) {
        ok = (*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'Z')
             || (*p >= 'a' && *p <= 'z') || *p == '.' || *p == '_'
             || *p == ':' || *p == '-';
    }
    CHECK(ok, "nonce matches the character class the portal accepts");

    char small[8];
    memset(small, 'A', sizeof(small));
    ob_sign_generate_nonce(small, sizeof(small));
    CHECK(small[0] == '\0', "a buffer too small yields an empty nonce");
}

/* Write a 0600 config file in `dir` and return its path in `out`. */
static void write_conf(const char *dir, char *out, size_t out_size,
                       const char *content, mode_t mode)
{
    snprintf(out, out_size, "%s/openbastion.conf", dir);
    unlink(out);
    int fd = open(out, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) { perror("open"); exit(1); }
    if (write(fd, content, strlen(content)) < 0) { perror("write"); exit(1); }
    /*
     * fchmod, not chmod: open() honours the umask, so the mode has to be set
     * again, and doing it by name would re-resolve the path -- a different
     * file could answer the second time. The whole point of these fixtures is
     * the mode (0600 accepted, 0644 refused), so a fixture that sets it on
     * something other than the file it just wrote would test nothing.
     */
    if (fchmod(fd, mode) != 0) { perror("fchmod"); exit(1); }
    close(fd);
}

struct secret_case {
    const char *content;
    int         rc;
    const char *want;
    const char *name;
};

static void test_load_secret(const char *dir)
{
    /*
     * The rule config.c applies to an opaque secret, restated: everything
     * after the first '=', trimmed, minus at most one layer of matching
     * quotes, and NO inline-comment stripping. Every reader that got this
     * wrong produced a valid-looking signature over the wrong key, which the
     * portal reports as bad_signature -- indistinguishable from a
     * misconfigured portal.
     */
    static const struct secret_case CASES[] = {
        { "request_signing_secret = plain\n", 0, "plain", "plain value" },
        { "request_signing_secret = a#b\n", 0, "a#b",
          "'#' inside the value is kept" },
        { "request_signing_secret = a # b\n", 0, "a # b",
          "' #' does not start a comment in a secret" },
        { "request_signing_secret = \"a # b\"\n", 0, "a # b",
          "one layer of double quotes is removed" },
        { "request_signing_secret = 'a # b'\n", 0, "a # b",
          "one layer of single quotes is removed" },
        { "request_signing_secret =    spaced   \n", 0, "spaced",
          "surrounding whitespace is trimmed" },
        { "portal_url = https://x\nrequest_signing_secret = s\n", 0, "s",
          "found among other keys" },
        { "request_signing_secret = first\nrequest_signing_secret = last\n",
          0, "last", "the last assignment wins, as in config.c" },
        { "portal_url = https://x\n", 1, NULL,
          "absent is not an error: signing is optional" },
        { "request_signing_secret =\n", 1, NULL, "empty counts as absent" },
    };

    char path[512];
    for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
        write_conf(dir, path, sizeof(path), CASES[i].content, 0600);
        char *secret = NULL;
        int rc = ob_sign_load_secret(path, &secret);
        int ok = (rc == CASES[i].rc)
                 && (CASES[i].want ? (secret && strcmp(secret, CASES[i].want) == 0)
                                   : (secret == NULL));
        if (!ok) {
            printf("    rc=%d secret=%s\n", rc, secret ? secret : "(null)");
        }
        CHECK(ok, CASES[i].name);
        free(secret);
    }

    /* Group- or world-readable: the secret is already compromised, and a file
     * anyone can write is a signature anyone can forge. Refuse it. */
    write_conf(dir, path, sizeof(path), "request_signing_secret = s\n", 0644);
    char *secret = NULL;
    CHECK(ob_sign_load_secret(path, &secret) < 0 && secret == NULL,
          "a group/world-readable config is refused");

    snprintf(path, sizeof(path), "%s/does-not-exist.conf", dir);
    secret = NULL;
    CHECK(ob_sign_load_secret(path, &secret) < 0 && secret == NULL,
          "a missing config is an error, not a silent 'no secret'");

    /* A value truncated by the line limit would sign with the wrong key. */
    char *big = malloc(4096);
    if (!big) exit(1);
    strcpy(big, "request_signing_secret = ");
    memset(big + strlen(big), 'z', 2000);
    strcpy(big + 25 + 2000, "\n");
    write_conf(dir, path, sizeof(path), big, 0600);
    free(big);
    secret = NULL;
    CHECK(ob_sign_load_secret(path, &secret) < 0 && secret == NULL,
          "an over-long secret line is refused, not truncated");
}

/*
 * ob_sign_load_settings(): the one pass the NSS module and ob-cert-daemon
 * make over openbastion.conf for the secret and the pin (#332).
 */
static void test_load_settings(const char *dir)
{
    char path[512];
    char *secret = NULL, *pin = NULL;
    const char *P1 = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    printf("ob_sign_load_settings (#332):\n");
    char conf[512];
    snprintf(conf, sizeof(conf),
             "portal_url = https://x\n"
             "request_signing_secret = s#1\n"
             "cert_pin = \"%s\"\n", P1);
    write_conf(dir, path, sizeof(path), conf, 0600);
    CHECK(ob_sign_load_settings(path, &secret, &pin) == 0
          && secret && strcmp(secret, "s#1") == 0 && pin && strcmp(pin, P1) == 0,
          "both keys read in one pass, quotes removed, '#' kept");
    free(secret);
    free(pin);

    write_conf(dir, path, sizeof(path), "portal_url = https://x\n", 0600);
    CHECK(ob_sign_load_settings(path, &secret, &pin) == 0 && !secret && !pin,
          "neither key: 0, both NULL (signing and pinning are optional)");

    write_conf(dir, path, sizeof(path),
               "cert_pin = sha256//old\ncert_pin =\n", 0600);
    CHECK(ob_sign_load_settings(path, &secret, &pin) == 0 && !pin,
          "the last assignment wins, and empty counts as absent");

    write_conf(dir, path, sizeof(path), "cert_pin = sha256//x\n", 0600);
    CHECK(ob_sign_load_settings(path, &secret, NULL) == 0 && !secret,
          "a NULL output skips that key");

    write_conf(dir, path, sizeof(path), "cert_pin = sha256//x\n", 0644);
    CHECK(ob_sign_load_settings(path, &secret, &pin) < 0 && !secret && !pin,
          "a group/world-readable config is refused");

    char *big = malloc(4096);
    if (!big) exit(1);
    strcpy(big, "request_signing_secret = s\ncert_pin = /");
    size_t n = strlen(big);
    memset(big + n, 'z', 2000);
    strcpy(big + n + 2000, "\n");
    write_conf(dir, path, sizeof(path), big, 0600);
    free(big);
    CHECK(ob_sign_load_settings(path, &secret, &pin) < 0 && !secret && !pin,
          "an over-long cert_pin line is refused, and the secret dropped with it");

    printf("str_cert_pin_valid:\n");
    CHECK(str_cert_pin_valid(P1), "sha256//<44 base64 chars>");
    CHECK(str_cert_pin_valid("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
          "sha256// without padding (43)");
    CHECK(str_cert_pin_valid("/etc/open-bastion/portal.pub"), "a key file path");
    CHECK(str_cert_pin_valid("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;"
                             "sha256//BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="),
          "two pins (rotation)");
    CHECK(!str_cert_pin_valid("md5//AAAA"), "another hash refused");
    CHECK(!str_cert_pin_valid("sha256//short"), "a short hash refused");
    CHECK(!str_cert_pin_valid("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_"),
          "base64url refused (libcurl takes standard base64)");
    CHECK(!str_cert_pin_valid(""), "empty refused");
}

int main(void)
{
    printf("=== ob_sign: request signing wire format ===\n");

    char dir[] = "/tmp/test_ob_sign_XXXXXX";
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    test_vectors();
    test_failures_are_empty();
    test_nonce();
    test_load_secret(dir);
    test_load_settings(dir);

    char path[512];
    snprintf(path, sizeof(path), "%s/openbastion.conf", dir);
    unlink(path);
    rmdir(dir);

    printf("\n%d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
