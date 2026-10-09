/*
 * ob-verify-response - verify a signed portal answer for the shell callers
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 *
 * ob-heartbeat, ob-bastion-id and ob-session-monitor are shell, and their
 * answers deserve the same check as the PAM and NSS modules' (#339). This is
 * the verifier those modules use (ob_jws.c), behind a command line, the same
 * way ob-sign-request puts ob_sign.c behind one.
 *
 *   ob-verify-response verify --jwks FILE --issuer ISS --endpoint NAME
 *                             --nonce NONCE --http-status CODE
 *                             --body-file FILE [--audience CLIENT_ID]
 *                             [--token-file FILE] [--jwks-out FILE]
 *                             [--skew SECONDS]
 *   ob-verify-response check-jwks [--anchor] [--quiet] FILE
 *   ob-verify-response nonce
 *
 * Nothing secret goes on the command line: the request body (ob-heartbeat's
 * carries the host's refresh_token) is read from a file -- a pipe, through
 * bash's process substitution -- and the answer (it carries the new access
 * token) from standard input. What is on argv (issuer, client_id, endpoint,
 * the nonce, a status) is sent over the wire or published by the portal.
 *
 * Exit status of `verify`:
 *   0  verified, and the answer names this client (`aud`); `resp` on stdout
 *   4  verified, but the answer carries no `aud`: it may refuse, never grant
 *   1  the answer does not verify (diagnostic on stderr, nothing on stdout)
 *   3  the JWKS file is missing, unsafe or has no usable key
 *   2  usage error
 * check-jwks: 0 at least one usable key, 1 none / unreadable, 2 usage.
 * nonce: 0, or 1 when no nonce could be generated.
 *
 * Nothing is written to stderr on success, so a caller may capture `2>&1`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <json-c/json.h>
#include <openssl/evp.h>

#include "ob_jws.h"
#include "ob_sign.h"

#define PROG "ob-verify-response"

#define EXIT_VERIFIED   0
#define EXIT_REFUSED    1
#define EXIT_USAGE      2
#define EXIT_NO_JWKS    3
#define EXIT_ANONYMOUS  4

/* The largest request body a shell caller sends is ob-heartbeat's session
 * report, orders below this; same bound as ob-sign-request. */
#define MAX_BODY  (1024 * 1024)
/* The answer is at most OB_JWS_MAX_TOKEN; read a little more so that an
 * oversized one is reported as such rather than truncated into garbage. */
#define MAX_TOKEN (OB_JWS_MAX_TOKEN + 1024)
/* Same bound as ob_jws.c's own JWKS limit. */
#define MAX_JWKS  (256 * 1024)
/* ob_jws.c ignores the keys past its 64th. */
#define OB_JWS_MAX_KEYS_LISTED 64

static void usage(FILE *out)
{
    fprintf(out,
        "Usage:\n"
        "  " PROG " verify --jwks FILE --issuer ISS --endpoint NAME --nonce NONCE\n"
        "                     --http-status CODE --body-file FILE\n"
        "                     [--audience CLIENT_ID] [--token-file FILE]\n"
        "                     [--jwks-out FILE] [--skew SECONDS]\n"
        "  " PROG " check-jwks [--anchor] [--quiet] FILE|-\n"
        "  " PROG " nonce\n"
        "\n"
        "verify reads the signed answer on stdin (or --token-file) and prints\n"
        "its `resp` object. Exit 0 verified, 4 verified without `aud` (may\n"
        "only refuse), 1 refused, 3 no usable JWKS, 2 usage.\n");
}

/*
 * Read a whole file ("-" is stdin) into a NUL-terminated buffer. Returns NULL
 * with a diagnostic on stderr on error or when it is larger than max.
 */
static char *read_all(const char *path, size_t max, size_t *len)
{
    const int is_stdin = strcmp(path, "-") == 0;
    const char *what = is_stdin ? "standard input" : path;
    int fd = STDIN_FILENO;
    if (!is_stdin) {
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, PROG ": cannot open %s: %s\n", path, strerror(errno));
            return NULL;
        }
    }

    size_t cap = 8192, used = 0;
    char *buf = malloc(cap + 1);
    while (buf) {
        if (used == cap) {
            if (cap >= max) {
                fprintf(stderr, PROG ": %s is larger than %zu bytes\n", what, max);
                goto fail;
            }
            size_t ncap = cap * 2 > max ? max : cap * 2;
            char *nbuf = realloc(buf, ncap + 1);
            if (!nbuf) break;
            buf = nbuf;
            cap = ncap;
        }
        ssize_t n = read(fd, buf + used, cap - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, PROG ": read error on %s: %s\n", what, strerror(errno));
            goto fail;
        }
        if (n == 0) {
            if (!is_stdin) close(fd);
            buf[used] = '\0';
            *len = used;
            return buf;
        }
        used += (size_t)n;
    }
    fprintf(stderr, PROG ": out of memory\n");

fail:
    free(buf);
    if (!is_stdin) close(fd);
    return NULL;
}

static int parse_long(const char *s, long min, long max, long *out)
{
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !end || *end || v < min || v > max) return -1;
    *out = v;
    return 0;
}

/* Write the `jwks` claim, compact, to path (created 0600, truncated). */
static int write_jwks(const char *path, struct json_object *jwks)
{
    const char *s = json_object_to_json_string_ext(jwks,
                        JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!s) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, PROG ": cannot write %s: %s\n", path, strerror(errno));
        return -1;
    }
    size_t len = strlen(s), off = 0;
    while (off < len) {
        ssize_t n = write(fd, s + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            fprintf(stderr, PROG ": cannot write %s: %s\n", path, strerror(errno));
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    if (write(fd, "\n", 1) != 1 || close(fd) != 0) {
        fprintf(stderr, PROG ": cannot write %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* ── verify ─────────────────────────────────────────────────────────────── */

static int cmd_verify(int argc, char **argv)
{
    const char *jwks = NULL, *issuer = NULL, *audience = NULL, *endpoint = NULL;
    const char *nonce = NULL, *status_s = NULL, *body_file = NULL;
    const char *token_file = "-", *jwks_out = NULL, *skew_s = NULL;

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        const char **dst = NULL;
        if (strcmp(a, "--jwks") == 0) dst = &jwks;
        else if (strcmp(a, "--issuer") == 0) dst = &issuer;
        else if (strcmp(a, "--audience") == 0) dst = &audience;
        else if (strcmp(a, "--endpoint") == 0) dst = &endpoint;
        else if (strcmp(a, "--nonce") == 0) dst = &nonce;
        else if (strcmp(a, "--http-status") == 0) dst = &status_s;
        else if (strcmp(a, "--body-file") == 0) dst = &body_file;
        else if (strcmp(a, "--token-file") == 0) dst = &token_file;
        else if (strcmp(a, "--jwks-out") == 0) dst = &jwks_out;
        else if (strcmp(a, "--skew") == 0) dst = &skew_s;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        }
        if (!dst || i + 1 >= argc) {
            fprintf(stderr, PROG ": verify: unexpected argument '%s'\n", a);
            usage(stderr);
            return EXIT_USAGE;
        }
        *dst = argv[++i];
    }

    long status = 0, skew = OB_JWS_DEFAULT_SKEW;
    const char *missing = !jwks ? "--jwks" : !issuer ? "--issuer"
                        : !endpoint ? "--endpoint" : !nonce ? "--nonce"
                        : !status_s ? "--http-status" : !body_file ? "--body-file"
                        : NULL;
    if (missing) {
        fprintf(stderr, PROG ": verify: %s is required\n", missing);
        return EXIT_USAGE;
    }
    if (!*issuer || !*endpoint || !*nonce) {
        fprintf(stderr, PROG ": verify: --issuer, --endpoint and --nonce must not be empty\n");
        return EXIT_USAGE;
    }
    if (audience && !*audience) {
        audience = NULL;  /* "no client_id configured": refuse any `aud` */
    }
    if (parse_long(status_s, 100, 599, &status) != 0) {
        fprintf(stderr, PROG ": verify: --http-status must be an HTTP status (100-599)\n");
        return EXIT_USAGE;
    }
    if (skew_s && parse_long(skew_s, 0, 3600, &skew) != 0) {
        fprintf(stderr, PROG ": verify: --skew must be 0..3600 seconds\n");
        return EXIT_USAGE;
    }
    if (strcmp(body_file, "-") == 0 && strcmp(token_file, "-") == 0) {
        fprintf(stderr, PROG ": verify: the body and the answer cannot both be on stdin\n");
        return EXIT_USAGE;
    }

    char err[256];
    ob_jws_keyset_t *ks = ob_jws_keyset_load(jwks, err, sizeof(err));
    if (!ks) {
        fprintf(stderr, PROG ": no usable JWKS: %s\n", err);
        return EXIT_NO_JWKS;
    }

    int rc = EXIT_REFUSED;
    size_t body_len = 0, token_len = 0;
    char *body = read_all(body_file, MAX_BODY, &body_len);
    char *token = body ? read_all(token_file, MAX_TOKEN, &token_len) : NULL;
    if (!body || !token) {
        goto out;
    }
    /* What curl received, which may end with a newline. */
    while (token_len > 0 && (token[token_len - 1] == '\n' || token[token_len - 1] == '\r'
                             || token[token_len - 1] == ' ' || token[token_len - 1] == '\t')) {
        token[--token_len] = '\0';
    }

    ob_jws_expect_t expect = {
        .issuer = issuer,
        .audience = audience,
        .endpoint = endpoint,
        .nonce = nonce,
        .body = body,
        .body_len = body_len,
        .now = time(NULL),
        .skew = (int)skew,
    };
    ob_jws_answer_t answer;
    if (ob_jws_verify_answer(ks, token, token_len, &expect, &answer,
                             err, sizeof(err)) != 0) {
        fprintf(stderr, PROG ": signed answer to %s rejected: %s\n", endpoint, err);
        goto out;
    }
    if (answer.http_status != status) {
        fprintf(stderr, PROG ": signed answer to %s rejected: HTTP %ld but signed "
                "for %ld\n", endpoint, status, answer.http_status);
        ob_jws_answer_free(&answer);
        goto out;
    }

    /* The key set travels only with an answer addressed to this client. */
    if (jwks_out && answer.has_aud && answer.jwks
        && write_jwks(jwks_out, answer.jwks) != 0) {
        ob_jws_answer_free(&answer);
        goto out;
    }

    const char *plain = json_object_to_json_string_ext(answer.resp,
                            JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!plain || printf("%s\n", plain) < 0 || fflush(stdout) != 0) {
        fprintf(stderr, PROG ": cannot write the answer\n");
        ob_jws_answer_free(&answer);
        goto out;
    }
    rc = answer.has_aud ? EXIT_VERIFIED : EXIT_ANONYMOUS;
    ob_jws_answer_free(&answer);

out:
    if (body) {
        explicit_bzero(body, body_len);
        free(body);
    }
    if (token) {
        explicit_bzero(token, token_len);
        free(token);
    }
    ob_jws_keyset_free(ks);
    return rc;
}

/* ── check-jwks ─────────────────────────────────────────────────────────── */

static const char *jwk_string(struct json_object *jwk, const char *key)
{
    struct json_object *v;
    if (!json_object_object_get_ex(jwk, key, &v)
        || !json_object_is_type(v, json_type_string)) {
        return NULL;
    }
    return json_object_get_string(v);
}

/* Safe to embed in the RFC 7638 JSON as is: printable, no quote or escape. */
static int plain_member(const char *s)
{
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x21 || *p > 0x7e || *p == '"' || *p == '\\') return 0;
    }
    return 1;
}

static void b64url(const unsigned char *in, size_t len, char *out)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0, i = 0;
    for (; i + 2 < len; i += 3) {
        unsigned v = (unsigned)in[i] << 16 | (unsigned)in[i + 1] << 8 | in[i + 2];
        out[o++] = tbl[v >> 18 & 63];
        out[o++] = tbl[v >> 12 & 63];
        out[o++] = tbl[v >> 6 & 63];
        out[o++] = tbl[v & 63];
    }
    if (len - i == 1) {
        unsigned v = (unsigned)in[i] << 16;
        out[o++] = tbl[v >> 18 & 63];
        out[o++] = tbl[v >> 12 & 63];
    } else if (len - i == 2) {
        unsigned v = (unsigned)in[i] << 16 | (unsigned)in[i + 1] << 8;
        out[o++] = tbl[v >> 18 & 63];
        out[o++] = tbl[v >> 12 & 63];
        out[o++] = tbl[v >> 6 & 63];
    }
    out[o] = '\0';
}

#define THUMB_LEN 44  /* base64url of 32 bytes, unpadded: 43, + NUL */

/*
 * RFC 7638 thumbprint: SHA-256 of the required members, in lexicographic
 * order, without whitespace. Independent of member order, of `kid`, `alg` or
 * `use`, and of how the JWKS was formatted.
 */
static int jwk_thumbprint(struct json_object *jwk, char out[THUMB_LEN])
{
    const char *kty = jwk_string(jwk, "kty");
    char canon[4096];
    int n;

    if (!kty) return -1;
    if (strcmp(kty, "RSA") == 0) {
        const char *e = jwk_string(jwk, "e"), *nn = jwk_string(jwk, "n");
        if (!plain_member(e) || !plain_member(nn)) return -1;
        n = snprintf(canon, sizeof(canon), "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}", e, nn);
    } else if (strcmp(kty, "EC") == 0) {
        const char *crv = jwk_string(jwk, "crv"), *x = jwk_string(jwk, "x"),
                   *y = jwk_string(jwk, "y");
        if (!plain_member(crv) || !plain_member(x) || !plain_member(y)) return -1;
        n = snprintf(canon, sizeof(canon),
                     "{\"crv\":\"%s\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", crv, x, y);
    } else if (strcmp(kty, "OKP") == 0) {
        const char *crv = jwk_string(jwk, "crv"), *x = jwk_string(jwk, "x");
        if (!plain_member(crv) || !plain_member(x)) return -1;
        n = snprintf(canon, sizeof(canon), "{\"crv\":\"%s\",\"kty\":\"OKP\",\"x\":\"%s\"}", crv, x);
    } else {
        return -1;
    }
    if (n < 0 || (size_t)n >= sizeof(canon)) return -1;

    unsigned char md[32];
    unsigned int mdlen = 0;
    if (EVP_Digest(canon, (size_t)n, md, &mdlen, EVP_sha256(), NULL) != 1 || mdlen != 32) {
        return -1;
    }
    b64url(md, 32, out);
    return 0;
}

/* Would ob_jws accept this one key on its own? */
static int jwk_usable(struct json_object *jwk)
{
    const char *s = json_object_to_json_string_ext(jwk, JSON_C_TO_STRING_PLAIN);
    if (!s) return 0;
    size_t len = strlen(s) + 16;
    char *doc = malloc(len);
    if (!doc) return 0;
    snprintf(doc, len, "{\"keys\":[%s]}", s);
    ob_jws_keyset_t *ks = ob_jws_keyset_parse(doc, strlen(doc), NULL, 0);
    free(doc);
    int ok = ks != NULL;
    ob_jws_keyset_free(ks);
    return ok;
}

/* A kid, printable on one line whatever it contains. */
static void print_kid(const char *kid)
{
    for (const unsigned char *p = (const unsigned char *)kid; *p; p++) {
        putchar(*p >= 0x21 && *p <= 0x7e ? *p : '?');
    }
}

typedef struct {
    char thumb[THUMB_LEN];
    const char *kid;
} usable_key_t;

static int cmp_thumb(const void *a, const void *b)
{
    return strcmp(((const usable_key_t *)a)->thumb, ((const usable_key_t *)b)->thumb);
}

static int cmd_check_jwks(int argc, char **argv)
{
    int anchor = 0, quiet = 0;
    const char *path = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--anchor") == 0) {
            anchor = 1;
        } else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (!path && (argv[i][0] != '-' || strcmp(argv[i], "-") == 0)) {
            path = argv[i];
        } else {
            fprintf(stderr, PROG ": check-jwks: unexpected argument '%s'\n", argv[i]);
            return EXIT_USAGE;
        }
    }
    if (!path) {
        fprintf(stderr, PROG ": check-jwks: a JWKS file is required\n");
        return EXIT_USAGE;
    }
    if (anchor && strcmp(path, "-") == 0) {
        fprintf(stderr, PROG ": check-jwks: --anchor needs a file, not stdin\n");
        return EXIT_USAGE;
    }

    char err[256];
    size_t count;
    if (anchor) {
        /* Exactly what the PAM and NSS modules will do with the file. */
        ob_jws_keyset_t *ks = ob_jws_keyset_load(path, err, sizeof(err));
        if (!ks) {
            fprintf(stderr, PROG ": %s\n", err);
            return EXIT_REFUSED;
        }
        ob_jws_keyset_free(ks);
    }

    size_t len = 0;
    char *buf = read_all(path, MAX_JWKS, &len);
    if (!buf) {
        return EXIT_REFUSED;
    }
    ob_jws_keyset_t *ks = ob_jws_keyset_parse(buf, len, err, sizeof(err));
    if (!ks) {
        fprintf(stderr, PROG ": %s: %s\n", strcmp(path, "-") == 0 ? "stdin" : path, err);
        free(buf);
        return EXIT_REFUSED;
    }
    count = ob_jws_keyset_size(ks);
    ob_jws_keyset_free(ks);

    /* Parsed once more, for what the key set does not expose. */
    struct json_object *doc = json_tokener_parse(buf), *keys = NULL;
    free(buf);
    if (!doc || !json_object_object_get_ex(doc, "keys", &keys)
        || !json_object_is_type(keys, json_type_array)) {
        json_object_put(doc);
        fprintf(stderr, PROG ": cannot list the keys of %s\n", path);
        return EXIT_REFUSED;
    }

    size_t n = json_object_array_length(keys);
    if (n > OB_JWS_MAX_KEYS_LISTED) {
        n = OB_JWS_MAX_KEYS_LISTED;  /* ob_jws reads no further either */
    }
    usable_key_t *list = calloc(n ? n : 1, sizeof(*list));
    size_t m = 0;
    if (!list) {
        json_object_put(doc);
        fprintf(stderr, PROG ": out of memory\n");
        return EXIT_REFUSED;
    }
    for (size_t i = 0; i < n; i++) {
        struct json_object *jwk = json_object_array_get_idx(keys, i);
        if (!jwk || !json_object_is_type(jwk, json_type_object) || !jwk_usable(jwk)) {
            continue;
        }
        if (jwk_thumbprint(jwk, list[m].thumb) != 0) {
            continue;
        }
        list[m].kid = jwk_string(jwk, "kid");
        m++;
    }
    if (m == 0) {
        free(list);
        json_object_put(doc);
        fprintf(stderr, PROG ": %s: no usable signature key\n", path);
        return EXIT_REFUSED;
    }

    /* Listed by thumbprint, so that the output does not depend on the order
     * of the keys in the file. No fingerprint of the whole document here: that
     * one is the SHA-256 of `jq -S -c .`, computed where jq runs (ob-builder,
     * the setup scripts, ob-heartbeat), and bytes identical to jq's are not
     * something to reproduce in C. */
    qsort(list, m, sizeof(*list), cmp_thumb);

    if (!quiet) {
        printf("keys=%zu\n", count);
        for (size_t i = 0; i < m; i++) {
            printf("key=%s ", list[i].thumb);
            print_kid(list[i].kid ? list[i].kid : "");
            putchar('\n');
        }
    }
    free(list);
    json_object_put(doc);
    if (fflush(stdout) != 0) {
        fprintf(stderr, PROG ": cannot write: %s\n", strerror(errno));
        return EXIT_REFUSED;
    }
    return 0;
}

/* ── nonce ──────────────────────────────────────────────────────────────── */

static int cmd_nonce(int argc, char **argv)
{
    (void)argv;
    if (argc != 0) {
        fprintf(stderr, PROG ": nonce takes no argument\n");
        return EXIT_USAGE;
    }
    char nonce[OB_SIGN_NONCE_SIZE];
    ob_sign_generate_nonce(nonce, sizeof(nonce));
    /* ob_sign_generate_nonce falls back to a bare timestamp without a CSPRNG:
     * not good enough to bind an answer to. */
    if (!strchr(nonce, '-')) {
        fprintf(stderr, PROG ": cannot generate a nonce\n");
        return EXIT_REFUSED;
    }
    printf("%s\n", nonce);
    return fflush(stdout) == 0 ? 0 : EXIT_REFUSED;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return EXIT_USAGE;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "verify") == 0) {
        return cmd_verify(argc - 2, argv + 2);
    }
    if (strcmp(cmd, "check-jwks") == 0) {
        return cmd_check_jwks(argc - 2, argv + 2);
    }
    if (strcmp(cmd, "nonce") == 0) {
        return cmd_nonce(argc - 2, argv + 2);
    }
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage(stdout);
        return 0;
    }
    fprintf(stderr, PROG ": unknown command '%s'\n", cmd);
    usage(stderr);
    return EXIT_USAGE;
}
