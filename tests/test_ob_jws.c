/*
 * test_ob_jws.c - The verifier of the portal's signed answers (src/ob_jws.c).
 *
 * The tokens are produced here with OpenSSL, the way the portal's createJWT
 * produces them, and every check of ob_jws_verify_answer() is driven to fail
 * on its own: a verifier that skips one still passes the "valid" cases.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <json-c/json.h>

#include "ob_jws.h"
#include "jws_test_util.h"

static int tests_run;
static int tests_passed;

#define CHECK(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  ok   %s\n", (msg)); \
    } else { \
        printf("  FAIL %s\n", (msg)); \
    } \
} while (0)

#define ISSUER   "https://auth.example.com"
#define CLIENT   "bastion-prod"
#define NONCE    "1790000000000-0f8b2c1e-1d2a-4c3b-9e8f-7a6b5c4d3e2f"
#define REQ_BODY "{\"token\":\"otp\",\"fingerprint\":\"SHA256:abc\"}"

static EVP_PKEY *k_rsa, *k_rsa_other, *k_p256, *k_p384, *k_p521, *k_ed;
static ob_jws_keyset_t *g_ks;
static time_t g_now;

/* The claims the portal would sign for REQ_BODY/NONCE on /pam/verify. */
static struct json_object *claims(void)
{
    char sha[65];
    tj_sha256_hex(REQ_BODY, strlen(REQ_BODY), sha);
    struct json_object *c = json_object_new_object();
    json_object_object_add(c, "iss", json_object_new_string(ISSUER));
    json_object_object_add(c, "aud", json_object_new_string(CLIENT));
    json_object_object_add(c, "iat", json_object_new_int64(g_now));
    json_object_object_add(c, "exp", json_object_new_int64(g_now + 60));
    json_object_object_add(c, "endpoint", json_object_new_string("verify"));
    json_object_object_add(c, "req_nonce", json_object_new_string(NONCE));
    json_object_object_add(c, "req_sha256", json_object_new_string(sha));
    json_object_object_add(c, "http_status", json_object_new_int(200));
    json_object_object_add(c, "resp",
        json_tokener_parse("{\"valid\":true,\"user\":\"dwho\"}"));
    return c;
}

static ob_jws_expect_t expect(void)
{
    ob_jws_expect_t x = {
        .issuer = ISSUER,
        .audience = CLIENT,
        .endpoint = "verify",
        .nonce = NONCE,
        .body = REQ_BODY,
        .body_len = strlen(REQ_BODY),
        .now = g_now,
        .skew = OB_JWS_DEFAULT_SKEW,
    };
    return x;
}

/* Verify `token` against the default expectations; 0 on success. */
static int verify_x(const char *token, const ob_jws_expect_t *x,
                    ob_jws_answer_t *a, char *why, size_t whylen)
{
    return ob_jws_verify_answer(g_ks, token, strlen(token), x, a, why, whylen);
}

static char g_why[256];

static int verify(const char *token, ob_jws_answer_t *a)
{
    ob_jws_expect_t x = expect();
    g_why[0] = '\0';
    return verify_x(token, &x, a, g_why, sizeof(g_why));
}

/*
 * Expect a refusal, and for the reason named by `because` (a substring of
 * the error): a token refused by an earlier, unrelated check would prove
 * nothing about the one the case is about.
 */
static void refused_token(const char *t, const char *because, const char *msg)
{
    ob_jws_answer_t a;
    int rc = verify(t, &a);
    bool ok = rc != 0 && a.resp == NULL && strstr(g_why, because);
    if (!ok) {
        printf("       (rc=%d, error: %s)\n", rc, g_why);
    }
    CHECK(ok, msg);
    ob_jws_answer_free(&a);
}

/* Sign c with k and expect a refusal. Consumes c. */
static void refused(EVP_PKEY *k, const char *alg, const char *kid,
                    struct json_object *c, const char *because, const char *msg)
{
    char *t = tj_sign(k, alg, kid, json_object_to_json_string(c));
    refused_token(t, because, msg);
    json_object_put(c);
    free(t);
}

/* ── Key set ────────────────────────────────────────────────────────────── */

static void setup_keys(void)
{
    k_rsa = tj_keygen("RSA");
    k_rsa_other = tj_keygen("RSA");
    k_p256 = tj_keygen("P-256");
    k_p384 = tj_keygen("P-384");
    k_p521 = tj_keygen("P-521");
    k_ed = tj_keygen("ED25519");
}

static char *build_jwks(void)
{
    EVP_PKEY *k1024 = tj_keygen("RSA1024");
    char *j[] = {
        tj_jwk(k_rsa, "rsa", "\"use\":\"sig\",\"alg\":\"RS256\""),
        tj_jwk(k_rsa, "rsa-any", NULL),
        tj_jwk(k_p256, "p256", "\"use\":\"sig\""),
        tj_jwk(k_p384, "p384", NULL),
        tj_jwk(k_p521, "p521", NULL),
        tj_jwk(k_ed, "ed", "\"key_ops\":[\"verify\"]"),
        /* skipped: encryption key, weak RSA, HMAC secret, unknown curve */
        tj_jwk(k_rsa_other, "enc", "\"use\":\"enc\""),
        tj_jwk(k1024, "weak", NULL),
        strdup("{\"kty\":\"oct\",\"kid\":\"hmac\",\"k\":\"c2VjcmV0\"}"),
        strdup("{\"kty\":\"EC\",\"kid\":\"k1\",\"crv\":\"secp256k1\",\"x\":\"AA\",\"y\":\"AA\"}"),
    };
    size_t n = sizeof(j) / sizeof(j[0]);
    char *out = malloc(64 * 1024);
    size_t o = (size_t)snprintf(out, 64 * 1024, "{\"keys\":[");
    for (size_t i = 0; i < n; i++) {
        o += (size_t)snprintf(out + o, 64 * 1024 - o, "%s%s", i ? "," : "", j[i]);
        free(j[i]);
    }
    snprintf(out + o, 64 * 1024 - o, "]}");
    EVP_PKEY_free(k1024);
    return out;
}

static void test_keyset(void)
{
    char err[256];
    printf("Key set:\n");

    char *jwks = build_jwks();
    g_ks = ob_jws_keyset_parse(jwks, strlen(jwks), err, sizeof(err));
    CHECK(g_ks != NULL, "a JWKS with RSA, EC P-256/384/521 and Ed25519 keys loads");
    CHECK(ob_jws_keyset_size(g_ks) == 6,
          "use:enc, a 1024-bit RSA key, kty:oct and secp256k1 are skipped");
    free(jwks);

    const char *bad[] = {
        "", "[]", "{}", "{\"keys\":{}}", "{\"keys\":[]}",
        "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"h\",\"k\":\"c2VjcmV0\"}]}",
        "{\"keys\":[]} trailing",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char msg[128];
        ob_jws_keyset_t *ks = ob_jws_keyset_parse(bad[i], strlen(bad[i]), err, sizeof(err));
        snprintf(msg, sizeof(msg), "no usable key set from '%s'", bad[i]);
        CHECK(ks == NULL, msg);
        ob_jws_keyset_free(ks);
    }
}

static void test_keyset_file(void)
{
    char dir[] = "/tmp/ob_jws_XXXXXX";
    char path[128], link[128], err[256];
    printf("Key set file:\n");

    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(path, sizeof(path), "%s/sso-jwks.json", dir);
    snprintf(link, sizeof(link), "%s/link.json", dir);

    char *jwk = tj_jwk(k_p256, "p256", NULL);
    FILE *f = fopen(path, "w");
    fprintf(f, "{\"keys\":[%s]}\n", jwk);
    fclose(f);
    free(jwk);

    chmod(path, 0644);
    ob_jws_keyset_t *ks = ob_jws_keyset_load(path, err, sizeof(err));
    CHECK(ks && ob_jws_keyset_size(ks) == 1, "a 0644 file of ours loads");
    ob_jws_keyset_free(ks);

    chmod(path, 0664);
    ks = ob_jws_keyset_load(path, err, sizeof(err));
    CHECK(ks == NULL && strstr(err, "writable"), "a group-writable file is refused");
    ob_jws_keyset_free(ks);
    chmod(path, 0644);

    if (symlink(path, link) == 0) {
        ks = ob_jws_keyset_load(link, err, sizeof(err));
        CHECK(ks == NULL, "a symlink is refused");
        ob_jws_keyset_free(ks);
        unlink(link);
    }

    ks = ob_jws_keyset_load(dir, err, sizeof(err));
    CHECK(ks == NULL, "a directory is refused");
    ob_jws_keyset_free(ks);

    snprintf(link, sizeof(link), "%s/missing.json", dir);
    ks = ob_jws_keyset_load(link, err, sizeof(err));
    CHECK(ks == NULL && strstr(err, "missing.json"), "a missing file is an error naming it");
    ob_jws_keyset_free(ks);

    ks = ob_jws_keyset_load(NULL, err, sizeof(err));
    CHECK(ks == NULL, "no path is an error");

    unlink(path);
    rmdir(dir);
}

/* ── Valid answers ──────────────────────────────────────────────────────── */

static void valid_with(EVP_PKEY *k, const char *alg, const char *kid)
{
    struct json_object *c = claims();
    char *t = tj_sign(k, alg, kid, json_object_to_json_string(c));
    ob_jws_answer_t a;
    ob_jws_expect_t x = expect();
    char why[256] = "", msg[128];
    int rc = verify_x(t, &x, &a, why, sizeof(why));
    struct json_object *user = NULL;
    bool ok = rc == 0 && a.resp && a.http_status == 200 && a.has_aud
              && json_object_object_get_ex(a.resp, "user", &user)
              && strcmp(json_object_get_string(user), "dwho") == 0;
    snprintf(msg, sizeof(msg), "%s answer verifies and yields resp/http_status%s%s",
             alg, ok ? "" : ": ", ok ? "" : why);
    CHECK(ok, msg);
    ob_jws_answer_free(&a);
    json_object_put(c);
    free(t);
}

static void test_valid(void)
{
    printf("Valid answers:\n");
    valid_with(k_rsa, "RS256", "rsa");
    valid_with(k_rsa, "RS384", "rsa-any");
    valid_with(k_rsa, "RS512", "rsa-any");
    valid_with(k_rsa, "PS256", "rsa-any");
    valid_with(k_rsa, "PS512", "rsa-any");
    valid_with(k_p256, "ES256", "p256");
    valid_with(k_p384, "ES384", "p384");
    valid_with(k_p521, "ES512", "p521");
    valid_with(k_ed, "EdDSA", "ed");

    /* No aud: verifies, and says so. The caller must refuse a grant. */
    struct json_object *c = claims();
    json_object_object_del(c, "aud");
    char *t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    ob_jws_answer_t a;
    CHECK(verify(t, &a) == 0 && !a.has_aud, "an answer without aud verifies, has_aud = false");
    ob_jws_answer_free(&a);
    json_object_put(c);
    free(t);

    c = claims();
    json_object_object_add(c, "aud", json_tokener_parse("[\"other\",\"" CLIENT "\"]"));
    t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    CHECK(verify(t, &a) == 0 && a.has_aud, "an aud array naming the client verifies");
    ob_jws_answer_free(&a);
    json_object_put(c);
    free(t);

    /* A refusal is a valid answer too: the verdict is the caller's. */
    c = claims();
    json_object_object_add(c, "http_status", json_object_new_int(403));
    json_object_object_add(c, "resp", json_tokener_parse("{\"error\":\"forbidden\"}"));
    t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    CHECK(verify(t, &a) == 0 && a.http_status == 403, "a signed 403 verifies with http_status 403");
    ob_jws_answer_free(&a);
    json_object_put(c);
    free(t);

    /* The heartbeat's jwks claim is handed over. */
    c = claims();
    json_object_object_add(c, "jwks", json_tokener_parse("{\"keys\":[]}"));
    t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    CHECK(verify(t, &a) == 0 && a.jwks != NULL, "a jwks claim is returned");
    ob_jws_answer_free(&a);
    json_object_put(c);
    free(t);

    /* Within the clock skew either way. */
    c = claims();
    json_object_object_add(c, "exp", json_object_new_int64(g_now - 30));
    json_object_object_add(c, "iat", json_object_new_int64(g_now + 30));
    t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    CHECK(verify(t, &a) == 0, "exp 30 s ago and iat 30 s ahead are within the skew");
    ob_jws_answer_free(&a);
    json_object_put(c);
    free(t);
}

/* ── Signature and header ───────────────────────────────────────────────── */

static void test_signature(void)
{
    printf("Signature and header:\n");

    refused(k_rsa_other, "RS256", "rsa", claims(),
            "bad signature", "an answer signed by another key under a trusted kid is refused");
    refused(k_rsa, "RS256", "nope", claims(), "unknown signing key", "an unknown kid is refused");
    refused(k_rsa_other, "RS256", "enc", claims(), "unknown signing key", "a use:enc key does not verify");

    /* alg/kty mismatches: the key decides, not the header. */
    refused(k_p256, "ES256", "rsa-any", claims(), "cannot be used", "ES256 naming an RSA kid is refused");
    refused(k_rsa, "RS256", "p256", claims(), "cannot be used", "RS256 naming an EC kid is refused");
    refused(k_p256, "ES384", "p256", claims(), "cannot be used", "ES384 with a P-256 key is refused");
    refused(k_p384, "ES256", "p384", claims(), "cannot be used", "ES256 with a P-384 key is refused");
    refused(k_rsa, "PS256", "rsa", claims(),
            "cannot be used", "PS256 with a key whose JWK says alg RS256 is refused");

    /* RS256 signature presented as PS256: same key, wrong padding. */
    struct json_object *c = claims();
    char *t = tj_sign_raw(k_rsa, "RS256",
        "{\"alg\":\"PS256\",\"kid\":\"rsa-any\",\"typ\":\"ob-pam-response+jwt\"}",
        json_object_to_json_string(c));
    refused_token(t, "bad signature", "a PKCS#1 v1.5 signature labelled PS256 is refused");
    free(t);

    /* HS256 keyed with the RSA public key, the classic confusion. */
    size_t pemlen;
    char *pem = tj_public_pem(k_rsa, &pemlen);
    t = tj_sign_hs256((unsigned char *)pem, pemlen,
        "{\"alg\":\"HS256\",\"kid\":\"rsa\",\"typ\":\"ob-pam-response+jwt\"}",
        json_object_to_json_string(c));
    refused_token(t, "not accepted", "HS256 keyed with the RSA public key (PEM) is refused");
    free(t);
    free(pem);

    /* alg none, with and without a signature segment */
    char *h = tj_b64url_str("{\"alg\":\"none\",\"kid\":\"rsa\",\"typ\":\"ob-pam-response+jwt\"}");
    char *p = tj_b64url_str(json_object_to_json_string(c));
    char buf[8192];
    snprintf(buf, sizeof(buf), "%s.%s.", h, p);
    refused_token(buf, "not a compact JWS", "alg none with an empty signature is refused");
    snprintf(buf, sizeof(buf), "%s.%s.AAAA", h, p);
    refused_token(buf, "not accepted", "alg none with a signature segment is refused");
    free(h);

    /* typ */
    t = tj_sign_raw(k_rsa, "RS256", "{\"alg\":\"RS256\",\"kid\":\"rsa\",\"typ\":\"JWT\"}",
                    json_object_to_json_string(c));
    refused_token(t, "typ", "typ JWT (an ID token, say) is refused");
    free(t);
    t = tj_sign_raw(k_rsa, "RS256", "{\"alg\":\"RS256\",\"kid\":\"rsa\"}",
                    json_object_to_json_string(c));
    refused_token(t, "typ", "a missing typ is refused");
    free(t);
    t = tj_sign_raw(k_rsa, "RS256", "{\"alg\":\"RS256\",\"typ\":\"ob-pam-response+jwt\"}",
                    json_object_to_json_string(c));
    refused_token(t, "no kid", "a missing kid is refused");
    free(t);
    t = tj_sign_raw(k_rsa, "RS256",
        "{\"alg\":\"RS256\",\"kid\":\"rsa\",\"typ\":\"ob-pam-response+jwt\",\"crit\":[\"x\"]}",
        json_object_to_json_string(c));
    refused_token(t, "crit", "a crit header is refused");
    free(t);

    /* Tampered payload: the signature covers the original one. */
    t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    json_object_object_add(c, "resp", json_tokener_parse("{\"valid\":true,\"user\":\"root\"}"));
    char *p2 = tj_b64url_str(json_object_to_json_string(c));
    char *d1 = strchr(t, '.'), *d2 = strchr(d1 + 1, '.');
    snprintf(buf, sizeof(buf), "%.*s.%s%s", (int)(d1 - t), t, p2, d2);
    refused_token(buf, "bad signature", "a payload swapped under a valid signature is refused");
    free(p2);
    free(t);
    free(p);
    json_object_put(c);
}

/* ── Claims ─────────────────────────────────────────────────────────────── */

static void test_claims(void)
{
    struct json_object *c;
    printf("Claims:\n");

    c = claims(); json_object_object_add(c, "iss", json_object_new_string("https://evil"));
    refused(k_rsa, "RS256", "rsa", c, "issuer", "a wrong iss is refused");
    c = claims(); json_object_object_del(c, "iss");
    refused(k_rsa, "RS256", "rsa", c, "issuer", "a missing iss is refused");
    c = claims(); json_object_object_add(c, "aud", json_object_new_string("other-client"));
    refused(k_rsa, "RS256", "rsa", c, "(aud)", "an answer for another client (aud) is refused");
    c = claims(); json_object_object_add(c, "aud", json_tokener_parse("[\"other\"]"));
    refused(k_rsa, "RS256", "rsa", c, "(aud)", "an aud array without the client is refused");
    c = claims(); json_object_object_add(c, "endpoint", json_object_new_string("userinfo"));
    refused(k_rsa, "RS256", "rsa", c, "endpoint", "an answer for another endpoint is refused");
    c = claims(); json_object_object_add(c, "exp", json_object_new_int64(g_now - 61));
    refused(k_rsa, "RS256", "rsa", c, "expired", "an expired answer (past the skew) is refused");
    c = claims(); json_object_object_del(c, "exp");
    refused(k_rsa, "RS256", "rsa", c, "exp or iat", "a missing exp is refused");
    c = claims(); json_object_object_add(c, "exp", json_object_new_string("9999999999"));
    refused(k_rsa, "RS256", "rsa", c, "exp or iat", "a string exp is refused");
    c = claims(); json_object_object_add(c, "iat", json_object_new_int64(g_now + 120));
    refused(k_rsa, "RS256", "rsa", c, "future", "an answer issued in the future is refused");
    c = claims(); json_object_object_add(c, "req_nonce", json_object_new_string("1790000000000-other"));
    refused(k_rsa, "RS256", "rsa", c, "(req_nonce)", "an answer to another nonce is refused");
    c = claims(); json_object_object_del(c, "req_nonce");
    refused(k_rsa, "RS256", "rsa", c, "no req_nonce", "an answer without req_nonce is refused");

    /* An authentic answer, replayed for another request body. */
    char sha[65];
    const char *other = "{\"token\":\"otp\",\"fingerprint\":\"SHA256:other\"}";
    tj_sha256_hex(other, strlen(other), sha);
    c = claims(); json_object_object_add(c, "req_sha256", json_object_new_string(sha));
    refused(k_rsa, "RS256", "rsa", c, "req_sha256", "an answer bound to another request body is refused");
    c = claims(); json_object_object_add(c, "req_sha256", json_object_new_string("ABC"));
    refused(k_rsa, "RS256", "rsa", c, "req_sha256", "a malformed req_sha256 is refused");

    c = claims(); json_object_object_del(c, "http_status");
    refused(k_rsa, "RS256", "rsa", c, "http_status", "a missing http_status is refused");
    c = claims(); json_object_object_add(c, "http_status", json_object_new_string("200"));
    refused(k_rsa, "RS256", "rsa", c, "http_status", "a string http_status is refused");
    c = claims(); json_object_object_del(c, "resp");
    refused(k_rsa, "RS256", "rsa", c, "resp missing", "a missing resp is refused");
    c = claims(); json_object_object_add(c, "resp", json_object_new_string("{\"valid\":true}"));
    refused(k_rsa, "RS256", "rsa", c, "resp missing", "a resp that is a string, not an object, is refused");

    /* No client_id configured: an answer that names one cannot match. */
    c = claims();
    char *t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    ob_jws_expect_t x = expect();
    x.audience = NULL;
    ob_jws_answer_t a;
    char why[256];
    CHECK(verify_x(t, &x, &a, why, sizeof(why)) != 0 && strstr(why, "client_id"),
          "aud with no client_id to compare to is refused");
    ob_jws_answer_free(&a);

    /* The body expectation is the bytes as sent */
    x = expect();
    x.body_len -= 1;
    CHECK(verify_x(t, &x, &a, why, sizeof(why)) != 0, "one byte less of request body is another request");
    ob_jws_answer_free(&a);
    json_object_put(c);
    free(t);
}

/* ── Malformed input ────────────────────────────────────────────────────── */

static void test_malformed(void)
{
    printf("Malformed input:\n");

    struct json_object *c = claims();
    char *t = tj_sign(k_rsa, "RS256", "rsa", json_object_to_json_string(c));
    size_t n = strlen(t);
    char *buf = malloc(OB_JWS_MAX_TOKEN + 64);

    refused_token("", "empty", "an empty answer is refused");
    refused_token("{\"valid\":true,\"user\":\"dwho\"}", "compact", "plain JSON is not a JWS");
    refused_token("a.b", "compact", "two segments are refused");

    snprintf(buf, OB_JWS_MAX_TOKEN, "%s.AAAA", t);
    refused_token(buf, "compact", "four segments are refused");

    memcpy(buf, t, n + 1);
    buf[3] = '+';
    refused_token(buf, "malformed JWS header", "a non-base64url character in the header is refused");

    snprintf(buf, OB_JWS_MAX_TOKEN, "%s=", t);
    refused_token(buf, "bad signature", "base64 padding is refused");

    char *h = tj_b64url_str("{\"alg\":\"RS256\",");
    char *p = strchr(t, '.');
    snprintf(buf, OB_JWS_MAX_TOKEN, "%s%s", h, p);
    refused_token(buf, "malformed JWS header", "a header that is not JSON is refused");
    free(h);

    char *bad = tj_sign(k_rsa, "RS256", "rsa", "[1,2,3]");
    refused_token(bad, "malformed JWS payload", "a payload that is not a JSON object is refused");
    free(bad);
    bad = tj_sign(k_rsa, "RS256", "rsa", "{\"iss\":\"" ISSUER "\"} trailing");
    refused_token(bad, "malformed JWS payload", "trailing bytes after the payload object are refused");
    free(bad);

    /* Over the cap: refused before anything is decoded. */
    memset(buf, 'A', OB_JWS_MAX_TOKEN + 10);
    buf[100] = '.';
    buf[200] = '.';
    ob_jws_answer_t a;
    ob_jws_expect_t x = expect();
    char why[256];
    CHECK(ob_jws_verify_answer(g_ks, buf, OB_JWS_MAX_TOKEN + 10, &x, &a, why, sizeof(why)) != 0
          && strstr(why, "larger"), "an answer over 64 KiB is refused");

    /* The token must be taken by length, not up to a NUL. */
    memcpy(buf, t, n + 1);
    CHECK(ob_jws_verify_answer(g_ks, buf, n - 5, &x, &a, why, sizeof(why)) != 0,
          "a truncated token is refused");

    x.nonce = "";
    CHECK(ob_jws_verify_answer(g_ks, t, n, &x, &a, why, sizeof(why)) != 0,
          "verifying without a nonce sent is refused");
    CHECK(ob_jws_verify_answer(NULL, t, n, &x, &a, why, sizeof(why)) != 0,
          "verifying without a key set is refused");

    free(buf);
    free(t);
    json_object_put(c);
}

static void test_media_type_and_mode(void)
{
    ob_response_signing_t m;
    printf("Content-Type and response_signing:\n");
    CHECK(ob_jws_is_media_type("application/ob-pam-response+jwt"), "the media type matches");
    CHECK(ob_jws_is_media_type("Application/OB-PAM-Response+JWT; charset=utf-8"),
          "case and parameters do not matter");
    CHECK(!ob_jws_is_media_type("application/json"), "application/json is not it");
    CHECK(!ob_jws_is_media_type("application/ob-pam-response+jwtx"), "a longer type is not it");
    CHECK(!ob_jws_is_media_type(NULL), "no Content-Type is not it");

    CHECK(ob_response_signing_parse("off", &m) == 0 && m == OB_RESPONSE_SIGNING_OFF, "off");
    CHECK(ob_response_signing_parse("prefer", &m) == 0 && m == OB_RESPONSE_SIGNING_PREFER, "prefer");
    CHECK(ob_response_signing_parse("required", &m) == 0 && m == OB_RESPONSE_SIGNING_REQUIRED, "required");
    CHECK(ob_response_signing_parse("Required", &m) != 0, "Required (capitalised) is invalid");
    CHECK(ob_response_signing_parse("", &m) != 0, "an empty value is invalid");
}

int main(void)
{
    g_now = time(NULL);
    printf("Running ob_jws tests...\n");
    setup_keys();
    test_keyset();
    if (!g_ks) {
        printf("no key set, giving up\n");
        return 1;
    }
    test_keyset_file();
    test_valid();
    test_signature();
    test_claims();
    test_malformed();
    test_media_type_and_mode();

    ob_jws_keyset_free(g_ks);
    EVP_PKEY_free(k_rsa);
    EVP_PKEY_free(k_rsa_other);
    EVP_PKEY_free(k_p256);
    EVP_PKEY_free(k_p384);
    EVP_PKEY_free(k_p521);
    EVP_PKEY_free(k_ed);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
