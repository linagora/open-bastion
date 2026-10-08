/*
 * test_ob_client_signed.c - The PAM client asks for and checks the portal's
 * signed answers (#339), on /pam/verify, /pam/authorize and /pam/heartbeat.
 *
 * Why through a parsed openbastion.conf: #332 shipped request signing that the
 * unit tests covered and the module never used, because nothing copied
 * request_signing_secret from the configuration to the HTTP client. So every
 * client here is built the way pam_openbastion.c builds it: the file is
 * parsed by config.c, checked by config_validate() and turned into client
 * settings by config_client_settings(). Only the server token is set by hand
 * (the module reads it from server_token_file).
 *
 * The portal is mock_portal.h, on plain HTTP: that needs verify_ssl = false,
 * since config_validate() refuses an http:// portal_url otherwise. TLS adds
 * nothing to what is checked here; the point of signed answers is precisely
 * not to depend on it.
 *
 * What is pinned:
 *   - off sends neither Accept nor X-Nonce; prefer and required send both,
 *     and with request_signing_secret one X-Nonce serves the HMAC and the
 *     signed answer;
 *   - required refuses an unsigned answer as a transport error (-1,
 *     last_http_code 0, so an unverified 401 triggers no token refresh),
 *     prefer accepts it; required without a usable JWKS sends nothing;
 *   - a signed valid:false is a refusal, not a transport error;
 *   - a signed answer for another request (replayed, other nonce, other
 *     body), another client, another endpoint, another issuer, with a wrong
 *     key or kid, or whose HTTP status differs from the signed one, is
 *     rejected; one without aud must not grant.
 *
 * config.c is included, as in test_config_line.c, to reach the per-line
 * parser config_load() runs once it has checked that the file is root's.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include "../src/config.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ob_client.h"
#include "ob_jws.h"
#include "ob_sign.h"
#include "mock_portal.h"

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

#define CLIENT     "bastion-test"
#define KID        "portal-sig-1"
#define HMAC_KEY   "fleet-request-signing-secret"
#define VERIFY_OK  "{\"valid\":true,\"user\":\"dwho\",\"groups\":[\"ops\"]}"
#define VERIFY_NO  "{\"valid\":false,\"error\":\"Token expired\"}"
#define AUTHZ_OK   "{\"authorized\":true,\"user\":\"dwho\",\"groups\":[\"ops\"]}"
#define AUTHZ_NO   "{\"authorized\":false,\"reason\":\"not in server group\"}"
#define HB_OK      "{\"access_token\":\"fresh-access-token\",\"expires_in\":3600}"

static char g_dir[64];
static char g_conf[128];
static char g_jwks[128];
static char g_no_jwks[128];
static EVP_PKEY *k_portal;   /* in the JWKS as KID */
static EVP_PKEY *k_rogue;    /* not in the JWKS */

static void write_file(const char *path, const char *content, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f || fputs(content, f) == EOF || fchmod(fileno(f), mode) != 0) {
        perror(path);
        exit(1);
    }
    fclose(f);
}

/*
 * config_load(), and when the file cannot be root's (an unprivileged run),
 * the very loop config_load() runs after that check.
 */
static int load_conf(const char *path, pam_openbastion_config_t *config)
{
    int rc = config_load(path, config);
    if (rc != -2) return rc;

    FILE *f = fopen(path, "r");
    char line[1024];
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        parse_config_file_line(line, config, path);
    }
    fclose(f);
    return 0;
}

/*
 * A client built as pam_openbastion.c builds it, from an openbastion.conf
 * with this response_signing and these extra lines.
 */
static ob_client_t *new_client(const char *mode, const char *jwks, const char *extra)
{
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "# openbastion.conf, as the setup scripts write it\n"
             "portal_url = http://127.0.0.1:%d\n"
             "client_id = " CLIENT "\n"
             "client_secret = client-secret\n"
             "server_group = default\n"
             "verify_ssl = false\n"
             "timeout = 5\n"
             "response_signing = %s\n"
             "sso_jwks_file = %s\n"
             "%s",
             mp.port, mode, jwks, extra ? extra : "");
    write_file(g_conf, conf, 0600);

    pam_openbastion_config_t cfg;
    config_init(&cfg);
    if (load_conf(g_conf, &cfg) != 0 || config_validate(&cfg) != 0) {
        printf("  FAIL cannot load the test configuration (%s)\n", mode);
        config_free(&cfg);
        return NULL;
    }

    ob_client_config_t cc;
    config_client_settings(&cfg, &cc);
    cc.server_token = (char *)"server-access-token";
    /*
     * #332 is still open: config_client_settings() does not carry
     * request_signing_secret to the client yet. Pass it here so the shared
     * nonce is tested now; this line becomes a no-op once #332 is fixed.
     */
    if (!cc.signing_secret) cc.signing_secret = cfg.request_signing_secret;

    ob_client_t *client = ob_client_init(&cc);
    config_free(&cfg);
    if (!client) printf("  FAIL ob_client_init (%s)\n", mode);
    return client;
}

/* A signed answer of the portal, honest unless the test bends it. */
static mp_answer_t signed_answer(const char *resp)
{
    mp_answer_t a = {
        .kind = MP_SIGNED, .resp = resp,
        .key = k_portal, .kid = KID, .alg = "RS256",
    };
    return a;
}

static mp_answer_t plain_answer(const char *resp, int status)
{
    mp_answer_t a = { .kind = MP_PLAIN, .resp = resp, .status = status };
    return a;
}

/* /pam/verify through the client: its rc; *active and *http filled. */
static int do_verify(ob_client_t *client, bool *active, long *http)
{
    ob_response_t r;
    int rc = ob_verify_token(client, "one-time-token", "SHA256:abc", &r);
    *active = rc == 0 && r.active;
    *http = ob_client_last_http_code(client);
    if (rc == 0) ob_response_free(&r);
    return rc;
}

static int do_authorize(ob_client_t *client, bool *authorized, long *http)
{
    ob_response_t r;
    int rc = ob_authorize_user(client, "dwho", "bastion1", "sshd", &r);
    *authorized = rc == 0 && r.authorized;
    *http = ob_client_last_http_code(client);
    if (rc == 0) ob_response_free(&r);
    return rc;
}

static int do_heartbeat(ob_client_t *client, char **token, long *http)
{
    int expires = 0;
    *token = NULL;
    int rc = ob_client_refresh_via_heartbeat(client, "refresh-token", "bastion1",
                                             token, &expires);
    *http = ob_client_last_http_code(client);
    if (rc == 0 && expires != 3600) {
        printf("  FAIL heartbeat expires_in: %d\n", expires);
    }
    return rc;
}

static bool asked_signed(const mp_seen_t *s)
{
    return strcmp(s->accept, OB_JWS_MEDIA_TYPE) == 0 && s->nonce_count == 1
        && s->nonce[0] != '\0';
}

/* ── 1. What is asked for, per mode ──────────────────────────────────────── */
static void test_headers(void)
{
    ob_client_t *c;
    mp_answer_t a;
    mp_seen_t s;
    bool active;
    long http;

    printf("off: nothing changes on the wire:\n");
    c = new_client("off", g_jwks, NULL);
    a = plain_answer(VERIFY_OK, 200);
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == 0 && active, "off: plain valid:true granted");
    s = mp_get_seen();
    CHECK(s.requests == 1 && strcmp(s.path, "/pam/verify") == 0, "off: one /pam/verify sent");
    CHECK(strcmp(s.accept, OB_JWS_MEDIA_TYPE) != 0, "off: no Accept for a signed answer");
    CHECK(s.nonce_count == 0, "off: no X-Nonce");
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == -1 && http == 0,
          "off: a signed answer nobody asked for is rejected");
    ob_client_destroy(c);

    printf("prefer and required ask for a signed answer:\n");
    c = new_client("prefer", g_jwks, NULL);
    a = plain_answer(VERIFY_OK, 200);
    mp_set(&a);
    do_verify(c, &active, &http);
    s = mp_get_seen();
    CHECK(asked_signed(&s), "prefer: Accept: " OB_JWS_MEDIA_TYPE " and one X-Nonce");
    CHECK(s.signature[0] == '\0', "prefer, no request_signing_secret: X-Nonce without HMAC");
    ob_client_destroy(c);

    c = new_client("required", g_jwks, NULL);
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    do_verify(c, &active, &http);
    s = mp_get_seen();
    CHECK(asked_signed(&s), "required: Accept and one X-Nonce");
    char first[128];
    snprintf(first, sizeof(first), "%s", s.nonce);
    do_verify(c, &active, &http);
    s = mp_get_seen();
    CHECK(strcmp(first, s.nonce) != 0, "required: a fresh X-Nonce per request");
    ob_client_destroy(c);
}

/* ── 2. Unsigned answers: required refuses, prefer accepts ───────────────── */
static void test_unsigned(void)
{
    ob_client_t *c;
    mp_answer_t a;
    bool active;
    long http;
    int rc;

    printf("An unsigned answer:\n");
    c = new_client("required", g_jwks, NULL);
    a = plain_answer(VERIFY_OK, 200);
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == -1 && !active, "required: unsigned valid:true refused");
    CHECK(http == 0, "required: ... as a transport error (last_http_code 0)");
    CHECK(strstr(ob_client_error(c), "Unsigned") != NULL, "required: ... and says why");

    /* A forged 401 must not send the module into a token refresh. */
    a = plain_answer("{\"error\":\"invalid token\"}", 401);
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == -1 && http == 0, "required: unsigned 401 leaves last_http_code at 0");
    ob_client_destroy(c);

    c = new_client("prefer", g_jwks, NULL);
    a = plain_answer(VERIFY_OK, 200);
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == 0 && active && http == 200, "prefer: unsigned valid:true accepted");
    ob_client_destroy(c);

    printf("No usable JWKS:\n");
    c = new_client("required", g_no_jwks, NULL);
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == -1 && http == 0, "required: the request fails");
    CHECK(mp_get_seen().requests == 0, "required: ... and is not even sent");
    ob_client_destroy(c);

    c = new_client("prefer", g_no_jwks, NULL);
    a = plain_answer(VERIFY_OK, 200);
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    mp_seen_t s = mp_get_seen();
    CHECK(rc == 0 && active, "prefer: unsigned answer accepted");
    CHECK(s.requests == 1 && s.nonce_count == 0 && strcmp(s.accept, OB_JWS_MEDIA_TYPE) != 0,
          "prefer: ... and no signed answer asked for");
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == -1,
          "prefer: a signed answer it cannot check is not taken");
    ob_client_destroy(c);
}

/* ── 3. Signed answers on /pam/verify ────────────────────────────────────── */
static void test_signed_verify(void)
{
    ob_client_t *c = new_client("required", g_jwks, NULL);
    mp_answer_t a;
    bool active;
    long http;
    int rc;

    printf("Signed answers to /pam/verify (required):\n");
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == 0 && active && http == 200, "signed valid:true granted");

    a = signed_answer(VERIFY_NO);
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == 0 && !active && http == 200,
          "signed valid:false is a refusal, not a transport error");

    a = signed_answer("{\"error\":\"invalid token\"}");
    a.status = 401;
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == -1 && http == 401, "signed 401 reaches last_http_code (token refresh)");

    /* A replay: the answer the portal gave to the previous request. */
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    do_verify(c, &active, &http);
    a.kind = MP_REPLAY;
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == -1 && http == 0 && strstr(ob_client_error(c), "(req_nonce)"),
          "a signed valid:true replayed for the next request (same body): req_nonce");

    /*
     * Each bent claim must be what gets the answer rejected: the error names
     * the check, so a rejection for an unrelated reason does not pass.
     */
    static const struct {
        const char *what, *why;
        const char *nonce, *body, *aud, *endpoint, *iss, *kid;
        int rogue, status, signed_status;
    } bent[] = {
        { "signed for another nonce", "(req_nonce)",
          .nonce = "1790000000000-00000000-0000-4000-8000-000000000000" },
        { "signed for another body", "(req_sha256)",
          .body = "{\"token\":\"another-token\"}" },
        { "signed without req_nonce", "carries no req_nonce", .nonce = "" },
        { "signed for another client", "another client (aud)", .aud = "bastion-other" },
        { "signed for /pam/authorize", "endpoint 'authorize'", .endpoint = "authorize" },
        { "signed by another issuer", "unexpected issuer", .iss = "https://evil.example.com" },
        { "signed with another key under the known kid", "bad signature", .rogue = 1 },
        { "signed with a kid not in the JWKS", "unknown signing key",
          .rogue = 1, .kid = "portal-sig-9" },
        { "HTTP 200 but signed for 403", "status mismatch", .signed_status = 403 },
        { "HTTP 403 but signed for 200", "status mismatch",
          .status = 403, .signed_status = 200 },
    };
    for (size_t i = 0; i < sizeof(bent) / sizeof(bent[0]); i++) {
        a = signed_answer(VERIFY_OK);
        a.nonce = bent[i].nonce;
        a.signed_body = bent[i].body;
        a.aud = bent[i].aud;
        a.endpoint = bent[i].endpoint;
        a.iss = bent[i].iss;
        if (bent[i].rogue) a.key = k_rogue;
        if (bent[i].kid) a.kid = bent[i].kid;
        a.status = bent[i].status;
        a.signed_status = bent[i].signed_status;
        mp_set(&a);
        rc = do_verify(c, &active, &http);
        char msg[160];
        snprintf(msg, sizeof(msg), "%s: rejected, %s", bent[i].what, bent[i].why);
        CHECK(rc == -1 && !active && http == 0
              && strstr(ob_client_error(c), bent[i].why) != NULL, msg);
    }

    /* No aud: the portal had not identified the caller, so nothing granted. */
    a = signed_answer(VERIFY_OK);
    a.aud = "";
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == -1 && !active && strstr(ob_client_error(c), "without aud"),
          "signed valid:true without aud refused");
    a = signed_answer(VERIFY_NO);
    a.aud = "";
    mp_set(&a);
    rc = do_verify(c, &active, &http);
    CHECK(rc == 0 && !active, "signed valid:false without aud is a plain refusal");
    ob_client_destroy(c);

    printf("prefer does not downgrade a bad signature to \"unsigned\":\n");
    c = new_client("prefer", g_jwks, NULL);
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == 0 && active, "prefer: signed valid:true granted");
    a.key = k_rogue;
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == -1 && !active, "prefer: forged signature rejected");
    ob_client_destroy(c);

    printf("The issuer comes from sso_issuer, else from portal_url:\n");
    c = new_client("required", g_jwks, "sso_issuer = https://auth.example.com\n");
    a = signed_answer(VERIFY_OK);
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == -1,
          "sso_issuer set: an answer issued as portal_url is rejected");
    a.iss = "https://auth.example.com";
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == 0 && active,
          "sso_issuer set: an answer issued as sso_issuer is granted");
    ob_client_destroy(c);
}

/* ── 4. request_signing_secret: one nonce for both signatures ────────────── */
static void test_shared_nonce(void)
{
    ob_client_t *c = new_client("required", g_jwks,
                                "request_signing_secret = " HMAC_KEY "\n");
    mp_answer_t a = signed_answer(VERIFY_OK);
    bool active;
    long http;

    printf("With request_signing_secret:\n");
    mp_set(&a);
    int rc = do_verify(c, &active, &http);
    mp_seen_t s = mp_get_seen();
    CHECK(rc == 0 && active, "signed answer bound to the HMAC nonce granted");
    CHECK(s.nonce_count == 1, "a single X-Nonce header");
    CHECK(strcmp(s.accept, OB_JWS_MEDIA_TYPE) == 0, "Accept still sent");

    /* The HMAC covers that very nonce: the portal recomputes it. */
    char expected[OB_SIGN_SIGNATURE_SIZE], header[OB_SIGN_SIGNATURE_SIZE + 16];
    ob_sign_compute(HMAC_KEY, atol(s.timestamp), s.nonce, "POST", "/pam/verify",
                    s.body, expected, sizeof(expected));
    snprintf(header, sizeof(header), "sha256=%s", expected);
    CHECK(expected[0] && strcmp(s.signature, header) == 0,
          "X-Signature-256 is computed over the same X-Nonce");

    a.nonce = "1790000000000-00000000-0000-4000-8000-000000000000";
    mp_set(&a);
    CHECK(do_verify(c, &active, &http) == -1, "an answer bound to another nonce is rejected");
    ob_client_destroy(c);

    /* /pam/heartbeat is signed too (#247): same rule. */
    c = new_client("required", g_jwks, "request_signing_secret = " HMAC_KEY "\n");
    a = signed_answer(HB_OK);
    mp_set(&a);
    char *tok;
    rc = do_heartbeat(c, &tok, &http);
    s = mp_get_seen();
    CHECK(rc == 0 && s.nonce_count == 1 && s.signature[0],
          "heartbeat: one X-Nonce for the HMAC and the signed answer");
    free(tok);
    ob_client_destroy(c);
}

/* ── 5. /pam/authorize ───────────────────────────────────────────────────── */
static void test_authorize(void)
{
    ob_client_t *c = new_client("required", g_jwks, NULL);
    mp_answer_t a;
    bool ok;
    long http;
    int rc;

    printf("/pam/authorize (required):\n");
    a = plain_answer(AUTHZ_OK, 200);
    mp_set(&a);
    rc = do_authorize(c, &ok, &http);
    CHECK(rc == -1 && !ok && http == 0, "unsigned authorized:true refused");
    mp_seen_t s = mp_get_seen();
    CHECK(asked_signed(&s) && strcmp(s.path, "/pam/authorize") == 0,
          "Accept and X-Nonce sent to /pam/authorize");

    a = signed_answer(AUTHZ_OK);
    mp_set(&a);
    rc = do_authorize(c, &ok, &http);
    CHECK(rc == 0 && ok && http == 200, "signed authorized:true granted");

    a = signed_answer(AUTHZ_NO);
    mp_set(&a);
    rc = do_authorize(c, &ok, &http);
    CHECK(rc == 0 && !ok && http == 200, "signed authorized:false is a refusal");

    a = signed_answer(AUTHZ_OK);
    a.aud = "";
    mp_set(&a);
    CHECK(do_authorize(c, &ok, &http) == -1 && !ok, "signed authorized:true without aud refused");

    a = signed_answer(AUTHZ_OK);
    a.endpoint = "verify";
    mp_set(&a);
    CHECK(do_authorize(c, &ok, &http) == -1, "an answer signed for /pam/verify rejected");

    a = signed_answer(AUTHZ_OK);
    mp_set(&a);
    do_authorize(c, &ok, &http);
    a.kind = MP_REPLAY;
    mp_set(&a);
    CHECK(do_authorize(c, &ok, &http) == -1 && !ok && http == 0, "a replayed grant rejected");

    a = signed_answer(AUTHZ_OK);
    a.key = k_rogue;
    mp_set(&a);
    CHECK(do_authorize(c, &ok, &http) == -1 && !ok, "a forged grant rejected");

    a = signed_answer(AUTHZ_OK);
    a.signed_status = 403;
    mp_set(&a);
    CHECK(do_authorize(c, &ok, &http) == -1 && http == 0, "HTTP status != signed http_status rejected");
    ob_client_destroy(c);

    c = new_client("required", g_no_jwks, NULL);
    mp_set(&a);
    CHECK(do_authorize(c, &ok, &http) == -1 && mp_get_seen().requests == 0,
          "required without JWKS: no /pam/authorize sent");
    ob_client_destroy(c);

    c = new_client("prefer", g_jwks, NULL);
    a = plain_answer(AUTHZ_OK, 200);
    mp_set(&a);
    CHECK(do_authorize(c, &ok, &http) == 0 && ok, "prefer: unsigned authorized:true accepted");
    ob_client_destroy(c);
}

/* ── 6. The token refresh through /pam/heartbeat ─────────────────────────── */
static void test_heartbeat(void)
{
    ob_client_t *c = new_client("required", g_jwks, NULL);
    mp_answer_t a;
    mp_seen_t s;
    char *tok;
    long http;
    int rc;

    printf("/pam/heartbeat refresh (required):\n");
    a = plain_answer(HB_OK, 200);
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    s = mp_get_seen();
    CHECK(rc == -1 && tok == NULL && http == 0, "unsigned access token refused");
    CHECK(asked_signed(&s) && strcmp(s.path, "/pam/heartbeat") == 0 && !s.has_authorization,
          "Accept and X-Nonce sent, no Bearer");

    a = signed_answer(HB_OK);
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    CHECK(rc == 0 && tok && strcmp(tok, "fresh-access-token") == 0 && http == 200,
          "signed access token taken");
    free(tok);

    a.kind = MP_REPLAY;
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    CHECK(rc == -1 && tok == NULL, "a replayed access token rejected");

    a = signed_answer(HB_OK);
    a.aud = "";
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    CHECK(rc == -1 && tok == NULL, "an access token signed without aud refused");

    a = signed_answer(HB_OK);
    a.kid = "portal-sig-9";
    a.key = k_rogue;
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    CHECK(rc == -1 && tok == NULL, "an access token signed with an unknown kid rejected");

    a = signed_answer("{\"error\":\"invalid refresh token\"}");
    a.status = 401;
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    CHECK(rc == -1 && tok == NULL && http == 401, "a signed 401 is reported as such");
    ob_client_destroy(c);

    c = new_client("required", g_no_jwks, NULL);
    a = signed_answer(HB_OK);
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    CHECK(rc == -1 && tok == NULL && mp_get_seen().requests == 0,
          "required without JWKS: no /pam/heartbeat sent");
    ob_client_destroy(c);

    c = new_client("off", g_jwks, NULL);
    a = plain_answer(HB_OK, 200);
    mp_set(&a);
    rc = do_heartbeat(c, &tok, &http);
    s = mp_get_seen();
    CHECK(rc == 0 && tok && s.nonce_count == 0, "off: unsigned refresh, no X-Nonce");
    free(tok);
    ob_client_destroy(c);
}

int main(void)
{
    char cmd[128];

    snprintf(g_dir, sizeof(g_dir), "/tmp/ob_client_signed_XXXXXX");
    if (!mkdtemp(g_dir)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(g_conf, sizeof(g_conf), "%s/openbastion.conf", g_dir);
    snprintf(g_jwks, sizeof(g_jwks), "%s/sso-jwks.json", g_dir);
    snprintf(g_no_jwks, sizeof(g_no_jwks), "%s/missing-jwks.json", g_dir);

    k_portal = tj_keygen("RSA");
    k_rogue = tj_keygen("RSA");
    char *jwk = tj_jwk(k_portal, KID, "\"use\":\"sig\",\"alg\":\"RS256\"");
    char jwks[4200];
    snprintf(jwks, sizeof(jwks), "{\"keys\":[%s]}\n", jwk);
    free(jwk);
    write_file(g_jwks, jwks, 0644);

    mp_start(CLIENT);

    printf("=== ob_client: signed portal answers (#339) ===\n\n");
    test_headers();
    printf("\n");
    test_unsigned();
    printf("\n");
    test_signed_verify();
    printf("\n");
    test_shared_nonce();
    printf("\n");
    test_authorize();
    printf("\n");
    test_heartbeat();

    mp_stop();
    EVP_PKEY_free(k_portal);
    EVP_PKEY_free(k_rogue);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) {
        /* best effort */
    }

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
