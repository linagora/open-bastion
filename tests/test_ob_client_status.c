/*
 * test_ob_client_status.c - Which /pam/authorize failures may use the
 * offline authorization cache.
 *
 * The PAM account phase falls back to the cache only when the client says the
 * portal is unreachable. Everything else -- an HTTP refusal, a malformed or
 * unsigned answer, a signature that does not verify, a TLS certificate, issuer
 * or pin that does not match, or a local TLS misconfiguration -- is a verdict
 * and must not be answered from a cache entry: a user revoked in the portal
 * would otherwise keep their cached grant, `sudo` right included, until it
 * expired.
 *
 * Drives ob_authorize_user() through mock_portal.h and mock_tls.h so each
 * return code is observed on the real HTTP/TLS path, not only in a helper.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include "../src/config.c"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ob_client.h"
#include "mock_portal.h"
#include "mock_tls.h"

#define CLIENT   "bastion-test"
#define KID      "portal-sig-1"
#define AUTHZ_OK "{\"authorized\":true,\"user\":\"dwho\"}"
#define AUTHZ_NO "{\"authorized\":false,\"reason\":\"not in server group\"}"

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

static char g_dir[64];
static char g_conf[128];
static char g_jwks[128];
static EVP_PKEY *k_portal;
static EVP_PKEY *k_rogue;

static void write_file(const char *path, const char *content, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f || fputs(content, f) == EOF || fchmod(fileno(f), mode) != 0) {
        perror(path);
        exit(1);
    }
    fclose(f);
}

static int load_conf(const char *path, pam_openbastion_config_t *config)
{
    int rc = config_load(path, config);
    if (rc != -2) return rc;

    FILE *f = fopen(path, "r");
    if (!f) return -1;
    rc = config_load_stream(f, config, path);
    fclose(f);
    return rc;
}

static ob_client_t *new_client_at(const char *url, const char *mode,
                                  const char *jwks, bool verify_ssl,
                                  const char *extra)
{
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "portal_url = %s\n"
             "client_id = " CLIENT "\n"
             "client_secret = client-secret\n"
             "server_group = default\n"
             "verify_ssl = %s\n"
             "timeout = 5\n"
             "response_signing = %s\n"
             "sso_jwks_file = %s\n"
             "%s",
             url, verify_ssl ? "true" : "false", mode, jwks,
             extra ? extra : "");
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

    ob_client_t *client = ob_client_init(&cc);
    config_free(&cfg);
    if (!client) printf("  FAIL ob_client_init (%s)\n", mode);
    return client;
}

/* The plain-HTTP mock portal always needs verify_ssl = false. */
static ob_client_t *new_client(const char *url, const char *mode,
                               const char *jwks)
{
    return new_client_at(url, mode, jwks, false, NULL);
}

static int authorize(ob_client_t *client)
{
    ob_response_t r;
    int rc = ob_authorize_user(client, "dwho", "bastion1", "sshd", &r);
    if (rc == 0) ob_response_free(&r);
    return rc;
}

static void test_http_statuses(void)
{
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d", mp.port);
    ob_client_t *client = new_client(url, "off", g_jwks);
    if (!client) return;

    struct {
        int status;
        int expected;
        const char *why;
    } cases[] = {
        { 200, 0, "200 is a verdict (the answer decides)" },
        { 400, OB_ERR_REFUSED, "400 (fingerprint required) is a refusal" },
        { 401, OB_ERR_REFUSED, "401 is a refusal after the retry" },
        { 403, OB_ERR_REFUSED, "403 (server refused) is a refusal" },
        { 500, OB_ERR_REFUSED, "500 is a refusal" },
        { 502, OB_ERR_UNREACHABLE, "502 is an outage" },
        { 503, OB_ERR_UNREACHABLE, "503 is an outage" },
        { 504, OB_ERR_UNREACHABLE, "504 is an outage" },
    };

    printf("HTTP status -> cache eligibility:\n");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        mp_answer_t a = { .kind = MP_PLAIN, .status = cases[i].status,
                          .resp = cases[i].status == 200 ? AUTHZ_OK : AUTHZ_NO };
        mp_set(&a);
        int rc = authorize(client);
        CHECK(rc == cases[i].expected, cases[i].why);
    }

    printf("\nAn answer that is not JSON:\n");
    mp_answer_t bad = { .kind = MP_PLAIN, .resp = "not json" };
    mp_set(&bad);
    CHECK(authorize(client) == OB_ERR_REFUSED, "200 with a malformed body is a refusal");

    ob_client_destroy(client);
}

static void test_signatures(void)
{
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d", mp.port);
    ob_client_t *client = new_client(url, "required", g_jwks);
    if (!client) return;

    printf("\nSignature outcome -> cache eligibility:\n");
    mp_answer_t unsigned_answer = { .kind = MP_PLAIN, .resp = AUTHZ_OK };
    mp_set(&unsigned_answer);
    CHECK(authorize(client) == OB_ERR_REFUSED,
          "an unsigned answer under 'required' is a refusal");

    mp_answer_t forged = { .kind = MP_SIGNED, .resp = AUTHZ_OK,
                           .key = k_rogue, .kid = KID, .alg = "RS256" };
    mp_set(&forged);
    CHECK(authorize(client) == OB_ERR_REFUSED,
          "a signature from another key is a refusal");

    mp_answer_t replayed = { .kind = MP_REPLAY };
    mp_set(&replayed);
    CHECK(authorize(client) == OB_ERR_REFUSED,
          "an answer replayed for another request is a refusal");

    mp_answer_t honest = { .kind = MP_SIGNED, .resp = AUTHZ_OK,
                           .key = k_portal, .kid = KID, .alg = "RS256" };
    mp_set(&honest);
    CHECK(authorize(client) == 0, "a verified answer reaches the verdict");

    mp_answer_t anonymous = { .kind = MP_SIGNED, .resp = AUTHZ_OK,
                              .key = k_portal, .kid = KID, .alg = "RS256",
                              .aud = "" };
    mp_set(&anonymous);
    CHECK(authorize(client) == OB_ERR_REFUSED,
          "a grant that does not name this client is a refusal");

    ob_client_destroy(client);
}

static void test_transport(void)
{
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d", mp.port);
    mp_stop();

    printf("\nTransport failure:\n");
    ob_client_t *client = new_client(url, "off", g_jwks);
    if (!client) return;
    CHECK(authorize(client) == OB_ERR_UNREACHABLE,
          "a closed portal is an outage");
    CHECK(ob_client_last_http_code(client) == 0,
          "  ... with no HTTP status to refresh a token on");
    ob_client_destroy(client);
}

/*
 * Only a failure that prevents the portal from answering may use the cache.
 * A verdict and a local TLS or configuration problem must deny, so any code
 * that is not clearly a lost connection falls back to refusal.
 */
static void test_curl_errors(void)
{
    struct {
        int code;
        bool cache;
        const char *why;
    } cases[] = {
        { CURLE_COULDNT_RESOLVE_PROXY, true,
          "a proxy name that does not resolve is an outage" },
        { CURLE_COULDNT_RESOLVE_HOST, true,
          "a portal name that does not resolve is an outage" },
        { CURLE_COULDNT_CONNECT, true,
          "a refused or unreachable portal is an outage" },
        { CURLE_PARTIAL_FILE, true,
          "a truncated answer is an outage" },
        { CURLE_HTTP2, true,
          "an HTTP/2 framing failure is an outage" },
        { CURLE_OPERATION_TIMEDOUT, true,
          "a timeout is an outage" },
        { CURLE_SSL_CONNECT_ERROR, true,
          "an incomplete TLS handshake is an outage" },
        { CURLE_GOT_NOTHING, true,
          "a closed connection without an answer is an outage" },
        { CURLE_SEND_ERROR, true,
          "a failed send is an outage" },
        { CURLE_RECV_ERROR, true,
          "a failed receive is an outage" },
        { CURLE_NO_CONNECTION_AVAILABLE, true,
          "no available connection is an outage" },
        { CURLE_HTTP2_STREAM, true,
          "an HTTP/2 stream failure is an outage" },
        { CURLE_HTTP3, true,
          "an HTTP/3 failure is an outage" },
        { CURLE_QUIC_CONNECT_ERROR, true,
          "a QUIC connection failure is an outage" },
        { CURLE_PROXY, true,
          "a proxy handshake failure is an outage" },

        { CURLE_UNSUPPORTED_PROTOCOL, false,
          "an unsupported scheme is a local configuration error" },
        { CURLE_FAILED_INIT, false,
          "a failed client initialisation is local" },
        { CURLE_URL_MALFORMAT, false,
          "a malformed portal URL is a local configuration error" },
        { CURLE_NOT_BUILT_IN, false,
          "a missing libcurl feature is local" },
        { CURLE_WEIRD_SERVER_REPLY, false,
          "a malformed answer is a refusal" },
        { CURLE_REMOTE_ACCESS_DENIED, false,
          "a denied request is a refusal" },
        { CURLE_WRITE_ERROR, false,
          "a failed or oversized response write is a refusal" },
        { CURLE_OUT_OF_MEMORY, false,
          "a local out-of-memory failure is not an outage" },
        { CURLE_BAD_FUNCTION_ARGUMENT, false,
          "a programming error is not an outage" },
        { CURLE_INTERFACE_FAILED, false,
          "a local interface problem is a configuration error" },
        { CURLE_TOO_MANY_REDIRECTS, false,
          "a redirect loop is a refusal" },
        { CURLE_SSL_ENGINE_NOTFOUND, false,
          "a missing TLS engine is a local configuration error" },
        { CURLE_SSL_ENGINE_SETFAILED, false,
          "a failed TLS engine selection is local" },
        { CURLE_SSL_CERTPROBLEM, false,
          "a client certificate problem is local, not an outage" },
        { CURLE_SSL_CIPHER, false,
          "an unusable cipher is a local configuration error" },
        { CURLE_PEER_FAILED_VERIFICATION, false,
          "an unverified peer certificate is a refusal" },
        { CURLE_BAD_CONTENT_ENCODING, false,
          "an undecodable answer is a refusal" },
        { CURLE_USE_SSL_FAILED, false,
          "a TLS level the client cannot use is local" },
        { CURLE_SSL_ENGINE_INITFAILED, false,
          "a failed TLS engine initialisation is local" },
        { CURLE_SSL_CACERT_BADFILE, false,
          "an unreadable ca_cert is a local configuration error" },
        { CURLE_SSL_SHUTDOWN_FAILED, false,
          "a failed TLS shutdown may follow an answer, so deny" },
        { CURLE_SSL_CRL_BADFILE, false,
          "an unreadable CRL is a local configuration error" },
        { CURLE_SSL_ISSUER_ERROR, false,
          "a failed issuer check is a refusal" },
        { CURLE_SSL_PINNEDPUBKEYNOTMATCH, false,
          "a mismatched cert_pin is a refusal" },
        { CURLE_SSL_INVALIDCERTSTATUS, false,
          "an invalid OCSP status is a refusal" },
        { CURLE_SSL_CLIENTCERT, false,
          "a missing client certificate is local" },
        { CURLE_AUTH_ERROR, false,
          "a failed authentication callback is local" },
        { CURLE_UNRECOVERABLE_POLL, false,
          "a fatal poll failure is local" },
        { 999, false,
          "an unknown code fails closed" },
    };

    printf("\nlibcurl failure -> cache eligibility:\n");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CHECK(ob_curl_error_allows_offline_cache(cases[i].code) == cases[i].cache,
              cases[i].why);
    }
}

/*
 * A TLS trust failure is not an outage: the host reached *something*, but
 * that something did not prove it is the portal. mock_tls.h serves a fresh
 * self-signed certificate, so verify_ssl = true fails the chain check and a
 * cert_pin naming another key fails the pin check.
 */
static void test_tls_trust(void)
{
    char url[64], pin[64], extra[128];
    ob_client_t *client;

    mt_start(200, AUTHZ_OK);
    snprintf(url, sizeof(url), "https://127.0.0.1:%d", mt.port);

    printf("\nTLS trust failure:\n");
    client = new_client_at(url, "off", g_jwks, true, NULL);
    if (client) {
        CHECK(authorize(client) == OB_ERR_REFUSED,
              "an unverified server certificate is a refusal");
        CHECK(ob_client_last_http_code(client) == 0,
              "  ... with no HTTP status to refresh a token on");
        ob_client_destroy(client);
    }

    mt_pin_of(k_rogue, pin, sizeof(pin));
    snprintf(extra, sizeof(extra), "cert_pin = %s\n", pin);
    client = new_client_at(url, "off", g_jwks, false, extra);
    if (client) {
        CHECK(authorize(client) == OB_ERR_REFUSED,
              "a pinned key that does not match is a refusal");
        CHECK(ob_client_last_http_code(client) == 0,
              "  ... with no HTTP status to refresh a token on");
        ob_client_destroy(client);
    }

    snprintf(extra, sizeof(extra), "ca_cert = %s/missing-ca.pem\n", g_dir);
    client = new_client_at(url, "off", g_jwks, true, extra);
    if (client) {
        CHECK(authorize(client) == OB_ERR_REFUSED,
              "an unreadable ca_cert is a local misconfiguration, not an outage");
        CHECK(ob_client_last_http_code(client) == 0,
              "  ... with no HTTP status to refresh a token on");
        ob_client_destroy(client);
    }

    /* The control: the same TLS portal is reachable once the trust checks
     * are off, so the two failures above are verdicts, not a broken setup. */
    client = new_client_at(url, "off", g_jwks, false, NULL);
    if (client) {
        CHECK(authorize(client) == 0,
              "with the checks off, the same portal is reached");
        ob_client_destroy(client);
    }

    mt_stop();
}

int main(void)
{
    char cmd[128];

    snprintf(g_dir, sizeof(g_dir), "/tmp/ob_client_status_XXXXXX");
    if (!mkdtemp(g_dir)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(g_conf, sizeof(g_conf), "%s/openbastion.conf", g_dir);
    snprintf(g_jwks, sizeof(g_jwks), "%s/sso-jwks.json", g_dir);

    k_portal = tj_keygen("RSA");
    k_rogue = tj_keygen("RSA");
    char *jwk = tj_jwk(k_portal, KID, "\"use\":\"sig\",\"alg\":\"RS256\"");
    char jwks[4200];
    snprintf(jwks, sizeof(jwks), "{\"keys\":[%s]}\n", jwk);
    free(jwk);
    write_file(g_jwks, jwks, 0644);

    mp_start(CLIENT);

    printf("=== ob_client: /pam/authorize failures and the offline cache ===\n\n");
    test_http_statuses();
    test_signatures();
    test_transport();
    test_curl_errors();
    test_tls_trust();

    EVP_PKEY_free(k_portal);
    EVP_PKEY_free(k_rogue);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) {
        /* best effort */
    }

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
