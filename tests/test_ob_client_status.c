/*
 * test_ob_client_status.c - Which /pam/authorize failures may use the
 * offline authorization cache.
 *
 * The PAM account phase falls back to the cache only when the client says the
 * portal is unreachable. Everything else -- an HTTP refusal, a malformed or
 * unsigned answer, a signature that does not verify -- is a verdict and must
 * not be answered from a cache entry: a user revoked in the portal would
 * otherwise keep their cached grant, `sudo` right included, until it expired.
 *
 * Drives ob_authorize_user() through mock_portal.h so each return code is
 * observed on the real HTTP path, not only in a helper.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include "../src/config.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ob_client.h"
#include "mock_portal.h"

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

static ob_client_t *new_client(const char *url, const char *mode,
                               const char *jwks)
{
    char conf[2048];
    snprintf(conf, sizeof(conf),
             "portal_url = %s\n"
             "client_id = " CLIENT "\n"
             "client_secret = client-secret\n"
             "server_group = default\n"
             "verify_ssl = false\n"
             "timeout = 5\n"
             "response_signing = %s\n"
             "sso_jwks_file = %s\n",
             url, mode, jwks);
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

    EVP_PKEY_free(k_portal);
    EVP_PKEY_free(k_rogue);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) {
        /* best effort */
    }

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
