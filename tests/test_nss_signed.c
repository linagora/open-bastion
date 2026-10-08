/*
 * test_nss_signed.c - libnss_openbastion and the portal's signed /pam/userinfo
 * answers (#339).
 *
 * The NSS module hands out passwd entries, uid included, straight from the
 * portal's answer, and caches them on disk for every other process. Behind a
 * TLS interceptor or a CA that trusts too much, an unsigned answer is a uid of
 * the attacker's choosing. These tests pin, through the module's real entry
 * point (_nss_openbastion_getpwnam_r) and a configuration file it parses
 * itself:
 *
 *   - under `required`, an unsigned, forged, replayed or anonymous (no aud)
 *     answer is NSS_STATUS_UNAVAIL and leaves NOTHING in either cache, not
 *     even a negative entry, so the next good answer is not shadowed;
 *   - a properly signed answer is served, cached in memory and on disk, and
 *     then served from the caches without the portal;
 *   - `required` without a usable JWKS or without client_id sends nothing;
 *   - `prefer` takes an unsigned answer, `off` asks for nothing new;
 *   - an unparseable response_signing means `required`.
 *
 * The module source is included, as in test_nss_force_shell.c, with the
 * configuration and cache paths redirected to a private directory. The portal
 * is tests/mock_portal.h. The server token is set by hand: the module only
 * takes a root-owned token file, which an unprivileged run cannot provide.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

const char *test_cache_root(void);
const char *test_cache_byname(void);
const char *test_conf_path(void);
#define CACHE_DIR            test_cache_root()
#define CACHE_DIR_BYNAME     test_cache_byname()
#define CACHE_TRUSTED_UID    (getuid())
#define NSS_OB_CONF          test_conf_path()
#define NSS_CONF_TRUSTED_UID (getuid())

#include "../nss/libnss_openbastion.c"

#include "mock_portal.h"

#define CLIENT  "bastion-test"
#define KID     "portal-sig-1"
#define DWHO    "{\"found\":true,\"uid\":20001,\"gid\":20001,\"gecos\":\"D Who\"," \
                "\"home\":\"/home/dwho\",\"shell\":\"/bin/bash\"}"
#define ROOTISH "{\"found\":true,\"uid\":20666,\"gid\":20666,\"gecos\":\"Mallory\"," \
                "\"home\":\"/home/mallory\",\"shell\":\"/bin/bash\"}"
#define NOUSER  "{\"found\":false}"

static char g_base[128];
static char g_jwks[192];
static char g_no_jwks[192];
static EVP_PKEY *k_portal;   /* in the JWKS as KID */
static EVP_PKEY *k_rogue;    /* not in the JWKS */
static int failures;

static const char *base(void)
{
    if (!g_base[0]) {
        snprintf(g_base, sizeof(g_base), "/tmp/ob_nss_signed_XXXXXX");
        if (!mkdtemp(g_base)) {
            perror("mkdtemp");
            exit(1);
        }
    }
    return g_base;
}

const char *test_cache_root(void)
{
    static char p[192];
    snprintf(p, sizeof(p), "%s/cache", base());
    return p;
}

const char *test_cache_byname(void)
{
    static char p[224];
    snprintf(p, sizeof(p), "%s/byname", test_cache_root());
    return p;
}

const char *test_conf_path(void)
{
    static char p[192];
    snprintf(p, sizeof(p), "%s/nss_openbastion.conf", base());
    return p;
}

static void check(const char *what, int cond)
{
    if (cond) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

static void write_file(const char *path, const char *content, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f || fputs(content, f) == EOF || fchmod(fileno(f), mode) != 0) {
        perror(path);
        exit(1);
    }
    fclose(f);
}

static void memory_cache_reset(void)
{
    if (g_cache.entries) {
        for (size_t i = 0; i < g_cache.count; i++) {
            free(g_cache.entries[i].username);
            free(g_cache.entries[i].pw_buffer);
        }
        free(g_cache.entries);
    }
    g_cache.entries = NULL;
    g_cache.count = g_cache.capacity = 0;
    init_cache();
}

static void cache_reset(void)
{
    char cmd[256];

    memory_cache_reset();
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", test_cache_root());
    if (system(cmd) != 0) {
        /* best effort */
    }
}

static void config_reset(void)
{
    free(g_config.portal_url);
    free(g_config.server_token_file);
    free(g_config.server_token);
    free(g_config.default_shell);
    free(g_config.force_shell);
    free(g_config.default_home_base);
    free(g_config.service_accounts_file);
    free(g_config.client_id);
    free(g_config.sso_jwks_file);
    free(g_config.sso_issuer);
    memset(&g_config, 0, sizeof(g_config));
}

/*
 * The module as it starts on a host whose nss_openbastion.conf carries these
 * lines, with both caches empty.
 */
static void configure(const char *lines)
{
    char conf[2048];

    snprintf(conf, sizeof(conf),
             "portal_url = http://127.0.0.1:%d\n"
             "server_token_file = %s/server_token.json\n"
             "service_accounts_file = %s/no-service-accounts.conf\n"
             "cache_ttl = 300\n"
             "%s",
             mp.port, base(), base(), lines);
    write_file(test_conf_path(), conf, 0644);

    config_reset();
    load_config(&g_config);       /* -1: no token file, but every key is parsed */
    g_config.server_token = strdup("server-access-token");
    g_initialized = 1;
    cache_reset();
}

static char *conf_lines(const char *mode, const char *jwks, int with_client)
{
    static char lines[512];
    snprintf(lines, sizeof(lines), "%s%s%s%ssso_jwks_file = %s\n",
             with_client ? "client_id = " CLIENT "\n" : "",
             mode ? "response_signing = " : "", mode ? mode : "", mode ? "\n" : "",
             jwks);
    return lines;
}

static enum nss_status lookup(const char *name, struct passwd *pw, char *buf, size_t len)
{
    int err = 0;
    return _nss_openbastion_getpwnam_r(name, pw, buf, len, &err);
}

/* In the memory cache (positive or negative entry)? */
static int in_memory(const char *name)
{
    pthread_mutex_lock(&g_cache.lock);
    int found = cache_find(name) != NULL;
    pthread_mutex_unlock(&g_cache.lock);
    return found;
}

/* On disk, by name or by uid (0: by name only)? */
static int on_disk(const char *name, uid_t uid)
{
    struct passwd pw;
    char buf[1024];
    time_t created;
    return file_cache_load_by_name(name, &pw, buf, sizeof(buf), &created) == 0
        || (uid && file_cache_load_by_uid(uid, &pw, buf, sizeof(buf), &created) == 0);
}

/* The name the disk cache gives for this uid, or "" */
static const char *disk_name_of(uid_t uid)
{
    static char buf[1024];
    struct passwd pw;
    time_t created;
    if (file_cache_load_by_uid(uid, &pw, buf, sizeof(buf), &created) != 0) return "";
    return pw.pw_name;
}

static mp_answer_t signed_answer(const char *resp)
{
    mp_answer_t a = {
        .kind = MP_SIGNED, .resp = resp,
        .key = k_portal, .kid = KID, .alg = "RS256",
    };
    return a;
}

static mp_answer_t plain_answer(const char *resp)
{
    mp_answer_t a = { .kind = MP_PLAIN, .resp = resp };
    return a;
}

/* A refused answer: UNAVAIL, and neither cache holds anything for it. */
static void expect_refused(const char *what, const mp_answer_t *a,
                           const char *name, uid_t uid)
{
    struct passwd pw;
    char buf[4096], msg[192];

    mp_set(a);
    enum nss_status st = lookup(name, &pw, buf, sizeof(buf));
    snprintf(msg, sizeof(msg), "%s -> NSS_STATUS_UNAVAIL", what);
    check(msg, st == NSS_STATUS_UNAVAIL);
    snprintf(msg, sizeof(msg), "  ... nothing in memory, nothing on disk");
    check(msg, !in_memory(name) && !on_disk(name, uid));
}

/* ── 1. required: only a verified answer is served or cached ─────────────── */
static void test_required(void)
{
    struct passwd pw;
    char buf[4096];
    mp_answer_t a;
    mp_seen_t s;

    printf("response_signing = required:\n");
    configure(conf_lines("required", g_jwks, 1));
    check("response_signing read from the file",
          g_config.response_signing == OB_RESPONSE_SIGNING_REQUIRED);

    a = plain_answer(DWHO);
    expect_refused("unsigned answer", &a, "dwho", 20001);
    s = mp_get_seen();
    check("  ... asked with Accept: " OB_JWS_MEDIA_TYPE " and an X-Nonce",
          s.requests >= 1 && strcmp(s.path, "/pam/userinfo") == 0
          && strcmp(s.accept, OB_JWS_MEDIA_TYPE) == 0 && s.nonce_count == 1);

    /*
     * Each case starts from empty caches, so one that wrongly caches does
     * not make the next ones look refused or served for the wrong reason.
     */
    static const struct {
        const char *what, *resp;
        int plain, rogue, signed_status;
        const char *kid, *aud, *endpoint, *body;
    } bent[] = {
        /* An unsigned "no such user" must not be negative-cached either. */
        { "unsigned found:false", NOUSER, .plain = 1 },
        { "forged (another key, known kid)", DWHO, .rogue = 1 },
        { "forged (unknown kid)", DWHO, .rogue = 1, .kid = "portal-sig-9" },
        { "signed found:true without aud", DWHO, .aud = "" },
        { "signed for another client", DWHO, .aud = "bastion-other" },
        { "signed for another endpoint", DWHO, .endpoint = "whoami" },
        { "HTTP 200 but signed for 404", DWHO, .signed_status = 404 },
        { "signed for another user's lookup (req_sha256)", DWHO,
          .body = "{ \"user\": \"mallory\" }" },
    };
    for (size_t i = 0; i < sizeof(bent) / sizeof(bent[0]); i++) {
        cache_reset();
        a = bent[i].plain ? plain_answer(bent[i].resp) : signed_answer(bent[i].resp);
        if (bent[i].rogue) a.key = k_rogue;
        if (bent[i].kid) a.kid = bent[i].kid;
        a.aud = bent[i].aud;
        a.endpoint = bent[i].endpoint;
        a.signed_status = bent[i].signed_status;
        a.signed_body = bent[i].body;
        expect_refused(bent[i].what, &a, "dwho", 20001);
    }

    printf("A properly signed answer:\n");
    cache_reset();
    a = signed_answer(DWHO);
    mp_set(&a);
    enum nss_status st = lookup("dwho", &pw, buf, sizeof(buf));
    check("signed found:true -> NSS_STATUS_SUCCESS", st == NSS_STATUS_SUCCESS);
    check("  ... with the signed uid", st == NSS_STATUS_SUCCESS && pw.pw_uid == 20001
          && strcmp(pw.pw_name, "dwho") == 0);
    check("  ... cached in memory and on disk", in_memory("dwho") && on_disk("dwho", 20001));

    /* dwho's answer, replayed for another lookup: other nonce, other body. */
    a.kind = MP_REPLAY;
    expect_refused("dwho's signed answer replayed for mallory", &a, "mallory", 0);
    check("  ... uid 20001 on disk is still dwho", strcmp(disk_name_of(20001), "dwho") == 0);

    /* The portal now answers garbage: dwho comes from the caches alone. */
    a = plain_answer(ROOTISH);
    mp_set(&a);
    st = lookup("dwho", &pw, buf, sizeof(buf));
    check("served again from the memory cache, portal not asked",
          st == NSS_STATUS_SUCCESS && pw.pw_uid == 20001 && mp_get_seen().requests == 0);
    memory_cache_reset();
    st = lookup("dwho", &pw, buf, sizeof(buf));
    check("served from the disk cache, portal not asked",
          st == NSS_STATUS_SUCCESS && pw.pw_uid == 20001 && mp_get_seen().requests == 0);

    printf("A signed \"no such user\":\n");
    a = signed_answer(NOUSER);
    mp_set(&a);
    st = lookup("nobody-here", &pw, buf, sizeof(buf));
    check("signed found:false -> NSS_STATUS_NOTFOUND", st == NSS_STATUS_NOTFOUND);
}

/* ── 2. required without the means to check: nothing is sent ────────────── */
static void test_required_unusable(void)
{
    struct passwd pw;
    char buf[4096];
    mp_answer_t a = signed_answer(DWHO);

    printf("required, but signed answers cannot be checked:\n");
    configure(conf_lines("required", g_no_jwks, 1));
    mp_set(&a);
    check("no JWKS -> NSS_STATUS_UNAVAIL",
          lookup("dwho", &pw, buf, sizeof(buf)) == NSS_STATUS_UNAVAIL);
    check("  ... no request sent, nothing cached",
          mp_get_seen().requests == 0 && !in_memory("dwho") && !on_disk("dwho", 20001));

    configure(conf_lines("required", g_jwks, 0));
    mp_set(&a);
    check("no client_id -> NSS_STATUS_UNAVAIL",
          lookup("dwho", &pw, buf, sizeof(buf)) == NSS_STATUS_UNAVAIL);
    check("  ... no request sent, nothing cached",
          mp_get_seen().requests == 0 && !in_memory("dwho") && !on_disk("dwho", 20001));

    configure(conf_lines("requried", g_jwks, 1));
    check("response_signing = requried (a typo) means required",
          g_config.response_signing == OB_RESPONSE_SIGNING_REQUIRED);
    a = plain_answer(DWHO);
    mp_set(&a);
    check("  ... and an unsigned answer is refused",
          lookup("dwho", &pw, buf, sizeof(buf)) == NSS_STATUS_UNAVAIL && !in_memory("dwho"));
}

/* ── 3. prefer and off ───────────────────────────────────────────────────── */
static void test_prefer_off(void)
{
    struct passwd pw;
    char buf[4096];
    mp_answer_t a;
    mp_seen_t s;
    enum nss_status st;

    printf("response_signing = prefer:\n");
    configure(conf_lines("prefer", g_jwks, 1));
    a = plain_answer(DWHO);
    mp_set(&a);
    st = lookup("dwho", &pw, buf, sizeof(buf));
    s = mp_get_seen();
    check("unsigned answer accepted", st == NSS_STATUS_SUCCESS && pw.pw_uid == 20001);
    check("  ... a signed one was asked for",
          strcmp(s.accept, OB_JWS_MEDIA_TYPE) == 0 && s.nonce_count == 1);

    cache_reset();
    a = signed_answer(DWHO);
    a.key = k_rogue;
    expect_refused("prefer: forged signed answer", &a, "dwho", 20001);

    printf("response_signing = off (and the default):\n");
    configure(conf_lines(NULL, g_jwks, 1));
    check("no response_signing line: off",
          g_config.response_signing == OB_RESPONSE_SIGNING_OFF);
    a = plain_answer(DWHO);
    mp_set(&a);
    st = lookup("dwho", &pw, buf, sizeof(buf));
    s = mp_get_seen();
    check("unsigned answer served", st == NSS_STATUS_SUCCESS && pw.pw_uid == 20001);
    check("  ... with neither Accept for a signed answer nor X-Nonce",
          strcmp(s.accept, OB_JWS_MEDIA_TYPE) != 0 && s.nonce_count == 0);

    cache_reset();
    a = signed_answer(DWHO);
    expect_refused("off: a signed answer nobody asked for", &a, "dwho", 20001);
}

int main(void)
{
    char cmd[256];

    curl_global_init(CURL_GLOBAL_DEFAULT);
    snprintf(g_jwks, sizeof(g_jwks), "%s/sso-jwks.json", base());
    snprintf(g_no_jwks, sizeof(g_no_jwks), "%s/missing-jwks.json", base());

    k_portal = tj_keygen("RSA");
    k_rogue = tj_keygen("RSA");
    char *jwk = tj_jwk(k_portal, KID, "\"use\":\"sig\",\"alg\":\"RS256\"");
    char jwks[4200];
    snprintf(jwks, sizeof(jwks), "{\"keys\":[%s]}\n", jwk);
    free(jwk);
    write_file(g_jwks, jwks, 0644);

    mp_start(CLIENT);

    printf("=== libnss_openbastion: signed /pam/userinfo answers (#339) ===\n\n");
    test_required();
    printf("\n");
    test_required_unusable();
    printf("\n");
    test_prefer_off();

    mp_stop();
    if (g_cache.entries) {
        for (size_t i = 0; i < g_cache.count; i++) {
            free(g_cache.entries[i].username);
            free(g_cache.entries[i].pw_buffer);
        }
        free(g_cache.entries);
    }
    config_reset();
    EVP_PKEY_free(k_portal);
    EVP_PKEY_free(k_rogue);
    curl_global_cleanup();
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base());
    if (system(cmd) != 0) {
        /* best effort */
    }
    printf("\n%s\n", failures == 0 ? "All tests passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
