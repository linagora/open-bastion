/*
 * test_pam_acct_cache.c - The PAM account phase and the offline cache.
 *
 * A cached authorization may answer only when the portal is unreachable. An
 * authoritative refusal (HTTP 400/401/403/5xx, an untrusted answer) or an
 * online denial must never be overridden by the cache, and an online denial
 * must delete the entry: otherwise a user revoked in the portal keeps logging
 * in, `sudo` right included, until the entry expires.
 *
 * Drives the real pam_sm_acct_mgmt() against mock_portal.h. The module source
 * is included so the test can build the module data (client, cache,
 * configuration) and hand it to the module's pam_get_data() lookup.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

/* Redirect the fingerprint spool before the module sees its default. */
#define OB_SSH_FP_SPOOL_DIR "/nonexistent/open-bastion-test-ssh-fp"

#include "../src/pam_openbastion.c"

#include <security/pam_appl.h>
#include <unistd.h>

#include "ob_jws.h"
#include "mock_portal.h"

#define AUTHZ_OK   "{\"authorized\":true,\"user\":\"dwho\"," \
                   "\"permissions\":{\"sudo_allowed\":true}," \
                   "\"offline\":{\"enabled\":true,\"ttl\":3600}}"
#define AUTHZ_NO   "{\"authorized\":false,\"reason\":\"revoked\"}"
#define AUTHZ_NO_OFFLINE "{\"authorized\":true,\"user\":\"dwho\"," \
                         "\"permissions\":{\"sudo_allowed\":true}}"

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
static char g_cache_dir[128];
static char g_host[256];

/*
 * A PAM application cannot call pam_set_data() (Linux-PAM reserves it for
 * modules), so the module's pam_get_data() lookup is wrapped instead. This is
 * the same handle a real pam_sm_authenticate would have populated.
 */
static pam_openbastion_data_t *g_data;

int __real_pam_get_data(pam_handle_t *pamh, const char *name, const void **data);

int __wrap_pam_get_data(pam_handle_t *pamh, const char *name, const void **data)
{
    if (g_data && strcmp(name, PAM_OPENBASTION_DATA) == 0) {
        *data = g_data;
        return PAM_SUCCESS;
    }
    return __real_pam_get_data(pamh, name, data);
}

static int no_conversation(int num_msg, const struct pam_message **msg,
                           struct pam_response **resp, void *appdata_ptr)
{
    (void)num_msg; (void)msg; (void)resp; (void)appdata_ptr;
    return PAM_CONV_ERR;
}

static ob_client_t *client_at(unsigned port)
{
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u", port);
    ob_client_config_t cc = {
        .portal_url = url,
        .client_id = "bastion-test",
        .client_secret = "client-secret",
        .server_token = "server-access-token",
        .server_group = "default",
        .timeout = 5,
        .verify_ssl = false,
        .response_signing = OB_RESPONSE_SIGNING_OFF,
    };
    return ob_client_init(&cc);
}

static void install_client(pam_openbastion_data_t *data, unsigned port)
{
    if (data->client) ob_client_destroy(data->client);
    data->client = client_at(port);
}

/* A port that was bound and closed: connecting to it is refused. */
static unsigned closed_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    if (fd < 0) return 1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0
        || getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return 1;
    }
    close(fd);
    return ntohs(a.sin_port);
}

static pam_openbastion_data_t *module_data(pam_handle_t *pamh, unsigned port)
{
    (void)pamh;
    pam_openbastion_data_t *data = calloc(1, sizeof(*data));
    if (!data) return NULL;

    config_init(&data->config);
    data->config.server_group = strdup("default");
    data->config.auth_cache_dir = strdup(g_cache_dir);
    data->client = client_at(port);
    data->auth_cache = auth_cache_init(g_cache_dir);

    if (!data->client) {
        fprintf(stderr, "  client init failed\n");
    } else if (!data->auth_cache) {
        fprintf(stderr, "  auth_cache_init failed (%s)\n", g_cache_dir);
    } else {
        g_data = data;
        return data;
    }
    if (data->client) ob_client_destroy(data->client);
    if (data->auth_cache) auth_cache_destroy(data->auth_cache);
    config_free(&data->config);
    free(data);
    return NULL;
}

static void seed_grant(pam_openbastion_data_t *data)
{
    auth_cache_entry_t entry = {
        .version = 4,
        .user = (char *)"dwho",
        .authorized = true,
        .sudo_allowed = true,
    };
    if (auth_cache_store(data->auth_cache, "dwho", data->config.server_group,
                         g_host, &entry, 3600) != 0) {
        printf("  FAIL cannot seed the authorization cache\n");
        exit(1);
    }
}

static bool has_cached_grant(pam_openbastion_data_t *data)
{
    auth_cache_entry_t entry = {0};
    bool found = auth_cache_lookup(data->auth_cache, "dwho",
                                   data->config.server_group, g_host, &entry);
    if (found) auth_cache_entry_free(&entry);
    return found;
}

static int account_phase(pam_handle_t *pamh)
{
    return pam_sm_acct_mgmt(pamh, 0, 0, NULL);
}

static void answer(int status, const char *body)
{
    mp_answer_t a = { .kind = MP_PLAIN, .status = status, .resp = body };
    mp_set(&a);
}

int main(void)
{
    char cmd[128];
    struct stat st;

    if (stat("/etc/machine-id", &st) != 0) {
        printf("SKIP: no /etc/machine-id, the authorization cache cannot be keyed\n");
        return 77;
    }

    snprintf(g_dir, sizeof(g_dir), "/tmp/pam_acct_cache_XXXXXX");
    if (!mkdtemp(g_dir)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(g_cache_dir, sizeof(g_cache_dir), "%s/auth-cache", g_dir);
    if (gethostname(g_host, sizeof(g_host) - 1) != 0) {
        snprintf(g_host, sizeof(g_host), "test-host");
    }

    mp_start("bastion-test");

    struct pam_conv conv = { no_conversation, NULL };
    pam_handle_t *pamh = NULL;
    if (pam_start("sshd", "dwho", &conv, &pamh) != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed\n");
        return 1;
    }
    pam_openbastion_data_t *data = module_data(pamh, (unsigned)mp.port);
    if (!data) {
        fprintf(stderr, "cannot install module data\n");
        return 1;
    }

    printf("=== PAM account phase: refusals vs the offline cache ===\n\n");

    printf("An online grant is cached:\n");
    answer(200, AUTHZ_OK);
    CHECK(account_phase(pamh) == PAM_SUCCESS, "200 authorized is a success");
    CHECK(has_cached_grant(data), "  ... and fills the offline cache");

    printf("\nAuthoritative refusals do not fall back to the cache:\n");
    answer(400, "{\"error\":\"SSH fingerprint required\"}");
    CHECK(account_phase(pamh) == PAM_PERM_DENIED, "400 is denied, not served from cache");
    answer(403, "{\"error\":\"server not enrolled\"}");
    CHECK(account_phase(pamh) == PAM_PERM_DENIED, "403 is denied, not served from cache");
    answer(500, "{\"error\":\"boom\"}");
    CHECK(account_phase(pamh) == PAM_PERM_DENIED, "500 is denied, not served from cache");

    printf("\nAn online denial deletes the entry:\n");
    answer(200, AUTHZ_NO);
    CHECK(account_phase(pamh) == PAM_PERM_DENIED, "authorized:false is denied");
    CHECK(!has_cached_grant(data), "  ... and purges the cached grant");

    install_client(data, closed_port());
    CHECK(account_phase(pamh) == PAM_AUTHINFO_UNAVAIL,
          "a later outage finds no entry to replay");

    printf("\nAn outage still serves a cached grant:\n");
    install_client(data, (unsigned)mp.port);
    seed_grant(data);
    answer(503, "{\"error\":\"gateway\"}");
    CHECK(account_phase(pamh) == PAM_SUCCESS, "503 still uses the cache");
    CHECK(has_cached_grant(data), "  ... and keeps the entry");

    install_client(data, closed_port());
    CHECK(account_phase(pamh) == PAM_SUCCESS,
          "a closed portal still uses the cache");

    printf("\nWithdrawing offline mode deletes the entry:\n");
    install_client(data, (unsigned)mp.port);
    answer(200, AUTHZ_NO_OFFLINE);
    CHECK(account_phase(pamh) == PAM_SUCCESS, "online grant without offline is a success");
    CHECK(!has_cached_grant(data), "  ... but purges the previous entry");

    install_client(data, closed_port());
    CHECK(account_phase(pamh) == PAM_AUTHINFO_UNAVAIL,
          "a later outage has nothing left to replay");

    pam_end(pamh, PAM_SUCCESS);
    cleanup_data(pamh, g_data, 0);
    g_data = NULL;
    mp_stop();

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) {
        /* best effort */
    }

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
