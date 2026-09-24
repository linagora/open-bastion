/*
 * test_nss_force_shell.c - force_shell in libnss_openbastion (#293).
 *
 * On a host that records sessions, sshd runs the ForceCommand through the
 * login shell, and bash or zsh read the user's startup files before they run
 * it. force_shell makes the module hand out /usr/sbin/ob-login-shell instead,
 * which reads nothing of the user's. These tests pin that:
 *
 *   - the key is read from nss_openbastion.conf, and an unusable value falls
 *     back to the launcher, never to "no forcing";
 *   - it wins over the shell the portal supplies (zsh reads ~/.zshenv even
 *     for `zsh -c`) and over default_shell;
 *   - it applies on every path an entry is SERVED from: a portal answer, the
 *     on-disk cache (including a record written before the key was set), the
 *     in-memory cache, by name and by uid, and a local service account;
 *   - the in-memory copy sizes its buffer for the forced shell, not for the
 *     shell it stored.
 *
 * The module source is included, as in test_nss_cache.c, with the
 * configuration and cache paths redirected to a private directory. The portal
 * is a one-shot HTTP responder forked by the test itself.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

const char *test_cache_root(void);
const char *test_cache_byname(void);
const char *test_conf_path(void);
#define CACHE_DIR            test_cache_root()
#define CACHE_DIR_BYNAME     test_cache_byname()
#define CACHE_TRUSTED_UID    (getuid())
#define NSS_OB_CONF          test_conf_path()
#define NSS_CONF_TRUSTED_UID (getuid())

#include "../nss/libnss_openbastion.c"

static char g_base[128];
static int failures;

static const char *base(void)
{
    if (!g_base[0]) {
        snprintf(g_base, sizeof(g_base), "/tmp/ob_nss_force_shell_XXXXXX");
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

#define LAUNCHER DEFAULT_FORCE_SHELL

static void check_str(const char *what, const char *got, const char *want)
{
    if ((got == NULL && want == NULL) ||
        (got && want && strcmp(got, want) == 0)) {
        printf("  ok   %s -> %s\n", what, got ? got : "(unset)");
    } else {
        printf("  FAIL %s -> %s (expected %s)\n", what,
               got ? got : "(unset)", want ? want : "(unset)");
        failures++;
    }
}

static void check_int(const char *what, long got, long want)
{
    if (got == want) {
        printf("  ok   %s -> %ld\n", what, got);
    } else {
        printf("  FAIL %s -> %ld (expected %ld)\n", what, got, want);
        failures++;
    }
}

static void free_config(nss_llng_config_t *c)
{
    free(c->portal_url);
    free(c->server_token_file);
    free(c->server_token);
    free(c->default_shell);
    free(c->force_shell);
    free(c->default_home_base);
    free(c->service_accounts_file);
    memset(c, 0, sizeof(*c));
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

/* ── 1. The key is read, and an unusable value is not "no forcing" ─────── */
static const char *load_with(const char *force_line, nss_llng_config_t *c)
{
    char content[512];
    snprintf(content, sizeof(content),
             "portal_url = http://127.0.0.1:9\n"
             "default_shell = /bin/bash\n%s", force_line);
    write_file(test_conf_path(), content, 0644);
    memset(c, 0, sizeof(*c));
    load_config(c);          /* -1: no token here, but every key is parsed */
    return c->force_shell;
}

static void test_config_key(void)
{
    nss_llng_config_t c;

    printf("force_shell is read from nss_openbastion.conf:\n");
    check_str("no force_shell line", load_with("", &c), NULL);
    free_config(&c);
    check_str("force_shell = " LAUNCHER,
              load_with("force_shell = " LAUNCHER "\n", &c), LAUNCHER);
    free_config(&c);
    check_str("force_shell = \"/usr/local/sbin/site-shell\" (quoted)",
              load_with("force_shell = \"/usr/local/sbin/site-shell\"\n", &c),
              "/usr/local/sbin/site-shell");
    free_config(&c);

    printf("An unusable value forces the launcher, it does not turn forcing off:\n");
    static const char *const bad[] = {
        "force_shell =\n", "force_shell = bash\n",
        "force_shell = /usr/../bin/bash\n", "force_shell = /bin/bash;id\n",
        "force_shell = /bin/ba sh\n", "force_shell = /home/u/.sh\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char what[96];
        snprintf(what, sizeof(what), "%.*s", (int)strcspn(bad[i], "\n"), bad[i]);
        check_str(what, load_with(bad[i], &c), LAUNCHER);
        free_config(&c);
    }

    printf("A configuration someone else could write is refused whole:\n");
    write_file(test_conf_path(), "force_shell = /bin/bash\n", 0666);
    memset(&c, 0, sizeof(c));
    load_config(&c);
    check_str("0666 file: force_shell not taken from it", c.force_shell, NULL);
    free_config(&c);
}

/* ── 2. The portal's shell, default_shell, and force_shell ───────────────── */
static void test_select_login_shell(void)
{
    struct json_object *zsh = json_tokener_parse("{\"shell\":\"/bin/zsh\"}");
    struct json_object *evil = json_tokener_parse("{\"shell\":\"/tmp/sh\"}");
    struct json_object *none = json_tokener_parse("{}");

    printf("The login shell for a portal answer:\n");
    g_config.default_shell = (char *)"/bin/bash";
    g_config.force_shell = NULL;
    check_str("portal zsh, no force_shell", select_login_shell(zsh), "/bin/zsh");
    check_str("portal /tmp/sh, no force_shell", select_login_shell(evil), "/bin/bash");
    check_str("no portal shell, no force_shell", select_login_shell(none), "/bin/bash");
    g_config.force_shell = (char *)LAUNCHER;
    check_str("portal zsh, force_shell", select_login_shell(zsh), LAUNCHER);
    check_str("no portal shell, force_shell", select_login_shell(none), LAUNCHER);
    g_config.force_shell = NULL;
    g_config.default_shell = NULL;

    json_object_put(zsh);
    json_object_put(evil);
    json_object_put(none);
}

/* ── A portal: answers every POST with one fixed JSON body ──────────────── */
static pid_t g_portal_pid;

static int start_portal(const char *json)
{
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(s, 8) != 0 || getsockname(s, (struct sockaddr *)&a, &alen) != 0) {
        perror("portal socket");
        exit(1);
    }
    fflush(stdout);
    g_portal_pid = fork();
    if (g_portal_pid < 0) {
        perror("fork");
        exit(1);
    }
    if (g_portal_pid == 0) {
        for (;;) {
            int c = accept(s, NULL, NULL);
            char req[8192], resp[1024];
            size_t got = 0;
            long clen = -1;
            char *hdr_end = NULL;

            if (c < 0)
                _exit(0);
            /* Headers, then Content-Length bytes of body. */
            while (got < sizeof(req) - 1) {
                ssize_t r = read(c, req + got, sizeof(req) - 1 - got);
                if (r <= 0)
                    break;
                got += (size_t)r;
                req[got] = '\0';
                if (!hdr_end && (hdr_end = strstr(req, "\r\n\r\n")) != NULL) {
                    char *cl = strcasestr(req, "Content-Length:");
                    clen = cl ? strtol(cl + 15, NULL, 10) : 0;
                }
                if (hdr_end && (long)(got - (size_t)(hdr_end + 4 - req)) >= clen)
                    break;
            }
            int n = snprintf(resp, sizeof(resp),
                             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                             strlen(json), json);
            if (write(c, resp, (size_t)n) < 0) {
                /* the client went away; nothing to do */
            }
            close(c);
        }
    }
    close(s);
    return ntohs(a.sin_port);
}

static void stop_portal(void)
{
    if (g_portal_pid > 0) {
        kill(g_portal_pid, SIGKILL);
        waitpid(g_portal_pid, NULL, 0);
        g_portal_pid = 0;
    }
}

static void cache_reset(void)
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
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", test_cache_root());
    if (system(cmd) != 0) {
        /* best effort */
    }
}

static enum nss_status by_name(const char *name, struct passwd *pw, char *buf, size_t len)
{
    int err = 0;
    return _nss_openbastion_getpwnam_r(name, pw, buf, len, &err);
}

static enum nss_status by_uid(uid_t uid, struct passwd *pw, char *buf, size_t len)
{
    int err = 0;
    return _nss_openbastion_getpwuid_r(uid, pw, buf, len, &err);
}

/* ── 3. Every serving path ───────────────────────────────────────────────── */
static void test_serving_paths(void)
{
    char buf[4096], url[64];
    struct passwd pw;
    int port;

    /* A module that has "loaded" its configuration, with no file behind it. */
    port = start_portal("{\"found\":true,\"uid\":20001,\"gid\":20001,"
                        "\"gecos\":\"D Who\",\"home\":\"/home/dwho\","
                        "\"shell\":\"/bin/zsh\"}");
    snprintf(url, sizeof(url), "http://127.0.0.1:%d", port);
    g_config.portal_url = strdup(url);
    g_config.server_token = strdup("test-token");
    g_config.timeout = 5;
    g_config.verify_ssl = 1;
    g_config.cache_ttl = 300;
    g_config.min_uid = 10000;
    g_config.max_uid = 60000;
    g_config.min_gid = 1000;
    g_config.max_gid = 65533;
    g_config.default_gid = 100;
    g_config.default_shell = strdup("/bin/bash");
    g_config.default_home_base = strdup("/home");
    char sa[256];
    snprintf(sa, sizeof(sa), "%s/no-service-accounts.conf", base());
    g_config.service_accounts_file = strdup(sa);
    g_initialized = 1;

    printf("The portal supplies /bin/zsh:\n");
    cache_reset();
    g_config.force_shell = NULL;
    check_int("lookup without force_shell", by_name("dwho", &pw, buf, sizeof(buf)),
              NSS_STATUS_SUCCESS);
    check_str("  its shell (the control: the portal's zsh)", pw.pw_shell, "/bin/zsh");

    cache_reset();
    g_config.force_shell = strdup(LAUNCHER);
    check_int("lookup with force_shell", by_name("dwho", &pw, buf, sizeof(buf)),
              NSS_STATUS_SUCCESS);
    check_str("  its shell", pw.pw_shell, LAUNCHER);
    check_str("  getpwuid of it, from the in-memory cache",
              by_uid(20001, &pw, buf, sizeof(buf)) == NSS_STATUS_SUCCESS
              ? pw.pw_shell : "(lookup failed)", LAUNCHER);
    stop_portal();

    printf("A record on disk from before force_shell was set:\n");
    cache_reset();
    free(g_config.force_shell);
    g_config.force_shell = NULL;
    struct passwd old = {
        .pw_name = (char *)"alice", .pw_passwd = (char *)"x",
        .pw_uid = 20002, .pw_gid = 100, .pw_gecos = (char *)"",
        .pw_dir = (char *)"/home/alice", .pw_shell = (char *)"/bin/bash",
    };
    file_cache_save(&old);
    file_cache_save_by_name(&old);
    g_config.force_shell = strdup(LAUNCHER);
    /* The portal is gone: only the disk can answer. */
    check_str("getpwnam from the file cache",
              by_name("alice", &pw, buf, sizeof(buf)) == NSS_STATUS_SUCCESS
              ? pw.pw_shell : "(lookup failed)", LAUNCHER);
    cache_reset();
    file_cache_save(&old);
    check_str("getpwuid from the file cache",
              by_uid(20002, &pw, buf, sizeof(buf)) == NSS_STATUS_SUCCESS
              ? pw.pw_shell : "(lookup failed)", LAUNCHER);

    printf("An in-memory record stored with bash:\n");
    cache_reset();
    struct passwd mem = old;
    mem.pw_name = (char *)"bob";
    mem.pw_uid = 20003;
    cache_add("bob", &mem, 1);
    check_str("getpwnam from memory",
              by_name("bob", &pw, buf, sizeof(buf)) == NSS_STATUS_SUCCESS
              ? pw.pw_shell : "(lookup failed)", LAUNCHER);
    check_str("getpwuid from memory",
              by_uid(20003, &pw, buf, sizeof(buf)) == NSS_STATUS_SUCCESS
              ? pw.pw_shell : "(lookup failed)", LAUNCHER);

    /* Room for the stored entry with its "/bin/bash", not for the launcher:
     * the copy must ask for more room, not write past the buffer. */
    size_t tight = strlen("bob") + strlen("x") + strlen("") + strlen("/home/alice")
                   + strlen("/bin/bash") + 16;
    char *small = malloc(tight);
    check_int("getpwnam into a buffer sized for bash", by_name("bob", &pw, small, tight),
              NSS_STATUS_TRYAGAIN);
    check_int("getpwuid into a buffer sized for bash", by_uid(20003, &pw, small, tight),
              NSS_STATUS_TRYAGAIN);
    free(small);

    printf("A local service account (service-accounts.conf):\n");
    if (getuid() != 0) {
        /* The module takes that file only when it is root:root 0600. */
        printf("  --   not exercised unprivileged (the file must be root's)\n");
    } else {
        write_file(sa, "[svc]\nuid = 20004\ngid = 20004\nshell = /bin/bash\n", 0600);
        if (chown(sa, 0, 0) != 0) {
            perror("chown");
            failures++;
        }
        cache_reset();
        check_str("getpwnam of a service account",
                  by_name("svc", &pw, buf, sizeof(buf)) == NSS_STATUS_SUCCESS
                  ? pw.pw_shell : "(lookup failed)", LAUNCHER);
        unlink(sa);
    }

    cache_reset();
    free(g_config.force_shell);
    g_config.force_shell = NULL;
    free(g_config.portal_url);
    free(g_config.server_token);
    free(g_config.default_shell);
    free(g_config.default_home_base);
    free(g_config.service_accounts_file);
    memset(&g_config, 0, sizeof(g_config));
}

int main(void)
{
    char cmd[256];

    curl_global_init(CURL_GLOBAL_DEFAULT);
    printf("=== libnss_openbastion: force_shell (#293) ===\n\n");
    test_config_key();
    printf("\n");
    test_select_login_shell();
    printf("\n");
    test_serving_paths();

    if (g_cache.entries) {
        for (size_t i = 0; i < g_cache.count; i++) {
            free(g_cache.entries[i].username);
            free(g_cache.entries[i].pw_buffer);
        }
        free(g_cache.entries);
    }
    stop_portal();
    curl_global_cleanup();
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base());
    if (system(cmd) != 0) {
        /* best effort */
    }
    printf("\n%s\n", failures == 0 ? "All tests passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
