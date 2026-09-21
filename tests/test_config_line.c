/*
 * test_config_line.c - Line syntax of openbastion.conf: inline comments and
 * quoting.
 *
 * Why this test exists: the #183 fix made an unrecognised boolean a fatal
 * error (config_validate() -> -6, PAM module refuses to start, every SSH and
 * sudo authentication on the host denied). Before the fix, only full-line
 * comments were stripped, so `verify_ssl = true # prod` produced the
 * unrecognised value "true # prod" -> silently false. After the fix that same
 * line would have become fatal, and an upgrade could have locked an operator
 * out of a bastion over a comment.
 *
 * The parser now strips inline comments, with a rule narrow enough that it can
 * never truncate a legitimate value (a secret, a URL fragment). These tests
 * pin both halves of that contract.
 *
 * config_load() insists on a root-owned 0600 file, which CI cannot produce, so
 * we include config.c directly (the test_nss_cache.c pattern) and drive the
 * per-line parser that config_load() itself uses.
 */

#include "../src/config.c"

#include <stdio.h>

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  ok   %s\n", (msg)); \
    } else { \
        printf("  FAIL %s\n", (msg)); \
    } \
} while (0)

/* Feed one raw config line to the real parser and return the config. */
static void feed(pam_openbastion_config_t *config, const char *raw)
{
    char line[1024];
    snprintf(line, sizeof(line), "%s", raw);
    parse_config_file_line(line, config, "test.conf");
}

static void with_config(const char *raw,
                        void (*assertion)(pam_openbastion_config_t *))
{
    pam_openbastion_config_t config;
    config_init(&config);
    feed(&config, raw);
    assertion(&config);
    config_free(&config);
}

/* ---- booleans: an inline comment must not make the line fatal ---- */

static void assert_true_not_latched(pam_openbastion_config_t *c)
{
    CHECK(c->verify_ssl == true && c->invalid_bool_value == false,
          "verify_ssl = true # prod        -> true, not a fatal config");
}

static void assert_false_not_latched(pam_openbastion_config_t *c)
{
    CHECK(c->verify_ssl == false && c->invalid_bool_value == false,
          "verify_ssl = false  # lab       -> false, not a fatal config");
}

static void assert_tab_comment(pam_openbastion_config_t *c)
{
    CHECK(c->verify_ssl == false && c->invalid_bool_value == false,
          "verify_ssl = false\\t# tab       -> false, not a fatal config");
}

static void assert_quoted_then_comment(pam_openbastion_config_t *c)
{
    CHECK(c->verify_ssl == true && c->invalid_bool_value == false,
          "verify_ssl = \"true\" # prod      -> true, not a fatal config");
}

/* ---- a real typo must STILL be fatal: stripping must not soften #183 ---- */

static void assert_typo_still_fatal(pam_openbastion_config_t *c)
{
    CHECK(c->verify_ssl == true && c->invalid_bool_value == true,
          "verify_ssl = TRUE # prod        -> still fatal (default kept)");
}

static void assert_comment_only_value_fatal(pam_openbastion_config_t *c)
{
    CHECK(c->verify_ssl == true && c->invalid_bool_value == true,
          "verify_ssl = # nothing          -> still fatal (empty value)");
}

/* ---- values that legitimately contain '#' must survive intact ---- */

static void assert_secret_preserved(pam_openbastion_config_t *c)
{
    CHECK(c->client_secret && strcmp(c->client_secret, "s3cr3t # not a comment") == 0,
          "client_secret = s3cr3t # ...    -> preserved verbatim (secret key)");
}

static void assert_password_preserved(pam_openbastion_config_t *c)
{
    CHECK(c->crowdsec_password && strcmp(c->crowdsec_password, "pw #1 for prod") == 0,
          "crowdsec_password = pw #1 ...   -> preserved verbatim (secret key)");
}

static void assert_url_fragment_preserved(pam_openbastion_config_t *c)
{
    CHECK(c->portal_url && strcmp(c->portal_url, "https://sso.example.com/#frag") == 0,
          "portal_url = https://x/#frag    -> '#' not preceded by space, kept");
}

static void assert_hash_inside_token_preserved(pam_openbastion_config_t *c)
{
    CHECK(c->server_group && strcmp(c->server_group, "prod#2") == 0,
          "server_group = prod#2           -> '#' inside a token, kept");
}

static void assert_quoted_hash_preserved(pam_openbastion_config_t *c)
{
    CHECK(c->server_group && strcmp(c->server_group, "prod # 2") == 0,
          "server_group = \"prod # 2\"       -> quoted, '#' kept");
}

static void assert_non_secret_stripped(pam_openbastion_config_t *c)
{
    CHECK(c->server_group && strcmp(c->server_group, "prod") == 0,
          "server_group = prod # site A    -> stripped and re-trimmed");
}

static void assert_quoted_value_then_comment(pam_openbastion_config_t *c)
{
    CHECK(c->server_group && strcmp(c->server_group, "prod") == 0,
          "server_group = \"prod\" # note    -> ends at the closing quote");
}

/* ---- no regression on the ordinary cases ---- */

static void assert_plain_value(pam_openbastion_config_t *c)
{
    CHECK(c->server_group && strcmp(c->server_group, "production") == 0,
          "server_group = production       -> unchanged");
}

static void assert_full_line_comment_ignored(pam_openbastion_config_t *c)
{
    /* config_init() default is "default"; the commented line must not apply */
    CHECK(c->server_group && strcmp(c->server_group, "default") == 0,
          "# server_group = hacked         -> full-line comment ignored");
}

/*
 * PAM-argument path: config_parse_args() now strips quotes like config_load()
 * does, so `ssh_cert_aware="true"` in a pam.d line is no longer a fatal
 * invalid boolean.
 */
static void test_pam_args_quotes(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = { "verify_ssl=\"true\"", "server_group='prod'" };
    config_parse_args(2, argv, &config);

    CHECK(config.verify_ssl == true && config.invalid_bool_value == false,
          "pam.d: verify_ssl=\"true\"        -> true, not a fatal config");
    CHECK(config.server_group && strcmp(config.server_group, "prod") == 0,
          "pam.d: server_group='prod'      -> quotes stripped");

    config_free(&config);
}

/* An unquoted '#' in a PAM argument is a value, not a comment. */
static void test_pam_args_no_comment_stripping(void)
{
    pam_openbastion_config_t config;
    config_init(&config);

    const char *argv[] = { "server_group=prod # x" };
    config_parse_args(1, argv, &config);

    CHECK(config.server_group && strcmp(config.server_group, "prod # x") == 0,
          "pam.d: server_group=prod # x    -> kept (no comments in pam.d)");

    config_free(&config);
}

/*
 * ---- unknown keys are reported, not silently swallowed (#229) ----
 *
 * doc/security/02-ssh-connection.rst told operators to set
 * `auth_cache_offline_ttl`, a key the parser never knew; the setting was
 * dropped without a word and the 7-day default silently applied. parse_line()
 * now says so, and config_load() turns that into a syslog warning.
 */
static int classify(const char *raw)
{
    pam_openbastion_config_t config;
    config_init(&config);

    char line[1024];
    snprintf(line, sizeof(line), "%s", raw);
    char *trimmed = trim(line);
    char *eq = strchr(trimmed, '=');
    int rc;
    if (!eq) {
        rc = -1;
    } else {
        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);
        rc = parse_line(key, strip_quotes(value), &config);
    }

    config_free(&config);
    return rc;
}

static void test_unknown_keys(void)
{
    CHECK(classify("auth_cache_offline_ttl = 86400") == PARSE_LINE_UNKNOWN_KEY,
          "auth_cache_offline_ttl        -> reported unknown (the #229 typo)");
    CHECK(classify("auth_cache_ttl = 3600") == PARSE_LINE_UNKNOWN_KEY,
          "auth_cache_ttl                -> reported unknown (same doc, no such key)");
    CHECK(classify("verify_ssl = true") == 0,
          "verify_ssl                    -> recognised");
    CHECK(classify("auth_cache = true") == 0,
          "auth_cache                    -> recognised");
#ifdef ENABLE_DESKTOP_SSO
    /*
     * offline_cache_ttl is the desktop-SSO credential cache, compiled in only
     * with INSTALL_DESKTOP=ON (the Debian package). In a core build the key is
     * genuinely inert, and reporting it is the honest answer.
     */
    CHECK(classify("offline_cache_ttl = 86400") == 0,
          "offline_cache_ttl             -> recognised (desktop build)");
#else
    CHECK(classify("offline_cache_ttl = 86400") == PARSE_LINE_UNKNOWN_KEY,
          "offline_cache_ttl             -> reported unknown (core build)");
#endif

    /*
     * Every key this project's own tooling writes into openbastion.conf must
     * be accepted. config_load() runs once per PAM process, so a key that
     * ob-bastion-setup or ob-backend-setup emits and this parser rejects costs
     * a syslog warning on every single login of every deployed host -- which
     * would bury the one typo the whole change exists to surface.
     */
    CHECK(classify("cache_enabled = true") == 0,
          "cache_enabled                 -> accepted (written by both setups)");
    CHECK(classify("cache_dir = /var/cache/open-bastion") == 0,
          "cache_dir                     -> accepted (written by both setups)");
    CHECK(classify("cache_ttl = 300") == 0,
          "cache_ttl                     -> accepted (both setups; live in NSS conf)");
    CHECK(classify("create_home = true") == 0,
          "create_home                   -> accepted (written by ob-backend-setup)");
    CHECK(classify("default_shell = /bin/bash") == 0,
          "default_shell                 -> accepted (backend setup; live in NSS conf)");

    /* openbastion.conf is shared with ob-heartbeat(8): its keys are not typos. */
    CHECK(classify("node_role = bastion") == 0,
          "node_role                     -> accepted (ob-heartbeat key)");
    CHECK(classify("report_sessions = true") == 0,
          "report_sessions               -> accepted (ob-heartbeat key)");
    CHECK(classify("max_reported_sessions = 50") == 0,
          "max_reported_sessions         -> accepted (ob-heartbeat key)");
}

int main(void)
{
    printf("Running openbastion.conf line-syntax tests...\n\n");

    printf("Inline comments must not turn a valid boolean into a fatal error:\n");
    with_config("verify_ssl = true # prod", assert_true_not_latched);
    with_config("verify_ssl = false  # lab", assert_false_not_latched);
    with_config("verify_ssl = false\t# tab", assert_tab_comment);
    with_config("verify_ssl = \"true\" # prod", assert_quoted_then_comment);

    printf("\nA genuine typo stays fatal (#183 is not softened):\n");
    with_config("verify_ssl = TRUE # prod", assert_typo_still_fatal);
    with_config("verify_ssl = # nothing", assert_comment_only_value_fatal);

    printf("\nValues that legitimately contain '#' are preserved:\n");
    with_config("client_secret = s3cr3t # not a comment", assert_secret_preserved);
    with_config("crowdsec_password = pw #1 for prod", assert_password_preserved);
    with_config("portal_url = https://sso.example.com/#frag", assert_url_fragment_preserved);
    with_config("server_group = prod#2", assert_hash_inside_token_preserved);
    with_config("server_group = \"prod # 2\"", assert_quoted_hash_preserved);

    printf("\nInline comments are stripped from ordinary keys:\n");
    with_config("server_group = prod # site A", assert_non_secret_stripped);
    with_config("server_group = \"prod\" # note", assert_quoted_value_then_comment);

    printf("\nNo regression on ordinary lines:\n");
    with_config("server_group = production", assert_plain_value);
    with_config("# server_group = hacked", assert_full_line_comment_ignored);

    printf("\nPAM module arguments:\n");
    test_pam_args_quotes();
    test_pam_args_no_comment_stripping();

    printf("\nUnknown keys are reported instead of silently ignored (#229):\n");
    test_unknown_keys();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
