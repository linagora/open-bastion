/*
 * test_nss_home_prefixes.c - The NSS module must apply the same approved shells
 * and home prefixes as the PAM module (#404).
 *
 * Both modules validate a portal-supplied home and shell, but the NSS module
 * used the built-in lists whatever the configuration said. On a host with
 * `approved_home_prefixes = /srv/home`, PAM accepted /srv/home/dwho and NSS
 * refused it, answering `default_home_base/dwho`: getpwnam() and the login
 * session then disagreed on $HOME, which shows up as a missing directory or a
 * wrong $HOME and is hard to attribute.
 *
 * NSS reads its own file, so the two list keys live in nss_openbastion.conf.
 * The test redirects NSS_OB_CONF to a throwaway file and NSS_CONF_TRUSTED_UID
 * to the uid running the suite, so the loader's real ownership and permission
 * checks apply to a file this test owns.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifndef OB_TEST_NSS_CONF
#error "OB_TEST_NSS_CONF must name the throwaway configuration file"
#endif
#define NSS_OB_CONF OB_TEST_NSS_CONF
#define NSS_CONF_TRUSTED_UID ((uid_t)geteuid())

#include "../nss/libnss_openbastion.c"

static int failures = 0;

static void check(const char *what, int ok)
{
    if (ok) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

static int write_conf(const char *text)
{
    size_t len = strlen(text);
    ssize_t written;

    int fd = open(NSS_OB_CONF, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    written = write(fd, text, len);
    close(fd);

    return written == (ssize_t)len ? 0 : -1;
}

static void reset_lists(void)
{
    free(g_config.approved_shells);
    free(g_config.approved_home_prefixes);
    free(g_config.default_home_base);
    g_config.approved_shells = NULL;
    g_config.approved_home_prefixes = NULL;
    g_config.default_home_base = NULL;
}

int main(void)
{
    printf("NSS approved shells and home prefixes (#404)\n");
    printf("===========================================\n\n");

    if (write_conf(
            "portal_url = https://sso.example.com\n"
            "approved_home_prefixes = /srv/home:/data/users\n"
            "approved_shells = /usr/local/bin/zsh\n"
            "home_base = /srv/home\n") != 0) {
        printf("  FAIL cannot write %s\n", NSS_OB_CONF);
        return 1;
    }

    /* load_config() returns -1 without a server token; the parsing still ran. */
    (void)load_config(&g_config);

    check("approved_home_prefixes is read from nss_openbastion.conf",
          g_config.approved_home_prefixes != NULL &&
          strcmp(g_config.approved_home_prefixes, "/srv/home:/data/users") == 0);
    check("approved_shells is read from nss_openbastion.conf",
          g_config.approved_shells != NULL &&
          strcmp(g_config.approved_shells, "/usr/local/bin/zsh") == 0);
    check("the setup's `home_base` alias sets the home base",
          g_config.default_home_base != NULL &&
          strcmp(g_config.default_home_base, "/srv/home") == 0);

    check("a home under an approved prefix is accepted",
          validate_home("/srv/home/dwho") == 0);
    check("a home outside the configured list is refused",
          validate_home("/home/dwho") == -1);
    check("a shell in the configured list is accepted",
          validate_shell("/usr/local/bin/zsh") == 0);
    check("a shell outside the configured list is refused",
          validate_shell("/bin/bash") == -1);

    reset_lists();

    if (write_conf("portal_url = https://sso.example.com\n") != 0) {
        printf("  FAIL cannot rewrite %s\n", NSS_OB_CONF);
        return 1;
    }

    (void)load_config(&g_config);

    check("without the keys, the built-in home list still applies",
          validate_home("/home/dwho") == 0);
    check("without the keys, the built-in shell list still applies",
          validate_shell("/bin/bash") == 0);

    unlink(NSS_OB_CONF);

    printf("\n%s\n", failures == 0 ? "All tests passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
