/*
 * pam_stack_probe — run pam_authenticate() against a PAM stack in a directory.
 *
 *   usage: pam_stack_probe <confdir> <service> [user] [auth|account]
 *
 * The fourth argument picks the phase: pam_authenticate() (the default) or
 * pam_acct_mgmt(), for the account stacks (#359).
 *
 * Prints the numeric PAM return code on stdout (nothing else) and exits 0, so
 * a shell test can compare it against the expected verdict. Exits 2 if
 * pam_start_confdir() itself fails.
 *
 * Why this exists: tests/test_ob_pam_stacks.sh checks the *text* of the stacks
 * Open Bastion generates, and text is not behaviour. The
 * "auth [success=1 default=ignore] pam_permit.so" + "auth required pam_deny.so"
 * pair reads like "permit, with a backstop" but actually denies every
 * pam_authenticate(): per pam.conf(5) the jump action's side effect is *ignore*,
 * so the jump clears pam_deny, lands past the end of the stack with no positive
 * impression recorded, and pam_dispatch returns PAM_PERM_DENIED. Only running
 * the stack catches that. See tests/test_ob_pam_runtime.sh.
 *
 * The conversation function answers every prompt with an empty response, which
 * is enough for the stock modules (pam_permit / pam_deny) the certificate-mode
 * stacks are built from.
 */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int probe_conv(int num_msg, const struct pam_message **msg,
                      struct pam_response **resp, void *appdata)
{
    struct pam_response *r;
    int i;

    (void)msg;
    (void)appdata;

    if (num_msg <= 0)
        return PAM_CONV_ERR;

    r = calloc((size_t)num_msg, sizeof(*r));
    if (r == NULL)
        return PAM_BUF_ERR;
    for (i = 0; i < num_msg; i++) {
        r[i].resp = strdup("");
        if (r[i].resp == NULL) {
            while (--i >= 0)
                free(r[i].resp);
            free(r);
            return PAM_BUF_ERR;
        }
    }
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { probe_conv, NULL };
    const char *user;
    int account;
    int rc;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <confdir> <service> [user] [auth|account]\n",
                argv[0]);
        return 2;
    }
    user = (argc > 3) ? argv[3] : "obpamtest";
    if (argc > 4 && strcmp(argv[4], "account") == 0) {
        account = 1;
    } else if (argc > 4 && strcmp(argv[4], "auth") != 0) {
        fprintf(stderr, "unknown phase: %s\n", argv[4]);
        return 2;
    } else {
        account = 0;
    }

    rc = pam_start_confdir(argv[2], user, &conv, argv[1], &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_start_confdir(%s, %s) failed: %d\n",
                argv[1], argv[2], rc);
        return 2;
    }

    rc = account ? pam_acct_mgmt(pamh, 0) : pam_authenticate(pamh, 0);
    printf("%d\n", rc);
    fprintf(stderr, "%s/%s: %s -> %d (%s)\n", argv[1], argv[2],
            account ? "pam_acct_mgmt" : "pam_authenticate",
            rc, pam_strerror(pamh, rc));
    pam_end(pamh, rc);
    return 0;
}
