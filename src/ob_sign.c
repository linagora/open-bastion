/*
 * ob_sign.c - Request signing for the LLNG /pam/<endpoint> endpoints
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 *
 * The wire format and why this is shared code are documented in ob_sign.h.
 * The two generators below were the PAM client's private helpers until #247
 * needed them in ob-cert-daemon and in ob-sign-request as well.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "ob_sign.h"
#include "str_utils.h"

/* Stack buffer size for HMAC signature message building */
#define SIGNATURE_STACK_BUFFER_SIZE 512

/* Same line limit as config.c, so both readers agree on what fits. */
#define OB_SIGN_CONF_LINE 1024

void ob_sign_generate_nonce(char *nonce, size_t size)
{
    if (!nonce || size < OB_SIGN_NONCE_SIZE) {
        if (nonce && size > 0) nonce[0] = '\0';
        return;
    }

    /* Get timestamp in milliseconds */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long timestamp_ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    /* Generate UUID v4 using OpenSSL RAND_bytes (CSPRNG) */
    unsigned char uuid[16];
    if (RAND_bytes(uuid, sizeof(uuid)) != 1) {
        /* RAND_bytes failed - this is a critical error, but use timestamp as fallback */
        snprintf(nonce, size, "%lld", timestamp_ms);
        return;
    }

    /* Set version (4) and variant bits */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    snprintf(nonce, size,
             "%lld-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             timestamp_ms,
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5],
             uuid[6], uuid[7],
             uuid[8], uuid[9],
             uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

/*
 * Security (#188): the nonce MUST be part of the signed message. It is sent
 * in its own X-Nonce header for the server's replay window; if it were left
 * out of the HMAC an attacker could replay a captured request with a fresh
 * nonce and the signature would still verify, defeating replay protection.
 */
void ob_sign_compute(const char *secret,
                     long timestamp,
                     const char *nonce,
                     const char *method,
                     const char *path,
                     const char *body,
                     char *signature,
                     size_t sig_size)
{
    /*
     * `!*secret` as well as `!secret`: an empty key is not a secret. HMAC over
     * a zero-length key is well defined and forgeable by anyone, so the single
     * rule across this file is "empty counts as absent" -- the same answer
     * ob_sign_load_secret() gives for `request_signing_secret =`.
     */
    if (!secret || !*secret || !nonce || !*nonce || !method || !path
        || !signature || sig_size < OB_SIGN_SIGNATURE_SIZE) {
        if (signature && sig_size > 0) signature[0] = '\0';
        return;
    }

    /* Build message: timestamp.nonce.method.path.body
     * Use stack allocation for typical message sizes to avoid malloc overhead.
     * Typical: timestamp(~10) + nonce(~55) + method(~4) + path(~50) + body(~200)
     * < SIGNATURE_STACK_BUFFER_SIZE
     */
    char ts_str[32];
    snprintf(ts_str, sizeof(ts_str), "%ld", timestamp);

    size_t msg_len = strlen(ts_str) + 1 + strlen(nonce) + 1 + strlen(method) + 1 +
                     strlen(path) + 1 + (body ? strlen(body) : 0);

    /* Use stack buffer for small messages, heap for large ones */
    char stack_message[SIGNATURE_STACK_BUFFER_SIZE];
    char *message;
    bool heap_allocated = false;

    if (msg_len < sizeof(stack_message)) {
        message = stack_message;
    } else {
        message = malloc(msg_len + 1);
        if (!message) {
            signature[0] = '\0';
            return;
        }
        heap_allocated = true;
    }

    snprintf(message, msg_len + 1, "%s.%s.%s.%s.%s",
             ts_str, nonce, method, path, body ? body : "");

    /* Generate HMAC-SHA256 */
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    unsigned char *result = HMAC(EVP_sha256(), secret, strlen(secret),
                                  (unsigned char *)message, strlen(message),
                                  hmac, &hmac_len);

    /* Clear message buffer */
    explicit_bzero(message, msg_len + 1);
    if (heap_allocated) {
        free(message);
    }

    /* Check HMAC result */
    if (!result) {
        signature[0] = '\0';
        return;
    }

    /* Convert to hex string */
    if (hmac_len * 2 + 1 <= sig_size) {
        str_bytes_to_hex(hmac, hmac_len, signature);
    } else {
        signature[0] = '\0';
    }

    /* Clear HMAC buffer */
    explicit_bzero(hmac, sizeof(hmac));
}

/* Trim leading and trailing whitespace in place; returns the new start. */
static char *ob_sign_trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

/*
 * Strip one layer of matching quotes, mirroring strip_quotes() in config.c:
 * the opening quote must be the first character, and the value ends at the
 * LAST occurrence of that same quote.
 */
static char *ob_sign_strip_quotes(char *value)
{
    if (*value != '"' && *value != '\'') {
        return value;
    }
    char quote = *value;
    value++;
    char *end = strrchr(value, quote);
    if (end) *end = '\0';
    return value;
}

/*
 * Refuse a config file that a non-owner could have written, on the opened fd
 * so the answer cannot be swapped underneath us. Accepting an euid-owned file
 * as well as a root-owned one is what lets the test suite exercise this
 * without root; in production every caller is root and the two coincide.
 */
static int ob_sign_check_fd(int fd)
{
    struct stat st;

    if (fstat(fd, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;
    if (st.st_uid != 0 && st.st_uid != geteuid()) return -1;
    if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) return -1;

    return 0;
}

/* Free a loaded value, wiping it first: the signing secret goes through here. */
static void ob_sign_drop(char **value)
{
    if (*value) {
        explicit_bzero(*value, strlen(*value));
        free(*value);
        *value = NULL;
    }
}

int ob_sign_load_settings(const char *conf_path, char **secret, char **cert_pin)
{
    if (!conf_path || (!secret && !cert_pin)) return -1;
    if (secret) *secret = NULL;
    if (cert_pin) *cert_pin = NULL;

    int fd = open(conf_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    if (ob_sign_check_fd(fd) != 0) {
        close(fd);
        return -1;
    }

    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return -1;
    }

    char line[OB_SIGN_CONF_LINE];
    int rc = 0;

    while (fgets(line, sizeof(line), f)) {
        /*
         * A line that filled the buffer without a newline was truncated. For
         * any other key that is someone else's problem, but truncating one of
         * THESE values yields a wrong secret -- a signature the portal refuses
         * -- or a wrong pin -- a portal this host refuses. Either failure
         * looks like a portal problem and is not. Refuse to guess.
         */
        bool complete = (strchr(line, '\n') != NULL) || feof(f);

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';

        char *key = ob_sign_trim(line);
        if (*key == '#' || *key == ';') continue;

        char **out = NULL;
        if (secret && strcmp(key, "request_signing_secret") == 0) {
            out = secret;
        } else if (cert_pin && strcmp(key, "cert_pin") == 0) {
            out = cert_pin;
        } else {
            continue;
        }

        if (!complete) {
            rc = -1;
            break;
        }

        /*
         * No inline-comment stripping: '#' is an ordinary character in a
         * generated secret, and config.c exempts these exact keys for the
         * same reason (key_holds_opaque_secret).
         */
        char *value = ob_sign_strip_quotes(ob_sign_trim(eq + 1));

        /* Last assignment wins, as in config.c; empty counts as absent. */
        ob_sign_drop(out);
        if (*value) {
            *out = strdup(value);
            if (!*out) {
                rc = -1;
                break;
            }
        }
    }

    explicit_bzero(line, sizeof(line));
    fclose(f);

    if (rc != 0) {
        if (secret) ob_sign_drop(secret);
        if (cert_pin) ob_sign_drop(cert_pin);
    }

    return rc;
}

int ob_sign_load_secret(const char *conf_path, char **secret)
{
    if (!secret) return -1;
    if (ob_sign_load_settings(conf_path, secret, NULL) != 0) return -1;
    return *secret ? 0 : 1;
}
