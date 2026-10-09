/*
 * jws-sign-fixture - plays the portal's signing side for the shell tests of
 * the signed answers (#339): tests/mock_portal_signed.py calls it to sign
 * what it answers, and tests/test_ob_verify_response.sh to make keys.
 *
 * Signs with OpenSSL through tests/jws_test_util.h, the same helper the C
 * tests use -- never with the code under test.
 *
 *   jws-sign-fixture keygen KIND OUT.pem     RSA, RSA1024, P-256, P-384,
 *                                            P-521 or ED25519
 *   jws-sign-fixture jwk KEY.pem KID         the public JWK, on stdout
 *   jws-sign-fixture sign KEY.pem ALG KID    payload JSON on stdin, the
 *                                            compact JWS on stdout
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>

#include "jws_test_util.h"

static EVP_PKEY *load_key(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        exit(1);
    }
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) {
        fprintf(stderr, "%s: not a private key\n", path);
        exit(1);
    }
    return k;
}

static char *read_stdin(void)
{
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    size_t n;
    if (!buf) abort();
    while ((n = fread(buf + len, 1, cap - len - 1, stdin)) > 0) {
        len += n;
        if (len + 1 == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
            if (!buf) abort();
        }
    }
    buf[len] = '\0';
    return buf;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "keygen") == 0) {
        EVP_PKEY *k = tj_keygen(argv[2]);
        FILE *f = fopen(argv[3], "w");
        if (!f || PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL) != 1) {
            perror(argv[3]);
            return 1;
        }
        fclose(f);
        EVP_PKEY_free(k);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "jwk") == 0) {
        EVP_PKEY *k = load_key(argv[2]);
        char *jwk = tj_jwk(k, argv[3], NULL);
        printf("%s\n", jwk);
        free(jwk);
        EVP_PKEY_free(k);
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "sign") == 0) {
        EVP_PKEY *k = load_key(argv[2]);
        char *payload = read_stdin();
        char *jws = tj_sign(k, argv[3], argv[4], payload);
        printf("%s", jws);
        free(jws);
        free(payload);
        EVP_PKEY_free(k);
        return 0;
    }
    fprintf(stderr,
            "usage: jws-sign-fixture keygen KIND OUT.pem\n"
            "       jws-sign-fixture jwk KEY.pem KID\n"
            "       jws-sign-fixture sign KEY.pem ALG KID < payload\n");
    return 2;
}
