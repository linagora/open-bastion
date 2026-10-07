/*
 * jws_test_util.h - Plays the portal for the signed-answer tests: generates
 * keys, publishes them as JWKs and signs compact JWS, with OpenSSL rather
 * than with the code under test.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#ifndef JWS_TEST_UTIL_H
#define JWS_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

static char *tj_b64url(const unsigned char *in, size_t len)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char *out = malloc(len / 3 * 4 + 5);
    size_t o = 0, i = 0;

    if (!out) abort();
    for (; i + 2 < len; i += 3) {
        unsigned v = (unsigned)in[i] << 16 | (unsigned)in[i + 1] << 8 | in[i + 2];
        out[o++] = tbl[v >> 18 & 63];
        out[o++] = tbl[v >> 12 & 63];
        out[o++] = tbl[v >> 6 & 63];
        out[o++] = tbl[v & 63];
    }
    if (len - i == 1) {
        unsigned v = (unsigned)in[i] << 16;
        out[o++] = tbl[v >> 18 & 63];
        out[o++] = tbl[v >> 12 & 63];
    } else if (len - i == 2) {
        unsigned v = (unsigned)in[i] << 16 | (unsigned)in[i + 1] << 8;
        out[o++] = tbl[v >> 18 & 63];
        out[o++] = tbl[v >> 12 & 63];
        out[o++] = tbl[v >> 6 & 63];
    }
    out[o] = '\0';
    return out;
}

static char *tj_b64url_str(const char *s)
{
    return tj_b64url((const unsigned char *)s, strlen(s));
}

static void tj_sha256_hex(const char *data, size_t len, char out[65])
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL);
    for (unsigned i = 0; i < 32; i++) {
        snprintf(out + 2 * i, 3, "%02x", md[i]);
    }
}

/* "RSA" (2048), "RSA1024", "P-256", "P-384", "P-521" or "ED25519". */
static EVP_PKEY *tj_keygen(const char *kind)
{
    EVP_PKEY *k = NULL;
    if (strcmp(kind, "RSA") == 0) {
        k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    } else if (strcmp(kind, "RSA1024") == 0) {
        k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)1024);
    } else if (strcmp(kind, "ED25519") == 0) {
        k = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    } else {
        k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", kind);
    }
    if (!k) {
        fprintf(stderr, "keygen %s failed\n", kind);
        abort();
    }
    return k;
}

static size_t tj_ec_coord(EVP_PKEY *k)
{
    return ((size_t)EVP_PKEY_get_bits(k) + 7) / 8;
}

static char *tj_bn_b64(EVP_PKEY *k, const char *param, size_t pad)
{
    BIGNUM *bn = NULL;
    unsigned char buf[1024];
    if (EVP_PKEY_get_bn_param(k, param, &bn) != 1) abort();
    int n = pad ? BN_bn2binpad(bn, buf, (int)pad) : BN_bn2bin(bn, buf);
    BN_free(bn);
    if (n <= 0) abort();
    return tj_b64url(buf, (size_t)n);
}

/* The public JWK of k; `extra` is spliced in as more members, or NULL. */
static char *tj_jwk(EVP_PKEY *k, const char *kid, const char *extra)
{
    char *out = malloc(4096);
    char *a = NULL, *b = NULL;
    const char *more = extra ? extra : "";
    const char *sep = extra ? "," : "";

    if (!out) abort();
    if (EVP_PKEY_is_a(k, "RSA")) {
        a = tj_bn_b64(k, OSSL_PKEY_PARAM_RSA_N, 0);
        b = tj_bn_b64(k, OSSL_PKEY_PARAM_RSA_E, 0);
        snprintf(out, 4096, "{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\"%s%s}",
                 kid, a, b, sep, more);
    } else if (EVP_PKEY_is_a(k, "EC")) {
        size_t c = tj_ec_coord(k);
        const char *crv = c == 32 ? "P-256" : c == 48 ? "P-384" : "P-521";
        a = tj_bn_b64(k, OSSL_PKEY_PARAM_EC_PUB_X, c);
        b = tj_bn_b64(k, OSSL_PKEY_PARAM_EC_PUB_Y, c);
        snprintf(out, 4096, "{\"kty\":\"EC\",\"kid\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\",\"y\":\"%s\"%s%s}",
                 kid, crv, a, b, sep, more);
    } else {
        unsigned char raw[32];
        size_t len = sizeof(raw);
        if (EVP_PKEY_get_raw_public_key(k, raw, &len) != 1) abort();
        a = tj_b64url(raw, len);
        snprintf(out, 4096, "{\"kty\":\"OKP\",\"kid\":\"%s\",\"crv\":\"Ed25519\",\"x\":\"%s\"%s%s}",
                 kid, a, sep, more);
    }
    free(a);
    free(b);
    return out;
}

/* Sign header.payload with k as `alg` (RS*, PS*, ES*, EdDSA). */
static char *tj_sign_raw(EVP_PKEY *k, const char *alg,
                         const char *header_json, const char *payload_json)
{
    char *h = tj_b64url_str(header_json);
    char *p = tj_b64url_str(payload_json);
    size_t inlen = strlen(h) + 1 + strlen(p);
    char *input = malloc(inlen + 1);
    snprintf(input, inlen + 1, "%s.%s", h, p);

    const EVP_MD *md = NULL;
    if (strcmp(alg, "EdDSA") != 0) {
        const char *bits = alg + 2;
        md = strcmp(bits, "256") == 0 ? EVP_sha256()
           : strcmp(bits, "384") == 0 ? EVP_sha384() : EVP_sha512();
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    size_t siglen = 0;
    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, k) != 1) abort();
    if (alg[0] == 'P') {
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    }
    if (EVP_DigestSign(ctx, NULL, &siglen, (unsigned char *)input, inlen) != 1) abort();
    unsigned char *sig = malloc(siglen);
    if (EVP_DigestSign(ctx, sig, &siglen, (unsigned char *)input, inlen) != 1) abort();
    EVP_MD_CTX_free(ctx);

    if (alg[0] == 'E' && alg[1] == 'S') {
        size_t c = tj_ec_coord(k);
        const unsigned char *pp = sig;
        ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &pp, (long)siglen);
        unsigned char *raw = malloc(2 * c);
        BN_bn2binpad(ECDSA_SIG_get0_r(es), raw, (int)c);
        BN_bn2binpad(ECDSA_SIG_get0_s(es), raw + c, (int)c);
        ECDSA_SIG_free(es);
        free(sig);
        sig = raw;
        siglen = 2 * c;
    }

    char *s = tj_b64url(sig, siglen);
    size_t outlen = inlen + 1 + strlen(s);
    char *out = malloc(outlen + 1);
    snprintf(out, outlen + 1, "%s.%s", input, s);
    free(h);
    free(p);
    free(input);
    free(sig);
    free(s);
    return out;
}

/* A header with this alg, kid and the dedicated typ. */
static char *tj_sign(EVP_PKEY *k, const char *alg, const char *kid,
                     const char *payload_json)
{
    char header[256];
    snprintf(header, sizeof(header),
             "{\"alg\":\"%s\",\"kid\":\"%s\",\"typ\":\"ob-pam-response+jwt\"}",
             alg, kid);
    return tj_sign_raw(k, alg, header, payload_json);
}

/* HS256 over header.payload, keyed with `key`: the alg-confusion attack. */
static char *tj_sign_hs256(const unsigned char *key, size_t keylen,
                           const char *header_json, const char *payload_json)
{
    char *h = tj_b64url_str(header_json);
    char *p = tj_b64url_str(payload_json);
    size_t inlen = strlen(h) + 1 + strlen(p);
    char *input = malloc(inlen + 1);
    snprintf(input, inlen + 1, "%s.%s", h, p);
    unsigned char mac[32];
    unsigned int maclen = 0;
    HMAC(EVP_sha256(), key, (int)keylen, (unsigned char *)input, inlen, mac, &maclen);
    char *s = tj_b64url(mac, maclen);
    char *out = malloc(inlen + 2 + strlen(s));
    sprintf(out, "%s.%s", input, s);
    free(h);
    free(p);
    free(input);
    free(s);
    return out;
}

/* PEM of the public key: what an HS256 attacker would use as the secret. */
static char *tj_public_pem(EVP_PKEY *k, size_t *len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    PEM_write_bio_PUBKEY(bio, k);
    long n = BIO_get_mem_data(bio, &data);
    char *out = malloc((size_t)n + 1);
    memcpy(out, data, (size_t)n);
    out[n] = '\0';
    *len = (size_t)n;
    BIO_free(bio);
    return out;
}

#endif /* JWS_TEST_UTIL_H */
