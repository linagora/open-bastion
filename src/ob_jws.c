/*
 * ob_jws.c - Verification of the portal's signed answers
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 *
 * See ob_jws.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <json-c/json.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include "ob_jws.h"

#define OB_JWS_MAX_JWKS   (256 * 1024)
#define OB_JWS_MAX_KEYS   64
#define OB_JWS_MAX_HEADER 4096
#define OB_JWS_JSON_DEPTH 16
#define OB_JWS_MIN_RSA_BITS 2048

typedef enum { KEY_RSA, KEY_EC, KEY_OKP } key_kind_t;

typedef struct {
    char *kid;
    char *alg;          /* the JWK's own "alg", or NULL */
    key_kind_t kind;
    size_t ec_bytes;    /* EC: coordinate size, which fixes the ES* alg */
    EVP_PKEY *pkey;
} jws_key_t;

struct ob_jws_keyset {
    jws_key_t *keys;
    size_t count;
};

/*
 * The algorithms accepted, and the key each one requires. The header's `alg`
 * only selects a row; the key found by `kid` must then be of that row's type
 * (and curve): a header can never turn an RSA public key into an HMAC secret
 * or pick `none`, because neither has a row.
 */
typedef struct {
    const char *name;
    key_kind_t kind;
    const EVP_MD *(*md)(void);
    bool pss;
    size_t ec_bytes;
} jws_alg_t;

static const jws_alg_t ALGS[] = {
    { "RS256", KEY_RSA, EVP_sha256, false, 0 },
    { "RS384", KEY_RSA, EVP_sha384, false, 0 },
    { "RS512", KEY_RSA, EVP_sha512, false, 0 },
    { "PS256", KEY_RSA, EVP_sha256, true,  0 },
    { "PS384", KEY_RSA, EVP_sha384, true,  0 },
    { "PS512", KEY_RSA, EVP_sha512, true,  0 },
    { "ES256", KEY_EC,  EVP_sha256, false, 32 },
    { "ES384", KEY_EC,  EVP_sha384, false, 48 },
    { "ES512", KEY_EC,  EVP_sha512, false, 66 },
    { "EdDSA", KEY_OKP, NULL,       false, 0 },
};

#define SET_ERR(...) do { if (err && errlen) snprintf(err, errlen, __VA_ARGS__); } while (0)

/* ── base64url ──────────────────────────────────────────────────────────── */

static int b64url_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

/*
 * Unpadded base64url only, as JWS mandates. Non-zero trailing bits are
 * refused, so a given byte string has exactly one accepted encoding.
 * The result is NUL-terminated (not counted in *outlen).
 */
static unsigned char *b64url_decode(const char *in, size_t inlen, size_t *outlen)
{
    if (inlen % 4 == 1) {
        return NULL;
    }
    size_t cap = inlen / 4 * 3 + 3;
    unsigned char *out = malloc(cap + 1);
    if (!out) {
        return NULL;
    }

    unsigned int acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        int v = b64url_value((unsigned char)in[i]);
        if (v < 0) {
            free(out);
            return NULL;
        }
        acc = (acc << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }
    if (acc != 0) {
        free(out);
        return NULL;
    }
    out[o] = '\0';
    *outlen = o;
    return out;
}

/* ── JSON ───────────────────────────────────────────────────────────────── */

/*
 * The whole buffer must be one JSON object, nothing before or after it: a
 * decoded segment may carry NUL bytes or trailing data, which a parser that
 * stops at the first complete value would silently ignore.
 */
static struct json_object *parse_json_object(const char *buf, size_t len)
{
    if (len == 0 || len > INT_MAX) {
        return NULL;
    }
    struct json_tokener *tok = json_tokener_new_ex(OB_JWS_JSON_DEPTH);
    if (!tok) {
        return NULL;
    }
    struct json_object *obj = json_tokener_parse_ex(tok, buf, (int)len);
    bool ok = obj && json_tokener_get_error(tok) == json_tokener_success
              && tok->char_offset == (int)len
              && json_object_is_type(obj, json_type_object);
    json_tokener_free(tok);
    if (!ok) {
        json_object_put(obj);
        return NULL;
    }
    return obj;
}

static const char *get_string(struct json_object *obj, const char *key)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)
        || !json_object_is_type(val, json_type_string)) {
        return NULL;
    }
    return json_object_get_string(val);
}

static unsigned char *get_b64url(struct json_object *obj, const char *key,
                                 size_t *len)
{
    const char *s = get_string(obj, key);
    if (!s || !*s) {
        return NULL;
    }
    return b64url_decode(s, strlen(s), len);
}

/* ── JWK → EVP_PKEY ─────────────────────────────────────────────────────── */

static EVP_PKEY *pkey_from_params(const char *type, OSSL_PARAM_BLD *bld)
{
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);

    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return pkey;
}

static EVP_PKEY *rsa_from_jwk(struct json_object *jwk)
{
    size_t nlen = 0, elen = 0;
    unsigned char *n = get_b64url(jwk, "n", &nlen);
    unsigned char *e = get_b64url(jwk, "e", &elen);
    BIGNUM *bn_n = NULL, *bn_e = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    EVP_PKEY *pkey = NULL;

    if (!n || !e || nlen == 0 || nlen > 2048 || elen == 0 || elen > 8) {
        goto out;
    }
    bn_n = BN_bin2bn(n, (int)nlen, NULL);
    bn_e = BN_bin2bn(e, (int)elen, NULL);
    bld = OSSL_PARAM_BLD_new();
    if (!bn_n || !bn_e || !bld
        || BN_num_bits(bn_n) < OB_JWS_MIN_RSA_BITS
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e)) {
        goto out;
    }
    pkey = pkey_from_params("RSA", bld);

out:
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_n);
    BN_free(bn_e);
    free(n);
    free(e);
    return pkey;
}

static EVP_PKEY *ec_from_jwk(struct json_object *jwk, size_t *coord)
{
    const char *crv = get_string(jwk, "crv");
    const char *group;
    size_t want;

    if (!crv) return NULL;
    if (strcmp(crv, "P-256") == 0) {
        group = "prime256v1"; want = 32;
    } else if (strcmp(crv, "P-384") == 0) {
        group = "secp384r1"; want = 48;
    } else if (strcmp(crv, "P-521") == 0) {
        group = "secp521r1"; want = 66;
    } else {
        return NULL;
    }

    size_t xlen = 0, ylen = 0;
    unsigned char *x = get_b64url(jwk, "x", &xlen);
    unsigned char *y = get_b64url(jwk, "y", &ylen);
    unsigned char point[1 + 2 * 66];
    OSSL_PARAM_BLD *bld = NULL;
    EVP_PKEY *pkey = NULL;

    if (!x || !y || xlen != want || ylen != want) {
        goto out;
    }
    /* Uncompressed SEC1 point; fromdata refuses one that is not on the curve. */
    point[0] = 0x04;
    memcpy(point + 1, x, want);
    memcpy(point + 1 + want, y, want);

    bld = OSSL_PARAM_BLD_new();
    if (!bld
        || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group, 0)
        || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             point, 1 + 2 * want)) {
        goto out;
    }
    pkey = pkey_from_params("EC", bld);
    if (pkey) {
        *coord = want;
    }

out:
    OSSL_PARAM_BLD_free(bld);
    free(x);
    free(y);
    return pkey;
}

static EVP_PKEY *okp_from_jwk(struct json_object *jwk)
{
    const char *crv = get_string(jwk, "crv");
    if (!crv || strcmp(crv, "Ed25519") != 0) {
        return NULL;
    }
    size_t xlen = 0;
    unsigned char *x = get_b64url(jwk, "x", &xlen);
    EVP_PKEY *pkey = NULL;
    if (x && xlen == 32) {
        pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, x, xlen);
    }
    free(x);
    return pkey;
}

/* A key that may verify signatures, per `use` and `key_ops` when present. */
static bool jwk_is_for_signatures(struct json_object *jwk)
{
    struct json_object *val;
    if (json_object_object_get_ex(jwk, "use", &val)) {
        if (!json_object_is_type(val, json_type_string)
            || strcmp(json_object_get_string(val), "sig") != 0) {
            return false;
        }
    }
    if (json_object_object_get_ex(jwk, "key_ops", &val)) {
        if (!json_object_is_type(val, json_type_array)) {
            return false;
        }
        size_t n = json_object_array_length(val);
        for (size_t i = 0; i < n; i++) {
            struct json_object *op = json_object_array_get_idx(val, i);
            if (op && json_object_is_type(op, json_type_string)
                && strcmp(json_object_get_string(op), "verify") == 0) {
                return true;
            }
        }
        return false;
    }
    return true;
}

static int add_key(ob_jws_keyset_t *ks, struct json_object *jwk)
{
    if (!json_object_is_type(jwk, json_type_object) || !jwk_is_for_signatures(jwk)) {
        return -1;
    }
    const char *kty = get_string(jwk, "kty");
    const char *kid = get_string(jwk, "kid");
    const char *alg = get_string(jwk, "alg");
    if (!kty || !kid || !*kid) {
        return -1;
    }

    jws_key_t key = {0};
    if (strcmp(kty, "RSA") == 0) {
        key.kind = KEY_RSA;
        key.pkey = rsa_from_jwk(jwk);
    } else if (strcmp(kty, "EC") == 0) {
        key.kind = KEY_EC;
        key.pkey = ec_from_jwk(jwk, &key.ec_bytes);
    } else if (strcmp(kty, "OKP") == 0) {
        key.kind = KEY_OKP;
        key.pkey = okp_from_jwk(jwk);
    }
    if (!key.pkey) {
        ERR_clear_error();
        return -1;
    }

    key.kid = strdup(kid);
    key.alg = alg ? strdup(alg) : NULL;
    if (!key.kid || (alg && !key.alg)) {
        free(key.kid);
        free(key.alg);
        EVP_PKEY_free(key.pkey);
        return -1;
    }
    ks->keys[ks->count++] = key;
    return 0;
}

ob_jws_keyset_t *ob_jws_keyset_parse(const char *json, size_t len,
                                     char *err, size_t errlen)
{
    if (!json || len > OB_JWS_MAX_JWKS) {
        SET_ERR("JWKS missing or larger than %d bytes", OB_JWS_MAX_JWKS);
        return NULL;
    }
    struct json_object *doc = parse_json_object(json, len);
    struct json_object *keys;
    if (!doc || !json_object_object_get_ex(doc, "keys", &keys)
        || !json_object_is_type(keys, json_type_array)) {
        SET_ERR("not a JWKS (a JSON object with a \"keys\" array)");
        json_object_put(doc);
        return NULL;
    }

    size_t n = json_object_array_length(keys);
    if (n > OB_JWS_MAX_KEYS) {
        n = OB_JWS_MAX_KEYS;
    }
    ob_jws_keyset_t *ks = calloc(1, sizeof(*ks));
    if (!ks || (n && !(ks->keys = calloc(n, sizeof(*ks->keys))))) {
        free(ks);
        json_object_put(doc);
        SET_ERR("out of memory");
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        (void)add_key(ks, json_object_array_get_idx(keys, i));
    }
    json_object_put(doc);

    if (ks->count == 0) {
        ob_jws_keyset_free(ks);
        SET_ERR("no usable signature key in the JWKS");
        return NULL;
    }
    return ks;
}

ob_jws_keyset_t *ob_jws_keyset_load(const char *path, char *err, size_t errlen)
{
    if (!path || !*path) {
        SET_ERR("no JWKS file configured");
        return NULL;
    }
    /* O_NONBLOCK: a fifo planted at the path must not hang the caller. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        SET_ERR("cannot open %s: %s", path, strerror(errno));
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        SET_ERR("%s is not a regular file", path);
        close(fd);
        return NULL;
    }
    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        SET_ERR("%s is not owned by root", path);
        close(fd);
        return NULL;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        SET_ERR("%s is writable by group or others", path);
        close(fd);
        return NULL;
    }
    if (st.st_size <= 0 || st.st_size > OB_JWS_MAX_JWKS) {
        SET_ERR("%s is empty or larger than %d bytes", path, OB_JWS_MAX_JWKS);
        close(fd);
        return NULL;
    }

    size_t cap = (size_t)st.st_size;
    char *buf = malloc(cap + 1);
    size_t got = 0;
    if (!buf) {
        close(fd);
        SET_ERR("out of memory");
        return NULL;
    }
    while (got < cap) {
        ssize_t r = read(fd, buf + got, cap - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    buf[got] = '\0';

    ob_jws_keyset_t *ks = ob_jws_keyset_parse(buf, got, err, errlen);
    free(buf);
    if (!ks && err && errlen) {
        char inner[192];
        snprintf(inner, sizeof(inner), "%s", err);
        snprintf(err, errlen, "%s: %s", path, inner);
    }
    return ks;
}

size_t ob_jws_keyset_size(const ob_jws_keyset_t *ks)
{
    return ks ? ks->count : 0;
}

void ob_jws_keyset_free(ob_jws_keyset_t *ks)
{
    if (!ks) return;
    for (size_t i = 0; i < ks->count; i++) {
        free(ks->keys[i].kid);
        free(ks->keys[i].alg);
        EVP_PKEY_free(ks->keys[i].pkey);
    }
    free(ks->keys);
    free(ks);
}

/* ── Signature ──────────────────────────────────────────────────────────── */

static const jws_alg_t *find_alg(const char *name)
{
    for (size_t i = 0; i < sizeof(ALGS) / sizeof(ALGS[0]); i++) {
        if (strcmp(ALGS[i].name, name) == 0) {
            return &ALGS[i];
        }
    }
    return NULL;
}

/* The key named by kid that this algorithm may use, or NULL. */
static const jws_key_t *find_key(const ob_jws_keyset_t *ks, const char *kid,
                                 const jws_alg_t *alg, bool *kid_known)
{
    *kid_known = false;
    for (size_t i = 0; i < ks->count; i++) {
        const jws_key_t *k = &ks->keys[i];
        if (strcmp(k->kid, kid) != 0) {
            continue;
        }
        *kid_known = true;
        if (k->kind != alg->kind || k->ec_bytes != alg->ec_bytes) {
            continue;
        }
        if (k->alg && strcmp(k->alg, alg->name) != 0) {
            continue;
        }
        return k;
    }
    return NULL;
}

/* JOSE carries ECDSA signatures as r||s; OpenSSL wants DER. */
static unsigned char *ecdsa_raw_to_der(const unsigned char *sig, size_t half,
                                       int *derlen)
{
    unsigned char *der = NULL;
    ECDSA_SIG *es = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, (int)half, NULL);
    BIGNUM *s = BN_bin2bn(sig + half, (int)half, NULL);

    if (!es || !r || !s || ECDSA_SIG_set0(es, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(es);
        return NULL;
    }
    *derlen = i2d_ECDSA_SIG(es, &der);
    ECDSA_SIG_free(es);
    if (*derlen <= 0) {
        OPENSSL_free(der);
        return NULL;
    }
    return der;
}

static bool verify_signature(const jws_key_t *key, const jws_alg_t *alg,
                             const unsigned char *input, size_t inlen,
                             const unsigned char *sig, size_t siglen)
{
    unsigned char *der = NULL;
    int derlen = 0;

    switch (alg->kind) {
    case KEY_RSA:
        if (siglen != (size_t)EVP_PKEY_get_size(key->pkey)) return false;
        break;
    case KEY_EC:
        if (siglen != 2 * alg->ec_bytes) return false;
        der = ecdsa_raw_to_der(sig, alg->ec_bytes, &derlen);
        if (!der) return false;
        sig = der;
        siglen = (size_t)derlen;
        break;
    case KEY_OKP:
        if (siglen != 64) return false;
        break;
    }

    bool ok = false;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx
        && EVP_DigestVerifyInit(ctx, &pctx, alg->md ? alg->md() : NULL,
                                NULL, key->pkey) == 1) {
        bool padding_ok = true;
        if (alg->kind == KEY_RSA) {
            padding_ok = EVP_PKEY_CTX_set_rsa_padding(pctx,
                             alg->pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING) > 0;
            if (padding_ok && alg->pss) {
                padding_ok = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                 RSA_PSS_SALTLEN_DIGEST) > 0;
            }
        }
        ok = padding_ok && EVP_DigestVerify(ctx, sig, siglen, input, inlen) == 1;
    }
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(der);
    ERR_clear_error();
    return ok;
}

/* ── Claims ─────────────────────────────────────────────────────────────── */

static bool get_int64(struct json_object *obj, const char *key, int64_t *out)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)
        || !json_object_is_type(val, json_type_int)) {
        return false;
    }
    errno = 0;
    *out = json_object_get_int64(val);
    return errno == 0;
}

/* Lengths first, then a constant-time comparison of the bytes. */
static bool same_secret_string(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    return la == lb && CRYPTO_memcmp(a, b, la) == 0;
}

static bool audience_matches(struct json_object *aud, const char *want)
{
    if (json_object_is_type(aud, json_type_string)) {
        return strcmp(json_object_get_string(aud), want) == 0;
    }
    if (json_object_is_type(aud, json_type_array)) {
        size_t n = json_object_array_length(aud);
        for (size_t i = 0; i < n; i++) {
            struct json_object *a = json_object_array_get_idx(aud, i);
            if (a && json_object_is_type(a, json_type_string)
                && strcmp(json_object_get_string(a), want) == 0) {
                return true;
            }
        }
    }
    return false;
}

static int check_claims(struct json_object *claims, const ob_jws_expect_t *x,
                        ob_jws_answer_t *answer, char *err, size_t errlen)
{
    const char *s;

    s = get_string(claims, "iss");
    if (!s || strcmp(s, x->issuer) != 0) {
        SET_ERR("unexpected issuer '%.80s' (expected '%.80s')", s ? s : "", x->issuer);
        return -1;
    }

    s = get_string(claims, "endpoint");
    if (!s || strcmp(s, x->endpoint) != 0) {
        SET_ERR("answer is for endpoint '%.32s', not '%s'", s ? s : "", x->endpoint);
        return -1;
    }

    int64_t exp, iat;
    if (!get_int64(claims, "exp", &exp) || !get_int64(claims, "iat", &iat)) {
        SET_ERR("exp or iat missing");
        return -1;
    }
    if (exp <= (int64_t)x->now - x->skew) {
        SET_ERR("answer expired");
        return -1;
    }
    if (iat > (int64_t)x->now + x->skew) {
        SET_ERR("answer issued in the future");
        return -1;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    char hex[2 * 32 + 1];
    if (EVP_Digest(x->body ? x->body : "", x->body ? x->body_len : 0,
                   md, &mdlen, EVP_sha256(), NULL) != 1 || mdlen != 32) {
        SET_ERR("cannot hash the request body");
        return -1;
    }
    for (unsigned int i = 0; i < mdlen; i++) {
        snprintf(hex + 2 * i, 3, "%02x", md[i]);
    }
    s = get_string(claims, "req_sha256");
    if (!s || !same_secret_string(s, hex)) {
        SET_ERR("answer is bound to another request body (req_sha256)");
        return -1;
    }

    s = get_string(claims, "req_nonce");
    if (!s) {
        SET_ERR("answer carries no req_nonce (did X-Nonce reach the portal?)");
        return -1;
    }
    if (!same_secret_string(s, x->nonce)) {
        SET_ERR("answer is bound to another request (req_nonce)");
        return -1;
    }

    struct json_object *val;
    answer->has_aud = json_object_object_get_ex(claims, "aud", &val);
    if (answer->has_aud && !x->audience) {
        SET_ERR("answer names a client (aud) but no client_id is configured");
        return -1;
    }
    if (answer->has_aud && !audience_matches(val, x->audience)) {
        SET_ERR("answer is for another client (aud)");
        return -1;
    }

    int64_t status;
    if (!get_int64(claims, "http_status", &status) || status < 100 || status > 599) {
        SET_ERR("http_status missing or invalid");
        return -1;
    }
    answer->http_status = (long)status;

    if (!json_object_object_get_ex(claims, "resp", &val)
        || !json_object_is_type(val, json_type_object)) {
        SET_ERR("resp missing or not an object");
        return -1;
    }
    answer->resp = json_object_get(val);

    if (json_object_object_get_ex(claims, "jwks", &val)
        && json_object_is_type(val, json_type_object)) {
        answer->jwks = json_object_get(val);
    }
    return 0;
}

/* ── Entry point ────────────────────────────────────────────────────────── */

int ob_jws_verify_answer(const ob_jws_keyset_t *ks,
                         const char *token, size_t token_len,
                         const ob_jws_expect_t *x,
                         ob_jws_answer_t *answer,
                         char *err, size_t errlen)
{
    if (!answer) {
        SET_ERR("invalid parameters");
        return -1;
    }
    memset(answer, 0, sizeof(*answer));
    if (!ks || !token || !x || !x->issuer || !x->endpoint
        || !x->nonce || !*x->nonce) {
        SET_ERR("invalid parameters");
        return -1;
    }
    if (token_len == 0 || token_len > OB_JWS_MAX_TOKEN) {
        SET_ERR("signed answer empty or larger than %d bytes", OB_JWS_MAX_TOKEN);
        return -1;
    }

    /* header.payload.signature, each non-empty */
    const char *dot1 = memchr(token, '.', token_len);
    const char *dot2 = dot1 ? memchr(dot1 + 1, '.', token_len - (size_t)(dot1 + 1 - token)) : NULL;
    if (!dot1 || !dot2
        || memchr(dot2 + 1, '.', token_len - (size_t)(dot2 + 1 - token))
        || dot1 == token || dot2 == dot1 + 1 || dot2 + 1 == token + token_len) {
        SET_ERR("not a compact JWS");
        return -1;
    }
    size_t hlen = (size_t)(dot1 - token);
    size_t plen = (size_t)(dot2 - dot1 - 1);
    size_t slen = token_len - (size_t)(dot2 + 1 - token);
    if (hlen > OB_JWS_MAX_HEADER) {
        SET_ERR("JWS header too large");
        return -1;
    }

    int rc = -1;
    struct json_object *header = NULL, *claims = NULL;
    unsigned char *hraw = NULL, *praw = NULL, *sig = NULL;
    size_t hrawlen = 0, prawlen = 0, siglen = 0;

    hraw = b64url_decode(token, hlen, &hrawlen);
    header = hraw ? parse_json_object((const char *)hraw, hrawlen) : NULL;
    if (!header) {
        SET_ERR("malformed JWS header");
        goto out;
    }

    const char *typ = get_string(header, "typ");
    if (!typ || strcmp(typ, OB_JWS_TYP) != 0) {
        SET_ERR("JWS typ is not " OB_JWS_TYP);
        goto out;
    }
    /* No extension is understood here, so none may be critical. */
    if (json_object_object_get_ex(header, "crit", NULL)) {
        SET_ERR("JWS header carries crit");
        goto out;
    }
    const char *kid = get_string(header, "kid");
    if (!kid || !*kid) {
        SET_ERR("JWS header has no kid");
        goto out;
    }
    const char *alg_name = get_string(header, "alg");
    const jws_alg_t *alg = alg_name ? find_alg(alg_name) : NULL;
    if (!alg) {
        SET_ERR("JWS alg '%.16s' not accepted", alg_name ? alg_name : "");
        goto out;
    }
    bool kid_known;
    const jws_key_t *key = find_key(ks, kid, alg, &kid_known);
    if (!key) {
        if (kid_known) {
            SET_ERR("key '%.64s' cannot be used with %s", kid, alg->name);
        } else {
            SET_ERR("unknown signing key '%.64s'", kid);
        }
        goto out;
    }

    sig = b64url_decode(dot2 + 1, slen, &siglen);
    if (!sig || !verify_signature(key, alg, (const unsigned char *)token,
                                  hlen + 1 + plen, sig, siglen)) {
        SET_ERR("bad signature (key '%.64s', %s)", kid, alg->name);
        goto out;
    }

    praw = b64url_decode(dot1 + 1, plen, &prawlen);
    claims = praw ? parse_json_object((const char *)praw, prawlen) : NULL;
    if (!claims) {
        SET_ERR("malformed JWS payload");
        goto out;
    }

    rc = check_claims(claims, x, answer, err, errlen);

out:
    if (rc != 0) {
        ob_jws_answer_free(answer);
    }
    json_object_put(header);
    json_object_put(claims);
    free(hraw);
    free(praw);
    free(sig);
    return rc;
}

void ob_jws_answer_free(ob_jws_answer_t *answer)
{
    if (!answer) return;
    json_object_put(answer->resp);
    json_object_put(answer->jwks);
    memset(answer, 0, sizeof(*answer));
}

bool ob_jws_is_media_type(const char *content_type)
{
    if (!content_type) {
        return false;
    }
    while (*content_type == ' ' || *content_type == '\t') {
        content_type++;
    }
    size_t n = strlen(OB_JWS_MEDIA_TYPE);
    if (strncasecmp(content_type, OB_JWS_MEDIA_TYPE, n) != 0) {
        return false;
    }
    char c = content_type[n];
    return c == '\0' || c == ';' || c == ' ' || c == '\t';
}
