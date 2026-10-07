/*
 * ob_jws.h - Verification of the portal's signed answers
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 *
 * Asked with `Accept: application/ob-pam-response+jwt` and an X-Nonce, the
 * pam-access plugin answers /pam/authorize, /pam/verify, /pam/userinfo,
 * /pam/whoami and /pam/heartbeat with a compact JWS instead of the plain JSON
 * object, same HTTP status. The format and the trust model are described in
 * doc/references/security-reference.rst ("Signed answers").
 *
 * Self-contained (OpenSSL and json-c), no global state, no threads: it runs
 * inside the NSS module, hence inside nscd and every program that resolves a
 * user.
 */

#ifndef OB_JWS_H
#define OB_JWS_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

struct json_object;

#define OB_JWS_MEDIA_TYPE   "application/ob-pam-response+jwt"
#define OB_JWS_TYP          "ob-pam-response+jwt"
#define OB_JWS_MAX_TOKEN    (64 * 1024)
#define OB_JWS_DEFAULT_SKEW 60

/* The `response_signing` setting. */
typedef enum {
    OB_RESPONSE_SIGNING_OFF = 0,
    OB_RESPONSE_SIGNING_PREFER,
    OB_RESPONSE_SIGNING_REQUIRED,
} ob_response_signing_t;

/* Returns 0 and sets *out for off/prefer/required, -1 for anything else. */
static inline int ob_response_signing_parse(const char *value,
                                            ob_response_signing_t *out)
{
    if (!value) return -1;
    if (strcmp(value, "off") == 0) {
        *out = OB_RESPONSE_SIGNING_OFF;
    } else if (strcmp(value, "prefer") == 0) {
        *out = OB_RESPONSE_SIGNING_PREFER;
    } else if (strcmp(value, "required") == 0) {
        *out = OB_RESPONSE_SIGNING_REQUIRED;
    } else {
        return -1;
    }
    return 0;
}

/* A set of public signature keys read from a JWKS. */
typedef struct ob_jws_keyset ob_jws_keyset_t;

/*
 * Parse a JWKS document. Keys that cannot verify a signature here are
 * skipped: `use` other than "sig", `kty: oct`, an unsupported curve, a
 * malformed key, an RSA modulus under 2048 bits. Returns NULL, with a message
 * in err, when nothing usable is left.
 */
ob_jws_keyset_t *ob_jws_keyset_parse(const char *json, size_t len,
                                     char *err, size_t errlen);

/*
 * Read and parse a JWKS file. The file is the trust anchor: it must be a
 * regular file, not a symlink, owned by root or by the effective uid, and
 * writable by nobody else.
 */
ob_jws_keyset_t *ob_jws_keyset_load(const char *path, char *err, size_t errlen);

size_t ob_jws_keyset_size(const ob_jws_keyset_t *ks);
void ob_jws_keyset_free(ob_jws_keyset_t *ks);

/* What the answer must be bound to. */
typedef struct {
    const char *issuer;     /* expected `iss` */
    const char *audience;   /* client_id; NULL refuses any `aud` */
    const char *endpoint;   /* authorize, verify, userinfo, whoami, heartbeat */
    const char *nonce;      /* the X-Nonce sent */
    const char *body;       /* the request body as sent, NULL for none */
    size_t body_len;
    time_t now;
    int skew;               /* clock skew tolerated on exp/iat, seconds */
} ob_jws_expect_t;

/* A verified answer. resp and jwks are owned (json_object_put). */
typedef struct {
    struct json_object *resp;   /* the plain answer */
    struct json_object *jwks;   /* the `jwks` claim, NULL if absent */
    long http_status;
    bool has_aud;               /* false: the answer must grant nothing */
} ob_jws_answer_t;

/*
 * Verify a compact JWS against the key set and the expectations. Returns 0
 * and fills *answer, or -1 with a message in err.
 *
 * A missing `aud` is not an error here: the portal omits it on the answers it
 * gives before it has identified the caller. The caller must then refuse
 * anything that grants (answer->has_aud is false).
 */
int ob_jws_verify_answer(const ob_jws_keyset_t *ks,
                         const char *token, size_t token_len,
                         const ob_jws_expect_t *expect,
                         ob_jws_answer_t *answer,
                         char *err, size_t errlen);

void ob_jws_answer_free(ob_jws_answer_t *answer);

/* Does a Content-Type header value name OB_JWS_MEDIA_TYPE? */
bool ob_jws_is_media_type(const char *content_type);

#endif /* OB_JWS_H */
