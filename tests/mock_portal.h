/*
 * mock_portal.h - A portal on 127.0.0.1 for the signed-answer wiring tests
 * (#339): plain HTTP, one thread, one request per connection.
 *
 * It records what the client sent (path, Accept, X-Nonce, the request
 * signature headers, the body) and answers as the test asks: plain JSON, a
 * compact JWS signed with jws_test_util.h and bound to the request it
 * received, or the exact bytes of its previous answer (a replay). Every
 * claim of a signed answer can be bent on its own, so each check of the
 * client is driven to fail through the real HTTP path, not only through
 * ob_jws_verify_answer().
 *
 * A thread rather than a fork: the test reads what the portal saw right
 * after the call returns. All names carry an mp_ prefix because the NSS test
 * includes libnss_openbastion.c in the same translation unit.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#ifndef MOCK_PORTAL_H
#define MOCK_PORTAL_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>

#include "jws_test_util.h"

typedef enum {
    MP_PLAIN = 0,   /* Content-Type: application/json, body = resp */
    MP_SIGNED,      /* Content-Type: application/ob-pam-response+jwt */
    MP_REPLAY,      /* the previous answer, byte for byte */
} mp_kind_t;

/* How to answer the next requests. NULL / 0 members take the honest value. */
typedef struct {
    mp_kind_t kind;
    int status;               /* HTTP status on the wire; 0: 200 */
    const char *resp;         /* the answer, a JSON object */
    /* MP_SIGNED only */
    EVP_PKEY *key;
    const char *kid;
    const char *alg;
    int signed_status;        /* `http_status` claim; 0: same as status */
    const char *iss;          /* NULL: the issuer set by mp_start() */
    const char *aud;          /* NULL: the audience set by mp_start(); "": none */
    const char *endpoint;     /* NULL: the path after /pam/ */
    const char *nonce;        /* NULL: the X-Nonce received; "": none */
    const char *signed_body;  /* NULL: the body received (req_sha256) */
} mp_answer_t;

/* What the portal saw of the last request, and how many it got. */
typedef struct {
    int requests;
    char path[128];
    char accept[256];
    int nonce_count;          /* X-Nonce headers in the last request */
    char nonce[128];
    char timestamp[32];       /* X-Timestamp */
    char signature[160];      /* X-Signature-256 */
    int has_authorization;
    char body[8192];
} mp_seen_t;

static struct {
    int fd;
    int port;
    pthread_t thread;
    pthread_mutex_t lock;
    mp_answer_t answer;
    mp_seen_t seen;
    char *last;               /* last full HTTP answer, for MP_REPLAY */
    size_t last_len;
    char issuer[256];
    char audience[128];
} mp = { .fd = -1, .lock = PTHREAD_MUTEX_INITIALIZER };

/* Value of header `name` in the raw header block; returns how many there are. */
static int mp_header(const char *headers, const char *name, char *out, size_t outlen)
{
    size_t nlen = strlen(name);
    int count = 0;
    const char *line = strstr(headers, "\r\n");   /* skip the request line */

    if (outlen) out[0] = '\0';
    while (line && line[2] != '\r' && line[2] != '\0') {
        line += 2;
        const char *end = strstr(line, "\r\n");
        if (!end) break;
        if ((size_t)(end - line) > nlen && strncasecmp(line, name, nlen) == 0
            && line[nlen] == ':') {
            const char *v = line + nlen + 1;
            while (*v == ' ' || *v == '\t') v++;
            if (count == 0 && outlen) {
                snprintf(out, outlen, "%.*s", (int)(end - v), v);
            }
            count++;
        }
        line = end;
    }
    return count;
}

/* The signed answer the portal gives for this request, as a JWS. */
static char *mp_sign_answer(const mp_answer_t *a, const char *path,
                            const char *nonce, const char *body, int status)
{
    const char *body_for_sha = a->signed_body ? a->signed_body : body;
    const char *aud = a->aud ? a->aud : mp.audience;
    const char *n = a->nonce ? a->nonce : nonce;
    char sha[65];
    time_t now = time(NULL);

    tj_sha256_hex(body_for_sha, strlen(body_for_sha), sha);

    struct json_object *c = json_object_new_object();
    json_object_object_add(c, "iss", json_object_new_string(a->iss ? a->iss : mp.issuer));
    if (*aud) {
        json_object_object_add(c, "aud", json_object_new_string(aud));
    }
    json_object_object_add(c, "iat", json_object_new_int64(now));
    json_object_object_add(c, "exp", json_object_new_int64(now + 60));
    json_object_object_add(c, "endpoint", json_object_new_string(
        a->endpoint ? a->endpoint
                    : strncmp(path, "/pam/", 5) == 0 ? path + 5 : path));
    if (*n) {
        json_object_object_add(c, "req_nonce", json_object_new_string(n));
    }
    json_object_object_add(c, "req_sha256", json_object_new_string(sha));
    json_object_object_add(c, "http_status",
                           json_object_new_int(a->signed_status ? a->signed_status : status));
    json_object_object_add(c, "resp", json_tokener_parse(a->resp ? a->resp : "{}"));

    char *jws = tj_sign(a->key, a->alg ? a->alg : "RS256", a->kid,
                        json_object_to_json_string_ext(c, JSON_C_TO_STRING_PLAIN));
    json_object_put(c);
    return jws;
}

static void mp_send_all(int c, const char *data, size_t len)
{
    while (len > 0) {
        ssize_t w = send(c, data, len, MSG_NOSIGNAL);
        if (w <= 0) return;   /* the client went away */
        data += w;
        len -= (size_t)w;
    }
}

static void mp_serve(int c)
{
    char req[16384];
    size_t got = 0;
    long clen = -1;
    char *hdr_end = NULL;

    /* Headers, then Content-Length bytes of body. */
    while (got < sizeof(req) - 1) {
        ssize_t r = read(c, req + got, sizeof(req) - 1 - got);
        if (r <= 0) break;
        got += (size_t)r;
        req[got] = '\0';
        if (!hdr_end && (hdr_end = strstr(req, "\r\n\r\n")) != NULL) {
            char cl[32];
            hdr_end[2] = '\0';                 /* headers only, for mp_header */
            clen = mp_header(req, "Content-Length", cl, sizeof(cl)) ? atol(cl) : 0;
            hdr_end[2] = '\r';
        }
        if (hdr_end && (long)(got - (size_t)(hdr_end + 4 - req)) >= clen) break;
    }
    if (!hdr_end) return;

    hdr_end[2] = '\0';
    const char *body = hdr_end + 4;
    char path[128] = "";
    const char *sp = strchr(req, ' ');
    if (sp) snprintf(path, sizeof(path), "%.*s", (int)strcspn(sp + 1, " "), sp + 1);

    pthread_mutex_lock(&mp.lock);
    mp_seen_t *s = &mp.seen;
    char auth[16];
    s->requests++;
    snprintf(s->path, sizeof(s->path), "%s", path);
    mp_header(req, "Accept", s->accept, sizeof(s->accept));
    s->nonce_count = mp_header(req, "X-Nonce", s->nonce, sizeof(s->nonce));
    mp_header(req, "X-Timestamp", s->timestamp, sizeof(s->timestamp));
    mp_header(req, "X-Signature-256", s->signature, sizeof(s->signature));
    s->has_authorization = mp_header(req, "Authorization", auth, sizeof(auth)) > 0;
    snprintf(s->body, sizeof(s->body), "%s", body);

    const mp_answer_t *a = &mp.answer;
    int status = a->status ? a->status : 200;
    char *out = NULL;
    size_t outlen = 0;

    if (a->kind == MP_REPLAY && mp.last) {
        out = malloc(mp.last_len);
        memcpy(out, mp.last, mp.last_len);
        outlen = mp.last_len;
    } else {
        char *payload = a->kind == MP_SIGNED
                      ? mp_sign_answer(a, path, s->nonce, body, status)
                      : strdup(a->resp ? a->resp : "{}");
        const char *ctype = a->kind == MP_SIGNED ? "application/ob-pam-response+jwt"
                                                 : "application/json";
        outlen = strlen(payload) + 256;
        out = malloc(outlen);
        outlen = (size_t)snprintf(out, outlen,
                                  "HTTP/1.1 %d Mock\r\nContent-Type: %s\r\n"
                                  "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                                  status, ctype, strlen(payload), payload);
        free(payload);
        free(mp.last);
        mp.last = malloc(outlen);
        memcpy(mp.last, out, outlen);
        mp.last_len = outlen;
    }
    pthread_mutex_unlock(&mp.lock);

    mp_send_all(c, out, outlen);
    free(out);
}

static void *mp_main(void *arg)
{
    (void)arg;
    for (;;) {
        int c = accept(mp.fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            return NULL;   /* mp_stop() shut the socket down */
        }
        mp_serve(c);
        close(c);
    }
}

/*
 * Start the portal; returns its port. The issuer of the signed answers is
 * http://127.0.0.1:<port> -- what the client expects when sso_issuer is
 * unset -- and their audience is `audience`.
 */
static int mp_start(const char *audience)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int one = 1;

    mp.fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (mp.fd < 0 || setsockopt(mp.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0
        || bind(mp.fd, (struct sockaddr *)&a, sizeof(a)) != 0
        || listen(mp.fd, 8) != 0
        || getsockname(mp.fd, (struct sockaddr *)&a, &alen) != 0) {
        perror("mock portal");
        exit(1);
    }
    mp.port = ntohs(a.sin_port);
    snprintf(mp.issuer, sizeof(mp.issuer), "http://127.0.0.1:%d", mp.port);
    snprintf(mp.audience, sizeof(mp.audience), "%s", audience);
    if (pthread_create(&mp.thread, NULL, mp_main, NULL) != 0) {
        perror("pthread_create");
        exit(1);
    }
    return mp.port;
}

static void mp_stop(void)
{
    if (mp.fd < 0) return;
    shutdown(mp.fd, SHUT_RDWR);   /* wakes accept() up */
    pthread_join(mp.thread, NULL);
    close(mp.fd);
    mp.fd = -1;
    free(mp.last);
    mp.last = NULL;
}

/* Answer the next requests this way, and forget what was seen so far. */
static void mp_set(const mp_answer_t *answer)
{
    pthread_mutex_lock(&mp.lock);
    mp.answer = *answer;
    memset(&mp.seen, 0, sizeof(mp.seen));
    pthread_mutex_unlock(&mp.lock);
}

static mp_seen_t mp_get_seen(void)
{
    mp_seen_t s;
    pthread_mutex_lock(&mp.lock);
    s = mp.seen;
    pthread_mutex_unlock(&mp.lock);
    return s;
}

#endif /* MOCK_PORTAL_H */
