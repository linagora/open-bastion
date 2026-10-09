/*
 * mock_tls.h - A TLS portal on 127.0.0.1 for the cert_pin tests (#332).
 *
 * The only question it answers is "did the client pin?": it holds a fresh
 * self-signed key, completes the handshake, reads one HTTP request and answers
 * it with a fixed status and JSON body. mt_pin() gives the pin of that key in
 * the sha256//<base64> form libcurl takes, so a test can configure the right
 * pin, another key's pin, or none, and count the requests that got through.
 *
 * The client runs with verify_ssl = false (the certificate is self-signed):
 * that is also the case worth pinning, since libcurl enforces
 * CURLOPT_PINNEDPUBLICKEY even when it does not verify the chain.
 *
 * Same conventions as mock_portal.h: one thread, one request per connection,
 * every name prefixed (mt_) because the NSS test includes
 * libnss_openbastion.c in the same translation unit.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#ifndef MOCK_TLS_H
#define MOCK_TLS_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static struct {
    int fd;
    int port;
    SSL_CTX *ctx;
    EVP_PKEY *key;
    pthread_t thread;
    pthread_mutex_t lock;
    int requests;             /* requests read after a completed handshake */
    char answer[1024];        /* full HTTP response */
    char pin[64];             /* sha256//<base64> of the server key */
} mt;

/* sha256//<base64 of SHA-256(SubjectPublicKeyInfo DER)> of `key` */
static void mt_pin_of(EVP_PKEY *key, char *out, size_t outlen)
{
    unsigned char *der = NULL, md[32], b64[64];
    int len = i2d_PUBKEY(key, &der);
    unsigned int mdlen = 0;

    out[0] = '\0';
    if (len <= 0) return;
    EVP_Digest(der, (size_t)len, md, &mdlen, EVP_sha256(), NULL);
    OPENSSL_free(der);
    EVP_EncodeBlock(b64, md, (int)mdlen);
    snprintf(out, outlen, "sha256//%s", (char *)b64);
}

static EVP_PKEY *mt_keygen(void)
{
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pc || EVP_PKEY_keygen_init(pc) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pc, NID_X9_62_prime256v1) <= 0
        || EVP_PKEY_keygen(pc, &k) <= 0) {
        fprintf(stderr, "mock_tls: keygen failed\n");
        exit(1);
    }
    EVP_PKEY_CTX_free(pc);
    return k;
}

static void mt_serve(int c)
{
    SSL *ssl = SSL_new(mt.ctx);
    char buf[16384];
    size_t got = 0;

    SSL_set_fd(ssl, c);
    if (SSL_accept(ssl) == 1) {
        /* Headers, then Content-Length bytes of body. */
        while (got < sizeof(buf) - 1) {
            int n = SSL_read(ssl, buf + got, (int)(sizeof(buf) - 1 - got));
            if (n <= 0) break;
            got += (size_t)n;
            buf[got] = '\0';
            char *end = strstr(buf, "\r\n\r\n");
            if (!end) continue;
            size_t want = 0;
            char *cl = strcasestr(buf, "Content-Length:");
            if (cl && cl < end) want = strtoul(cl + 15, NULL, 10);
            if (got >= (size_t)(end + 4 - buf) + want) break;
        }
        if (got > 0) {
            pthread_mutex_lock(&mt.lock);
            mt.requests++;
            pthread_mutex_unlock(&mt.lock);
            SSL_write(ssl, mt.answer, (int)strlen(mt.answer));
        }
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    close(c);
}

static void *mt_main(void *arg)
{
    (void)arg;
    for (;;) {
        int c = accept(mt.fd, NULL, NULL);
        if (c < 0) break;
        mt_serve(c);
    }
    return NULL;
}

/* Start the portal; every request is answered `status` with `json`. */
static int mt_start(int status, const char *json)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    X509 *crt = X509_new();

    memset(&mt, 0, sizeof(mt));
    pthread_mutex_init(&mt.lock, NULL);
    /* A client that refuses the pin hangs up mid-handshake: the server's
     * next write must fail, not kill the test. */
    signal(SIGPIPE, SIG_IGN);
    snprintf(mt.answer, sizeof(mt.answer),
             "HTTP/1.1 %d X\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             status, strlen(json), json);

    mt.key = mt_keygen();
    mt_pin_of(mt.key, mt.pin, sizeof(mt.pin));
    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_getm_notBefore(crt), -60);
    X509_gmtime_adj(X509_getm_notAfter(crt), 3600);
    X509_set_pubkey(crt, mt.key);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(crt), "CN", MBSTRING_ASC,
                               (const unsigned char *)"127.0.0.1", -1, -1, 0);
    X509_set_issuer_name(crt, X509_get_subject_name(crt));
    X509_sign(crt, mt.key, EVP_sha256());

    mt.ctx = SSL_CTX_new(TLS_server_method());
    if (!mt.ctx || SSL_CTX_use_certificate(mt.ctx, crt) != 1
        || SSL_CTX_use_PrivateKey(mt.ctx, mt.key) != 1) {
        fprintf(stderr, "mock_tls: TLS context setup failed\n");
        exit(1);
    }
    X509_free(crt);

    mt.fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (mt.fd < 0 || bind(mt.fd, (struct sockaddr *)&sa, sizeof(sa)) != 0
        || listen(mt.fd, 8) != 0
        || getsockname(mt.fd, (struct sockaddr *)&sa, &sl) != 0) {
        perror("mock_tls");
        exit(1);
    }
    mt.port = ntohs(sa.sin_port);
    return pthread_create(&mt.thread, NULL, mt_main, NULL);
}

static void mt_stop(void)
{
    shutdown(mt.fd, SHUT_RDWR);
    close(mt.fd);
    pthread_join(mt.thread, NULL);
    SSL_CTX_free(mt.ctx);
    EVP_PKEY_free(mt.key);
    pthread_mutex_destroy(&mt.lock);
}

static int mt_requests(void)
{
    pthread_mutex_lock(&mt.lock);
    int n = mt.requests;
    pthread_mutex_unlock(&mt.lock);
    return n;
}

#endif /* MOCK_TLS_H */
