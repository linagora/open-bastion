/*
 * ob-cert-daemon - privileged bastion certificate minting service
 *
 * Socket-activated (systemd, Accept=yes): one short-lived instance per
 * connection. The connected socket is stdin (fd 0) and stdout (fd 1).
 *
 * It replaces the old `sudo ob-bastion-cert-helper` bridge. ob-ssh / ob-scp
 * (running as the logged-in bastion user) connect via ob-cert-request and send
 * a 4-line request; this daemon:
 *
 *   1. derives the calling user from the connection's SO_PEERCRED. This is the
 *      ONLY source of the certificate's user identity — kernel-verified, never
 *      taken from the request body. A caller therefore cannot mint a cert for
 *      anyone but itself (LLNG additionally binds the voucher to (bastion_id,
 *      user), so a stolen voucher is doubly useless).
 *   2. reads the bastion's server token (root-only by design),
 *   3. POSTs {user, target_host, target_group, public_key, voucher} to LLNG
 *      /pam/bastion-cert with the token as Bearer,
 *   4. writes the raw LLNG JSON response back over the socket.
 *
 * The server token never leaves this process. No sudo, no setuid, no
 * interactive PAM: minting a machine certificate is decoupled from the human
 * sudo policy (Mode E).
 *
 * Request (newline-delimited, read from the socket):
 *   line 1: target_host
 *   line 2: target_group   (empty -> "default")
 *   line 3: voucher
 *   line 4: ephemeral SSH public key
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "ob_cert_proto.h"

#define OB_CONFIG "/etc/open-bastion/openbastion.conf"
#define PROXY_CONFIG "/etc/open-bastion/ssh-proxy.conf"
#define DEFAULT_TOKEN_FILE "/var/lib/open-bastion/token"

/* Per-field request limits (a too-long line is rejected as malformed). These
 * are generous upper bounds for legitimate values, kept small to deny an
 * unauthenticated local caller any large-allocation / amplification surface. */
#define MAX_HOST 256
#define MAX_GROUP 64
#define MAX_VOUCHER 1024
#define MAX_PUBKEY 4096
#define MAX_TOKEN 65536
/* Cap the LLNG response we buffer (a cert reply is a few KB). */
#define MAX_RESP (256 * 1024)
/* Drop a stalled peer instead of pinning a per-connection process. */
#define IO_TIMEOUT_SEC 10

static void fail(const char *msg)
{
    /* stderr -> journal (StandardError=journal). Never log secrets. */
    fprintf(stderr, "[ob-cert-daemon] %s\n", msg);
}

/* Request field validators (ob_valid_*) and the line reader (ob_read_line) live
 * in ob_cert_proto.c so they can be unit-tested in isolation
 * (tests/test_ob_cert_proto.c). */

/* ── config/token helpers ─────────────────────────────────────────────────── */

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

static void strip_quotes(char *s)
{
    size_t n = strlen(s);
    if (n >= 2 && ((s[0] == '"' && s[n - 1] == '"') ||
                   (s[0] == '\'' && s[n - 1] == '\''))) {
        memmove(s, s + 1, n - 2);
        s[n - 2] = '\0';
    }
}

/* ── configuration ────────────────────────────────────────────────────────── */

struct ob_cfg {
    char portal_url[1024];
    char token_file[1024];
    int verify_ssl;
    long timeout;
};

/* openbastion.conf: ini-style "key = value". We only need portal_url/verify_ssl. */
static void load_ini(struct ob_cfg *cfg)
{
    FILE *f = fopen(OB_CONFIG, "r");
    if (!f)
        return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *hash = strchr(p, '#');
        if (hash)
            *hash = '\0';
        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);
        if (strcmp(key, "portal_url") == 0)
            snprintf(cfg->portal_url, sizeof(cfg->portal_url), "%s", val);
        else if (strcmp(key, "verify_ssl") == 0)
            cfg->verify_ssl = !(strcmp(val, "false") == 0 || strcmp(val, "no") == 0 ||
                                strcmp(val, "0") == 0);
    }
    fclose(f);
}

/* ssh-proxy.conf: shell-style KEY="value". Honoured only when root-owned and
 * not group/world-writable (mirrors ob-cert-lib.sh / the old helper). */
static void load_proxy(struct ob_cfg *cfg)
{
    struct stat st;
    if (stat(PROXY_CONFIG, &st) != 0)
        return;
    if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)))
        return;
    FILE *f = fopen(PROXY_CONFIG, "r");
    if (!f)
        return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '#' || *p == '\0')
            continue;
        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);
        strip_quotes(val);
        if (strcmp(key, "PORTAL_URL") == 0)
            snprintf(cfg->portal_url, sizeof(cfg->portal_url), "%s", val);
        else if (strcmp(key, "SERVER_TOKEN_FILE") == 0)
            snprintf(cfg->token_file, sizeof(cfg->token_file), "%s", val);
        else if (strcmp(key, "VERIFY_SSL") == 0)
            cfg->verify_ssl = !(strcmp(val, "false") == 0);
        else if (strcmp(key, "TIMEOUT") == 0)
            cfg->timeout = strtol(val, NULL, 10);
    }
    fclose(f);
}

/* Read the server token: plain text, or JSON with .access_token. */
static char *read_server_token(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    char *buf = malloc(MAX_TOKEN);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, MAX_TOKEN - 1, f);
    fclose(f);
    buf[n] = '\0';

    char *start = buf;
    while (*start && isspace((unsigned char)*start))
        start++;
    if (*start == '{') {
        struct json_object *root = json_tokener_parse(buf);
        char *tok = NULL;
        struct json_object *at;
        if (root && json_object_object_get_ex(root, "access_token", &at)) {
            const char *s = json_object_get_string(at);
            if (s && *s)
                tok = strdup(s);
        }
        if (root)
            json_object_put(root);
        free(buf);
        return tok;
    }
    char *t = strdup(trim(buf));
    free(buf);
    if (t && !*t) {
        free(t);
        return NULL;
    }
    return t;
}

/* ── HTTP ─────────────────────────────────────────────────────────────────── */

struct resp_buf {
    char *data;
    size_t len;
};

static size_t collect(void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t add = size * nmemb;
    struct resp_buf *b = userp;
    if (b->len + add + 1 > MAX_RESP)
        return 0; /* abort the transfer: response too large */
    char *p = realloc(b->data, b->len + add + 1);
    if (!p)
        return 0;
    b->data = p;
    memcpy(b->data + b->len, ptr, add);
    b->len += add;
    b->data[b->len] = '\0';
    return add;
}

/* Write all of buf to fd. */
static void write_out(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        off += (size_t)w;
    }
}

int main(void)
{
    /* Locate the connected socket. With systemd Accept=yes + StandardInput=
     * socket it is stdin (fd 0); with the LISTEN_FDS protocol (e.g. systemd-
     * socket-activate) it is fd 3 (SD_LISTEN_FDS_START). The socket is
     * bidirectional, so we read the request from and write the response to the
     * same fd. */
    int conn_fd = STDIN_FILENO;
    struct stat fdst;
    if (!(fstat(conn_fd, &fdst) == 0 && S_ISSOCK(fdst.st_mode))) {
        /* sd-daemon protocol: only trust fd 3 when LISTEN_PID names us, so a
         * manually-invoked daemon can't be tricked into using a stray fd. */
        const char *lf = getenv("LISTEN_FDS");
        const char *lp = getenv("LISTEN_PID");
        if (lf && atoi(lf) >= 1 && lp && atoi(lp) == (int)getpid())
            conn_fd = 3; /* SD_LISTEN_FDS_START */
    }

    /* Bound how long a peer may stall us: one process lives per connection, so
     * a slow/silent client must not pin it. read()/write() then fail after the
     * timeout and we abort the request. */
    struct timeval tv = {.tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0};
    setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(conn_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* 1. Caller identity from the connection, kernel-verified. */
    struct ucred cred;
    socklen_t clen = sizeof(cred);
    if (getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0) {
        fail("SO_PEERCRED failed (not a socket?)");
        return 1;
    }

    char pwbuf[4096];
    struct passwd pw, *pwp = NULL;
    if (getpwuid_r(cred.uid, &pw, pwbuf, sizeof(pwbuf), &pwp) != 0 || !pwp) {
        fail("cannot resolve calling uid to a user");
        return 1;
    }
    const char *cert_user = pw.pw_name;
    if (!ob_valid_username(cert_user)) {
        fail("calling user name rejected by policy");
        return 1;
    }

    /* 2. Request body (target_host, target_group, voucher, public_key). */
    char host[MAX_HOST], group[MAX_GROUP], voucher[MAX_VOUCHER], pubkey[MAX_PUBKEY];
    if (ob_read_line(conn_fd, host, sizeof(host)) <= 0 ||
        ob_read_line(conn_fd, group, sizeof(group)) < 0 ||
        ob_read_line(conn_fd, voucher, sizeof(voucher)) <= 0 ||
        ob_read_line(conn_fd, pubkey, sizeof(pubkey)) <= 0) {
        fail("malformed request (expected host/group/voucher/pubkey lines)");
        return 1;
    }
    if (group[0] == '\0')
        snprintf(group, sizeof(group), "%s", "default");

    if (!ob_valid_host(host)) {
        fail("invalid target host");
        return 1;
    }
    if (!ob_valid_group(group)) {
        fail("invalid target group");
        return 1;
    }
    if (!ob_valid_pubkey(pubkey)) {
        fail("invalid SSH public key");
        return 1;
    }
    if (voucher[0] == '\0') {
        fail("empty voucher");
        return 1;
    }

    /* 3. Configuration + server token. */
    struct ob_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.verify_ssl = 1;
    cfg.timeout = 10;
    snprintf(cfg.token_file, sizeof(cfg.token_file), "%s", DEFAULT_TOKEN_FILE);
    load_ini(&cfg);
    load_proxy(&cfg);

    /* strip a trailing slash from portal_url */
    size_t ul = strlen(cfg.portal_url);
    while (ul > 0 && cfg.portal_url[ul - 1] == '/')
        cfg.portal_url[--ul] = '\0';
    if (ul == 0) {
        fail("portal_url not configured");
        return 1;
    }

    char *token = read_server_token(cfg.token_file);
    if (!token) {
        fail("cannot read server token (is this host enrolled?)");
        return 1;
    }

    /* 4. Build the JSON payload (user = SO_PEERCRED identity, NOT from input). */
    struct json_object *body = json_object_new_object();
    json_object_object_add(body, "user", json_object_new_string(cert_user));
    json_object_object_add(body, "target_host", json_object_new_string(host));
    json_object_object_add(body, "target_group", json_object_new_string(group));
    json_object_object_add(body, "public_key", json_object_new_string(pubkey));
    json_object_object_add(body, "voucher", json_object_new_string(voucher));
    const char *payload = json_object_to_json_string(body);

    char url[1152];
    snprintf(url, sizeof(url), "%s/pam/bastion-cert", cfg.portal_url);

    char authhdr[MAX_TOKEN + 32];
    snprintf(authhdr, sizeof(authhdr), "Authorization: Bearer %s", token);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (!curl) {
        fail("curl init failed");
        curl_global_cleanup();
        free(token);
        json_object_put(body);
        return 1;
    }

    struct resp_buf rb = {0};
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, authhdr);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, cfg.timeout);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (!cfg.verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    CURLcode rc = curl_easy_perform(curl);

    /* Wipe the Authorization header copy of the token before freeing. */
    memset(authhdr, 0, sizeof(authhdr));
    memset(token, 0, strlen(token));
    free(token);

    int ret;
    if (rc != CURLE_OK) {
        fail(curl_easy_strerror(rc));
        ret = 1;
    } else if (rb.data && rb.len > 0) {
        /* Pass the LLNG response (success OR structured error) to the client.
         * --fail-with-body semantics: we relay the body regardless of status. */
        write_out(conn_fd, rb.data, rb.len);
        ret = 0;
    } else {
        fail("empty response from LLNG /pam/bastion-cert");
        ret = 1;
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(rb.data);
    json_object_put(body);
    return ret;
}
