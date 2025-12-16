/*
 * client_context.c - Client context collection for PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <security/pam_modules.h>

#include "client_context.h"

/*
 * Validate and extract IP address from rhost using inet_pton.
 * Handles: "192.168.1.1", "192.168.1.1:22", "::1", "[::1]:22", hostnames
 */
static char *parse_ip_from_rhost(const char *rhost)
{
    if (!rhost || !*rhost) {
        return strdup("local");
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;
    char ip_buf[INET6_ADDRSTRLEN];
    char *result = NULL;

    /* Handle IPv6 in brackets: [::1]:port or [::1] */
    if (rhost[0] == '[') {
        const char *end = strchr(rhost, ']');
        if (end && (end - rhost - 1) < (int)sizeof(ip_buf)) {
            size_t len = end - rhost - 1;
            memcpy(ip_buf, rhost + 1, len);
            ip_buf[len] = '\0';

            if (inet_pton(AF_INET6, ip_buf, &ipv6) == 1) {
                return strdup(ip_buf);
            }
        }
    }

    /* Try parsing as plain IPv6 first */
    if (inet_pton(AF_INET6, rhost, &ipv6) == 1) {
        return strdup(rhost);
    }

    /* Try parsing as IPv4 */
    if (inet_pton(AF_INET, rhost, &ipv4) == 1) {
        return strdup(rhost);
    }

    /* Handle IPv4:port format (e.g., "192.168.1.1:22") */
    const char *last_colon = strrchr(rhost, ':');
    if (last_colon && strchr(rhost, '.')) {  /* Has both colon and dot = likely IPv4:port */
        size_t ip_len = last_colon - rhost;
        if (ip_len > 0 && ip_len < sizeof(ip_buf)) {
            memcpy(ip_buf, rhost, ip_len);
            ip_buf[ip_len] = '\0';

            if (inet_pton(AF_INET, ip_buf, &ipv4) == 1) {
                return strdup(ip_buf);
            }
        }
    }

    /* Not a valid IP address, return as-is (hostname) */
    result = strdup(rhost);
    return result;
}

client_context_t *client_context_collect(pam_handle_t *pamh)
{
    if (!pamh) return NULL;

    client_context_t *ctx = calloc(1, sizeof(client_context_t));
    if (!ctx) return NULL;

    const char *item = NULL;

    /* Collect PAM items */
    if (pam_get_item(pamh, PAM_USER, (const void **)&item) == PAM_SUCCESS && item) {
        ctx->username = strdup(item);
    }

    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&item) == PAM_SUCCESS && item) {
        ctx->service = strdup(item);
    }

    if (pam_get_item(pamh, PAM_RHOST, (const void **)&item) == PAM_SUCCESS && item) {
        ctx->rhost = strdup(item);
        ctx->client_ip = parse_ip_from_rhost(item);
    } else {
        ctx->client_ip = strdup("local");
        ctx->is_local = true;
    }

    if (pam_get_item(pamh, PAM_TTY, (const void **)&item) == PAM_SUCCESS && item) {
        ctx->tty = strdup(item);
    }

    if (pam_get_item(pamh, PAM_RUSER, (const void **)&item) == PAM_SUCCESS && item) {
        ctx->ruser = strdup(item);
    }

    /* Check if connection is local */
    if (ctx->client_ip) {
        ctx->is_local = (strcmp(ctx->client_ip, "local") == 0 ||
                         strcmp(ctx->client_ip, "127.0.0.1") == 0 ||
                         strcmp(ctx->client_ip, "::1") == 0 ||
                         strncmp(ctx->client_ip, "localhost", 9) == 0);
    }

    /* Build rate limit key */
    client_context_build_rate_key(ctx);

    return ctx;
}

void client_context_free(client_context_t *ctx)
{
    if (!ctx) return;

    free(ctx->username);
    free(ctx->service);
    free(ctx->rhost);
    free(ctx->tty);
    free(ctx->ruser);
    free(ctx->client_ip);
    free(ctx->fingerprint);
    free(ctx->rate_limit_key);

    explicit_bzero(ctx, sizeof(*ctx));
    free(ctx);
}

void client_context_generate_fingerprint(client_context_t *ctx)
{
    if (!ctx) return;

    /* Free existing fingerprint */
    free(ctx->fingerprint);
    ctx->fingerprint = NULL;

    /* Build string to hash: "username|client_ip|service" */
    char to_hash[512];
    snprintf(to_hash, sizeof(to_hash), "%s|%s|%s",
             ctx->username ? ctx->username : "",
             ctx->client_ip ? ctx->client_ip : "",
             ctx->service ? ctx->service : "");

    /* Hash with SHA-256 */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, to_hash, strlen(to_hash)) != 1 ||
        EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return;
    }

    EVP_MD_CTX_free(md_ctx);

    /* Convert to hex string (first 16 bytes = 32 chars) */
    ctx->fingerprint = malloc(65);  /* 64 hex chars + null */
    if (ctx->fingerprint) {
        for (unsigned int i = 0; i < hash_len && i < 32; i++) {
            snprintf(ctx->fingerprint + (i * 2), 3, "%02x", hash[i]);
        }
    }

    /* Clear the to_hash buffer */
    explicit_bzero(to_hash, sizeof(to_hash));
}

bool client_context_is_high_risk(const client_context_t *ctx,
                                  const char *high_risk_services)
{
    if (!ctx || !ctx->service || !high_risk_services) {
        return false;
    }

    /* Parse comma-separated list */
    char *list = strdup(high_risk_services);
    if (!list) return false;

    bool is_high_risk = false;
    char *saveptr = NULL;
    char *token = strtok_r(list, ",", &saveptr);

    while (token) {
        /* Trim whitespace */
        while (*token && isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

        if (strcmp(ctx->service, token) == 0) {
            is_high_risk = true;
            break;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(list);
    return is_high_risk;
}

int client_context_get_cache_ttl(const client_context_t *ctx,
                                  int normal_ttl,
                                  int high_risk_ttl,
                                  const char *high_risk_services)
{
    if (client_context_is_high_risk(ctx, high_risk_services)) {
        return high_risk_ttl;
    }
    return normal_ttl;
}

void client_context_build_rate_key(client_context_t *ctx)
{
    if (!ctx) return;

    free(ctx->rate_limit_key);
    ctx->rate_limit_key = NULL;

    size_t key_len = 256;
    ctx->rate_limit_key = malloc(key_len);
    if (ctx->rate_limit_key) {
        snprintf(ctx->rate_limit_key, key_len, "%s:%s",
                 ctx->username ? ctx->username : "unknown",
                 ctx->client_ip ? ctx->client_ip : "local");
    }
}
