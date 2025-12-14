/*
 * config.c - Configuration parsing for LemonLDAP::NG PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"

/* Security: check file permissions for sensitive files */
static int check_file_permissions(const char *filename)
{
    struct stat st;

    if (stat(filename, &st) != 0) {
        return -1;  /* File doesn't exist or can't be accessed */
    }

    /* File must be owned by root (uid 0) */
    if (st.st_uid != 0) {
        return -2;  /* Not owned by root */
    }

    /* File must not be readable by group or others */
    if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
        return -3;  /* Permissions too open */
    }

    return 0;  /* OK */
}

/* Default values */
#define DEFAULT_TIMEOUT         10
#define DEFAULT_CACHE_TTL       300
#define DEFAULT_CACHE_DIR       "/var/cache/pam_llng"
#define DEFAULT_SERVER_GROUP    "default"

void config_init(pam_llng_config_t *config)
{
    memset(config, 0, sizeof(*config));

    config->timeout = DEFAULT_TIMEOUT;
    config->verify_ssl = true;
    config->cache_enabled = true;
    config->cache_ttl = DEFAULT_CACHE_TTL;
    config->cache_dir = strdup(DEFAULT_CACHE_DIR);
    config->server_group = strdup(DEFAULT_SERVER_GROUP);
    config->log_level = 1;  /* warn */
}

/* Secure free: zero memory before freeing */
static void secure_free_str(char *ptr)
{
    if (ptr) {
        explicit_bzero(ptr, strlen(ptr));
        free(ptr);
    }
}

void config_free(pam_llng_config_t *config)
{
    if (!config) return;

    free(config->portal_url);
    free(config->client_id);
    /* Securely erase secret before freeing */
    secure_free_str(config->client_secret);
    free(config->server_token_file);
    free(config->server_group);
    free(config->ca_cert);
    free(config->cache_dir);

    explicit_bzero(config, sizeof(*config));
}

/* Trim whitespace from string */
static char *trim(char *str)
{
    if (!str) return NULL;

    /* Trim leading */
    while (isspace((unsigned char)*str)) str++;

    if (*str == '\0') return str;

    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

/* Parse a single config line */
static int parse_line(const char *key, const char *value, pam_llng_config_t *config)
{
    if (strcmp(key, "portal_url") == 0 || strcmp(key, "portal") == 0) {
        free(config->portal_url);
        config->portal_url = strdup(value);
    }
    else if (strcmp(key, "client_id") == 0) {
        free(config->client_id);
        config->client_id = strdup(value);
    }
    else if (strcmp(key, "client_secret") == 0) {
        free(config->client_secret);
        config->client_secret = strdup(value);
    }
    else if (strcmp(key, "server_token_file") == 0 || strcmp(key, "token_file") == 0) {
        free(config->server_token_file);
        config->server_token_file = strdup(value);
    }
    else if (strcmp(key, "server_group") == 0) {
        free(config->server_group);
        config->server_group = strdup(value);
    }
    else if (strcmp(key, "timeout") == 0) {
        config->timeout = atoi(value);
    }
    else if (strcmp(key, "verify_ssl") == 0) {
        config->verify_ssl = (strcmp(value, "true") == 0 ||
                              strcmp(value, "yes") == 0 ||
                              strcmp(value, "1") == 0);
    }
    else if (strcmp(key, "ca_cert") == 0) {
        free(config->ca_cert);
        config->ca_cert = strdup(value);
    }
    else if (strcmp(key, "cache_enabled") == 0 || strcmp(key, "cache") == 0) {
        config->cache_enabled = (strcmp(value, "true") == 0 ||
                                 strcmp(value, "yes") == 0 ||
                                 strcmp(value, "1") == 0);
    }
    else if (strcmp(key, "cache_dir") == 0) {
        free(config->cache_dir);
        config->cache_dir = strdup(value);
    }
    else if (strcmp(key, "cache_ttl") == 0) {
        config->cache_ttl = atoi(value);
    }
    else if (strcmp(key, "authorize_only") == 0) {
        config->authorize_only = (strcmp(value, "true") == 0 ||
                                  strcmp(value, "yes") == 0 ||
                                  strcmp(value, "1") == 0);
    }
    else if (strcmp(key, "log_level") == 0 || strcmp(key, "debug") == 0) {
        if (strcmp(value, "error") == 0) config->log_level = 0;
        else if (strcmp(value, "warn") == 0) config->log_level = 1;
        else if (strcmp(value, "info") == 0) config->log_level = 2;
        else if (strcmp(value, "debug") == 0) config->log_level = 3;
        else config->log_level = atoi(value);
    }
    /* Unknown keys are silently ignored */

    return 0;
}

int config_load(const char *filename, pam_llng_config_t *config)
{
    /* Security check: verify file permissions */
    int perm_check = check_file_permissions(filename);
    if (perm_check == -2) {
        /* File not owned by root - security risk */
        return -2;
    }
    if (perm_check == -3) {
        /* Permissions too open - security risk */
        return -3;
    }

    FILE *f = fopen(filename, "r");
    if (!f) {
        return -1;
    }

    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }

        /* Skip section headers [section] */
        if (*trimmed == '[') {
            continue;
        }

        /* Find = separator */
        char *eq = strchr(trimmed, '=');
        if (!eq) {
            continue;  /* Skip malformed lines */
        }

        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);

        /* Remove quotes from value */
        if (*value == '"' || *value == '\'') {
            char quote = *value;
            value++;
            char *end = strrchr(value, quote);
            if (end) *end = '\0';
        }

        parse_line(key, value, config);
    }

    fclose(f);
    return 0;
}

int config_parse_args(int argc, const char **argv, pam_llng_config_t *config)
{
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];

        /* Skip conf= as it's handled separately */
        if (strncmp(arg, "conf=", 5) == 0) {
            continue;
        }

        /* Check for key=value */
        const char *eq = strchr(arg, '=');
        if (eq) {
            size_t key_len = eq - arg;
            char key[64];
            if (key_len >= sizeof(key) - 1) {
                continue;  /* Key too long, skip */
            }
            memcpy(key, arg, key_len);
            key[key_len] = '\0';  /* Explicit null termination */

            const char *value = eq + 1;
            parse_line(key, value, config);
        }
        /* Boolean flags */
        else if (strcmp(arg, "debug") == 0) {
            config->log_level = 3;
        }
        else if (strcmp(arg, "authorize_only") == 0) {
            config->authorize_only = true;
        }
        else if (strcmp(arg, "no_cache") == 0 || strcmp(arg, "nocache") == 0) {
            config->cache_enabled = false;
        }
        else if (strcmp(arg, "no_verify_ssl") == 0 || strcmp(arg, "insecure") == 0) {
            config->verify_ssl = false;
        }
    }

    return 0;
}

int config_validate(const pam_llng_config_t *config)
{
    if (!config->portal_url || strlen(config->portal_url) == 0) {
        return -1;  /* portal_url is required */
    }

    /* Security: require HTTPS unless SSL verification is explicitly disabled */
    if (config->verify_ssl) {
        if (strncmp(config->portal_url, "https://", 8) != 0) {
            return -4;  /* HTTPS required when verify_ssl is enabled */
        }
    }

    /* For authorize endpoint, we need client credentials for introspection */
    if (!config->authorize_only) {
        if (!config->client_id || !config->client_secret) {
            return -1;  /* client_id and client_secret required for token validation */
        }
    }

    /* For account management, we need a server token */
    /* But it's okay to not have one if only doing authentication */

    return 0;
}
