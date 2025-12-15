/*
 * rate_limiter.c - Rate limiting with exponential backoff for PAM module
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>

#include "rate_limiter.h"

/* Default configuration values */
#define DEFAULT_STATE_DIR       "/var/lib/pam_llng/ratelimit"
#define DEFAULT_MAX_ATTEMPTS    5
#define DEFAULT_INITIAL_LOCKOUT 30
#define DEFAULT_MAX_LOCKOUT     3600
#define DEFAULT_BACKOFF_MULT    2.0

/* Rate limiter structure */
struct rate_limiter {
    rate_limiter_config_t config;
};

/* Hash a key to a filename-safe string */
static void hash_key(const char *key, char *out, size_t out_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (!ctx || out_size < 33) {
        if (out_size > 0) out[0] = '\0';
        if (ctx) EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, key, strlen(key)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        out[0] = '\0';
        return;
    }

    EVP_MD_CTX_free(ctx);

    /* Convert first 16 bytes to hex */
    for (int i = 0; i < 16 && (size_t)(i * 2 + 2) < out_size; i++) {
        snprintf(out + (i * 2), 3, "%02x", hash[i]);
    }
}

/* Build state file path */
static void build_state_path(rate_limiter_t *rl, const char *key, char *path, size_t path_size)
{
    char hash[64];
    hash_key(key, hash, sizeof(hash));
    snprintf(path, path_size, "%s/%s.state", rl->config.state_dir, hash);
}

/* Load state from file */
static bool load_state(const char *path, rate_limit_state_t *state)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;

    char line[256];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return false;
    }
    fclose(f);

    memset(state, 0, sizeof(*state));

    /* Format: failure_count lockout_until last_failure first_failure */
    if (sscanf(line, "%d %ld %ld %ld",
               &state->failure_count,
               &state->lockout_until,
               &state->last_failure,
               &state->first_failure) < 2) {
        return false;
    }

    return true;
}

/* Save state to file */
static bool save_state(const char *path, const rate_limit_state_t *state)
{
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(temp_path);
        return false;
    }

    fprintf(f, "%d %ld %ld %ld\n",
            state->failure_count,
            state->lockout_until,
            state->last_failure,
            state->first_failure);

    fclose(f);

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return false;
    }

    return true;
}

/* Delete state file */
static void delete_state(const char *path)
{
    unlink(path);
}

rate_limiter_t *rate_limiter_init(const rate_limiter_config_t *config)
{
    rate_limiter_t *rl = calloc(1, sizeof(rate_limiter_t));
    if (!rl) return NULL;

    /* Copy configuration with defaults */
    rl->config.enabled = config ? config->enabled : true;

    if (config && config->state_dir) {
        rl->config.state_dir = strdup(config->state_dir);
    } else {
        rl->config.state_dir = strdup(DEFAULT_STATE_DIR);
    }

    rl->config.max_attempts = (config && config->max_attempts > 0) ?
                               config->max_attempts : DEFAULT_MAX_ATTEMPTS;
    rl->config.initial_lockout_sec = (config && config->initial_lockout_sec > 0) ?
                                      config->initial_lockout_sec : DEFAULT_INITIAL_LOCKOUT;
    rl->config.max_lockout_sec = (config && config->max_lockout_sec > 0) ?
                                  config->max_lockout_sec : DEFAULT_MAX_LOCKOUT;
    rl->config.backoff_multiplier = (config && config->backoff_multiplier > 1.0) ?
                                     config->backoff_multiplier : DEFAULT_BACKOFF_MULT;

    /* Create state directory if it doesn't exist */
    struct stat st;
    if (stat(rl->config.state_dir, &st) != 0) {
        if (mkdir(rl->config.state_dir, 0700) != 0 && errno != EEXIST) {
            /* Try to create parent directory */
            char *parent = strdup(rl->config.state_dir);
            if (parent) {
                char *last_slash = strrchr(parent, '/');
                if (last_slash) {
                    *last_slash = '\0';
                    mkdir(parent, 0755);
                }
                free(parent);
            }
            mkdir(rl->config.state_dir, 0700);
        }
    }

    return rl;
}

void rate_limiter_destroy(rate_limiter_t *rl)
{
    if (!rl) return;
    free(rl->config.state_dir);
    free(rl);
}

int rate_limiter_check(rate_limiter_t *rl, const char *key)
{
    if (!rl || !rl->config.enabled || !key) {
        return 0;  /* Allow if disabled or invalid */
    }

    char path[512];
    build_state_path(rl, key, path, sizeof(path));

    rate_limit_state_t state;
    if (!load_state(path, &state)) {
        return 0;  /* No state = not rate limited */
    }

    time_t now = time(NULL);

    /* Check if lockout has expired */
    if (state.lockout_until > 0 && now < state.lockout_until) {
        return (int)(state.lockout_until - now);
    }

    /* Lockout expired or no lockout */
    return 0;
}

int rate_limiter_record_failure(rate_limiter_t *rl, const char *key)
{
    if (!rl || !rl->config.enabled || !key) {
        return 0;
    }

    char path[512];
    build_state_path(rl, key, path, sizeof(path));

    rate_limit_state_t state;
    time_t now = time(NULL);

    if (!load_state(path, &state)) {
        /* First failure */
        memset(&state, 0, sizeof(state));
        state.first_failure = now;
    }

    /* If lockout has expired, reset counter but keep some history */
    if (state.lockout_until > 0 && now >= state.lockout_until) {
        /* Keep the lockout duration for exponential backoff calculation */
        state.failure_count = 0;
        state.lockout_until = 0;
    }

    state.failure_count++;
    state.last_failure = now;

    /* Check if we should start lockout */
    if (state.failure_count >= rl->config.max_attempts) {
        /* Calculate lockout duration with exponential backoff */
        int lockout_count = state.failure_count - rl->config.max_attempts;
        double multiplier = 1.0;

        /*
         * Limit backoff iterations to 10 to prevent:
         * 1. Integer overflow with large multipliers (e.g., 2^10 = 1024x)
         * 2. Excessive lockout times beyond max_lockout_sec
         * With default settings (initial=30s, mult=2.0, max=3600s):
         *   - 10 iterations = 30 * 1024 = 30720s, capped to 3600s
         */
        for (int i = 0; i < lockout_count && i < 10; i++) {
            multiplier *= rl->config.backoff_multiplier;
        }

        /* Compute lockout duration with explicit overflow protection */
        double duration_d = (double)rl->config.initial_lockout_sec * multiplier;
        int lockout_duration;

        if (duration_d > (double)rl->config.max_lockout_sec) {
            lockout_duration = rl->config.max_lockout_sec;
        } else if (duration_d > (double)INT_MAX) {
            lockout_duration = rl->config.max_lockout_sec;
        } else {
            lockout_duration = (int)duration_d;
        }

        state.lockout_until = now + lockout_duration;

        save_state(path, &state);
        return lockout_duration;
    }

    save_state(path, &state);
    return 0;
}

void rate_limiter_reset(rate_limiter_t *rl, const char *key)
{
    if (!rl || !rl->config.enabled || !key) {
        return;
    }

    char path[512];
    build_state_path(rl, key, path, sizeof(path));
    delete_state(path);
}

bool rate_limiter_get_state(rate_limiter_t *rl, const char *key, rate_limit_state_t *state)
{
    if (!rl || !key || !state) {
        return false;
    }

    char path[512];
    build_state_path(rl, key, path, sizeof(path));
    return load_state(path, state);
}

int rate_limiter_cleanup(rate_limiter_t *rl)
{
    if (!rl || !rl->config.state_dir) {
        return 0;
    }

    DIR *dir = opendir(rl->config.state_dir);
    if (!dir) return 0;

    int removed = 0;
    time_t now = time(NULL);
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        /* Check if filename ends with ".state" */
        size_t name_len = strlen(entry->d_name);
        const char *suffix = ".state";
        size_t suffix_len = 6;
        if (name_len < suffix_len ||
            strcmp(entry->d_name + name_len - suffix_len, suffix) != 0) {
            continue;
        }

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", rl->config.state_dir, entry->d_name);

        rate_limit_state_t state;
        if (load_state(path, &state)) {
            /* Remove if lockout expired and no recent activity (1 hour) */
            if ((state.lockout_until == 0 || now >= state.lockout_until) &&
                (now - state.last_failure > 3600)) {
                delete_state(path);
                removed++;
            }
        }
    }

    closedir(dir);
    return removed;
}

void rate_limiter_build_key(const char *user, const char *client_ip, char *key, size_t key_size)
{
    if (!key || key_size == 0) return;

    snprintf(key, key_size, "%s:%s",
             user ? user : "unknown",
             client_ip ? client_ip : "local");
}
