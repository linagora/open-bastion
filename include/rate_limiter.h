/*
 * rate_limiter.h - Rate limiting with exponential backoff for PAM module
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <stdbool.h>
#include <time.h>

/* Rate limiter configuration */
typedef struct {
    bool enabled;
    char *state_dir;          /* Directory for state files (default: /var/lib/pam_llng/ratelimit) */
    int max_attempts;         /* Max failures before lockout (default: 5) */
    int initial_lockout_sec;  /* Initial lockout duration (default: 30) */
    int max_lockout_sec;      /* Maximum lockout duration (default: 3600) */
    double backoff_multiplier; /* Exponential backoff factor (default: 2.0) */
} rate_limiter_config_t;

/* Rate limiter state for a key */
typedef struct {
    int failure_count;
    time_t lockout_until;
    time_t last_failure;
    time_t first_failure;
} rate_limit_state_t;

/* Rate limiter handle */
typedef struct rate_limiter rate_limiter_t;

/*
 * Initialize rate limiter
 * Returns NULL on failure
 */
rate_limiter_t *rate_limiter_init(const rate_limiter_config_t *config);

/*
 * Destroy rate limiter and free resources
 */
void rate_limiter_destroy(rate_limiter_t *rl);

/*
 * Check if a key (user:ip) is rate limited
 * Returns: 0 if allowed, >0 seconds until allowed, -1 on error
 */
int rate_limiter_check(rate_limiter_t *rl, const char *key);

/*
 * Record a failed authentication attempt
 * Returns: seconds until allowed (0 if not locked out yet), -1 on error
 */
int rate_limiter_record_failure(rate_limiter_t *rl, const char *key);

/*
 * Reset failures for a key (call on successful auth)
 */
void rate_limiter_reset(rate_limiter_t *rl, const char *key);

/*
 * Get current state for a key
 * Returns true if state exists, false otherwise
 */
bool rate_limiter_get_state(rate_limiter_t *rl, const char *key, rate_limit_state_t *state);

/*
 * Clean up expired lockout states
 * Returns number of states cleaned up
 */
int rate_limiter_cleanup(rate_limiter_t *rl);

/*
 * Build a rate limit key from user and IP
 */
void rate_limiter_build_key(const char *user, const char *client_ip, char *key, size_t key_size);

#endif /* RATE_LIMITER_H */
