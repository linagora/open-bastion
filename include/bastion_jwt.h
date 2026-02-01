/*
 * bastion_jwt.h - JWT verification for bastion-to-backend authentication
 *
 * This module verifies RS256-signed JWTs issued by LLNG to bastion servers.
 * It ensures that SSH connections to backends come from authorized bastions.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef BASTION_JWT_H
#define BASTION_JWT_H

#include <stdbool.h>
#include <time.h>

/* Forward declarations */
typedef struct jwks_cache jwks_cache_t;
typedef struct jti_cache jti_cache_t;

/* JWT claims extracted from bastion token */
typedef struct {
    char *iss;           /* Issuer (LLNG portal URL) */
    char *sub;           /* Subject (username) */
    char *aud;           /* Audience (should be "pam:bastion-backend") */
    char *jti;           /* JWT ID (unique identifier) */
    time_t exp;          /* Expiration time */
    time_t iat;          /* Issued at time */
    time_t nbf;          /* Not before time (RFC 7519) */
    char *bastion_id;    /* Bastion server ID (client_id) */
    char *bastion_group; /* Bastion server group */
    char *bastion_ip;    /* Bastion IP address */
    char *target_host;   /* Target backend hostname */
    char *target_group;  /* Target server group */
    char **user_groups;  /* User's LLNG groups */
    size_t user_groups_count;
} bastion_jwt_claims_t;

/* JWT verifier configuration */
typedef struct {
    char *issuer;                /* Expected issuer (LLNG portal URL) */
    char *audience;              /* Expected audience (default: "pam:bastion-backend") */
    int max_clock_skew;          /* Allowed clock skew in seconds (default: 30) */
    char *allowed_bastions;      /* Comma-separated list of allowed bastion IDs (NULL = all) */
    jwks_cache_t *jwks_cache;    /* JWKS cache for public keys */
    jti_cache_t *jti_cache;      /* JTI cache for replay detection (NULL = disabled) */
} bastion_jwt_config_t;

/* JWT verifier handle */
typedef struct bastion_jwt_verifier bastion_jwt_verifier_t;

/* Verification result codes */
typedef enum {
    BASTION_JWT_OK = 0,
    BASTION_JWT_INVALID_FORMAT,
    BASTION_JWT_INVALID_HEADER,
    BASTION_JWT_INVALID_PAYLOAD,
    BASTION_JWT_INVALID_SIGNATURE,
    BASTION_JWT_EXPIRED,
    BASTION_JWT_NOT_YET_VALID,
    BASTION_JWT_INVALID_ISSUER,
    BASTION_JWT_INVALID_AUDIENCE,
    BASTION_JWT_UNAUTHORIZED_BASTION,
    BASTION_JWT_NO_KEY_FOUND,
    BASTION_JWT_REPLAY_DETECTED,
    BASTION_JWT_INTERNAL_ERROR
} bastion_jwt_result_t;

/*
 * Initialize a JWT verifier
 * Returns NULL on error
 */
bastion_jwt_verifier_t *bastion_jwt_verifier_init(const bastion_jwt_config_t *config);

/*
 * Destroy a JWT verifier
 */
void bastion_jwt_verifier_destroy(bastion_jwt_verifier_t *verifier);

/*
 * Verify a JWT and extract claims
 *
 * Parameters:
 *   verifier - JWT verifier handle
 *   jwt      - JWT string to verify
 *   claims   - Output: extracted claims (must be freed with bastion_jwt_claims_free)
 *
 * Returns:
 *   BASTION_JWT_OK on success, error code otherwise
 */
bastion_jwt_result_t bastion_jwt_verify(bastion_jwt_verifier_t *verifier,
                                        const char *jwt,
                                        bastion_jwt_claims_t *claims);

/*
 * Get human-readable error message for result code
 */
const char *bastion_jwt_result_str(bastion_jwt_result_t result);

/*
 * Free claims structure
 */
void bastion_jwt_claims_free(bastion_jwt_claims_t *claims);

/*
 * Check if a bastion ID is in the allowed list
 *
 * Parameters:
 *   bastion_id       - Bastion ID to check
 *   allowed_bastions - Comma-separated list of allowed bastions (NULL = all allowed)
 *
 * Returns:
 *   true if allowed, false otherwise
 */
bool bastion_jwt_is_bastion_allowed(const char *bastion_id, const char *allowed_bastions);

#ifdef BASTION_JWT_TEST
/*
 * Validate JWT time claims (exposed for unit testing)
 *
 * Parameters:
 *   exp            - Expiration time (0 = not set)
 *   nbf            - Not before time (0 = not set)
 *   iat            - Issued at time (0 = not set)
 *   now            - Current time to validate against
 *   max_clock_skew - Allowed clock skew in seconds
 *
 * Returns:
 *   BASTION_JWT_OK if valid
 *   BASTION_JWT_EXPIRED if token expired
 *   BASTION_JWT_NOT_YET_VALID if token not yet valid
 */
bastion_jwt_result_t bastion_jwt_validate_time(
    time_t exp, time_t nbf, time_t iat, time_t now, int max_clock_skew);

bastion_jwt_result_t bastion_jwt_validate_issuer_audience(
    const char *iss, const char *aud,
    const char *expected_issuer, const char *expected_audience);
#endif

#endif /* BASTION_JWT_H */
