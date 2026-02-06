/*
 * ssh_key_policy.h - SSH key type and size policy enforcement
 *
 * This module enforces policy restrictions on SSH key types and minimum
 * key sizes. It validates keys during authentication based on the algorithm
 * information exposed by SSH via the SSH_USER_AUTH environment variable.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef SSH_KEY_POLICY_H
#define SSH_KEY_POLICY_H

#include <stdbool.h>

/* SSH key types */
typedef enum {
    SSH_KEY_TYPE_UNKNOWN = 0,
    SSH_KEY_TYPE_RSA,
    SSH_KEY_TYPE_ED25519,
    SSH_KEY_TYPE_ECDSA_256,   /* ecdsa-sha2-nistp256 */
    SSH_KEY_TYPE_ECDSA_384,   /* ecdsa-sha2-nistp384 */
    SSH_KEY_TYPE_ECDSA_521,   /* ecdsa-sha2-nistp521 */
    SSH_KEY_TYPE_DSA,         /* ssh-dss (deprecated) */
    SSH_KEY_TYPE_SK_ED25519,  /* sk-ssh-ed25519@openssh.com (FIDO2) */
    SSH_KEY_TYPE_SK_ECDSA,    /* sk-ecdsa-sha2-nistp256@openssh.com (FIDO2) */
} ssh_key_type_t;

/* SSH key policy configuration */
typedef struct {
    bool enabled;              /* Policy enforcement enabled */
    bool allow_rsa;            /* Allow RSA keys */
    bool allow_ed25519;        /* Allow Ed25519 keys */
    bool allow_ecdsa;          /* Allow ECDSA keys */
    bool allow_dsa;            /* Allow DSA keys (deprecated, default false) */
    bool allow_sk;             /* Allow FIDO2/security key types */
    int min_rsa_bits;          /* Minimum RSA key size (default: 2048) */
    int min_ecdsa_bits;        /* Minimum ECDSA key size (default: 256) */
} ssh_key_policy_t;

/* Validation result */
typedef struct {
    bool valid;                /* Key passes policy */
    ssh_key_type_t type;       /* Detected key type */
    int key_bits;              /* Key size in bits (0 if unknown) */
    const char *error;         /* Error message if invalid */
} ssh_key_validation_result_t;

/*
 * Initialize a policy structure with secure defaults.
 * Defaults: all modern types allowed, RSA >= 2048 bits, ECDSA >= 256 bits, DSA disabled.
 */
void ssh_key_policy_init(ssh_key_policy_t *policy);

/*
 * Parse allowed key types from a comma-separated string.
 * Recognized values: rsa, ed25519, ecdsa, dsa, sk (for FIDO2), all
 * Example: "ed25519,ecdsa,rsa"
 *
 * Returns 0 on success, -1 on error.
 */
int ssh_key_policy_parse_types(ssh_key_policy_t *policy, const char *types_str);

/*
 * Parse SSH key algorithm from SSH_USER_AUTH format.
 * Input format examples:
 *   - "ssh-rsa"
 *   - "ssh-ed25519"
 *   - "ecdsa-sha2-nistp256"
 *   - "ssh-ed25519-cert-v01@openssh.com" (certificate)
 *   - "sk-ssh-ed25519@openssh.com" (FIDO2)
 *
 * Returns the detected key type.
 */
ssh_key_type_t ssh_key_parse_algorithm(const char *algorithm);

/*
 * Get the key size in bits for a key type.
 * For fixed-size keys (Ed25519, ECDSA), returns the known size.
 * For RSA, returns 0 (size not determinable from algorithm alone).
 */
int ssh_key_type_bits(ssh_key_type_t type);

/*
 * Check if a key type is allowed by the policy.
 * Also checks minimum key size requirements.
 *
 * Parameters:
 *   policy    - Policy configuration
 *   algorithm - SSH algorithm string from SSH_USER_AUTH
 *   result    - Output validation result (may be NULL)
 *
 * Returns true if allowed, false if rejected.
 */
bool ssh_key_policy_check(const ssh_key_policy_t *policy,
                          const char *algorithm,
                          ssh_key_validation_result_t *result);

/*
 * Get human-readable name for a key type.
 */
const char *ssh_key_type_name(ssh_key_type_t type);

/*
 * Validate RSA key size (for additional validation when size is known).
 * This is useful when RSA key size is available from other sources.
 */
bool ssh_key_policy_check_rsa_size(const ssh_key_policy_t *policy, int bits);

#endif /* SSH_KEY_POLICY_H */
