/*
 * ssh_key_policy.h - SSH key type and size policy enforcement
 *
 * This module enforces policy restrictions on SSH key types and minimum
 * key sizes.
 *
 * Two sources of truth are supported:
 *   - an algorithm *name* (e.g. from SSH_USER_AUTH), which cannot carry the
 *     RSA modulus size — see ssh_key_policy_check();
 *   - the key material itself (sshd's `%k` token), decoded by
 *     ssh_key_blob_info(), which yields both the real type and the real size.
 * Production enforcement uses ssh_key_policy_check_key() with the latter.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef SSH_KEY_POLICY_H
#define SSH_KEY_POLICY_H

#include <stdbool.h>
#include <stddef.h>

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
 * Check if a key type is allowed by the policy (TYPE ONLY).
 *
 * WARNING: this entry point cannot enforce `min_rsa_bits`, because an RSA
 * algorithm name carries no size information. It accepts any RSA key when
 * `allow_rsa` is set. Production code that has (or should have) the key size
 * MUST use ssh_key_policy_check_key() instead; this variant is kept for
 * callers that only ever see an algorithm string.
 *
 * Parameters:
 *   policy    - Policy configuration
 *   algorithm - SSH algorithm string (e.g. from SSH_USER_AUTH)
 *   result    - Output validation result (may be NULL)
 *
 * Returns true if allowed, false if rejected.
 */
bool ssh_key_policy_check(const ssh_key_policy_t *policy,
                          const char *algorithm,
                          ssh_key_validation_result_t *result);

/*
 * Full policy check: key type AND key size.
 *
 * `key_bits` is the size derived from the key material itself (see
 * ssh_key_blob_info()); pass 0 when it is unknown.
 *
 * Fail-closed semantics: when the policy is enabled and the size of a
 * variable-size key (RSA) is unknown, the key is REJECTED — an unverifiable
 * key must not be treated as a compliant one.
 *
 * Returns true if allowed, false if rejected.
 */
bool ssh_key_policy_check_key(const ssh_key_policy_t *policy,
                              const char *algorithm,
                              int key_bits,
                              ssh_key_validation_result_t *result);

/* Maximum accepted length of a base64-encoded SSH key/certificate blob. */
#define SSH_KEY_BLOB_B64_MAX 16384

/*
 * Decode a base64-encoded SSH public key or certificate blob — the `%k` token
 * of sshd's AuthorizedKeysCommand / AuthorizedPrincipalsCommand — and derive
 * the key type and size from the key material itself.
 *
 * This is strictly stronger than parsing an algorithm *name*: the RSA modulus
 * size is only available here, and the type cannot be misreported.
 *
 * Parameters:
 *   blob_b64  - base64 blob (no whitespace, optional '=' padding)
 *   algo_out  - buffer receiving the algorithm name found inside the blob
 *               (may be NULL), e.g. "ssh-rsa-cert-v01@openssh.com"
 *   algo_sz   - size of algo_out
 *   type_out  - receives the detected key type (may be NULL)
 *   bits_out  - receives the key size in bits (may be NULL)
 *
 * Returns true when the blob was decoded and understood, false otherwise
 * (invalid base64, truncated blob, unknown key type).
 */
bool ssh_key_blob_info(const char *blob_b64,
                       char *algo_out, size_t algo_sz,
                       ssh_key_type_t *type_out,
                       int *bits_out);

/*
 * Fingerprint of a base64-encoded SSH public key blob, in the form
 * `ssh-keygen -l` prints it: "SHA256:<base64 without padding>" when hash is
 * "SHA256", "MD5:<lowercase hex pairs joined by ':'>" when hash is "MD5".
 * The digest covers the decoded blob, as OpenSSH's does for a plain key.
 *
 * type_out (may be NULL) receives the key type name the blob carries, so a
 * caller can check it against the type written next to the blob.
 *
 * Returns false on a blob that does not decode, an unknown hash name, or a
 * buffer too small.
 */
bool ssh_key_blob_fingerprint(const char *blob_b64, const char *hash,
                              char *type_out, size_t type_sz,
                              char *out, size_t out_sz);

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
