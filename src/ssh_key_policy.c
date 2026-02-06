/*
 * ssh_key_policy.c - SSH key type and size policy enforcement
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

#include "ssh_key_policy.h"

/* Default minimum key sizes */
#define DEFAULT_MIN_RSA_BITS   2048
#define DEFAULT_MIN_ECDSA_BITS 256

void ssh_key_policy_init(ssh_key_policy_t *policy)
{
    if (!policy) return;

    policy->enabled = false;
    policy->allow_rsa = true;
    policy->allow_ed25519 = true;
    policy->allow_ecdsa = true;
    policy->allow_dsa = false;       /* DSA is deprecated */
    policy->allow_sk = true;         /* FIDO2 keys allowed by default */
    policy->min_rsa_bits = DEFAULT_MIN_RSA_BITS;
    policy->min_ecdsa_bits = DEFAULT_MIN_ECDSA_BITS;
}

int ssh_key_policy_parse_types(ssh_key_policy_t *policy, const char *types_str)
{
    if (!policy || !types_str) return -1;

    /* Disable all types first, then enable only specified ones */
    policy->allow_rsa = false;
    policy->allow_ed25519 = false;
    policy->allow_ecdsa = false;
    policy->allow_dsa = false;
    policy->allow_sk = false;

    /* Parse comma-separated list without modifying original string */
    const char *p = types_str;
    while (*p) {
        /* Skip leading whitespace and commas */
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p) break;

        /* Find end of token */
        const char *start = p;
        while (*p && !isspace((unsigned char)*p) && *p != ',') p++;
        size_t len = (size_t)(p - start);

        /* Match token */
        if (len == 3 && strncasecmp(start, "all", 3) == 0) {
            policy->allow_rsa = true;
            policy->allow_ed25519 = true;
            policy->allow_ecdsa = true;
            policy->allow_sk = true;
            /* Note: DSA not included in "all" - must be explicit */
        }
        else if (len == 3 && strncasecmp(start, "rsa", 3) == 0) {
            policy->allow_rsa = true;
        }
        else if (len == 7 && strncasecmp(start, "ed25519", 7) == 0) {
            policy->allow_ed25519 = true;
        }
        else if (len == 5 && strncasecmp(start, "ecdsa", 5) == 0) {
            policy->allow_ecdsa = true;
        }
        else if (len == 3 && strncasecmp(start, "dsa", 3) == 0) {
            policy->allow_dsa = true;
        }
        else if (len == 2 && strncasecmp(start, "sk", 2) == 0) {
            policy->allow_sk = true;
        }
        else if (len == 5 && strncasecmp(start, "fido2", 5) == 0) {
            policy->allow_sk = true;  /* Alias for sk */
        }
        /* Unknown types are silently ignored */
    }

    return 0;
}

ssh_key_type_t ssh_key_parse_algorithm(const char *algorithm)
{
    if (!algorithm || !*algorithm) {
        return SSH_KEY_TYPE_UNKNOWN;
    }

    /*
     * Handle certificate types by stripping -cert-v01@openssh.com suffix
     * Example: "ssh-ed25519-cert-v01@openssh.com" -> "ssh-ed25519"
     */
    char algo_buf[128];
    size_t algo_len = strlen(algorithm);
    if (algo_len >= sizeof(algo_buf)) {
        return SSH_KEY_TYPE_UNKNOWN;
    }

    memcpy(algo_buf, algorithm, algo_len + 1);

    /* Strip certificate suffix if present */
    char *cert_suffix = strstr(algo_buf, "-cert-");
    if (cert_suffix) {
        *cert_suffix = '\0';
    }

    /* RSA variants */
    if (strcmp(algo_buf, "ssh-rsa") == 0 ||
        strcmp(algo_buf, "rsa-sha2-256") == 0 ||
        strcmp(algo_buf, "rsa-sha2-512") == 0) {
        return SSH_KEY_TYPE_RSA;
    }

    /* Ed25519 */
    if (strcmp(algo_buf, "ssh-ed25519") == 0) {
        return SSH_KEY_TYPE_ED25519;
    }

    /* FIDO2/Security Key Ed25519 */
    if (strcmp(algo_buf, "sk-ssh-ed25519@openssh.com") == 0 ||
        strcmp(algo_buf, "sk-ssh-ed25519") == 0) {
        return SSH_KEY_TYPE_SK_ED25519;
    }

    /* ECDSA variants */
    if (strcmp(algo_buf, "ecdsa-sha2-nistp256") == 0) {
        return SSH_KEY_TYPE_ECDSA_256;
    }
    if (strcmp(algo_buf, "ecdsa-sha2-nistp384") == 0) {
        return SSH_KEY_TYPE_ECDSA_384;
    }
    if (strcmp(algo_buf, "ecdsa-sha2-nistp521") == 0) {
        return SSH_KEY_TYPE_ECDSA_521;
    }

    /* FIDO2/Security Key ECDSA */
    if (strcmp(algo_buf, "sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
        strcmp(algo_buf, "sk-ecdsa-sha2-nistp256") == 0) {
        return SSH_KEY_TYPE_SK_ECDSA;
    }

    /* DSA (deprecated) */
    if (strcmp(algo_buf, "ssh-dss") == 0) {
        return SSH_KEY_TYPE_DSA;
    }

    return SSH_KEY_TYPE_UNKNOWN;
}

int ssh_key_type_bits(ssh_key_type_t type)
{
    switch (type) {
    case SSH_KEY_TYPE_ED25519:
    case SSH_KEY_TYPE_SK_ED25519:
        return 256;  /* Ed25519 is always 256 bits */

    case SSH_KEY_TYPE_ECDSA_256:
    case SSH_KEY_TYPE_SK_ECDSA:
        return 256;

    case SSH_KEY_TYPE_ECDSA_384:
        return 384;

    case SSH_KEY_TYPE_ECDSA_521:
        return 521;

    case SSH_KEY_TYPE_DSA:
        return 1024;  /* DSA is typically 1024 bits */

    case SSH_KEY_TYPE_RSA:
        return 0;  /* RSA size varies, not determinable from algorithm alone */

    case SSH_KEY_TYPE_UNKNOWN:
    default:
        return 0;
    }
}

const char *ssh_key_type_name(ssh_key_type_t type)
{
    switch (type) {
    case SSH_KEY_TYPE_RSA:
        return "RSA";
    case SSH_KEY_TYPE_ED25519:
        return "Ed25519";
    case SSH_KEY_TYPE_ECDSA_256:
        return "ECDSA-256";
    case SSH_KEY_TYPE_ECDSA_384:
        return "ECDSA-384";
    case SSH_KEY_TYPE_ECDSA_521:
        return "ECDSA-521";
    case SSH_KEY_TYPE_DSA:
        return "DSA";
    case SSH_KEY_TYPE_SK_ED25519:
        return "SK-Ed25519";
    case SSH_KEY_TYPE_SK_ECDSA:
        return "SK-ECDSA";
    case SSH_KEY_TYPE_UNKNOWN:
    default:
        return "Unknown";
    }
}

bool ssh_key_policy_check_rsa_size(const ssh_key_policy_t *policy, int bits)
{
    if (!policy) return false;
    return bits >= policy->min_rsa_bits;
}

bool ssh_key_policy_check(const ssh_key_policy_t *policy,
                          const char *algorithm,
                          ssh_key_validation_result_t *result)
{
    /* Initialize result */
    ssh_key_validation_result_t local_result = {
        .valid = false,
        .type = SSH_KEY_TYPE_UNKNOWN,
        .key_bits = 0,
        .error = NULL
    };

    if (!policy) {
        local_result.error = "No policy configured";
        if (result) *result = local_result;
        return false;
    }

    /* If policy is disabled, allow everything */
    if (!policy->enabled) {
        local_result.valid = true;
        local_result.type = ssh_key_parse_algorithm(algorithm);
        local_result.key_bits = ssh_key_type_bits(local_result.type);
        if (result) *result = local_result;
        return true;
    }

    if (!algorithm || !*algorithm) {
        local_result.error = "No algorithm specified";
        if (result) *result = local_result;
        return false;
    }

    /* Parse the algorithm */
    local_result.type = ssh_key_parse_algorithm(algorithm);
    local_result.key_bits = ssh_key_type_bits(local_result.type);

    /* Check if type is allowed */
    switch (local_result.type) {
    case SSH_KEY_TYPE_RSA:
        if (!policy->allow_rsa) {
            local_result.error = "RSA keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        /*
         * For RSA, we can't check the key size from the algorithm alone.
         * The size check must be done separately if size information
         * is available from another source.
         */
        local_result.valid = true;
        break;

    case SSH_KEY_TYPE_ED25519:
        if (!policy->allow_ed25519) {
            local_result.error = "Ed25519 keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        local_result.valid = true;
        break;

    case SSH_KEY_TYPE_SK_ED25519:
        if (!policy->allow_sk) {
            local_result.error = "FIDO2/Security keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        if (!policy->allow_ed25519) {
            local_result.error = "Ed25519 keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        local_result.valid = true;
        break;

    case SSH_KEY_TYPE_ECDSA_256:
        if (!policy->allow_ecdsa) {
            local_result.error = "ECDSA keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        if (local_result.key_bits < policy->min_ecdsa_bits) {
            local_result.error = "ECDSA key size below minimum required";
            if (result) *result = local_result;
            return false;
        }
        local_result.valid = true;
        break;

    case SSH_KEY_TYPE_ECDSA_384:
    case SSH_KEY_TYPE_ECDSA_521:
        if (!policy->allow_ecdsa) {
            local_result.error = "ECDSA keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        if (local_result.key_bits < policy->min_ecdsa_bits) {
            local_result.error = "ECDSA key size below minimum required";
            if (result) *result = local_result;
            return false;
        }
        local_result.valid = true;
        break;

    case SSH_KEY_TYPE_SK_ECDSA:
        if (!policy->allow_sk) {
            local_result.error = "FIDO2/Security keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        if (!policy->allow_ecdsa) {
            local_result.error = "ECDSA keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        local_result.valid = true;
        break;

    case SSH_KEY_TYPE_DSA:
        if (!policy->allow_dsa) {
            local_result.error = "DSA keys are not allowed by policy (deprecated)";
            if (result) *result = local_result;
            return false;
        }
        local_result.valid = true;
        break;

    case SSH_KEY_TYPE_UNKNOWN:
    default:
        local_result.error = "Unknown or unsupported key type";
        if (result) *result = local_result;
        return false;
    }

    if (result) *result = local_result;
    return local_result.valid;
}
