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

/*
 * Shared implementation of the policy check.
 *
 * key_bits      - size derived from the key material (0 = unknown)
 * enforce_size  - when true, a variable-size key (RSA) whose size is unknown
 *                 is REJECTED instead of silently accepted.
 */
static bool policy_check_impl(const ssh_key_policy_t *policy,
                              const char *algorithm,
                              int key_bits,
                              bool enforce_size,
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
        local_result.key_bits = key_bits > 0 ? key_bits
                                             : ssh_key_type_bits(local_result.type);
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
    /*
     * Prefer the size derived from the key material; fall back to the size
     * implied by the algorithm name (exact for Ed25519/ECDSA, unknown for RSA).
     */
    local_result.key_bits = key_bits > 0 ? key_bits
                                         : ssh_key_type_bits(local_result.type);

    /* Check if type is allowed */
    switch (local_result.type) {
    case SSH_KEY_TYPE_RSA:
        if (!policy->allow_rsa) {
            local_result.error = "RSA keys are not allowed by policy";
            if (result) *result = local_result;
            return false;
        }
        /*
         * RSA is the only variable-size type here, and its size is NOT
         * derivable from the algorithm name. When the caller supplied the size
         * (decoded from the key blob) we enforce min_rsa_bits; when it did not
         * and size enforcement was requested, we fail CLOSED — accepting a key
         * we cannot measure would make ssh_key_min_rsa_bits inert.
         */
        if (enforce_size) {
            if (local_result.key_bits <= 0) {
                local_result.error =
                    "RSA key size could not be determined - cannot enforce "
                    "ssh_key_min_rsa_bits";
                if (result) *result = local_result;
                return false;
            }
            if (!ssh_key_policy_check_rsa_size(policy, local_result.key_bits)) {
                local_result.error = "RSA key size below minimum required";
                if (result) *result = local_result;
                return false;
            }
        }
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
        /* SK_ECDSA is always P-256 (256 bits), check minimum requirement */
        if (local_result.key_bits < policy->min_ecdsa_bits) {
            local_result.error = "ECDSA key size below minimum required";
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

bool ssh_key_policy_check(const ssh_key_policy_t *policy,
                          const char *algorithm,
                          ssh_key_validation_result_t *result)
{
    /* Type-only check: no size information available, no size enforcement. */
    return policy_check_impl(policy, algorithm, 0, false, result);
}

bool ssh_key_policy_check_key(const ssh_key_policy_t *policy,
                              const char *algorithm,
                              int key_bits,
                              ssh_key_validation_result_t *result)
{
    return policy_check_impl(policy, algorithm, key_bits, true, result);
}

/* ------------------------------------------------------------------------ *
 * SSH public key / certificate blob decoding
 *
 * sshd hands the base64 blob of the presented key or certificate to
 * AuthorizedPrincipalsCommand via the %k token. Decoding it gives the
 * authoritative key type and, for RSA, the modulus size - neither of which can
 * be obtained from an algorithm name. The wire format (RFC 4253 section 6.6
 * and PROTOCOL.certkeys) is a sequence of length-prefixed strings/mpints:
 *
 *   plain key   : string type, <key material>
 *   certificate : string type, string nonce, <key material>, ...
 *
 * with key material:
 *   ssh-rsa                  : mpint e, mpint n         -> bits = |n|
 *   ssh-dss                  : mpint p, q, g, y         -> bits = |p|
 *   ssh-ed25519 / sk-ed25519 : string pk                -> 256
 *   ecdsa-sha2-*             : string curve, string Q   -> from curve
 *
 * Every field the type fixes is checked against an expected value (curve name,
 * point length, key sizes), so a blob whose material contradicts its own type
 * name is refused rather than reported with a size taken from that name.
 *
 * The same decode is implemented in Perl in the LLNG ssh-ca plugin
 * (_parseSshPubKey / _mpintBits); keep the two in sync.
 * ------------------------------------------------------------------------ */

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/*
 * Strict base64 decoder: rejects whitespace and any character outside the
 * standard alphabet (the spool writer already filters; this is defence in
 * depth). Returns a malloc'd buffer, or NULL.
 */
static unsigned char *b64_decode(const char *s, size_t *out_len)
{
    if (!s || !out_len) return NULL;

    size_t len = strlen(s);
    if (len == 0 || len > SSH_KEY_BLOB_B64_MAX || (len % 4) != 0) return NULL;

    /* Padding: at most two '=', only at the very end */
    size_t pad = 0;
    while (pad < 2 && len > pad && s[len - 1 - pad] == '=') pad++;
    for (size_t i = 0; i < len - pad; i++) {
        if (b64_value(s[i]) < 0) return NULL;
    }

    size_t out_cap = (len / 4) * 3;
    unsigned char *out = malloc(out_cap ? out_cap : 1);
    if (!out) return NULL;

    size_t o = 0;
    for (size_t i = 0; i + 3 < len; i += 4) {
        int v0 = b64_value(s[i]);
        int v1 = b64_value(s[i + 1]);
        int v2 = s[i + 2] == '=' ? 0 : b64_value(s[i + 2]);
        int v3 = s[i + 3] == '=' ? 0 : b64_value(s[i + 3]);
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            free(out);
            return NULL;
        }
        unsigned int triple = ((unsigned int)v0 << 18) | ((unsigned int)v1 << 12) |
                              ((unsigned int)v2 << 6)  | (unsigned int)v3;
        out[o++] = (unsigned char)((triple >> 16) & 0xFF);
        out[o++] = (unsigned char)((triple >> 8) & 0xFF);
        out[o++] = (unsigned char)(triple & 0xFF);
    }
    if (o < pad) {
        free(out);
        return NULL;
    }
    o -= pad;

    *out_len = o;
    return out;
}

/* Minimal cursor over an SSH wire-format buffer. */
typedef struct {
    const unsigned char *data;
    size_t len;
    size_t off;
} ssh_blob_reader_t;

/* Read a length-prefixed string (also used for mpints). */
static bool blob_get_string(ssh_blob_reader_t *r,
                            const unsigned char **out, size_t *out_len)
{
    if (!r || r->len < 4 || r->off > r->len - 4) return false;
    size_t n = ((size_t)r->data[r->off] << 24) |
               ((size_t)r->data[r->off + 1] << 16) |
               ((size_t)r->data[r->off + 2] << 8) |
               ((size_t)r->data[r->off + 3]);
    r->off += 4;
    /* Cannot overflow: r->off <= r->len, and n is compared to what is left */
    if (n > r->len - r->off) return false;
    if (out) *out = r->data + r->off;
    if (out_len) *out_len = n;
    r->off += n;
    return true;
}

/*
 * Curve name and public point size an algorithm name implies. OpenSSH
 * (sshkey_ecdsa_nid_from_name, SSH_ERR_EC_CURVE_MISMATCH) refuses a key whose
 * curve field disagrees with its type; a size read from the name of such a blob
 * would describe material the key does not hold.
 */
static const char *ecdsa_curve_name_for(ssh_key_type_t type)
{
    switch (type) {
    case SSH_KEY_TYPE_ECDSA_256:
    case SSH_KEY_TYPE_SK_ECDSA:
        return "nistp256";
    case SSH_KEY_TYPE_ECDSA_384:
        return "nistp384";
    case SSH_KEY_TYPE_ECDSA_521:
        return "nistp521";
    default:
        return NULL;
    }
}

static size_t ecdsa_point_len_for(ssh_key_type_t type)
{
    switch (type) {
    case SSH_KEY_TYPE_ECDSA_256:
    case SSH_KEY_TYPE_SK_ECDSA:
        return 1 + 2 * 32;
    case SSH_KEY_TYPE_ECDSA_384:
        return 1 + 2 * 48;
    case SSH_KEY_TYPE_ECDSA_521:
        return 1 + 2 * 66;
    default:
        return 0;
    }
}

/*
 * Whether an ECDSA curve field and public point are the ones the type names:
 * the same curve, and an uncompressed point (0x04 || X || Y) of its size.
 */
static bool ecdsa_material_matches(ssh_key_type_t type,
                                   const unsigned char *curve, size_t curve_len,
                                   const unsigned char *point, size_t point_len)
{
    const char *expected = ecdsa_curve_name_for(type);
    if (!expected) return false;
    if (curve_len != strlen(expected)
        || memcmp(curve, expected, curve_len) != 0) return false;
    if (point_len != ecdsa_point_len_for(type)) return false;
    return point[0] == 0x04;
}

/* Bit length of an SSH mpint (leading zero bytes stripped). */
static int mpint_bits(const unsigned char *d, size_t len)
{
    size_t i = 0;
    while (i < len && d[i] == 0) i++;
    if (i >= len) return 0;
    int bits = (int)((len - i - 1) * 8);
    unsigned char top = d[i];
    while (top) {
        bits++;
        top >>= 1;
    }
    return bits;
}

bool ssh_key_blob_info(const char *blob_b64,
                       char *algo_out, size_t algo_sz,
                       ssh_key_type_t *type_out,
                       int *bits_out)
{
    if (algo_out && algo_sz) algo_out[0] = '\0';
    if (type_out) *type_out = SSH_KEY_TYPE_UNKNOWN;
    if (bits_out) *bits_out = 0;

    if (!blob_b64 || !*blob_b64) return false;

    size_t raw_len = 0;
    unsigned char *raw = b64_decode(blob_b64, &raw_len);
    if (!raw) return false;

    bool ok = false;
    ssh_blob_reader_t r = { raw, raw_len, 0 };
    char algo_buf[128];
    ssh_key_type_t type = SSH_KEY_TYPE_UNKNOWN;
    int bits = 0;
    const unsigned char *field = NULL;
    size_t field_len = 0;
    const unsigned char *algo = NULL;
    size_t algo_len = 0;

    if (!blob_get_string(&r, &algo, &algo_len) || algo_len == 0
        || algo_len >= sizeof(algo_buf)) {
        goto out;
    }

    memcpy(algo_buf, algo, algo_len);
    algo_buf[algo_len] = '\0';
    /* The type name must be printable ASCII without spaces */
    for (size_t i = 0; i < algo_len; i++) {
        if (algo_buf[i] < 0x21 || algo_buf[i] > 0x7e) goto out;
    }

    type = ssh_key_parse_algorithm(algo_buf);
    if (type == SSH_KEY_TYPE_UNKNOWN) goto out;

    /* Certificates insert a nonce string before the key material */
    if (strstr(algo_buf, "-cert-") != NULL) {
        if (!blob_get_string(&r, NULL, NULL)) goto out;
    }

    switch (type) {
    case SSH_KEY_TYPE_RSA:
        /* mpint e, mpint n */
        if (!blob_get_string(&r, NULL, NULL)) goto out;
        if (!blob_get_string(&r, &field, &field_len)) goto out;
        bits = mpint_bits(field, field_len);
        if (bits <= 0) goto out;
        break;

    case SSH_KEY_TYPE_DSA:
        /* mpint p, q, g, y -> the prime p sets the size */
        if (!blob_get_string(&r, &field, &field_len)) goto out;
        bits = mpint_bits(field, field_len);
        if (bits <= 0) goto out;
        break;

    case SSH_KEY_TYPE_ED25519:
    case SSH_KEY_TYPE_SK_ED25519:
        /* string pk (32 bytes) */
        if (!blob_get_string(&r, &field, &field_len)) goto out;
        if (field_len != 32) goto out;
        bits = 256;
        break;

    case SSH_KEY_TYPE_ECDSA_256:
    case SSH_KEY_TYPE_ECDSA_384:
    case SSH_KEY_TYPE_ECDSA_521:
    case SSH_KEY_TYPE_SK_ECDSA:
        /* string curve name, string Q */
        {
            const unsigned char *curve = NULL;
            size_t curve_len = 0;
            if (!blob_get_string(&r, &curve, &curve_len)) goto out;
            if (!blob_get_string(&r, &field, &field_len)) goto out;
            if (!ecdsa_material_matches(type, curve, curve_len, field, field_len))
                goto out;
            bits = ssh_key_type_bits(type);
            if (bits <= 0) goto out;
        }
        break;

    default:
        goto out;
    }

    if (algo_out && algo_sz) {
        if (algo_len + 1 > algo_sz) goto out;
        memcpy(algo_out, algo_buf, algo_len + 1);
    }
    if (type_out) *type_out = type;
    if (bits_out) *bits_out = bits;
    ok = true;

out:
    free(raw);
    return ok;
}
