#!/bin/bash
# sso-discovery.sh - OIDC discovery + SSH CA / KRL / JWKS fetch for ob-builder.
#
# Public functions:
#   sso_validate_url URL          → populates SSO_* globals on success
#   sso_fetch_ca URL OUTFILE      → writes CA pubkey, sets SSO_CA_FINGERPRINT
#   sso_fetch_krl URL OUTFILE     → best-effort; returns 1 silently if unavailable
#   sso_fetch_jwks URL OUTFILE CLIENT_ID
#                                 → writes the canonical JWKS of that RP, sets
#                                   SSO_JWKS_SHA256; non-zero on failure
#
# All fetches honour the OB_BUILDER_INSECURE env var (skip TLS verification,
# set by --insecure). This module does no protocol check itself: the
# entrypoint refuses http:// unless --insecure was given.

if [ -n "${_OB_BUILDER_SSO_SOURCED:-}" ]; then
    return 0
fi
_OB_BUILDER_SSO_SOURCED=1

# Populated by sso_validate_url and consumed by the entrypoint via globals.
# shellcheck disable=SC2034  # read by ob-builder across files
SSO_ISSUER=""
# shellcheck disable=SC2034
SSO_DEVICE_AUTH_ENDPOINT=""
# shellcheck disable=SC2034
SSO_TOKEN_ENDPOINT=""
SSO_JWKS_URI=""
# Populated by sso_fetch_ca:
# shellcheck disable=SC2034  # read by ob-builder template renderer
SSO_CA_FINGERPRINT=""

# Internal: build a curl command array honouring --insecure / TLS1.3 pref.
# We do not force --tlsv1.3 because some LLNG portals still run on TLS 1.2;
# we prefer it but accept lower. Connect-timeout keeps the builder snappy
# when the SSO is unreachable.
_sso_curl_opts() {
    local -a opts=("-sS" "-f" "--tlsv1.3" "--connect-timeout" "10" "--max-time" "30")
    if [ "${OB_BUILDER_INSECURE:-0}" = "1" ]; then
        opts+=("-k")
    fi
    printf '%s\n' "${opts[@]}"
}

# sso_validate_url URL
# Fetches /.well-known/openid-configuration and extracts the endpoints we
# need. Fatal (returns non-zero) if the document is missing or malformed.
sso_validate_url() {
    local url="$1"
    local discovery
    local -a opts
    mapfile -t opts < <(_sso_curl_opts)

    log_step "Validating SSO URL (OIDC discovery)"
    log_info "Fetching ${url}/.well-known/openid-configuration"

    if ! discovery=$(curl "${opts[@]}" "${url}/.well-known/openid-configuration" 2>/dev/null); then
        log_error "Failed to fetch OIDC discovery from ${url}"
        log_error "  - check the URL spelling"
        log_error "  - check TLS certificate validity (or use --insecure for self-signed)"
        log_error "  - check that the LLNG portal exposes /.well-known/openid-configuration"
        return 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is required to parse OIDC discovery; install it (apt install jq)"
        return 1
    fi

    SSO_ISSUER=$(printf '%s' "$discovery" | jq -r '.issuer // empty' 2>/dev/null)
    SSO_DEVICE_AUTH_ENDPOINT=$(printf '%s' "$discovery" | jq -r '.device_authorization_endpoint // empty' 2>/dev/null)
    SSO_TOKEN_ENDPOINT=$(printf '%s' "$discovery" | jq -r '.token_endpoint // empty' 2>/dev/null)
    SSO_JWKS_URI=$(printf '%s' "$discovery" | jq -r '.jwks_uri // empty' 2>/dev/null)

    if [ -z "$SSO_ISSUER" ] || [ -z "$SSO_TOKEN_ENDPOINT" ]; then
        log_error "OIDC discovery document is missing required fields (issuer/token_endpoint)"
        return 1
    fi

    if [ -z "$SSO_DEVICE_AUTH_ENDPOINT" ]; then
        log_warn "device_authorization_endpoint not advertised — Device Flow may not be enabled."
        log_warn "ob-enroll will fail until the LLNG portal advertises it."
    fi

    log_info "  issuer:                          $SSO_ISSUER"
    log_info "  token_endpoint:                  $SSO_TOKEN_ENDPOINT"
    log_info "  device_authorization_endpoint:   ${SSO_DEVICE_AUTH_ENDPOINT:-<not advertised>}"
    log_info "  jwks_uri:                        ${SSO_JWKS_URI:-<not advertised>}"
    return 0
}

# sso_fetch_ca URL OUTFILE
# Tries /ssh/ca?fingerprint=1 first; if the portal advertises the
# fingerprint (header X-OB-CA-Fingerprint or JSON field 'fingerprint'),
# we use it. Otherwise we recompute locally with ssh-keygen.
# Writes the raw CA pubkey (single-line "ssh-... ..." form) to OUTFILE and
# populates SSO_CA_FINGERPRINT.
sso_fetch_ca() {
    local url="$1"
    local outfile="$2"
    local -a opts
    mapfile -t opts < <(_sso_curl_opts)

    log_step "Fetching SSH CA public key"

    local hdr_file body_file
    hdr_file=$(mktemp -t ob-builder-ca-hdr.XXXXXX)
    body_file=$(mktemp -t ob-builder-ca-body.XXXXXX)
    # Cleanup helper used at every exit path; we deliberately do NOT use a
    # bash RETURN trap because RETURN traps without `set -T` persist across
    # all subsequent function returns in the same shell and would re-fire
    # against expanded-then-empty variables in later calls.
    _ca_cleanup() { rm -f -- "$hdr_file" "$body_file"; }

    # First attempt: ?fingerprint=1, with Accept: application/json so a
    # JSON-aware portal can return {"ca": "...", "fingerprint": "SHA256:..."}.
    if ! curl "${opts[@]}" -D "$hdr_file" -H 'Accept: application/json' \
              -o "$body_file" "${url}/ssh/ca?fingerprint=1" 2>/dev/null; then
        # Fallback: plain /ssh/ca
        if ! curl "${opts[@]}" -D "$hdr_file" -o "$body_file" "${url}/ssh/ca" 2>/dev/null; then
            log_error "Failed to fetch ${url}/ssh/ca"
            log_error "  - check that sshCaActivation is enabled on the LLNG portal"
            _ca_cleanup
            return 1
        fi
    fi

    local ca_pubkey fp=""
    # Detect JSON-shaped body.
    if head -c 1 -- "$body_file" 2>/dev/null | grep -q '{'; then
        if command -v jq >/dev/null 2>&1; then
            ca_pubkey=$(jq -r '.ca // .ca_public_key // empty' < "$body_file" 2>/dev/null)
            fp=$(jq -r '.fingerprint // empty' < "$body_file" 2>/dev/null)
        fi
        if [ -z "$ca_pubkey" ]; then
            log_error "JSON CA response missing 'ca' field"
            _ca_cleanup
            return 1
        fi
    else
        # Plain text body: the file itself is the pubkey.
        ca_pubkey=$(cat -- "$body_file")
    fi

    # If JSON didn't carry the fingerprint, try the response header.
    if [ -z "$fp" ] && [ -f "$hdr_file" ]; then
        fp=$(grep -i '^X-OB-CA-Fingerprint:' "$hdr_file" 2>/dev/null \
             | tail -n1 | sed -E 's/^[^:]+:[[:space:]]*//' | tr -d '\r\n')
    fi

    # Sanity: must look like an OpenSSH pubkey.
    if ! printf '%s' "$ca_pubkey" | grep -qE '^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-)'; then
        log_error "Fetched CA does not look like an OpenSSH public key"
        _ca_cleanup
        return 1
    fi

    # Write the CA. Strip trailing newlines, then add exactly one.
    printf '%s\n' "$(printf '%s' "$ca_pubkey" | sed -e ':a' -e '/^[[:space:]]*$/{$d;N;ba' -e '}')" > "$outfile"

    # Retro-compat fallback: recompute fingerprint locally if the portal
    # didn't advertise one. ssh-keygen -lf reads a file and prints
    # "<bits> SHA256:... comment (TYPE)".
    if [ -z "$fp" ]; then
        if command -v ssh-keygen >/dev/null 2>&1; then
            fp=$(ssh-keygen -lf "$outfile" 2>/dev/null | awk '{print $2}')
            if [ -n "$fp" ]; then
                log_info "Computed CA fingerprint locally (portal did not advertise one)"
            fi
        else
            log_warn "ssh-keygen not available; cannot compute CA fingerprint locally"
        fi
    else
        log_info "CA fingerprint provided by portal"
    fi

    # shellcheck disable=SC2034  # read by ob-builder template renderer
    SSO_CA_FINGERPRINT="$fp"
    log_info "CA written to $outfile"
    [ -n "$fp" ] && log_info "CA fingerprint: $fp"
    _ca_cleanup
    return 0
}

# sso_fetch_krl URL OUTFILE
# Best-effort: returns 0 if KRL fetched and looks valid, 1 otherwise
# (empty file at OUTFILE). Caller decides whether to abort or warn.
sso_fetch_krl() {
    local url="$1"
    local outfile="$2"
    local -a opts
    mapfile -t opts < <(_sso_curl_opts)

    log_step "Fetching SSH Key Revocation List (KRL)"

    local tmp
    tmp=$(mktemp -t ob-builder-krl.XXXXXX)

    if ! curl "${opts[@]}" -o "$tmp" "${url}/ssh/revoked" 2>/dev/null; then
        log_warn "KRL not available at ${url}/ssh/revoked (will use empty KRL initially)"
        rm -f -- "$tmp"
        : > "$outfile"
        return 1
    fi

    # KRL format starts with the magic "SSHKRL".
    if head -c 6 "$tmp" 2>/dev/null | grep -q 'SSHKRL'; then
        mv -f -- "$tmp" "$outfile"
        log_info "KRL written to $outfile"
        return 0
    fi

    log_warn "Fetched KRL does not have the SSHKRL magic; treating as unavailable"
    rm -f -- "$tmp"
    : > "$outfile"
    return 1
}

# The filter a JWKS must pass to be deployed as the trust anchor of signed
# portal answers (#339). It mirrors what src/ob_jws.c (add_key) can use: a JSON
# object whose "keys" array holds at least one key with a non-empty kid, meant
# for signatures (no "use" or use = sig; no "key_ops" or key_ops containing
# verify), of a supported shape: RSA of 2048 bits or more, EC on P-256, P-384
# or P-521, OKP Ed25519 (judged by the length of the base64url members; the
# curve point itself is left to the C verifier, which the setup script asks
# through ob-verify-response on the target). A private key ("d") anywhere
# refuses the whole file: it is the wrong file, and a trust anchor is public.
#
# ob-bastion-setup carries the same filter (OB_JWKS_FILTER); keep both in step.
SSO_JWKS_FILTER='def b64len: if type == "string" then gsub("=+$"; "") | length else -1 end;
type == "object"
  and (.keys | type == "array")
  and ([.keys[] | objects | select(has("d"))] | length == 0)
  and ([.keys[] | objects
        | select((.kid | type) == "string" and (.kid | length) > 0)
        | select((has("use") | not) or .use == "sig")
        | select((has("key_ops") | not)
                 or ((.key_ops | type) == "array" and any(.key_ops[]; . == "verify")))
        | select((.kty == "RSA" and (.n | b64len) >= 342 and (.e | b64len) > 0)
                 or (.kty == "EC" and ([.crv, (.x | b64len), (.y | b64len)]
                     | . == ["P-256", 43, 43] or . == ["P-384", 64, 64]
                       or . == ["P-521", 88, 88]))
                 or (.kty == "OKP" and .crv == "Ed25519" and (.x | b64len) == 43))
       ] | length > 0)'

# Same bound as OB_JWS_MAX_JWKS in src/ob_jws.c: a bigger file never loads.
SSO_JWKS_MAX_BYTES=262144

# Populated by sso_fetch_jwks: SHA-256 (hex) of the canonical JWKS written,
# and the client_id it was fetched for.
# shellcheck disable=SC2034  # read by ob-builder
SSO_JWKS_SHA256=""
# shellcheck disable=SC2034
SSO_JWKS_CLIENT_ID=""

# sso_jwks_url PORTAL CLIENT_ID
# The JWKS of the relying party CLIENT_ID: jwks_uri from the discovery when
# advertised, ${PORTAL}/oauth2/jwks otherwise (LemonLDAP::NG has no
# /.well-known/jwks.json), with client_id appended as a query parameter.
# Without client_id the portal answers with its global keys, which need not be
# the ones it signs this RP's answers with.
sso_jwks_url() {
    local url="$1" client_id="$2" base enc
    base="${SSO_JWKS_URI:-${url%/}/oauth2/jwks}"
    [ -n "$client_id" ] || { printf '%s' "$base"; return 0; }
    enc=$(jq -rn --arg v "$client_id" '$v | @uri') || return 1
    case "$base" in
        *\?*) printf '%s&client_id=%s' "$base" "$enc" ;;
        *)    printf '%s?client_id=%s' "$base" "$enc" ;;
    esac
}

# sso_jwks_canonical FILE
# Prints the canonical form (sorted keys, compact: `jq -S -c .`) of FILE on
# stdout when it is a usable JWKS, fails otherwise. The portal's JSON encoder
# does not sort keys, so two fetches of the same JWKS may differ byte for byte;
# the canonical form is what is written to the targets and fingerprinted, and
# anyone can reproduce the fingerprint with:
#   curl -s '<jwks url>' | jq -S -c . | sha256sum
sso_jwks_canonical() {
    local f="$1" size
    [ -f "$f" ] || return 1
    size=$(wc -c < "$f" 2>/dev/null) || return 1
    [ "$size" -gt 0 ] && [ "$size" -le "$SSO_JWKS_MAX_BYTES" ] || return 1
    jq -e "$SSO_JWKS_FILTER" "$f" >/dev/null 2>&1 || return 1
    jq -S -c . "$f"
}

# sso_jwks_sha256 FILE: SHA-256 (lowercase hex) of FILE as it is.
sso_jwks_sha256() {
    sha256sum -- "$1" | awk '{print $1}'
}

# sso_fetch_jwks URL OUTFILE CLIENT_ID
# The trust anchor of signed portal answers (#339), fetched for every role.
# Writes the canonical JWKS to OUTFILE and sets SSO_JWKS_SHA256 and
# SSO_JWKS_CLIENT_ID. Returns non-zero (OUTFILE untouched) when the fetch fails
# or the document is not a usable JWKS.
sso_fetch_jwks() {
    local url="$1"
    local outfile="$2"
    local client_id="${3:-}"
    local -a opts
    mapfile -t opts < <(_sso_curl_opts)

    log_step "Fetching the portal's JWKS (trust anchor of signed answers)"

    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is required to validate the JWKS; install it (apt install jq)"
        return 1
    fi

    local jwks_url
    jwks_url=$(sso_jwks_url "$url" "$client_id") || {
        log_error "Cannot build the JWKS URL for client_id '$client_id'"
        return 1
    }
    log_info "Fetching $jwks_url"

    local tmp canon
    tmp=$(mktemp -t ob-builder-jwks.XXXXXX)
    canon=$(mktemp -t ob-builder-jwks-canon.XXXXXX)

    if ! curl "${opts[@]}" -o "$tmp" "$jwks_url" 2>/dev/null; then
        log_error "Failed to fetch JWKS from $jwks_url"
        rm -f -- "$tmp" "$canon"
        return 1
    fi

    if ! sso_jwks_canonical "$tmp" > "$canon"; then
        log_error "The document at $jwks_url is not a usable JWKS: it must be a JSON"
        log_error "  object with a 'keys' array holding at least one RSA, EC or OKP"
        log_error "  signature key with a kid, no private key, and at most $SSO_JWKS_MAX_BYTES bytes."
        rm -f -- "$tmp" "$canon"
        return 1
    fi
    rm -f -- "$tmp"

    mv -f -- "$canon" "$outfile"
    # shellcheck disable=SC2034  # read by ob-builder
    SSO_JWKS_SHA256=$(sso_jwks_sha256 "$outfile")
    # shellcheck disable=SC2034
    SSO_JWKS_CLIENT_ID="$client_id"
    log_info "JWKS written to $outfile ($(jq '[.keys[]] | length' "$outfile") key(s))"
    log_info "JWKS SHA-256: $SSO_JWKS_SHA256"
    return 0
}
