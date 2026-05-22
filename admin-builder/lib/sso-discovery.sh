#!/bin/bash
# sso-discovery.sh - OIDC discovery + SSH CA / KRL / JWKS fetch for ob-builder.
#
# Public functions:
#   sso_validate_url URL          → populates SSO_* globals on success
#   sso_fetch_ca URL OUTFILE      → writes CA pubkey, sets SSO_CA_FINGERPRINT
#   sso_fetch_krl URL OUTFILE     → best-effort; returns 1 silently if unavailable
#   sso_fetch_jwks URL OUTFILE    → writes JWKS JSON; returns non-zero on failure
#
# All fetches honour the OB_BUILDER_INSECURE env var (skip TLS verification)
# and OB_BUILDER_ALLOW_HTTP (controls protocol enforcement upstream — this
# module does no protocol check itself; the entrypoint does that).

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
    local -a opts=("-sS" "-f" "--connect-timeout" "10" "--max-time" "30")
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

# sso_fetch_jwks URL OUTFILE
# Required for backend mode (JWT verification). Returns non-zero on failure.
sso_fetch_jwks() {
    local url="$1"
    local outfile="$2"
    local -a opts
    mapfile -t opts < <(_sso_curl_opts)

    log_step "Fetching SSO JWKS (for backend JWT verification)"

    # Prefer the URL advertised by OIDC discovery if we already have it,
    # falling back to the conventional path otherwise.
    local jwks_url="${SSO_JWKS_URI:-${url}/.well-known/jwks.json}"

    local tmp
    tmp=$(mktemp -t ob-builder-jwks.XXXXXX)

    if ! curl "${opts[@]}" -o "$tmp" "$jwks_url" 2>/dev/null; then
        log_error "Failed to fetch JWKS from $jwks_url"
        rm -f -- "$tmp"
        return 1
    fi

    # Sanity: must be JSON with a 'keys' array.
    if command -v jq >/dev/null 2>&1; then
        if ! jq -e '.keys | type == "array"' < "$tmp" >/dev/null 2>&1; then
            log_error "JWKS at $jwks_url is not a JSON document with a 'keys' array"
            rm -f -- "$tmp"
            return 1
        fi
    fi

    mv -f -- "$tmp" "$outfile"
    log_info "JWKS written to $outfile"
    return 0
}
