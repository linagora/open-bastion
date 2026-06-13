# shellcheck shell=bash
# shellcheck disable=SC2155
#
# ob-cert-lib.sh - shared bastion certificate-vouching helpers
#
# Sourced by ob-ssh and ob-scp. Holds the
# common configuration, logging and the LLNG /pam/bastion-cert minting flow so
# both the SSH and SCP front-ends behave identically.
#
# This file is meant to be SOURCED, not executed. It does not set shell options
# (the sourcing script owns `set -euo pipefail`) and defines no main().
#
# Copyright (C) 2025 Linagora
# Author: Xavier Guimard <xguimard@linagora.com>
# License: AGPL-3.0

# Configuration (can be overridden via /etc/open-bastion/ssh-proxy.conf, then by
# the sourcing script before load_config is called).
: "${PORTAL_URL:=}"
: "${SERVER_TOKEN_FILE:=/var/lib/open-bastion/token}"
: "${TARGET_GROUP:=default}"
: "${TIMEOUT:=10}"
: "${VERIFY_SSL:=true}"
: "${DEBUG:=false}"
: "${CONFIG_FILE:=/etc/open-bastion/ssh-proxy.conf}"
# SSH_OPTIONS_ARRAY may already be set by the caller; default to empty.
if ! declare -p SSH_OPTIONS_ARRAY >/dev/null 2>&1; then
    SSH_OPTIONS_ARRAY=()
fi

# Per-session voucher proving this user connected to this bastion. Set by
# pam_openbastion (pam_putenv) at bastion login and inherited by this session
# on the SAME host — unlike the old SendEnv JWT, this transport actually works.
VOUCHER="${LLNG_BASTION_VOUCHER:-}"

# ── Logging ──────────────────────────────────────────────────────────────────
debug() { if [ "$DEBUG" = "true" ]; then echo "[DEBUG] $*" >&2; fi; }
warn()  { echo "[WARN] $*" >&2; }
error() { echo "[ERROR] $*" >&2; }

# ── Configuration loading ────────────────────────────────────────────────────
# Load /etc/open-bastion/ssh-proxy.conf securely (root-owned, not group/world
# writable). Parsed line-by-line — never sourced — to avoid code injection.
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        local file_stat
        file_stat=$(stat -c '%u:%a' "$CONFIG_FILE" 2>/dev/null)
        if [ -z "$file_stat" ]; then
            error "Unable to check permissions for config file: $CONFIG_FILE"
            exit 1
        fi

        local owner="${file_stat%%:*}"
        local perms="${file_stat##*:}"

        # Must be owned by root (uid 0)
        if [ "$owner" != "0" ]; then
            error "Insecure config file ownership (must be root): $CONFIG_FILE"
            exit 1
        fi

        # Check for group-writable (x2x) or world-writable (xx2)
        if [ $((perms % 100 / 10 & 2)) -ne 0 ] || [ $((perms % 10 & 2)) -ne 0 ]; then
            error "Insecure config file permissions (group/world-writable): $CONFIG_FILE"
            exit 1
        fi

        local key value
        while IFS='=' read -r key value || [ -n "$key" ]; do
            key="${key%%#*}"
            key="${key// /}"
            [ -z "$key" ] && continue
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            value="${value#\"}" ; value="${value%\"}"
            value="${value#\'}" ; value="${value%\'}"
            case "$key" in
                PORTAL_URL)          PORTAL_URL="$value" ;;
                SERVER_TOKEN_FILE)   SERVER_TOKEN_FILE="$value" ;;
                # SERVER_GROUP accepted-but-ignored (back-compat): the bastion's
                # group is resolved server-side from its enrolled token.
                SERVER_GROUP)        : ;;
                TARGET_GROUP)        TARGET_GROUP="$value" ;;
                TIMEOUT)             TIMEOUT="$value" ;;
                VERIFY_SSL)          VERIFY_SSL="$value" ;;
                DEBUG)               DEBUG="$value" ;;
                SSH_OPTIONS)
                    read -r -a SSH_OPTIONS_ARRAY <<<"$value"
                    ;;
            esac
        done < "$CONFIG_FILE"
    fi
}

# Validate required configuration and warn about insecure transports. Call after
# load_config from the sourcing script's main().
validate_config() {
    if [ -z "$PORTAL_URL" ]; then
        error "PORTAL_URL not configured. Set it in $CONFIG_FILE"
        exit 1
    fi
    if [[ "$PORTAL_URL" != https://* ]] && [[ "$VERIFY_SSL" != "false" ]]; then
        warn "PORTAL_URL does not use HTTPS - credentials will be sent in clear text"
    fi
}

# ── Certificate minting ──────────────────────────────────────────────────────
# Build curl options into the global CURL_OPTS array.
build_curl_opts() {
    # --fail-with-body (not -f): on a non-2xx response curl still writes the
    # JSON error body to stdout AND returns non-zero, so the caller can detect
    # structured reasons like {"reason":"voucher_expired"} instead of getting an
    # empty body. (-f would discard the body and hide the reason.)
    CURL_OPTS=("-s" "--fail-with-body" "--connect-timeout" "$TIMEOUT")
    if [ "$VERIFY_SSL" = "false" ]; then
        CURL_OPTS+=("-k")
    fi
}

# Read the server access token (JSON from ob-enroll, or plain text).
get_server_token() {
    if [ ! -f "$SERVER_TOKEN_FILE" ]; then
        error "Server token file not found: $SERVER_TOKEN_FILE"
        exit 1
    fi
    if head -c1 "$SERVER_TOKEN_FILE" | grep -q '{'; then
        jq -r '.access_token // empty' "$SERVER_TOKEN_FILE" 2>/dev/null || cat "$SERVER_TOKEN_FILE"
    else
        cat "$SERVER_TOKEN_FILE"
    fi
}

# Validate a hostname to prevent SSH option injection.
# Only allows: alphanumeric, dots, hyphens, underscores, colons (IPv6), brackets.
validate_hostname() {
    local host="$1"
    # NB: in an ERE bracket expression a literal ']' must come FIRST (and '-'
    # last); '\]' does NOT escape it — it closes the set and breaks the regex.
    if [[ ! "$host" =~ ^[][a-zA-Z0-9.:_-]+$ ]]; then
        error "Invalid hostname: $host"
        exit 1
    fi
    if [[ "$host" == -* ]]; then
        error "Invalid hostname (starts with dash): $host"
        exit 1
    fi
}

# Request a short-lived bastion certificate from LLNG.
# Args: <user> <target_host> <ephemeral_public_key>
# Prints the signed certificate on stdout; returns non-zero on failure.
request_bastion_cert() {
    local user="$1"
    local target_host="$2"
    local pubkey="$3"

    if [ -z "$VOUCHER" ]; then
        error "No bastion voucher found (LLNG_BASTION_VOUCHER is unset)."
        error "This session was not vouched by the bastion PAM module (or it"
        error "predates the cert-vouching feature). Reconnect to the bastion."
        return 1
    fi

    debug "Requesting bastion cert for user $user to host $target_host"

    local response
    if [ -r "$SERVER_TOKEN_FILE" ]; then
        # Privileged path (root, or a relaxed lab setup): call LLNG directly.
        local server_token
        server_token=$(get_server_token)
        if [ -z "$server_token" ]; then
            error "Failed to read server token"
            return 1
        fi

        build_curl_opts

        local json_payload
        json_payload=$(jq -n \
            --arg user "$user" \
            --arg target_host "$target_host" \
            --arg target_group "$TARGET_GROUP" \
            --arg public_key "$pubkey" \
            --arg voucher "$VOUCHER" \
            '{user: $user, target_host: $target_host, target_group: $target_group, public_key: $public_key, voucher: $voucher}')

        # 2>/dev/null (not 2>&1): keep curl's stderr OUT of $response so it stays
        # valid JSON. With --fail-with-body the JSON error body is captured even
        # on non-2xx, so we do NOT early-return on a non-zero rc — the parser
        # below extracts .reason/.error. Only a truly empty response is fatal.
        response=$(curl "${CURL_OPTS[@]}" \
            -X POST \
            -H "Authorization: Bearer $server_token" \
            -H "Content-Type: application/json" \
            -d "$json_payload" \
            "${PORTAL_URL}/pam/bastion-cert" 2>/dev/null) || true
        if [ -z "$response" ]; then
            error "Failed to request bastion certificate (no response from ${PORTAL_URL}/pam/bastion-cert)"
            return 1
        fi
    else
        # Normal user path: the server token is root-only BY DESIGN. Delegate the
        # single privileged call to ob-bastion-cert-helper through the narrow
        # NOPASSWD sudoers rule installed by ob-bastion-setup. The helper always
        # mints for the INVOKING user, whatever we send it.
        debug "Server token not readable; delegating to ob-bastion-cert-helper"
        local rc=0
        response=$(printf '%s\n%s\n' "$VOUCHER" "$pubkey" \
            | sudo -n /usr/sbin/ob-bastion-cert-helper "$target_host" "$TARGET_GROUP") || rc=$?
        if [ -z "$response" ]; then
            error "Failed to request bastion certificate via ob-bastion-cert-helper (rc=$rc)."
            error "Is the sudoers rule installed? (re-run ob-bastion-setup on this bastion)"
            return 1
        fi
    fi

    local cert
    cert=$(echo "$response" | jq -r '.certificate // empty' 2>/dev/null)
    if [ -z "$cert" ]; then
        local reason err_msg
        reason=$(echo "$response" | jq -r '.reason // empty' 2>/dev/null)
        err_msg=$(echo "$response" | jq -r '.error // .message // empty' 2>/dev/null)
        if [ "$reason" = "voucher_expired" ]; then
            error "Your bastion authorization has expired."
            error "Reconnect to the bastion to refresh it, then retry."
        elif [ -n "$err_msg" ]; then
            error "LLNG refused to issue a certificate: $err_msg${reason:+ ($reason)}"
        else
            error "Invalid response from LLNG: $response"
        fi
        return 1
    fi

    printf '%s\n' "$cert"
}

# Mint an ephemeral keypair + LLNG-signed certificate for <user> reaching
# <target_host>. The private key lives in tmpfs and never leaves the bastion.
#
# On success sets the globals:
#   OB_EPH_DIR   ephemeral directory (caller MUST clean it up, e.g.
#                `trap 'rm -rf "$OB_EPH_DIR"' EXIT`)
#   OB_EPH_KEY   path to the ephemeral private key
#   OB_EPH_CERT  path to the signed certificate
# Returns non-zero on failure (with a message on stderr).
mint_ephemeral_cert() {
    local target_user="$1"
    local target_host="$2"

    validate_hostname "$target_host"

    OB_EPH_DIR=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/ob-hop.XXXXXX") || {
        error "Failed to create ephemeral key directory"
        return 1
    }
    chmod 700 "$OB_EPH_DIR"

    ssh-keygen -t ed25519 -N '' -q -f "$OB_EPH_DIR/id" -C "ob-ephemeral" || {
        error "Failed to generate ephemeral keypair"
        return 1
    }

    local pubkey cert
    pubkey=$(cat "$OB_EPH_DIR/id.pub")
    cert=$(request_bastion_cert "$target_user" "$target_host" "$pubkey") || return 1
    printf '%s\n' "$cert" > "$OB_EPH_DIR/id-cert.pub"

    # Consumed by the sourcing script (ob-ssh / ob-scp), not within this lib.
    # shellcheck disable=SC2034
    OB_EPH_KEY="$OB_EPH_DIR/id"
    # shellcheck disable=SC2034
    OB_EPH_CERT="$OB_EPH_DIR/id-cert.pub"
    debug "Got ephemeral cert for ${target_user}@${target_host} in $OB_EPH_DIR"
}
