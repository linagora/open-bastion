# shellcheck shell=bash
# shellcheck disable=SC2155
#
# ob-cert-lib.sh - shared bastion certificate-vouching helpers
#
# Sourced (never executed) by ob-ssh, ob-scp and ob-sftp; the caller owns
# `set -euo pipefail`.
#
# Copyright (C) 2025 Linagora
# Author: Xavier Guimard <xguimard@linagora.com>
# License: AGPL-3.0

: "${PORTAL_URL:=}"
: "${TARGET_GROUP:=default}"
: "${TIMEOUT:=10}"
: "${VERIFY_SSL:=true}"
: "${DEBUG:=false}"
: "${CONFIG_FILE:=/etc/open-bastion/ssh-proxy.conf}"
if ! declare -p SSH_OPTIONS_ARRAY >/dev/null 2>&1; then
    SSH_OPTIONS_ARRAY=()
fi

# Per-session voucher set by pam_openbastion (pam_putenv) at bastion login.
VOUCHER="${LLNG_BASTION_VOUCHER:-}"

debug() { if [ "$DEBUG" = "true" ]; then echo "[DEBUG] $*" >&2; fi; }
warn()  { echo "[WARN] $*" >&2; }
error() { echo "[ERROR] $*" >&2; }

# Parsed line by line, never sourced; must be root-owned and not
# group/world-writable.
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
                # Read by ob-cert-daemon from this same file.
                SERVER_TOKEN_FILE)   : ;;
                # Ignored: the group is resolved server-side from the token.
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

# PORTAL_URL is not contacted here (ob-cert-daemon is), but a conf without it
# is an unconfigured bastion: fail clearly rather than on a socket error.
validate_config() {
    if [ -z "$PORTAL_URL" ]; then
        error "PORTAL_URL not configured. Set it in $CONFIG_FILE"
        exit 1
    fi
    if [[ "$PORTAL_URL" != https://* ]] && [[ "$VERIFY_SSL" != "false" ]]; then
        warn "PORTAL_URL does not use HTTPS - credentials will be sent in clear text"
    fi
}

# Default is accept-new (TOFU) unless SSH_OPTIONS sets StrictHostKeyChecking.
# ssh keeps the first value given, so this must follow SSH_OPTIONS.
# See doc/security/02-ssh-connection.rst.
build_host_key_opts() {
    # Consumed by the sourcing script (ob-ssh / ob-scp / ob-sftp), not this lib.
    # shellcheck disable=SC2034
    HOST_KEY_OPTS=()
    local opt
    for opt in ${SSH_OPTIONS_ARRAY[@]+"${SSH_OPTIONS_ARRAY[@]}"}; do
        case "$opt" in
            StrictHostKeyChecking=*|-oStrictHostKeyChecking=*) return 0 ;;
        esac
    done
    # shellcheck disable=SC2034
    HOST_KEY_OPTS=(-o StrictHostKeyChecking=accept-new)
}

# Guards against SSH option injection.
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

    # The server token is root-only: ob-cert-daemon holds it and mints for the
    # SO_PEERCRED user, whatever we send.
    local response
    local rc=0
    local client
    client=$(command -v ob-cert-request 2>/dev/null) || client="/usr/bin/ob-cert-request"
    # Protocol (newline-delimited): target_host, target_group, voucher, pubkey.
    response=$(printf '%s\n%s\n%s\n%s\n' \
        "$target_host" "$TARGET_GROUP" "$VOUCHER" "$pubkey" \
        | "$client") || rc=$?
    if [ -z "$response" ]; then
        error "Failed to request bastion certificate via ob-cert-daemon (rc=$rc)."
        error "Is ob-cert.socket enabled? (re-run ob-bastion-setup on this bastion)"
        return 1
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

# Sets OB_EPH_DIR (caller must remove it), OB_EPH_KEY and OB_EPH_CERT. The
# private key lives in tmpfs and never leaves the bastion.
mint_ephemeral_cert() {
    local target_user="$1"
    local target_host="$2"

    validate_hostname "$target_host"

    OB_EPH_DIR=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/ob-hop.XXXXXX") || {
        error "Failed to create ephemeral key directory"
        return 1
    }
    chmod 700 "$OB_EPH_DIR"

    # The caller arms its cleanup trap only on success: every failure path
    # must wipe the dir so the private key does not linger.
    if ! ssh-keygen -t ed25519 -N '' -q -f "$OB_EPH_DIR/id" -C "ob-ephemeral"; then
        error "Failed to generate ephemeral keypair"
        rm -rf "$OB_EPH_DIR"
        return 1
    fi

    local pubkey cert
    pubkey=$(cat "$OB_EPH_DIR/id.pub")
    if ! cert=$(request_bastion_cert "$target_user" "$target_host" "$pubkey"); then
        rm -rf "$OB_EPH_DIR"
        return 1
    fi
    printf '%s\n' "$cert" > "$OB_EPH_DIR/id-cert.pub"

    # Consumed by the sourcing script (ob-ssh / ob-scp / ob-sftp), not this lib.
    # shellcheck disable=SC2034
    OB_EPH_KEY="$OB_EPH_DIR/id"
    # shellcheck disable=SC2034
    OB_EPH_CERT="$OB_EPH_DIR/id-cert.pub"
    debug "Got ephemeral cert for ${target_user}@${target_host} in $OB_EPH_DIR"
}
