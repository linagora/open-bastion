# shellcheck shell=bash
# shellcheck disable=SC2155
#
# ob-cert-lib.sh - shared bastion certificate-vouching helpers
#
# Sourced by ob-ssh, ob-scp and ob-sftp. Holds the common configuration,
# logging and certificate-minting flow so the SSH, SCP and SFTP front-ends
# behave identically. Minting itself is delegated to ob-cert-daemon through the
# unprivileged ob-cert-request client; nothing here contacts the portal.
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
                # SERVER_TOKEN_FILE is consumed by ob-cert-daemon, which
                # parses this same file; nothing in this library reads the
                # server token any more, so accept the key and drop it here.
                SERVER_TOKEN_FILE)   : ;;
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
#
# PORTAL_URL is no longer contacted from here -- ob-cert-daemon holds the portal
# connection -- but it stays required: an ssh-proxy.conf without it is an
# unconfigured bastion, and failing here says so far more clearly than a socket
# error would.
validate_config() {
    if [ -z "$PORTAL_URL" ]; then
        error "PORTAL_URL not configured. Set it in $CONFIG_FILE"
        exit 1
    fi
    if [[ "$PORTAL_URL" != https://* ]] && [[ "$VERIFY_SSL" != "false" ]]; then
        warn "PORTAL_URL does not use HTTPS - credentials will be sent in clear text"
    fi
}

# ── Host-key policy ──────────────────────────────────────────────────────────
# Emit the default host-key options for the bastion->backend hop, unless the
# operator has already set StrictHostKeyChecking in SSH_OPTIONS.
#
# The default is accept-new: the first connection to a backend trusts whatever
# host key it presents (TOFU), later ones are pinned by known_hosts. An attacker
# who can intercept the bastion->backend path can therefore MITM that first hop
# and read the session. The ephemeral private key never leaves the bastion and
# the certificate is pinned to the bastion's source address, so credentials are
# not stolen -- but the session content is exposed.
#
# ssh takes the FIRST value it is given for an option, so this must be emitted
# after the operator's SSH_OPTIONS to be overridable; a site that pre-seeds
# /etc/ssh/ssh_known_hosts sets, in /etc/open-bastion/ssh-proxy.conf:
#
#   SSH_OPTIONS="-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts"
#
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

# ── Certificate minting ──────────────────────────────────────────────────────
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

    # The server token is root-only BY DESIGN, and this is the only path: the
    # single privileged call is performed by ob-cert-daemon (socket-activated,
    # runs as root), reached through the unprivileged ob-cert-request client.
    # The daemon derives the certificate's user from the connection's
    # SO_PEERCRED — so it always mints for the connecting user, whatever we send
    # — and the server token never leaves it. No sudo, no setuid, and minting is
    # decoupled from the interactive sudo policy (Mode E).
    #
    # Until 0.6.2 a `[ -r "$SERVER_TOKEN_FILE" ]` branch called LLNG directly
    # with the bearer token whenever the caller could read it — root, or a lab
    # that had relaxed the 0600. It was an escape hatch around the SO_PEERCRED
    # design with no counterpart in the daemon's checks, so it is gone: root
    # and unprivileged callers now take the same, audited path (#202).
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

    # Any failure from here on must wipe the tmpfs dir before returning: the
    # caller only arms its cleanup trap AFTER we succeed, so an early return
    # would otherwise leave the ephemeral private key on disk.
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
