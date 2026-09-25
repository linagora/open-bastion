# shellcheck shell=bash
#
# ob-sign-lib.sh - request signing for the shell callers of /pam/ endpoints
#
# Copyright (C) 2025 Linagora
# License: AGPL-3.0
#
# Sourced by ob-heartbeat, ob-bastion-id, ob-enroll and ob-session-monitor.
#
# The HMAC is computed by ob-sign-request, never `openssl dgst -hmac`, which
# takes the key on argv (world-readable via /proc). The body goes on stdin too:
# some bodies carry credentials.
#
# ob_sign_request METHOD PATH BODY sets SIGN_HEADERS (curl args, maybe none).
# It fails with OB_SIGN_ERROR when signing is configured but fails: sending
# unsigned then would be a silent downgrade. OB_SIGN_CONFIG names the conf.
#
# Read by the sourcing script; shellcheck, run per file, cannot see that.
# shellcheck disable=SC2034

SIGN_HEADERS=()
OB_SIGN_ERROR=""
OB_SIGN_NOTE=""

ob_sign_request() {
    local method="$1" path="$2" payload="$3"
    local helper out line rc=0
    local conf="${OB_SIGN_CONFIG:-/etc/open-bastion/openbastion.conf}"

    SIGN_HEADERS=()
    OB_SIGN_ERROR=""
    OB_SIGN_NOTE=""

    helper="${OB_SIGN_REQUEST:-}"
    if [ -z "$helper" ]; then
        helper=$(command -v ob-sign-request 2>/dev/null) \
            || helper="/usr/sbin/ob-sign-request"
    fi
    if [ ! -x "$helper" ]; then
        # Source checkout: not fatal, a portal in `required` refuses unsigned
        # requests visibly.
        OB_SIGN_NOTE="ob-sign-request not found; sending $path unsigned"
        return 0
    fi

    out=$(printf '%s' "$payload" \
        | "$helper" --method "$method" --path "$path" --config "$conf" 2>&1) || rc=$?
    case "$rc" in
        0) ;;
        3) return 0 ;;   # no request_signing_secret configured: nothing to sign
        *) OB_SIGN_ERROR="cannot sign $path: $out"; return 1 ;;
    esac

    while IFS= read -r line; do
        [ -n "$line" ] && SIGN_HEADERS+=("-H" "$line")
    done <<< "$out"
    return 0
}
