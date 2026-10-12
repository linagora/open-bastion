# shellcheck shell=bash
#
# ob-sign-lib.sh - request signing for the shell callers of /pam/ endpoints
#
# Copyright (C) 2025 Linagora
# License: AGPL-3.0
#
# Sourced by ob-heartbeat, ob-bastion-id, ob-enroll and ob-session-monitor.
# The second half (ob_pam_post) also checks the portal's signed answers.
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

# ── Signed answers (#339) ────────────────────────────────────────────────────
#
# ob_pam_post BASE_URL PATH BODY [CURL_ARG...] POSTs BODY to BASE_URL/PATH,
# signed as above, and applies `response_signing` (openbastion.conf) to the
# answer the way the PAM module does (ob_client.c, pam_call_answer):
#
#   off       nothing asked, nothing checked
#   prefer    a signed answer is asked for when the JWKS is usable; an
#             unsigned one is accepted with OB_PAM_WARNING set, a signed one
#             that does not verify is refused
#   required  an unsigned or invalid answer is refused, and with no usable
#             JWKS nothing is sent; so is an unrecognised mode
#
# A signed answer is checked by ob-verify-response against sso_jwks_file,
# sso_issuer (default: portal_url) and client_id, bound to the X-Nonce sent
# (the HMAC signature's own nonce when request_signing_secret is set) and to
# BODY. A verified answer without `aud` and a 2xx status is refused: the
# portal only omits `aud` on refusals.
#
# Returns 0 with OB_PAM_STATUS (HTTP status) and OB_PAM_BODY (the plain JSON
# answer, the verified `resp` for a signed one), OB_PAM_SIGNED (verified |
# unsigned) and OB_PAM_ANONYMOUS (true: verified, no `aud`, so it may only
# refuse). Returns 1 with OB_PAM_ERROR when nothing usable came back -- a
# transport error for the caller, whatever the portal said -- and
# OB_PAM_CURL_RC non-zero when curl itself failed. The caller's CURL_ARGs must
# not include -w, -o, -d or -f (a refusal must stay readable to be verified).
#
# OB_PAM_JWKS_OUT, when set, names a file that receives the `jwks` claim of an
# answer that verified with `aud` (ob-heartbeat's rotation); it is left alone
# otherwise. The settings read are left in OB_RS_* for the caller.

OB_PAM_MEDIA_TYPE="application/ob-pam-response+jwt"
OB_PAM_STATUS=""
OB_PAM_BODY=""
OB_PAM_SIGNED=""
OB_PAM_ANONYMOUS=false
OB_PAM_ERROR=""
OB_PAM_WARNING=""
OB_PAM_CURL_RC=0
OB_RS_MODE=off
OB_RS_JWKS=""
OB_RS_ISSUER=""
OB_RS_CLIENT_ID=""
OB_RS_HELPER=""

# ob_conf_get KEY FILE: the value of KEY, read the way config.c reads
# openbastion.conf -- the last occurrence wins, one layer of quotes is
# removed, and an unquoted value ends at a '#' that starts it or follows a
# blank. Not for the secret-bearing keys, which config.c reads verbatim.
ob_conf_get() {
    local key="$1" file="$2"
    [ -r "$file" ] || return 0
    awk -v want="$key" '
        function trim(s) { sub(/^[ \t\r\n\v\f]+/, "", s); sub(/[ \t\r\n\v\f]+$/, "", s); return s }
        {
            line = trim($0)
            c = substr(line, 1, 1)
            if (line == "" || c == "#" || c == ";" || c == "[") next
            eq = index(line, "=")
            if (!eq || trim(substr(line, 1, eq - 1)) != want) next
            v = trim(substr(line, eq + 1))
            q = substr(v, 1, 1)
            if (q == "\"" || q == "\047") {
                v = substr(v, 2)
                for (i = length(v); i > 0; i--) {
                    if (substr(v, i, 1) == q) { v = substr(v, 1, i - 1); break }
                }
            } else {
                for (i = 1; i <= length(v); i++) {
                    if (substr(v, i, 1) == "#" && (i == 1 || substr(v, i - 1, 1) ~ /[ \t]/)) {
                        v = trim(substr(v, 1, i - 1)); break
                    }
                }
            }
            val = v; found = 1
        }
        END { if (found) print val }
    ' "$file"
}

# ob_response_settings CONF [PORTAL]: fill OB_RS_*. An unrecognised mode is
# read as `required` (OB_RS_MODE=invalid): the module refuses such a file
# outright (config_validate), the NSS module reads it as required, and a typo
# must never turn the checks off.
ob_response_settings() {
    local conf="$1" portal="${2:-}" mode url
    mode=$(ob_conf_get response_signing "$conf")
    case "${mode:-off}" in
        off|prefer|required) OB_RS_MODE="${mode:-off}" ;;
        *) OB_RS_MODE=invalid ;;
    esac
    OB_RS_JWKS=$(ob_conf_get sso_jwks_file "$conf")
    OB_RS_JWKS="${OB_RS_JWKS:-/var/lib/open-bastion/jwks/sso-jwks.json}"
    OB_RS_CLIENT_ID=$(ob_conf_get client_id "$conf")
    OB_RS_ISSUER=$(ob_conf_get sso_issuer "$conf")
    if [ -z "$OB_RS_ISSUER" ]; then
        url=$(ob_conf_get portal_url "$conf")
        [ -n "$url" ] || url=$(ob_conf_get portal "$conf")
        [ -n "$url" ] || url="$portal"
        while [ "${url%/}" != "$url" ]; do url="${url%/}"; done
        OB_RS_ISSUER="$url"
    fi
    OB_RS_HELPER="${OB_VERIFY_RESPONSE:-}"
    if [ -z "$OB_RS_HELPER" ]; then
        OB_RS_HELPER=$(command -v ob-verify-response 2>/dev/null) \
            || OB_RS_HELPER="/usr/sbin/ob-verify-response"
    fi
}

# Can a signed answer be checked? Sets OB_RS_UNUSABLE to say why not.
ob_response_keys_usable() {
    local out
    OB_RS_UNUSABLE=""
    if [ ! -x "$OB_RS_HELPER" ]; then
        OB_RS_UNUSABLE="ob-verify-response not found"
    elif [ -z "$OB_RS_ISSUER" ]; then
        OB_RS_UNUSABLE="no sso_issuer and no portal_url"
    elif ! out=$("$OB_RS_HELPER" check-jwks --anchor --quiet "$OB_RS_JWKS" 2>&1); then
        OB_RS_UNUSABLE="${out:-$OB_RS_JWKS unusable}"
    fi
    [ -z "$OB_RS_UNUSABLE" ]
}

# A Content-Type naming the signed-answer media type (case-insensitive,
# parameters allowed), like ob_jws_is_media_type.
ob_is_signed_answer_type() {
    local ct="${1,,}"
    ct="${ct#"${ct%%[![:space:]]*}"}"
    case "$ct" in
        "$OB_PAM_MEDIA_TYPE" | "$OB_PAM_MEDIA_TYPE;"* | "$OB_PAM_MEDIA_TYPE "* \
            | "$OB_PAM_MEDIA_TYPE"$'\t'*) return 0 ;;
    esac
    return 1
}

ob_pam_post() {
    local base="$1" path="$2" payload="$3"
    shift 3
    local conf="${OB_SIGN_CONFIG:-/etc/open-bastion/openbastion.conf}"
    local endpoint="${path#/pam/}" ask=false nonce="" h raw meta ctype body out
    local rc=0 vrc=0
    local -a extra=() vargs=()

    OB_PAM_STATUS="" OB_PAM_BODY="" OB_PAM_SIGNED="" OB_PAM_ANONYMOUS=false
    OB_PAM_ERROR="" OB_PAM_WARNING="" OB_PAM_CURL_RC=0

    ob_response_settings "$conf" "$base"
    if [ "$OB_RS_MODE" != "off" ]; then
        if ob_response_keys_usable; then
            ask=true
        elif [ "$OB_RS_MODE" = "prefer" ]; then
            OB_PAM_WARNING="response_signing = prefer but no usable JWKS ($OB_RS_UNUSABLE): asking $path for a plain answer"
        else
            OB_PAM_ERROR="response_signing = ${OB_RS_MODE/invalid/required (invalid value)} but no usable JWKS ($OB_RS_UNUSABLE): $path not sent"
            return 1
        fi
    fi

    if ! ob_sign_request POST "$path" "$payload"; then
        OB_PAM_ERROR="$OB_SIGN_ERROR"
        return 1
    fi

    if [ "$ask" = "true" ]; then
        # One nonce for both: the portal echoes the X-Nonce it got.
        for h in "${SIGN_HEADERS[@]}"; do
            case "$h" in
                X-Nonce:*) nonce="${h#X-Nonce:}"; nonce="${nonce# }" ;;
            esac
        done
        if [ -z "$nonce" ]; then
            if ! nonce=$("$OB_RS_HELPER" nonce 2>&1) || [ -z "$nonce" ]; then
                OB_PAM_ERROR="cannot generate a nonce for $path: $nonce"
                return 1
            fi
            extra+=(-H "X-Nonce: $nonce")
        fi
        extra+=(-H "Accept: $OB_PAM_MEDIA_TYPE")
    fi

    # The body on stdin, not argv: ob-heartbeat's carries the refresh_token.
    # TLS 1.3 like every other curl call (#330), whatever the caller passed.
    raw=$(printf '%s' "$payload" | curl --tlsv1.3 "$@" "${SIGN_HEADERS[@]}" "${extra[@]}" \
        -X POST -H "Content-Type: application/json" --data-binary @- \
        -w '\n__OB_HTTP__:%{http_code}:%{content_type}' \
        "${base}${path}" 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then
        OB_PAM_CURL_RC=$rc
        OB_PAM_ERROR="request to $path failed (curl exit $rc)${raw:+: ${raw%%$'\n'__OB_HTTP__:*}}"
        return 1
    fi
    case "$raw" in
        *$'\n'__OB_HTTP__:*) ;;
        *) OB_PAM_ERROR="no HTTP status for $path"; return 1 ;;
    esac
    meta="${raw##*$'\n'__OB_HTTP__:}"
    body="${raw%$'\n'__OB_HTTP__:*}"
    OB_PAM_STATUS="${meta%%:*}"
    ctype="${meta#*:}"

    if ! ob_is_signed_answer_type "$ctype"; then
        case "$OB_RS_MODE" in
            required|invalid)
                OB_PAM_ERROR="unsigned answer to $path (HTTP $OB_PAM_STATUS) refused: response_signing = required"
                return 1 ;;
            prefer)
                [ "$ask" = "true" ] \
                    && OB_PAM_WARNING="unsigned answer to $path accepted (response_signing = prefer)" ;;
        esac
        OB_PAM_SIGNED=unsigned
        OB_PAM_BODY="$body"
        return 0
    fi

    if [ "$ask" != "true" ]; then
        OB_PAM_ERROR="signed answer to $path that was not asked for"
        return 1
    fi

    vargs=(verify --jwks "$OB_RS_JWKS" --issuer "$OB_RS_ISSUER"
           --endpoint "$endpoint" --nonce "$nonce" --http-status "$OB_PAM_STATUS")
    [ -n "$OB_RS_CLIENT_ID" ] && vargs+=(--audience "$OB_RS_CLIENT_ID")
    [ -n "${OB_PAM_JWKS_OUT:-}" ] && vargs+=(--jwks-out "$OB_PAM_JWKS_OUT")
    # Nothing on stderr unless it fails, so 2>&1 keeps stdout clean.
    out=$(printf '%s' "$body" \
        | "$OB_RS_HELPER" "${vargs[@]}" --body-file <(printf '%s' "$payload") 2>&1) \
        || vrc=$?
    case "$vrc" in
        0) ;;
        4)
            OB_PAM_ANONYMOUS=true
            case "$OB_PAM_STATUS" in
                2*)
                    OB_PAM_ERROR="signed answer to $path (HTTP $OB_PAM_STATUS) carries no aud: refused"
                    return 1 ;;
            esac ;;
        *)
            OB_PAM_ERROR="${out:-signed answer to $path rejected (ob-verify-response exit $vrc)}"
            return 1 ;;
    esac
    OB_PAM_SIGNED=verified
    OB_PAM_BODY="$out"
    return 0
}
