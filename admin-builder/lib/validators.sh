#!/bin/bash
# validators.sh - regex-based input validation for ob-builder.

if [ -n "${_OB_BUILDER_VALIDATORS_SOURCED:-}" ]; then
    return 0
fi
_OB_BUILDER_VALIDATORS_SOURCED=1

# is_valid_slug <s>
# Deployment slug: lowercase alphanumerics + dashes. Used for artefact
# filenames so must be filesystem-safe.
is_valid_slug() {
    [[ "$1" =~ ^[a-z0-9][a-z0-9-]*$ ]]
}

# is_valid_url <url>
# Accepts http:// or https://. Excludes shell metacharacters ($, `, ", ', \)
# so the URL can be safely embedded as a bash double-quoted literal in the
# generated installer.sh — preventing command-substitution at install time.
# The caller decides whether to refuse http based on --allow-http.
is_valid_url() {
    [[ "$1" =~ ^https?://[A-Za-z0-9._:/?#@!()*+,\;=~%-]+$ ]]
}

# is_valid_https_url <url>
# Strict HTTPS check. Same shell-safe character class as is_valid_url.
is_valid_https_url() {
    [[ "$1" =~ ^https://[A-Za-z0-9._:/?#@!()*+,\;=~%-]+$ ]]
}

# is_valid_server_group <s>
# May be empty (means "no embedded default, ask at install time").
is_valid_server_group() {
    local s="$1"
    [ -z "$s" ] && return 0
    [[ "$s" =~ ^[A-Za-z0-9_-]+$ ]]
}

# is_valid_client_id <s>
# Standard OIDC client_id charset (RFC 6749 doesn't constrain, but in
# practice ASCII identifier-ish). Empty allowed for "modifiable, no default".
is_valid_client_id() {
    local s="$1"
    [ -z "$s" ] && return 0
    [[ "$s" =~ ^[A-Za-z0-9._-]+$ ]]
}

# is_valid_service_username <s>
# Mirrors validate_username() in src/service_account.c: first char a lowercase
# letter or underscore, then lowercase letters, digits, underscore or hyphen.
is_valid_service_username() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]*$ ]]
}

# is_valid_fingerprint <s>
# Mirrors validate_fingerprint() in src/service_account.c: must start with
# SHA256: or MD5:, and contain only base64-ish characters (alnum : + / =).
is_valid_fingerprint() {
    local s="$1"
    [[ "$s" == SHA256:* || "$s" == MD5:* ]] || return 1
    [[ "$s" =~ ^[A-Za-z0-9:+/=]+$ ]]
}

# is_valid_abs_path <s>
# Light sanity check for shell / home values: an absolute path with no
# whitespace or shell metacharacters (the authoritative approved-list check
# happens on the target in src/service_account.c). Empty is allowed (means
# "use the default" on the target).
is_valid_abs_path() {
    local s="$1"
    [ -z "$s" ] && return 0
    [[ "$s" =~ ^/[A-Za-z0-9._/-]+$ ]]
}

# is_valid_scenario <s>
is_valid_scenario() {
    case "$1" in
        token-only|token+unix|keys+llng|mixed|max-security) return 0 ;;
        *) return 1 ;;
    esac
}

# is_valid_target_role <s>
is_valid_target_role() {
    case "$1" in
        bastion|standalone|backend) return 0 ;;
        *) return 1 ;;
    esac
}

# scenario_to_pam_mode <scenario>
# Maps the user-facing scenario name to the PAM mode letter (see doc/pam-modes.md).
scenario_to_pam_mode() {
    case "$1" in
        token-only)    printf 'A\n' ;;
        token+unix)    printf 'B\n' ;;
        keys+llng)     printf 'C\n' ;;
        mixed)         printf 'D\n' ;;
        max-security)  printf 'E\n' ;;
        *) return 1 ;;
    esac
}
