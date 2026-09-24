# shellcheck shell=bash
#
# ob-login-shell-lib.sh - the login shell of SSO users on a recording host
#
# Sourced by ob-bastion-setup and ob-post-upgrade, which must agree on which
# hosts get force_shell and how it is written. See ob-login-shell(8).
#
# Nothing here prints: the callers report differently.
#
# Copyright (C) 2026 Linagora
# License: AGPL-3.0

OB_LOGIN_SHELL="/usr/sbin/ob-login-shell"

# 0 when the sshd configuration the setup wrote forces sessions through the
# recorder: the bastion-stack drop-in in $1 (sshd_config.d), or, on an sshd
# without drop-ins, the block the setup appended to $2 (sshd_config).
ob_host_records_sessions() {
    local dir="$1" main="$2" f
    for f in "$dir"/*-open-bastion-bastion.conf; do
        [ -f "$f" ] || continue
        grep -Eq '^[[:space:]]*ForceCommand[[:space:]]+[^#]*ob-session-recorder' "$f" \
            && return 0
    done
    [ -f "$main" ] || return 1
    grep -q 'TrustedUserCAKeys.*open-bastion' "$main" || return 1
    grep -Eq '^[[:space:]]*ForceCommand[[:space:]]+[^#]*ob-session-recorder' "$main"
}

# The force_shell value in NSS configuration $1: the last active one, the way
# libnss_openbastion reads it (quotes stripped). Empty when there is none.
ob_nss_force_shell_value() {
    [ -r "$1" ] || return 0
    sed -n 's/^[[:space:]]*force_shell[[:space:]]*=[[:space:]]*//p' "$1" \
        | tail -1 | sed "s/[[:space:]]*\$//; s/^[\"']//; s/[\"']\$//"
}

# The lines the setup and ob-post-upgrade write into nss_openbastion.conf.
ob_nss_force_shell_block() {
    printf '%s\n' \
        '# Login shell of every user resolved here; see ob-login-shell(8).' \
        "force_shell = $OB_LOGIN_SHELL"
}

# Make NSS configuration $1 force the launcher. Returns
#   0  the file now forces it
#   1  the file could not be written
#   2  it already forces ANOTHER shell: an administrator's choice, left alone
# The rest of the file is kept byte for byte; the block is appended.
ob_nss_force_launcher() {
    local conf="$1" cur tmp
    cur=$(ob_nss_force_shell_value "$conf")
    if [ "$cur" = "$OB_LOGIN_SHELL" ]; then
        return 0
    fi
    [ -n "$cur" ] && return 2
    tmp=$(mktemp "$conf.XXXXXX") || return 1
    # Same owner and mode as the file it replaces (0644 root: every process
    # that resolves a user reads it, and the module refuses a writable one).
    if ! { cat "$conf" && printf '\n' && ob_nss_force_shell_block; } > "$tmp" \
       || ! chmod --reference="$conf" "$tmp" \
       || ! chown --reference="$conf" "$tmp" \
       || ! mv -f "$tmp" "$conf"; then
        rm -f "$tmp"
        return 1
    fi
    return 0
}

# List the launcher in $1 (/etc/shells), for pam_shells and anything else that
# asks whether a login shell is a real one. Idempotent. The package does this
# too; the setup repeats it for an installation from source.
ob_register_login_shell() {
    local shells="$1"
    grep -qxF "$OB_LOGIN_SHELL" "$shells" 2>/dev/null && return 0
    printf '%s\n' "$OB_LOGIN_SHELL" >> "$shells"
}

# nscd's copy of libnss_openbastion keeps the configuration it read at start,
# so invalidating its cache is not enough: restart it. Returns 1 only when nscd
# runs and could not be restarted.
ob_restart_nscd() {
    local unit
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        for unit in nscd.service unscd.service; do
            systemctl is-active --quiet "$unit" 2>/dev/null || continue
            systemctl restart "$unit" >/dev/null 2>&1 || return 1
        done
        return 0
    fi
    if command -v pgrep >/dev/null 2>&1 && pgrep -x nscd >/dev/null 2>&1; then
        # No systemd: the most that can be done is dropping its cache.
        nscd --invalidate=passwd >/dev/null 2>&1 || true
        return 1
    fi
    return 0
}
