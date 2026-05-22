#!/bin/bash
# common.sh - logging, atomic write, tmpdir helpers for ob-builder.
# Sourced by ob-builder and other lib files; never executed directly.

# Guard against double-source.
if [ -n "${_OB_BUILDER_COMMON_SOURCED:-}" ]; then
    return 0
fi
_OB_BUILDER_COMMON_SOURCED=1

# Colors only when stdout is a tty and `tput` is available — keeps logs
# clean when output is captured (CI, |tee logfile).
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    _OB_RED=$(tput setaf 1)
    _OB_GREEN=$(tput setaf 2)
    _OB_YELLOW=$(tput setaf 3)
    _OB_BLUE=$(tput setaf 4)
    _OB_BOLD=$(tput bold)
    _OB_DIM=$(tput dim 2>/dev/null || echo "")
    _OB_NC=$(tput sgr0)
else
    _OB_RED=""
    _OB_GREEN=""
    _OB_YELLOW=""
    _OB_BLUE=""
    _OB_BOLD=""
    _OB_DIM=""
    _OB_NC=""
fi

log_info()  { printf '%s[INFO]%s %s\n' "$_OB_GREEN" "$_OB_NC" "$*"; }
log_warn()  { printf '%s[WARN]%s %s\n' "$_OB_YELLOW" "$_OB_NC" "$*" >&2; }
log_error() { printf '%s[ERROR]%s %s\n' "$_OB_RED" "$_OB_NC" "$*" >&2; }
log_step()  { printf '\n%s==>%s %s%s%s\n' "$_OB_BLUE" "$_OB_NC" "$_OB_BOLD" "$*" "$_OB_NC"; }

# explain <text> — short hint shown above an interactive prompt
explain() { printf '\n%s%s%s\n' "$_OB_DIM" "$*" "$_OB_NC"; }

die() {
    log_error "$*"
    exit 1
}

# atomic_write <dest> <mode> <content>
# Write content to dest via a temp file in the same directory, then rename.
# `mode` is passed to chmod (e.g. "0644"). Caller is responsible for
# parent-directory creation.
atomic_write() {
    local dest="$1"
    local mode="$2"
    local content="$3"
    local dir tmp

    dir=$(dirname -- "$dest")
    [ -d "$dir" ] || mkdir -p -- "$dir"

    tmp=$(mktemp -- "${dir}/.$(basename -- "$dest").XXXXXX") || die "mktemp failed for $dest"
    # Use printf %s, not echo, to avoid swallowing backslashes / leading -.
    printf '%s' "$content" > "$tmp" || { rm -f -- "$tmp"; die "write failed: $dest"; }
    chmod -- "$mode" "$tmp" || { rm -f -- "$tmp"; die "chmod $mode failed: $dest"; }
    mv -f -- "$tmp" "$dest" || { rm -f -- "$tmp"; die "rename failed: $dest"; }
}

# atomic_write_from <dest> <mode> <src>
# Same as atomic_write but copies an existing source file (no buffering of
# binary content through a shell variable, which would mangle NULs).
atomic_write_from() {
    local dest="$1"
    local mode="$2"
    local src="$3"
    local dir tmp

    [ -f "$src" ] || die "atomic_write_from: source missing: $src"
    dir=$(dirname -- "$dest")
    [ -d "$dir" ] || mkdir -p -- "$dir"

    tmp=$(mktemp -- "${dir}/.$(basename -- "$dest").XXXXXX") || die "mktemp failed for $dest"
    cp -- "$src" "$tmp" || { rm -f -- "$tmp"; die "copy failed: $src -> $dest"; }
    chmod -- "$mode" "$tmp" || { rm -f -- "$tmp"; die "chmod $mode failed: $dest"; }
    mv -f -- "$tmp" "$dest" || { rm -f -- "$tmp"; die "rename failed: $dest"; }
}

# Temp-dir tracking.
#
# The cleanup trap is registered at SCRIPT init (via ob_init_tmpdir_trap),
# NOT inside mktemp_dir, so that calling mktemp_dir from a command
# substitution — which runs in a subshell — does not register a subshell-
# local trap that would fire when the subshell exits and prematurely wipe
# the directory we just created.
#
# Likewise, _OB_TMPDIRS in the subshell would be a copy: we instead write
# directly to a file at $_OB_TMPDIRS_FILE which is shared between subshells.
_OB_TMPDIRS_FILE=""
_ob_cleanup_tmpdirs() {
    [ -n "$_OB_TMPDIRS_FILE" ] && [ -f "$_OB_TMPDIRS_FILE" ] || return 0
    local d
    while IFS= read -r d; do
        [ -n "$d" ] && [ -d "$d" ] && rm -rf -- "$d"
    done < "$_OB_TMPDIRS_FILE"
    rm -f -- "$_OB_TMPDIRS_FILE"
}

# Call once from the parent shell (not a subshell) before any mktemp_dir.
ob_init_tmpdir_trap() {
    [ -n "$_OB_TMPDIRS_FILE" ] && return 0
    _OB_TMPDIRS_FILE=$(mktemp -t ob-builder-tmplist.XXXXXX)
    export _OB_TMPDIRS_FILE
    trap _ob_cleanup_tmpdirs EXIT
}

mktemp_dir() {
    local d
    d=$(mktemp -d -t ob-builder.XXXXXX) || die "mktemp -d failed"
    if [ -n "$_OB_TMPDIRS_FILE" ]; then
        printf '%s\n' "$d" >> "$_OB_TMPDIRS_FILE"
    fi
    printf '%s\n' "$d"
}

# base64_file <path>
# Emit base64 of a file on a single long line. Used for embedding binaries
# (GPG keyring, KRL) into the generated installer. We do NOT wrap, to keep
# the heredoc in the generated script trivially parseable.
base64_file() {
    local f="$1"
    [ -f "$f" ] || die "base64_file: missing $f"
    base64 -w0 -- "$f" 2>/dev/null || base64 -- "$f" | tr -d '\n'
}

# base64_string <string>
# Emit base64 of an arbitrary string, single line.
base64_string() {
    printf '%s' "$1" | { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
}
