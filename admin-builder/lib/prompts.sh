#!/bin/bash
# prompts.sh - interactive prompt helpers for ob-builder.
# All prompts honour the OB_BUILDER_NON_INTERACTIVE env var: when set, a
# missing default value is a fatal error rather than an interactive read.

if [ -n "${_OB_BUILDER_PROMPTS_SOURCED:-}" ]; then
    return 0
fi
_OB_BUILDER_PROMPTS_SOURCED=1

# Prompts read from /dev/tty when available so that piping config into
# ob-builder via stdin (e.g. for the YAML loader) does not swallow prompts.
# "Available" means openable: without a controlling terminal /dev/tty exists
# but cannot be opened, and stdin is used instead.
_ob_has_tty() {
    { : < /dev/tty; } 2>/dev/null
}

# EOF on input: fatal (else retry loops spin forever). Inside $(...) this
# only leaves the subshell; callers abort on its non-zero status.
_ob_eof() {
    log_error "No more input (EOF) while prompting"
    exit 1
}

_ob_read_line() {
    local __var="$1"
    if _ob_has_tty; then
        # shellcheck disable=SC2229
        IFS= read -r "$__var" < /dev/tty || _ob_eof
    else
        # shellcheck disable=SC2229
        IFS= read -r "$__var" || _ob_eof
    fi
}

_ob_read_secret() {
    local __var="$1"
    if _ob_has_tty; then
        # shellcheck disable=SC2229
        IFS= read -rs "$__var" < /dev/tty || _ob_eof
        printf '\n' >&2
    else
        # shellcheck disable=SC2229
        IFS= read -rs "$__var" || _ob_eof
    fi
}

# ask "Question" [default]
# Echoes the answer (possibly empty) on stdout.
ask() {
    local question="$1"
    local default="${2:-}"
    local prompt answer

    if [ "${OB_BUILDER_NON_INTERACTIVE:-}" = "1" ]; then
        if [ -n "$default" ]; then
            printf '%s\n' "$default"
            return 0
        fi
        log_error "Non-interactive mode: no default for question '$question'"
        exit 1
    fi

    if [ -n "$default" ]; then
        prompt="$question [$default]: "
    else
        prompt="$question: "
    fi
    printf '%s' "$prompt" >&2
    _ob_read_line answer
    if [ -z "$answer" ] && [ -n "$default" ]; then
        answer="$default"
    fi
    printf '%s\n' "$answer"
}

# ask_yesno "Question" [y|n]
# Returns 0 for yes, 1 for no.
ask_yesno() {
    local question="$1"
    local default="${2:-n}"
    local hint answer

    case "$default" in
        y|Y) hint="[Y/n]" ;;
        n|N|"") hint="[y/N]"; default="n" ;;
        *)   hint="[y/n]"; default="" ;;
    esac

    if [ "${OB_BUILDER_NON_INTERACTIVE:-}" = "1" ]; then
        case "$default" in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            *)
                log_error "Non-interactive mode: no default for yes/no '$question'"
                exit 1
                ;;
        esac
    fi

    printf '%s %s: ' "$question" "$hint" >&2
    _ob_read_line answer
    if [ -z "$answer" ]; then
        answer="$default"
    fi
    case "$answer" in
        y|Y|yes|YES|Yes) return 0 ;;
        *)               return 1 ;;
    esac
}

# ask_choice "Question" "opt1|opt2|opt3" [default]
# Repeats until a valid option is selected. Echoes the chosen option.
ask_choice() {
    local question="$1"
    local options="$2"
    local default="${3:-}"
    local answer hint
    local -a opts

    # shellcheck disable=SC2206  # intentional word-splitting on |
    IFS='|' read -r -a opts <<< "$options"

    if [ "${OB_BUILDER_NON_INTERACTIVE:-}" = "1" ]; then
        if [ -n "$default" ]; then
            printf '%s\n' "$default"
            return 0
        fi
        log_error "Non-interactive mode: no default for choice '$question'"
        exit 1
    fi

    if [ -n "$default" ]; then
        hint="[${opts[*]}] (default: $default)"
    else
        hint="[${opts[*]}]"
    fi

    while :; do
        printf '%s %s: ' "$question" "$hint" >&2
        _ob_read_line answer
        if [ -z "$answer" ] && [ -n "$default" ]; then
            answer="$default"
        fi
        local o
        for o in "${opts[@]}"; do
            if [ "$answer" = "$o" ]; then
                printf '%s\n' "$answer"
                return 0
            fi
        done
        printf '  Invalid choice. Pick one of: %s\n' "${opts[*]}" >&2
    done
}

# ask_secret "Question"
# Reads with echo off; no default, no display. Echoes the secret on stdout.
ask_secret() {
    local question="$1"
    local answer

    if [ "${OB_BUILDER_NON_INTERACTIVE:-}" = "1" ]; then
        log_error "Non-interactive mode: cannot prompt for secret '$question'"
        exit 1
    fi

    printf '%s: ' "$question" >&2
    _ob_read_secret answer
    printf '%s\n' "$answer"
}

# ask_secret_confirm "Question"
# Like ask_secret, but asks twice and repeats until both entries match and
# are non-empty. Echoes the secret on stdout.
ask_secret_confirm() {
    local question="$1"
    local first second

    if [ "${OB_BUILDER_NON_INTERACTIVE:-}" = "1" ]; then
        log_error "Non-interactive mode: cannot prompt for secret '$question'"
        exit 1
    fi

    while :; do
        printf '%s: ' "$question" >&2
        _ob_read_secret first
        if [ -z "$first" ]; then
            printf '  Empty value, try again.\n' >&2
            continue
        fi
        printf 'Confirm %s: ' "$question" >&2
        _ob_read_secret second
        [ "$first" = "$second" ] && break
        printf '  Entries do not match, try again.\n' >&2
    done
    printf '%s\n' "$first"
}
