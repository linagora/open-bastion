#!/bin/bash
# test_ob_setup_roles.sh -- one setup script, three roles (#288).
#
# scripts/ob-bastion-setup is installed as ob-bastion-setup, ob-standalone-setup
# and ob-backend-setup. The name picks the default role, --node-role overrides
# it, and what gets configured must follow the role in effect -- not the name,
# and not the label. Before the merge, `ob-bastion-setup --node-role backend`
# wrote node_role = backend into a complete bastion configuration; these tests
# pin that the flag now configures what it names, that an option of one role
# is refused for another instead of being ignored, and that switching a host's
# role does not leave the other role's sshd drop-in behind.
# shellcheck disable=SC2034  # variables are read by the loaded script's functions
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# shellcheck source=tests/lib_setup_script.sh
. "$TESTS_DIR/lib_setup_script.sh"

# Load the script as NAME, parse ARGS, and print the dry-run rendering of
# everything whose content depends on the role: the sshd drop-in, the sshd
# PAM stack, openbastion.conf and the principals helper it would install.
render_as() {
    local name="$1"
    shift
    (
        load_setup_as "$name" || exit 99
        parse_args -p "https://x.example.com" -g g --dry-run "$@" || exit 98
        printf 'ROLE=%s\n' "$NODE_ROLE"
        configure_sshd 2>&1
        configure_pam_sshd 2>&1
        render_openbastion_conf
        install_principals_helper 2>&1
    )
}

# The markers of each stack. Every one of them has to hold, so that a
# half-switched configuration (the old "bastion labelled backend") fails.
is_backend_stack() {
    local out="$1" miss=""
    grep -q 'ob-ssh-principals %u %f %i %t %k$' <<<"$out" || miss="$miss %i"
    grep -q '^AllowAgentForwarding no$' <<<"$out"         || miss="$miss agent-no"
    grep -q '^ForceCommand' <<<"$out"                     && miss="$miss forcecommand"
    grep -q '^session    required     pam_openbastion.so create_user=true$' <<<"$out" \
                                                          || miss="$miss create_user"
    grep -q 'pam_mkhomedir' <<<"$out"                     && miss="$miss mkhomedir"
    grep -q '^create_user_enabled = true$' <<<"$out"      || miss="$miss conf-create_user"
    grep -q 'ob-ssh-principals\.backend' <<<"$out"        || miss="$miss helper"
    grep -q 'allowed_bastions' <<<"$out"                  || miss="$miss allowlist"
    printf '%s' "$miss"
    [ -z "$miss" ]
}

is_bastion_stack() {
    local out="$1" miss=""
    grep -q 'ob-ssh-principals %u %f %t %k$' <<<"$out"    || miss="$miss no-%i"
    grep -q '^AllowAgentForwarding yes$' <<<"$out"        || miss="$miss agent-yes"
    grep -q '^ForceCommand /usr/sbin/ob-session-recorder$' <<<"$out" \
                                                          || miss="$miss forcecommand"
    grep -q '^session    optional     pam_mkhomedir.so' <<<"$out" \
                                                          || miss="$miss mkhomedir"
    grep -q 'create_user' <<<"$out"                       && miss="$miss create_user"
    grep -q 'ob-ssh-principals\.bastion' <<<"$out"        || miss="$miss helper"
    grep -q 'allowed_bastions' <<<"$out"                  && miss="$miss allowlist"
    printf '%s' "$miss"
    [ -z "$miss" ]
}

# ── 1. The name chooses the default role ─────────────────────────────────────
test_role_from_name() {
    local bad="" name want out
    for name in ob-bastion-setup:bastion ob-standalone-setup:standalone \
                ob-backend-setup:backend some-copy-of-the-script:bastion; do
        want="${name#*:}"; name="${name%%:*}"
        out=$(render_as "$name")
        grep -q "^ROLE=$want$" <<<"$out"            || bad="$bad $name(role)"
        grep -q "^node_role = $want$" <<<"$out"     || bad="$bad $name(conf)"
        if [ "$want" = "backend" ]; then
            is_backend_stack "$out" >/dev/null      || bad="$bad $name(stack:$(is_backend_stack "$out"))"
        else
            is_bastion_stack "$out" >/dev/null      || bad="$bad $name(stack:$(is_bastion_stack "$out"))"
        fi
    done
    if [ -z "$bad" ]; then
        pass "each command name configures its own role"
    else
        fail "each command name configures its own role" "$bad"
    fi
}

# ── 2. --node-role configures the role it names ──────────────────────────────
# The regression this whole change is about: the flag used to change only the
# node_role label. Every name x every role, and the whole stack must follow.
test_node_role_overrides_the_stack() {
    local bad="" name role out
    for name in ob-bastion-setup ob-standalone-setup ob-backend-setup; do
        for role in bastion standalone backend; do
            out=$(render_as "$name" --node-role "$role")
            grep -q "^ROLE=$role$" <<<"$out"         || bad="$bad $name/$role(role)"
            grep -q "^node_role = $role$" <<<"$out"  || bad="$bad $name/$role(conf)"
            if [ "$role" = "backend" ]; then
                is_backend_stack "$out" >/dev/null   || bad="$bad $name/$role(stack:$(is_backend_stack "$out"))"
            else
                is_bastion_stack "$out" >/dev/null   || bad="$bad $name/$role(stack:$(is_bastion_stack "$out"))"
            fi
        done
    done
    if [ -z "$bad" ]; then
        pass "--node-role configures the stack of the role it names, under every name"
    else
        fail "--node-role configures the stack of the role it names" "$bad"
    fi
}

# ── 3. Role-specific options are refused for the other role ─────────────────
# Run through the real command: the refusal has to happen in option parsing,
# before the root check and before anything is written.
test_wrong_role_options_refused() {
    local bad="" out rc opt name
    for name in ob-bastion-setup ob-standalone-setup; do
        for opt in --no-sudo --no-create-user --allow-any-bastion "--allowed-bastions b1"; do
            # shellcheck disable=SC2086  # "--allowed-bastions b1" is two words
            out=$(bash "$(setup_command "$name")" -p https://x.example.com -g g -c c \
                      $opt --dry-run --yes 2>&1)
            rc=$?
            opt="${opt%% *}"
            if [ "$rc" -eq 0 ] || ! grep -q -- "Option $opt applies to a backend only" <<<"$out"; then
                bad="$bad $name:$opt"
            fi
        done
    done
    out=$(bash "$(setup_command ob-backend-setup)" -p https://x.example.com -g g -c c \
              --disable-session-recorder --dry-run --yes 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ] || ! grep -q -- "Option --disable-session-recorder applies to a bastion or standalone host" <<<"$out"; then
        bad="$bad ob-backend-setup:--disable-session-recorder"
    fi
    # The role in effect decides, wherever --node-role sits on the line.
    out=$(bash "$(setup_command ob-backend-setup)" -p https://x.example.com -g g -c c \
              --no-sudo --node-role bastion --dry-run --yes 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ] || ! grep -q -- "Option --no-sudo applies to a backend only" <<<"$out"; then
        bad="$bad ob-backend-setup:--no-sudo+--node-role-bastion"
    fi
    # And the refusal is where the run stops. A non-zero exit and the message
    # are not enough on their own: without the exit, an unprivileged run still
    # fails a moment later at the root check, with the message already printed.
    local spec
    for spec in "ob-bastion-setup --no-sudo" "ob-standalone-setup --allow-any-bastion" \
                "ob-backend-setup --disable-session-recorder" \
                "ob-backend-setup --no-create-user --node-role bastion"; do
        out=$(
            # shellcheck disable=SC2086  # the spec is a name then options
            set -- $spec
            load_setup_as "$1" || exit 99
            shift
            parse_args -p https://x.example.com "$@" 2>/dev/null
            echo "PARSED"
        )
        grep -q PARSED <<<"$out" && bad="$bad not-stopped:[$spec]"
    done
    if [ -z "$bad" ]; then
        pass "options of one role are refused for another, with the reason"
    else
        fail "options of one role are refused for another" "$bad"
    fi
}

# ── 4. ... and accepted for their own role, wherever --node-role sits ────────
test_right_role_options_accepted() {
    local bad="" rc
    (
        load_setup_as ob-bastion-setup || exit 99
        parse_args -p https://x.example.com --no-sudo --allowed-bastions b1 \
            --no-create-user --allow-any-bastion --node-role backend >/dev/null 2>&1 || exit 1
        [ "$ENABLE_SUDO" = false ] && [ "$CREATE_USERS" = false ] \
            && [ "$BASTION_ALLOWED_IDS" = b1 ] && [ "$ALLOW_ANY_BASTION" = true ]
    )
    rc=$?; [ "$rc" -eq 0 ] || bad="$bad bastion-name+backend-role($rc)"
    (
        load_setup_as ob-backend-setup || exit 99
        parse_args -p https://x.example.com --disable-session-recorder \
            --node-role standalone >/dev/null 2>&1 || exit 1
        [ "$DISABLE_SESSION_RECORDER" = true ]
    )
    rc=$?; [ "$rc" -eq 0 ] || bad="$bad backend-name+standalone-role($rc)"
    if [ -z "$bad" ]; then
        pass "options of the role in effect are accepted, before or after --node-role"
    else
        fail "options of the role in effect are accepted" "$bad"
    fi
}

# ── 5. --help describes the role in effect ──────────────────────────────────
test_help_is_role_specific() {
    local bad="" h
    h=$(bash "$(setup_command ob-bastion-setup)" --help 2>&1)
    grep -q 'This help describes the bastion role' <<<"$h"   || bad="$bad bastion(title)"
    grep -q -- '--disable-session-recorder' <<<"$h"         || bad="$bad bastion(recorder)"
    grep -q -- '--allowed-bastions\|--no-sudo\|--no-create-user\|--allow-any-bastion' <<<"$h" \
                                                            && bad="$bad bastion(backend-opts)"
    h=$(bash "$(setup_command ob-backend-setup)" --help 2>&1)
    grep -q 'This help describes the backend role' <<<"$h"   || bad="$bad backend(title)"
    for o in --allowed-bastions --allow-any-bastion --no-sudo --no-create-user; do
        grep -q -- "$o" <<<"$h"                             || bad="$bad backend($o)"
    done
    grep -q -- '--disable-session-recorder' <<<"$h"         && bad="$bad backend(recorder)"
    h=$(bash "$(setup_command ob-standalone-setup)" --help 2>&1)
    grep -q 'This help describes the standalone role' <<<"$h" || bad="$bad standalone(title)"
    grep -q -- '--disable-session-recorder' <<<"$h"         || bad="$bad standalone(recorder)"
    # --help is read after the whole line, so a later --node-role counts.
    h=$(bash "$(setup_command ob-bastion-setup)" --help --node-role backend 2>&1)
    grep -q 'This help describes the backend role' <<<"$h"   || bad="$bad deferred(title)"
    grep -q -- '--node-role backend --portal' <<<"$h"       || bad="$bad deferred(example)"
    # The help is an unquoted heredoc: a backtick in it runs a command. The
    # sudoers line used to be executed and printed as "(writes )".
    grep -q 'Defaults:%open-bastion-sudo timestamp_timeout=0' <<<"$h" \
                                                            || bad="$bad substitution"
    if [ -z "$bad" ]; then
        pass "--help describes the role in effect and only its options"
    else
        fail "--help describes the role in effect" "$bad"
    fi
}

# ── 6. Switching role removes the other role's sshd drop-in ─────────────────
# Both drop-ins would be read. The backend's sorts first and wins every keyword
# it sets, but the bastion's ForceCommand would still apply to every backend
# session -- through a recorder whose sink a backend does not enable.
test_other_role_dropin_removed() {
    local tmp bad="" role other
    tmp=$(mktemp -d)
    mkdir -p "$tmp/bin"
    printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/sshd"
    chmod +x "$tmp/bin/sshd"
    for role in backend bastion; do
        if [ "$role" = backend ]; then other=bastion; else other=backend; fi
        rm -rf "$tmp/d"; mkdir -p "$tmp/d"
        printf 'Include %s/*.conf\n' "$tmp/d" > "$tmp/sshd_config"
        printf 'ForceCommand /usr/sbin/ob-session-recorder\n' > "$tmp/d/00-open-bastion-$other.conf"
        printf 'PasswordAuthentication no\n' > "$tmp/d/50-open-bastion-$other.conf"
        printf 'PasswordAuthentication yes\n' > "$tmp/d/50-cloud-init.conf"
        (
            load_setup_as ob-bastion-setup || exit 99
            parse_args -p https://x.example.com -g g --node-role "$role" >/dev/null 2>&1 || exit 98
            SSHD_CONFIG_DIR="$tmp/d"; SSHD_CONFIG="$tmp/sshd_config"
            BACKUP_DIR="$tmp/backup-$role"
            PATH="$tmp/bin:$PATH"
            configure_sshd >/dev/null 2>&1
        ) || bad="$bad $role(configure_sshd-failed)"
        [ -f "$tmp/d/00-open-bastion-$role.conf" ]  || bad="$bad $role(not-written)"
        [ -e "$tmp/d/00-open-bastion-$other.conf" ] && bad="$bad $role(00-$other-left)"
        [ -e "$tmp/d/50-open-bastion-$other.conf" ] && bad="$bad $role(50-$other-left)"
        [ -f "$tmp/d/50-cloud-init.conf" ]          || bad="$bad $role(foreign-file-touched)"
        [ -f "$tmp/backup-$role/00-open-bastion-$other.conf" ] \
                                                    || bad="$bad $role(no-backup)"
    done
    rm -rf "$tmp"
    if [ -z "$bad" ]; then
        pass "writing one role's sshd drop-in removes the other role's (backed up)"
    else
        fail "writing one role's sshd drop-in removes the other role's" "$bad"
    fi
}

# ── 7. A role switch installs the new helper last, not in phase 1 ───────────
# sshd runs the old role's configuration until the restart at the end of the
# run. Installing the new principals helper in phase 1 paired it with that
# configuration for the whole enrollment -- and before the helpers learnt to
# deny a mismatch, a backend's sshd with the bastion helper admitted a direct
# SSO certificate, unrecorded (#290 review). The helper now waits for the end
# on a switch, and only on a switch.
test_role_switch_defers_helper() {
    local tmp bad="" role current out
    tmp=$(mktemp -d)
    for role in bastion standalone backend; do
        for current in none bastion backend; do
            rm -rf "$tmp/d"; mkdir -p "$tmp/d"
            [ "$current" = none ] || : > "$tmp/d/00-open-bastion-$current.conf"
            out=$(
                load_setup_as ob-bastion-setup || exit 99
                parse_args -p https://x.example.com --node-role "$role" >/dev/null 2>&1 || exit 98
                SSHD_CONFIG_DIR="$tmp/d"
                install_principals_helper() { echo "INSTALLED"; }
                echo "stack=$(configured_sshd_stack)"
                prepare_principals_helper >/dev/null 2>&1 && echo "PREPARE-OK"
                prepare_principals_helper 2>/dev/null | grep -q INSTALLED && echo "PHASE1"
                finish_principals_helper 2>/dev/null | grep -q INSTALLED && echo "AT-END"
            )
            local stack="bastion"; [ "$role" = backend ] && stack=backend
            local cur_label="$current"; [ "$current" = none ] && cur_label=""
            grep -q "^stack=$cur_label$" <<<"$out"   || bad="$bad $role/$current(detected)"
            grep -q '^PREPARE-OK$' <<<"$out"          || bad="$bad $role/$current(prepare-failed)"
            if [ "$current" != none ] && [ "$current" != "$stack" ]; then
                grep -q '^PHASE1$' <<<"$out" && bad="$bad $role/$current(installed-in-phase-1)"
                grep -q '^AT-END$' <<<"$out" || bad="$bad $role/$current(never-installed)"
            else
                grep -q '^PHASE1$' <<<"$out" || bad="$bad $role/$current(not-in-phase-1)"
                grep -q '^AT-END$' <<<"$out" && bad="$bad $role/$current(installed-twice)"
            fi
        done
    done
    rm -rf "$tmp"
    if [ -z "$bad" ]; then
        pass "on a role switch the principals helper is installed at the end, otherwise in phase 1"
    else
        fail "on a role switch the principals helper is installed at the end" "$bad"
    fi
}

echo "=== one setup script, three roles (#288) ==="
run_test test_role_from_name
run_test test_node_role_overrides_the_stack
run_test test_wrong_role_options_refused
run_test test_right_role_options_accepted
run_test test_help_is_role_specific
run_test test_other_role_dropin_removed
run_test test_role_switch_defers_helper

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
