#!/bin/bash
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
SCRIPT_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# shellcheck source=tests/lib_pam_stack.sh
. "$TESTS_DIR/lib_pam_stack.sh"

source_script() {
    local script="$1"
    local content
    content=$(cat "$SCRIPT_DIR/$script")
    content="${content%main \"\$@\"}"
    content=$(echo "$content" | sed -E 's/^set -e(uo pipefail)?$//')
    eval "$content"
}

# ── Test 1: Syntax check ──
test_syntax() {
    if bash -n "$SCRIPT_DIR/ob-bastion-setup" 2>/dev/null; then
        pass "Syntax check"
    else
        fail "Syntax check"
    fi
}

# ── Test 2: --version / --help ──
test_version() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-bastion-setup" --version 2>&1)
    if echo "$out" | grep -q "version"; then
        pass "--version outputs version"
    else
        fail "--version outputs version" "$out"
    fi
}

test_help() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-bastion-setup" --help 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "--help outputs usage"
    else
        fail "--help outputs usage" "$out"
    fi
}

# ── Test 3: Unknown option rejected ──
test_unknown_option() {
    if bash "$SCRIPT_DIR/ob-bastion-setup" --bogus 2>/dev/null; then
        fail "Unknown option rejected"
    else
        pass "Unknown option rejected"
    fi
}

# ── Test 4: Missing portal URL exits with error ──
test_missing_portal() {
    if bash "$SCRIPT_DIR/ob-bastion-setup" 2>/dev/null; then
        fail "Missing portal URL exits with error"
    else
        pass "Missing portal URL exits with error"
    fi
}

# ── Test 5: parse_args sets variables correctly ──
test_parse_args_sets_variables() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://auth.example.com" -g "mygroup" -n -y -k
        local ok=true
        [ "$PORTAL_URL" = "https://auth.example.com" ] || ok=false
        [ "$SERVER_GROUP" = "mygroup" ] || ok=false
        [ "$DRY_RUN" = "true" ] || ok=false
        [ "$NON_INTERACTIVE" = "true" ] || ok=false
        [ "$VERIFY_SSL" = "false" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "parse_args sets PORTAL_URL, SERVER_GROUP, DRY_RUN, NON_INTERACTIVE, VERIFY_SSL"
    else
        fail "parse_args sets PORTAL_URL, SERVER_GROUP, DRY_RUN, NON_INTERACTIVE, VERIFY_SSL"
    fi
}

# ── Test 6: --dry-run sets DRY_RUN=true ──
test_dry_run() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --dry-run
        [ "$DRY_RUN" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--dry-run sets DRY_RUN=true"
    else
        fail "--dry-run sets DRY_RUN=true"
    fi
}

# ── Test 7: --yes sets NON_INTERACTIVE=true ──
test_yes() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --yes
        [ "$NON_INTERACTIVE" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--yes sets NON_INTERACTIVE=true"
    else
        fail "--yes sets NON_INTERACTIVE=true"
    fi
}

# ── Test 8: --insecure sets VERIFY_SSL=false ──
test_insecure() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --insecure
        [ "$VERIFY_SSL" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--insecure sets VERIFY_SSL=false"
    else
        fail "--insecure sets VERIFY_SSL=false"
    fi
}

# ── Test 9: Portal URL trailing slash stripped ──
test_trailing_slash() {
    (
        source_script "ob-bastion-setup"
        PORTAL_URL="https://auth.example.com/"
        PORTAL_URL="${PORTAL_URL%/}"
        [ "$PORTAL_URL" = "https://auth.example.com" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "Portal URL trailing slash stripped"
    else
        fail "Portal URL trailing slash stripped"
    fi
}

# ── Test 10: confirm() returns 0 in non-interactive mode ──
test_confirm_noninteractive() {
    (
        source_script "ob-bastion-setup"
        NON_INTERACTIVE=true
        confirm "Test?" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "confirm() returns 0 in non-interactive mode"
    else
        fail "confirm() returns 0 in non-interactive mode"
    fi
}

# ── Test 11: backup_file copies file to backup dir ──
test_backup_file() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local srcfile="$tmpdir/original.conf"
    echo "test content" > "$srcfile"
    (
        source_script "ob-bastion-setup"
        BACKUP_DIR="$tmpdir/backups"
        backup_file "$srcfile"
        [ -f "$tmpdir/backups/original.conf" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "backup_file copies file to backup dir"
    else
        fail "backup_file copies file to backup dir"
    fi
}

# ── Test 12: build_curl_opts with/without insecure ──
test_build_curl_opts_default() {
    (
        source_script "ob-bastion-setup"
        VERIFY_SSL="true"
        build_curl_opts
        local opts="${CURL_OPTS[*]}"
        echo "$opts" | grep -q "\-k" && exit 1 || exit 0
    )
    if [ $? -eq 0 ]; then
        pass "build_curl_opts without insecure has no -k"
    else
        fail "build_curl_opts without insecure has no -k"
    fi
}

test_build_curl_opts_insecure() {
    (
        source_script "ob-bastion-setup"
        VERIFY_SSL="false"
        build_curl_opts
        local opts="${CURL_OPTS[*]}"
        echo "$opts" | grep -q "\-k" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "build_curl_opts with insecure has -k"
    else
        fail "build_curl_opts with insecure has -k"
    fi
}

# ── Test 13: --max-security sets MAX_SECURITY=true ──
test_max_security() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --max-security
        [ "$MAX_SECURITY" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--max-security sets MAX_SECURITY=true"
    else
        fail "--max-security sets MAX_SECURITY=true"
    fi
}

# ── Test 14: --node-role parsed and rendered into the config ──
test_node_role() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --node-role standalone
        [ "$NODE_ROLE" = "standalone" ] || exit 1
        PORTAL_URL="https://x"; OB_TOKEN="/v/t"; SERVER_GROUP="g"
        CLIENT_ID=""; CLIENT_SECRET=""; VERIFY_SSL=true
        # Capture first: piping into `grep -q` makes grep exit on first match,
        # which SIGPIPEs render_openbastion_conf and trips `set -o pipefail`.
        local conf; conf=$(render_openbastion_conf)
        grep -q "^node_role = standalone$" <<<"$conf" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--node-role is parsed and written to the config"
    else
        fail "--node-role is parsed and written to the config"
    fi
}

# ── Test 15: invalid --node-role is rejected ──
test_node_role_invalid() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --node-role bogus 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        pass "invalid --node-role is rejected"
    else
        fail "invalid --node-role is rejected"
    fi
}

# ── Test 16: default node_role is bastion ──
test_node_role_default() {
    (
        source_script "ob-bastion-setup"
        PORTAL_URL="https://x"; OB_TOKEN="/v/t"; SERVER_GROUP="g"
        CLIENT_ID=""; CLIENT_SECRET=""; VERIFY_SSL=true
        local conf; conf=$(render_openbastion_conf)
        grep -q "^node_role = bastion$" <<<"$conf" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "default node_role is bastion"
    else
        fail "default node_role is bastion"
    fi
}

# -- Test 17: portal URL with shell metacharacters is rejected --
# PORTAL_URL is interpolated into generated artefacts (notably the root-cron
# open-bastion-refresh-krl script, written through an unquoted heredoc), so the
# script validates its shape the same way ob-builder's is_valid_url() does.
test_portal_url_rejects_metacharacters() {
    local bad out rc failed=0
    for bad in 'https://x.example.com/$(id)' 'https://x.example.com/`id`' \
               'https://x.example.com/a b' 'https://x.example.com/";reboot;"' \
               'ftp://x.example.com'; do
        out=$(bash "$SCRIPT_DIR/ob-bastion-setup" -p "$bad" --dry-run --yes 2>&1)
        rc=$?
        if [ $rc -eq 0 ] || ! grep -q "Invalid portal URL" <<<"$out"; then
            failed=1
            echo "    (not rejected: $bad)"
        fi
    done
    if [ "$failed" -eq 0 ]; then
        pass "portal URL with shell metacharacters is rejected"
    else
        fail "portal URL with shell metacharacters is rejected"
    fi
}

# -- Test 18: ordinary portal URLs still pass validation --
test_portal_url_accepts_normal() {
    local good out failed=0
    for good in "https://auth.example.com" "http://localhost:8080/portal" \
                "https://auth.example.com/path?a=b#c"; do
        # The run still fails later (not root); it must not fail HERE.
        out=$(bash "$SCRIPT_DIR/ob-bastion-setup" -p "$good" --dry-run --yes 2>&1)
        if grep -q "Invalid portal URL" <<<"$out"; then
            failed=1
            echo "    (wrongly rejected: $good)"
        fi
    done
    if [ "$failed" -eq 0 ]; then
        pass "ordinary portal URLs pass validation"
    else
        fail "ordinary portal URLs pass validation"
    fi
}

# -- The fresh-OTP opt-in (#178) --
#
# sudo caches its own credential (timestamp_timeout, 15 min, idle-based and
# rearmed on each use). While it is valid sudo skips the PAM auth phase
# entirely, so pam_openbastion never runs and no LLNG one-time token is asked
# for. --enable-sudo-fresh-otp scopes timestamp_timeout=0 to the SSO group so
# every elevation goes through PAM. It must stay OFF by default: turning it on
# changes the prompt cadence for every SSO user on an upgraded fleet.
test_sudo_fresh_otp_optin() {
    local off on ok=1

    off=$(
        source_script "ob-bastion-setup"
        SUDO_FRESH_OTP=false
        render_open_bastion_sudoers "# header"
    )
    on=$(
        source_script "ob-bastion-setup"
        SUDO_FRESH_OTP=true
        render_open_bastion_sudoers "# header"
    )

    grep -q '^%open-bastion-sudo ALL=(ALL) ALL$' <<<"$off" \
        || { ok=0; echo "    (default drop-in lost its sudo rule)"; }
    grep -q 'timestamp_timeout' <<<"$off" \
        && { ok=0; echo "    (timestamp_timeout applied without the flag)"; }
    grep -q '^Defaults:%open-bastion-sudo timestamp_timeout=0$' <<<"$on" \
        || { ok=0; echo "    (--enable-sudo-fresh-otp did not scope timestamp_timeout=0)"; }
    grep -q '^%open-bastion-sudo ALL=(ALL) ALL$' <<<"$on" \
        || { ok=0; echo "    (opt-in drop-in lost its sudo rule)"; }
    grep -q 'enable-sudo-fresh-otp' <<<"$(bash "$SCRIPT_DIR/ob-bastion-setup" --help 2>&1)" \
        || { ok=0; echo "    (not documented in --help)"; }

    if command -v visudo >/dev/null 2>&1; then
        local tmp; tmp=$(mktemp)
        printf '%s\n' "$on" > "$tmp"
        visudo -cf "$tmp" >/dev/null 2>&1 \
            || { ok=0; echo "    (opt-in drop-in fails visudo)"; }
        rm -f "$tmp"
    fi

    if [ "$ok" -eq 1 ]; then
        pass "--enable-sudo-fresh-otp is opt-in, scoped, and documented"
    else
        fail "--enable-sudo-fresh-otp is opt-in, scoped, and documented"
    fi
}
# -- Test 19: sudoers drop-in is validated before it is installed --
# A malformed /etc/sudoers.d/open-bastion breaks sudo host-wide, so the rule is
# written to a temp file, checked with visudo -cf, and only then installed 0440
# -- one function, used by every role.
test_sudoers_validated_before_install() {
    local body ok=1
    body=$(sed -n '/^write_open_bastion_sudoers()/,/^}/p' "$SCRIPT_DIR/ob-bastion-setup")

    grep -q 'visudo -cf' <<<"$body" || { ok=0; echo "    (no visudo -cf)"; }
    grep -q 'install -m 0440 -o root -g root' <<<"$body" || { ok=0; echo "    (no install -m 0440)"; }
    # The rule must never be echoed straight into the live sudoers.d path.
    if grep -qE '>[[:space:]]*"\$sudoers_file"' <<<"$body"; then
        ok=0; echo "    (writes \$sudoers_file directly)"
    fi

    if [ "$ok" -eq 1 ]; then
        pass "sudoers drop-in is visudo-validated before install"
    else
        fail "sudoers drop-in is visudo-validated before install"
    fi
}

# -- Test 20: the generated sudoers rule actually parses --
test_sudoers_rule_is_valid() {
    if ! command -v visudo >/dev/null 2>&1; then
        pass "generated sudoers rule parses (skipped: no visudo)"
        return
    fi

    local body tmp
    body=$(sed -n '/^write_open_bastion_sudoers()/,/^}/p' "$SCRIPT_DIR/ob-bastion-setup")
    tmp=$(mktemp)
    # Replay exactly the lines the script writes into its temp sudoers file,
    # including the opt-in Defaults line so both shapes are checked at once.
    grep -oE "printf '%s\\\\n' \"(#|%|Defaults)[^\"]*\"" <<<"$body" \
        | sed -E "s/^printf '%s\\\\n' \"//; s/\"\$//" > "$tmp"

    if [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        fail "generated sudoers rule parses" "could not extract the rule"
        return
    fi

    if visudo -cf "$tmp" >/dev/null 2>&1; then
        pass "generated sudoers rule parses under visudo"
    else
        fail "generated sudoers rule parses under visudo" "$(cat "$tmp")"
    fi
    rm -f "$tmp"
}

# ── Test 21: the generated sshd PAM auth stack is fail-closed (#180) ──
# A bare "auth required pam_permit.so" made pam_authenticate() succeed for any
# password if sshd ever ran the stack (PasswordAuthentication /
# KbdInteractiveAuthentication yes with UsePAM yes). The stack now denies
# outright: sshd never calls pam_authenticate() for a certificate login, so the
# only thing that reaches it is a password/keyboard-interactive attempt.
# tests/test_ob_pam_runtime.sh proves the denial by running the stack.
test_pam_sshd_fail_closed() {
    local out
    out=$(
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --dry-run
        configure_pam_sshd 2>&1
    )
    assert_auth_stack_denies "generated /etc/pam.d/sshd auth stack denies" "$out"
}

# ── Test 22: the Mode E sudo stack keeps its pam_deny backstop (#180) ──
test_pam_sudo_max_security_fail_closed() {
    local out
    out=$(
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --max-security --dry-run
        configure_max_security_sudo 2>&1
    )
    assert_auth_stack_fail_closed "generated Mode E /etc/pam.d/sudo auth stack is fail-closed" "$out"
}

# ── Run all tests ──
echo "=== Testing ob-bastion-setup ==="
run_test test_syntax
run_test test_version
run_test test_help
run_test test_unknown_option
run_test test_missing_portal
run_test test_parse_args_sets_variables
run_test test_dry_run
run_test test_yes
run_test test_insecure
run_test test_trailing_slash
run_test test_confirm_noninteractive
run_test test_backup_file
run_test test_build_curl_opts_default
run_test test_build_curl_opts_insecure
run_test test_max_security
run_test test_node_role
run_test test_node_role_invalid
run_test test_node_role_default
run_test test_portal_url_rejects_metacharacters
run_test test_portal_url_accepts_normal
run_test test_sudo_fresh_otp_optin
run_test test_sudoers_validated_before_install
run_test test_sudoers_rule_is_valid

run_test test_pam_sshd_fail_closed
run_test test_pam_sudo_max_security_fail_closed

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
