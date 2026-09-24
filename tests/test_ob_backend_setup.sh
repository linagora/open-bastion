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
    if bash -n "$SCRIPT_DIR/ob-backend-setup" 2>/dev/null; then
        pass "Syntax check"
    else
        fail "Syntax check"
    fi
}

# ── Test 2: --version / --help ──
test_version() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-backend-setup" --version 2>&1)
    if echo "$out" | grep -q "version"; then
        pass "--version outputs version"
    else
        fail "--version outputs version" "$out"
    fi
}

test_help() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-backend-setup" --help 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "--help outputs usage"
    else
        fail "--help outputs usage" "$out"
    fi
}

# ── Test 3: Unknown option rejected ──
test_unknown_option() {
    if bash "$SCRIPT_DIR/ob-backend-setup" --bogus 2>/dev/null; then
        fail "Unknown option rejected"
    else
        pass "Unknown option rejected"
    fi
}

# ── Test 4: Missing portal URL exits with error ──
test_missing_portal() {
    if bash "$SCRIPT_DIR/ob-backend-setup" -g mygroup 2>/dev/null; then
        fail "Missing portal URL exits with error"
    else
        pass "Missing portal URL exits with error"
    fi
}

# ── Test 5: Missing server-group exits with error ──
test_missing_server_group() {
    if bash "$SCRIPT_DIR/ob-backend-setup" -p "https://x" 2>/dev/null; then
        fail "Missing server-group exits with error"
    else
        pass "Missing server-group exits with error"
    fi
}

# ── Test 6: parse_args sets all variables correctly ──
test_parse_args_sets_variables() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://auth.example.com" -g "prod" -n -y -k --no-sudo --no-create-user
        local ok=true
        [ "$PORTAL_URL" = "https://auth.example.com" ] || ok=false
        [ "$SERVER_GROUP" = "prod" ] || ok=false
        [ "$DRY_RUN" = "true" ] || ok=false
        [ "$NON_INTERACTIVE" = "true" ] || ok=false
        [ "$VERIFY_SSL" = "false" ] || ok=false
        [ "$ENABLE_SUDO" = "false" ] || ok=false
        [ "$CREATE_USERS" = "false" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "parse_args sets all variables correctly"
    else
        fail "parse_args sets all variables correctly"
    fi
}

# ── Test 7: --no-sudo sets ENABLE_SUDO=false ──
test_no_sudo() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --no-sudo
        [ "$ENABLE_SUDO" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--no-sudo sets ENABLE_SUDO=false"
    else
        fail "--no-sudo sets ENABLE_SUDO=false"
    fi
}

# ── Test 7b: sudo config provisions the open-bastion-sudo group + sudoers rule (#154) ──
# ob-backend-setup used to configure only PAM for sudo, never the sudoers
# drop-in, so SSO users always got "not in the sudoers file" on backends.
test_sudo_creates_sudoers_rule() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        configure_pam_sudo 2>&1
    )
    if echo "$out" | grep -q "open-bastion-sudo" \
       && echo "$out" | grep -q "/etc/sudoers.d/open-bastion"; then
        pass "configure_pam_sudo provisions open-bastion-sudo group + sudoers rule (#154)"
    else
        fail "configure_pam_sudo provisions sudoers rule (#154)" "$out"
    fi
}

# ── Test 7c: --no-sudo skips the sudoers rule entirely ──
test_no_sudo_skips_sudoers() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --no-sudo --dry-run
        configure_pam_sudo 2>&1
    )
    if echo "$out" | grep -q "sudoers.d/open-bastion"; then
        fail "--no-sudo must not provision a sudoers rule" "$out"
    else
        pass "--no-sudo skips the sudoers rule"
    fi
}

# ── Test 7d: Mode E provisions the sudoers rule itself ──
# The Mode E sudo stack is useless to an SSO user without the group and its
# sudoers rule. On a backend configure_pam_sudo happened to create them first;
# Mode E must not depend on that ordering, as it does not on a bastion.
test_max_security_sudo_provisions_sudoers() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --max-security --dry-run
        configure_max_security_sudo 2>&1
    )
    if grep -q "Would create group open-bastion-sudo" <<<"$out" \
       && grep -q "/etc/sudoers.d/open-bastion" <<<"$out"; then
        pass "Mode E sudo provisions the open-bastion-sudo group + sudoers rule"
    else
        fail "Mode E sudo provisions the open-bastion-sudo group + sudoers rule" "$out"
    fi
}

# ── Test 7e: --no-sudo and --max-security are refused together ──
# Mode E rewrites /etc/pam.d/sudo whatever --no-sudo says, so the pair cannot
# both be honoured; the run must stop before touching anything.
test_no_sudo_conflicts_with_max_security() {
    local out rc
    out=$(bash "$SCRIPT_DIR/ob-backend-setup" -p "https://x.example.com" -g g \
              --no-sudo --max-security --dry-run --yes 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ] && grep -q -- "--no-sudo cannot be combined with --max-security" <<<"$out"; then
        pass "--no-sudo with --max-security is refused"
    else
        fail "--no-sudo with --max-security is refused" "rc=$rc $out"
    fi
}

# ── Test 8: --no-create-user sets CREATE_USERS=false ──
test_no_create_user() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --no-create-user
        [ "$CREATE_USERS" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--no-create-user sets CREATE_USERS=false"
    else
        fail "--no-create-user sets CREATE_USERS=false"
    fi
}

# ── Test 9: --dry-run sets DRY_RUN=true ──
test_dry_run() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        [ "$DRY_RUN" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--dry-run sets DRY_RUN=true"
    else
        fail "--dry-run sets DRY_RUN=true"
    fi
}

# ── Test 10: confirm() in non-interactive mode ──
test_confirm_noninteractive() {
    (
        source_script "ob-backend-setup"
        NON_INTERACTIVE=true
        confirm "Test?" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "confirm() returns 0 in non-interactive mode"
    else
        fail "confirm() returns 0 in non-interactive mode"
    fi
}

# ── Test 11: backup_file works correctly ──
test_backup_file() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local srcfile="$tmpdir/original.conf"
    echo "test content" > "$srcfile"
    (
        source_script "ob-backend-setup"
        BACKUP_DIR="$tmpdir/backups"
        backup_file "$srcfile"
        [ -f "$tmpdir/backups/original.conf" ] || exit 1
        local backed
        backed=$(cat "$tmpdir/backups/original.conf")
        [ "$backed" = "test content" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "backup_file works correctly"
    else
        fail "backup_file works correctly"
    fi
}

# ── Test 12: Portal URL trailing slash stripped ──
test_trailing_slash() {
    (
        source_script "ob-backend-setup"
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

# ── Test 13: --max-security sets MAX_SECURITY=true ──
test_max_security() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --max-security
        [ "$MAX_SECURITY" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--max-security sets MAX_SECURITY=true"
    else
        fail "--max-security sets MAX_SECURITY=true"
    fi
}

# ── Test 14: default node_role is backend, --node-role overrides ──
test_node_role_default() {
    (
        source_script "ob-backend-setup"
        PORTAL_URL="https://x"; OB_TOKEN="/v/t"; SERVER_GROUP="g"
        CLIENT_ID=""; CLIENT_SECRET=""; VERIFY_SSL=true
        # Capture first: piping into `grep -q` makes grep exit on first match,
        # which SIGPIPEs render_openbastion_conf and trips `set -o pipefail`.
        local conf; conf=$(render_openbastion_conf)
        grep -q "^node_role = backend$" <<<"$conf" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "default node_role is backend"
    else
        fail "default node_role is backend"
    fi
}

test_node_role_override() {
    local rc1 rc2
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --node-role bastion
        [ "$NODE_ROLE" = "bastion" ] && exit 0 || exit 1
    )
    rc1=$?
    # invalid role: parse_args errors out (exits non-zero)
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --node-role bogus 2>/dev/null
    )
    rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -ne 0 ]; then
        pass "--node-role accepts valid role and rejects invalid"
    else
        fail "--node-role accepts valid role and rejects invalid"
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
        source_script "ob-backend-setup"
        SUDO_FRESH_OTP=false
        render_open_bastion_sudoers "# header"
    )
    on=$(
        source_script "ob-backend-setup"
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
    grep -q 'enable-sudo-fresh-otp' <<<"$(bash "$SCRIPT_DIR/ob-backend-setup" --help 2>&1)" \
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

# ── The allowed-bastions list is validated and normalised (#182) ──
#
# The list is written to a world-readable file consumed by the principals
# helper, which compares each entry against a bastion_id it has already
# restricted to [A-Za-z0-9._-]. A typo outside that charset would sit there
# matching nothing (every hop denied, unexplained), and a whitespace-only value
# would silently mean "any bastion" while looking configured.
test_allowed_bastions_normalised() {
    local rc1 rc2 rc3
    (
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b1, b2 ;b3"
        normalize_allowed_bastions
        [ "$BASTION_ALLOWED_IDS" = "b1 b2 b3" ] && exit 0 || exit 1
    )
    rc1=$?
    (
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="   "
        normalize_allowed_bastions
        [ -z "$BASTION_ALLOWED_IDS" ] && exit 0 || exit 1
    )
    rc2=$?
    (
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="ok,bad id!"
        normalize_allowed_bastions 2>/dev/null
    )
    rc3=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$rc3" -ne 0 ]; then
        pass "allowed-bastions list normalised, blank collapses, junk rejected"
    else
        fail "allowed-bastions validation" "rc=$rc1/$rc2/$rc3"
    fi
}

# ── A glob in the list must be refused, not silently rewritten (#236 review) ──
#
# Splitting the raw list runs pathname expansion as well as word splitting, so
# 'b[1]' used to become whichever file matched in the CURRENT DIRECTORY -- the
# typo was accepted as a different, valid-looking id instead of being refused.
# The test runs from a directory seeded with files that the globs match, which
# is the only condition under which the bug is observable.
test_allowed_bastions_no_glob() {
    local tmp rc out ok=1
    tmp=$(mktemp -d)
    : > "$tmp/b1"
    : > "$tmp/b2"

    # 'b[1]' matches the file b1; must still be rejected as an invalid id.
    out=$(
        cd "$tmp" || exit 99
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b[1]"
        normalize_allowed_bastions 2>&1
        printf 'RESULT=%s\n' "$BASTION_ALLOWED_IDS"
    )
    rc=$?
    [ "$rc" -ne 0 ] || { ok=0; echo "    (glob 'b[1]' accepted, rc=$rc: $out)"; }
    grep -q 'RESULT=b1' <<<"$out" && { ok=0; echo "    (glob 'b[1]' rewritten to the file b1)"; }

    # 'b*' matches two files; must not turn into a two-entry allowlist.
    out=$(
        cd "$tmp" || exit 99
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b*"
        normalize_allowed_bastions 2>&1
        printf 'RESULT=%s\n' "$BASTION_ALLOWED_IDS"
    )
    rc=$?
    [ "$rc" -ne 0 ] || { ok=0; echo "    (glob 'b*' accepted, rc=$rc: $out)"; }
    grep -q 'RESULT=b1 b2' <<<"$out" && { ok=0; echo "    (glob 'b*' expanded to the cwd)"; }

    # A legitimate list must still normalise with globbing restored afterwards.
    out=$(
        cd "$tmp" || exit 99
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b1,b2"
        normalize_allowed_bastions
        printf 'RESULT=%s|GLOB=%s\n' "$BASTION_ALLOWED_IDS" "$(case $- in *f*) echo off ;; *) echo on ;; esac)"
    )
    grep -q 'RESULT=b1 b2|GLOB=on' <<<"$out" \
        || { ok=0; echo "    (valid list broken, or globbing left disabled: $out)"; }

    rm -rf "$tmp"
    if [ "$ok" -eq 1 ]; then
        pass "globs in the allowed-bastions list are refused, not expanded"
    else
        fail "globs in the allowed-bastions list are refused, not expanded"
    fi
}

# ── An empty list must be an explicit interactive choice (#236 review) ──
#
# Pressing Enter used to accept "any bastion" -- the exposure #182 is about --
# as the path of least resistance. It now re-asks and takes only an explicit
# "y". Non-interactive runs keep the empty default: an upgrade must not start
# refusing hops that worked yesterday.
test_allowed_bastions_empty_is_explicit() {
    local out ok=1

    # Enter, then "n", then a real id: the empty answer must not stick.
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=false
        ALLOW_ANY_BASTION=false
        BASTION_ALLOWED_IDS=""
        # NOT a pipe: a pipeline would run the function in a subshell and
        # throw away the assignment this test is about.
        prompt_allowed_bastions >/dev/null 2>&1 <<<$'\nn\nb1'
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[b1\]' <<<"$out" \
        || { ok=0; echo "    (declining 'any bastion' did not re-ask: $out)"; }

    # A separators-only answer must not slip past the gate either: the
    # normaliser collapses whitespace AND ',;' to nothing, so each of these
    # reaches the empty list while looking like an answer (#236 review).
    local blank
    for blank in '   ' ',,' ' ; , '; do
        out=$(
            source_script "ob-backend-setup"
            NON_INTERACTIVE=false
            ALLOW_ANY_BASTION=false
            BASTION_ALLOWED_IDS=""
            prompt_allowed_bastions >/dev/null 2>&1 <<<"$blank"$'\nn\nb1'
            printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
        )
        grep -q 'RESULT=\[b1\]' <<<"$out" \
            || { ok=0; echo "    (blank answer '$blank' bypassed the gate: $out)"; }
    done

    # Enter, then "y": empty, on the record.
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=false
        ALLOW_ANY_BASTION=false
        BASTION_ALLOWED_IDS=""
        prompt_allowed_bastions >/dev/null 2>&1 <<<$'\ny'
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[\]' <<<"$out" \
        || { ok=0; echo "    (explicit 'y' did not leave the list empty: $out)"; }

    # --allow-any-bastion answers up front, without a prompt (no stdin at all).
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=false
        ALLOW_ANY_BASTION=true
        BASTION_ALLOWED_IDS=""
        prompt_allowed_bastions >/dev/null 2>&1 </dev/null
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[\]' <<<"$out" \
        || { ok=0; echo "    (--allow-any-bastion still prompted: $out)"; }

    # A non-interactive run keeps the legacy empty default, unprompted.
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=true
        ALLOW_ANY_BASTION=false
        BASTION_ALLOWED_IDS=""
        prompt_allowed_bastions >/dev/null 2>&1 </dev/null
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[\]' <<<"$out" \
        || { ok=0; echo "    (--yes run no longer keeps the empty default: $out)"; }

    # Both options must be discoverable, since the prompt now depends on them.
    local help
    help=$(bash "$SCRIPT_DIR/ob-backend-setup" --help 2>&1)
    grep -q -- '--allowed-bastions' <<<"$help" \
        || { ok=0; echo "    (--allowed-bastions missing from --help)"; }
    grep -q -- '--allow-any-bastion' <<<"$help" \
        || { ok=0; echo "    (--allow-any-bastion missing from --help)"; }

    if [ "$ok" -eq 1 ]; then
        pass "empty allowed-bastions is an explicit choice, and both flags documented"
    else
        fail "empty allowed-bastions is an explicit choice, and both flags documented"
    fi
}

# ── Test 18: the generated sshd PAM auth stack is fail-closed (#180) ──
# A bare "auth required pam_permit.so" made pam_authenticate() succeed for any
# password if sshd ever ran the stack (PasswordAuthentication /
# KbdInteractiveAuthentication yes with UsePAM yes). The stack now denies
# outright: sshd never calls pam_authenticate() for a certificate login, so the
# only thing that reaches it is a password/keyboard-interactive attempt.
# tests/test_ob_pam_runtime.sh proves the denial by running the stack.
test_pam_sshd_fail_closed() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        configure_pam_sshd 2>&1
    )
    assert_auth_stack_denies "generated /etc/pam.d/sshd auth stack denies" "$out"
}

# ── Test 19: the generated sudo PAM auth stack is fail-closed (#180) ──
test_pam_sudo_fail_closed() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        configure_pam_sudo 2>&1
    )
    assert_auth_stack_fail_closed "generated /etc/pam.d/sudo auth stack is fail-closed" "$out"
}

# ── Run all tests ──
echo "=== Testing ob-backend-setup ==="
run_test test_syntax
run_test test_version
run_test test_help
run_test test_unknown_option
run_test test_missing_portal
run_test test_missing_server_group
run_test test_parse_args_sets_variables
run_test test_no_sudo
run_test test_sudo_creates_sudoers_rule
run_test test_no_sudo_skips_sudoers
run_test test_max_security_sudo_provisions_sudoers
run_test test_no_sudo_conflicts_with_max_security
run_test test_no_create_user
run_test test_dry_run
run_test test_confirm_noninteractive
run_test test_backup_file
run_test test_trailing_slash
run_test test_max_security
run_test test_node_role_default
run_test test_node_role_override
run_test test_allowed_bastions_normalised
run_test test_allowed_bastions_no_glob
run_test test_allowed_bastions_empty_is_explicit

run_test test_sudo_fresh_otp_optin
run_test test_pam_sshd_fail_closed
run_test test_pam_sudo_fail_closed

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
