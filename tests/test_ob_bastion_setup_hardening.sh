#!/bin/bash
# Integration tests for the session-containment hardening step
# added to ob-bastion-setup (PR1). All tests run in dry-run mode and
# inside a sandboxed temporary directory so they never touch the host.
#
# shellcheck disable=SC2034  # variables are read by sourced functions
# shellcheck disable=SC2181  # $? idiom matches existing test style
# shellcheck disable=SC2329  # mocked functions invoked indirectly via sourced helpers
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
SCRIPT_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# Source ob-bastion-setup without executing main, à la test_ob_bastion_setup.sh
source_script() {
    local script="$1"
    local content
    content=$(cat "$SCRIPT_DIR/$script")
    content="${content%main \"\$@\"}"
    content=$(echo "$content" | sed -E 's/^set -e(uo pipefail)?$//')
    eval "$content"
}

# ── Test 1: Templates exist in the source tree ──
test_templates_present() {
    local ok=true
    for f in \
        "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
        "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
        "$REPO_DIR/config/hardening/at.allow" \
        "$REPO_DIR/config/hardening/cron.allow"
    do
        [ -f "$f" ] || { ok=false; echo "    missing: $f"; }
    done
    if $ok; then
        pass "All four hardening templates present in config/hardening/"
    else
        fail "All four hardening templates present in config/hardening/"
    fi
}

# ── Test 2: logind template enables KillUserProcesses ──
test_logind_template_content() {
    local f="$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf"
    if grep -q "^KillUserProcesses=yes" "$f" && grep -q "^\[Login\]" "$f"; then
        pass "logind template sets KillUserProcesses=yes under [Login]"
    else
        fail "logind template sets KillUserProcesses=yes under [Login]"
    fi
}

# ── Test 3: limits template caps nproc and exempts root ──
test_limits_template_content() {
    local f="$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf"
    if grep -qE '^\*[[:space:]]+hard[[:space:]]+nproc[[:space:]]+256' "$f" \
       && grep -qE '^root[[:space:]]+hard[[:space:]]+nproc[[:space:]]+unlimited' "$f"; then
        pass "limits template caps nproc=256 with root unlimited"
    else
        fail "limits template caps nproc=256 with root unlimited"
    fi
}

# ── Test 4: at.allow template does NOT whitelist any user ──
test_at_allow_template_content() {
    local f="$REPO_DIR/config/hardening/at.allow"
    # grep -v comments, blank lines; expect zero non-comment lines.
    local non_comments
    non_comments=$(grep -cvE '^[[:space:]]*(#|$)' "$f")
    if [ "$non_comments" -eq 0 ]; then
        pass "at.allow template is empty (root-only by design)"
    else
        fail "at.allow template is empty" "$non_comments non-comment lines"
    fi
}

# ── Test 5: cron.allow whitelists root only ──
test_cron_allow_template_content() {
    local f="$REPO_DIR/config/hardening/cron.allow"
    local non_comments
    non_comments=$(grep -vE '^[[:space:]]*(#|$)' "$f")
    if [ "$non_comments" = "root" ]; then
        pass "cron.allow template whitelists exactly 'root'"
    else
        fail "cron.allow template whitelists exactly 'root'" "got: $non_comments"
    fi
}

# ── Test 6: --skip-hardening sets SKIP_HARDENING=true ──
test_skip_hardening_flag() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --skip-hardening
        [ "$SKIP_HARDENING" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--skip-hardening sets SKIP_HARDENING=true"
    else
        fail "--skip-hardening sets SKIP_HARDENING=true"
    fi
}

# ── Test 7: Without --skip-hardening, SKIP_HARDENING defaults to false ──
test_skip_hardening_default() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x"
        [ "$SKIP_HARDENING" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "SKIP_HARDENING defaults to false"
    else
        fail "SKIP_HARDENING defaults to false"
    fi
}

# ── Test 8: --help mentions hardening ──
test_help_mentions_hardening() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-bastion-setup" --help 2>&1)
    if echo "$out" | grep -qi "hardening"; then
        pass "--help mentions hardening"
    else
        fail "--help mentions hardening"
    fi
}

# ── Test 9: setup_hardening in dry-run with --skip-hardening is a noop ──
test_setup_hardening_skipped() {
    (
        source_script "ob-bastion-setup"
        DRY_RUN=true
        SKIP_HARDENING=true
        NON_INTERACTIVE=true
        out=$(setup_hardening 2>&1)
        echo "$out" | grep -q "Skipping session containment hardening" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "setup_hardening with SKIP_HARDENING=true logs skip and returns 0"
    else
        fail "setup_hardening with SKIP_HARDENING=true logs skip and returns 0"
    fi
}

# ── Test 10: setup_hardening in dry-run does not write anything ──
test_setup_hardening_dryrun() {
    local sandbox
    sandbox=$(mktemp -d)
    # Build a fake template tree
    mkdir -p "$sandbox/share/hardening/logind.conf.d" \
             "$sandbox/share/hardening/security/limits.d"
    cp "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
       "$sandbox/share/hardening/logind.conf.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
       "$sandbox/share/hardening/security/limits.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/at.allow" "$sandbox/share/hardening/at.allow"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"

    (
        source_script "ob-bastion-setup"
        DRY_RUN=true
        NON_INTERACTIVE=true
        SKIP_HARDENING=false
        HARDENING_TEMPLATE_DIR="$sandbox/share/hardening"
        HARDENING_LOGIND_DST="$sandbox/etc/systemd/logind.conf.d/open-bastion.conf"
        HARDENING_LIMITS_DST="$sandbox/etc/security/limits.d/open-bastion.conf"
        HARDENING_AT_ALLOW="$sandbox/etc/at.allow"
        HARDENING_CRON_ALLOW="$sandbox/etc/cron.allow"
        BACKUP_DIR="$sandbox/backup"
        out=$(setup_hardening 2>&1)
        rc=$?
        # Expect at least 4 [DRY-RUN] log lines and no file written
        echo "$out" | grep -q "DRY-RUN" || exit 2
        [ ! -e "$sandbox/etc/systemd/logind.conf.d/open-bastion.conf" ] || exit 3
        [ ! -e "$sandbox/etc/security/limits.d/open-bastion.conf" ] || exit 4
        [ ! -e "$sandbox/etc/at.allow" ] || exit 5
        [ ! -e "$sandbox/etc/cron.allow" ] || exit 6
        exit $rc
    )
    local rc=$?
    rm -rf "$sandbox"
    if [ $rc -eq 0 ]; then
        pass "setup_hardening dry-run logs intent and writes nothing"
    else
        fail "setup_hardening dry-run logs intent and writes nothing" "rc=$rc"
    fi
}

# ── Test 11: setup_hardening warns when an admin file already exists ──
test_setup_hardening_preserves_admin_file() {
    local sandbox
    sandbox=$(mktemp -d)
    mkdir -p "$sandbox/share/hardening/logind.conf.d" \
             "$sandbox/share/hardening/security/limits.d" \
             "$sandbox/etc"
    cp "$REPO_DIR/config/hardening/at.allow" "$sandbox/share/hardening/at.allow"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"
    cp "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
       "$sandbox/share/hardening/logind.conf.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
       "$sandbox/share/hardening/security/limits.d/open-bastion.conf"
    # Pre-existing admin-managed at.allow
    echo "alice" > "$sandbox/etc/at.allow"

    (
        source_script "ob-bastion-setup"
        # Use real (non-dry-run) installer to test the "leave existing" branch
        DRY_RUN=false
        NON_INTERACTIVE=true
        SKIP_HARDENING=false
        # Avoid root-only operations: shadow install/systemctl with no-ops
        install() { :; }
        systemctl() { :; }
        export -f install systemctl 2>/dev/null || true

        out=$(install_hardening_allowlist \
            "$sandbox/share/hardening/at.allow" \
            "$sandbox/etc/at.allow" 2>&1)
        rc=$?
        # Admin content must remain untouched
        grep -q "^alice$" "$sandbox/etc/at.allow" || exit 2
        echo "$out" | grep -q "leaving untouched" || exit 3
        exit $rc
    )
    local rc=$?
    rm -rf "$sandbox"
    if [ $rc -eq 0 ]; then
        pass "install_hardening_allowlist preserves pre-existing admin file"
    else
        fail "install_hardening_allowlist preserves pre-existing admin file" "rc=$rc"
    fi
}

# ── Run all tests ──
echo "=== Testing ob-bastion-setup hardening step ==="
run_test test_templates_present
run_test test_logind_template_content
run_test test_limits_template_content
run_test test_at_allow_template_content
run_test test_cron_allow_template_content
run_test test_skip_hardening_flag
run_test test_skip_hardening_default
run_test test_help_mentions_hardening
run_test test_setup_hardening_skipped
run_test test_setup_hardening_dryrun
run_test test_setup_hardening_preserves_admin_file

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
