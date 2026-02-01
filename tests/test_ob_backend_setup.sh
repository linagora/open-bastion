#!/bin/bash
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
SCRIPT_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

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
run_test test_no_create_user
run_test test_dry_run
run_test test_confirm_noninteractive
run_test test_backup_file
run_test test_trailing_slash

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
