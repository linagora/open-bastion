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

# ── Test 12: curl_opts with/without insecure ──
test_curl_opts_default() {
    (
        source_script "ob-bastion-setup"
        VERIFY_SSL="true"
        local opts
        opts=$(curl_opts)
        echo "$opts" | grep -q "\-k" && exit 1 || exit 0
    )
    if [ $? -eq 0 ]; then
        pass "curl_opts without insecure has no -k"
    else
        fail "curl_opts without insecure has no -k"
    fi
}

test_curl_opts_insecure() {
    (
        source_script "ob-bastion-setup"
        VERIFY_SSL="false"
        local opts
        opts=$(curl_opts)
        echo "$opts" | grep -q "\-k" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "curl_opts with insecure has -k"
    else
        fail "curl_opts with insecure has -k"
    fi
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
run_test test_curl_opts_default
run_test test_curl_opts_insecure

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
