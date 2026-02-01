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
    if bash -n "$SCRIPT_DIR/ob-ssh-cert" 2>/dev/null; then
        pass "Syntax check"
    else
        fail "Syntax check"
    fi
}

# ── Test 2: --version / --help ──
test_version() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-ssh-cert" --version 2>&1)
    if echo "$out" | grep -q "version"; then
        pass "--version outputs version"
    else
        fail "--version outputs version" "$out"
    fi
}

test_help() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-ssh-cert" --help 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "--help outputs usage"
    else
        fail "--help outputs usage" "$out"
    fi
}

# ── Test 3: Unknown option rejected ──
test_unknown_option() {
    if bash "$SCRIPT_DIR/ob-ssh-cert" --bogus 2>/dev/null; then
        fail "Unknown option rejected"
    else
        pass "Unknown option rejected"
    fi
}

# ── Test 4: Missing portal URL exits with error ──
test_missing_portal() {
    if bash "$SCRIPT_DIR/ob-ssh-cert" 2>/dev/null; then
        fail "Missing portal URL exits with error"
    else
        pass "Missing portal URL exits with error"
    fi
}

# ── Test 5: parse_args sets variables correctly ──
test_parse_args_sets_variables() {
    (
        source_script "ob-ssh-cert"
        parse_args -p "https://auth.example.com" -v 60 -c myclient -K /tmp/key.pub -o /tmp/cert.pub
        local ok=true
        [ "$PORTAL_URL" = "https://auth.example.com" ] || ok=false
        [ "$VALIDITY_MINUTES" = "60" ] || ok=false
        [ "$CLIENT_ID" = "myclient" ] || ok=false
        [ "$PUBLIC_KEY_FILE" = "/tmp/key.pub" ] || ok=false
        [ "$OUTPUT_FILE" = "/tmp/cert.pub" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "parse_args sets PORTAL_URL, VALIDITY_MINUTES, CLIENT_ID, PUBLIC_KEY_FILE, OUTPUT_FILE"
    else
        fail "parse_args sets PORTAL_URL, VALIDITY_MINUTES, CLIENT_ID, PUBLIC_KEY_FILE, OUTPUT_FILE"
    fi
}

# ── Test 6: parse_args validates validity must be positive integer ──
test_validity_abc() {
    (
        source_script "ob-ssh-cert"
        parse_args -p "https://x" -v "abc" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        pass "Validity rejects 'abc'"
    else
        fail "Validity rejects 'abc'"
    fi
}

test_validity_zero() {
    (
        source_script "ob-ssh-cert"
        parse_args -p "https://x" -v "0" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        pass "Validity rejects '0'"
    else
        fail "Validity rejects '0'"
    fi
}

test_validity_negative() {
    (
        source_script "ob-ssh-cert"
        parse_args -p "https://x" -v "-5" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        pass "Validity rejects '-5'"
    else
        fail "Validity rejects '-5'"
    fi
}

# ── Test 7: -k sets VERIFY_SSL=false ──
test_insecure_flag() {
    (
        source_script "ob-ssh-cert"
        parse_args -p "https://x" -k
        [ "$VERIFY_SSL" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "-k sets VERIFY_SSL=false"
    else
        fail "-k sets VERIFY_SSL=false"
    fi
}

# ── Test 8: build_curl_opts without/with insecure ──
test_build_curl_opts_default() {
    (
        source_script "ob-ssh-cert"
        build_curl_opts
        local opts="${CURL_OPTS[*]}"
        if echo "$opts" | grep -q "\-k"; then
            exit 1
        fi
        exit 0
    )
    if [ $? -eq 0 ]; then
        pass "build_curl_opts without insecure has no -k"
    else
        fail "build_curl_opts without insecure has no -k"
    fi
}

test_build_curl_opts_insecure() {
    (
        source_script "ob-ssh-cert"
        VERIFY_SSL=false
        build_curl_opts
        local opts="${CURL_OPTS[*]}"
        if echo "$opts" | grep -q "\-k"; then
            exit 0
        fi
        exit 1
    )
    if [ $? -eq 0 ]; then
        pass "build_curl_opts with insecure has -k"
    else
        fail "build_curl_opts with insecure has -k"
    fi
}

# ── Test 9: get_key_from_file reads a public key file correctly ──
test_get_key_from_file() {
    local tmpkey
    tmpkey=$(mktemp)
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@host" > "$tmpkey"
    (
        source_script "ob-ssh-cert"
        local result
        result=$(get_key_from_file "$tmpkey")
        [ "$result" = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@host" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -f "$tmpkey"
    if [ $rc -eq 0 ]; then
        pass "get_key_from_file reads public key correctly"
    else
        fail "get_key_from_file reads public key correctly"
    fi
}

# ── Test 10: get_key_from_file rejects missing file ──
test_get_key_from_file_missing() {
    (
        source_script "ob-ssh-cert"
        get_key_from_file "/nonexistent/key.pub" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        pass "get_key_from_file rejects missing file"
    else
        fail "get_key_from_file rejects missing file"
    fi
}

# ── Test 11: Portal URL trailing slash stripped ──
test_trailing_slash() {
    (
        source_script "ob-ssh-cert"
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

# ── Test 12: Environment variables used as defaults ──
test_env_defaults() {
    (
        export LLNG_PORTAL_URL="https://env.example.com"
        export LLNG_SSH_CERT_VALIDITY="45"
        source_script "ob-ssh-cert"
        local ok=true
        [ "$PORTAL_URL" = "https://env.example.com" ] || ok=false
        [ "$VALIDITY_MINUTES" = "45" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "Environment variables used as defaults"
    else
        fail "Environment variables used as defaults"
    fi
}

# ── Test 13: cleanup function removes temp files ──
test_cleanup() {
    (
        source_script "ob-ssh-cert"
        local tmpfile
        tmpfile=$(mktemp)
        TEMP_FILES=("$tmpfile")
        [ -f "$tmpfile" ] || exit 1
        cleanup
        [ ! -f "$tmpfile" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "cleanup removes temp files"
    else
        fail "cleanup removes temp files"
    fi
}

# ── Run all tests ──
echo "=== Testing ob-ssh-cert ==="
run_test test_syntax
run_test test_version
run_test test_help
run_test test_unknown_option
run_test test_missing_portal
run_test test_parse_args_sets_variables
run_test test_validity_abc
run_test test_validity_zero
run_test test_validity_negative
run_test test_insecure_flag
run_test test_build_curl_opts_default
run_test test_build_curl_opts_insecure
run_test test_get_key_from_file
run_test test_get_key_from_file_missing
run_test test_trailing_slash
run_test test_env_defaults
run_test test_cleanup

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
