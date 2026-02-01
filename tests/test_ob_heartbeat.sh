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
    if bash -n "$SCRIPT_DIR/ob-heartbeat" 2>/dev/null; then
        pass "Syntax check"
    else
        fail "Syntax check"
    fi
}

# ── Test 2: --version / --help ──
test_version() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-heartbeat" --version 2>&1)
    if echo "$out" | grep -q "version"; then
        pass "--version outputs version"
    else
        fail "--version outputs version" "$out"
    fi
}

test_help() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-heartbeat" --help 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "--help outputs usage"
    else
        fail "--help outputs usage" "$out"
    fi
}

# ── Test 3: Unknown option rejected ──
test_unknown_option() {
    if bash "$SCRIPT_DIR/ob-heartbeat" --bogus 2>/dev/null; then
        fail "Unknown option rejected"
    else
        pass "Unknown option rejected"
    fi
}

# ── Test 4: read_config parses key=value correctly ──
test_read_config() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
# This is a comment
portal_url = https://auth.example.com
server_group = "production"
token_file = '/etc/token'
verify_ssl = true  # inline comment

empty_line_above = works
CONF
    (
        source_script "ob-heartbeat"
        local ok=true
        [ "$(read_config portal_url "$tmpconf")" = "https://auth.example.com" ] || ok=false
        [ "$(read_config server_group "$tmpconf")" = "production" ] || ok=false
        [ "$(read_config token_file "$tmpconf")" = "/etc/token" ] || ok=false
        [ "$(read_config verify_ssl "$tmpconf")" = "true" ] || ok=false
        [ "$(read_config empty_line_above "$tmpconf")" = "works" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "read_config parses key=value correctly"
    else
        fail "read_config parses key=value correctly"
    fi
}

# ── Test 5: load_config reads portal_url, server_group, token_file, verify_ssl ──
test_load_config() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
portal_url = https://portal.test.com
server_group = mygroup
token_file = /tmp/mytoken
verify_ssl = false
CONF
    (
        source_script "ob-heartbeat"
        CONFIG_FILE="$tmpconf"
        load_config
        local ok=true
        [ "$PORTAL_URL" = "https://portal.test.com" ] || ok=false
        [ "$SERVER_GROUP" = "mygroup" ] || ok=false
        [ "$TOKEN_FILE" = "/tmp/mytoken" ] || ok=false
        [ "$VERIFY_SSL" = "false" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "load_config reads all config values"
    else
        fail "load_config reads all config values"
    fi
}

# ── Test 6: load_config fails when config file missing ──
test_load_config_missing_file() {
    (
        source_script "ob-heartbeat"
        CONFIG_FILE="/nonexistent/config"
        load_config 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        pass "load_config fails when config file missing"
    else
        fail "load_config fails when config file missing"
    fi
}

# ── Test 7: load_config fails when portal_url missing ──
test_load_config_missing_portal() {
    local tmpconf
    tmpconf=$(mktemp)
    echo "server_group = test" > "$tmpconf"
    (
        source_script "ob-heartbeat"
        CONFIG_FILE="$tmpconf"
        load_config 2>/dev/null
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -ne 0 ]; then
        pass "load_config fails when portal_url missing"
    else
        fail "load_config fails when portal_url missing"
    fi
}

# ── Test 8: read_token reads JSON format token file ──
test_read_token_json() {
    local tmptoken
    tmptoken=$(mktemp)
    echo '{"refresh_token":"myrefresh123","access_token":"access456"}' > "$tmptoken"
    (
        source_script "ob-heartbeat"
        TOKEN_FILE="$tmptoken"
        REFRESH_TOKEN=""
        read_token
        [ "$REFRESH_TOKEN" = "myrefresh123" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -f "$tmptoken"
    if [ $rc -eq 0 ]; then
        pass "read_token reads JSON format and extracts refresh_token"
    else
        fail "read_token reads JSON format and extracts refresh_token"
    fi
}

# ── Test 9: read_token exits silently when token file missing ──
test_read_token_missing() {
    # read_token calls exit 0, so we must run in a full bash subprocess
    local out rc
    local tmpscript
    tmpscript=$(mktemp)
    cat > "$tmpscript" <<SCRIPT
source_script() {
    local script="\$1"
    local content
    content=\$(cat "$SCRIPT_DIR/\$script")
    content="\${content%main \"\\\$@\"}"
    content=\$(echo "\$content" | sed -E 's/^set -e(uo pipefail)?\$//')
    eval "\$content"
}
source_script "ob-heartbeat"
TOKEN_FILE="/nonexistent/token"
read_token
echo "DID_NOT_EXIT"
SCRIPT
    out=$(bash "$tmpscript" 2>/dev/null)
    rc=$?
    rm -f "$tmpscript"
    if [ $rc -eq 0 ] && [ "$out" != "DID_NOT_EXIT" ]; then
        pass "read_token exits silently (code 0) when token file missing"
    else
        fail "read_token exits silently (code 0) when token file missing"
    fi
}

# ── Test 10: read_token exits silently for legacy plain text format ──
test_read_token_legacy() {
    local tmptoken
    tmptoken=$(mktemp)
    echo "some-plain-text-token" > "$tmptoken"
    local tmpscript
    tmpscript=$(mktemp)
    cat > "$tmpscript" <<SCRIPT
source_script() {
    local script="\$1"
    local content
    content=\$(cat "$SCRIPT_DIR/\$script")
    content="\${content%main \"\\\$@\"}"
    content=\$(echo "\$content" | sed -E 's/^set -e(uo pipefail)?\$//')
    eval "\$content"
}
source_script "ob-heartbeat"
TOKEN_FILE="$tmptoken"
read_token
echo "DID_NOT_EXIT"
SCRIPT
    local out rc
    out=$(bash "$tmpscript" 2>/dev/null)
    rc=$?
    rm -f "$tmptoken" "$tmpscript"
    if [ $rc -eq 0 ] && [ "$out" != "DID_NOT_EXIT" ]; then
        pass "read_token exits silently for legacy plain text format"
    else
        fail "read_token exits silently for legacy plain text format"
    fi
}

# ── Test 11: build_curl_opts with/without SSL verification ──
test_build_curl_opts_default() {
    (
        source_script "ob-heartbeat"
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
        source_script "ob-heartbeat"
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

# ── Test 12: parse_args sets variables ──
test_parse_args() {
    (
        source_script "ob-heartbeat"
        parse_args -c /tmp/myconf -t /tmp/mytok -d
        local ok=true
        [ "$CONFIG_FILE" = "/tmp/myconf" ] || ok=false
        [ "$TOKEN_FILE" = "/tmp/mytok" ] || ok=false
        [ "$DEBUG" = "1" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "parse_args -c sets CONFIG_FILE, -t sets TOKEN_FILE, -d enables DEBUG"
    else
        fail "parse_args -c sets CONFIG_FILE, -t sets TOKEN_FILE, -d enables DEBUG"
    fi
}

# ── Run all tests ──
echo "=== Testing ob-heartbeat ==="
run_test test_syntax
run_test test_version
run_test test_help
run_test test_unknown_option
run_test test_read_config
run_test test_load_config
run_test test_load_config_missing_file
run_test test_load_config_missing_portal
run_test test_read_token_json
run_test test_read_token_missing
run_test test_read_token_legacy
run_test test_build_curl_opts_default
run_test test_build_curl_opts_insecure
run_test test_parse_args

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
