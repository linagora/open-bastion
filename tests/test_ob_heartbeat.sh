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

# ── Test 13: load_config sanitizes invalid max_reported_sessions ──
test_load_config_invalid_max_sessions() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
portal_url = https://portal.test.com
max_reported_sessions = abc
CONF
    (
        source_script "ob-heartbeat"
        CONFIG_FILE="$tmpconf"
        load_config 2>/dev/null
        [ "$MAX_SESSIONS" = "200" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "load_config sanitizes invalid max_reported_sessions to 200"
    else
        fail "load_config sanitizes invalid max_reported_sessions to 200"
    fi
}

# ── Test 14: load_config keeps a valid max_reported_sessions / report_sessions ──
test_load_config_session_settings() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
portal_url = https://portal.test.com
report_sessions = false
max_reported_sessions = 50
CONF
    (
        source_script "ob-heartbeat"
        CONFIG_FILE="$tmpconf"
        load_config 2>/dev/null
        local ok=true
        [ "$REPORT_SESSIONS" = "false" ] || ok=false
        [ "$MAX_SESSIONS" = "50" ] || ok=false
        $ok && exit 0 || exit 1
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "load_config keeps valid report_sessions/max_reported_sessions"
    else
        fail "load_config keeps valid report_sessions/max_reported_sessions"
    fi
}

# ── Test 14b: load_config reads node_role ──
test_load_config_node_role() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
portal_url = https://portal.test.com
node_role = standalone
CONF
    (
        source_script "ob-heartbeat"
        CONFIG_FILE="$tmpconf"
        load_config 2>/dev/null
        [ "$NODE_ROLE" = "standalone" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "load_config reads node_role"
    else
        fail "load_config reads node_role"
    fi
}

# ── Test 15: get_sessions returns [] when reporting disabled ──
test_get_sessions_disabled() {
    local out
    out=$(
        source_script "ob-heartbeat"
        REPORT_SESSIONS=false
        MAX_SESSIONS=200
        get_sessions
    )
    if [ "$out" = "[]" ]; then
        pass "get_sessions returns [] when report_sessions=false"
    else
        fail "get_sessions returns [] when report_sessions=false" "$out"
    fi
}

# ── Test 16: get_sessions via loginctl (stubbed) ──
test_get_sessions_loginctl() {
    local out
    out=$(
        source_script "ob-heartbeat"
        REPORT_SESSIONS=true
        MAX_SESSIONS=200
        loginctl() {
            case "$1" in
                list-sessions) printf '%s\n' "c1 1000 alice seat0 tty2" ;;
                show-session)
                    printf '%s\n' "Name=alice" "RemoteHost=10.0.0.9" \
                        "TTY=pts/0" "Timestamp=Sun 2026-06-14 22:03:00 UTC" "Class=user" ;;
            esac
        }
        get_sessions
    )
    if echo "$out" | jq -e \
        '.[0].user=="alice" and .[0].from=="10.0.0.9" and .[0].tty=="pts/0"' >/dev/null 2>&1; then
        pass "get_sessions (loginctl) reports user/from/tty"
    else
        fail "get_sessions (loginctl) reports user/from/tty" "$out"
    fi
}

# ── Test 17: get_sessions skips non-user (greeter) loginctl sessions ──
test_get_sessions_loginctl_skips_nonuser() {
    local out
    out=$(
        source_script "ob-heartbeat"
        REPORT_SESSIONS=true
        MAX_SESSIONS=200
        loginctl() {
            case "$1" in
                list-sessions) printf '%s\n' "c1 121 gdm seat0 tty1" ;;
                show-session)
                    printf '%s\n' "Name=gdm" "RemoteHost=" "TTY=tty1" \
                        "Timestamp=Sun 2026-06-14 22:03:00 UTC" "Class=greeter" ;;
            esac
        }
        get_sessions
    )
    if [ "$out" = "[]" ]; then
        pass "get_sessions skips non-user loginctl sessions"
    else
        fail "get_sessions skips non-user loginctl sessions" "$out"
    fi
}

# ── Test 18: get_sessions falls back to who when loginctl fails ──
test_get_sessions_who_fallback() {
    local out
    out=$(
        source_script "ob-heartbeat"
        REPORT_SESSIONS=true
        MAX_SESSIONS=200
        # loginctl exists but list-sessions fails (logind/dbus down)
        loginctl() { return 1; }
        who() { printf '%s\n' "carol pts/1 2026-06-14 23:00 (192.168.1.5)"; }
        get_sessions
    )
    if echo "$out" | jq -e \
        '.[0].user=="carol" and .[0].from=="192.168.1.5" and .[0].tty=="pts/1"' >/dev/null 2>&1; then
        pass "get_sessions falls back to who when loginctl fails"
    else
        fail "get_sessions falls back to who when loginctl fails" "$out"
    fi
}

# ── Test 19: get_sessions honours max_reported_sessions cap ──
test_get_sessions_cap() {
    local out
    out=$(
        source_script "ob-heartbeat"
        REPORT_SESSIONS=true
        MAX_SESSIONS=1
        loginctl() { return 1; }
        who() {
            printf '%s\n' \
                "u1 pts/1 2026-06-14 23:00 (1.1.1.1)" \
                "u2 pts/2 2026-06-14 23:01 (2.2.2.2)"
        }
        get_sessions 2>/dev/null
    )
    if [ "$(echo "$out" | jq 'length')" = "1" ]; then
        pass "get_sessions caps the list at max_reported_sessions"
    else
        fail "get_sessions caps the list at max_reported_sessions" "$out"
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
run_test test_load_config_invalid_max_sessions
run_test test_load_config_session_settings
run_test test_load_config_node_role
run_test test_get_sessions_disabled
run_test test_get_sessions_loginctl
run_test test_get_sessions_loginctl_skips_nonuser
run_test test_get_sessions_who_fallback
run_test test_get_sessions_cap

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
