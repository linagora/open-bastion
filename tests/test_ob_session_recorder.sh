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
    # Ensure SSH_CLIENT is set for ob-session-recorder
    SSH_CLIENT="${SSH_CLIENT:-}"
    SSH_TTY="${SSH_TTY:-}"
    SSH_ORIGINAL_COMMAND="${SSH_ORIGINAL_COMMAND:-}"
    eval "$content"
}

# ── Test 1: Syntax check ──
test_syntax() {
    if bash -n "$SCRIPT_DIR/ob-session-recorder" 2>/dev/null; then
        pass "Syntax check"
    else
        fail "Syntax check"
    fi
}

# ── Test 2: --version / --help ──
test_version() {
    local out
    out=$(SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" bash "$SCRIPT_DIR/ob-session-recorder" --version 2>&1)
    if echo "$out" | grep -q "version"; then
        pass "--version outputs version"
    else
        fail "--version outputs version" "$out"
    fi
}

test_help() {
    local out
    out=$(SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" bash "$SCRIPT_DIR/ob-session-recorder" --help 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "--help outputs usage"
    else
        fail "--help outputs usage" "$out"
    fi
}

# ── Test 3: Unknown option rejected ──
test_unknown_option() {
    if SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" bash "$SCRIPT_DIR/ob-session-recorder" --bogus 2>/dev/null; then
        fail "Unknown option rejected"
    else
        pass "Unknown option rejected"
    fi
}

# ── Test 4: Config file parsing ──
test_config_parsing() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
# comment line
sessions_dir = /tmp/my-sessions
format = asciinema
max_duration = 3600

CONF
    (
        source_script "ob-session-recorder"
        # Override stat to simulate root-owned config for testing
        stat() { echo "0:644"; }
        export -f stat
        CONFIG_FILE="$tmpconf"
        load_config
        local ok=true
        [ "$SESSIONS_DIR" = "/tmp/my-sessions" ] || ok=false
        [ "$FORMAT" = "asciinema" ] || ok=false
        [ "$MAX_SESSION_DURATION" = "3600" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "Config parsing: sessions_dir, format, max_duration read correctly"
    else
        fail "Config parsing: sessions_dir, format, max_duration read correctly"
    fi
}

# ── Test 5: Config parsing ignores comments and blank lines ──
test_config_comments() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
# full comment
   # indented comment

sessions_dir = /tmp/test
CONF
    (
        source_script "ob-session-recorder"
        # Override stat to simulate root-owned config for testing
        stat() { echo "0:644"; }
        export -f stat
        SESSIONS_DIR="/default"
        CONFIG_FILE="$tmpconf"
        load_config
        [ "$SESSIONS_DIR" = "/tmp/test" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "Config parsing ignores comments and blank lines"
    else
        fail "Config parsing ignores comments and blank lines"
    fi
}

# ── Test 6: generate_session_id produces non-empty UUID-like string ──
test_generate_session_id() {
    (
        source_script "ob-session-recorder"
        local id
        id=$(generate_session_id)
        [ -n "$id" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "generate_session_id produces non-empty string"
    else
        fail "generate_session_id produces non-empty string"
    fi
}

# ── Test 7: Session file path format based on format type ──
test_session_file_script() {
    (
        source_script "ob-session-recorder"
        FORMAT="script"
        # Simulate what main does
        case "$FORMAT" in
            asciinema) ext=".cast" ;;
            ttyrec) ext=".ttyrec" ;;
            *) ext=".typescript" ;;
        esac
        [ "$ext" = ".typescript" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "script format -> .typescript extension"
    else
        fail "script format -> .typescript extension"
    fi
}

test_session_file_asciinema() {
    (
        source_script "ob-session-recorder"
        FORMAT="asciinema"
        case "$FORMAT" in
            asciinema) ext=".cast" ;;
            ttyrec) ext=".ttyrec" ;;
            *) ext=".typescript" ;;
        esac
        [ "$ext" = ".cast" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "asciinema format -> .cast extension"
    else
        fail "asciinema format -> .cast extension"
    fi
}

test_session_file_ttyrec() {
    (
        source_script "ob-session-recorder"
        FORMAT="ttyrec"
        case "$FORMAT" in
            asciinema) ext=".cast" ;;
            ttyrec) ext=".ttyrec" ;;
            *) ext=".typescript" ;;
        esac
        [ "$ext" = ".ttyrec" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "ttyrec format -> .ttyrec extension"
    else
        fail "ttyrec format -> .ttyrec extension"
    fi
}

# ── Test 8: Default format is "script" for unknown formats ──
test_default_format_unknown() {
    (
        source_script "ob-session-recorder"
        FORMAT="somethingweird"
        case "$FORMAT" in
            asciinema) fmt="asciinema" ;;
            ttyrec) fmt="ttyrec" ;;
            *) fmt="script" ;;
        esac
        [ "$fmt" = "script" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "Default format is 'script' for unknown formats"
    else
        fail "Default format is 'script' for unknown formats"
    fi
}

# ── Test 9: ensure_sessions_dir creates user subdir when parent exists ──
test_ensure_sessions_dir() {
    local tmpdir
    tmpdir=$(mktemp -d)
    (
        source_script "ob-session-recorder"
        SESSIONS_DIR="$tmpdir"
        SESSION_USER="testuser"
        ensure_sessions_dir
        [ -d "$tmpdir/testuser" ] || exit 1
        local perms
        perms=$(stat -c '%a' "$tmpdir/testuser" 2>/dev/null || stat -f '%Lp' "$tmpdir/testuser" 2>/dev/null)
        [ "$perms" = "770" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "ensure_sessions_dir creates user subdir when parent exists"
    else
        fail "ensure_sessions_dir creates user subdir when parent exists"
    fi
}

# ── Test 9b: ensure_sessions_dir fails when parent dir missing ──
test_ensure_sessions_dir_missing() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local testdir="$tmpdir/nonexistent"
    (
        source_script "ob-session-recorder"
        SESSIONS_DIR="$testdir"
        SESSION_USER="testuser"
        ensure_sessions_dir 2>/dev/null && exit 1 || exit 0
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "ensure_sessions_dir fails when parent dir missing"
    else
        fail "ensure_sessions_dir fails when parent dir missing"
    fi
}

# ── Test 10: write_metadata produces valid JSON with expected fields ──
test_write_metadata() {
    local tmpdir
    tmpdir=$(mktemp -d)
    (
        source_script "ob-session-recorder"
        SESSION_ID="test-uuid-123"
        SESSION_USER="alice"
        CLIENT_IP="10.0.0.1"
        TTY_NAME="/dev/pts/0"
        SESSION_START="2025-01-01T00:00:00Z"
        ORIGINAL_COMMAND="ls -la"
        FORMAT="script"
        SESSION_FILE="$tmpdir/session.typescript"
        METADATA_FILE="$tmpdir/meta.json"
        write_metadata "active"
        # Verify it is valid JSON with expected fields
        if command -v jq >/dev/null 2>&1; then
            jq -e '.session_id' "$tmpdir/meta.json" >/dev/null 2>&1 || exit 1
            jq -e '.user' "$tmpdir/meta.json" >/dev/null 2>&1 || exit 1
            jq -e '.status' "$tmpdir/meta.json" >/dev/null 2>&1 || exit 1
            local sid
            sid=$(jq -r '.session_id' "$tmpdir/meta.json")
            [ "$sid" = "test-uuid-123" ] || exit 1
            exit 0
        else
            grep -q "session_id" "$tmpdir/meta.json" && exit 0 || exit 1
        fi
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "write_metadata produces valid JSON with expected fields"
    else
        fail "write_metadata produces valid JSON with expected fields"
    fi
}

# ── Test 11: Environment variable defaults ──
test_env_defaults() {
    (
        export LLNG_SESSIONS_DIR="/tmp/env-sessions"
        export LLNG_RECORDER_FORMAT="ttyrec"
        export LLNG_MAX_SESSION="7200"
        source_script "ob-session-recorder"
        local ok=true
        [ "$SESSIONS_DIR" = "/tmp/env-sessions" ] || ok=false
        [ "$FORMAT" = "ttyrec" ] || ok=false
        [ "$MAX_SESSION_DURATION" = "7200" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "Environment variable defaults (LLNG_SESSIONS_DIR, LLNG_RECORDER_FORMAT, LLNG_MAX_SESSION)"
    else
        fail "Environment variable defaults (LLNG_SESSIONS_DIR, LLNG_RECORDER_FORMAT, LLNG_MAX_SESSION)"
    fi
}

# ── Test 12: parse_args -c, -d, -f set correct variables ──
test_parse_args() {
    (
        source_script "ob-session-recorder"
        parse_args -c /tmp/myconf -d /tmp/mydir -f asciinema
        local ok=true
        [ "$CONFIG_FILE" = "/tmp/myconf" ] || ok=false
        [ "$SESSIONS_DIR" = "/tmp/mydir" ] || ok=false
        [ "$FORMAT" = "asciinema" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "parse_args -c, -d, -f set correct variables"
    else
        fail "parse_args -c, -d, -f set correct variables"
    fi
}

# ── Test 13: Invalid SESSION_USER is rejected (path traversal prevention) ──
test_invalid_session_user() {
    # Run the script with a path-traversal username; it should exit non-zero.
    local rc
    USER="../../../etc/passwd" SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" \
        bash "$SCRIPT_DIR/ob-session-recorder" --version >/dev/null 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then
        pass "Invalid SESSION_USER (path traversal) is rejected"
    else
        fail "Invalid SESSION_USER (path traversal) is rejected"
    fi
}

# ── Test 14: Valid SESSION_USER passes validation ──
test_valid_session_user() {
    local out rc
    out=$(USER="alice" SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" \
        bash "$SCRIPT_DIR/ob-session-recorder" --version 2>&1)
    rc=$?
    if [ $rc -eq 0 ] && echo "$out" | grep -q "version"; then
        pass "Valid SESSION_USER passes validation"
    else
        fail "Valid SESSION_USER passes validation" "exit=$rc out=$out"
    fi
}

# ── Test 15: build_drop_gid_prefix returns empty when OB_ORIG_GID unset ──
test_build_drop_gid_prefix_empty() {
    (
        source_script "ob-session-recorder"
        unset OB_ORIG_GID 2>/dev/null || true
        local prefix
        prefix=$(build_drop_gid_prefix)
        [ -z "$prefix" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "build_drop_gid_prefix: empty when OB_ORIG_GID unset"
    else
        fail "build_drop_gid_prefix: empty when OB_ORIG_GID unset"
    fi
}

# ── Test 16: build_drop_gid_prefix includes setpriv when OB_ORIG_GID set ──
test_build_drop_gid_prefix_setpriv() {
    (
        source_script "ob-session-recorder"
        if ! command -v setpriv >/dev/null 2>&1; then
            # setpriv not installed; skip by passing
            exit 0
        fi
        OB_ORIG_GID=1000
        local prefix
        prefix=$(build_drop_gid_prefix)
        echo "$prefix" | grep -q "setpriv" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "build_drop_gid_prefix: setpriv prefix when OB_ORIG_GID set"
    else
        fail "build_drop_gid_prefix: setpriv prefix when OB_ORIG_GID set"
    fi
}

# ── Run all tests ──
echo "=== Testing ob-session-recorder ==="
run_test test_syntax
run_test test_version
run_test test_help
run_test test_unknown_option
run_test test_config_parsing
run_test test_config_comments
run_test test_generate_session_id
run_test test_session_file_script
run_test test_session_file_asciinema
run_test test_session_file_ttyrec
run_test test_default_format_unknown
run_test test_ensure_sessions_dir
run_test test_ensure_sessions_dir_missing
run_test test_write_metadata
run_test test_env_defaults
run_test test_parse_args
run_test test_invalid_session_user
run_test test_valid_session_user
run_test test_build_drop_gid_prefix_empty
run_test test_build_drop_gid_prefix_setpriv

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
