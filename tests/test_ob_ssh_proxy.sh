#!/bin/bash
#
# Comprehensive test suite for ob-ssh-proxy (llng-ssh-proxy)
#
# This test suite validates the core functionality of the SSH proxy script
# by sourcing its functions and testing them in isolation.
#

set -u

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/scripts/ob-ssh-proxy"

# Temp directory for test files
TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

# Test result tracking
test_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗${NC} $1"
    if [ -n "${2:-}" ]; then
        echo -e "  ${YELLOW}Details:${NC} $2"
    fi
    ((TESTS_FAILED++))
}

# Test 1: Syntax check
test_syntax_check() {
    if bash -n "$PROXY_SCRIPT" 2>/dev/null; then
        test_pass "Syntax check: bash -n passes"
    else
        test_fail "Syntax check: bash -n failed"
    fi
}

# Test 2: --version outputs version string
test_version_flag() {
    local output
    output=$("$PROXY_SCRIPT" --version 2>&1)
    if [[ "$output" =~ version.*[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        test_pass "--version outputs version string"
    else
        test_fail "--version does not output version string" "Got: $output"
    fi
}

# Test 3: --help exits 0 and contains Usage
test_help_flag() {
    local output
    local exit_code
    output=$("$PROXY_SCRIPT" --help 2>&1)
    exit_code=$?
    if [ $exit_code -eq 0 ] && [[ "$output" =~ Usage ]]; then
        test_pass "--help exits 0 and contains 'Usage'"
    else
        test_fail "--help check failed" "Exit code: $exit_code, Contains Usage: $([[ $output =~ Usage ]] && echo yes || echo no)"
    fi
}

# Test 4: Unknown option exits non-zero
test_unknown_option() {
    local output
    local exit_code
    output=$("$PROXY_SCRIPT" --bogus 2>&1)
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        test_pass "Unknown option --bogus exits non-zero"
    else
        test_fail "Unknown option --bogus should exit non-zero" "Exit code: $exit_code"
    fi
}

# Test 5: Config file permission check - rejects group-writable
test_config_permissions_group_writable() {
    local test_script="$TEST_TMPDIR/test_permissions.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"
test_config="$2"

# Source the script without running main
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

# Override stat to return group-writable permissions
stat() {
    if [[ "$*" =~ test_config ]]; then
        echo "1000:664"
    else
        command stat "$@"
    fi
}
export -f stat

CONFIG_FILE="$test_config"
load_config 2>&1
TESTSCRIPT

    chmod +x "$test_script"
    local test_config="$TEST_TMPDIR/test_config"
    echo "PORTAL_URL=https://test.example.com" > "$test_config"

    local output
    output=$("$test_script" "$PROXY_SCRIPT" "$test_config" 2>&1)

    if [[ "$output" =~ "Insecure config file" ]]; then
        test_pass "Config file permission check: rejects non-root ownership"
    else
        test_fail "Config file permission check: should reject non-root ownership" "Output: $output"
    fi
}

# Test 6: Safe config parsing (no source injection)
test_safe_config_parsing() {
    local test_script="$TEST_TMPDIR/test_parsing.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"
test_config="$2"

# Source the script without running main
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

# Override stat to return safe permissions
stat() {
    if [[ "$*" =~ test_config ]]; then
        echo "0:644"
    else
        command stat "$@"
    fi
}
export -f stat

CONFIG_FILE="$test_config"
load_config 2>/dev/null

# Output variables for verification
echo "PORTAL_URL=$PORTAL_URL"
echo "SERVER_TOKEN_FILE=$SERVER_TOKEN_FILE"
echo "SERVER_GROUP=$SERVER_GROUP"
echo "TIMEOUT=$TIMEOUT"
echo "VERIFY_SSL=$VERIFY_SSL"
echo "SSH_OPTIONS_COUNT=${#SSH_OPTIONS_ARRAY[@]}"
echo "MALICIOUS=${MALICIOUS:-NOTSET}"
TESTSCRIPT

    chmod +x "$test_script"
    local test_config="$TEST_TMPDIR/test_config_safe"
    cat > "$test_config" <<'EOF'
PORTAL_URL=https://test.example.com
SERVER_TOKEN_FILE=/tmp/test_token
SERVER_GROUP=mygroup
# This is a comment
TIMEOUT=15
VERIFY_SSL=false
SSH_OPTIONS=-o ConnectTimeout=5 -o StrictHostKeyChecking=no
MALICIOUS=$(echo pwned)
EOF

    local output
    output=$("$test_script" "$PROXY_SCRIPT" "$test_config" 2>&1)

    local all_good=true
    local details=""

    if ! echo "$output" | grep -q "PORTAL_URL=https://test.example.com"; then
        all_good=false
        details+="PORTAL_URL wrong; "
    fi
    if ! echo "$output" | grep -q "SERVER_TOKEN_FILE=/tmp/test_token"; then
        all_good=false
        details+="SERVER_TOKEN_FILE wrong; "
    fi
    if ! echo "$output" | grep -q "SERVER_GROUP=mygroup"; then
        all_good=false
        details+="SERVER_GROUP wrong; "
    fi
    if ! echo "$output" | grep -q "TIMEOUT=15"; then
        all_good=false
        details+="TIMEOUT wrong; "
    fi
    if ! echo "$output" | grep -q "VERIFY_SSL=false"; then
        all_good=false
        details+="VERIFY_SSL wrong; "
    fi
    if ! echo "$output" | grep -q "MALICIOUS=NOTSET"; then
        all_good=false
        details+="MALICIOUS variable set (injection!); "
    fi

    if $all_good; then
        test_pass "Safe config parsing: prevents injection and parses correctly"
    else
        test_fail "Safe config parsing: failed" "$details"
    fi
}

# Test 7: Config parsing handles quotes
test_config_quotes() {
    local test_script="$TEST_TMPDIR/test_quotes.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"
test_config="$2"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

stat() { if [[ "$*" =~ test_config ]]; then echo "0:644"; else command stat "$@"; fi; }
export -f stat

CONFIG_FILE="$test_config"
load_config 2>/dev/null

echo "PORTAL_URL=$PORTAL_URL"
echo "SERVER_GROUP=$SERVER_GROUP"
TESTSCRIPT

    chmod +x "$test_script"
    local test_config="$TEST_TMPDIR/test_config_quotes"
    cat > "$test_config" <<'EOF'
PORTAL_URL="https://quoted.example.com"
SERVER_GROUP='single-quoted'
EOF

    local output
    output=$("$test_script" "$PROXY_SCRIPT" "$test_config" 2>&1)

    if echo "$output" | grep -q "PORTAL_URL=https://quoted.example.com" && \
       echo "$output" | grep -q "SERVER_GROUP=single-quoted"; then
        test_pass "Config parsing handles quotes correctly"
    else
        test_fail "Config parsing handles quotes" "Output: $output"
    fi
}

# Test 8: Config parsing ignores comments and blank lines
test_config_comments() {
    local test_script="$TEST_TMPDIR/test_comments.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"
test_config="$2"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

stat() { if [[ "$*" =~ test_config ]]; then echo "0:644"; else command stat "$@"; fi; }
export -f stat

CONFIG_FILE="$test_config"
load_config 2>/dev/null

echo "PORTAL_URL=$PORTAL_URL"
echo "SERVER_GROUP=$SERVER_GROUP"
TESTSCRIPT

    chmod +x "$test_script"
    local test_config="$TEST_TMPDIR/test_config_comments"
    cat > "$test_config" <<'EOF'
# This is a comment
PORTAL_URL=https://example.com

# Another comment
SERVER_GROUP=testgroup  # inline comment

EOF

    local output
    output=$("$test_script" "$PROXY_SCRIPT" "$test_config" 2>&1)

    if echo "$output" | grep -q "PORTAL_URL=https://example.com" && \
       echo "$output" | grep -q "SERVER_GROUP=testgroup"; then
        test_pass "Config parsing ignores comments and blank lines"
    else
        test_fail "Config parsing with comments" "Output: $output"
    fi
}

# Test 9: build_curl_opts without SSL skip
test_curl_opts_ssl_verify() {
    local test_script="$TEST_TMPDIR/test_curl_ssl.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

VERIFY_SSL=true
TIMEOUT=10

build_curl_opts

# Check for -k flag
has_k=false
for opt in "${CURL_OPTS[@]}"; do
    if [ "$opt" = "-k" ]; then
        has_k=true
    fi
done

if $has_k; then
    echo "HAS_K"
else
    echo "NO_K"
fi
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1)

    if [[ "$output" == "NO_K" ]]; then
        test_pass "build_curl_opts without SSL skip: no -k flag"
    else
        test_fail "build_curl_opts without SSL skip: should not have -k flag"
    fi
}

# Test 10: build_curl_opts with SSL skip
test_curl_opts_ssl_skip() {
    local test_script="$TEST_TMPDIR/test_curl_nossl.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

VERIFY_SSL=false
TIMEOUT=10

build_curl_opts

has_k=false
for opt in "${CURL_OPTS[@]}"; do
    if [ "$opt" = "-k" ]; then
        has_k=true
    fi
done

if $has_k; then
    echo "HAS_K"
else
    echo "NO_K"
fi
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1)

    if [[ "$output" == "HAS_K" ]]; then
        test_pass "build_curl_opts with SSL skip: has -k flag"
    else
        test_fail "build_curl_opts with SSL skip: should have -k flag"
    fi
}

# Test 11: get_server_token reads JSON format
test_get_token_json() {
    local test_script="$TEST_TMPDIR/test_token_json.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"
token_file="$2"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

SERVER_TOKEN_FILE="$token_file"
get_server_token 2>/dev/null
TESTSCRIPT

    chmod +x "$test_script"
    local token_file="$TEST_TMPDIR/token_json"
    echo '{"access_token": "mytoken123", "refresh_token": "rt"}' > "$token_file"

    local output
    output=$("$test_script" "$PROXY_SCRIPT" "$token_file" 2>&1)

    if [[ "$output" == "mytoken123" ]]; then
        test_pass "get_server_token reads JSON format"
    else
        test_fail "get_server_token reads JSON format" "Got: $output"
    fi
}

# Test 12: get_server_token reads plain text
test_get_token_plaintext() {
    local test_script="$TEST_TMPDIR/test_token_plain.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"
token_file="$2"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

SERVER_TOKEN_FILE="$token_file"
get_server_token 2>/dev/null
TESTSCRIPT

    chmod +x "$test_script"
    local token_file="$TEST_TMPDIR/token_plain"
    echo "plaintoken456" > "$token_file"

    local output
    output=$("$test_script" "$PROXY_SCRIPT" "$token_file" 2>&1)

    if [[ "$output" == "plaintoken456" ]]; then
        test_pass "get_server_token reads plain text format"
    else
        test_fail "get_server_token reads plain text format" "Got: $output"
    fi
}

# Test 13: get_server_token rejects missing file
test_get_token_missing() {
    local test_script="$TEST_TMPDIR/test_token_missing.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

SERVER_TOKEN_FILE="/nonexistent/path/to/token"
get_server_token 2>&1
exit $?
TESTSCRIPT

    chmod +x "$test_script"
    local output
    local exit_code=0
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1) || exit_code=$?

    if [ $exit_code -ne 0 ]; then
        test_pass "get_server_token rejects missing file"
    else
        test_fail "get_server_token should reject missing file" "Exit code: $exit_code"
    fi
}

# Test 14: parse_args sets TARGET_HOST and TARGET_PORT
test_parse_args_host_port() {
    local test_script="$TEST_TMPDIR/test_parse_args.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

parse_args "backend.example.com" "2222"

echo "TARGET_HOST=$TARGET_HOST"
echo "TARGET_PORT=$TARGET_PORT"
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1)

    if echo "$output" | grep -q "TARGET_HOST=backend.example.com" && \
       echo "$output" | grep -q "TARGET_PORT=2222"; then
        test_pass "parse_args sets TARGET_HOST and TARGET_PORT"
    else
        test_fail "parse_args sets TARGET_HOST and TARGET_PORT" "Output: $output"
    fi
}

# Test 15: parse_args default port is 22
test_parse_args_default_port() {
    local test_script="$TEST_TMPDIR/test_parse_default.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

parse_args "backend.example.com"

echo "TARGET_HOST=$TARGET_HOST"
echo "TARGET_PORT=$TARGET_PORT"
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1)

    if echo "$output" | grep -q "TARGET_HOST=backend.example.com" && \
       echo "$output" | grep -q "TARGET_PORT=22"; then
        test_pass "parse_args default port is 22"
    else
        test_fail "parse_args default port is 22" "Output: $output"
    fi
}

# Test 16: parse_args -c sets CONFIG_FILE
test_parse_args_config_file() {
    local test_script="$TEST_TMPDIR/test_parse_config.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

parse_args "-c" "/custom/config.conf"

echo "CONFIG_FILE=$CONFIG_FILE"
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1)

    if echo "$output" | grep -q "CONFIG_FILE=/custom/config.conf"; then
        test_pass "parse_args -c sets CONFIG_FILE"
    else
        test_fail "parse_args -c sets CONFIG_FILE" "Output: $output"
    fi
}

# Test 17: parse_args -d enables DEBUG
test_parse_args_debug() {
    local test_script="$TEST_TMPDIR/test_parse_debug.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

parse_args "-d"

echo "DEBUG=$DEBUG"
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1)

    if echo "$output" | grep -q "DEBUG=true"; then
        test_pass "parse_args -d enables DEBUG"
    else
        test_fail "parse_args -d enables DEBUG" "Output: $output"
    fi
}

# Test 18: Missing PORTAL_URL fails
test_missing_portal_url() {
    local test_script="$TEST_TMPDIR/test_missing_portal.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

# Set empty PORTAL_URL (as would happen with empty config)
PORTAL_URL=""
CONFIG_FILE="/tmp/empty_config"

# Validate required configuration (this should fail)
if [ -z "$PORTAL_URL" ]; then
    error "PORTAL_URL not configured. Set it in $CONFIG_FILE"
    exit 1
fi
TESTSCRIPT

    chmod +x "$test_script"

    local output
    local exit_code=0
    output=$("$test_script" "$PROXY_SCRIPT" 2>&1) || exit_code=$?

    if [ $exit_code -ne 0 ] && [[ "$output" =~ "PORTAL_URL not configured" ]]; then
        test_pass "Missing PORTAL_URL fails with error"
    else
        test_fail "Missing PORTAL_URL should fail" "Exit code: $exit_code, Output: $output"
    fi
}

# Main test execution
echo "=========================================="
echo "Testing ob-ssh-proxy (llng-ssh-proxy)"
echo "=========================================="
echo ""

test_syntax_check
test_version_flag
test_help_flag
test_unknown_option
test_config_permissions_group_writable
test_safe_config_parsing
test_config_quotes
test_config_comments
test_curl_opts_ssl_verify
test_curl_opts_ssl_skip
test_get_token_json
test_get_token_plaintext
test_get_token_missing
test_parse_args_host_port
test_parse_args_default_port
test_parse_args_config_file
test_parse_args_debug
test_missing_portal_url

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo "Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
