#!/bin/bash
#
# test_ob_enroll.sh - Unit tests for ob-enroll script
#
# Copyright (C) 2025 Linagora
# License: AGPL-3.0

set -euo pipefail

TESTS_RUN=0
TESTS_PASSED=0
SCRIPT_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/ob-enroll"
TEMP_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test result functions
pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "  ${GREEN}PASS${NC}: $1"
}

fail() {
    echo -e "  ${RED}FAIL${NC}: $1 - $2"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${BLUE}Test $TESTS_RUN:${NC} $1"
    shift
    if "$@"; then
        pass "$1"
    else
        fail "$1" "Test function returned non-zero"
    fi
}

# Setup and teardown
setup_temp_dir() {
    TEMP_DIR=$(mktemp -d)
}

cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

# Source the script functions without executing main
# We do this by reading the script and removing the final main call
source_script_functions() {
    # Read the script content
    local script_content
    script_content=$(cat "$SCRIPT_PATH")

    # Remove the final 'main "$@"' line and 'set -e'
    # We disable set -e so we can test error conditions
    script_content="${script_content%main \"\$@\"}"
    script_content="${script_content//set -e/# set -e disabled for testing}"

    # Source the modified script
    eval "$script_content"
}

# Test 1: Syntax check
test_syntax_check() {
    bash -n "$SCRIPT_PATH"
}

# Test 2: --version outputs version
test_version_flag() {
    local output
    output=$("$SCRIPT_PATH" --version 2>&1) || return 1
    echo "$output" | grep -q "version 1.0.0"
}

# Test 3: --help exits 0
test_help_flag() {
    "$SCRIPT_PATH" --help > /dev/null 2>&1
    return $?
}

# Test 4: Unknown option exits non-zero
test_unknown_option() {
    if "$SCRIPT_PATH" --bogus-option > /dev/null 2>&1; then
        return 1  # Should have failed
    fi
    return 0
}

# Test 5: Missing portal URL exits with error
test_missing_portal_url() {
    # Create a temp config with client_secret but no portal
    local config="$TEMP_DIR/test_config.conf"
    echo "client_secret = test_secret" > "$config"

    # Should fail because portal_url is missing
    if OB_CLIENT_SECRET=test "$SCRIPT_PATH" -C "$config" > /dev/null 2>&1; then
        return 1  # Should have failed
    fi
    return 0
}

# Test 6: Missing client_secret exits with error
test_missing_client_secret() {
    local config="$TEMP_DIR/test_config.conf"
    echo "portal_url = https://example.com" > "$config"

    # Should fail because client_secret is missing
    if "$SCRIPT_PATH" -C "$config" > /dev/null 2>&1; then
        return 1  # Should have failed
    fi
    return 0
}

# Test 7: Config file parsing (read_config function)
test_read_config_function() {
    source_script_functions

    local config="$TEMP_DIR/test_config.conf"
    cat > "$config" << 'EOF'
# Test config file
portal_url = https://test.example.com
client_id = test-client
client_secret = "secret123"
server_group = 'production'
# Comment line
  token_file  =  /tmp/token  # inline comment
EOF

    local val

    # Test reading portal_url
    val=$(read_config "portal_url" "$config")
    [ "$val" = "https://test.example.com" ] || return 1

    # Test reading client_id
    val=$(read_config "client_id" "$config")
    [ "$val" = "test-client" ] || return 1

    # Test reading value with quotes
    val=$(read_config "client_secret" "$config")
    [ "$val" = "secret123" ] || return 1

    # Test reading value with single quotes
    val=$(read_config "server_group" "$config")
    [ "$val" = "production" ] || return 1

    # Test reading value with spaces and inline comment
    val=$(read_config "token_file" "$config")
    [ "$val" = "/tmp/token" ] || return 1

    return 0
}

# Test 8: load_config reads config correctly
test_load_config_function() {
    source_script_functions

    local config="$TEMP_DIR/test_config.conf"
    cat > "$config" << 'EOF'
portal_url = https://auth.example.com
client_id = my-client
client_secret = my-secret
server_group = staging
token_file = /var/lib/token
EOF

    CONFIG_FILE="$config"
    load_config

    [ "$PORTAL_URL" = "https://auth.example.com" ] || return 1
    [ "$CLIENT_ID" = "my-client" ] || return 1
    [ "$CLIENT_SECRET" = "my-secret" ] || return 1
    [ "$SERVER_GROUP" = "staging" ] || return 1
    [ "$TOKEN_FILE" = "/var/lib/token" ] || return 1

    return 0
}

# Test 9: parse_args sets variables correctly
test_parse_args_function() {
    source_script_functions

    # Reset variables
    PORTAL_URL=""
    CLIENT_ID=""
    SERVER_GROUP=""
    TOKEN_FILE=""
    INSECURE=""
    QUIET=""

    parse_args -p https://example.com -c test-id -g mygroup -t /tmp/mytoken -k -q

    [ "$PORTAL_URL" = "https://example.com" ] || return 1
    [ "$CLIENT_ID" = "test-id" ] || return 1
    [ "$SERVER_GROUP" = "mygroup" ] || return 1
    [ "$TOKEN_FILE" = "/tmp/mytoken" ] || return 1
    [ "$INSECURE" = "1" ] || return 1
    [ "$QUIET" = "1" ] || return 1

    return 0
}

# Test 10: validate_config rejects missing portal
test_validate_config_missing_portal() {
    # Run in subshell because validate_config calls exit
    (
        source_script_functions

        PORTAL_URL=""
        CLIENT_SECRET="test"

        validate_config 2>/dev/null
    )

    # Should have exited with non-zero
    if [ $? -eq 0 ]; then
        return 1  # Should have failed
    fi
    return 0
}

# Test 11: validate_config sets defaults
test_validate_config_defaults() {
    source_script_functions

    PORTAL_URL="https://example.com"
    CLIENT_SECRET="test"
    CLIENT_ID=""
    SERVER_GROUP=""

    validate_config > /dev/null 2>&1

    [ "$CLIENT_ID" = "pam-access" ] || return 1
    [ "$SERVER_GROUP" = "default" ] || return 1

    return 0
}

# Test 12: validate_config strips trailing slash
test_validate_config_strips_slash() {
    source_script_functions

    PORTAL_URL="https://example.com/"
    CLIENT_SECRET="test"

    validate_config > /dev/null 2>&1

    [ "$PORTAL_URL" = "https://example.com" ] || return 1

    return 0
}

# Test 13: PKCE generation produces valid values
test_generate_pkce() {
    source_script_functions

    CODE_VERIFIER=""
    CODE_CHALLENGE=""
    CODE_CHALLENGE_METHOD=""

    generate_pkce

    # Code verifier should be 43+ characters (base64url of 32 bytes)
    [ ${#CODE_VERIFIER} -ge 43 ] || return 1

    # Code challenge should be non-empty
    [ -n "$CODE_CHALLENGE" ] || return 1

    # Method should be S256
    [ "$CODE_CHALLENGE_METHOD" = "S256" ] || return 1

    # Verify base64url encoding (no +, /, or =)
    echo "$CODE_VERIFIER" | grep -qE '^[A-Za-z0-9_-]+$' || return 1
    echo "$CODE_CHALLENGE" | grep -qE '^[A-Za-z0-9_-]+$' || return 1

    return 0
}

# Test 14: JWT generation produces valid JWT
test_generate_client_jwt() {
    source_script_functions

    local jwt
    jwt=$(generate_client_jwt "test-client" "test-secret" "https://example.com/token")

    # JWT should have 3 parts separated by dots
    local parts
    parts=$(echo "$jwt" | tr '.' '\n' | wc -l)
    [ "$parts" -eq 3 ] || return 1

    # Decode header (first part)
    local header
    header=$(echo "$jwt" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null)

    # Check that header contains alg and typ
    echo "$header" | jq -e '.alg == "HS256"' > /dev/null 2>&1 || return 1
    echo "$header" | jq -e '.typ == "JWT"' > /dev/null 2>&1 || return 1

    # Decode payload (second part) - add padding if needed
    local payload_b64
    payload_b64=$(echo "$jwt" | cut -d. -f2)
    # Add padding to make length multiple of 4
    while [ $((${#payload_b64} % 4)) -ne 0 ]; do
        payload_b64="${payload_b64}="
    done

    local payload
    payload=$(echo "$payload_b64" | tr '_-' '/+' | base64 -d 2>/dev/null)

    # Check payload contains required claims
    echo "$payload" | jq -e '.iss == "test-client"' > /dev/null 2>&1 || return 1
    echo "$payload" | jq -e '.sub == "test-client"' > /dev/null 2>&1 || return 1
    echo "$payload" | jq -e '.aud == "https://example.com/token"' > /dev/null 2>&1 || return 1
    echo "$payload" | jq -e '.exp' > /dev/null 2>&1 || return 1
    echo "$payload" | jq -e '.iat' > /dev/null 2>&1 || return 1
    echo "$payload" | jq -e '.jti' > /dev/null 2>&1 || return 1

    return 0
}

# Test 15: OB_CLIENT_SECRET env var has highest priority
test_env_secret_priority() {
    source_script_functions

    local config="$TEMP_DIR/test_config.conf"
    echo "client_secret = config_secret" > "$config"

    CONFIG_FILE="$config"
    load_config

    # Should be config_secret initially
    [ "$CLIENT_SECRET" = "config_secret" ] || return 1

    # Parse args with CLI secret
    parse_args -s cli_secret 2>/dev/null

    # Should be cli_secret now
    [ "$CLIENT_SECRET" = "cli_secret" ] || return 1

    # Now apply env secret (this happens in main after parse_args)
    OB_CLIENT_SECRET="env_secret"
    if [ -n "${OB_CLIENT_SECRET:-}" ]; then
        CLIENT_SECRET="$OB_CLIENT_SECRET"
    fi

    # Should be env_secret (highest priority)
    [ "$CLIENT_SECRET" = "env_secret" ] || return 1

    return 0
}

# Test 16: build_curl_opts without insecure
test_build_curl_opts_secure() {
    source_script_functions

    INSECURE=""
    CURL_OPTS=()

    build_curl_opts

    # Should contain -s and -f
    local opts_str="${CURL_OPTS[*]}"
    echo "$opts_str" | grep -q -- "-s" || return 1
    echo "$opts_str" | grep -q -- "-f" || return 1

    # Should NOT contain -k
    if echo "$opts_str" | grep -q -- "-k"; then
        return 1
    fi

    return 0
}

# Test 17: build_curl_opts with insecure
test_build_curl_opts_insecure() {
    source_script_functions

    INSECURE=1
    CURL_OPTS=()

    build_curl_opts

    # Should contain -s, -f, and -k
    local opts_str="${CURL_OPTS[*]}"
    echo "$opts_str" | grep -q -- "-s" || return 1
    echo "$opts_str" | grep -q -- "-f" || return 1
    echo "$opts_str" | grep -q -- "-k" || return 1

    return 0
}

# Test 18: Color disabled when not terminal
test_colors_disabled_non_tty() {
    # The script checks [ -t 1 ] which will be false in tests
    # So colors should be empty
    source_script_functions

    [ -z "$RED" ] || return 1
    [ -z "$GREEN" ] || return 1
    [ -z "$BLUE" ] || return 1
    [ -z "$NC" ] || return 1

    return 0
}

# Test 19: save_token creates valid JSON via jq
test_save_token_json() {
    source_script_functions

    local token_file="$TEMP_DIR/test_token.json"
    TOKEN_FILE="$token_file"
    ACCESS_TOKEN="test_access_token_12345"
    REFRESH_TOKEN="test_refresh_token_67890"
    EXPIRES_IN=3600

    save_token > /dev/null 2>&1

    # Check file exists
    [ -f "$token_file" ] || return 1

    # Verify JSON is valid
    jq empty "$token_file" 2>/dev/null || return 1

    # Verify fields
    local access
    access=$(jq -r '.access_token' "$token_file")
    [ "$access" = "test_access_token_12345" ] || return 1

    local refresh
    refresh=$(jq -r '.refresh_token' "$token_file")
    [ "$refresh" = "test_refresh_token_67890" ] || return 1

    # Verify expires_at is present and is a number
    local expires_at
    expires_at=$(jq -r '.expires_at' "$token_file")
    [ -n "$expires_at" ] || return 1
    [[ "$expires_at" =~ ^[0-9]+$ ]] || return 1

    # Verify enrolled_at is present and is a number
    local enrolled_at
    enrolled_at=$(jq -r '.enrolled_at' "$token_file")
    [ -n "$enrolled_at" ] || return 1
    [[ "$enrolled_at" =~ ^[0-9]+$ ]] || return 1

    return 0
}

# Test 20: Config file with 'portal' alias works
test_config_portal_alias() {
    source_script_functions

    local config="$TEMP_DIR/test_config.conf"
    cat > "$config" << 'EOF'
# Using 'portal' instead of 'portal_url'
portal = https://portal.example.com
client_secret = test
EOF

    CONFIG_FILE="$config"
    PORTAL_URL=""
    load_config

    [ "$PORTAL_URL" = "https://portal.example.com" ] || return 1

    return 0
}

# Test 21: Multiple values in config - last one wins
test_config_last_value_wins() {
    source_script_functions

    local config="$TEMP_DIR/test_config.conf"
    cat > "$config" << 'EOF'
client_id = first-value
client_id = second-value
client_id = final-value
EOF

    CONFIG_FILE="$config"
    CLIENT_ID=""
    load_config

    [ "$CLIENT_ID" = "final-value" ] || return 1

    return 0
}

# Test 22: Empty config file doesn't break load_config
test_empty_config() {
    source_script_functions

    local config="$TEMP_DIR/empty_config.conf"
    touch "$config"

    CONFIG_FILE="$config"
    PORTAL_URL="preserved"
    load_config

    # Should preserve existing values
    [ "$PORTAL_URL" = "preserved" ] || return 1

    return 0
}

# Test 23: Config with only comments
test_config_only_comments() {
    source_script_functions

    local config="$TEMP_DIR/comments_config.conf"
    cat > "$config" << 'EOF'
# This is a comment
# Another comment
  # Indented comment
EOF

    CONFIG_FILE="$config"
    PORTAL_URL="preserved"
    load_config

    [ "$PORTAL_URL" = "preserved" ] || return 1

    return 0
}

# Test 24: Parse args with long options
test_parse_args_long_options() {
    source_script_functions

    PORTAL_URL=""
    CLIENT_ID=""
    SERVER_GROUP=""
    TOKEN_FILE=""

    parse_args --portal https://long.example.com --client-id long-id --server-group longgroup --token-file /tmp/longtoken

    [ "$PORTAL_URL" = "https://long.example.com" ] || return 1
    [ "$CLIENT_ID" = "long-id" ] || return 1
    [ "$SERVER_GROUP" = "longgroup" ] || return 1
    [ "$TOKEN_FILE" = "/tmp/longtoken" ] || return 1

    return 0
}

# Test 25: JWT has proper expiration time
test_jwt_expiration() {
    source_script_functions

    local jwt
    jwt=$(generate_client_jwt "test-client" "test-secret" "https://example.com/token")

    # Decode payload
    local payload_b64
    payload_b64=$(echo "$jwt" | cut -d. -f2)
    while [ $((${#payload_b64} % 4)) -ne 0 ]; do
        payload_b64="${payload_b64}="
    done

    local payload
    payload=$(echo "$payload_b64" | tr '_-' '/+' | base64 -d 2>/dev/null)

    # Get exp and iat
    local exp iat
    exp=$(echo "$payload" | jq -r '.exp')
    iat=$(echo "$payload" | jq -r '.iat')

    # exp should be iat + 300 (5 minutes)
    local expected_exp=$((iat + 300))
    [ "$exp" -eq "$expected_exp" ] || return 1

    return 0
}

# Run all tests
main() {
    echo "================================"
    echo "ob-enroll Test Suite"
    echo "================================"

    setup_temp_dir

    run_test "Syntax check" test_syntax_check
    run_test "--version outputs version" test_version_flag
    run_test "--help exits 0" test_help_flag
    run_test "Unknown option exits non-zero" test_unknown_option
    run_test "Missing portal URL exits with error" test_missing_portal_url
    run_test "Missing client_secret exits with error" test_missing_client_secret
    run_test "Config file parsing (read_config function)" test_read_config_function
    run_test "load_config reads config correctly" test_load_config_function
    run_test "parse_args sets variables correctly" test_parse_args_function
    run_test "validate_config rejects missing portal" test_validate_config_missing_portal
    run_test "validate_config sets defaults" test_validate_config_defaults
    run_test "validate_config strips trailing slash" test_validate_config_strips_slash
    run_test "PKCE generation produces valid values" test_generate_pkce
    run_test "JWT generation produces valid JWT" test_generate_client_jwt
    run_test "OB_CLIENT_SECRET env var has highest priority" test_env_secret_priority
    run_test "build_curl_opts without insecure" test_build_curl_opts_secure
    run_test "build_curl_opts with insecure" test_build_curl_opts_insecure
    run_test "Color disabled when not terminal" test_colors_disabled_non_tty
    run_test "save_token creates valid JSON via jq" test_save_token_json
    run_test "Config file with 'portal' alias works" test_config_portal_alias
    run_test "Multiple values in config - last one wins" test_config_last_value_wins
    run_test "Empty config file doesn't break load_config" test_empty_config
    run_test "Config with only comments" test_config_only_comments
    run_test "Parse args with long options" test_parse_args_long_options
    run_test "JWT has proper expiration time" test_jwt_expiration

    echo ""
    echo "================================"
    echo "Test Results"
    echo "================================"
    echo "Total tests:  $TESTS_RUN"
    echo "Passed:       $TESTS_PASSED"
    echo "Failed:       $((TESTS_RUN - TESTS_PASSED))"
    echo ""

    if [ $TESTS_PASSED -eq $TESTS_RUN ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        exit 1
    fi
}

main "$@"
