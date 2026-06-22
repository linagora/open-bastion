#!/bin/bash
#
# Test suite for ob-sftp (llng bastion SFTP connector)
#
# Tests syntax, CLI flags, and offline function logic by sourcing
# ob-cert-lib.sh (shared library) and ob-sftp itself.
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
SFTP_SCRIPT="$SCRIPT_DIR/scripts/ob-sftp"
LIB="$SCRIPT_DIR/scripts/ob-cert-lib.sh"
export OB_CERT_LIB="$LIB"

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
    if bash -n "$SFTP_SCRIPT" 2>/dev/null; then
        test_pass "Syntax check: bash -n passes"
    else
        test_fail "Syntax check: bash -n failed"
    fi
}

# Test 2: --version outputs version string
test_version_flag() {
    local output
    output=$("$SFTP_SCRIPT" --version 2>&1)
    if [[ "$output" =~ version.*[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        test_pass "--version outputs version string"
    else
        test_fail "--version does not output version string" "Got: $output"
    fi
}

# Test 3: --help exits 0 and mentions the destination spec
test_help_flag() {
    local output
    local exit_code
    output=$("$SFTP_SCRIPT" --help 2>&1)
    exit_code=$?
    if [ $exit_code -eq 0 ] && [[ "$output" =~ backend ]] && [[ "$output" =~ Usage ]]; then
        test_pass "--help exits 0 and documents usage"
    else
        test_fail "--help check failed" "Exit code: $exit_code, output: $output"
    fi
}

# Test 4: No args exits non-zero.
# ob-sftp calls load_config+validate_config before the arg count check, and
# load_config requires the config file to be root-owned; running as non-root
# with the default config path (/etc/open-bastion/ssh-proxy.conf) will fail
# the ownership check before we ever reach the arg count. Therefore we assert
# only that the exit code is non-zero — regardless of whether the error is
# "need a destination" or "config not found".
test_no_args() {
    local exit_code=0
    "$SFTP_SCRIPT" 2>/dev/null || exit_code=$?
    if [ "$exit_code" -ne 0 ]; then
        test_pass "ob-sftp with no args exits non-zero"
    else
        test_fail "ob-sftp with no args should exit non-zero" "Exit code: $exit_code"
    fi
}

# Test 5: split_dest_spec parses the destination forms correctly.
# split_dest_spec is defined inside ob-sftp (not the shared lib). Source ob-sftp
# via the sed-strip approach (removes 'set -euo pipefail' and the 'main "$@"'
# call). OB_CERT_LIB is exported above so the '. "$_OB_LIB"' line resolves.
test_split_dest_spec() {
    local test_script="$TEST_TMPDIR/test_split_dest.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

ok=true

# user@host -> REMOTE_USER=dwho, REMOTE_HOST=b1
split_dest_spec "dwho@b1"
if [ "$REMOTE_USER" != "dwho" ] || [ "$REMOTE_HOST" != "b1" ]; then
    echo "FAIL_user_at_host: user=[$REMOTE_USER] host=[$REMOTE_HOST]"
    ok=false
fi

# user@host:/path -> REMOTE_USER=dwho, REMOTE_HOST=b1 (path stripped)
split_dest_spec "dwho@b1:/var/log"
if [ "$REMOTE_USER" != "dwho" ] || [ "$REMOTE_HOST" != "b1" ]; then
    echo "FAIL_user_at_host_path: user=[$REMOTE_USER] host=[$REMOTE_HOST]"
    ok=false
fi

# host only -> REMOTE_USER="", REMOTE_HOST=b1
split_dest_spec "b1"
if [ -n "$REMOTE_USER" ] || [ "$REMOTE_HOST" != "b1" ]; then
    echo "FAIL_host_only: user=[$REMOTE_USER] host=[$REMOTE_HOST]"
    ok=false
fi

# sftp:// URI form -> scheme stripped, host isolated
split_dest_spec "sftp://dwho@b1:2222/var/log"
if [ "$REMOTE_USER" != "dwho" ] || [ "$REMOTE_HOST" != "b1" ]; then
    echo "FAIL_uri: user=[$REMOTE_USER] host=[$REMOTE_HOST]"
    ok=false
fi

if $ok; then
    echo "SPLIT_DEST_SPEC_OK"
fi
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$SFTP_SCRIPT" 2>&1)

    if echo "$output" | grep -q "SPLIT_DEST_SPEC_OK"; then
        test_pass "split_dest_spec: all destination forms parsed correctly"
    else
        test_fail "split_dest_spec parsing" "Output: $output"
    fi
}

# parse_args: own options are consumed, everything else (incl. sftp's own -c
# CIPHER) reaches SFTP_ARGS. Regression: a short -c used to be ob-sftp's
# --config and swallowed sftp's cipher option so it never reached sftp.
test_parse_args_passthrough() {
    local test_script="$TEST_TMPDIR/test_sftp_passthrough.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

check() { # argv... ; last arg is expected "CONFIG|SFTP_ARGS*"
    local expected="${!#}"
    local -a argv=("${@:1:$#-1}")
    CONFIG_FILE="DEFAULT"
    parse_args "${argv[@]}"
    local got="${CONFIG_FILE}|${SFTP_ARGS[*]}"
    [ "$got" = "$expected" ] || { echo "MISMATCH for [${argv[*]}]: got [$got] want [$expected]"; exit 1; }
}
#      argv...                                  expected CONFIG|SFTP_ARGS
check  dwho@h                                   "DEFAULT|dwho@h"
check  -c aes256-gcm@openssh.com dwho@h         "DEFAULT|-c aes256-gcm@openssh.com dwho@h"
check  --config /x dwho@h                       "/x|dwho@h"
check  -P 2222 dwho@h:/var/log                  "DEFAULT|-P 2222 dwho@h:/var/log"
check  -b /tmp/s dwho@h                         "DEFAULT|-b /tmp/s dwho@h"
echo "SFTP_PASSTHROUGH_OK"
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$SFTP_SCRIPT" 2>&1)

    if echo "$output" | grep -q "SFTP_PASSTHROUGH_OK"; then
        test_pass "parse_args: sftp options pass through; -c CIPHER not shadowed"
    else
        test_fail "sftp option passthrough matrix" "Output: $output"
    fi
}

# Main test execution
echo "=========================================="
echo "Testing ob-sftp (llng bastion SFTP connector)"
echo "=========================================="
echo ""

test_syntax_check
test_version_flag
test_help_flag
test_no_args
test_split_dest_spec
test_parse_args_passthrough

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
