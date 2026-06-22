#!/bin/bash
#
# Test suite for ob-scp (llng bastion SCP connector)
#
# Tests syntax, CLI flags, and offline function logic by sourcing
# ob-cert-lib.sh (shared library) and ob-scp itself.
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
SCP_SCRIPT="$SCRIPT_DIR/scripts/ob-scp"
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
    if bash -n "$SCP_SCRIPT" 2>/dev/null; then
        test_pass "Syntax check: bash -n passes"
    else
        test_fail "Syntax check: bash -n failed"
    fi
}

# Test 2: --version outputs version string
test_version_flag() {
    local output
    output=$("$SCP_SCRIPT" --version 2>&1)
    if [[ "$output" =~ version.*[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        test_pass "--version outputs version string"
    else
        test_fail "--version does not output version string" "Got: $output"
    fi
}

# Test 3: --help exits 0 and mentions SOURCE and DEST
test_help_flag() {
    local output
    local exit_code
    output=$("$SCP_SCRIPT" --help 2>&1)
    exit_code=$?
    if [ $exit_code -eq 0 ] && [[ "$output" =~ SOURCE ]] && [[ "$output" =~ DEST ]]; then
        test_pass "--help exits 0 and mentions SOURCE and DEST"
    else
        test_fail "--help check failed" "Exit code: $exit_code, output: $output"
    fi
}

# Test 4: Too few args (only one) exits non-zero.
# ob-scp calls load_config+validate_config before the arg count check, and
# load_config requires the config file to be root-owned; running as non-root
# with the default config path (/etc/open-bastion/ssh-proxy.conf) will fail
# the ownership check before we ever reach the arg count. Therefore we test
# with a single positional arg and assert only that the exit code is non-zero
# — regardless of whether the error is "not enough args" or "config not found".
test_too_few_args() {
    local exit_code=0
    "$SCP_SCRIPT" onlyonearg 2>/dev/null || exit_code=$?
    if [ "$exit_code" -ne 0 ]; then
        test_pass "ob-scp with only one arg exits non-zero"
    else
        test_fail "ob-scp with only one arg should exit non-zero" "Exit code: $exit_code"
    fi
}

# Test 5: is_remote_spec classification.
# is_remote_spec is defined inside ob-scp (not the shared lib). Source ob-scp
# via the sed-strip approach (removes 'set -euo pipefail' and the 'main "$@"'
# call). OB_CERT_LIB is exported above so the '. "$_OB_LIB"' line in ob-scp
# resolves correctly.
test_is_remote_spec() {
    local test_script="$TEST_TMPDIR/test_is_remote.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

ok=true

# These must be classified as remote
for remote in "host:/path" "user@host:/path" "h:rel"; do
    if ! is_remote_spec "$remote"; then
        echo "SHOULD_BE_REMOTE:$remote"
        ok=false
    fi
done

# These must be classified as local
for local_spec in "./local:x" "/abs/path" "plainfile"; do
    if is_remote_spec "$local_spec"; then
        echo "SHOULD_BE_LOCAL:$local_spec"
        ok=false
    fi
done

if $ok; then
    echo "IS_REMOTE_SPEC_OK"
fi
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$SCP_SCRIPT" 2>&1)

    if echo "$output" | grep -q "IS_REMOTE_SPEC_OK"; then
        test_pass "is_remote_spec: remote and local specs classified correctly"
    else
        test_fail "is_remote_spec classification" "Output: $output"
    fi
}

# Test 6: split_remote_spec parses user@host:path and host:path correctly.
test_split_remote_spec() {
    local test_script="$TEST_TMPDIR/test_split_remote.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

ok=true

# user@host:/path -> REMOTE_USER=dwho, REMOTE_HOST=b1
split_remote_spec "dwho@b1:/p"
if [ "$REMOTE_USER" != "dwho" ] || [ "$REMOTE_HOST" != "b1" ]; then
    echo "FAIL_user_at_host: user=[$REMOTE_USER] host=[$REMOTE_HOST]"
    ok=false
fi

# host:/path (no user) -> REMOTE_USER="", REMOTE_HOST=b1
split_remote_spec "b1:/p"
if [ -n "$REMOTE_USER" ] || [ "$REMOTE_HOST" != "b1" ]; then
    echo "FAIL_host_only: user=[$REMOTE_USER] host=[$REMOTE_HOST]"
    ok=false
fi

if $ok; then
    echo "SPLIT_REMOTE_SPEC_OK"
fi
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$SCP_SCRIPT" 2>&1)

    if echo "$output" | grep -q "SPLIT_REMOTE_SPEC_OK"; then
        test_pass "split_remote_spec: user@host and host-only parsed correctly"
    else
        test_fail "split_remote_spec parsing" "Output: $output"
    fi
}

# parse_args: own options are consumed, everything else (incl. scp's own -c
# CIPHER) reaches SCP_ARGS. Regression: a short -c used to be ob-scp's --config
# and swallowed scp's cipher option so it never reached scp.
test_parse_args_passthrough() {
    local test_script="$TEST_TMPDIR/test_scp_passthrough.sh"
    cat > "$test_script" <<'TESTSCRIPT'
#!/bin/bash
set -u
source_file="$1"

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$source_file")"

check() { # argv... ; last arg is expected "CONFIG|SCP_ARGS*"
    local expected="${!#}"
    local -a argv=("${@:1:$#-1}")
    CONFIG_FILE="DEFAULT"
    parse_args "${argv[@]}"
    local got="${CONFIG_FILE}|${SCP_ARGS[*]}"
    [ "$got" = "$expected" ] || { echo "MISMATCH for [${argv[*]}]: got [$got] want [$expected]"; exit 1; }
}
#      argv...                                  expected CONFIG|SCP_ARGS
check  ./f h:/p                                 "DEFAULT|./f h:/p"
check  -c aes256-gcm@openssh.com ./f h:/p       "DEFAULT|-c aes256-gcm@openssh.com ./f h:/p"
check  --config /x ./f h:/p                     "/x|./f h:/p"
check  -P 2222 -r ./f h:/p                      "DEFAULT|-P 2222 -r ./f h:/p"
check  -d -- -c aes ./f h:/p                    "DEFAULT|-c aes ./f h:/p"
echo "SCP_PASSTHROUGH_OK"
TESTSCRIPT

    chmod +x "$test_script"
    local output
    output=$("$test_script" "$SCP_SCRIPT" 2>&1)

    if echo "$output" | grep -q "SCP_PASSTHROUGH_OK"; then
        test_pass "parse_args: scp options pass through; -c CIPHER not shadowed"
    else
        test_fail "scp option passthrough matrix" "Output: $output"
    fi
}

# Main test execution
echo "=========================================="
echo "Testing ob-scp (llng bastion SCP connector)"
echo "=========================================="
echo ""

test_syntax_check
test_version_flag
test_help_flag
test_too_few_args
test_is_remote_spec
test_split_remote_spec
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
