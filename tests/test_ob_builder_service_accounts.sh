#!/bin/bash
#
# Test suite for ob-builder service-account support.
#
# Sources ob-builder (with `set -euo pipefail` and the `main "$@"` call
# stripped) and exercises the service-account parsing, validation and INI
# rendering helpers directly. OB_BUILDER_LIB_DIR / OB_BUILDER_SHARE are exported
# so ob-builder's lib/template auto-detection short-circuits.
#

set -u

TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$SCRIPT_DIR/admin-builder/ob-builder"
export OB_BUILDER_LIB_DIR="$SCRIPT_DIR/admin-builder/lib"
export OB_BUILDER_SHARE="$SCRIPT_DIR/admin-builder"

TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

test_pass() { echo -e "${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); }
test_fail() {
    echo -e "${RED}✗${NC} $1"
    [ -n "${2:-}" ] && echo -e "  ${YELLOW}Details:${NC} $2"
    ((TESTS_FAILED++))
}

# Source ob-builder definitions into THIS shell (functions + globals), with the
# top-level `set -euo pipefail` and the final `main "$@"` removed so nothing
# runs and a failing helper does not kill the harness.
# shellcheck disable=SC1090
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
BUILD_DATE="2026-01-01T00:00:00Z"

# Test 1: syntax check
test_syntax() {
    if bash -n "$BUILDER" 2>/dev/null; then
        test_pass "Syntax check: bash -n passes"
    else
        test_fail "Syntax check failed"
    fi
}

# Test 2: validators mirror the C rules
test_validators() {
    local ok=true
    is_valid_service_username "ansible"  || ok=false
    is_valid_service_username "_svc-1"   || ok=false
    is_valid_service_username "Ansible"  && ok=false   # uppercase first char
    is_valid_service_username "1svc"     && ok=false   # leading digit
    is_valid_fingerprint "SHA256:abcDEF123+/="  || ok=false
    is_valid_fingerprint "MD5:aa:bb:cc"  || ok=false
    is_valid_fingerprint "abc123"        && ok=false   # no prefix
    is_valid_fingerprint "SHA256:bad spaces" && ok=false
    is_valid_abs_path ""                 || ok=false   # empty OK
    is_valid_abs_path "/bin/bash"        || ok=false
    is_valid_abs_path "relative/path"    && ok=false
    $ok && test_pass "validators: username / fingerprint / path" \
         || test_fail "validators returned wrong result"
}

# Test 3: parse a YAML service_accounts block
test_parse_block() {
    local cfg="$TEST_TMPDIR/cfg.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
portal_url: https://sso.example.com
service_accounts:
  - name: ansible
    key_fingerprint: "SHA256:abc123"
    sudo_allowed: true
    sudo_nopasswd: true
    shell: /bin/bash
    home: /var/lib/ansible
    gecos: Ansible Automation
  - name: backup
    key_fingerprint: "SHA256:xyz789"
    sudo_allowed: false
    shell: /bin/sh
auto_enroll_setup: prompt
YML
    SERVICE_ACCOUNTS_RECORDS=()
    _parse_service_accounts_block "$cfg"

    local ok=true
    [ "${#SERVICE_ACCOUNTS_RECORDS[@]}" -eq 2 ] || { ok=false; echo "  count=${#SERVICE_ACCOUNTS_RECORDS[@]}"; }
    [ "$(_sa_field 1 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "ansible" ] || ok=false
    [ "$(_sa_field 2 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "SHA256:abc123" ] || ok=false
    [ "$(_sa_field 3 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "true" ] || ok=false
    [ "$(_sa_field 5 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "/bin/bash" ] || ok=false
    [ "$(_sa_field 7 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "Ansible Automation" ] || ok=false
    [ "$(_sa_field 1 "${SERVICE_ACCOUNTS_RECORDS[1]}")" = "backup" ] || ok=false
    [ "$(_sa_field 3 "${SERVICE_ACCOUNTS_RECORDS[1]}")" = "false" ] || ok=false
    $ok && test_pass "parse: service_accounts block → 2 records, fields correct" \
         || test_fail "parse: block parsing wrong"
}

# Test 4: a config with no service_accounts yields zero records
test_parse_none() {
    local cfg="$TEST_TMPDIR/none.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
portal_url: https://sso.example.com
YML
    SERVICE_ACCOUNTS_RECORDS=()
    _parse_service_accounts_block "$cfg"
    [ "${#SERVICE_ACCOUNTS_RECORDS[@]}" -eq 0 ] \
        && test_pass "parse: no service_accounts → 0 records" \
        || test_fail "parse: expected 0 records, got ${#SERVICE_ACCOUNTS_RECORDS[@]}"
}

# Test 5: record validation
test_record_validation() {
    local ok=true
    validate_service_account_record "$(_sa_pack ansible SHA256:abc true false /bin/bash /var/lib/ansible '' '' '')" || ok=false
    validate_service_account_record "$(_sa_pack BadName SHA256:abc false false '' '' '' '' '')" && ok=false
    validate_service_account_record "$(_sa_pack svc nofingerprint false false '' '' '' '' '')" && ok=false
    validate_service_account_record "$(_sa_pack svc SHA256:abc false false relpath '' '' '' '')" && ok=false
    $ok && test_pass "validate_service_account_record: accepts valid, rejects bad" \
         || test_fail "record validation wrong"
}

# Test 6: INI rendering
test_render_conf() {
    SERVICE_ACCOUNTS_RECORDS=(
        "$(_sa_pack ansible SHA256:abc123 true true /bin/bash /var/lib/ansible 'Ansible Automation' '' '')"
        "$(_sa_pack backup SHA256:xyz789 false false /bin/sh '' '' '' '')"
    )
    local out
    out=$(_render_service_accounts_conf)
    local ok=true
    grep -q '^\[ansible\]$'                      <<<"$out" || ok=false
    grep -q '^key_fingerprint = SHA256:abc123$'  <<<"$out" || ok=false
    grep -q '^sudo_allowed = true$'              <<<"$out" || ok=false
    grep -q '^sudo_nopasswd = true$'             <<<"$out" || ok=false
    grep -q '^gecos = Ansible Automation$'       <<<"$out" || ok=false
    grep -q '^home = /var/lib/ansible$'          <<<"$out" || ok=false
    grep -q '^\[backup\]$'                       <<<"$out" || ok=false
    grep -q '^sudo_allowed = false$'             <<<"$out" || ok=false
    # backup has no home/gecos → those keys absent in its section is not trivially
    # grep-able, but the file must not carry an empty 'home =' line anywhere.
    grep -q '^home = $'                          <<<"$out" && ok=false
    $ok && test_pass "render: INI output well-formed" \
         || test_fail "render: INI output wrong" "$out"
}

echo "=========================================="
echo "Testing ob-builder service-account support"
echo "=========================================="
echo ""

test_syntax
test_validators
test_parse_block
test_parse_none
test_record_validation
test_render_conf

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
