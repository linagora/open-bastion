#!/bin/bash
#
# Every key this project writes into openbastion.conf must be recognised by
# src/config.c (#229).
#
# Why: config_load() runs once per PAM process, so a key that ob-bastion-setup
# (every role, ob-backend-setup included) or an ob-builder template emits and the parser does not know
# costs one syslog warning per login on every deployed host. Reporting unknown
# keys is only useful while the report means something -- three to five
# warnings per authentication would bury the single typo the feature exists to
# surface, which is the opposite of the point.
#
# Text-level on purpose: it reads the generators and the shipped example rather
# than linking the parser, so it stays valid for keys handled anywhere in
# parse_line(), including the "consumed elsewhere" branches.
#

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_C="$ROOT_DIR/src/config.c"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }

# Keys written into openbastion.conf, per source. Anything else these scripts
# emit goes to a different file (nss_openbastion.conf, service-accounts.conf)
# and is parsed by different code.
keys_from_printf() {           # generator scripts: printf 'key = ...'
    grep -oE "printf '[a-z_]+ = " "$1" 2>/dev/null | sed "s/printf '//; s/ = $//"
}
keys_from_conf() {             # example / template: active "key = value" lines
    grep -oE '^[a-z_]+[[:space:]]*=' "$1" 2>/dev/null | sed 's/[[:space:]]*=$//'
}
keys_from_heredoc() {          # ob-builder: config emitted inside `cat << MODE`
    # Same shape as a conf file, but embedded in a shell script, so the printf
    # extractor above sees none of it. ob-builder was missed entirely until a
    # reviewer's miscount sent us back to check who writes what.
    grep -oE '^[a-z_]+[[:space:]]*=' "$1" 2>/dev/null | sed 's/[[:space:]]*=$//'
}

check_source() {
    local desc="$1" file="$2" mode="$3" missing="" k
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ ! -f "$file" ]; then
        pass "$desc (absent, skipped)"
        return
    fi
    for k in $("keys_from_$mode" "$file" | sort -u); do
        grep -q "\"$k\"" "$CONFIG_C" || missing="$missing $k"
    done
    if [ -z "$missing" ]; then
        pass "$desc"
    else
        fail "$desc" "src/config.c does not know:$missing"
    fi
}

echo "=== openbastion.conf keys the project writes are all parsed (#229) ==="

check_source "ob-bastion-setup writes only known keys (all roles)"  "$ROOT_DIR/scripts/ob-bastion-setup"  printf
check_source "the shipped example carries only known keys" \
    "$ROOT_DIR/config/openbastion.conf.example" conf
check_source "the ansible template carries only known keys" \
    "$ROOT_DIR/admin-builder/templates/ansible/role/templates/openbastion.conf.j2" conf
check_source "ob-builder's embedded configs carry only known keys" \
    "$ROOT_DIR/admin-builder/ob-builder" heredoc

# The generators' own keys must also survive a round trip through the parser's
# unknown-key branch: assert the five that nothing reads back are listed, so a
# future cleanup removes them from BOTH sides or from neither.
TESTS_RUN=$((TESTS_RUN + 1))
_absent=""
for k in cache_enabled cache_dir cache_ttl create_home default_shell; do
    grep -q "\"$k\"" "$CONFIG_C" || _absent="$_absent $k"
done
if [ -z "$_absent" ]; then
    pass "the write-only cache_*/create_home/default_shell keys stay tolerated"
else
    fail "the write-only keys stay tolerated" "missing from src/config.c:$_absent"
fi

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
