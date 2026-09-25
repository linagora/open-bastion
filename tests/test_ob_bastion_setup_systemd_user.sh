#!/bin/bash
# Tests for configure_pam_systemd_user() (#296). See scripts/ob-bastion-setup.
#
# shellcheck disable=SC2034  # variables are read by sourced functions

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

DEBIAN_SAMPLE='auth    requisite pam_deny.so
auth    required  pam_permit.so

@include common-account

session required  pam_limits.so
@include common-session
'

RHEL_SAMPLE='auth       required     pam_env.so
auth       required     pam_faildelay.so delay=2000

account    include      system-auth

password   include      system-auth

session    optional     pam_keyinit.so revoke
session    include      system-auth
'

# ── Test 1: inserted before "@include common-account" (Debian) ──
test_insert_before_debian_include() {
    local sandbox out
    sandbox=$(mktemp -d)
    printf '%s' "$DEBIAN_SAMPLE" > "$sandbox/systemd-user"

    out=$(
        source_script "ob-bastion-setup"
        DRY_RUN=false
        BACKUP_DIR="$sandbox/backup"
        PAM_SYSTEMD_USER="$sandbox/systemd-user"
        configure_pam_systemd_user 2>&1
    )
    local rc=$?

    local ok=true
    grep -q "pam_localuser.so" "$sandbox/systemd-user" || ok=false
    grep -q "pam_unix.so broken_shadow" "$sandbox/systemd-user" || ok=false
    # The inserted block must appear strictly before the @include line.
    local bridge_line include_line
    bridge_line=$(grep -n "pam_localuser.so" "$sandbox/systemd-user" | head -1 | cut -d: -f1)
    include_line=$(grep -n "@include common-account" "$sandbox/systemd-user" | head -1 | cut -d: -f1)
    [ -n "$bridge_line" ] && [ -n "$include_line" ] && [ "$bridge_line" -lt "$include_line" ] || ok=false

    rm -rf "$sandbox"
    if [ $rc -eq 0 ] && $ok; then
        pass "configure_pam_systemd_user inserts bridge before @include common-account (Debian)"
    else
        fail "configure_pam_systemd_user inserts bridge before @include common-account (Debian)" "rc=$rc$out"
    fi
}

# ── Test 2: inserted before "account include system-auth" (RHEL) ──
test_insert_before_rhel_account_line() {
    local sandbox out
    sandbox=$(mktemp -d)
    printf '%s' "$RHEL_SAMPLE" > "$sandbox/systemd-user"

    out=$(
        source_script "ob-bastion-setup"
        DRY_RUN=false
        BACKUP_DIR="$sandbox/backup"
        PAM_SYSTEMD_USER="$sandbox/systemd-user"
        configure_pam_systemd_user 2>&1
    )
    local rc=$?

    local ok=true
    grep -q "pam_localuser.so" "$sandbox/systemd-user" || ok=false
    grep -q "pam_unix.so broken_shadow" "$sandbox/systemd-user" || ok=false
    local bridge_line account_line
    bridge_line=$(grep -n "pam_localuser.so" "$sandbox/systemd-user" | head -1 | cut -d: -f1)
    account_line=$(grep -n "account    include      system-auth" "$sandbox/systemd-user" | head -1 | cut -d: -f1)
    [ -n "$bridge_line" ] && [ -n "$account_line" ] && [ "$bridge_line" -lt "$account_line" ] || ok=false

    rm -rf "$sandbox"
    if [ $rc -eq 0 ] && $ok; then
        pass "configure_pam_systemd_user inserts bridge before 'account include system-auth' (RHEL)"
    else
        fail "configure_pam_systemd_user inserts bridge before 'account include system-auth' (RHEL)" "rc=$rc$out"
    fi
}

# ── Test 3: idempotent on second run ──
test_idempotent_second_run() {
    local sandbox out1 out2
    sandbox=$(mktemp -d)
    printf '%s' "$DEBIAN_SAMPLE" > "$sandbox/systemd-user"

    (
        source_script "ob-bastion-setup"
        DRY_RUN=false
        BACKUP_DIR="$sandbox/backup"
        PAM_SYSTEMD_USER="$sandbox/systemd-user"
        configure_pam_systemd_user >/dev/null 2>&1
        configure_pam_systemd_user >/dev/null 2>&1
    )

    local count
    count=$(grep -c "pam_localuser.so" "$sandbox/systemd-user")

    out2=$(
        source_script "ob-bastion-setup"
        DRY_RUN=false
        BACKUP_DIR="$sandbox/backup"
        PAM_SYSTEMD_USER="$sandbox/systemd-user"
        configure_pam_systemd_user 2>&1
    )

    rm -rf "$sandbox"
    if [ "$count" -eq 1 ] && echo "$out2" | grep -qi "already configured"; then
        pass "configure_pam_systemd_user is idempotent"
    else
        fail "configure_pam_systemd_user is idempotent" "count=$count out2=$out2"
    fi
}

# ── Test 4: missing file is skipped, not created ──
test_missing_file_skipped() {
    local sandbox out
    sandbox=$(mktemp -d)

    out=$(
        source_script "ob-bastion-setup"
        DRY_RUN=false
        BACKUP_DIR="$sandbox/backup"
        PAM_SYSTEMD_USER="$sandbox/does-not-exist"
        configure_pam_systemd_user 2>&1
    )
    local rc=$?

    rm -rf "$sandbox"
    if [ $rc -eq 0 ] && echo "$out" | grep -qi "not found"; then
        pass "configure_pam_systemd_user skips a missing systemd-user file"
    else
        fail "configure_pam_systemd_user skips a missing systemd-user file" "rc=$rc out=$out"
    fi
}

# ── Test 5: no account line -> file left unchanged, warns ──
test_no_account_line_unchanged() {
    local sandbox out before after
    sandbox=$(mktemp -d)
    printf 'auth    required  pam_permit.so\nsession required  pam_limits.so\n' \
        > "$sandbox/systemd-user"
    before=$(cat "$sandbox/systemd-user")

    out=$(
        source_script "ob-bastion-setup"
        DRY_RUN=false
        BACKUP_DIR="$sandbox/backup"
        PAM_SYSTEMD_USER="$sandbox/systemd-user"
        configure_pam_systemd_user 2>&1
    )
    local rc=$?
    after=$(cat "$sandbox/systemd-user")

    rm -rf "$sandbox"
    if [ $rc -eq 0 ] && [ "$before" = "$after" ] && echo "$out" | grep -qi "No 'account' line"; then
        pass "configure_pam_systemd_user leaves a file with no account line unchanged"
    else
        fail "configure_pam_systemd_user leaves a file with no account line unchanged" "rc=$rc out=$out"
    fi
}

# ── Run all tests ──
echo "=== Testing ob-bastion-setup systemd-user PAM bridge (#296) ==="
run_test test_insert_before_debian_include
run_test test_insert_before_rhel_account_line
run_test test_idempotent_second_run
run_test test_missing_file_skipped
run_test test_no_account_line_unchanged

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
