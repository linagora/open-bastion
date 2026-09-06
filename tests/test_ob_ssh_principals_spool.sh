#!/bin/bash
# test_ob_ssh_principals_spool.sh
#
# Guards the out-of-band channel that makes the SSH key policy enforceable
# (issue #181).
#
# sshd does not export SSH_USER_AUTH to the PAM environment during
# pam_acct_mgmt, so pam_openbastion cannot see which key was presented. The
# ob-ssh-principals helper — installed by ob-bastion-setup / ob-backend-setup
# as AuthorizedPrincipalsCommand — therefore drops it in
# /run/open-bastion/ssh-fp/<anchor>.{fp,key}. This test extracts the helper
# from BOTH setup scripts (single source of truth) and checks:
#
#   - the legacy "<anchor>.fp" drop keeps its exact previous content;
#   - the new "<anchor>.key" drop carries v=1 / fp= / alg= / key=;
#   - both drops are mode 0600;
#   - a malformed key type or key blob is filtered out rather than spooled;
#   - a legacy invocation without %t/%k still writes .fp and writes no .key
#     (so an old sshd_config with a new helper degrades, it does not break);
#   - the backend helper still enforces bastion vouching;
#   - both sshd_config templates pass %t and %k to the helper.
#
# The helper walks /proc to find its per-connection sshd anchor, so the test
# runs it under a process renamed "sshd-session".

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASTION_SETUP="$ROOT_DIR/scripts/ob-bastion-setup"
BACKEND_SETUP="$ROOT_DIR/scripts/ob-backend-setup"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SPOOL="$TMP/spool"
CONF_DIR="$TMP/etc"
mkdir -p "$SPOOL" "$CONF_DIR"

# A process named "sshd-session" so the helper's anchor walk terminates the way
# it does under a real sshd.
FAKE_SSHD="$TMP/sshd-session"
cp "$(command -v sh)" "$FAKE_SSHD" 2>/dev/null || cp /bin/sh "$FAKE_SSHD"
chmod 755 "$FAKE_SSHD"

# Extract a helper from a setup script and point it at the throwaway paths.
extract_helper() {
    local src="$1" dst="$2"
    awk "/cat > \"\\\$script_path\" << 'PRINCIPALS'/{f=1;next} /^PRINCIPALS\$/{f=0} f" \
        "$src" > "$dst"
    [ -s "$dst" ] || return 1
    sed -i \
        -e "s|^SPOOL_DIR=.*|SPOOL_DIR=\"$SPOOL\"|" \
        -e "s|^ALLOWED_FILE=.*|ALLOWED_FILE=\"$CONF_DIR/allowed_bastions\"|" \
        -e "s|^OB_DIR=.*|OB_DIR=\"$CONF_DIR\"|" \
        "$dst"
    chmod 755 "$dst"
}

# Run a helper as a child of the fake sshd-session process. The trailing ":"
# stops the shell from exec'ing the helper in its own place, which would make
# the helper's PPID the test runner instead of "sshd-session".
run_helper() {
    local helper="$1"; shift
    # shellcheck disable=SC2016  # the inner script must expand in the child
    "$FAKE_SSHD" -c 'h="$1"; shift; "$h" "$@"; :' _ "$helper" "$@"
}

reset_spool() { rm -f "$SPOOL"/* 2>/dev/null; }
drop_fp()  { cat "$SPOOL"/*.fp 2>/dev/null; }
drop_key() { cat "$SPOOL"/*.key 2>/dev/null; }
count_key() { find "$SPOOL" -maxdepth 1 -name '*.key' 2>/dev/null | wc -l; }

FP="SHA256:AbCdEf0123456789+/abcdefghijklmnopqrstuvw"
# A real, if small, ssh-ed25519 blob shape is not needed here: the module
# validates the blob, the helper only filters the character set.
BLOB="AAAAC3NzaC1lZDI1NTE5AAAAILsowx9DXYSSOCdnpC+9upU7TbW6thHwXvHY/128Qfrg"
USER_NAME="$(id -un)"

BASTION_HELPER="$TMP/helper-bastion"
BACKEND_HELPER="$TMP/helper-backend"

# ── Test 1: helpers extract and are valid POSIX sh ──
test_extract_and_syntax() {
    local ok=1
    extract_helper "$BASTION_SETUP" "$BASTION_HELPER" || { ok=0; }
    extract_helper "$BACKEND_SETUP" "$BACKEND_HELPER" || { ok=0; }
    if [ "$ok" != 1 ]; then
        fail "Helpers extracted from setup scripts"
        return
    fi
    if sh -n "$BASTION_HELPER" && sh -n "$BACKEND_HELPER"; then
        pass "Helpers extracted and syntactically valid"
    else
        fail "Helpers extracted and syntactically valid"
    fi
}

# ── Test 2: bastion helper writes both drops ──
test_bastion_writes_both_drops() {
    reset_spool
    run_helper "$BASTION_HELPER" "$USER_NAME" "$FP" "ssh-ed25519" "$BLOB" >/dev/null

    local fp key
    fp=$(drop_fp)
    key=$(drop_key)

    if [ "$fp" != "$FP" ]; then
        fail "Bastion .fp drop unchanged" "got '$fp'"
        return
    fi
    if ! echo "$key" | grep -qx "v=1"; then
        fail "Bastion .key drop has v=1" "got '$key'"
        return
    fi
    if ! echo "$key" | grep -qx "fp=$FP"; then
        fail "Bastion .key drop carries fp=" "got '$key'"
        return
    fi
    if ! echo "$key" | grep -qx "alg=ssh-ed25519"; then
        fail "Bastion .key drop carries alg=" "got '$key'"
        return
    fi
    if ! echo "$key" | grep -qx "key=$BLOB"; then
        fail "Bastion .key drop carries key=" "got '$key'"
        return
    fi
    pass "Bastion helper writes .fp (unchanged) and v=1 .key drop"
}

# ── Test 3: both drops are 0600 ──
test_drop_permissions() {
    reset_spool
    run_helper "$BASTION_HELPER" "$USER_NAME" "$FP" "ssh-ed25519" "$BLOB" >/dev/null
    local bad=""
    local f
    for f in "$SPOOL"/*.fp "$SPOOL"/*.key; do
        [ -f "$f" ] || continue
        local mode
        mode=$(stat -c '%a' "$f")
        [ "$mode" = "600" ] || bad="$bad $f=$mode"
    done
    if [ -z "$bad" ]; then
        pass "Spool drops are mode 0600"
    else
        fail "Spool drops are mode 0600" "$bad"
    fi
}

# ── Test 4: a malformed key type is not spooled at all ──
test_bad_keytype_filtered() {
    reset_spool
    run_helper "$BASTION_HELPER" "$USER_NAME" "$FP" 'ssh-ed25519; rm -rf /' "$BLOB" >/dev/null
    if [ "$(count_key)" = "0" ] && [ "$(drop_fp)" = "$FP" ]; then
        pass "Malformed key type is filtered (no .key drop, .fp still written)"
    else
        fail "Malformed key type is filtered" "key drops: $(count_key)"
    fi
}

# ── Test 5: a malformed key blob drops key= but keeps alg= ──
test_bad_blob_filtered() {
    reset_spool
    # shellcheck disable=SC2016  # deliberately literal: the helper must reject it
    run_helper "$BASTION_HELPER" "$USER_NAME" "$FP" "ssh-rsa" 'AAAA$(id)' >/dev/null
    local key
    key=$(drop_key)
    if echo "$key" | grep -qx "alg=ssh-rsa" && ! echo "$key" | grep -q "^key="; then
        pass "Malformed key blob is dropped, algorithm still recorded"
    else
        fail "Malformed key blob is dropped" "got '$key'"
    fi
}

# ── Test 6: legacy invocation (no %t/%k) still writes .fp, writes no .key ──
# This is the "new helper, old sshd_config" ordering: it must degrade to the
# previous behaviour, never break the fingerprint binding.
test_legacy_invocation() {
    reset_spool
    run_helper "$BASTION_HELPER" "$USER_NAME" "$FP" >/dev/null
    if [ "$(drop_fp)" = "$FP" ] && [ "$(count_key)" = "0" ]; then
        pass "Legacy 2-argument invocation still writes .fp and no .key"
    else
        fail "Legacy 2-argument invocation" "fp='$(drop_fp)' keys=$(count_key)"
    fi
}

# ── Test 7: backend helper, vouched cert, writes both drops and emits principal ──
test_backend_vouched() {
    reset_spool
    printf 'bastion1\n' > "$CONF_DIR/allowed_bastions"
    local out
    out=$(run_helper "$BACKEND_HELPER" "$USER_NAME" "$FP" \
            "bastion=bastion1;user=$USER_NAME;target=host" "ssh-ed25519" "$BLOB")
    if [ "$out" != "$USER_NAME" ]; then
        fail "Backend helper emits principal for a vouched cert" "got '$out'"
        return
    fi
    if drop_key | grep -qx "alg=ssh-ed25519" && [ "$(drop_fp)" = "$FP" ]; then
        pass "Backend helper: vouched cert accepted and both drops written"
    else
        fail "Backend helper: vouched cert drops" "key='$(drop_key)'"
    fi
}

# ── Test 8: backend helper still denies an unvouched cert ──
test_backend_unvouched_denied() {
    reset_spool
    printf 'bastion1\n' > "$CONF_DIR/allowed_bastions"
    local out
    out=$(run_helper "$BACKEND_HELPER" "$USER_NAME" "$FP" \
            "user=$USER_NAME" "ssh-ed25519" "$BLOB")
    if [ -z "$out" ]; then
        pass "Backend helper still denies an unvouched (direct SSO) cert"
    else
        fail "Backend helper still denies an unvouched cert" "got '$out'"
    fi
}

# ── Test 9: backend helper denies a bastion_id outside the allowlist ──
test_backend_wrong_bastion_denied() {
    reset_spool
    printf 'bastion1\n' > "$CONF_DIR/allowed_bastions"
    local out
    out=$(run_helper "$BACKEND_HELPER" "$USER_NAME" "$FP" \
            "bastion=evil;user=$USER_NAME;target=host" "ssh-ed25519" "$BLOB")
    if [ -z "$out" ]; then
        pass "Backend helper still denies a bastion_id outside the allowlist"
    else
        fail "Backend helper still denies a wrong bastion_id" "got '$out'"
    fi
}

# ── Test 9b: an empty allowlist still accepts, but says so on every hop ──
#
# Empty means "any vouched bastion" (#182). That semantic is kept -- inverting
# it would deny every hop on a fleet that upgrades -- but it must no longer be
# invisible: the helper logs a warning to authpriv for each accepted hop.
test_backend_empty_allowlist_warns() {
    reset_spool
    : > "$CONF_DIR/allowed_bastions"

    # Capture what the helper would send to syslog by shadowing logger(1).
    local bindir="$TMP/bin" logged="$TMP/logged"
    mkdir -p "$bindir"
    rm -f "$logged"
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\n' "$logged" > "$bindir/logger"
    chmod 755 "$bindir/logger"

    local out
    out=$(PATH="$bindir:$PATH" run_helper "$BACKEND_HELPER" "$USER_NAME" "$FP" \
            "bastion=whatever;user=$USER_NAME;target=host" "ssh-ed25519" "$BLOB")

    if [ "$out" != "$USER_NAME" ]; then
        fail "Empty allowlist still accepts a vouched cert" "got '$out'"
        return
    fi
    if [ -s "$logged" ] && grep -q 'allowed_bastions is empty' "$logged"; then
        pass "Empty allowlist accepts but logs a warning naming the bastion"
    else
        fail "Empty allowlist logs a warning" "logged: $(cat "$logged" 2>/dev/null)"
    fi
}

# ── Test 10: both sshd_config templates pass %t and %k ──
test_sshd_config_tokens() {
    local bastion_line backend_line
    bastion_line=$(grep -m1 '^AuthorizedPrincipalsCommand ' "$BASTION_SETUP")
    backend_line=$(grep -m1 '^AuthorizedPrincipalsCommand ' "$BACKEND_SETUP")
    if [ "$bastion_line" = "AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f %t %k" ] \
       && [ "$backend_line" = "AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f %i %t %k" ]; then
        pass "sshd_config templates pass %t and %k to the helper"
    else
        fail "sshd_config templates pass %t and %k" "bastion='$bastion_line' backend='$backend_line'"
    fi
}

# ── Test 11: helpers advertise the v1 spool format (postinst upgrade guard) ──
test_spool_format_marker() {
    if grep -q 'spool-format: v1' "$BASTION_HELPER" \
       && grep -q 'spool-format: v1' "$BACKEND_HELPER"; then
        pass "Helpers advertise 'spool-format: v1' for the postinst upgrade guard"
    else
        fail "Helpers advertise 'spool-format: v1'"
    fi
}

echo "=== ob-ssh-principals spool tests ==="
run_test test_extract_and_syntax
if [ ! -s "$BASTION_HELPER" ] || [ ! -s "$BACKEND_HELPER" ]; then
    echo "Cannot continue without the extracted helpers"
    exit 1
fi
run_test test_bastion_writes_both_drops
run_test test_drop_permissions
run_test test_bad_keytype_filtered
run_test test_bad_blob_filtered
run_test test_legacy_invocation
run_test test_backend_vouched
run_test test_backend_unvouched_denied
run_test test_backend_wrong_bastion_denied
run_test test_backend_empty_allowlist_warns
run_test test_sshd_config_tokens
run_test test_spool_format_marker

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
