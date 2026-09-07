#!/bin/bash
# test_ob_service_account_keys.sh
#
# The service-account SSH layer ships, and ships in one place (issue #263).
#
# scripts/ob-service-account-keys is the AuthorizedKeysCommand helper that
# makes a service account usable: it serves the account's public key from
# /etc/open-bastion/service-accounts.d/<name>.pub without the Unix account
# having to exist yet. Without it sshd has no key for the account and refuses
# at the protocol layer, before pam_openbastion runs at all.
#
# It was in the tree and in **none** of the three packaging paths, so there was
# no copy on a host to point AuthorizedKeysCommand at. Everyone who needed it
# installed their own, at a path of their choosing: /usr/local/bin/ in two
# demos, /usr/local/sbin/ in the lab and in the documentation. A field report
# hit the wall from the outside (#263).
#
# So: it must be packaged, at one path, and nothing shipped may point anywhere
# else.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HELPER="$ROOT_DIR/scripts/ob-service-account-keys"
CANONICAL="/usr/sbin/ob-service-account-keys"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    if ! declare -F "$1" >/dev/null; then
        fail "$1 is listed as a test but is not defined"
        return
    fi
    "$@"
}

[ -f "$HELPER" ] || { echo "SKIP: $HELPER not found"; exit 0; }

echo "=== service-account SSH layer (issue #263) ==="

# ── 1. All three packaging paths carry it ───────────────────────────────────
test_helper_is_packaged() {
    local missing=""
    grep -q 'ob-service-account-keys' "$ROOT_DIR/CMakeLists.txt"           || missing="$missing CMakeLists.txt"
    grep -q 'ob-service-account-keys' "$ROOT_DIR/debian/open-bastion.install" || missing="$missing debian/.install"
    grep -q 'ob-service-account-keys' "$ROOT_DIR/rpm/open-bastion.spec"    || missing="$missing rpm/.spec"
    if [ -z "$missing" ]; then
        pass "the helper is installed by CMake, the .deb and the RPM"
    else
        fail "the helper is installed by CMake, the .deb and the RPM" "absent from:$missing"
    fi
}

# ── 2. Nothing shipped points outside the packaged path ─────────────────────
# /usr/local is the administrator's, not a package's (Debian policy 9.1.2), and
# a second copy there is what let the three paths drift apart in the first
# place. local-test/ is exempt: it provisions lab VMs over ssh and predates the
# packaged helper.
test_one_path_everywhere() {
    local strays
    strays=$(grep -rn '/usr/local/\(s\?bin\)/ob-service-account-keys' \
                  --exclude-dir=.git --exclude-dir=analyse --exclude-dir=build \
                  --exclude-dir=local-test "$ROOT_DIR" 2>/dev/null \
             | sed "s|$ROOT_DIR/||")
    if [ -z "$strays" ]; then
        pass "every shipped reference uses $CANONICAL"
    else
        fail "every shipped reference uses $CANONICAL" \
             "$(printf '%s' "$strays" | tr '\n' ' ')"
    fi
}

# ── 3. The documentation does not claim the SSH layer is optional ───────────
# doc/service-accounts.md used to say, of Mode E, "No `authorized_keys` file is
# required" -- true in the literal sense and badly misleading in practice: it
# reads as "nothing else is needed", and the PAM fingerprint check it describes
# is a re-validation, not an authorisation. That sentence is what cost the
# reporter a debugging session.
test_doc_does_not_claim_pam_is_enough() {
    local doc="$ROOT_DIR/doc/service-accounts.md" bad=""
    grep -q 'No `authorized_keys` file is required' "$doc" \
        && bad="$bad still-says-nothing-is-required"
    grep -q 'ExposeAuthInfo yes` must be set (the setups do this)' "$doc" \
        && bad="$bad still-claims-the-setups-write-ExposeAuthInfo"
    grep -q 'AuthorizedKeysCommand' "$doc" || bad="$bad no-AuthorizedKeysCommand-documented"
    if [ -z "$bad" ]; then
        pass "the documentation states that the SSH layer is required"
    else
        fail "the documentation states that the SSH layer is required" "$bad"
    fi
}

# ── 4. ExposeAuthInfo really is Mode-E only, as the doc now says ────────────
# Pinned because the doc's correction rests on it: if a setup script starts
# writing it unconditionally, the new paragraph becomes the wrong one.
test_exposeauthinfo_is_mode_e_only() {
    local bad="" f fn
    for f in ob-bastion-setup ob-backend-setup; do
        fn=$(awk '/ExposeAuthInfo yes/{print NR; exit}' "$ROOT_DIR/scripts/$f")
        [ -n "$fn" ] || { bad="$bad $f(absent)"; continue; }
        awk -v n="$fn" 'NR<=n{if(/^[a-z_]+\(\) \{/) f=$0} END{print f}' \
            "$ROOT_DIR/scripts/$f" | grep -q 'configure_max_security_sshd' \
            || bad="$bad $f(moved-out-of-max-security)"
    done
    if [ -z "$bad" ]; then
        pass "ExposeAuthInfo is written only by configure_max_security_sshd, as documented"
    else
        fail "ExposeAuthInfo is written only by configure_max_security_sshd, as documented" \
             "$bad — doc/service-accounts.md says so and would now be wrong"
    fi
}

# ── 5. The helper refuses what it must refuse ───────────────────────────────
#
# Driven through OB_SERVICE_ACCOUNTS_KEYS_DIR. The happy path needs a
# root-owned key file and so needs root; what is checked here is everything the
# helper is supposed to REFUSE, which is the half that matters and which an
# unprivileged run can prove:
#
#   - a key file that is not root-owned. This one is free: a file created by
#     this test is owned by the test user, so the refusal is exercised without
#     any privilege at all;
#   - names that could reach outside the directory or carry shell syntax.
#
# It must never exit non-zero: sshd treats that as a failure and would refuse
# the login outright, including for ordinary users who are not service accounts
# at all.
test_helper_refusals() {
    local d out rc bad=""
    d=$(mktemp -d)
    mkdir -p "$d/keys"
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYFORTESTINGONLY svc@test" > "$d/keys/svc.pub"

    # Not root-owned (this test does not run as root), so: no output.
    out=$(OB_SERVICE_ACCOUNTS_KEYS_DIR="$d/keys" bash "$HELPER" svc 2>/dev/null); rc=$?
    [ "$rc" -eq 0 ] || bad="$bad nonzero-exit-on-nonroot-file($rc)"
    [ -z "$out" ]   || bad="$bad served-a-non-root-owned-key"

    # Names that must never reach the filesystem.
    local name
    for name in "../../etc/passwd" "sv;id" "SVC" "svc key" "-svc" ""; do
        out=$(OB_SERVICE_ACCOUNTS_KEYS_DIR="$d/keys" bash "$HELPER" "$name" 2>/dev/null); rc=$?
        [ "$rc" -eq 0 ] || bad="$bad nonzero-exit-on[$name]($rc)"
        [ -z "$out" ]   || bad="$bad output-for[$name]"
    done

    # An unknown but well-formed name: nothing, and still zero.
    out=$(OB_SERVICE_ACCOUNTS_KEYS_DIR="$d/keys" bash "$HELPER" nosuchacct 2>/dev/null); rc=$?
    [ "$rc" -eq 0 ] || bad="$bad nonzero-exit-on-unknown($rc)"
    [ -z "$out" ]   || bad="$bad output-for-unknown"

    rm -rf "$d"

    if [ -z "$bad" ]; then
        pass "the helper refuses a non-root key file and every malformed name, always exiting 0"
    else
        fail "the helper refuses a non-root key file and every malformed name, always exiting 0" "$bad"
    fi
}

# ── 6. The directory the helper reads is shipped too ────────────────────────
#
# A helper without its directory is inert: it exits 0 with no output for every
# account, which is indistinguishable from "this user is not a service
# account". Nothing in the shipped tree created it -- only the lab and the two
# demo entrypoints did, by hand, which is again why the gap survived.
#
# 0755: it holds public keys, and the AuthorizedKeysCommandUser (nobody) has to
# traverse and read it. tests/test_integration_token_svc.sh asserts exactly
# that mode on a running bastion.
test_keys_dir_is_shipped() {
    local missing=""
    grep -q 'service-accounts.d' "$ROOT_DIR/debian/open-bastion.dirs" \
        || missing="$missing debian/.dirs"
    grep -q 'service-accounts.d' "$ROOT_DIR/CMakeLists.txt" \
        || missing="$missing CMakeLists.txt"
    grep -q 'service-accounts.d' "$ROOT_DIR/rpm/open-bastion.spec" \
        || missing="$missing rpm/.spec"
    if [ -z "$missing" ]; then
        pass "service-accounts.d is created by all three packaging paths"
    else
        fail "service-accounts.d is created by all three packaging paths" "absent from:$missing"
    fi
}

run_test test_helper_is_packaged
run_test test_one_path_everywhere
run_test test_doc_does_not_claim_pam_is_enough
run_test test_exposeauthinfo_is_mode_e_only
run_test test_helper_refusals
run_test test_keys_dir_is_shipped

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
