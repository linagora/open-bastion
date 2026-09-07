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

# No SKIP path. This suite reads the tree and nothing else -- no docker, no
# portal, no build -- so there is no environment in which it legitimately
# cannot run. A missing helper is the #263 regression itself, and every
# packaging assertion below would vanish with it: exiting 0 there would leave
# CI green on exactly the defect this suite exists for.
if [ ! -f "$HELPER" ]; then
    echo "  FAIL: $HELPER is missing -- that IS the regression this suite guards"
    echo
    echo "Tests run: 1, passed: 0, failed: 1"
    exit 1
fi

SCRATCH=""
trap '[ -n "$SCRATCH" ] && rm -rf "$SCRATCH"' EXIT INT TERM

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
    local bad="" line
    # What matters is not every mention of the name -- packaging files carry it
    # as a relative path or an RPM macro, and git grep prefixes each hit with
    # the file it came from, all of which a path-shaped regex trips over. What
    # matters is every place that names a path something will EXECUTE:
    #
    #   - the AuthorizedKeysCommand lines sshd runs;
    #   - a direct invocation of the helper by absolute path;
    #   - the CMake DESTINATION, checked separately below.
    #
    # git grep so build trees and lab VM images stay out; -I so a binary never
    # answers "Binary file matches".
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in
            # The narrative names the historical paths on purpose.
            CHANGELOG.md:*|doc/*) continue ;;
            # The helper's own header, and this suite's, describe the mechanism.
            scripts/ob-service-account-keys:*|tests/test_ob_service_account_keys.sh:*) continue ;;
            *"$CANONICAL"*) continue ;;
        esac
        # A comment is prose, not an invocation.
        case "${line#*:*:}" in
            [[:space:]]*\#*|\#*|*'* '*|*'/*'*) continue ;;
        esac
        bad="$bad|$line"
    done <<EOF
$(cd "$ROOT_DIR" && git grep -I -n -E \
    "(AuthorizedKeysCommand[[:space:]]+[^%]|/(usr|opt)[A-Za-z0-9_/.-]*ob-service-account-keys)" \
    -- . 2>/dev/null | grep 'ob-service-account-keys')
EOF

    grep -A2 'install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-service-account-keys' \
        "$ROOT_DIR/CMakeLists.txt" | grep -q 'CMAKE_INSTALL_SBINDIR' \
        || bad="$bad|CMakeLists.txt: DESTINATION is not CMAKE_INSTALL_SBINDIR"

    if [ -z "$bad" ]; then
        pass "every executed reference uses $CANONICAL"
    else
        fail "every executed reference uses $CANONICAL" "${bad//|/ }"
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
test_exposeauthinfo_is_always_guarded() {
    local bad="" f n line fun
    # The property is not "it lives in Mode E" any more -- --enable-service-keys
    # writes it too, because an AuthorizedKeysCommand without it means sshd
    # accepts the key and the fingerprint is never checked. What must hold is
    # that EVERY write sits behind an opt-in guard: an unconditional one would
    # turn SSH_USER_AUTH on for every session on every host, and would make
    # doc/service-accounts.md wrong again.
    for f in ob-bastion-setup ob-backend-setup; do
        local src="$ROOT_DIR/scripts/$f" found=0
        # Non-comment writes only: a mention in prose is not a write.
        while IFS= read -r n; do
            [ -n "$n" ] || continue
            found=$((found + 1))
            fun=$(awk -v n="$n" 'NR<=n{if(/^[a-z_]+\(\) \{/) x=$0} END{print x}' "$src")
            case "$fun" in
                configure_max_security_sshd*|configure_service_account_keys*) ;;
                # --help text describes the directive; it writes nothing.
                usage*|show_help*) found=$((found - 1)) ;;
                *) bad="$bad $f:$n(in ${fun%%(*}, unguarded)" ;;
            esac
        done < <(awk '!/^[[:space:]]*#/ && /ExposeAuthInfo yes/{print NR}' "$src")

        [ "$found" -gt 0 ] || bad="$bad $f(no-write-at-all)"

        # Each of those two functions must early-return when its flag is off.
        for fun in configure_max_security_sshd configure_service_account_keys; do
            sed -n "/^$fun() {/,/^}/p" "$src" | head -4 \
                | grep -qE '(MAX_SECURITY|ENABLE_SERVICE_KEYS)" != "true"' \
                || bad="$bad $f:$fun(no-early-return)"
        done
    done

    if [ -z "$bad" ]; then
        pass "every ExposeAuthInfo write is behind an opt-in guard"
    else
        fail "every ExposeAuthInfo write is behind an opt-in guard" \
             "$bad — doc/service-accounts.md describes these two paths and would now be wrong"
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
    # Registered in a file-scope variable, not a RETURN trap on this `local`:
    # the trap fires after the local is gone and `set -u` then aborts on it.
    SCRATCH="$d"
    mkdir -p "$d/keys"

    local as_root=false
    [ "$(id -u)" = "0" ] && as_root=true

    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYFORTESTINGONLY svc@test" > "$d/keys/svc.pub"

    # ── The root-ownership gate ──────────────────────────────────────────────
    # As an ordinary user the file we just wrote is ours, so the gate is
    # exercised for free. As root it would pass, so give it a non-root owner
    # explicitly rather than let the assertion invert and fail on a sound tree.
    if $as_root; then
        chown nobody "$d/keys/svc.pub" 2>/dev/null || chown 65534 "$d/keys/svc.pub" 2>/dev/null || true
    fi
    out=$(OB_SERVICE_ACCOUNTS_KEYS_DIR="$d/keys" bash "$HELPER" svc 2>/dev/null); rc=$?
    [ "$rc" -eq 0 ] || bad="$bad nonzero-exit-on-nonroot-file($rc)"
    [ -z "$out" ]   || bad="$bad served-a-non-root-owned-key"

    # ── Name validation ──────────────────────────────────────────────────────
    # The files these names would reach are CREATED first. Without them the
    # assertions prove nothing: the helper appends ".pub", so `../../etc/passwd`
    # probes a file that does not exist, and deleting the validation entirely
    # still yields no output. Verified by mutation -- that is how this test
    # looked before, and it passed with the checks removed.
    mkdir -p "$d/keys/sub"
    echo "ssh-ed25519 AAAAESCAPED escaped@test" > "$d/escaped.pub"   # reached by ../escaped
    echo "ssh-ed25519 AAAAUPPER   upper@test"   > "$d/keys/SVC.pub"
    echo "ssh-ed25519 AAAASEMI    semi@test"    > "$d/keys/sv;id.pub"
    echo "ssh-ed25519 AAAASPACE   space@test"   > "$d/keys/svc key.pub"
    echo "ssh-ed25519 AAAADASH    dash@test"    > "$d/keys/-svc.pub"
    if $as_root; then
        # Ownership then cannot be the reason for the refusal: only validation
        # can be. This is the strong form of the assertion, and it needs root.
        chown -R root:root "$d" 2>/dev/null || true
    fi

    local name
    for name in "../escaped" "SVC" "sv;id" "svc key" "-svc" ""; do
        out=$(OB_SERVICE_ACCOUNTS_KEYS_DIR="$d/keys" bash "$HELPER" "$name" 2>/dev/null); rc=$?
        [ "$rc" -eq 0 ] || bad="$bad nonzero-exit-on[$name]($rc)"
        [ -z "$out" ]   || bad="$bad served[$name]"
    done

    # A well-formed name with no file: nothing, still zero.
    out=$(OB_SERVICE_ACCOUNTS_KEYS_DIR="$d/keys" bash "$HELPER" nosuchacct 2>/dev/null); rc=$?
    [ "$rc" -eq 0 ] || bad="$bad nonzero-exit-on-unknown($rc)"
    [ -z "$out" ]   || bad="$bad output-for-unknown"

    rm -rf "$d"; SCRATCH=""

    local how="the target files exist, so only validation can be refusing them"
    $as_root || how="run as root for the strong form: here ownership could also explain it"

    if [ -z "$bad" ]; then
        pass "the helper refuses a non-root key file and every malformed name, always exiting 0 ($how)"
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
    grep -qE '^etc/open-bastion/service-accounts\.d$' "$ROOT_DIR/debian/open-bastion.dirs" \
        || missing="$missing debian/.dirs"
    # The RULE, not the string: 'service-accounts.d' also appears in the comment
    # above it, so a bare grep stayed green with the install() deleted.
    grep -A3 'install(DIRECTORY' "$ROOT_DIR/CMakeLists.txt" \
        | grep -q 'DESTINATION /etc/open-bastion/service-accounts.d' \
        || missing="$missing CMakeLists.txt(rule)"
    grep -qE '^%dir %attr\(0755,root,root\) %\{_sysconfdir\}/open-bastion/service-accounts\.d$' \
        "$ROOT_DIR/rpm/open-bastion.spec" || missing="$missing rpm/.spec"
    # 0755 is the whole point: nobody must traverse and read it. A silent
    # return to 0700 in either place makes the helper inert -- exit 0, no
    # output -- which is the failure this is here to prevent. The RPM %attr is
    # matched above; the CMake permissions are checked here.
    local perms
    perms=$(sed -n '/DESTINATION \/etc\/open-bastion\/service-accounts.d/,/^)/p' \
                "$ROOT_DIR/CMakeLists.txt")
    printf '%s' "$perms" | grep -q 'WORLD_READ'    || missing="$missing cmake(no-WORLD_READ)"
    printf '%s' "$perms" | grep -q 'WORLD_EXECUTE' || missing="$missing cmake(no-WORLD_EXECUTE)"
    printf '%s' "$perms" | grep -q 'OWNER_WRITE'   || missing="$missing cmake(no-OWNER_WRITE)"

    if [ -z "$missing" ]; then
        pass "service-accounts.d is created 0755 by all three packaging paths"
    else
        fail "service-accounts.d is created 0755 by all three packaging paths" "$missing"
    fi
}

# ── 7. --enable-service-keys, and the silence without it ────────────────────
#
# Batch 2 of #263: the setup scripts can now write the sshd drop-in. Opt-in,
# because it changes sshd for every session on the host, not only for service
# accounts.
#
# The half that matters most is the default one: without the flag, nothing must
# change. An opt-in that leaks is worse than no flag, because the operator
# believes the host is untouched.
test_service_keys_flag() {
    local bad="" f
    for f in ob-bastion-setup ob-backend-setup; do
        local src="$ROOT_DIR/scripts/$f"
        grep -q 'ENABLE_SERVICE_KEYS=false' "$src" || bad="$bad $f(not-default-off)"
        grep -q -- '--enable-service-keys)' "$src" || bad="$bad $f(no-flag)"
        grep -q -- '--enable-service-keys ' "$src" || bad="$bad $f(not-in-usage)"
        grep -q 'configure_service_account_keys || exit 1' "$src" || bad="$bad $f(never-called)"

        # The guard: the function must return before doing anything when the
        # flag is off. Checked on the first lines of the function, not merely
        # "the variable appears somewhere".
        sed -n '/^configure_service_account_keys() {/,/^}/p' "$src" \
            | head -4 | grep -q 'ENABLE_SERVICE_KEYS" != "true"' \
            || bad="$bad $f(no-early-return)"

        # It must write ExposeAuthInfo itself. Leaving it to Mode E would ship
        # an AuthorizedKeysCommand whose fingerprint check silently never runs
        # -- the exact half-configuration doc/service-accounts.md warns about.
        sed -n '/^configure_service_account_keys() {/,/^}/p' "$src" \
            | grep -q 'ExposeAuthInfo yes' || bad="$bad $f(no-ExposeAuthInfo)"

        # And the canonical helper path, not a rediscovered one.
        sed -n '/^configure_service_account_keys() {/,/^}/p' "$src" \
            | grep -q "$CANONICAL" || bad="$bad $f(wrong-helper-path)"
    done

    if [ -z "$bad" ]; then
        pass "--enable-service-keys is opt-in, guarded, and writes ExposeAuthInfo with the drop-in"
    else
        fail "--enable-service-keys is opt-in, guarded, and writes ExposeAuthInfo with the drop-in" "$bad"
    fi
}

run_test test_helper_is_packaged
run_test test_one_path_everywhere
run_test test_doc_does_not_claim_pam_is_enough
run_test test_exposeauthinfo_is_always_guarded
run_test test_helper_refusals
run_test test_keys_dir_is_shipped
run_test test_service_keys_flag

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
