#!/bin/bash
# Runtime test for the PAM auth stacks Open Bastion generates (issue #180).
#
# tests/test_ob_pam_stacks.sh checks the TEXT of the generated stacks. Text is
# not behaviour, and that gap let an inverted stack ship: the pair
#
#   auth       [success=1 default=ignore] pam_permit.so
#   auth       required     pam_deny.so
#
# reads as "permit, with a deny backstop" but denies EVERY pam_authenticate().
# Per pam.conf(5) the jump action's side effect is *ignore* for
# pam_authenticate/pam_acct_mgmt/pam_chauthtok/pam_open_session: the jump
# clears pam_deny, lands past the end of the stack, nothing records a positive
# impression, and pam_dispatch() returns PAM_MUST_FAIL_CODE = PAM_PERM_DENIED.
#
# This test therefore builds a tiny libpam client (tests/pam_stack_probe.c,
# using pam_start_confdir()) and runs pam_authenticate() against each stack the
# project generates, asserting the verdict per service:
#
#   * sshd, certificate modes -> DENY.  Refusing password/keyboard-interactive
#     authentication is the point of #180. The certificate path is unaffected:
#     sshd does not call pam_authenticate() for pubkey/certificate auth.
#   * sudo, mode-c            -> SUCCEED.  mode-c is the "SSH keys, sudo
#     without a password" scenario; sudo calls pam_authenticate() whenever it
#     has no valid timestamp, so a denying stack there breaks sudo for good.
#
# Skips cleanly (exit 77, ctest's SKIP_RETURN_CODE) when the PAM development
# headers, a C compiler, or pam_start_confdir() (libpam >= 1.4) are missing, so
# it never turns a build red on a host that cannot run it. It does run locally
# on Debian/Ubuntu with libpam0g-dev installed, and in CI, which installs it.
#
# Stacks built from pam_openbastion.so (modes a/b/d, the Mode E sudo stack) are
# deliberately out of scope: the module is not installed in a test environment,
# so running them would measure dlopen failure, not the stack.
set -uo pipefail

TESTS_PASSED=0
TESTS_FAILED=0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
skip_all() { echo "  SKIP: $1"; echo "=== Skipped (exit 77) ==="; exit 77; }

# shellcheck source=tests/lib_pam_stack.sh
. "$REPO_ROOT/tests/lib_pam_stack.sh"
# shellcheck source=tests/lib_setup_script.sh
. "$REPO_ROOT/tests/lib_setup_script.sh"

# PAM return codes we assert on (values from <security/_pam_types.h>).
PAM_SUCCESS=0
PAM_PERM_DENIED=6
PAM_AUTH_ERR=7

echo "=== Runtime PAM stack test (#180) ==="

# ── Preflight: can we build and run the probe? ──
CC_BIN="${CC:-cc}"
command -v "$CC_BIN" >/dev/null 2>&1 || skip_all "no C compiler ($CC_BIN) available"

TMPDIR_RUN=$(mktemp -d) || skip_all "mktemp failed"
# Replaces lib_setup_script.sh's EXIT trap, so it takes over its directory too.
cleanup() { rm -rf "$TMPDIR_RUN" "$SETUP_LINK_DIR"; }
trap cleanup EXIT

PROBE="$TMPDIR_RUN/pam_stack_probe"
if ! "$CC_BIN" -o "$PROBE" "$REPO_ROOT/tests/pam_stack_probe.c" -lpam 2>"$TMPDIR_RUN/cc.log"; then
    echo "    (compiler output: $(tr '\n' ' ' <"$TMPDIR_RUN/cc.log"))"
    skip_all "cannot build tests/pam_stack_probe.c (libpam0g-dev / pam_start_confdir missing?)"
fi

CONFDIR="$TMPDIR_RUN/pam.d"
mkdir -p "$CONFDIR"

# Sanity: the stock modules the certificate stacks are made of must be usable
# here, otherwise every verdict below would just be measuring a missing module.
printf 'auth       required     pam_permit.so\n' >"$CONFDIR/obprobe_selftest"
if [ "$("$PROBE" "$CONFDIR" obprobe_selftest 2>/dev/null)" != "$PAM_SUCCESS" ]; then
    skip_all "pam_permit.so is not usable in this environment"
fi

# run_stack <service> <auth stack text> -> echoes the pam_authenticate() rc
run_stack() {
    local service="$1" content="$2"
    printf '%s\n' "$content" | pam_auth_lines >"$CONFDIR/$service"
    "$PROBE" "$CONFDIR" "$service" 2>/dev/null
}

rc_name() {
    case "$1" in
        0) echo "PAM_SUCCESS" ;;
        6) echo "PAM_PERM_DENIED" ;;
        7) echo "PAM_AUTH_ERR" ;;
        *) echo "rc=$1" ;;
    esac
}

# assert_runtime <label> <service> <expected rc> <stack text>
assert_runtime() {
    local label="$1" service="$2" expected="$3" content="$4" got
    got=$(run_stack "$service" "$content")
    if [ "$got" = "$expected" ]; then
        pass "$label -> $got ($(rc_name "$got"))"
    else
        fail "$label" "expected $expected ($(rc_name "$expected")), got ${got:-<none>} ($(rc_name "${got:-none}"))
stack:
$(printf '%s\n' "$content" | pam_auth_lines)"
    fi
}

# assert_denied <label> <service> <stack text>
# A denying stack may legitimately answer PAM_AUTH_ERR (pam_deny) or
# PAM_PERM_DENIED (fell off the end of the stack); both refuse the login.
assert_denied() {
    local label="$1" service="$2" content="$3" got
    got=$(run_stack "$service" "$content")
    if [ "$got" = "$PAM_AUTH_ERR" ] || [ "$got" = "$PAM_PERM_DENIED" ]; then
        pass "$label -> $got ($(rc_name "$got"))"
    else
        fail "$label" "expected a denial, got ${got:-<none>} ($(rc_name "${got:-none}"))
stack:
$(printf '%s\n' "$content" | pam_auth_lines)"
    fi
}

# ── Canaries: the harness must reproduce the two known verdicts ──
# These encode the review finding for PR #220 so it can never come back.
echo "--- canaries (what the shapes actually do) ---"
assert_runtime "bare 'auth required pam_permit.so' (the #180 bug) succeeds" \
    obprobe_bare_permit "$PAM_SUCCESS" \
    "auth       required     pam_permit.so"
assert_runtime "the permit-jump/deny PAIR denies (no trailing permit)" \
    obprobe_pair "$PAM_PERM_DENIED" \
    "auth       [success=1 default=ignore] pam_permit.so
auth       required     pam_deny.so"
assert_runtime "the canonical 3-line fail-closed permit succeeds" \
    obprobe_canonical "$PAM_SUCCESS" \
    "auth       [success=1 default=ignore] pam_permit.so
auth       required     pam_deny.so
auth       required     pam_permit.so"
assert_runtime "'auth required pam_deny.so' alone denies" \
    obprobe_deny "$PAM_AUTH_ERR" \
    "auth       required     pam_deny.so"

# ── The Debian postinst generators ──
echo "--- debian/open-bastion.postinst ---"
POSTINST="$REPO_ROOT/debian/open-bastion.postinst"

extract_func() {
    awk -v f="$1" '
        $0 ~ "^"f"\\(\\) \\{" { p = 1 }
        p { print }
        p && /^\}$/ { exit }
    ' "$POSTINST"
}

if ! eval "$(extract_func generate_pam_sshd)
$(extract_func generate_pam_sudo)" 2>/dev/null; then
    fail "postinst PAM generators extracted" "generate_pam_sshd/generate_pam_sudo not found in $POSTINST"
else
    pass "postinst PAM generators extracted"
    assert_denied "postinst /etc/pam.d/sshd mode-c denies" obprobe_postinst_sshd_c \
        "$(generate_pam_sshd mode-c grp)"
    # The one stack that MUST succeed: mode-c is passwordless sudo.
    assert_runtime "postinst /etc/pam.d/sudo mode-c succeeds" obprobe_postinst_sudo_c \
        "$PAM_SUCCESS" "$(generate_pam_sudo mode-c grp)"
fi

# ── The setup scripts ──
echo "--- scripts/ob-bastion-setup, as ob-bastion-setup and ob-backend-setup ---"

# Load the setup script under one of its names (which picks the role) without
# running main(), then run configure_pam_sshd in dry-run mode and keep its
# generated stack.
setup_sshd_stack() {
    local script="$1"
    shift
    (
        load_setup_as "$script" || exit 1
        parse_args "$@" >/dev/null 2>&1
        configure_pam_sshd 2>/dev/null
    )
}

for spec in "ob-bastion-setup:-p https://x --dry-run" \
            "ob-backend-setup:-p https://x -g g --dry-run"; do
    script="${spec%%:*}"
    # shellcheck disable=SC2086
    set -- ${spec#*:}
    out=$(setup_sshd_stack "$script" "$@")
    if [ -z "$(printf '%s\n' "$out" | pam_auth_lines)" ]; then
        fail "$script generated sshd stack denies" "no auth line in dry-run output"
    else
        assert_denied "$script generated /etc/pam.d/sshd denies" \
            "obprobe_${script//-/_}" "$out"
    fi
done

# ── The demo images and the stacks documented for copy-paste ──
# These files hold several stacks each (sshd + sudo, or one per mode). Run every
# contiguous run of auth lines built solely from pam_permit/pam_deny — i.e. the
# certificate modes. Stacks that need pam_openbastion.so are skipped, as
# explained at the top of this file.
echo "--- demo images and documented stacks (certificate modes only) ---"

stock_auth_blocks() {
    sed -e 's/\\n\\[[:space:]]*$//' -e 's/^[[:space:]]*//' "$1" |
        awk '
            /^auth[[:space:]]/ { block = block $0 "\n"; next }
            { if (block != "") { printf "%s\f", block; block = "" } }
            END { if (block != "") printf "%s\f", block }
        '
}

block_n=0
for f in docker-demo-cert/bastion/Dockerfile \
         docker-demo-cert/bastion/entrypoint.sh \
         docker-demo-cert/backend/Dockerfile \
         docker-demo-cert/backend/entrypoint.sh \
         docker-demo-maxsec/bastion/Dockerfile \
         docker-demo-maxsec/backend/Dockerfile \
         docker-demo-maxsec/backend/entrypoint.sh \
         doc/pam-modes.rst \
         doc/admin-guide.rst \
         doc/presentation.rst \
         docker-demo-cert/README.md; do
    if [ ! -f "$REPO_ROOT/$f" ]; then
        fail "$f certificate-mode stacks deny" "file not found"
        continue
    fi
    file_blocks=0
    while IFS= read -r -d $'\f' block; do
        [ -n "$block" ] || continue
        # Keep only blocks made purely of the stock modules.
        if printf '%s\n' "$block" | grep -qvE '^[[:space:]]*$|pam_permit\.so|pam_deny\.so'; then
            continue
        fi
        block_n=$((block_n + 1))
        file_blocks=$((file_blocks + 1))
        assert_denied "$f certificate-mode stack #$file_blocks denies" \
            "obprobe_block_$block_n" "$block"
    done < <(stock_auth_blocks "$REPO_ROOT/$f")
    if [ "$file_blocks" -eq 0 ]; then
        fail "$f certificate-mode stacks deny" "no stock-module auth block found — did this file change shape?"
    fi
done
if [ "$block_n" -eq 0 ]; then
    fail "certificate-mode stacks were found at all" "nothing was actually exercised"
fi

echo ""
echo "=== Results: $TESTS_PASSED/$((TESTS_PASSED + TESTS_FAILED)) passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
