#!/bin/bash
# test_ob_fp_daemon.sh
#
# Guards the fingerprint spool's trust root (issue #249).
#
# Before #249 the AuthorizedPrincipalsCommand helper wrote
# /run/open-bastion/ssh-fp/<anchor>.fp itself. sshd requires that helper to run
# unprivileged, so the spool was 0700 nobody and the integrity of the
# fingerprint binding rested on a shared, low-trust account. ob-fp-daemon takes
# the deposit over a unix socket instead and writes the spool as root.
#
# The property that actually matters is NOT "a deposit produces a drop" -- it
# is that a client cannot choose WHICH session it deposits for. The daemon
# derives the sshd anchor from the depositing process's own /proc ancestry, so
# these tests run ob-fp-submit under a process renamed "sshd-session" and check
# that the drop lands on that anchor and nowhere else.
#
# Covered:
#   - a deposit under an sshd-session anchor writes <anchor>.fp and <anchor>.key
#   - the .fp drop is byte-for-byte what the pre-#249 helper wrote
#   - drops are 0600 and owned by the user running the daemon
#   - the anchor is derived, not received: extra lines in the request cannot
#     redirect the drop to another PID
#   - a deposit with NO sshd-session ancestor is refused outright
#   - a malformed fingerprint is refused
#   - a malformed algorithm/blob degrades to .fp only, it does not fail
#   - the daemon re-asserts 0700 on the spool directory it is handed
#   - a deposit from a uid that does not own the socket is refused
#   - an anchor whose real uid is not root is refused (strict-uid build)
#   - neither shipped helper writes the spool directly any more
#
# The daemon is normally socket-activated by systemd with Accept=yes, which
# hands it the connection on fd 0/1. Here `socat` plays systemd; the test skips
# if it is absent rather than pretending to have run.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# The relaxed test build (see tests/CMakeLists.txt), not the shipped binary:
# its spool and socket paths live in the build tree.
DAEMON="$ROOT_DIR/build/tests/ob-fp-daemon-testbuild"
[ -x "$DAEMON" ] || DAEMON=""
SUBMIT=""
for c in "$ROOT_DIR/build/ob-fp-submit" "$(command -v ob-fp-submit 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { SUBMIT="$c"; break; }
done

if [ -z "$DAEMON" ] || [ -z "$SUBMIT" ]; then
    echo "SKIP: ob-fp-daemon / ob-fp-submit not built (run cmake --build build)"
    exit 0
fi
command -v socat >/dev/null 2>&1 || { echo "SKIP: socat is required to stand in for systemd"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is required"; exit 0; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${SOCAT_PID:-}" ] && kill "$SOCAT_PID" 2>/dev/null' EXIT

FP="SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHI"
ALG="ssh-ed25519"
BLOB="AAAAC3NzaC1lZDI1NTE5AAAAIExampleBlobForTesting0123456789abcd"

# The shipped ob-fp-daemon hard-codes /run/open-bastion/{ssh-fp,ssh-fp.sock}.
# A test can only reach those through a mount namespace, and unprivileged user
# namespaces are restricted on Ubuntu 24.04 -- a test that needed one would SKIP
# in CI, and a skip reads as a pass. So the suite drives ob-fp-daemon-testbuild:
# the same source with the two paths redefined into the build tree. Nothing
# about the logic under test differs; only two string constants do.
DAEMON_SPOOL="$(dirname "$DAEMON")/fp-spool"
SOCK="$(dirname "$DAEMON")/fp.sock"

# Run one deposit end to end.
#   $1 = name the submitting process runs under ("sshd-session" to look like a
#        real anchor, anything else to look like a stray process)
#   $2 = request body sent to the daemon
#   $3 = mode to pre-create the spool directory with (default 700)
# Sets DEPOSIT_RC, DEPOSIT_ERR, ANCHOR and SPOOL_MODE.
deposit() {
    local comm="$1" body="$2" premode="${3:-700}"
    printf '%s' "$body" > "$WORK/body"
    rm -rf "$DAEMON_SPOOL"; mkdir -p "$DAEMON_SPOOL"; chmod "$premode" "$DAEMON_SPOOL"
    rm -f "$SOCK"
    : > "$WORK/submit.err"; : > "$WORK/anchor.pid"

    # systemd's Accept=yes hands the daemon one connection on fd 0 and fd 1.
    # ",nofork" is essential: plain EXEC: makes socat RELAY through a pipe, so
    # SO_PEERCRED would report socat instead of the depositing process and every
    # ancestry check below would be measuring the wrong tree.
    socat UNIX-LISTEN:"$SOCK",fork EXEC:"$DAEMON",nofork 2>"$WORK/daemon.err" &
    SOCAT_PID=$!
    for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.05; done

    # Rename the submitting process so the daemon's /proc walk sees the anchor
    # we want, then submit from a child of it -- exactly the shape sshd produces
    # (ob-fp-submit <- ob-ssh-principals <- sshd-session).
    OB_FP_SOCKET="$SOCK" python3 - "$comm" "$SUBMIT" "$WORK/body" \
        "$WORK/anchor.pid" "$WORK/submit.err" <<'PY_EOF'
import ctypes, os, subprocess, sys
comm, submit, body_path, anchor_path, err_path = sys.argv[1:6]
libc = ctypes.CDLL("libc.so.6", use_errno=True)
# PR_SET_NAME = 15. This is what makes the process look like an sshd anchor.
libc.prctl(15, comm.encode(), 0, 0, 0)
open(anchor_path, "w").write(str(os.getpid()))
with open(body_path, "rb") as b, open(err_path, "wb") as e:
    r = subprocess.run([submit], stdin=b, stderr=e, stdout=subprocess.DEVNULL)
sys.exit(r.returncode)
PY_EOF
    DEPOSIT_RC=$?
    kill "$SOCAT_PID" 2>/dev/null; wait "$SOCAT_PID" 2>/dev/null; SOCAT_PID=""

    DEPOSIT_ERR=$(cat "$WORK/submit.err" 2>/dev/null)
    # A connect failure is a broken harness, not a refusal. Without this, every
    # "is it refused?" test below would pass by never reaching the daemon.
    case "$DEPOSIT_ERR" in
        *"cannot reach the fingerprint sink"*)
            echo "  HARNESS ERROR: the daemon was never reached: $DEPOSIT_ERR" >&2
            DEPOSIT_RC=99 ;;
    esac
    ANCHOR=$(cat "$WORK/anchor.pid" 2>/dev/null)
    SPOOL_MODE=$(stat -c '%a' "$DAEMON_SPOOL" 2>/dev/null)
}

# ── 1. The nominal deposit ────────────────────────────────────────────────────
test_nominal() {
    deposit sshd-session "$FP
$ALG
$BLOB
"
    if [ "$DEPOSIT_RC" != "0" ]; then
        fail "a deposit under an sshd-session anchor is accepted" \
             "rc=$DEPOSIT_RC err=$DEPOSIT_ERR"
        return
    fi
    if [ ! -f "$DAEMON_SPOOL/$ANCHOR.fp" ]; then
        fail "the drop lands on the derived anchor" \
             "no $ANCHOR.fp; spool holds: $(ls "$DAEMON_SPOOL" 2>/dev/null | tr '\n' ' ')"
        return
    fi
    pass "a deposit under an sshd-session anchor lands on that anchor"

    # Byte-for-byte the pre-#249 content: an older pam_openbastion reads this
    # file and must not be able to tell that a daemon wrote it.
    if [ "$(cat "$DAEMON_SPOOL/$ANCHOR.fp")" = "$FP" ]; then
        pass "the .fp drop keeps its exact pre-#249 content"
    else
        fail "the .fp drop keeps its exact pre-#249 content" \
             "got '$(cat "$DAEMON_SPOOL/$ANCHOR.fp")'"
    fi

    if [ -f "$DAEMON_SPOOL/$ANCHOR.key" ] \
       && grep -q '^v=1$' "$DAEMON_SPOOL/$ANCHOR.key" \
       && grep -q "^alg=$ALG$" "$DAEMON_SPOOL/$ANCHOR.key" \
       && grep -q "^key=$BLOB$" "$DAEMON_SPOOL/$ANCHOR.key"; then
        pass "the v1 .key drop carries v=1 / alg= / key="
    else
        fail "the v1 .key drop carries v=1 / alg= / key=" \
             "got '$(cat "$DAEMON_SPOOL/$ANCHOR.key" 2>/dev/null | tr '\n' ' ')'"
    fi

    local modes
    modes=$(find "$DAEMON_SPOOL" -type f -printf '%m ' 2>/dev/null)
    if [ "$modes" = "600 600 " ] || [ "$modes" = "600 600" ]; then
        pass "drops are mode 0600"
    else
        fail "drops are mode 0600" "modes: $modes"
    fi
}

# ── 2. The anchor is derived, never received ─────────────────────────────────
# This is the security property. A client that appends a PID of its choosing
# must not be able to steer the drop: the daemon reads only three lines and
# keys the drop on its own view of the peer's ancestry.
test_anchor_is_not_client_controlled() {
    deposit sshd-session "$FP
$ALG
$BLOB
99999
anchor=99999
"
    if [ -f "$DAEMON_SPOOL/99999.fp" ]; then
        fail "a client cannot name the anchor it deposits for" \
             "the request steered the drop to PID 99999"
        return
    fi
    if [ "$DEPOSIT_RC" = "0" ] && [ -f "$DAEMON_SPOOL/$ANCHOR.fp" ]; then
        pass "extra request lines cannot redirect the drop to another PID"
    else
        # Refusing outright is also an acceptable answer here; what must never
        # happen is a drop on the attacker's chosen PID.
        if [ "$DEPOSIT_RC" = "99" ]; then
            fail "extra request lines cannot redirect the drop" "harness never reached the daemon"
        else
            pass "extra request lines cannot redirect the drop (deposit refused)"
        fi
    fi
}

# ── 3. No sshd-session ancestor: refused ─────────────────────────────────────
test_requires_sshd_ancestor() {
    deposit definitely-not-sshd "$FP
$ALG
$BLOB
"
    if [ "$DEPOSIT_RC" != "0" ] && [ "$DEPOSIT_RC" != "99" ] \
       && [ -z "$(ls -A "$DAEMON_SPOOL" 2>/dev/null)" ]; then
        pass "a deposit outside any SSH connection is refused and writes nothing"
    else
        fail "a deposit outside any SSH connection is refused" \
             "rc=$DEPOSIT_RC spool: $(ls -A "$DAEMON_SPOOL" 2>/dev/null | tr '\n' ' ')"
    fi
}

# ── 4. Input validation ──────────────────────────────────────────────────────
test_bad_fingerprint_refused() {
    deposit sshd-session "MD5:not-a-sha256-fingerprint
$ALG
$BLOB
"
    if [ "$DEPOSIT_RC" != "0" ] && [ "$DEPOSIT_RC" != "99" ] \
       && [ -z "$(ls -A "$DAEMON_SPOOL" 2>/dev/null)" ]; then
        pass "a malformed fingerprint is refused and writes nothing"
    else
        fail "a malformed fingerprint is refused" \
             "rc=$DEPOSIT_RC spool: $(ls -A "$DAEMON_SPOOL" 2>/dev/null | tr '\n' ' ')"
    fi
}

test_bad_algorithm_degrades() {
    deposit sshd-session "$FP
not a valid; algorithm
$BLOB
"
    # The fingerprint is what the LLNG binding needs; losing the key metadata
    # must not cost us the binding as well.
    if [ "$DEPOSIT_RC" = "0" ] \
       && [ -f "$DAEMON_SPOOL/$ANCHOR.fp" ] && [ ! -f "$DAEMON_SPOOL/$ANCHOR.key" ]; then
        pass "a malformed algorithm drops .key but keeps the fingerprint"
    else
        fail "a malformed algorithm drops .key but keeps the fingerprint" \
             "rc=$DEPOSIT_RC spool: $(ls -A "$DAEMON_SPOOL" 2>/dev/null | tr '\n' ' ')"
    fi
}

# ── 5. The daemon owns the directory ─────────────────────────────────────────
# An upgraded host still has the pre-#249 0700 *nobody* directory. Leaving it
# would keep the old trust root while looking fixed, so the daemon re-asserts
# ownership and mode on every deposit.
test_daemon_reasserts_spool_mode() {
    deposit sshd-session "$FP
$ALG
$BLOB
" 777
    local mode="$SPOOL_MODE"
    if [ "$mode" = "700" ]; then
        pass "the daemon re-asserts 0700 on a loosened spool directory"
    else
        fail "the daemon re-asserts 0700 on a loosened spool directory" \
             "mode is $mode"
    fi
}

# ── 5b. The uid gate ─────────────────────────────────────────────────────────
# The daemon takes the uid allowed to deposit from the owner of its listening
# socket (SocketUser=nobody in the shipped unit). Every other test here connects
# to that socket, so the depositor and the owner are the same user and the gate
# is satisfied for the right reason but never exercised in the negative.
#
# Here socat listens somewhere else, so the daemon stats a socket that does not
# exist, falls back to the shipped default (nobody), and must refuse an ordinary
# user. Without this, deleting the SO_PEERCRED check entirely would still pass
# the whole suite.
test_uid_gate_refuses_a_stranger() {
    if [ "$(id -u)" = "0" ]; then
        # root is accepted by design (it can write the spool anyway).
        pass "uid gate: skipped, running as root"
        return
    fi
    local other
    other="$(dirname "$DAEMON")/other.sock"
    rm -rf "$DAEMON_SPOOL"; mkdir -p "$DAEMON_SPOOL"; chmod 700 "$DAEMON_SPOOL"
    rm -f "$other" "$SOCK"
    printf '%s\n%s\n%s\n' "$FP" "$ALG" "$BLOB" > "$WORK/body"

    socat UNIX-LISTEN:"$other",fork EXEC:"$DAEMON",nofork 2>/dev/null &
    local sp=$!
    for _ in $(seq 1 50); do [ -S "$other" ] && break; sleep 0.05; done

    local err rc
    err=$(OB_FP_SOCKET="$other" python3 - "$SUBMIT" "$WORK/body" <<'PY_EOF' 2>&1
import ctypes, subprocess, sys
submit, body_path = sys.argv[1:3]
ctypes.CDLL("libc.so.6").prctl(15, b"sshd-session", 0, 0, 0)
with open(body_path, "rb") as b:
    r = subprocess.run([submit], stdin=b, stderr=subprocess.PIPE,
                       stdout=subprocess.DEVNULL)
# The daemon's reason is on the submitter's stderr; hand it to the shell.
sys.stdout.write(r.stderr.decode("utf-8", "replace"))
sys.exit(r.returncode)
PY_EOF
    ); rc=$?
    kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
    rm -f "$other"

    if [ "$rc" != "0" ] \
       && [ -z "$(ls -A "$DAEMON_SPOOL" 2>/dev/null)" ] \
       && printf '%s' "$err" | grep -q "expected the principals helper uid"; then
        pass "a deposit from a uid that does not own the socket is refused"
    else
        fail "a deposit from a uid that does not own the socket is refused" \
             "rc=$rc err=$(printf '%s' "$err" | tr '\n' ' ')"
    fi
}

# ── 5c. The anchor's real uid must be root ───────────────────────────────────
# The anchor is chosen by process NAME, and prctl(PR_SET_NAME) takes fifteen
# characters while "sshd-session" is twelve -- so a local user can put a process
# called sshd-session in their own ancestry. Requiring the anchor to be
# real-uid root is what excludes it.
#
# Every other test here drives the relaxed build, whose fake anchor is owned by
# the user running the suite and therefore satisfies that check either way:
# deleting it outright would leave the suite green (confirmed by mutation). This
# one drives ob-fp-daemon-strictuid, which compiles the literal "must be root"
# the shipped binary has, and must refuse the very same anchor.
test_anchor_must_be_root_owned() {
    local strict
    strict="$(dirname "$DAEMON")/ob-fp-daemon-strictuid"
    if [ ! -x "$strict" ]; then
        fail "the anchor-owner check is live" "ob-fp-daemon-strictuid not built"
        return
    fi
    if [ "$(id -u)" = "0" ]; then
        pass "anchor-owner check: skipped, running as root"
        return
    fi
    # Exactly the strict build's compiled-in OB_FP_SOCKET, so helper_uid()
    # resolves to us and the uid gate passes -- otherwise that gate fires first
    # and we would be asserting on the wrong refusal.
    local sock
    sock="$(dirname "$DAEMON")/fp-strict.sock"
    rm -f "$sock"
    printf '%s\n%s\n%s\n' "$FP" "$ALG" "$BLOB" > "$WORK/body"

    socat UNIX-LISTEN:"$sock",fork EXEC:"$strict",nofork 2>/dev/null &
    local sp=$!
    for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.05; done

    local err rc
    err=$(OB_FP_SOCKET="$sock" python3 - "$SUBMIT" "$WORK/body" <<'PY_EOF' 2>&1
import ctypes, subprocess, sys
submit, body_path = sys.argv[1:3]
ctypes.CDLL("libc.so.6").prctl(15, b"sshd-session", 0, 0, 0)
with open(body_path, "rb") as b:
    r = subprocess.run([submit], stdin=b, stderr=subprocess.PIPE,
                       stdout=subprocess.DEVNULL)
sys.stdout.write(r.stderr.decode("utf-8", "replace"))
sys.exit(r.returncode)
PY_EOF
    ); rc=$?
    kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
    rm -f "$sock"

    if [ "$rc" != "0" ] && printf '%s' "$err" | grep -q "not root: refusing"; then
        pass "an anchor whose real uid is not root is refused"
    else
        fail "an anchor whose real uid is not root is refused" \
             "rc=$rc err=$(printf '%s' "$err" | tr '\n' ' ')"
    fi
}

# ── 6. Neither shipped helper writes the spool any more ──────────────────────
# The point of #249 is that the unprivileged principals helper no longer holds
# the trust root. A future edit that reintroduces a direct write would undo it
# silently, so assert it against the shipped scripts.
test_helpers_do_not_write_the_spool() {
    local offenders=""
    # The helpers are shipped data since ob-post-upgrade: one copy in share/,
    # installed to /usr/lib/open-bastion, used by both setup scripts and by
    # ob-post-upgrade. Strip comments first: the helper's own header still
    # NAMES the spool path, and matching that would flag documentation as a
    # direct write.
    for f in share/ob-ssh-principals.bastion share/ob-ssh-principals.backend; do
        if sed 's/[[:space:]]*#.*$//' "$ROOT_DIR/$f" \
             | grep -qE '(mv|cp|tee|mktemp)[^|]*(\$\{?SPOOL_DIR|/run/open-bastion/ssh-fp/)'; then
            offenders="$offenders $f"
        fi
    done
    if [ -z "$offenders" ]; then
        pass "neither principals helper writes the spool directly"
    else
        fail "neither principals helper writes the spool directly" "$offenders"
    fi
}

test_helpers_deposit_via_submit() {
    local missing=""
    for f in share/ob-ssh-principals.bastion share/ob-ssh-principals.backend; do
        grep -q 'ob-fp-submit' "$ROOT_DIR/$f" || missing="$missing $f"
    done
    if [ -z "$missing" ]; then
        pass "both principals helpers deposit through ob-fp-submit"
    else
        fail "both principals helpers deposit through ob-fp-submit" "$missing"
    fi
}

# ── 7. The shipped spool is root-owned ───────────────────────────────────────
test_setup_scripts_own_the_spool_as_root() {
    local bad=""
    for f in scripts/ob-bastion-setup scripts/ob-post-upgrade; do
        grep -qE 'chown[[:space:]]+nobody(:[a-z]+)?' "$ROOT_DIR/$f" && bad="$bad $f"
        # Anchored on the spool directory itself, not on "an 0700 somewhere in
        # the file": the point is that THIS directory is root's, and an
        # assertion that accepts any 0700 install would pass on a script that
        # stopped touching it.
        grep -qE '(install -d -m 0700 -o root -g root "?\$(spool_dir|SPOOL_DIR)"?|chmod 0700 "\$(spool_dir|SPOOL_DIR)")' \
            "$ROOT_DIR/$f" || bad="$bad $f(spool-not-0700-root)"
    done
    # And the boot-time rule, now shipped once rather than written twice.
    grep -q 'd /run/open-bastion/ssh-fp   0700 root root' \
        "$ROOT_DIR/share/ob-fp-spool.tmpfiles" || bad="$bad tmpfiles"
    if [ -z "$bad" ]; then
        pass "the setup script and ob-post-upgrade create the spool 0700 root, in place and at boot"
    else
        fail "the setup script and ob-post-upgrade create the spool 0700 root" "$bad"
    fi
}

echo "=== ob-fp-daemon (issue #249) ==="
run_test test_nominal
run_test test_anchor_is_not_client_controlled
run_test test_requires_sshd_ancestor
run_test test_bad_fingerprint_refused
run_test test_bad_algorithm_degrades
run_test test_daemon_reasserts_spool_mode
run_test test_uid_gate_refuses_a_stranger
run_test test_anchor_must_be_root_owned
run_test test_helpers_do_not_write_the_spool
run_test test_helpers_deposit_via_submit
run_test test_setup_scripts_own_the_spool_as_root

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
