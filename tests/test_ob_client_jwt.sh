#!/bin/bash
# test_ob_client_jwt.sh
#
# Guards the client_secret_jwt assertion helper (issue #256).
#
# ob-enroll authenticates to the OIDC token endpoint with a client_secret_jwt
# assertion. It used to build it in shell, ending in
#
#     openssl dgst -sha256 -hmac "$client_secret" -binary
#
# and openssl has no form that takes the HMAC key anywhere but argv.
# /proc/<pid>/cmdline is world-readable, so the host's OIDC client secret was
# readable by any local user -- once per poll of the device-grant loop, of the
# order of sixty times over five minutes, while an operator is away in a
# browser approving the grant.
#
# Two things are asserted here, and the second is the one that matters:
#
#   1. the assertion is correct -- claims per RFC 7523, and a signature an
#      independent implementation agrees with;
#   2. the secret is not observable from outside the process. That is checked
#      by reading /proc/<pid>/cmdline of the running helper, not by reading the
#      source, because "we pass it on stdin now" is exactly the kind of claim
#      that survives a refactor in prose while stopping being true in fact.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
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

HELPER=""
for c in "${OB_BUILD_DIR:-$ROOT_DIR/build}/ob-client-jwt" "$(command -v ob-client-jwt 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { HELPER="$c"; break; }
done
[ -n "$HELPER" ] || { echo "SKIP: ob-client-jwt not built (cmake --build build)"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is required"; exit 0; }

AUD="https://sso.example.com/oauth2/token"
CID="pam-access"
# Deliberately awkward: spaces, quotes, a dollar and a backslash all survive a
# pipe but would need quoting on a command line.
SECRET='s3cr3t with "quotes" and $dollar and \back'

echo "=== ob-client-jwt: client_secret_jwt assertions (issue #256) ==="

# ── 1. The assertion verifies against an independent implementation ──────────
test_signature_is_correct() {
    local jwt
    jwt=$(printf '%s' "$SECRET" | "$HELPER" --client-id "$CID" --audience "$AUD") || {
        fail "the assertion verifies against an independent HMAC" "helper failed"
        return
    }
    if python3 - "$SECRET" "$jwt" <<'PY'
import sys, hmac, hashlib, base64
secret, jwt = sys.argv[1], sys.argv[2]
h, p, sig = jwt.split('.')
mac = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
sys.exit(0 if base64.urlsafe_b64encode(mac).decode().rstrip('=') == sig else 1)
PY
    then
        pass "the assertion verifies against an independent HMAC"
    else
        fail "the assertion verifies against an independent HMAC"
    fi
}

# ── 2. The claims are the ones RFC 7523 asks for ─────────────────────────────
test_claims() {
    local jwt
    jwt=$(printf '%s' "$SECRET" | "$HELPER" --client-id "$CID" --audience "$AUD")
    local report
    report=$(python3 - "$jwt" "$CID" "$AUD" <<'PY'
import sys, json, base64
jwt, cid, aud = sys.argv[1], sys.argv[2], sys.argv[3]
def d(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
h, p, _ = jwt.split('.')
head, pay = json.loads(d(h)), json.loads(d(p))
bad = []
if head != {"alg": "HS256", "typ": "JWT"}: bad.append(f"header={head}")
for k, v in (("iss", cid), ("sub", cid), ("aud", aud)):
    if pay.get(k) != v: bad.append(f"{k}={pay.get(k)!r}")
if pay.get("exp", 0) - pay.get("iat", 0) != 300: bad.append("exp-iat != 300")
if len(str(pay.get("jti", ""))) != 36: bad.append("jti is not a uuid")
print(" ".join(bad))
PY
)
    if [ -z "$report" ]; then
        pass "iss, sub, aud, exp, iat and jti are as RFC 7523 requires"
    else
        fail "iss, sub, aud, exp, iat and jti are as RFC 7523 requires" "$report"
    fi
}

# ── 3. A fresh jti per call: it is the portal's replay key ───────────────────
test_fresh_jti() {
    local a b
    a=$(printf '%s' "$SECRET" | "$HELPER" --client-id "$CID" --audience "$AUD" | cut -d. -f2)
    b=$(printf '%s' "$SECRET" | "$HELPER" --client-id "$CID" --audience "$AUD" | cut -d. -f2)
    if [ -n "$a" ] && [ "$a" != "$b" ]; then
        pass "each call carries a fresh jti"
    else
        fail "each call carries a fresh jti" "identical payloads"
    fi
}

# ── 4. THE POINT: the secret is not visible in any process's argv ────────────
#
# Read from outside, the way any local user would: a slow secret producer keeps
# the helper alive long enough to sample /proc.
#
# The scan is over EVERY process, not just the helper's own pid. Scanning only
# the helper would miss the regression that actually threatens this -- a helper
# that shells out to `openssl dgst -hmac "$secret"` leaks from a *child*, and
# the helper's own cmdline stays clean. That is precisely the code this change
# removed, so it is precisely the shape a regression would take.
#
# (An interface change -- teaching the helper to take --secret -- is caught by
# the refusals test below instead, since it means accepting an option that does
# not exist. It cannot be caught here: the shipped invocation only ever feeds
# stdin, so no mutation of the helper alone puts the marker on this cmdline.)
test_secret_never_in_proc() {
    local marker="MARKER-$$-do-not-appear-in-proc"
    local fifo="${TMPDIR:-/tmp}/objwt.$$.fifo"
    local pat="${TMPDIR:-/tmp}/objwt.$$.pat"
    mkfifo "$fifo" || { fail "the secret never reaches any process's argv" "mkfifo"; return; }
    # The marker goes in a file, and every scan uses -f. Putting it in a grep
    # argument would plant it in the scanner's own argv, and a scan that starts
    # while a previous one is still exiting then finds it and reports a leak
    # that is entirely the test's own doing. That happened; this is the fix.
    printf '%s\n' "$marker" > "$pat"

    # Feed the secret slowly so the helper is still running when we look.
    ( exec >"$fifo"; printf '%s' "$marker"; sleep 2 ) &
    local feeder=$!

    "$HELPER" --client-id "$CID" --audience "$AUD" < "$fifo" >/dev/null 2>&1 &
    local hpid=$!

    # observed: proof we actually caught the process alive. Without it, a helper
    # that exited too fast to sample would make this test pass by never looking.
    local seen="" observed=""
    for _ in $(seq 1 20); do
        local cl="" en=""
        { cl=$(tr '\0' ' ' < "/proc/$hpid/cmdline"); } 2>/dev/null
        [ -n "$cl" ] && observed=yes

        # Every process, so a leak from a child (the openssl shape) is caught.
        if grep -rlFf "$pat" /proc/[0-9]*/cmdline 2>/dev/null | grep -q .; then
            seen="cmdline"
        fi
        # environ is 0400 owner-only, unlike world-readable cmdline; this test
        # runs as the owner, so it sees the worst case.
        { en=$(tr '\0' '\n' < "/proc/$hpid/environ"); } 2>/dev/null
        printf '%s' "$en" | grep -qFf "$pat" && seen="$seen environ"
        [ -n "$seen" ] && break
        sleep 0.1
    done

    wait "$feeder" 2>/dev/null
    wait "$hpid" 2>/dev/null
    rm -f "$fifo" "$pat"

    if [ -z "$observed" ]; then
        fail "the secret never reaches any process's argv, the helper's or a child's" \
             "never caught the helper running, so nothing was actually checked"
    elif [ -z "$seen" ]; then
        pass "the secret never reaches any process's argv, the helper's or a child's"
    else
        fail "the secret never reaches any process's argv, the helper's or a child's" \
             "found in: $seen"
    fi
}

# ── 5. The old shell path leaked, and this test can see it ───────────────────
#
# Without this, test 4 proves nothing: a probe that never catches anything
# passes just as happily against a helper that does leak. So run the exact
# openssl invocation ob-enroll used to make, and require the probe to find it.
test_probe_catches_the_old_leak() {
    command -v openssl >/dev/null 2>&1 || { pass "(skipped: no openssl to demonstrate the leak)"; return; }
    local marker="MARKER-$$-old-leak"
    local pat="${TMPDIR:-/tmp}/objwt.$$.leak.pat"
    printf '%s\n' "$marker" > "$pat"

    # The line as it was in ob-enroll before #256. openssl is fed from a slow
    # pipe so it is still alive to be sampled: it hashes in microseconds, and an
    # earlier version of this test put the `sleep` after it instead, so the
    # process was always gone before the first sample. That version passed --
    # on the test's own `grep "$marker"` argv, which is why the marker now
    # lives in a file.
    ( printf 'msg'; sleep 2 ) | openssl dgst -sha256 -hmac "$marker" -binary >/dev/null 2>&1 &
    local wrapper=$!

    local found=""
    for _ in $(seq 1 20); do
        # Same scan as test 4, marker from a file for the same reason.
        if grep -rlFf "$pat" /proc/[0-9]*/cmdline 2>/dev/null | grep -q .; then
            found=yes; break
        fi
        sleep 0.1
    done
    wait "$wrapper" 2>/dev/null
    rm -f "$pat"

    if [ -n "$found" ]; then
        pass "the probe does catch the openssl -hmac leak it is aimed at"
    else
        fail "the probe does catch the openssl -hmac leak it is aimed at" \
             "the probe found nothing, so test 4 proves nothing"
    fi
}

# ── 6. Refusals ──────────────────────────────────────────────────────────────
test_refusals() {
    local bad=""
    printf '' | "$HELPER" --client-id "$CID" --audience "$AUD" >/dev/null 2>&1 \
        && bad="$bad empty-secret-accepted"
    printf 'a\0b' | "$HELPER" --client-id "$CID" --audience "$AUD" >/dev/null 2>&1 \
        && bad="$bad nul-accepted"
    head -c 5000 /dev/zero | tr '\0' 'x' | "$HELPER" --client-id "$CID" --audience "$AUD" >/dev/null 2>&1 \
        && bad="$bad oversize-accepted"
    printf '%s' "$SECRET" | "$HELPER" --audience "$AUD" >/dev/null 2>&1 \
        && bad="$bad missing-client-id-accepted"
    printf '%s' "$SECRET" | "$HELPER" --client-id "$CID" >/dev/null 2>&1 \
        && bad="$bad missing-audience-accepted"
    printf '%s' "$SECRET" | "$HELPER" --client-id "$CID" --audience "$AUD" --secret "$SECRET" >/dev/null 2>&1 \
        && bad="$bad unknown-option-accepted"

    if [ -z "$bad" ]; then
        pass "an empty, NUL-bearing or oversized secret and a bad invocation are all refused"
    else
        fail "an empty, NUL-bearing or oversized secret and a bad invocation are all refused" "$bad"
    fi
}

# ── 7. A trailing newline must not change the key ────────────────────────────
# `printf '%s'` and `echo` must produce the same assertion, or an operator who
# pipes the secret from a file gets bad_client_credentials with no clue why.
test_trailing_newline() {
    local bad="" form jwt
    # No newline, LF and CRLF must all key the HMAC with the same secret. An
    # operator whose secret file came from a Windows editor otherwise gets
    # bad_client_credentials with nothing to go on.
    for form in '%s' '%s\n' '%s\r\n'; do
        # shellcheck disable=SC2059  # the format is ours, not user input
        jwt=$(printf "$form" "$SECRET" | "$HELPER" --client-id "$CID" --audience "$AUD")
        if [ -z "$jwt" ]; then
            bad="$bad no-output-for[$form]"
            continue
        fi
        python3 - "$SECRET" "$jwt" <<'VERIFY' || bad="$bad wrong-key-for[$form]"
import sys, hmac, hashlib, base64
secret, jwt = sys.argv[1], sys.argv[2]
h, p, sig = jwt.split('.')
mac = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
sys.exit(0 if base64.urlsafe_b64encode(mac).decode().rstrip('=') == sig else 1)
VERIFY
    done

    if [ -z "$bad" ]; then
        pass "no newline, LF and CRLF on the secret all key the same HMAC"
    else
        fail "no newline, LF and CRLF on the secret all key the same HMAC" "$bad"
    fi
}

run_test test_signature_is_correct
run_test test_claims
run_test test_fresh_jti
run_test test_secret_never_in_proc
run_test test_probe_catches_the_old_leak
run_test test_refusals
run_test test_trailing_newline

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
