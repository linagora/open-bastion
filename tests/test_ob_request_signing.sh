#!/bin/bash
#
# Every /pam/ caller signs, end to end (#247).
#
# Why this exists: the client had produced X-Signature-256 on two endpoints for
# a year and nothing checked it, so when the portal started verifying
# (lemonldap-ng-plugins#93) the strictest mode could not be turned on -- the
# four other endpoints were unsigned, and /pam/heartbeat is how every enrolled
# host renews its access token. Flipping the switch would have broken nothing
# visible and taken the whole fleet down hours later, together.
#
# So this test does not check that the client can sign. It checks that a portal
# which REFUSES unsigned requests is still usable, which is the only property
# that makes `pamAccessRequestSigningMode = required` deployable. The mock
# verifies the HMAC itself (tests/mock_portal_signing.py, a transcription of
# _checkRequestSignature), so a client that signed the wrong bytes fails here.
#
# The unit test tests/test_ob_sign.c pins the wire format against the portal's
# own Digest::SHA output; this one pins the wiring.
#

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MOCK="$ROOT_DIR/tests/mock_portal_signing.py"
WORK="$(mktemp -d)"
PORT_BASE=${OB_TEST_PORT_BASE:-18800}
trap 'rm -rf "$WORK"' EXIT

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }

command -v jq >/dev/null      || { echo "SKIP: jq is required"; exit 0; }
command -v curl >/dev/null    || { echo "SKIP: curl is required"; exit 0; }
command -v python3 >/dev/null || { echo "SKIP: python3 is required"; exit 0; }

# The helper is built, not installed, when the tests run. Put the build tree on
# PATH so the scripts find it exactly the way they will in production
# (command -v ob-sign-request).
BUILD_DIR="${OB_BUILD_DIR:-$ROOT_DIR/build}"
if [ ! -x "$BUILD_DIR/ob-sign-request" ]; then
    echo "SKIP: $BUILD_DIR/ob-sign-request not built (cmake --build build)"
    exit 0
fi
PATH="$BUILD_DIR:$PATH"
export PATH

# A secret with a '#' and a space in it, on purpose: every config reader in the
# tree used to end the value at the '#', which yields a signature over the
# wrong key -- reported by the portal as bad_signature, which looks like a
# portal problem and is not.
SECRET='s3cr#t key'

port=$PORT_BASE
next_port() { port=$((port + 1)); echo "$port"; }

# start_mock MODE PORT SECRET -> sets MOCK_PID, MOCK_LOG
start_mock() {
    local mode="$1" p="$2" secret="$3"
    MOCK_LOG="$WORK/mock-$p.log"
    : > "$MOCK_LOG"
    printf '%s' "$secret" > "$WORK/mock-secret-$p"
    python3 "$MOCK" "$mode" "$p" "$WORK/mock-secret-$p" "$MOCK_LOG" &
    MOCK_PID=$!
    local i
    for i in $(seq 1 50); do
        (echo > "/dev/tcp/127.0.0.1/$p") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

stop_mock() {
    kill "$MOCK_PID" 2>/dev/null
    wait "$MOCK_PID" 2>/dev/null
    return 0
}

# write_conf PORT SECRET -> path of an openbastion.conf
write_conf() {
    local p="$1" secret="$2"
    local f="$WORK/ob-$p.conf"
    {
        printf 'portal_url = http://127.0.0.1:%s\n' "$p"
        printf 'server_group = bastion\n'
        printf 'verify_ssl = false\n'
        [ -n "$secret" ] && printf 'request_signing_secret = %s\n' "$secret"
    } > "$f"
    chmod 600 "$f"
    echo "$f"
}

# The reason the mock recorded for the last request on a path.
last_reason() {
    local log="$1" path="$2"
    jq -r --arg p "$path" 'select(.path == $p) | .reason' "$log" 2>/dev/null | tail -1
}

# ── 1. ob-heartbeat against a portal in `required` ────────────────────────────
#
# The endpoint that made `required` undeployable. A pass here means an enrolled
# host can still renew its access token once the switch is flipped.
test_heartbeat_required() {
    local p conf token out rc
    p=$(next_port)
    start_mock required "$p" "$SECRET" || { fail "heartbeat/required" "mock did not start"; return; }
    conf=$(write_conf "$p" "$SECRET")
    token="$WORK/token-$p"
    echo '{"access_token":"old","refresh_token":"rt-1","expires_at":0}' > "$token"

    out=$(bash "$ROOT_DIR/scripts/ob-heartbeat" -c "$conf" -t "$token" 2>&1); rc=$?
    stop_mock

    local reason; reason=$(last_reason "$MOCK_LOG" /pam/heartbeat)
    if [ "$rc" != "0" ]; then
        fail "ob-heartbeat is accepted by a portal in 'required'" "rc=$rc reason=$reason $out"
    elif [ "$reason" != "verified" ]; then
        fail "ob-heartbeat is accepted by a portal in 'required'" "portal said: $reason"
    elif [ "$(jq -r .access_token "$token")" != "fresh-access-token" ]; then
        fail "ob-heartbeat is accepted by a portal in 'required'" "token not refreshed"
    else
        pass "ob-heartbeat is accepted by a portal in 'required'"
    fi
}

# ── 2. The mock really verifies ───────────────────────────────────────────────
#
# Without this, case 1 would also pass against a mock that accepted anything.
test_wrong_secret_is_refused() {
    local p conf token rc
    p=$(next_port)
    start_mock required "$p" "$SECRET" || { fail "wrong secret" "mock did not start"; return; }
    conf=$(write_conf "$p" "not-the-portals-secret")
    token="$WORK/token-$p"
    echo '{"access_token":"old","refresh_token":"rt-1","expires_at":0}' > "$token"

    bash "$ROOT_DIR/scripts/ob-heartbeat" -c "$conf" -t "$token" >/dev/null 2>&1; rc=$?
    stop_mock

    local reason; reason=$(last_reason "$MOCK_LOG" /pam/heartbeat)
    if [ "$reason" = "bad_signature" ] && [ "$rc" != "0" ]; then
        pass "a signature over the wrong secret is refused (the mock verifies)"
    else
        fail "a signature over the wrong secret is refused" "rc=$rc reason=$reason"
    fi
}

# ── 3. No secret configured, portal in `required` ─────────────────────────────
#
# Proves the headers come from the configuration and not from somewhere that
# would have made case 1 pass regardless.
test_unconfigured_is_unsigned() {
    local p conf token rc
    p=$(next_port)
    start_mock required "$p" "$SECRET" || { fail "unconfigured" "mock did not start"; return; }
    conf=$(write_conf "$p" "")
    token="$WORK/token-$p"
    echo '{"access_token":"old","refresh_token":"rt-1","expires_at":0}' > "$token"

    bash "$ROOT_DIR/scripts/ob-heartbeat" -c "$conf" -t "$token" >/dev/null 2>&1; rc=$?
    stop_mock

    local reason; reason=$(last_reason "$MOCK_LOG" /pam/heartbeat)
    if [ "$reason" = "unsigned" ] && [ "$rc" != "0" ]; then
        pass "no request_signing_secret means unsigned, and 'required' refuses it"
    else
        fail "no request_signing_secret means unsigned" "rc=$rc reason=$reason"
    fi
}

# ── 4. Unsigned is still fine where the portal allows it ──────────────────────
#
# The upgrade order is optional -> roll the secret out -> required. A host that
# has not received the secret yet must keep working meanwhile.
test_unconfigured_optional() {
    local p conf token rc
    p=$(next_port)
    start_mock optional "$p" "$SECRET" || { fail "optional" "mock did not start"; return; }
    conf=$(write_conf "$p" "")
    token="$WORK/token-$p"
    echo '{"access_token":"old","refresh_token":"rt-1","expires_at":0}' > "$token"

    bash "$ROOT_DIR/scripts/ob-heartbeat" -c "$conf" -t "$token" >/dev/null 2>&1; rc=$?
    stop_mock

    local reason; reason=$(last_reason "$MOCK_LOG" /pam/heartbeat)
    if [ "$rc" = "0" ] && [ "$reason" = "unsigned_allowed" ]; then
        pass "a host without the secret still works while the portal is 'optional'"
    else
        fail "a host without the secret still works in 'optional'" "rc=$rc reason=$reason"
    fi
}

# ── 5. ob-bastion-id / /pam/whoami ────────────────────────────────────────────
#
# A bodyless POST: the message it signs ends with the fourth separator and an
# empty body. An implementation that dropped the trailing '.' passes every
# other case in this file and fails this one.
test_whoami_required() {
    local p conf token out rc
    p=$(next_port)
    start_mock required "$p" "$SECRET" || { fail "whoami/required" "mock did not start"; return; }
    conf=$(write_conf "$p" "$SECRET")
    token="$WORK/token-$p"
    echo '{"access_token":"at-1"}' > "$token"

    out=$(bash "$ROOT_DIR/scripts/ob-bastion-id" --quiet -c "$conf" -t "$token" 2>&1); rc=$?
    stop_mock

    local reason; reason=$(last_reason "$MOCK_LOG" /pam/whoami)
    if [ "$rc" = "0" ] && [ "$out" = "mock-bastion-1" ] && [ "$reason" = "verified" ]; then
        pass "ob-bastion-id signs the bodyless /pam/whoami"
    else
        fail "ob-bastion-id signs the bodyless /pam/whoami" "rc=$rc out=$out reason=$reason"
    fi
}

# ── 6. The helper's contract ──────────────────────────────────────────────────
test_helper_contract() {
    local conf out rc
    conf=$(write_conf 1 "$SECRET")

    out=$(printf '%s' '{"a":1}' | ob-sign-request --method POST --path /pam/heartbeat --config "$conf" 2>&1); rc=$?
    if [ "$rc" = "0" ] \
       && echo "$out" | grep -qE '^X-Timestamp: [0-9]+$' \
       && echo "$out" | grep -qE '^X-Nonce: [0-9A-Za-z._:-]+$' \
       && echo "$out" | grep -qE '^X-Signature-256: sha256=[0-9a-f]{64}$'; then
        pass "ob-sign-request prints the three headers"
    else
        fail "ob-sign-request prints the three headers" "rc=$rc out=$(echo "$out" | tr '\n' ' ')"
    fi

    # --config is the only spelling. ob-sign-lib.sh passes exactly this, so an
    # unknown option must be refused rather than ignored -- a helper that
    # skipped it would fall back to the default config path and sign with a
    # secret the caller never asked for.
    out=$(printf '%s' '{"a":1}' | ob-sign-request --method POST --path /pam/heartbeat -c "$conf" 2>&1); rc=$?
    if [ "$rc" = "1" ]; then
        pass "ob-sign-request refuses an unknown option"
    else
        fail "ob-sign-request refuses an unknown option" "rc=$rc out=$out"
    fi

    # Exit 3, not an error and not a signature: nothing is configured.
    conf=$(write_conf 2 "")
    out=$(printf '%s' '{}' | ob-sign-request --method POST --path /pam/whoami --config "$conf" 2>&1); rc=$?
    if [ "$rc" = "3" ] && [ -z "$out" ]; then
        pass "ob-sign-request exits 3 and prints nothing with no secret configured"
    else
        fail "ob-sign-request exits 3 with no secret configured" "rc=$rc out=$out"
    fi

    # A query string is not part of what the portal signs, so refuse it here
    # rather than emit a signature the portal can only compute differently.
    out=$(printf '%s' '{}' | ob-sign-request --method POST --path '/pam/whoami?x=1' --config "$(write_conf 1 "$SECRET")" 2>&1); rc=$?
    if [ "$rc" = "1" ]; then
        pass "ob-sign-request refuses a path with a query string"
    else
        fail "ob-sign-request refuses a path with a query string" "rc=$rc out=$out"
    fi

    # Two runs must not produce the same nonce: it is the portal's replay key.
    local a b
    a=$(printf '%s' '{}' | ob-sign-request --method POST --path /pam/whoami --config "$(write_conf 1 "$SECRET")" | grep X-Nonce)
    b=$(printf '%s' '{}' | ob-sign-request --method POST --path /pam/whoami --config "$(write_conf 1 "$SECRET")" | grep X-Nonce)
    if [ -n "$a" ] && [ "$a" != "$b" ]; then
        pass "ob-sign-request generates a fresh nonce per call"
    else
        fail "ob-sign-request generates a fresh nonce per call" "$a / $b"
    fi
}

# ── 7. No secret must reach a command line, anywhere under scripts/ ──────────
#
# This is the reason ob-sign-request exists rather than `openssl dgst -hmac`.
# argv is world-readable through /proc/<pid>/cmdline, and ob-heartbeat runs
# from a timer, forever, on a host whose users have shells. A future edit that
# "simplifies" the helper away would hand the fleet-wide signing secret to
# anyone who polls, silently and with every test still green -- so the guard is
# here rather than in a comment.
#
# The scan is over every script rather than a named few (#256). It used to list
# ob-heartbeat and ob-bastion-id, which made it a guard about the /pam/
# endpoints; meanwhile ob-enroll signed its client_secret_jwt assertion with the
# OIDC client secret on openssl's command line, once per poll of the device
# grant loop, and this test had nothing to say about it. The property is not
# "the /pam/ callers are careful", it is "no script puts an HMAC key in argv" --
# so nothing has to be remembered when the next script is written.
#
# Full-line comments are stripped: this file and ob-enroll both quote the old
# leaking line in prose to explain why it went, and prose is not a call.
test_no_secret_in_argv() {
    local hits
    hits=$(for f in "$ROOT_DIR"/scripts/*; do
               [ -f "$f" ] || continue
               grep -nE 'dgst[^|]*-hmac|-macopt[[:space:]]*(hex)?key:' "$f" \
                   | grep -vE '^[0-9]+:[[:space:]]*#' \
                   | sed "s|^|$(basename "$f"):|"
           done)
    if [ -z "$hits" ]; then
        pass "no script under scripts/ puts an HMAC key on a command line"
    else
        fail "no script under scripts/ puts an HMAC key on a command line" "$hits"
    fi
}

# The replacement must not be reachable around: ob-enroll must have no fallback
# to openssl for when the helper is missing. A fallback would put the leak back
# exactly on the hosts where it is hardest to notice, and the suite would still
# be green because the helper is present here.
test_enroll_has_no_openssl_fallback() {
    local leaks
    leaks=$(grep -nE 'dgst[^|]*-hmac' "$ROOT_DIR/scripts/ob-enroll" \
            | grep -vE '^[0-9]+:[[:space:]]*#')
    if grep -q 'ob-client-jwt' "$ROOT_DIR/scripts/ob-enroll" && [ -z "$leaks" ]; then
        pass "ob-enroll signs its client assertion with ob-client-jwt, with no openssl fallback"
    else
        fail "ob-enroll signs its client assertion with ob-client-jwt, with no openssl fallback" \
             "${leaks:-ob-client-jwt is not called}"
    fi
}

# ── 8. Inventory: no endpoint creeps back in unsigned ─────────────────────────
#
# Item 4 of #247. Each row is "endpoint | file that calls it | what signing
# looks like in that file". A new caller of a /pam/ endpoint that forgets to
# sign fails here instead of being discovered when a portal turns `required`
# on and the fleet stops renewing its tokens.
test_every_caller_signs() {
    local rows=(
        "/pam/verify|src/ob_client.c|add_signing_headers"
        "/pam/authorize|src/ob_client.c|add_signing_headers"
        "/pam/heartbeat|src/ob_client.c|add_signing_headers"
        "/pam/bastion-cert|src/ob-cert-daemon.c|ob_sign_compute"
        "/pam/heartbeat|scripts/ob-heartbeat|ob_pam_post"
        "/pam/whoami|scripts/ob-bastion-id|ob_pam_post"
        "/pam/authorize|scripts/ob-enroll|ob_sign_request"
        "/pam/userinfo|scripts/ob-session-monitor|ob_pam_post"
        # ob_pam_post (signed answers, #339) signs through ob_sign_request.
        "/pam/|scripts/ob-sign-lib.sh|ob_sign_request POST \"\$path\""
    )
    local row endpoint file marker ok=1 detail=""
    for row in "${rows[@]}"; do
        IFS='|' read -r endpoint file marker <<< "$row"
        if ! grep -q -- "$endpoint" "$ROOT_DIR/$file"; then
            ok=0; detail="$detail $file no longer calls $endpoint;"
        elif ! grep -q -- "$marker" "$ROOT_DIR/$file"; then
            ok=0; detail="$detail $file calls $endpoint without $marker;"
        fi
    done

    # And the reverse direction: any *other* file that builds a /pam/ URL has
    # to appear in the table above.
    local known="src/ob_client.c src/ob-cert-daemon.c scripts/ob-heartbeat"
    known="$known scripts/ob-bastion-id scripts/ob-enroll scripts/ob-session-monitor"
    local f
    while IFS= read -r f; do
        case " $known " in
            *" $f "*) continue ;;
        esac
        ok=0; detail="$detail $f calls a /pam/ endpoint and is not in the inventory;"
    #
    # Match where a request URL is BUILT, not where an endpoint is merely
    # named: src/pam_openbastion.c mentions /pam/heartbeat in a log message
    # and calls nothing. C builds it with snprintf("%s/pam/...", portal_url),
    # shell with "${PORTAL_URL}/pam/..." or, in ob-bastion-id, the generic
    # "${PORTAL_URL}${path}".
    done < <(cd "$ROOT_DIR" && grep -rlE '"%s/pam/|\$\{PORTAL_URL\}(/pam/|\$\{path\})' \
                 src scripts 2>/dev/null | sort -u)

    if [ "$ok" = "1" ]; then
        pass "every caller of a /pam/ endpoint signs it"
    else
        fail "every caller of a /pam/ endpoint signs it" "$detail"
    fi
}

echo "=== Request signing, end to end (#247) ==="
# A name in this list that is not a defined function used to be a shell error
# the loop walked straight past, leaving the suite green with a test that never
# ran -- found while adding one below. Fail loudly instead.
for t in test_heartbeat_required test_wrong_secret_is_refused \
         test_unconfigured_is_unsigned test_unconfigured_optional \
         test_whoami_required test_helper_contract \
         test_no_secret_in_argv test_enroll_has_no_openssl_fallback \
         test_every_caller_signs; do
    if ! declare -F "$t" >/dev/null; then
        fail "$t is listed as a test but is not defined"
        continue
    fi
    "$t"
done

TESTS_RUN=$((TESTS_PASSED + TESTS_FAILED))
echo
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
