#!/bin/bash
# test_ob_session_monitor.sh
#
# Guards the verdict semantics of check_user_valid (issue #257).
#
# The loop this function feeds calls `loginctl terminate-session` on live user
# sessions. Until #257 it had two outcomes: valid, and everything else. Because
# `curl -sf` fails on a connection error, a DNS or TLS failure, the timeout AND
# on any HTTP status >= 400, a portal answering 500, a rate limit, or an expired
# SERVER_TOKEN answering 401 all read as "the user was revoked" -- and killed
# their sessions while logging "no longer valid on LLNG", which was false.
#
# The reachability probe in the main loop does not cover it: check_portal()
# fetches /desktop/login?check=1, a different endpoint, so a healthy front end
# says nothing about whether /pam/userinfo works.
#
# What is asserted here is the distinction itself:
#
#   0  valid    -- 200 with found: true
#   1  revoked  -- 200 with found: false, the only case that may terminate
#   2  unknown  -- connection refused, timeout, 401, 403, 500, unparseable body
#
# The function is sourced out of the script rather than reimplemented, so the
# test breaks when the shipped code changes rather than when a copy of it does.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/ob-session-monitor"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

command -v curl >/dev/null 2>&1 || { echo "SKIP: curl is required"; exit 0; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is required"; exit 0; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null' EXIT

# A portal that answers /pam/userinfo however the test tells it to.
cat > "$WORK/mock.py" <<'MOCK'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[1]
PORT = int(sys.argv[2])

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        if MODE == "valid":
            body, code = json.dumps({"found": True}), 200
        elif MODE == "revoked":
            body, code = json.dumps({"found": False}), 200
        elif MODE.startswith("bearer="):
            ok = self.headers.get("Authorization") == "Bearer " + MODE[7:]
            body, code = (json.dumps({"found": True}), 200) if ok else \
                (json.dumps({"error": "invalid_token"}), 401)
        elif MODE == "unauthorized":
            body, code = json.dumps({"error": "invalid_token"}), 401
        elif MODE == "forbidden":
            body, code = json.dumps({"error": "forbidden"}), 403
        elif MODE == "server_error":
            body, code = "upstream exploded", 500
        elif MODE == "garbage":
            body, code = "not json at all", 200
        elif MODE == "no_found_field":
            body, code = json.dumps({"user": "alice"}), 200
        else:
            body, code = "?", 500
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
MOCK

# Pull check_user_valid out of the shipped script, with just enough scaffolding
# around it. Sourcing the whole script would start its main loop.
extract_function() {
    awk '/^check_user_valid\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT"
}

PORT=18257
run_case() {
    local mode="$1"
    PORT=$((PORT + 1))

    python3 "$WORK/mock.py" "$mode" "$PORT" & MOCK_PID=$!
    for _ in $(seq 1 50); do
        (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
        sleep 0.1
    done

    {
        echo 'set -uo pipefail'
        echo "PORTAL_URL='http://127.0.0.1:$PORT'"
        echo "CONFIG_FILE='$WORK/ob.conf'"
        echo 'SERVER_TOKEN=""'
        echo 'SIGN_HEADERS=()'
        echo 'ob_sign_request() { SIGN_HEADERS=(); return 0; }'
        echo 'log_warn() { echo "WARN: $*" >&2; }'
        echo 'log_crit() { echo "CRIT: $*" >&2; }'
        echo 'log_debug() { :; }'
        extract_function
        echo 'check_user_valid alice; echo "VERDICT=$?"'
    } > "$WORK/case.sh"

    CASE_OUT=$(bash "$WORK/case.sh" 2>&1)
    kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; MOCK_PID=""
    CASE_VERDICT=$(printf '%s' "$CASE_OUT" | sed -n 's/^VERDICT=//p' | tail -1)
}

# The one case that needs no server: nothing is listening.
run_unreachable_case() {
    PORT=$((PORT + 1))
    {
        echo 'set -uo pipefail'
        echo "PORTAL_URL='http://127.0.0.1:$PORT'"
        echo "CONFIG_FILE='$WORK/ob.conf'"
        echo 'SERVER_TOKEN=""'
        echo 'SIGN_HEADERS=()'
        echo 'ob_sign_request() { SIGN_HEADERS=(); return 0; }'
        echo 'log_warn() { echo "WARN: $*" >&2; }'
        echo 'log_crit() { echo "CRIT: $*" >&2; }'
        echo 'log_debug() { :; }'
        extract_function
        echo 'check_user_valid alice; echo "VERDICT=$?"'
    } > "$WORK/case.sh"
    CASE_OUT=$(bash "$WORK/case.sh" 2>&1)
    CASE_VERDICT=$(printf '%s' "$CASE_OUT" | sed -n 's/^VERDICT=//p' | tail -1)
}

expect() {
    local mode="$1" want="$2" label="$3"
    if [ "$mode" = "__unreachable__" ]; then
        run_unreachable_case
    else
        run_case "$mode"
    fi
    if [ "$CASE_VERDICT" = "$want" ]; then
        pass "$label"
    else
        fail "$label" "verdict=$CASE_VERDICT expected=$want out=$(printf '%s' "$CASE_OUT" | tr '\n' ' ')"
    fi
}

echo "=== ob-session-monitor: check_user_valid verdicts (issue #257) ==="

# ── The two real answers ─────────────────────────────────────────────────────
run_test expect valid    0 "200 found:true  -> valid (0)"
run_test expect revoked  1 "200 found:false -> revoked (1), the only case that may terminate"

# ── Everything that is not an answer ─────────────────────────────────────────
# Each of these returned 1 before #257 and terminated the user's sessions.
run_test expect __unreachable__ 2 "connection refused -> unknown (2), not revoked"
run_test expect server_error    2 "HTTP 500 -> unknown (2), not revoked"
run_test expect unauthorized    2 "HTTP 401 (our own token) -> unknown (2), not revoked"
run_test expect forbidden       2 "HTTP 403 -> unknown (2), not revoked"
run_test expect garbage         2 "200 with an unparseable body -> unknown (2)"
run_test expect no_found_field  2 "200 without a 'found' field -> unknown (2)"

# ── A 401 must be diagnosed, not just survived ───────────────────────────────
# Every non-answer yields verdict 2, so the verdict alone cannot tell an expired
# SERVER_TOKEN from a network blip -- with `curl -f` both land in the transport
# branch and are indistinguishable. Dropping `-f` is what buys the operator a
# message naming the actual cause, and this is what keeps it: an expired server
# token, from a heartbeat timer that never armed, is a failure this project has
# already shipped once (#159), and "check the server token" is the sentence that
# saves the next hour.
test_401_names_the_cause() {
    run_case unauthorized
    if [ "$CASE_VERDICT" = "2" ] \
       && printf '%s' "$CASE_OUT" | grep -q "refused our own credentials"; then
        pass "a 401 is reported as our credentials, not as a generic failure"
    else
        fail "a 401 is reported as our credentials, not as a generic failure" \
             "out=$(printf '%s' "$CASE_OUT" | tr '\n' ' ')"
    fi
}
run_test test_401_names_the_cause

# ── A signing failure is not a verdict either ────────────────────────────────
test_signing_failure_is_unknown() {
    {
        echo 'set -uo pipefail'
        echo "PORTAL_URL='http://127.0.0.1:1'"
        echo "CONFIG_FILE='$WORK/ob.conf'"
        echo 'SERVER_TOKEN=""'
        echo 'SIGN_HEADERS=()'
        echo 'OB_SIGN_ERROR="cannot sign /pam/userinfo: boom"'
        echo 'ob_sign_request() { return 1; }'
        echo 'log_warn() { echo "WARN: $*" >&2; }'
        echo 'log_crit() { echo "CRIT: $*" >&2; }'
        echo 'log_debug() { :; }'
        extract_function
        echo 'check_user_valid alice; echo "VERDICT=$?"'
    } > "$WORK/case.sh"
    local out verdict
    out=$(bash "$WORK/case.sh" 2>&1)
    verdict=$(printf '%s' "$out" | sed -n 's/^VERDICT=//p' | tail -1)
    if [ "$verdict" = "2" ]; then
        pass "a local signing failure -> unknown (2), and no request is sent"
    else
        fail "a local signing failure -> unknown (2)" "verdict=$verdict"
    fi
}
run_test test_signing_failure_is_unknown

# ── The unknown branch must survive errexit ──────────────────────────────────
# The shipped script runs under `set -euo pipefail`; this harness does not,
# because it has to capture a return value. That gap has bitten this project
# before: a command whose non-zero status is fine in the tests kills the real
# script.
#
# `found=$(... | jq ...)` takes jq's exit status, and jq exits non-zero on
# exactly the input the "unknown" branch exists to handle. Today's caller is
# `check_user_valid "$user" || verdict=$?`, which suspends errexit for the whole
# function, so nothing breaks -- but a future plain call would die at the
# assignment and never reach the branch, and no test that drops errexit could
# tell. So this one puts errexit back and calls plainly.
test_unknown_branch_survives_errexit() {
    PORT=$((PORT + 1))
    python3 "$WORK/mock.py" garbage "$PORT" & MOCK_PID=$!
    for _ in $(seq 1 50); do
        (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
        sleep 0.1
    done

    {
        echo 'set -euo pipefail'          # as shipped, not as the harness runs
        echo "PORTAL_URL='http://127.0.0.1:$PORT'"
        echo "CONFIG_FILE='$WORK/ob.conf'"
        echo 'SERVER_TOKEN=""'
        echo 'SIGN_HEADERS=()'
        echo 'ob_sign_request() { SIGN_HEADERS=(); return 0; }'
        echo 'log_warn() { echo "WARN: $*" >&2; }'
        echo 'log_crit() { echo "CRIT: $*" >&2; }'
        echo 'log_debug() { :; }'
        extract_function
        echo 'check_user_valid alice'     # plain call: errexit is live
    } > "$WORK/errexit.sh"

    local out
    out=$(bash "$WORK/errexit.sh" 2>&1)
    kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; MOCK_PID=""

    # The branch ran if it logged. Without `|| true` the shell dies at the
    # assignment with jq's status and nothing is logged at all.
    if printf '%s' "$out" | grep -q "without a usable 'found' field"; then
        pass "the unknown branch is reached under errexit, not skipped by jq's status"
    else
        fail "the unknown branch is reached under errexit, not skipped by jq's status" \
             "out=$(printf '%s' "$out" | tr '\n' ' ')"
    fi
}
run_test test_unknown_branch_survives_errexit

# ── The caller must act on the distinction ───────────────────────────────────
# A three-valued check_user_valid is worthless if the caller still writes
# `if check_user_valid`, which treats 1 and 2 alike.
test_caller_distinguishes_unknown() {
    if grep -qE '^\s*if check_user_valid "\$user"; then' "$SCRIPT"; then
        fail "the caller distinguishes unknown from revoked" \
             "still uses 'if check_user_valid', which folds 2 into 1"
        return
    fi
    if grep -qF '"$verdict" -eq 2' "$SCRIPT" \
       && grep -qF 'check_user_valid "$user" || verdict=$?' "$SCRIPT"; then
        pass "the caller distinguishes unknown from revoked"
    else
        fail "the caller distinguishes unknown from revoked" \
             "no verdict==2 branch found"
    fi
}
run_test test_caller_distinguishes_unknown

# ── An unusable endpoint still converges on a bound ──────────────────────────
# Leaving sessions alive forever because the endpoint that would revoke them is
# broken is the hole Part D exists to close, reached by another route.
test_unknown_still_bounded() {
    local missing=""
    grep -q "handle_userinfo_unusable" "$SCRIPT" || missing="$missing handler"
    grep -q "userinfo_unusable_since" "$SCRIPT" || missing="$missing counter"
    grep -q 'duration" -lt "\$MAX_SSO_UNREACHABLE' "$SCRIPT" || missing="$missing bound"
    # The counter must NOT be the one check_portal resets, or a working front
    # end wipes it every cycle and it never converges.
    if grep -q "userinfo_unusable_since=0" "$SCRIPT" \
       && grep -A3 "^check_portal()" "$SCRIPT" | grep -q "userinfo_unusable_since"; then
        missing="$missing shares-check_portal-reset"
    fi
    if [ -z "$missing" ]; then
        pass "a persistently unusable /pam/userinfo still terminates after MAX_SSO_UNREACHABLE"
    else
        fail "a persistently unusable /pam/userinfo still terminates after MAX_SSO_UNREACHABLE" \
             "$missing"
    fi
}
run_test test_unknown_still_bounded

# --- #342: the Bearer is the access token, not the token file ----------------
# Runs read_config + check_user_valid from the shipped script against a portal
# that only answers found:true to the exact expected Bearer (401 otherwise).
token_case() {
    local expected="$1"
    PORT=$((PORT + 1))
    python3 "$WORK/mock.py" "bearer=$expected" "$PORT" & MOCK_PID=$!
    for _ in $(seq 1 50); do
        (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
        sleep 0.1
    done
    {
        echo 'set -uo pipefail'
        echo "PORTAL_URL='http://127.0.0.1:$PORT'"
        echo "CONFIG_FILE='$WORK/tok.conf'"
        echo 'SERVER_TOKEN=""'
        echo 'SIGN_HEADERS=()'
        echo 'ob_sign_request() { SIGN_HEADERS=(); return 0; }'
        echo 'log_warn() { echo "WARN: $*" >&2; }'
        echo 'log_crit() { echo "CRIT: $*" >&2; }'
        echo 'log_info() { :; }'
        echo 'log_debug() { :; }'
        awk '/^read_server_token\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT"
        awk '/^read_config\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT"
        extract_function
        echo 'read_config; PORTAL_URL="http://127.0.0.1:'"$PORT"'"'
        echo 'check_user_valid alice; echo "VERDICT=$?"'
    } > "$WORK/case.sh"
    CASE_OUT=$(bash "$WORK/case.sh" 2>&1)
    kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; MOCK_PID=""
    CASE_VERDICT=$(printf '%s' "$CASE_OUT" | sed -n 's/^VERDICT=//p' | tail -1)
}

expect_token() {
    local desc="$1" expected="$2"
    token_case "$expected"
    if [ "$CASE_VERDICT" = "0" ]; then
        pass "$desc"
    else
        fail "$desc" "verdict=$CASE_VERDICT out=$CASE_OUT"
    fi
}

printf '%s\n' '{"access_token":"AT-json","refresh_token":"RT","expires_at":4102444800}' > "$WORK/tok.json"
printf '  AT-plain  \n' > "$WORK/tok.txt"
printf '\n' > "$WORK/tok.empty"

test_json_token_file() {
    printf 'portal_url = http://x\nserver_token_file = %s\n' "$WORK/tok.json" > "$WORK/tok.conf"
    expect_token "JSON token file -> Bearer is .access_token" "AT-json"
}
run_test test_json_token_file

test_plain_token_file() {
    printf 'server_token_file = "%s"\n' "$WORK/tok.txt" > "$WORK/tok.conf"
    expect_token "plain-text token file -> trimmed raw content" "AT-plain"
}
run_test test_plain_token_file

test_token_file_alias() {
    printf 'token_file = %s\n' "$WORK/tok.json" > "$WORK/tok.conf"
    expect_token "token_file alias is honoured" "AT-json"
}
run_test test_token_file_alias

test_token_file_last_wins() {
    printf 'server_token_file = %s\ntoken_file = %s\n' "$WORK/tok.json" "$WORK/tok.txt" > "$WORK/tok.conf"
    expect_token "last of server_token_file/token_file wins" "AT-plain"
}
run_test test_token_file_last_wins

test_empty_token_not_sent() {
    printf 'server_token_file = %s\n' "$WORK/tok.empty" > "$WORK/tok.conf"
    token_case "anything"
    if [ "$CASE_VERDICT" = "2" ]; then
        pass "empty token file -> no Bearer sent (portal 401 -> unknown)"
    else
        fail "empty token file" "verdict=$CASE_VERDICT"
    fi
}
run_test test_empty_token_not_sent

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
