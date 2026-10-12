#!/bin/bash
# test_ob_tls13.sh
#
# Every connection to the portal requires TLS 1.3 (#330).
#
# Only the PAM module's HTTP client set a minimum, and its min_tls_version
# setting never reached it; the token refresh, ob-cert-daemon, the NSS module
# and every script used curl's default, which accepts TLS 1.2. A portal limited
# to TLS 1.2 thus enrolled and heartbeated fine while every PAM authorization
# failed. This pins the minimum on every client of the portal:
#
#   1. each C file that opens a curl handle to the portal sets
#      CURLOPT_SSLVERSION to TLSv1_3, and none asks for less;
#   2. each curl call in the scripts passes --tlsv1.3, directly or through
#      the option array it expands;
#   3. curl's --tlsv1.3 does refuse a TLS 1.2-only server (skipped without
#      openssl).

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

echo "=== TLS 1.3 towards the portal (issue #330) ==="

# Not the portal: the CrowdSec LAPI and notification webhooks.
NOT_PORTAL="src/crowdsec.c src/notify.c"

test_c_clients() {
    local bad="" f rel
    for f in "$ROOT_DIR"/src/*.c "$ROOT_DIR"/nss/*.c; do
        rel=${f#"$ROOT_DIR"/}
        grep -q 'curl_easy_init' "$f" || continue
        case " $NOT_PORTAL " in *" $rel "*) continue ;; esac
        grep -q 'CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3' "$f" \
            || bad="$bad $rel:no-TLSv1_3"
        grep -qE 'CURL_SSLVERSION_(TLSv1_[012]|TLSv1|SSLv|DEFAULT)\b' "$f" \
            && bad="$bad $rel:weaker-version"
    done
    if [ -z "$bad" ]; then
        pass "every C client of the portal requires TLS 1.3"
    else
        fail "every C client of the portal requires TLS 1.3" "$bad"
    fi
}

SCRIPTS="scripts/ob-bastion-id scripts/ob-bastion-setup scripts/ob-desktop-setup
scripts/ob-enroll scripts/ob-heartbeat scripts/ob-krl-refresh
scripts/ob-session-monitor scripts/ob-uninstall admin-builder/lib/sso-discovery.sh
scripts/ob-sign-lib.sh"

test_script_clients() {
    local bad="" rel out
    for rel in $SCRIPTS; do
        [ -f "$ROOT_DIR/$rel" ] || { bad="$bad $rel:missing"; continue; }
        # A curl call -- curl followed by an option or an expansion; not a
        # comment, not text in a message -- must carry --tlsv1.3 or expand an
        # option array.
        out=$(grep -nE '(^|[^a-z_-])curl[[:space:]]+(-|"?\$)' "$ROOT_DIR/$rel" \
              | grep -vE '^[0-9]+:[[:space:]]*#' \
              | grep -vE '(log_[a-z]+|echo|error|info|warn|printf)[[:space:]]+"' \
              | grep -vE -- '--tlsv1\.3|"\$\{(CURL_OPTS|opts)\[@\]\}"')
        [ -z "$out" ] || bad="$bad $rel:${out%%:*}"
        # Every non-empty option array those calls expand carries it.
        out=$(grep -nE '(^|[^a-z_])(CURL_OPTS|opts)=\(' "$ROOT_DIR/$rel" \
              | grep -vE '=\(\)' | grep -v -- '--tlsv1\.3')
        [ -z "$out" ] || bad="$bad $rel:opts@${out%%:*}"
    done
    if [ -z "$bad" ]; then
        pass "every curl call of the scripts requires TLS 1.3"
    else
        fail "every curl call of the scripts requires TLS 1.3" "$bad"
    fi
}

test_curl_refuses_tls12() {
    local work port pid ok12 ok13
    if ! command -v openssl >/dev/null || ! command -v curl >/dev/null; then
        pass "(skipped: openssl or curl missing)"
        return
    fi
    work=$(mktemp -d)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 -subj /CN=localhost \
        >/dev/null 2>&1
    port=$((20000 + RANDOM % 20000))
    openssl s_server -quiet -tls1_2 -accept "$port" -www \
        -cert "$work/cert.pem" -key "$work/key.pem" >/dev/null 2>&1 &
    pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        curl -sk -o /dev/null "https://127.0.0.1:$port/" 2>/dev/null && break
        sleep 0.2
    done
    curl -sk -o /dev/null "https://127.0.0.1:$port/" 2>/dev/null; ok12=$?
    curl -sk --tlsv1.3 -o /dev/null "https://127.0.0.1:$port/" 2>/dev/null; ok13=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    rm -rf "$work"
    if [ "$ok12" -eq 0 ] && [ "$ok13" -ne 0 ]; then
        pass "curl --tlsv1.3 refuses a TLS 1.2-only server"
    else
        fail "curl --tlsv1.3 refuses a TLS 1.2-only server" \
             "plain curl rc=$ok12 (want 0), --tlsv1.3 rc=$ok13 (want non-zero)"
    fi
}

run_test test_c_clients
run_test test_script_clients
run_test test_curl_refuses_tls12

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
