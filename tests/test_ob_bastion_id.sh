#!/bin/bash
#
# Exercises ob-bastion-id against every portal shape it has to survive (#246).
#
# Why this exists: the migration from the removed /pam/bastion-token to
# POST /pam/whoami had no coverage at all. The docker integration test only
# reaches whichever path the published demo image happens to take -- today the
# legacy fallback, because that image predates plugin 0.6.0 -- so the change
# this test is about, a portal that DOES answer /pam/whoami, was exercised by
# nothing. Worse, the day the image moves to 0.6.0 the fallback loses its only
# exercise too, and the skip-on-403/404 branch there would mask a real
# regression as "endpoint not provisioned in this demo".
#
# The mock is deliberately not a fixture of the portal: it reproduces the four
# response shapes that matter, including LemonLDAP::NG's catch-all, which
# serves the portal's HTML login page with a 200 for any /pam/* path no plugin
# registered. Assuming that absence looks like a 404 is what broke the first
# version of this migration.
#

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/ob-bastion-id"
MOCK="$ROOT_DIR/tests/mock_portal_whoami.py"
WORK="$(mktemp -d)"
PORT_BASE=${OB_TEST_PORT_BASE:-18700}
trap 'rm -rf "$WORK"' EXIT

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }

command -v jq >/dev/null || { echo "SKIP: jq is required"; exit 0; }
command -v curl >/dev/null || { echo "SKIP: curl is required"; exit 0; }
command -v python3 >/dev/null || { echo "SKIP: python3 is required"; exit 0; }

echo '{"access_token":"dummy-token"}' > "$WORK/token"

# Run ob-bastion-id against a mock in the given mode. Sets RC and OUT.
run_against() {
    local mode="$1" port="$2" pid
    printf 'portal_url = http://127.0.0.1:%s\nserver_group = bastion\nverify_ssl = false\n' \
        "$port" > "$WORK/ob.conf"
    # 0600 like the real /etc/open-bastion/openbastion.conf: config_load()
    # refuses anything looser, and so does the signing helper (#247).
    chmod 600 "$WORK/ob.conf"
    python3 "$MOCK" "$mode" "$port" & pid=$!
    for _ in $(seq 1 50); do
        (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
        sleep 0.1
    done
    OUT=$(bash "$SCRIPT" --quiet -c "$WORK/ob.conf" -t "$WORK/token" 2>&1); RC=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    return 0
}

# mode | expected rc | expected substring in the output
#
# The rc column is the contract the man page and usage() state:
#   0 an id was printed
#   2 the portal request failed or was refused
#   3 the portal answered, but with no identity in it
CASES=(
    "whoami|0|9f86d081"
    "legacy-id|0|legacy-id-42"
    "legacy-jwt|0|jwt-id-7"
    "catchall-then-probe|0|legacy-id-42"
    "forbidden|2|HTTP 403 on /pam/whoami"
    "catchall|3|implements neither"
    "none|2|HTTP 404 on /pam/bastion-token"
    "legacy-badjwt|3|base64url-decode"
)

port=$PORT_BASE
for spec in "${CASES[@]}"; do
    IFS='|' read -r mode want_rc want_out <<< "$spec"
    port=$((port + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
    run_against "$mode" "$port"
    if [ "$RC" != "$want_rc" ]; then
        fail "$mode" "rc=$RC expected $want_rc; output: $(echo "$OUT" | tr '\n' ' ')"
    elif ! echo "$OUT" | grep -qF "$want_out"; then
        fail "$mode" "output does not contain '$want_out': $(echo "$OUT" | tr '\n' ' ')"
    else
        pass "$mode (rc=$RC)"
    fi
done

# die() used to log "$*", which joins the message with the exit code passed as
# its second argument, so every error that set one ended in a stray digit.
TESTS_RUN=$((TESTS_RUN + 1))
port=$((port + 1))
run_against catchall "$port"
if echo "$OUT" | tail -1 | grep -qE '[^0-9] [0-9]$'; then
    fail "no error message ends with its own exit code" "$(echo "$OUT" | tail -1)"
else
    pass "no error message ends with its own exit code"
fi

# --json is what deploy scripts and ob-backend-setup consume.
TESTS_RUN=$((TESTS_RUN + 1))
port=$((port + 1))
printf 'portal_url = http://127.0.0.1:%s\nserver_group = bastion\nverify_ssl = false\n' \
    "$port" > "$WORK/ob.conf"
chmod 600 "$WORK/ob.conf"
python3 "$MOCK" whoami "$port" & mpid=$!
for _ in $(seq 1 50); do (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null && break; sleep 0.1; done
json=$(bash "$SCRIPT" --quiet --json -c "$WORK/ob.conf" -t "$WORK/token" 2>&1)
kill "$mpid" 2>/dev/null; wait "$mpid" 2>/dev/null
if [ "$(echo "$json" | jq -r '.bastion_id // empty' 2>/dev/null)" = "9f86d081" ]; then
    pass "--json emits {\"bastion_id\":...}"
else
    fail "--json emits a bastion_id object" "$json"
fi

# #377: a lookup keeps the id where --id-file says, 0644, and --cached prints
# it back with no portal, no configuration and no token -- what a backend's
# Ansible play reads on a bastion whose sudo only takes SSO tokens.
check() { # NAME CONDITION-RC DETAIL
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ "$2" -eq 0 ]; then pass "$1"; else fail "$1" "$3"; fi
}
start_mock() { # MODE PORT
    printf 'portal_url = http://127.0.0.1:%s\nserver_group = bastion\nverify_ssl = false\n' \
        "$2" > "$WORK/ob.conf"
    chmod 600 "$WORK/ob.conf"
    python3 "$MOCK" "$1" "$2" & mpid=$!
    for _ in $(seq 1 50); do (echo > "/dev/tcp/127.0.0.1/$2") 2>/dev/null && break; sleep 0.1; done
}
stop_mock() { kill "$mpid" 2>/dev/null; wait "$mpid" 2>/dev/null; }

kept="$WORK/kept/bastion-id"
mkdir -p "$WORK/kept"
port=$((port + 1))
start_mock whoami "$port"
OB_BASTION_ID_FILE="$WORK/kept/default" \
    bash "$SCRIPT" --quiet -c "$WORK/ob.conf" -t "$WORK/token" >/dev/null 2>&1
[ -z "$(ls "$WORK/kept")" ]; check "-c/-t without --id-file keeps nothing" $? "$(ls "$WORK/kept")"
out=$(bash "$SCRIPT" --quiet -c "$WORK/ob.conf" -t "$WORK/token" --id-file "$kept" 2>&1)
stop_mock
[ "$out" = 9f86d081 ] && [ "$(cat "$kept" 2>/dev/null)" = 9f86d081 ] \
    && [ "$(stat -c %a "$kept")" = 644 ]
check "a lookup keeps the id, 0644" $? "out=$out kept=$(cat "$kept" 2>/dev/null) mode=$(stat -c %a "$kept" 2>/dev/null)"

out=$(bash "$SCRIPT" --cached --id-file "$kept" -c /nonexistent 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = 9f86d081 ]
check "--cached prints the kept id without portal or configuration" $? "rc=$rc out=$out"
out=$(bash "$SCRIPT" --cached --json --id-file "$kept" 2>&1)
[ "$(echo "$out" | jq -r .bastion_id 2>/dev/null)" = 9f86d081 ]
check "--cached --json" $? "$out"

port=$((port + 1))
start_mock catchall "$port"
bash "$SCRIPT" --quiet -c "$WORK/ob.conf" -t "$WORK/token" --id-file "$kept" >/dev/null 2>&1
stop_mock
[ "$(cat "$kept")" = 9f86d081 ]
check "a lookup with no identity leaves the kept id alone" $? "$(cat "$kept")"

bash "$SCRIPT" --cached --verbose --id-file "$kept" >/dev/null 2>&1; rc=$?
[ "$rc" -ne 0 ]; check "--cached refuses --verbose" $? "rc=$rc"
bash "$SCRIPT" --cached --id-file "$WORK/kept/none" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ]; check "--cached with no id kept exits 4" $? "rc=$rc"
printf '<html>\n' > "$WORK/kept/bad"
out=$(bash "$SCRIPT" --cached --id-file "$WORK/kept/bad" 2>/dev/null); rc=$?
[ "$rc" -eq 4 ] && [ -z "$out" ]; check "--cached refuses a file that holds no id" $? "rc=$rc out=$out"
printf 'id-1\nid-2\n' > "$WORK/kept/two"
out=$(bash "$SCRIPT" --cached --id-file "$WORK/kept/two" 2>/dev/null); rc=$?
[ "$rc" -eq 4 ] && [ -z "$out" ]; check "--cached refuses two lines" $? "rc=$rc out=$out"

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
