#!/bin/bash
# test_ob_krl_refresh.sh
#
# ob-krl-refresh replaces the refresh script ob-bastion-setup used to generate
# for /etc/cron.d/open-bastion-krl (#281). What it writes is read by sshd at
# every authentication, and sshd treats a revocation list it cannot parse as
# revoking EVERY key. So the property under test is less "it downloads" than
# "nothing but a valid KRL ever replaces the current one, and never partially":
#
#   - a valid list replaces the current one, mode 0644, by rename;
#   - an HTML page, a truncated or corrupt list, an empty body, a 404, a 500 or
#     an unreachable portal each leave the current list byte-for-byte intact
#     and exit non-zero (the unit then shows as failed);
#   - the magic check holds on its own, on a host with no ssh-keygen;
#   - portal_url, verify_ssl and timeout come from openbastion.conf at every
#     run, and a config file others can write is refused.
#
# shellcheck disable=SC2016  # single-quoted $ is source text being searched for

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$ROOT_DIR/scripts/ob-krl-refresh"
MOCK="$ROOT_DIR/tests/mock_portal_krl.py"
PORT_BASE=${OB_TEST_PORT_BASE:-18800}

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

for dep in curl python3 ssh-keygen od; do
    command -v "$dep" >/dev/null || { echo "SKIP: $dep is required"; exit 0; }
done

WORK=$(mktemp -d)
MOCK_PID=""
cleanup() {
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== ob-krl-refresh (#281) ==="

# A real KRL, made the way OpenSSH makes them, revoking one throwaway key.
ssh-keygen -q -t ed25519 -N '' -C revoked -f "$WORK/revoked" >/dev/null
ssh-keygen -q -k -f "$WORK/portal.krl" "$WORK/revoked.pub" 2>/dev/null
# The list the host has before each run: a different valid KRL, so that
# "unchanged" and "replaced" cannot be confused.
ssh-keygen -q -t ed25519 -N '' -C old -f "$WORK/old" >/dev/null
ssh-keygen -q -k -f "$WORK/current.krl" "$WORK/old.pub" 2>/dev/null

start_mock() {
    local mode="$1" port="$2"
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    rm -f "$WORK/portal.krl.log"
    python3 "$MOCK" "$mode" "$port" "$WORK/portal.krl" & MOCK_PID=$!
    for _ in $(seq 1 50); do
        (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# write_conf PORT [extra lines...]
write_conf() {
    local port="$1"; shift
    {
        printf 'portal_url = http://127.0.0.1:%s/\n' "$port"
        printf 'verify_ssl = false\n'
        printf 'timeout = 5\n'
        local l
        for l in "$@"; do printf '%s\n' "$l"; done
    } > "$WORK/ob.conf"
    chmod 600 "$WORK/ob.conf"
}

# Fresh target directory holding the "current" list. Sets OUT.
fresh_target() {
    rm -rf "$WORK/ssh"
    mkdir -p "$WORK/ssh"
    OUT="$WORK/ssh/revoked_keys"
    cp "$WORK/current.krl" "$OUT"
    chmod 644 "$OUT"
}

# ── 1. A valid list replaces the current one ─────────────────────────────────
test_valid_list_replaces() {
    local port=$((PORT_BASE + 1)) rc bad=""
    start_mock krl "$port" || { fail "valid list replaces the current one" "mock did not start"; return; }
    write_conf "$port"
    fresh_target
    "$PROG" --config "$WORK/ob.conf" --output "$OUT" 2>/dev/null; rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    cmp -s "$OUT" "$WORK/portal.krl" || bad="$bad not-replaced"
    [ "$(stat -c %a "$OUT")" = "644" ] || bad="$bad mode=$(stat -c %a "$OUT")"
    # sshd must be able to use it: the revoked key is reported as revoked.
    ssh-keygen -Q -f "$OUT" "$WORK/revoked.pub" >/dev/null 2>&1
    [ $? -eq 1 ] || bad="$bad key-not-revoked-by-result"
    # No temporary file left behind next to the list.
    [ "$(find "$WORK/ssh" -mindepth 1 | wc -l)" -eq 1 ] || bad="$bad leftovers"
    # The trailing slash of portal_url is not doubled.
    grep -qx '/ssh/revoked' "$WORK/portal.krl.log" || bad="$bad path:$(tr '\n' ' ' < "$WORK/portal.krl.log")"
    if [ -z "$bad" ]; then
        pass "a valid KRL replaces the current list, mode 0644, nothing left behind"
    else
        fail "a valid KRL replaces the current list" "$bad"
    fi
}

# ── 2. Nothing else ever replaces it ─────────────────────────────────────────
test_invalid_answers_keep_the_list() {
    local port=$((PORT_BASE + 2)) mode rc bad=""
    write_conf "$port"
    for mode in html truncated corrupt empty notfound error; do
        start_mock "$mode" "$port" || { bad="$bad $mode:mock"; continue; }
        fresh_target
        "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
        [ "$rc" -ne 0 ] || bad="$bad $mode:rc=0"
        cmp -s "$OUT" "$WORK/current.krl" || bad="$bad $mode:list-changed"
        [ "$(find "$WORK/ssh" -mindepth 1 | wc -l)" -eq 1 ] || bad="$bad $mode:leftovers"
    done
    if [ -z "$bad" ]; then
        pass "HTML, truncated, corrupt, empty, 404 and 500 answers leave the list intact and fail"
    else
        fail "invalid answers leave the list intact and fail" "$bad"
    fi
}

# ── 3. An unreachable portal keeps the list too ──────────────────────────────
test_unreachable_portal() {
    local port=$((PORT_BASE + 3)) rc
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; MOCK_PID=""
    write_conf "$port"
    fresh_target
    "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
    if [ "$rc" -eq 2 ] && cmp -s "$OUT" "$WORK/current.krl"; then
        pass "an unreachable portal exits 2 and leaves the list intact"
    else
        fail "an unreachable portal exits 2 and leaves the list intact" "rc=$rc"
    fi
}

# ── 4. The magic check holds without ssh-keygen ──────────────────────────────
# ssh-keygen is optional (a host may lack openssh-client), so the header check
# must refuse a non-KRL by itself: without this test, deleting it would go
# unnoticed on every machine that has ssh-keygen.
test_magic_check_alone() {
    local port=$((PORT_BASE + 4)) rc bad="" f
    # A PATH holding only the tools the program uses, ssh-keygen excepted.
    # Linking all of /usr/bin instead cost a minute per run, and the mutation
    # job runs this suite once per entry. A tool missing from this list makes
    # the "krl" half below fail loudly, not pass.
    mkdir -p "$WORK/nokeygen"
    for f in awk basename cat chmod cmp curl dirname id mktemp mv od rm stat touch tr; do
        ln -sf "$(command -v "$f")" "$WORK/nokeygen/$f"
    done
    write_conf "$port"
    start_mock html "$port" || { fail "magic check without ssh-keygen" "mock did not start"; return; }
    fresh_target
    PATH="$WORK/nokeygen" "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 3 ] || bad="$bad html:rc=$rc"
    cmp -s "$OUT" "$WORK/current.krl" || bad="$bad html:list-changed"
    # ...and still accepts a real list.
    start_mock krl "$port" || { fail "magic check without ssh-keygen" "mock did not start"; return; }
    fresh_target
    PATH="$WORK/nokeygen" "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 0 ] && cmp -s "$OUT" "$WORK/portal.krl" || bad="$bad krl:rc=$rc"
    if [ -z "$bad" ]; then
        pass "without ssh-keygen, the KRL header alone still refuses a non-KRL"
    else
        fail "without ssh-keygen, the KRL header alone still refuses a non-KRL" "$bad"
    fi
}

# ── 5. The replacement is a rename, never a rewrite in place ─────────────────
# A reader holding the old file open (sshd, mid-authentication) must keep
# seeing a whole list. With a rename the old inode survives unchanged; a
# `cat > target` or `cp` would rewrite it under the reader.
test_replace_is_atomic_rename() {
    local port=$((PORT_BASE + 5)) before after bad=""
    start_mock krl "$port" || { fail "replacement is a rename" "mock did not start"; return; }
    write_conf "$port"
    fresh_target
    ln "$OUT" "$WORK/ssh-old-inode"     # a second name for the OLD inode
    before=$(stat -c %i "$OUT")
    "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1 || bad="$bad rc"
    after=$(stat -c %i "$OUT")
    [ "$before" != "$after" ] || bad="$bad same-inode"
    cmp -s "$WORK/ssh-old-inode" "$WORK/current.krl" || bad="$bad old-inode-rewritten"
    rm -f "$WORK/ssh-old-inode"
    # The temporary file is created in the target directory (same filesystem,
    # so mv is rename(2)), not in /tmp.
    grep -q 'mktemp "$out_dir/' "$PROG" || bad="$bad tmp-not-beside-target"
    if [ -z "$bad" ]; then
        pass "the list is replaced by rename: the old inode is never rewritten"
    else
        fail "the list is replaced by rename" "$bad"
    fi
}

# ── 6. An identical list is not rewritten ────────────────────────────────────
test_identical_list_untouched() {
    local port=$((PORT_BASE + 6)) before after rc
    start_mock krl "$port" || { fail "identical list untouched" "mock did not start"; return; }
    write_conf "$port"
    fresh_target
    cp "$WORK/portal.krl" "$OUT"
    touch -d '2 hours ago' "$OUT"
    before=$(stat -c %i "$OUT")
    "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
    after=$(stat -c %i "$OUT")
    # Not rewritten (same inode), but dated now: monitoring the file's age
    # ("KRL older than an hour") must keep telling a working refresh from a
    # broken one when the list itself does not change.
    if [ "$rc" -eq 0 ] && [ "$before" = "$after" ] \
       && [ -z "$(find "$OUT" -mmin +5)" ]; then
        pass "an identical list is not rewritten, but its date says it was confirmed"
    else
        fail "an identical list is not rewritten, but its date says it was confirmed" \
             "rc=$rc inode $before -> $after mtime $(stat -c %y "$OUT")"
    fi
}

# ── 7. The configuration is read, and must be trustworthy ────────────────────
test_config_parsing_and_trust() {
    local port=$((PORT_BASE + 7)) rc bad="" out
    start_mock krl "$port" || { fail "config parsing" "mock did not start"; return; }

    # Quotes and an inline comment, as ob-heartbeat accepts them; `portal`
    # as a fallback key.
    printf 'portal = "http://127.0.0.1:%s"  # the portal\nverify_ssl = false\n' "$port" > "$WORK/ob.conf"
    chmod 600 "$WORK/ob.conf"
    fresh_target
    "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1 || bad="$bad quoted-fallback"
    cmp -s "$OUT" "$WORK/portal.krl" || bad="$bad quoted-fallback:not-replaced"

    # Group- or world-writable: refused before any request is made.
    write_conf "$port"
    chmod 620 "$WORK/ob.conf"
    rm -f "$WORK/portal.krl.log"
    fresh_target
    out=$("$PROG" --config "$WORK/ob.conf" --output "$OUT" 2>&1); rc=$?
    [ "$rc" -eq 1 ] || bad="$bad writable:rc=$rc"
    [ ! -s "$WORK/portal.krl.log" ] || bad="$bad writable:requested"
    grep -q 'writable' <<<"$out" || bad="$bad writable:msg"
    chmod 600 "$WORK/ob.conf"

    # No portal_url at all.
    printf 'verify_ssl = false\n' > "$WORK/ob.conf"; chmod 600 "$WORK/ob.conf"
    "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 1 ] || bad="$bad no-url:rc=$rc"

    # A portal_url that is not a URL is not handed to curl.
    printf 'portal_url = file:///etc/shadow\n' > "$WORK/ob.conf"; chmod 600 "$WORK/ob.conf"
    "$PROG" --config "$WORK/ob.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 1 ] || bad="$bad file-url:rc=$rc"
    cmp -s "$OUT" "$WORK/current.krl" || bad="$bad file-url:list-changed"

    # Missing configuration file.
    "$PROG" --config "$WORK/absent.conf" --output "$OUT" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 1 ] || bad="$bad absent:rc=$rc"

    if [ -z "$bad" ]; then
        pass "portal_url/portal are parsed like ob-heartbeat; a writable or bad config is refused"
    else
        fail "configuration parsing and trust" "$bad"
    fi
}

# ── 8. verify_ssl reaches curl ───────────────────────────────────────────────
# Against an https URL on a plain-HTTP port, curl fails at the TLS handshake
# whatever -k says; what differs is the error curl reports. Cheaper and more
# robust than a TLS mock: check the option list the program builds.
test_verify_ssl_and_timeout() {
    local bad=""
    grep -qE 'false\|0\|no\|off\) CURL_OPTS\+=\(-k\)' "$PROG" || bad="$bad no-k-branch"
    grep -q -- '--connect-timeout "$TIMEOUT"' "$PROG" || bad="$bad no-timeout"
    grep -q -- "--proto '=http,https'" "$PROG" || bad="$bad no-proto-restriction"
    grep -q -- '--max-filesize' "$PROG" || bad="$bad no-size-bound"
    if [ -z "$bad" ]; then
        pass "curl gets -k only for verify_ssl=false, a timeout, http(s) only, a size bound"
    else
        fail "curl options" "$bad"
    fi
}

# ── 9. Syntax, help, version ─────────────────────────────────────────────────
test_cli() {
    local bad=""
    bash -n "$PROG" || bad="$bad syntax"
    "$PROG" --help 2>&1 | grep -q 'Usage' || bad="$bad help"
    "$PROG" --version 2>&1 | grep -q 'version' || bad="$bad version"
    "$PROG" --bogus >/dev/null 2>&1 && bad="$bad accepts-unknown"
    if [ -z "$bad" ]; then
        pass "syntax, --help, --version, unknown option refused"
    else
        fail "command line" "$bad"
    fi
}

run_test test_valid_list_replaces
run_test test_invalid_answers_keep_the_list
run_test test_unreachable_portal
run_test test_magic_check_alone
run_test test_replace_is_atomic_rename
run_test test_identical_list_untouched
run_test test_config_parsing_and_trust
run_test test_verify_ssl_and_timeout
run_test test_cli

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
