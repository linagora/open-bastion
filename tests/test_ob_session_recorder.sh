#!/bin/bash
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
SCRIPT_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

source_script() {
    local script="$1"
    local content
    content=$(cat "$SCRIPT_DIR/$script")
    content="${content%main \"\$@\"}"
    content=$(echo "$content" | sed -E 's/^set -e(uo pipefail)?$//')
    # Ensure SSH_CLIENT is set for ob-session-recorder
    SSH_CLIENT="${SSH_CLIENT:-}"
    SSH_TTY="${SSH_TTY:-}"
    SSH_ORIGINAL_COMMAND="${SSH_ORIGINAL_COMMAND:-}"
    eval "$content"
}

# ── End-to-end harness ──
#
# The end-to-end tests run the real recorder against the real connector and
# sink (build/), stood up with systemd-socket-activate exactly as
# tests/test_ob_record_sink.sh does. The recorder takes nothing from the
# environment, so the test settings (connector, socket, config) are written
# into a copy of it, just before its final `main "$@"`: a knob only a modified
# program can turn, never the recorded user.
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
E2E_SINK="$ROOT_DIR/build/ob-record-sink"
E2E_CONNECT="$ROOT_DIR/build/ob-record-connect"
E2E_WORK=""
E2E_SA_PID=""

e2e_setup() {
    local sa
    [ -x "$E2E_SINK" ] && [ -x "$E2E_CONNECT" ] || {
        echo "SKIP: end-to-end recorder tests need build/ob-record-sink and build/ob-record-connect"
        return 1; }
    sa=$(command -v systemd-socket-activate 2>/dev/null)
    [ -z "$sa" ] && [ -x /usr/lib/systemd/systemd-socket-activate ] && sa=/usr/lib/systemd/systemd-socket-activate
    [ -z "$sa" ] && [ -x /lib/systemd/systemd-socket-activate ] && sa=/lib/systemd/systemd-socket-activate
    [ -n "$sa" ] || { echo "SKIP: end-to-end recorder tests need systemd-socket-activate"; return 1; }
    command -v setsid >/dev/null 2>&1 || { echo "SKIP: end-to-end recorder tests need setsid"; return 1; }
    [ "$(tail -n 1 "$SCRIPT_DIR/ob-session-recorder")" = 'main "$@"' ] || {
        fail "e2e harness: the recorder no longer ends with main \"\$@\""; return 1; }

    E2E_WORK=$(mktemp -d)
    mkdir -p "$E2E_WORK/sessions" "$E2E_WORK/home" "$E2E_WORK/tmp"
    "$sa" --accept -l "$E2E_WORK/rec.sock" \
        env OB_SESSIONS_DIR="$E2E_WORK/sessions" OB_RECORD_POLL_SEC=1 "$E2E_SINK" \
        >"$E2E_WORK/sa.log" 2>&1 &
    E2E_SA_PID=$!
    for _ in $(seq 1 50); do [ -S "$E2E_WORK/rec.sock" ] && break; sleep 0.1; done
    [ -S "$E2E_WORK/rec.sock" ] || {
        echo "SKIP: the test sink socket did not come up"; return 1; }
}

e2e_teardown() {
    [ -n "$E2E_SA_PID" ] && kill "$E2E_SA_PID" 2>/dev/null
    [ -n "$E2E_WORK" ] && rm -rf "$E2E_WORK"
}
trap e2e_teardown EXIT

# Write the recorder under test to $E2E_WORK/recorder, with the test settings
# and any extra shell assignments given as arguments.
e2e_driver() {
    {
        sed '$d' "$SCRIPT_DIR/ob-session-recorder"
        printf 'RECORD_CONNECT=%q\n' "$E2E_CONNECT"
        printf 'RECORD_SOCKET=%q\n' "$E2E_WORK/rec.sock"
        printf 'CONFIG_FILE=%q\n' "$E2E_WORK/no-such.conf"
        printf '%s\n' "$@"
        printf 'main "$@"\n'
    } > "$E2E_WORK/recorder"
}

# Run the recorder under test as sshd would for SSH_ORIGINAL_COMMAND=$1, in a
# session of its own (it is then the leader of its process group, as under
# sshd). Extra environment as VAR=value after the command. Stdin/stdout are the
# caller's. Returns the recorder's exit status.
#
# script(1) copies the command line into the typescript's first line, so a
# marker the tests look for is split with "" in the command (echo A-""B): only
# the command's OUTPUT then contains it whole.
e2e_run() { # $1 original command, [VAR=value ...]
    local cmd="$1"; shift
    env -u SSH_TTY SSH_ORIGINAL_COMMAND="$cmd" SSH_CLIENT="203.0.113.7 50000 22" \
        HOME="$E2E_WORK/home" "$@" setsid -w bash -p "$E2E_WORK/recorder"
}

# The metadata file of the most recent session, once the sink has finalized it.
e2e_last_json() {
    local j
    for _ in $(seq 1 100); do
        j=$(ls -t "$E2E_WORK/sessions/$(id -un)"/*.json 2>/dev/null | head -1)
        if [ -n "$j" ] && ! grep -q '"status": "active"' "$j"; then
            echo "$j"; return 0
        fi
        sleep 0.1
    done
    echo "$j"; return 1
}

e2e_session_count() {
    ls "$E2E_WORK/sessions/$(id -un)"/*.json 2>/dev/null | wc -l
}

# ── Test 1: Syntax check ──
test_syntax() {
    if bash -n "$SCRIPT_DIR/ob-session-recorder" 2>/dev/null; then
        pass "Syntax check"
    else
        fail "Syntax check"
    fi
}

# ── Test 2: --version / --help ──
test_version() {
    local out
    out=$(SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" bash "$SCRIPT_DIR/ob-session-recorder" --version 2>&1)
    if echo "$out" | grep -q "version"; then
        pass "--version outputs version"
    else
        fail "--version outputs version" "$out"
    fi
}

test_help() {
    local out
    out=$(SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" bash "$SCRIPT_DIR/ob-session-recorder" --help 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "--help outputs usage"
    else
        fail "--help outputs usage" "$out"
    fi
}

# ── Test 3: Unknown option rejected ──
test_unknown_option() {
    if SSH_CLIENT="" SSH_TTY="" SSH_ORIGINAL_COMMAND="" bash "$SCRIPT_DIR/ob-session-recorder" --bogus 2>/dev/null; then
        fail "Unknown option rejected"
    else
        pass "Unknown option rejected"
    fi
}

# ── Test 4: Config file parsing ──
test_config_parsing() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
# comment line
sessions_dir = /tmp/my-sessions
format = asciinema
max_duration = 3600

CONF
    (
        source_script "ob-session-recorder"
        # Override stat to simulate root-owned config for testing
        stat() { echo "0:644"; }
        export -f stat
        CONFIG_FILE="$tmpconf"
        load_config
        local ok=true
        [ "$SESSIONS_DIR" = "/tmp/my-sessions" ] || ok=false
        [ "$FORMAT" = "asciinema" ] || ok=false
        [ "$MAX_SESSION_DURATION" = "3600" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "Config parsing: sessions_dir, format, max_duration read correctly"
    else
        fail "Config parsing: sessions_dir, format, max_duration read correctly"
    fi
}

# ── Test 5: Config parsing ignores comments and blank lines ──
test_config_comments() {
    local tmpconf
    tmpconf=$(mktemp)
    cat > "$tmpconf" <<'CONF'
# full comment
   # indented comment

sessions_dir = /tmp/test
CONF
    (
        source_script "ob-session-recorder"
        # Override stat to simulate root-owned config for testing
        stat() { echo "0:644"; }
        export -f stat
        SESSIONS_DIR="/default"
        CONFIG_FILE="$tmpconf"
        load_config
        [ "$SESSIONS_DIR" = "/tmp/test" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -f "$tmpconf"
    if [ $rc -eq 0 ]; then
        pass "Config parsing ignores comments and blank lines"
    else
        fail "Config parsing ignores comments and blank lines"
    fi
}

# ── Test 6: generate_session_id produces non-empty UUID-like string ──
test_generate_session_id() {
    (
        source_script "ob-session-recorder"
        local id
        id=$(generate_session_id)
        [ -n "$id" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "generate_session_id produces non-empty string"
    else
        fail "generate_session_id produces non-empty string"
    fi
}

# ── Test 7: build_header emits a single-line JSON object with the session_id ──
# The recording is now streamed to the root sink (ob-record-sink); the recorder
# only builds a one-line JSON header (ob-record-connect rejects embedded
# newlines). It no longer writes files or metadata itself.
test_build_header_single_line() {
    (
        source_script "ob-session-recorder"
        SESSION_ID="test-uuid-123"
        SESSION_USER="alice"
        CLIENT_IP="10.0.0.1"
        TTY_NAME="/dev/pts/0"
        SESSION_START="2025-01-01T00:00:00Z"
        ORIGINAL_COMMAND="ls -la"
        FORMAT="script"
        local h
        h=$(build_header)
        # Exactly one line.
        [ "$(printf '%s' "$h" | wc -l)" -eq 0 ] || exit 1
        if command -v jq >/dev/null 2>&1; then
            printf '%s' "$h" | jq -e '.session_id == "test-uuid-123"' >/dev/null 2>&1 || exit 1
            printf '%s' "$h" | jq -e '.format == "script"' >/dev/null 2>&1 || exit 1
        else
            printf '%s' "$h" | grep -q '"session_id":"test-uuid-123"' || exit 1
        fi
        exit 0
    )
    if [ $? -eq 0 ]; then
        pass "build_header emits a single-line JSON header with session_id/format"
    else
        fail "build_header emits a single-line JSON header with session_id/format"
    fi
}

# ── Test 8: build_header keeps the header single-line even with a newline in the command ──
test_build_header_no_newline_injection() {
    (
        source_script "ob-session-recorder"
        SESSION_ID="id1"
        FORMAT="script"
        CLIENT_IP="x"; TTY_NAME="x"; SESSION_START="x"
        ORIGINAL_COMMAND=$'evil\ninjected'
        local h
        h=$(build_header)
        # Must remain a single line (jq escapes the newline as \n inside the string).
        [ "$(printf '%s' "$h" | wc -l)" -eq 0 ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "build_header keeps one line when the command contains a newline"
    else
        fail "build_header keeps one line when the command contains a newline"
    fi
}

# ── Test 8b: the no-jq header escapes EVERY field (#287) ──
# The fallback escaped only original_command. SSH_CLIENT and SSH_TTY are just as
# client-side: a quote or a newline there produced an invalid or multi-line
# header, which the connector refuses -- a session refused for a stray byte.
test_build_header_fallback_escapes_all_fields() {
    command -v python3 >/dev/null 2>&1 || { fail "python3 is needed to check the header"; return; }
    local h
    h=$(
        source_script "ob-session-recorder"
        # Hide jq from build_header, so the fallback is what runs.
        command() { [ "${1:-}" = "-v" ] && [ "${2:-}" = "jq" ] && return 1; builtin command "$@"; }
        SESSION_ID='id"1\'
        FORMAT=$'scr\tipt'
        CLIENT_IP=$'198.51.100.1\n"injected":1'
        TTY_NAME=$'/dev/pts/1\x01\x1b[2J'
        ORIGINAL_COMMAND=$'ls "a b"\\\r\n'
        SESSION_START=$'2026\x7f'
        build_header
    )
    if [ "$(printf '%s' "$h" | wc -l)" -eq 0 ] && printf '%s' "$h" | python3 -c '
import json, sys
h = json.loads(sys.stdin.read())
want = {"session_id": "id\"1\\", "format": "scr\tipt",
        "client_ip": "198.51.100.1\n\"injected\":1",
        "ssh_tty": "/dev/pts/1\x01\x1b[2J", "original_command": "ls \"a b\"\\\r\n",
        "start": "2026\x7f", "v": 2}
sys.exit(0 if h == want else 1)'; then
        pass "no-jq header: every field escaped, one valid JSON line"
    else
        fail "no-jq header is not one valid JSON line with every field intact" "$h"
    fi
}

# ── Test 8c: client-supplied strings reach syslog on one line (#287) ──
test_log_lines_sanitized() {
    local log
    log=$(mktemp)
    (
        source_script "ob-session-recorder"
        logger() { printf '%s\n' "$*" >> "$log"; }
        SESSION_ID="sid"
        CLIENT_IP=$'198.51.100.1\nFAKE: forged line'
        ORIGINAL_COMMAND=$'id\nFAKE: another forged line\x1b[1A'
        log_session_start
    )
    if [ "$(wc -l < "$log")" -eq 1 ] && ! grep -q $'\x1b' "$log" \
       && grep -q 'FAKE: forged line' "$log"; then
        pass "session start logged on one line, control characters escaped"
    else
        fail "a client-supplied string broke the syslog line" "$(cat -A "$log")"
    fi
    rm -f "$log"
}

# ── Test 8d: which commands skip the PTY recording (#287) ──
#
# A command classified as a file transfer runs WITHOUT its stream being
# recorded, so the classifier is an allow-list of what genuine clients send,
# and everything else must be recorded. The forms below were captured from
# OpenSSH 10 scp/sftp and rsync 3.x through a stand-in ssh; the refusals are
# the #287 bypasses and their variations.
CT_DIR=""
classify() { # $1 SSH_ORIGINAL_COMMAND  [$2 SSH_TTY] -> the verdict on stdout
    (
        source_script "ob-session-recorder"
        cd "$CT_DIR" || exit 99
        HOME="$CT_DIR/home"
        # The first candidate stands for "the root-owned system binary", so the
        # verdict does not depend on what this host has installed.
        resolve_system_bin() { printf '%s\n' "$1"; }
        logger() { printf '%s\n' "$*" >> "$CT_DIR/log"; }
        SESSION_ID="t"
        SSH_TTY="${2:-}"
        ORIGINAL_COMMAND="$1"
        if classify_transfer; then
            printf '%s' "$TRANSFER_BIN"
            [ "${#TRANSFER_ARGS[@]}" -eq 0 ] || printf ' [%s]' "${TRANSFER_ARGS[@]}"
        else
            printf 'RECORD'
        fi
    )
}

test_transfer_classification() {
    CT_DIR=$(mktemp -d)
    mkdir -p "$CT_DIR/home/foo"
    : > "$CT_DIR/home/foo/a.txt"; : > "$CT_DIR/home/foo/b.txt"
    : > "$CT_DIR/r1.log"; : > "$CT_DIR/r2.log"
    local H="$CT_DIR/home" bad=0 i got
    # command | expected argv (the program is the root-owned system binary)
    local -a accept=(
        'rsync --server -logDtpre.iLsfxCIvu . dst\ dir/'
        '/usr/bin/rsync [--server] [-logDtpre.iLsfxCIvu] [--] [.] [dst dir/]'
        'rsync --server --sender -vlogDtpre.iLsfxCIvu . ~/foo/*.txt my\ file'
        "/usr/bin/rsync [--server] [--sender] [-vlogDtpre.iLsfxCIvu] [--] [.] [$H/foo/a.txt] [$H/foo/b.txt] [my file]"
        'rsync --server --sender -vlogDtprze.iLsfxCIvu . /tmp/x'
        '/usr/bin/rsync [--server] [--sender] [-vlogDtprze.iLsfxCIvu] [--] [.] [/tmp/x]'
        'rsync --server -vlogDtpre.iLsfxCIvu --log-format=%i . ./-dash'
        '/usr/bin/rsync [--server] [-vlogDtpre.iLsfxCIvu] [--log-format=%i] [--] [.] [./-dash]'
        'rsync --server -lHogDtpAXre.iLsfxCIvu --numeric-ids . a\;b\$c'
        '/usr/bin/rsync [--server] [-lHogDtpAXre.iLsfxCIvu] [--numeric-ids] [--] [.] [a;b$c]'
        'rsync --server --sender -logDtpre.iLsfxCIvu . .'
        '/usr/bin/rsync [--server] [--sender] [-logDtpre.iLsfxCIvu] [--] [.] [.]'
        'rsync --server -logDtpre.iLsfxCIvu --delete --partial-dir=.p --timeout=30 . ~'
        "/usr/bin/rsync [--server] [-logDtpre.iLsfxCIvu] [--delete] [--partial-dir=.p] [--timeout=30] [--] [.] [$H]"
        'scp -t /tmp/d/'
        '/usr/bin/scp [-t] [--] [/tmp/d/]'
        'scp -r -p -f my\ file'
        '/usr/bin/scp [-r] [-p] [-f] [--] [my file]'
        'scp -v -f -- -x'
        '/usr/bin/scp [-v] [-f] [--] [-x]'
        'scp -d -t dir'
        '/usr/bin/scp [-d] [-t] [--] [dir]'
        'scp -f ~/foo/*.txt nomatch*.txt'
        "/usr/bin/scp [-f] [--] [$H/foo/a.txt] [$H/foo/b.txt] [nomatch*.txt]"
        'internal-sftp'
        '/usr/lib/openssh/sftp-server'
        '/usr/lib/openssh/sftp-server'
        '/usr/lib/openssh/sftp-server'
        '/usr/libexec/openssh/sftp-server -f AUTHPRIV -l INFO'
        '/usr/lib/openssh/sftp-server [-f] [AUTHPRIV] [-l] [INFO]'
    )
    local -a refuse=(
        'scp -t /tmp/x; bash'
        'scp -t /tmp/x;bash'
        'scp -t /tmp/x && bash'
        'scp -t /tmp/x | bash'
        'scp -t /tmp/x > /tmp/y'
        'scp -f $(id)'
        'scp -f `id`'
        'scp -f "a b"'
        "scp -f 'a'"
        'scp -f a{b,c}'
        'scp -f #x'
        'scp -f a!b'
        $'scp -t /tmp/x\nbash'
        $'scp\t-t\t/tmp/x'
        $'scp -f my\\\nfile'
        ' scp -t /tmp/x'
        'scp  -t /tmp/x'
        'scp -t /tmp/x '
        'scp -t /tmp/x\'
        'scp -t/tmp/d'
        'scp -tr /tmp/d'
        'scp -t'
        'scp -t a b'
        'scp -t -f x'
        'scp -x -t /tmp'
        'scp -f -x'
        'scp -d -f x'
        'scp -r -r -t x'
        'scp -f ~root/x'
        '~/.local/bin/scp -t /x'
        '/home/u/bin/scp -t /x'
        'rsync --server --daemon .'
        'rsync --server --daemon --config=/tmp/x . .'
        'rsync --server -slogDtpre.iLsfxCIvu'
        'rsync --server -slogDtpre.iLsfxCIvu . x'
        'rsync --server -logDtpre.iLsfxCIvu . a b'
        'rsync --server -logDtpre.iLsfxCIvu --rsh=sh . a'
        'rsync --server -logDtpre.iLsfxCIvu --log-file . a'
        'rsync --server -logDtpre.iLsfxCIvu a'
        'rsync -logDtpre.iLsfxCIvu --server . a'
        'rsync --server -logDtpre.iLsfxCIvu . a; id'
        '/usr/bin/rsync --server -logDtpre.iLsfxCIvu . a'
        'internal-sftp; bash'
        'internal-sftp -f $(id)'
        'sftp-server -h'
        'sftp-server -l'
        '/tmp/sftp-server'
        'sftp-server -d /tmp;id'
    )
    for ((i = 0; i < ${#accept[@]}; i += 2)); do
        got=$(classify "${accept[i]}")
        if [ "$got" != "${accept[i+1]}" ]; then
            fail "transfer allow-list: accept $(printf '%q' "${accept[i]}")" "got: $got"
            bad=1
        fi
    done
    for i in "${!refuse[@]}"; do
        got=$(classify "${refuse[i]}")
        if [ "$got" != "RECORD" ]; then
            fail "transfer allow-list: must record $(printf '%q' "${refuse[i]}")" "got: $got"
            bad=1
        fi
    done
    # A PTY request is never a transfer, however genuine the command.
    got=$(classify 'scp -t /tmp/d/' /dev/pts/3)
    [ "$got" = "RECORD" ] || { fail "transfer allow-list: a PTY session must be recorded" "got: $got"; bad=1; }
    # Refusals of transfer-like commands are logged, on one line each.
    if ! grep -q 'transfer-like command recorded as a normal session' "$CT_DIR/log" 2>/dev/null \
       || grep -q '^bash' "$CT_DIR/log"; then
        fail "transfer allow-list: refusals must be logged, one line each"; bad=1
    fi
    [ "$bad" = 0 ] && pass "transfer allow-list: ${#refuse[@]} forged forms recorded, $(( ${#accept[@]} / 2 )) genuine forms accepted, PTY never a transfer"
    rm -rf "$CT_DIR"
}

# ── Test 8e: a malformed max_duration does not switch the watchdog off ──
# `[ "abc" -gt 0 ]` fails inside an `if`, which `set -e` ignores: any typo in
# max_duration used to disable the watchdog silently.
test_max_duration_validation() {
    local v got bad=0 tmpconf
    for v in abc "" -5 1e3 12abc 1234567890 " 60" "60 "; do
        got=$(
            source_script "ob-session-recorder"
            logger() { :; }
            MAX_SESSION_DURATION="$v"
            validate_max_duration
            printf '%s' "$MAX_SESSION_DURATION"
        )
        [ "$got" = "86400" ] || { fail "max_duration '$v' should fall back to 86400" "got '$got'"; bad=1; }
    done
    for v in 0:0 007:7 3600:3600; do
        got=$(
            source_script "ob-session-recorder"
            logger() { :; }
            MAX_SESSION_DURATION="${v%%:*}"
            validate_max_duration
            printf '%s' "$MAX_SESSION_DURATION"
        )
        [ "$got" = "${v##*:}" ] || { fail "max_duration '${v%%:*}' should read as ${v##*:}" "got '$got'"; bad=1; }
    done
    # Through the config file, as an administrator's typo would arrive.
    tmpconf=$(mktemp)
    printf 'max_duration = 8h\n' > "$tmpconf"
    got=$(
        source_script "ob-session-recorder"
        stat() { echo "0:644"; }
        logger() { :; }
        CONFIG_FILE="$tmpconf"
        load_config
        validate_max_duration
        printf '%s' "$MAX_SESSION_DURATION"
    )
    rm -f "$tmpconf"
    [ "$got" = "86400" ] || { fail "max_duration = 8h in the config should fall back to 86400" "got '$got'"; bad=1; }
    [ "$bad" = 0 ] && pass "max_duration: non-numeric values fall back to the default, numbers are kept"
}

# ── Test 9: the recorder streams to the sink via ob-record-connect + a FIFO ──
# script(1) writes the typescript to a FIFO (a socket cannot be opened by path),
# and ob-record-connect forwards the FIFO to the sink socket.
test_streams_via_connect() {
    if grep -q 'ob-record-connect' "$SCRIPT_DIR/ob-session-recorder" && \
       grep -q 'mkfifo' "$SCRIPT_DIR/ob-session-recorder" && \
       grep -qE 'script .*-c .*OB_REC_FIFO' "$SCRIPT_DIR/ob-session-recorder"; then
        pass "recorder streams via ob-record-connect + FIFO"
    else
        fail "recorder should stream via ob-record-connect + a FIFO"
    fi
}

# ── Test 10: recording is mandatory — recorder refuses when ob-record-connect is absent ──
# main() checks `command -v ob-record-connect` and exits non-zero (fail-closed)
# if it is missing, rather than running an unrecorded session.
test_fail_closed_no_connect() {
    # In CI the ob-record-connect binary is not installed and the rec.sock does
    # not exist, so either way the recorder must refuse (non-zero) with a
    # "recording is required/unavailable" message instead of running a shell.
    local out rc
    out=$(SSH_CLIENT="1.2.3.4 5 22" SSH_TTY="" SSH_ORIGINAL_COMMAND="id" \
          /bin/bash "$SCRIPT_DIR/ob-session-recorder" 2>&1)
    rc=$?
    if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qiE "recording (is )?required|unavailable|refus"; then
        pass "recorder fails closed when the sink is unavailable"
    else
        fail "recorder should refuse the session when the sink is unavailable" "rc=$rc out=$out"
    fi
}

# ── Test 11: the user's environment does not set the tunables (#287) ──
# The recorder runs as the recorded user. OB_MAX_SESSION=0 in that user's
# environment used to switch the max_duration watchdog off, and
# OB_RECORDER_CONFIG could point it at a config other than the admin's.
test_env_ignored() {
    (
        export OB_RECORDER_CONFIG="/tmp/user-chosen.conf"
        export OB_SESSIONS_DIR="/tmp/env-sessions"
        export OB_RECORDER_FORMAT="ttyrec"
        export OB_MAX_SESSION="0"
        export RECORD_CONNECT="/tmp/fake-connect"
        export RECORD_SOCKET="/tmp/fake.sock"
        source_script "ob-session-recorder"
        local ok=true
        [ "$CONFIG_FILE" = "/etc/open-bastion/session-recorder.conf" ] || ok=false
        [ "$SESSIONS_DIR" = "/var/lib/open-bastion/sessions" ] || ok=false
        [ "$FORMAT" = "script" ] || ok=false
        [ "$MAX_SESSION_DURATION" = "86400" ] || ok=false
        [ -z "$RECORD_CONNECT" ] || ok=false
        [ "$RECORD_SOCKET" = "/run/open-bastion/rec.sock" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "OB_* and RECORD_* in the environment are ignored"
    else
        fail "the environment overrode a recorder tunable"
    fi
}

# ── Test 11b: helpers do not come from the user's PATH (#287) ──
# A user-writable PATH entry (PermitUserEnvironment, a pam_env file, ~/bin
# added by an operator) could shadow `script` or `ob-record-connect` with a
# program that records nothing. The recorder sets its own PATH and looks the
# connector up among root-owned paths only.
test_helpers_not_from_user_path() {
    local fake marker out rc
    fake=$(mktemp -d)
    marker="$fake/used"
    for prog in ob-record-connect script logger jq uuidgen; do
        printf '#!/bin/sh\necho %s >> %s\nexit 0\n' "$prog" "$marker" > "$fake/$prog"
        chmod +x "$fake/$prog"
    done
    out=$(PATH="$fake:$PATH" SSH_CLIENT="1.2.3.4 5 22" SSH_TTY="" SSH_ORIGINAL_COMMAND="id" \
          bash -p "$SCRIPT_DIR/ob-session-recorder" 2>&1)
    rc=$?
    if [ -e "$marker" ]; then
        fail "the recorder ran a helper from the user's PATH" "$(tr '\n' ' ' < "$marker")"
    elif [ -x /usr/bin/ob-record-connect ] || [ -x /usr/local/bin/ob-record-connect ]; then
        pass "no helper taken from the user's PATH (connector installed, rc=$rc)"
    elif [ $rc -ne 0 ]; then
        pass "no helper taken from the user's PATH (no system connector: refused)"
    else
        fail "no system connector, yet the session was not refused" "$out"
    fi
    rm -rf "$fake"
}

# ── Test 12: parse_args -c, -d, -f set correct variables ──
test_parse_args() {
    (
        source_script "ob-session-recorder"
        parse_args -c /tmp/myconf -d /tmp/mydir -f asciinema
        local ok=true
        [ "$CONFIG_FILE" = "/tmp/myconf" ] || ok=false
        [ "$SESSIONS_DIR" = "/tmp/mydir" ] || ok=false
        [ "$FORMAT" = "asciinema" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "parse_args -c, -d, -f set correct variables"
    else
        fail "parse_args -c, -d, -f set correct variables"
    fi
}

# ── Test 13: Invalid SESSION_USER regex rejects path traversal ──
test_invalid_session_user() {
    # Test the validation regex directly (SESSION_USER is now derived from
    # id -un, not $USER, so we can't inject via environment).
    (
        SESSION_USER="../../../etc/passwd"
        if [[ ! "$SESSION_USER" =~ ^[a-z_][a-z0-9_.-]*$ ]]; then
            exit 0  # correctly rejected
        else
            exit 1  # incorrectly accepted
        fi
    )
    if [ $? -eq 0 ]; then
        pass "Invalid SESSION_USER (path traversal) is rejected by regex"
    else
        fail "Invalid SESSION_USER (path traversal) was unexpectedly accepted by regex"
    fi
}

# ── Test 14: Valid SESSION_USER passes regex validation ──
test_valid_session_user() {
    (
        SESSION_USER="alice"
        if [[ "$SESSION_USER" =~ ^[a-z_][a-z0-9_.-]*$ ]]; then
            exit 0  # correctly accepted
        else
            exit 1  # incorrectly rejected
        fi
    )
    if [ $? -eq 0 ]; then
        pass "Valid SESSION_USER passes regex validation"
    else
        fail "Valid SESSION_USER was unexpectedly rejected by regex"
    fi
}

# ── Test 15: Script uses id -un, not $USER ──
test_session_user_from_uid() {
    # Verify the script source contains 'id -un' and not '${USER'
    if grep -q 'id -un' "$SCRIPT_DIR/ob-session-recorder" && \
       ! grep -q 'SESSION_USER=.*\${USER' "$SCRIPT_DIR/ob-session-recorder"; then
        pass "SESSION_USER derived from id -un, not \$USER"
    else
        fail "SESSION_USER should use id -un, not \$USER"
    fi
}


# ── E2E 1: a command session is recorded, whatever the user's environment ──
# OB_RECORD_SOCKET pointing nowhere and a fake `script` first in PATH must not
# change where, or whether, the session is recorded.
test_e2e_command_recorded() {
    local fake j ts
    fake="$E2E_WORK/fakebin"
    mkdir -p "$fake"
    printf '#!/bin/sh\ntouch %s/fake-script-ran\nexec /bin/sh -c "$4"\n' "$E2E_WORK" > "$fake/script"
    chmod +x "$fake/script"
    e2e_driver
    e2e_run 'echo OB-E2E-""HELLO' OB_RECORD_SOCKET="$E2E_WORK/nowhere.sock" \
        PATH="$fake:$PATH" </dev/null >/dev/null 2>&1
    j=$(e2e_last_json); ts="${j%.json}.typescript"
    if [ -e "$E2E_WORK/fake-script-ran" ]; then
        fail "E2E: the recorder ran \`script\` from the user's PATH"
    elif [ -n "$j" ] && grep -q '"status": "completed"' "$j" && grep -q '"format": "script"' "$j" \
         && grep -q OB-E2E-HELLO "$ts" 2>/dev/null; then
        pass "E2E: command session recorded through the system sink, env ignored"
    else
        fail "E2E: command session not recorded as expected" "json=$j"
    fi
}

# ── E2E 2: the #287 bypass now opens a RECORDED session ──
# `ssh -tt bastion 'scp -t /tmp/x; bash'` used to run the whole string through
# a shell with no typescript at all. Now it is an ordinary command session.
test_e2e_bypass_recorded() {
    local j
    e2e_driver
    e2e_run 'scp -t /nonexistent-ob-287; echo OB-287-NOW-""RECORDED' </dev/null >/dev/null 2>&1
    j=$(e2e_last_json)
    if [ -n "$j" ] && grep -q '"format": "script"' "$j" \
       && grep -q OB-287-NOW-RECORDED "${j%.json}.typescript" 2>/dev/null; then
        pass "E2E: 'scp -t /x; <command>' runs recorded, output in the typescript"
    else
        fail "E2E: the #287 compound command was not recorded" "json=$j"
        [ -n "$j" ] && cat "$j"
    fi
}

# A stand-in for ssh, for rsync -e / scp -S / sftp -S: it runs the recorder as
# sshd would under ForceCommand, with the remote command (or, for a subsystem
# request, the Subsystem command) as SSH_ORIGINAL_COMMAND, and no PTY.
e2e_fakessh() {
    cat > "$E2E_WORK/fakessh" <<'EOF'
#!/bin/bash
sub=0
while [ $# -gt 0 ]; do
    case "$1" in
        -s) sub=1; shift ;;
        -[bcDEeFIiJLlmOoPpQRSWw]) shift 2 ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
shift                                   # the host
if [ "$sub" = 1 ]; then cmd=$OB_TEST_SUBSYSTEM; else cmd="$*"; fi
exec env -u SSH_TTY SSH_ORIGINAL_COMMAND="$cmd" SSH_CLIENT="203.0.113.7 50000 22" \
    HOME="$OB_TEST_HOME" setsid bash -p "$OB_TEST_RECORDER"
EOF
    chmod +x "$E2E_WORK/fakessh"
}

# The last session must be a transfer: metadata only, completed.
e2e_expect_transfer() { # $1 label  $2 sessions before
    local j
    if [ "$(e2e_session_count)" -le "$2" ]; then
        fail "E2E transfer ($1): no session recorded"; return 1
    fi
    j=$(e2e_last_json)
    if grep -q '"format": "transfer"' "$j" && grep -q '"status": "completed"' "$j" \
       && [ ! -s "${j%.json}.typescript" ]; then
        return 0
    fi
    fail "E2E transfer ($1): not recorded as a completed transfer" "json=$j"
    return 1
}

# ── E2E 3: genuine rsync, scp (both protocols) and sftp still work ──
test_e2e_transfers() {
    local w="$E2E_WORK" ssh="$E2E_WORK/fakessh" n ok=1
    local -a missing=()
    for b in rsync scp sftp; do command -v "$b" >/dev/null 2>&1 || missing+=("$b"); done
    [ -x /usr/bin/rsync ] || missing+=("/usr/bin/rsync")
    local have_sftp=0 s
    for s in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server \
             /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; do
        [ -x "$s" ] && have_sftp=1
    done
    [ "$have_sftp" = 1 ] || missing+=("sftp-server")
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "SKIP: E2E transfers need ${missing[*]}"
        return
    fi
    e2e_driver
    e2e_fakessh
    export OB_TEST_RECORDER="$w/recorder" OB_TEST_HOME="$w/home" OB_TEST_SUBSYSTEM=internal-sftp
    mkdir -p "$w/src" "$w/dst" "$w/home/pull" "$w/rsync-pull" "$w/scp-pull"
    printf 'first\n' > "$w/src/my file.txt"
    printf 'second\n' > "$w/src/b.txt"
    cp "$w/src/"*.txt "$w/home/pull/"

    # rsync push, into a directory whose name needs escaping
    n=$(e2e_session_count)
    if rsync -a -e "$ssh" "$w/src/" "h:$w/dst/sub dir/" </dev/null >/dev/null 2>&1 \
       && cmp -s "$w/src/my file.txt" "$w/dst/sub dir/my file.txt"; then
        e2e_expect_transfer "rsync push" "$n" || ok=0
    else
        fail "E2E transfer: rsync push failed"; ok=0
    fi
    # rsync pull, with a leading ~ and a wildcard for the remote shell
    n=$(e2e_session_count)
    if rsync -a -e "$ssh" "h:~/pull/*.txt" "$w/rsync-pull/" </dev/null >/dev/null 2>&1 \
       && cmp -s "$w/src/b.txt" "$w/rsync-pull/b.txt" \
       && cmp -s "$w/src/my file.txt" "$w/rsync-pull/my file.txt"; then
        e2e_expect_transfer "rsync pull" "$n" || ok=0
    else
        fail "E2E transfer: rsync pull with ~ and a wildcard failed"; ok=0
    fi
    # legacy scp (-O): push, then pull with ~ and a wildcard
    n=$(e2e_session_count)
    if scp -O -q -S "$ssh" "$w/src/b.txt" "h:$w/dst/scp-legacy.txt" </dev/null >/dev/null 2>&1 \
       && cmp -s "$w/src/b.txt" "$w/dst/scp-legacy.txt"; then
        e2e_expect_transfer "scp -O push" "$n" || ok=0
    else
        fail "E2E transfer: legacy scp push failed"; ok=0
    fi
    n=$(e2e_session_count)
    if scp -O -q -S "$ssh" "h:~/pull/*.txt" "$w/scp-pull/" </dev/null >/dev/null 2>&1 \
       && cmp -s "$w/src/my file.txt" "$w/scp-pull/my file.txt"; then
        e2e_expect_transfer "scp -O pull" "$n" || ok=0
    else
        fail "E2E transfer: legacy scp pull with ~ and a wildcard failed"; ok=0
    fi
    # modern scp and sftp: the sftp subsystem, i.e. internal-sftp
    n=$(e2e_session_count)
    if scp -q -S "$ssh" "$w/src/b.txt" "h:$w/dst/scp-sftp.txt" </dev/null >/dev/null 2>&1 \
       && cmp -s "$w/src/b.txt" "$w/dst/scp-sftp.txt"; then
        e2e_expect_transfer "scp (sftp protocol)" "$n" || ok=0
    else
        fail "E2E transfer: scp over the sftp subsystem failed"; ok=0
    fi
    n=$(e2e_session_count)
    if printf 'put %s %s\nget %s %s\n' "$w/src/b.txt" "$w/dst/sftp-put.txt" \
            "$w/src/b.txt" "$w/sftp-get.txt" \
       | sftp -q -b - -S "$ssh" h >/dev/null 2>&1 \
       && cmp -s "$w/src/b.txt" "$w/dst/sftp-put.txt" && cmp -s "$w/src/b.txt" "$w/sftp-get.txt"; then
        e2e_expect_transfer "sftp" "$n" || ok=0
    else
        fail "E2E transfer: sftp (internal-sftp subsystem) failed"; ok=0
    fi
    [ "$ok" = 1 ] && pass "E2E: rsync push/pull, scp -O push/pull, scp and sftp work, each recorded as a transfer"
}

# ── E2E 4: the recording channel lives in a private directory, removed after ──
# The FIFO used to be `mktemp -u` + `mkfifo` in /tmp: a predicted name in a
# shared directory. It is now inside a `mktemp -d` directory (0700). The
# session itself looks at it, so the answer lands in its own typescript.
test_e2e_private_channel_dir() {
    local j tmp="$E2E_WORK/tmp"
    rm -rf "$tmp"; mkdir -p "$tmp"
    e2e_driver "REC_TMP_BASE=$(printf '%q' "$tmp")"
    e2e_run "stat -c 'OB-CHAN %a %F' $tmp/ob-rec.* $tmp/ob-rec.*/stream" </dev/null >/dev/null 2>&1
    j=$(e2e_last_json)
    if grep -q 'OB-CHAN 700 directory' "${j%.json}.typescript" 2>/dev/null \
       && grep -q 'OB-CHAN 600 fifo' "${j%.json}.typescript" 2>/dev/null \
       && [ -z "$(ls -A "$tmp")" ]; then
        pass "E2E: FIFO in a private 0700 directory, removed when the session ends"
    else
        fail "E2E: recording channel not private, or left behind" \
            "$(grep -a OB-CHAN "${j%.json}.typescript" 2>/dev/null | tr -d '\r' | tr '\n' ' ') left: $(ls -A "$tmp")"
    fi
}

# ── E2E 5: max_duration really ends the session (#287) ──
# The old watchdog was an ALRM trap, which bash defers until the foreground
# command -- script, i.e. the whole session -- returns: it never fired in
# time. Here a session that would run for 30 s has a 2 s limit.
test_e2e_max_duration() {
    local j tmp="$E2E_WORK/tmp" start elapsed rc=0 ok=1
    rm -rf "$tmp"; mkdir -p "$tmp"
    e2e_driver "MAX_SESSION_DURATION=2" "WATCHDOG_GRACE=2" "REC_TMP_BASE=$(printf '%q' "$tmp")"
    start=$SECONDS
    e2e_run 'echo WD-""START; sleep 30; echo WD-""END' </dev/null >/dev/null 2>&1 || rc=$?
    elapsed=$((SECONDS - start))
    j=$(e2e_last_json)
    if [ "$elapsed" -ge 15 ]; then
        fail "E2E: max_duration=2 did not end the session (${elapsed}s)"; ok=0
    fi
    if ! grep -q WD-START "${j%.json}.typescript" 2>/dev/null \
       || grep -q WD-END "${j%.json}.typescript" 2>/dev/null; then
        fail "E2E: the timed-out session's recording is wrong" "json=$j elapsed=$elapsed $(tr -d "\r" < "${j%.json}.typescript" 2>/dev/null | tr "\n" " ")"; ok=0
    fi
    # The forwarder survives the hang-up and delivers the end of the stream.
    grep -q '"status": "completed"' "$j" 2>/dev/null \
        || { fail "E2E: the timed-out session's recording is not complete" "$(cat "$j" 2>/dev/null)"; ok=0; }
    [ "$rc" -ne 0 ] || { fail "E2E: a timed-out session exited 0"; ok=0; }
    [ -z "$(ls -A "$tmp")" ] || { fail "E2E: the timed-out session left its FIFO behind" "$(ls -A "$tmp")"; ok=0; }

    # A transfer is bounded too: an sftp-server whose client never speaks.
    local s have_sftp=0
    for s in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server \
             /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; do
        [ -x "$s" ] && have_sftp=1
    done
    if [ "$have_sftp" = 1 ]; then
        local quiet="$E2E_WORK/quiet-client" qpid
        mkfifo "$quiet"
        sleep 30 > "$quiet" 2>/dev/null &     # holds the transfer's stdin open, says nothing
        qpid=$!
        start=$SECONDS
        e2e_run internal-sftp < "$quiet" >/dev/null 2>&1
        elapsed=$((SECONDS - start))
        kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null
        rm -f "$quiet"
        [ "$elapsed" -lt 15 ] || { fail "E2E: max_duration=2 did not end an idle sftp transfer (${elapsed}s)"; ok=0; }
    else
        echo "SKIP: E2E max_duration on a transfer needs sftp-server"
    fi
    [ "$ok" = 1 ] && pass "E2E: max_duration ends the session (and a transfer), recording complete, FIFO removed"
}

# ── Run all tests ──
echo "=== Testing ob-session-recorder ==="
run_test test_syntax
run_test test_version
run_test test_help
run_test test_unknown_option
run_test test_config_parsing
run_test test_config_comments
run_test test_generate_session_id
run_test test_build_header_single_line
run_test test_build_header_no_newline_injection
run_test test_build_header_fallback_escapes_all_fields
run_test test_log_lines_sanitized
run_test test_transfer_classification
run_test test_max_duration_validation
run_test test_streams_via_connect
run_test test_fail_closed_no_connect
run_test test_env_ignored
run_test test_helpers_not_from_user_path
run_test test_parse_args
run_test test_invalid_session_user
run_test test_valid_session_user
run_test test_session_user_from_uid

echo "--- end to end (real recorder, connector and sink) ---"
if e2e_setup; then
    run_test test_e2e_command_recorded
    run_test test_e2e_bypass_recorded
    run_test test_e2e_transfers
    run_test test_e2e_private_channel_dir
    run_test test_e2e_max_duration
fi

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
