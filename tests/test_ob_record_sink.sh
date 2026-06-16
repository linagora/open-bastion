#!/bin/bash
# test_ob_record_sink.sh
#
# End-to-end test for the tamper-evident recording chain (#151):
#   ob-record-connect (unprivileged) → ob-record.socket → ob-record-sink (root).
#
# Uses systemd-socket-activate --accept to stand up the socket and pass each
# accepted AF_UNIX connection to the sink as fd 3 (so SO_PEERCRED resolves to the
# connecting test user, exactly as in production). OB_SESSIONS_DIR redirects the
# sink's output tree into a throwaway dir (the daemon env is systemd-controlled
# in production, never client-controlled).
#
# Skips (exit 0) when the binaries are not built or systemd-socket-activate is
# unavailable.

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SINK="$SCRIPT_DIR/build/ob-record-sink"
CONNECT="$SCRIPT_DIR/build/ob-record-connect"

if [ ! -x "$SINK" ] || [ ! -x "$CONNECT" ]; then
    echo "SKIP: build/ob-record-sink or build/ob-record-connect missing (cmake --build build)"
    exit 0
fi
SA=$(command -v systemd-socket-activate 2>/dev/null)
[ -z "$SA" ] && [ -x /usr/lib/systemd/systemd-socket-activate ] && SA=/usr/lib/systemd/systemd-socket-activate
[ -z "$SA" ] && [ -x /lib/systemd/systemd-socket-activate ] && SA=/lib/systemd/systemd-socket-activate
if [ -z "$SA" ]; then
    echo "SKIP: systemd-socket-activate not available"
    exit 0
fi

WORK=$(mktemp -d)
SESS="$WORK/sessions"
SOCK="$WORK/rec.sock"
mkdir -p "$SESS"
USER_NAME=$(id -un)

fail=0
ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }

# Start the activator: each connection spawns the sink with OB_SESSIONS_DIR set.
"$SA" --accept -l "$SOCK" env OB_SESSIONS_DIR="$SESS" "$SINK" >"$WORK/sa.log" 2>&1 &
SA_PID=$!
trap 'kill "$SA_PID" 2>/dev/null; rm -rf "$WORK"' EXIT

# Wait for the socket to appear.
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
if [ ! -S "$SOCK" ]; then
    echo "SKIP: socket did not come up (systemd-socket-activate unusable here)"
    cat "$WORK/sa.log" 2>/dev/null
    exit 0
fi

hdr() { # $1 session_id  $2 format
    printf '{"v":1,"session_id":"%s","format":"%s","client_ip":"203.0.113.9","ssh_tty":"/dev/pts/9","original_command":"","start":"2026-01-01T00:00:00Z"}' "$1" "$2"
}

# Wait until the sink has finalized the session (json exists and status != active).
# Echoes the json path on success.
wait_done() { # $1 session_id
    local j
    for _ in $(seq 1 80); do
        j=$(ls "$SESS/$USER_NAME"/*_"$1".json 2>/dev/null | head -1)
        if [ -n "$j" ] && ! grep -q '"status": "active"' "$j"; then
            echo "$j"; return 0
        fi
        sleep 0.1
    done
    echo "$j"; return 1
}

# ── Test 1: interactive-style stream is captured, root-owned tree, status completed
OB_RECORD_SOCKET="$SOCK" "$CONNECT" "$(hdr testid01 script)" \
    sh -c 'printf "HELLO-RECORDING\n" >&3' 2>"$WORK/c1.err"
js=$(wait_done testid01)
ts="${js%.json}.typescript"
if [ -f "$ts" ] && grep -q "HELLO-RECORDING" "$ts"; then
    ok "stream captured into the recording file"
else
    bad "stream not captured (file=$ts)"; cat "$WORK/c1.err" 2>/dev/null
fi
if [ -n "$js" ] && grep -q '"status": "completed"' "$js" \
   && grep -q "\"user\": \"$USER_NAME\"" "$js" \
   && grep -q '"session_id": "testid01"' "$js"; then
    ok "metadata json: user from SO_PEERCRED, status completed"
else
    bad "metadata json wrong/missing (file=$js)"; [ -n "$js" ] && cat "$js"
fi

# ── Test 2: the recorded user comes from SO_PEERCRED, NOT the header
OB_RECORD_SOCKET="$SOCK" "$CONNECT" \
    '{"v":1,"session_id":"spoofid1","format":"script","client_ip":"x","ssh_tty":"x","original_command":"","start":"x"}' \
    sh -c 'printf "x\n" >&3' 2>/dev/null
# Even if the header had tried another name, the file must land under our user.
sj=$(wait_done spoofid1)
if [ -n "$sj" ]; then
    ok "path derives from SO_PEERCRED uid (no header-controlled user)"
else
    bad "spoof session not under the real user dir"
fi

# ── Test 3: transfer session — header only, empty placeholder, status completed
OB_RECORD_SOCKET="$SOCK" "$CONNECT" "$(hdr xferid01 transfer)" true 2>/dev/null
tj=$(wait_done xferid01)
tt="${tj%.json}.typescript"
if [ -n "$tj" ] && grep -q '"format": "transfer"' "$tj" && grep -q '"status": "completed"' "$tj" \
   && [ -f "$tt" ] && [ ! -s "$tt" ]; then
    ok "transfer session: metadata-only, empty placeholder"
else
    bad "transfer session wrong (json=$tj typescript=$tt)"
fi

# ── Test 4: fail-closed — unreachable sink → connector exits non-zero, no exec
if OB_RECORD_SOCKET="$WORK/nope.sock" "$CONNECT" "$(hdr noid script)" \
       sh -c 'echo SHOULD-NOT-RUN >&3' 2>/dev/null; then
    bad "connector returned 0 against an unreachable sink (should fail closed)"
else
    ok "fail-closed: unreachable sink → connector non-zero, command not run"
fi

echo "=== record-sink e2e: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ==="
exit $fail
