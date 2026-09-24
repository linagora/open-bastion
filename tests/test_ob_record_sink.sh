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

# Start an activator: each connection spawns the sink with OB_SESSIONS_DIR set,
# plus any extra VAR=value given (the daemon's own environment, which systemd
# owns in production). OB_RECORD_POLL_SEC=1 makes an idle stream wake the sink
# every second instead of every 30, so the tests below can idle for several
# wake-ups -- longer than the 30 s timeout #287 removed, in the sink's own
# units -- without sleeping for half a minute.
SA_PIDS=""
trap 'kill $SA_PIDS 2>/dev/null; rm -rf "$WORK"' EXIT
start_activator() { # $1 socket  $2 log  [VAR=value...]
    local sock="$1" log="$2"; shift 2
    "$SA" --accept -l "$sock" env OB_SESSIONS_DIR="$SESS" "$@" "$SINK" >"$log" 2>&1 &
    SA_PIDS="$SA_PIDS $!"
    for _ in $(seq 1 50); do [ -S "$sock" ] && return 0; sleep 0.1; done
    return 1
}

if ! start_activator "$SOCK" "$WORK/sa.log" OB_RECORD_POLL_SEC=1; then
    echo "SKIP: socket did not come up (systemd-socket-activate unusable here)"
    cat "$WORK/sa.log" 2>/dev/null
    exit 0
fi
# A second sink whose duration cap is two seconds.
CAP_SOCK="$WORK/rec-cap.sock"
if ! start_activator "$CAP_SOCK" "$WORK/sa-cap.log" OB_RECORD_POLL_SEC=1 OB_RECORD_MAX_SEC=2; then
    bad "the duration-capped sink did not come up"
fi

hdr() { # $1 session_id  $2 format
    printf '{"v":2,"session_id":"%s","format":"%s","client_ip":"203.0.113.9","ssh_tty":"/dev/pts/9","original_command":"","start":"2026-01-01T00:00:00Z"}' "$1" "$2"
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

# Drive a PTY recording exactly as ob-session-recorder does: script(1) writes the
# typescript to a FIFO, ob-record-connect forwards FIFO -> socket. This exercises
# the REAL path (a socket cannot be opened via /dev/fd, so script must target a
# FIFO) — the gap that an earlier "/dev/fd/3" approach hid.
record_via_script() { # $1 header  $2 command
    local fifo; fifo="$WORK/fifo.$$.$RANDOM"
    mkfifo -m 600 "$fifo" || return 1
    OB_RECORD_SOCKET="${REC_SOCK:-$SOCK}" "$CONNECT" "$1" "$fifo" &
    local cpid=$!
    sleep 0.2
    if ! kill -0 "$cpid" 2>/dev/null; then wait "$cpid"; rm -f "$fifo"; return 1; fi
    script -q -f -c "$2" "$fifo" >/dev/null 2>&1
    wait "$cpid"; local rc=$?
    rm -f "$fifo"
    return $rc
}

# ── Test 1: interactive PTY stream captured via script→FIFO→sink, root-owned
record_via_script "$(hdr testid01 script)" 'printf "HELLO-RECORDING\n"' 2>"$WORK/c1.err"
js=$(wait_done testid01)
ts="${js%.json}.typescript"
if [ -f "$ts" ] && grep -q "HELLO-RECORDING" "$ts"; then
    ok "PTY stream captured (script -> FIFO -> sink)"
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
record_via_script \
    '{"v":2,"session_id":"spoofid1","format":"script","client_ip":"x","ssh_tty":"x","original_command":"","start":"x"}' \
    'printf "x\n"' 2>/dev/null
sj=$(wait_done spoofid1)
if [ -n "$sj" ]; then
    ok "path derives from SO_PEERCRED uid (no header-controlled user)"
else
    bad "spoof session not under the real user dir"
fi

# ── Test 3: transfer session — /dev/null stream, empty placeholder, status completed
OB_RECORD_SOCKET="$SOCK" "$CONNECT" "$(hdr xferid01 transfer)" /dev/null 2>/dev/null
tj=$(wait_done xferid01)
tt="${tj%.json}.typescript"
if [ -n "$tj" ] && grep -q '"format": "transfer"' "$tj" && grep -q '"status": "completed"' "$tj" \
   && [ -f "$tt" ] && [ ! -s "$tt" ]; then
    ok "transfer session: metadata-only, empty placeholder"
else
    bad "transfer session wrong (json=$tj typescript=$tt)"
fi

# ── Test 4: fail-closed — unreachable sink → connector exits non-zero before stream
if OB_RECORD_SOCKET="$WORK/nope.sock" "$CONNECT" "$(hdr noid script)" /dev/null 2>/dev/null; then
    bad "connector returned 0 against an unreachable sink (should fail closed)"
else
    ok "fail-closed: unreachable sink → connector non-zero"
fi

# ── Test 5: a duplicate session_id must never truncate existing metadata (#198)
#
# File names are <ts>_<session_id>.{typescript,json} and session_id comes from
# the client, so a replayed id landing in the same second collides. The
# typescript is created with O_EXCL and rejects the duplicate — but the
# metadata used to be written FIRST with O_TRUNC, so it was already destroyed
# by the time the connection got refused.
#
# Deterministic setup: wait for a fresh second, plant the metadata file the
# sink is about to pick, then connect. If the sink still landed on another
# second (files under a different prefix appeared) the attempt is inconclusive
# and retried with a new id.
dup_metadata_attempt() { # $1 session_id -> echoes the timestamp used
    local sid="$1" before ts
    before=$(date +%Y%m%d-%H%M%S)
    while [ "$(date +%Y%m%d-%H%M%S)" = "$before" ]; do sleep 0.05; done
    ts=$(date +%Y%m%d-%H%M%S)

    mkdir -p "$SESS/$USER_NAME"
    printf 'PRE-EXISTING-METADATA' >"$SESS/$USER_NAME/${ts}_${sid}.json"

    OB_RECORD_SOCKET="$SOCK" "$CONNECT" "$(hdr "$sid" transfer)" /dev/null \
        >/dev/null 2>&1
    # Let the (short-lived) sink instance finish before inspecting the tree.
    sleep 1
    echo "$ts"
}

dup_ok=0
dup_msg="sink never landed on the pre-created timestamp (inconclusive)"
for attempt in 1 2 3 4 5; do
    dsid="dupid00$attempt"
    dts=$(dup_metadata_attempt "$dsid")
    djson="$SESS/$USER_NAME/${dts}_${dsid}.json"
    dts_file="$SESS/$USER_NAME/${dts}_${dsid}.typescript"
    # Another prefix => the sink used a different second: retry.
    other=0
    for f in "$SESS/$USER_NAME"/*_"$dsid".json; do
        [ -e "$f" ] || continue
        [ "$f" = "$djson" ] || other=1
    done
    if [ "$other" = 1 ]; then
        continue
    fi
    if ! grep -q 'PRE-EXISTING-METADATA' "$djson" 2>/dev/null; then
        dup_msg="duplicate session_id truncated the existing metadata ($djson)"
        break
    fi
    if [ -e "$dts_file" ]; then
        dup_msg="duplicate session_id was accepted (created $dts_file)"
        break
    fi
    dup_ok=1
    break
done
if [ "$dup_ok" = 1 ]; then
    ok "duplicate session_id refused, existing metadata intact"
else
    bad "$dup_msg"
fi

# ── Test 6: silence is not the end of a session (#287)
#
# The sink used to put a 30 s SO_RCVTIMEO on the stream: a user who read a man
# page for half a minute had their recording finalized as "aborted", and was
# then disconnected at the next keystroke when the forwarder hit SIGPIPE. Here
# the stream stays silent for four of the sink's idle wake-ups; everything
# printed after the pause must still be recorded, and the session completed.
record_via_script "$(hdr idleid01 script)" \
    'printf "BEFORE-IDLE\n"; sleep 4; printf "AFTER-IDLE\n"' 2>/dev/null
ij=$(wait_done idleid01)
its="${ij%.json}.typescript"
if [ -n "$ij" ] && grep -q '"status": "completed"' "$ij" \
   && grep -q BEFORE-IDLE "$its" && grep -q AFTER-IDLE "$its"; then
    ok "an idle session keeps recording and completes"
else
    bad "an idle stream ended the recording (json=$ij)"; [ -n "$ij" ] && cat "$ij"
fi

# ── Test 7: a connection that outlives its peer is not held open forever
#
# With no idle timeout, what bounds a connection is the process that opened it.
# The peer connects, sends a header and some bytes, hands the socket to a child
# and exits: the socket never reaches EOF, and only the peer's death can end
# the recording.
python3 - "$SOCK" "$(hdr deadpeer01 script)" "$WORK/holder.pid" <<'PY' >/dev/null 2>&1
import os, socket, struct, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
data = b"BEFORE-PEER-EXIT\n"
s.sendall(sys.argv[2].encode() + b"\n" + struct.pack(">I", len(data)) + data)
pid = os.fork()
if pid == 0:
    time.sleep(30)          # keeps the connection open, never writes
    os._exit(0)
with open(sys.argv[3], "w") as f:
    f.write(str(pid))
os._exit(0)                 # the peer the sink identified is gone
PY
dj=$(wait_done deadpeer01)
[ -s "$WORK/holder.pid" ] && kill "$(cat "$WORK/holder.pid")" 2>/dev/null
if [ -n "$dj" ] && grep -q '"status": "aborted"' "$dj" \
   && grep -q BEFORE-PEER-EXIT "${dj%.json}.typescript"; then
    ok "peer gone, connection held elsewhere: finalized as aborted"
else
    bad "a connection outliving its peer was not finalized as aborted (json=$dj)"
    [ -n "$dj" ] && cat "$dj"
fi

# ── Test 8: the total duration cap still bounds a live, silent session
REC_SOCK="$CAP_SOCK" record_via_script "$(hdr capid01 script)" \
    'printf "UNDER-CAP\n"; sleep 5' 2>/dev/null
cj=$(wait_done capid01)
if [ -n "$cj" ] && grep -q '"status": "truncated"' "$cj" \
   && grep -q UNDER-CAP "${cj%.json}.typescript"; then
    ok "duration cap reached: finalized as truncated"
else
    bad "the duration cap did not finalize the recording as truncated (json=$cj)"
    [ -n "$cj" ] && cat "$cj"
fi

# ── Test 9: a killed forwarder is an aborted recording, not a completed one
#
# #287 / EBIOS MT34: the forwarder runs as the recorded user, who can kill it
# from inside the session. An unframed stream ends in EOF either way, and the
# sink stamped both "completed". Now only the end-of-stream frame, sent after a
# clean EOF on the FIFO, completes a recording.
kfifo="$WORK/fifo.kill"
mkfifo -m 600 "$kfifo"
OB_RECORD_SOCKET="$SOCK" "$CONNECT" "$(hdr killid01 script)" "$kfifo" 2>/dev/null &
kpid=$!
sleep 0.2
script -q -f -c 'printf "BEFORE-KILL\n"; sleep 3; printf "AFTER-KILL\n"' "$kfifo" \
    >/dev/null 2>&1 &
spid=$!
sleep 1
kill -KILL "$kpid" 2>/dev/null
wait "$kpid" 2>/dev/null
wait "$spid" 2>/dev/null
rm -f "$kfifo"
kj=$(wait_done killid01)
if [ -n "$kj" ] && grep -q '"status": "aborted"' "$kj" \
   && grep -q BEFORE-KILL "${kj%.json}.typescript"; then
    ok "forwarder killed mid-session: finalized as aborted"
else
    bad "a killed forwarder was not finalized as aborted (json=$kj)"; [ -n "$kj" ] && cat "$kj"
fi

# ── Test 10: a hang-up does not cost the end-of-stream frame
#
# SIGHUP is how sessions end (client gone, max_duration watchdog). The
# forwarder must survive it, drain what script wrote, and complete the stream.
hfifo="$WORK/fifo.hup"
mkfifo -m 600 "$hfifo"
OB_RECORD_SOCKET="$SOCK" "$CONNECT" "$(hdr hupid01 script)" "$hfifo" 2>/dev/null &
hpid=$!
sleep 0.2
script -q -f -c 'printf "BEFORE-HUP\n"; sleep 2; printf "AFTER-HUP\n"' "$hfifo" \
    >/dev/null 2>&1 &
hspid=$!
sleep 1
kill -HUP "$hpid" 2>/dev/null
wait "$hspid" 2>/dev/null
wait "$hpid" 2>/dev/null
rm -f "$hfifo"
hj=$(wait_done hupid01)
if [ -n "$hj" ] && grep -q '"status": "completed"' "$hj" \
   && grep -q AFTER-HUP "${hj%.json}.typescript"; then
    ok "forwarder survives SIGHUP and completes the stream"
else
    bad "SIGHUP on the forwarder lost the end of the stream (json=$hj)"; [ -n "$hj" ] && cat "$hj"
fi

# ── Test 11: the framing itself — end frame completes, anything else does not
frame_session() { # $1 session_id  $2 mode: end | noend | garbage | v1
    python3 - "$SOCK" "$1" "$2" <<'PY' >/dev/null 2>&1
import socket, struct, sys
sock, sid, mode = sys.argv[1:4]
v = 1 if mode == "v1" else 2
hdr = ('{"v":%d,"session_id":"%s","format":"script","client_ip":"x",'
       '"ssh_tty":"x","original_command":"","start":"x"}' % (v, sid))
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)
data = b"FRAMED-PAYLOAD\n"
out = hdr.encode() + b"\n" + struct.pack(">I", len(data)) + data
if mode == "end" or mode == "v1":
    out += struct.pack(">I", 0)
elif mode == "garbage":
    out += struct.pack(">I", 0x7fffffff)      # longer than any frame may be
s.sendall(out)
s.shutdown(socket.SHUT_WR)
s.recv(1)
PY
}
frame_session frameend01 end
fe=$(wait_done frameend01)
frame_session framecut01 noend
fc=$(wait_done framecut01)
frame_session framebad01 garbage
fb=$(wait_done framebad01)
frame_session framev101 v1
sleep 1
fv=$(ls "$SESS/$USER_NAME"/*_framev101.json 2>/dev/null | head -1)
if grep -q '"status": "completed"' "$fe" 2>/dev/null \
   && grep -q FRAMED-PAYLOAD "${fe%.json}.typescript" 2>/dev/null; then
    ok "framed stream with its end frame: completed, payload unframed"
else
    bad "a well-framed stream was not completed (json=$fe)"
fi
if grep -q '"status": "aborted"' "$fc" 2>/dev/null; then
    ok "framed stream cut before its end frame: aborted"
else
    bad "a stream with no end frame was not finalized as aborted (json=$fc)"
fi
if grep -q '"status": "aborted"' "$fb" 2>/dev/null; then
    ok "oversized frame: aborted"
else
    bad "an oversized frame was not finalized as aborted (json=$fb)"
fi
if [ -z "$fv" ]; then
    ok "unframed v1 header refused"
else
    bad "the sink accepted a v1 (unframed) header ($fv)"
fi

echo "=== record-sink e2e: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ==="
exit $fail
