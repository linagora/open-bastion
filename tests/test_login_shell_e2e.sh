#!/bin/bash
# test_ob_login_shell_e2e.sh
#
# End to end, in debian:trixie: a real sshd, a real libnss_openbastion answer,
# the distribution's bash and zsh, and the question of #293 -- does anything of
# the user's run before the session recorder?
#
# sshd runs the ForceCommand through the login shell. Debian's bash, started as
# `bash -c` with SSH_CLIENT set, sources /etc/bash.bashrc and ~/.bashrc first;
# zsh reads /etc/zsh/zshenv and ~/.zshenv for any invocation. Every startup
# file a shell could read here touches a marker, and the stand-in recorder
# notes which markers exist the moment it starts:
#
#   A  control: NSS gives bash (default_shell), no force_shell.
#      Markers expected: the bug, reproduced.
#   B  control: the portal supplies /bin/zsh, no force_shell. Same.
#   C  force_shell = /usr/sbin/ob-login-shell, the portal still supplies zsh:
#      no marker before the recorder; getent shows the launcher; the recorder
#      gets SHELL=/bin/bash (default_shell), the client's command, and none of
#      the BASH_ENV/ENV sshd was told to set; and the shell the recorder then
#      starts is an ordinary bash that reads ~/.bashrc -- inside the recording.
#   D  the same with default_shell = /bin/zsh: the recorded shell is zsh.
#   E  an interactive login with a terminal (ssh -tt).
#   F  su - / su -c / sudo -i: through the recorder as well.
#
# A and B are what make C to F mean something: the same markers, the same
# sshd, with the fix removed, do fire.
#
# The tree is built inside the container (only the two targets needed), so the
# binaries match the container's libc. Needs docker; skips without it.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${OB_E2E_IMAGE:-debian:trixie}"

echo "=== ob-login-shell end to end: real sshd, NSS, bash and zsh (#293) ==="

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker is not available"
    exit 0
fi

RUNNER=$(mktemp)
trap 'rm -f "$RUNNER"' EXIT
cat > "$RUNNER" <<'INNER'
#!/bin/bash
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
fails=0
ok()   { echo "  PASS: $1"; }
bad()  { echo "  FAIL: $1${2:+ - $2}"; fails=$((fails + 1)); }

apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends \
    build-essential cmake pkg-config libcurl4-openssl-dev libjson-c-dev \
    libpam0g-dev libssl-dev openssh-server openssh-client zsh python3 sudo \
    ca-certificates >/dev/null 2>&1 || { echo "  FAIL: apt-get install"; exit 1; }

# ── Build the NSS module and the launcher ────────────────────────────────────
cmake -S /src -B /tmp/build -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release \
    >/tmp/cmake.log 2>&1 || { tail -20 /tmp/cmake.log; exit 1; }
cmake --build /tmp/build --target nss_openbastion ob-login-shell -j"$(nproc)" \
    >/tmp/build.log 2>&1 || { tail -30 /tmp/build.log; exit 1; }
MA=$(gcc -print-multiarch)
install -m 0644 /tmp/build/nss/libnss_openbastion.so.2 "/usr/lib/$MA/libnss_openbastion.so.2"
install -m 0755 /tmp/build/ob-login-shell /usr/sbin/ob-login-shell
echo /usr/sbin/ob-login-shell >> /etc/shells
sed -i -E 's/^(passwd:[[:space:]]+files)/\1 openbastion/' /etc/nsswitch.conf

# ── A portal: /pam/userinfo for dwho, shell from /tmp/portal-shell ───────────
cat > /tmp/portal.py <<'PY'
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        req = json.loads(self.rfile.read(n) or b'{}')
        if req.get('user') != 'dwho':
            body = {'found': False}
        else:
            body = {'found': True, 'uid': 20001, 'gid': 20001, 'gecos': 'D Who',
                    'home': '/home/dwho'}
            shell = open('/tmp/portal-shell').read().strip()
            if shell:
                body['shell'] = shell
        out = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass
http.server.HTTPServer(('127.0.0.1', 8080), H).serve_forever()
PY
: > /tmp/portal-shell
python3 /tmp/portal.py &
mkdir -p /etc/open-bastion /var/lib/open-bastion /var/cache/nss_llng/byname
chmod 711 /var/cache/nss_llng /var/cache/nss_llng/byname
echo test-token > /var/lib/open-bastion/token
chmod 600 /var/lib/open-bastion/token

nss_conf() {  # $1 = default_shell, $2 = force_shell ("" for none)
    {
        echo "portal_url = http://127.0.0.1:8080"
        echo "server_token_file = /var/lib/open-bastion/token"
        echo "cache_ttl = 300"
        echo "default_shell = $1"
        [ -n "$2" ] && echo "force_shell = $2"
    } > /etc/open-bastion/nss_openbastion.conf
    chmod 644 /etc/open-bastion/nss_openbastion.conf
    # Each scenario starts from nothing cached.
    find /var/cache/nss_llng -type f -delete
}

# ── The user, and a marker in every file a shell could read ──────────────────
M=/tmp/e2e/markers
mkdir -p "$M"
chmod 1777 /tmp/e2e "$M"
mkdir -p /home/dwho/.ssh
for f in .bashrc .bash_profile .bash_login .profile .zshenv .zshrc .zprofile .zlogin \
         .bashenv .env .ssh/rc; do
    printf 'touch %s/home%s 2>/dev/null\n' "$M" "$(echo "$f" | tr / _)" > "/home/dwho/$f"
done
chown -R 20001:20001 /home/dwho
for f in /etc/bash.bashrc /etc/profile /etc/zsh/zshenv /etc/zsh/zshrc; do
    [ -f "$f" ] || continue
    { printf 'touch %s/etc%s 2>/dev/null\n' "$M" "$(echo "$f" | tr / _)"; cat "$f"; } > "$f.new"
    mv "$f.new" "$f"
done
# su and sudo check the account through pam_unix, which wants a shadow entry.
echo 'dwho:*:19000:0:99999:7:::' >> /etc/shadow

# ── sshd: the ForceCommand of a recording bastion, and a hostile environment ─
ssh-keygen -A >/dev/null
mkdir -p /run/sshd /etc/ssh/keys
ssh-keygen -q -t ed25519 -N '' -f /tmp/id
install -m 0644 /tmp/id.pub /etc/ssh/keys/dwho
cat > /etc/ssh/sshd_test_config <<'EOF'
Port 2222
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/keys/%u
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
ForceCommand /usr/sbin/ob-session-recorder
SetEnv BASH_ENV=/home/dwho/.bashenv ENV=/home/dwho/.env
AcceptEnv LANG LC_*
EOF
/usr/sbin/sshd -f /etc/ssh/sshd_test_config -E /tmp/sshd.log

# The stand-in recorder: which markers exist when it starts, what it was given,
# then what the recorded session would be -- the shell it is told to start.
cat > /usr/sbin/ob-session-recorder <<'EOF'
#!/bin/sh
d=/tmp/e2e
ls /tmp/e2e/markers > $d/before
cat /proc/$$/environ > $d/env0
: > $d/args0
for a in "$@"; do printf '%s\0' "$a" >> $d/args0; done
"$SHELL" -i -c true </dev/null >/dev/null 2>&1
ls /tmp/e2e/markers > $d/after
echo RECORDER-RAN
EOF
chmod 755 /usr/sbin/ob-session-recorder

reset_markers() { rm -f "$M"/* /tmp/e2e/before /tmp/e2e/after /tmp/e2e/env0 /tmp/e2e/args0; }
env_of() {
    local v
    v=$(tr '\0' '\n' < /tmp/e2e/env0 2>/dev/null | grep -m1 "^$1=") || { printf '<unset>'; return; }
    printf '%s' "${v#*=}"
}
before() { tr '\n' ' ' < /tmp/e2e/before 2>/dev/null; }
after()  { tr '\n' ' ' < /tmp/e2e/after 2>/dev/null; }
login() {  # ssh as dwho, with a command
    reset_markers
    LANG=C.UTF-8 ssh -q -i /tmp/id -p 2222 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o SendEnv=LANG "$@" dwho@127.0.0.1 \
        'echo the client command' </dev/null >/tmp/e2e/out 2>&1
}

# ── A. Control: bash, no force_shell ─────────────────────────────────────────
nss_conf /bin/bash ""
: > /tmp/portal-shell
login
case "$(before)" in
    *home.bashrc*) ok "control A: without the fix, bash -c read ~/.bashrc before the recorder ($(before))" ;;
    *) bad "control A: the bug reproduces with bash" "markers before the recorder: '$(before)' $(cat /tmp/e2e/out)" ;;
esac

# ── B. Control: the portal supplies zsh, no force_shell ──────────────────────
nss_conf /bin/bash ""
echo /bin/zsh > /tmp/portal-shell
login
case "$(before)" in
    *home.zshenv*) ok "control B: without the fix, a portal-supplied zsh read ~/.zshenv before the recorder ($(before))" ;;
    *) bad "control B: the bug reproduces with zsh" "markers before the recorder: '$(before)'" ;;
esac

# ── C. The fix: force_shell, the portal still says zsh ───────────────────────
nss_conf /bin/bash /usr/sbin/ob-login-shell
echo /bin/zsh > /tmp/portal-shell
pwent=$(getent passwd dwho)
[ "${pwent##*:}" = /usr/sbin/ob-login-shell ] \
    && ok "C: getent passwd dwho gives the launcher although the portal says zsh" \
    || bad "C: getent passwd dwho gives the launcher" "$pwent"
login
if ! grep -q RECORDER-RAN /tmp/e2e/out; then
    bad "C: the recorder runs" "$(cat /tmp/e2e/out; tail -5 /tmp/sshd.log)"
else
    [ -z "$(before)" ] \
        && ok "C: no startup file of any shell ran before the recorder (bash, zsh, /etc, BASH_ENV, ENV, ~/.ssh/rc)" \
        || bad "C: nothing before the recorder" "markers: $(before)"
    [ "$(env_of SHELL)" = /bin/bash ] || bad "C: SHELL for the recorder" "$(env_of SHELL)"
    [ "$(env_of SSH_ORIGINAL_COMMAND)" = "echo the client command" ] \
        || bad "C: the client command reaches the recorder" "$(env_of SSH_ORIGINAL_COMMAND)"
    [ "$(env_of BASH_ENV)$(env_of ENV)" = "<unset><unset>" ] \
        || bad "C: BASH_ENV/ENV from sshd are dropped" "$(env_of BASH_ENV) $(env_of ENV)"
    [ "$(env_of SSH_CLIENT)" != "<unset>" ] || bad "C: SSH_CLIENT is kept"
    [ "$(env_of LANG)" = C.UTF-8 ] || bad "C: LANG sent by the client is kept" "$(env_of LANG)"
    [ ! -s /tmp/e2e/args0 ] || bad "C: the recorder gets no argument" "$(tr '\0' ' ' < /tmp/e2e/args0)"
    case "$(after)" in
        *home.bashrc*) ok "C: the recorder's SHELL=/bin/bash, the client's command, no BASH_ENV/ENV; the recorded bash then reads ~/.bashrc" ;;
        *) bad "C: the recorded session is an ordinary bash" "markers after: $(after)" ;;
    esac
fi

# ── D. default_shell = zsh: the recorded shell follows it ────────────────────
nss_conf /bin/zsh /usr/sbin/ob-login-shell
: > /tmp/portal-shell
login
if [ -z "$(before)" ] && [ "$(env_of SHELL)" = /bin/zsh ]; then
    case "$(after)" in
        *home.zshenv*) ok "D: default_shell = /bin/zsh: nothing before the recorder, then a recorded zsh" ;;
        *) bad "D: the recorded shell is zsh" "after: $(after)" ;;
    esac
else
    bad "D: default_shell = /bin/zsh" "before: '$(before)' SHELL=$(env_of SHELL)"
fi

# ── E. An interactive login with a terminal ──────────────────────────────────
nss_conf /bin/bash /usr/sbin/ob-login-shell
reset_markers
LANG=C.UTF-8 ssh -tt -q -i /tmp/id -p 2222 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null dwho@127.0.0.1 </dev/null >/tmp/e2e/out 2>&1
if grep -q RECORDER-RAN /tmp/e2e/out && [ -z "$(before)" ] \
   && [ "$(env_of SSH_ORIGINAL_COMMAND)" = "<unset>" ] && [ "$(env_of SSH_TTY)" != "<unset>" ]; then
    ok "E: ssh -tt: the recorder starts first, with the terminal and no command"
else
    bad "E: ssh -tt" "before='$(before)' orig=$(env_of SSH_ORIGINAL_COMMAND) tty=$(env_of SSH_TTY)"
fi

# ── F. su and sudo go through the recorder too ───────────────────────────────
reset_markers
su - dwho </dev/null >/tmp/e2e/out 2>&1
if grep -q RECORDER-RAN /tmp/e2e/out && [ -z "$(before)" ] \
   && [ "$(env_of SSH_ORIGINAL_COMMAND)" = "<unset>" ]; then
    ok "F: su - dwho: the recorder, no startup file first (not even /etc/profile)"
else
    bad "F: su - dwho" "before='$(before)' $(cat /tmp/e2e/out)"
fi
reset_markers
su dwho -c 'touch /tmp/e2e/markers/su-command-ran-directly' </dev/null >/tmp/e2e/out 2>&1
if grep -q RECORDER-RAN /tmp/e2e/out \
   && [ "$(env_of SSH_ORIGINAL_COMMAND)" = "touch /tmp/e2e/markers/su-command-ran-directly" ] \
   && ! grep -q su-command-ran-directly /tmp/e2e/before; then
    ok "F: su dwho -c CMD: CMD is handed to the recorder, not run by the launcher"
else
    bad "F: su dwho -c CMD" "before='$(before)' orig=$(env_of SSH_ORIGINAL_COMMAND)"
fi
reset_markers
sudo -i -u dwho true </dev/null >/tmp/e2e/out 2>&1
if grep -q RECORDER-RAN /tmp/e2e/out && [ -z "$(before)" ]; then
    ok "F: sudo -i -u dwho: through the recorder ($(env_of SSH_ORIGINAL_COMMAND))"
else
    bad "F: sudo -i -u dwho" "before='$(before)' $(cat /tmp/e2e/out)"
fi

echo
echo "e2e failures: $fails"
[ "$fails" -eq 0 ]
INNER

out=$(docker run --rm -v "$ROOT_DIR":/src:ro -v "$RUNNER":/run.sh:ro "$IMAGE" bash /run.sh 2>&1)
rc=$?
echo "$out"
if [ "$rc" -ne 0 ]; then
    echo "Tests run: 1, passed: 0, failed: 1"
    exit 1
fi
echo "Tests run: 1, passed: 1, failed: 0"
