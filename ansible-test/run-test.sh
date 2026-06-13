#!/usr/bin/env bash
# shellcheck shell=bash
#
# run-test.sh — end-to-end Open Bastion integration test on a 3-VM libvirt lab.
#
# This reproduces, automatically, the manual validation we run before a release:
# build the .deb, (re)create three Debian VMs (one bastion + two backends),
# deploy with Ansible against the local test SSO, then assert the whole chain
# works — NSS user resolution, the bastion→backend `ob-ssh` hop, and `ob-scp`
# (incl. backend→backend via `scp -3`).
#
# It is DELIBERATELY NOT wired into CI: it needs libvirt VMs (nested
# virtualisation) and a Docker SSO, which the GitHub runners do not provide.
# Run it on a workstation that has the lab prerequisites (see README.md).
#
# Usage:
#   ansible-test/run-test.sh                 # full cycle (recreate VMs + deploy + assert)
#   KEEP_VMS=1 ansible-test/run-test.sh      # keep VMs running at the end
#   SKIP_BUILD=1 ansible-test/run-test.sh    # reuse the .deb already in sso/aptrepo
#   SKIP_RECREATE=1 ansible-test/run-test.sh # reuse existing VMs (just redeploy + assert)
#
# Key environment overrides (all optional):
#   OB_GOLDEN          path to the Debian genericcloud golden qcow2 (else vm/ is searched)
#   GW_IP              libvirt gateway IP serving the APT repo + SSO (default 192.168.122.1)
#   LLNG               path to the `llng` OIDC client (default: search PATH then ~/bin/llng)
#   OB_DWHO_KEY/_CERT  dwho SSO key + cert for the connection-phase assertions
#                      (default /tmp/ob-e2e/id_dwho[-cert.pub]); absent => those
#                      assertions are SKIPPED (infra assertions still run)
#
set -uo pipefail

# ── locations ────────────────────────────────────────────────────────────────
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
VM_DIR="$HERE/vm"
SSO_DIR="$HERE/sso"
APTREPO="$SSO_DIR/aptrepo"
ANSIBLE_DIR="$HERE/ansible"
INVENTORY="$ANSIBLE_DIR/inventory.yml"

# ── config (env-overridable) ─────────────────────────────────────────────────
GW_IP="${GW_IP:-192.168.122.1}"
APT_PORT="${APT_PORT:-8088}"
DOCKER_SUBNET="${DOCKER_SUBNET:-172.19.0.0/16}"
SSH_KEY="${OB_SSH_KEY:-$HOME/.ssh/id_oblab}"
DEB="open-bastion_0.2.3_amd64.deb"
BASTION=lab-a
BACKENDS=(lab-b lab-c)
ALL_VMS=("$BASTION" "${BACKENDS[@]}")
DWHO_KEY="${OB_DWHO_KEY:-/tmp/ob-e2e/id_dwho}"
DWHO_CERT="${OB_DWHO_CERT:-/tmp/ob-e2e/id_dwho-cert.pub}"

MKVM="$VM_DIR/mkvm.sh"
MGMT_SSH=(-o IdentityAgent=none -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=8 -i "$SSH_KEY")

# ── pretty output + scoreboard ───────────────────────────────────────────────
RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;34m'; NC=$'\033[0m'
PASS=0; FAIL=0; SKIP=0
phase() { printf '\n%s== %s ==%s\n' "$BLU" "$*" "$NC"; }
info()  { printf '%s[..]%s %s\n' "$YLW" "$NC" "$*"; }
ok()    { printf '%s[OK]%s %s\n' "$GRN" "$NC" "$*"; PASS=$((PASS+1)); }
bad()   { printf '%s[!!]%s %s\n' "$RED" "$NC" "$*"; FAIL=$((FAIL+1)); }
skip()  { printf '%s[--]%s %s (skipped)\n' "$YLW" "$NC" "$*"; SKIP=$((SKIP+1)); }
die()   { printf '%s[FATAL]%s %s\n' "$RED" "$NC" "$*" >&2; exit 2; }

# Run a check: assert that the command succeeds, scoreboard it.
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else bad "$desc"; fi; }

mssh()  { ssh -p 2222 "${MGMT_SSH[@]}" "debian@$1" "${@:2}"; }   # mgmt :2222
ip_of() { "$MKVM" ip "$1" 2>/dev/null; }

# ── 0. preflight ─────────────────────────────────────────────────────────────
phase "0. Preflight"
for tool in virsh virt-install docker ansible ansible-playbook dpkg-buildpackage \
            dpkg-scanpackages qemu-img cloud-localds ssh-keygen jq; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
LLNG="${LLNG:-$(command -v llng || true)}"; [ -n "$LLNG" ] || LLNG="$HOME/bin/llng"
[ -x "$LLNG" ] || die "llng OIDC client not found (set \$LLNG)"
[ -f "$SSH_KEY" ] || die "lab SSH key not found: $SSH_KEY"
[ -x "$MKVM" ] || die "mkvm.sh not executable: $MKVM"
info "tools present; llng=$LLNG; key=$SSH_KEY"

# ── 1. build the .deb + serve the flat APT repo ──────────────────────────────
phase "1. Build .deb and serve APT repo"
mkdir -p "$APTREPO"
if [ "${SKIP_BUILD:-0}" != "1" ]; then
    info "dpkg-buildpackage (this compiles the PAM + NSS C modules)…"
    ( cd "$REPO_ROOT" && dpkg-buildpackage -us -uc -b ) >/tmp/ob-test-build.log 2>&1 \
        || die "package build failed — see /tmp/ob-test-build.log"
    cp "$REPO_ROOT/../$DEB" "$APTREPO/" || die "built .deb not found at $REPO_ROOT/../$DEB"
    ok "built and staged $DEB"
else
    [ -f "$APTREPO/$DEB" ] || die "SKIP_BUILD=1 but $APTREPO/$DEB is absent"
    skip "package build (reusing $APTREPO/$DEB)"
fi
( cd "$APTREPO" && dpkg-scanpackages -m . > Packages 2>/dev/null && gzip -kf Packages )
# Verify the freshly staged package carries the expected binaries.
if dpkg-deb -c "$APTREPO/$DEB" | grep -q '/usr/bin/ob-scp'; then ok "ob-scp present in .deb"; else bad "ob-scp MISSING from .deb"; fi

if ! curl -fsS "http://$GW_IP:$APT_PORT/Packages" >/dev/null 2>&1; then
    info "starting APT http server on $GW_IP:$APT_PORT…"
    ( cd "$APTREPO" && setsid python3 -m http.server "$APT_PORT" --bind "$GW_IP" \
        >/tmp/ob-test-apt.log 2>&1 & )
    sleep 1
fi
check "APT repo reachable at http://$GW_IP:$APT_PORT/" \
    curl -fsS "http://$GW_IP:$APT_PORT/Packages" -o /dev/null

# ── 2. SSO ───────────────────────────────────────────────────────────────────
phase "2. Test SSO (LemonLDAP::NG)"
if ! docker ps --format '{{.Names}}' | grep -qx ob-sso; then
    info "starting ob-sso container…"
    docker compose -f "$SSO_DIR/docker-compose.yml" up -d >/dev/null 2>&1 || die "docker compose up failed"
    sleep 5
    info "applying SSO configuration (OIDC clients + ssh-ca)…"
    bash "$SSO_DIR/configure.sh" >/tmp/ob-test-sso.log 2>&1 || die "configure.sh failed — see /tmp/ob-test-sso.log"
fi
check "SSO device endpoint answers" bash -c \
  "curl -fsS -H 'Host: auth.example.com' -d 'client_id=pam-access&client_secret=pamsecret&scope=pam:server offline_access' http://$GW_IP/oauth2/device | jq -e .device_code >/dev/null"

# ── 3. (re)create VMs ────────────────────────────────────────────────────────
phase "3. Create VMs"
if [ "${SKIP_RECREATE:-0}" != "1" ]; then
    for vm in "${ALL_VMS[@]}"; do "$MKVM" rm "$vm" >/dev/null 2>&1 || true; done
    for vm in "${ALL_VMS[@]}"; do
        "$MKVM" create "$vm" >/dev/null 2>&1 && ok "created $vm" || bad "create $vm failed"
    done
else
    skip "VM recreation (reusing existing VMs)"
fi

info "waiting for DHCP leases…"
declare -A IP
for vm in "${ALL_VMS[@]}"; do
    for _ in $(seq 1 40); do IP[$vm]="$(ip_of "$vm")"; [ -n "${IP[$vm]}" ] && break; sleep 3; done
    [ -n "${IP[$vm]}" ] && ok "$vm -> ${IP[$vm]}" || bad "no lease for $vm"
done
[ -n "${IP[$BASTION]:-}" ] || die "bastion has no IP, cannot continue"

# ── 4. write inventory + bootstrap the :2222 escape hatch ───────────────────
phase "4. Inventory + :2222 escape-hatch sshd"
# Rewrite each host's ansible_host with its lease (idempotent: matches the
# REPLACE_ME_* placeholder on first run and any prior IP afterwards).
python3 - "$INVENTORY" "${IP[lab-a]}" "${IP[lab-b]}" "${IP[lab-c]}" <<'PY'
import re, sys
path, a, b, c = sys.argv[1:5]
s = open(path).read()
s = re.sub(r'(lab-a:\n\s+ansible_host: )\S+', r'\g<1>'+a, s)
s = re.sub(r'(lab-b:\n\s+ansible_host: )\S+', r'\g<1>'+b, s)
s = re.sub(r'(lab-c:\n\s+ansible_host: )\S+', r'\g<1>'+c, s)
open(path, 'w').write(s)
PY
ok "inventory updated (lab-a=${IP[lab-a]} lab-b=${IP[lab-b]} lab-c=${IP[lab-c]})"

info "waiting for port-22 SSH on each VM…"
for vm in "${ALL_VMS[@]}"; do
    for _ in $(seq 1 40); do
        ssh "${MGMT_SSH[@]}" "debian@${IP[$vm]}" true 2>/dev/null && break; sleep 3
    done
done
# Add the SSO host entry and a no-PAM sshd on :2222 so the port-22 lockdown
# applied by ob-*-setup cannot sever Ansible's control connection. The :2222
# instance is a LAB DEBUG AID, never part of a real deployment.
for vm in "${ALL_VMS[@]}"; do
    # Intentionally an UNQUOTED heredoc: only $GW_IP must expand here (client
    # side); the inner CFG/UNIT bodies contain no $ tokens, so nothing else is
    # affected. (Quoting would break the /etc/hosts gateway line.)
    # shellcheck disable=SC2087
    ssh "${MGMT_SSH[@]}" "debian@${IP[$vm]}" 'sudo bash -s' <<BS >/dev/null 2>&1
set -e
grep -q auth.example.com /etc/hosts || echo "$GW_IP auth.example.com" >> /etc/hosts
mkdir -p /etc/ssh/mgmt
[ -f /etc/ssh/mgmt/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/mgmt/ssh_host_ed25519_key
cat > /etc/ssh/sshd_mgmt_config <<CFG
Port 2222
HostKey /etc/ssh/mgmt/ssh_host_ed25519_key
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile /home/debian/.ssh/authorized_keys
PidFile /run/sshd-mgmt.pid
AllowUsers debian
Subsystem sftp internal-sftp
CFG
cat > /etc/systemd/system/sshd-mgmt.service <<UNIT
[Unit]
Description=Management sshd (port 2222, no PAM) - lab escape hatch
After=network.target
[Service]
ExecStartPre=/usr/sbin/sshd -t -f /etc/ssh/sshd_mgmt_config
ExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_mgmt_config
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sshd-mgmt.service
BS
    if mssh "${IP[$vm]}" 'systemctl is-active --quiet sshd-mgmt.service'; then
        ok "$vm: :2222 escape-hatch up"
    else
        bad "$vm: :2222 escape-hatch failed"
    fi
done

# ── 5. NAT fidelity (best effort) ────────────────────────────────────────────
phase "5. NAT source-address fidelity (best effort)"
# Docker masquerade can rewrite the bastion's source IP when it calls the SSO,
# which would put the wrong source-address in the minted cert. A RETURN rule
# for VM->docker traffic preserves it. Needs host root; non-fatal if we can't.
if sudo -n iptables -t nat -C POSTROUTING -s 192.168.122.0/24 -d "$DOCKER_SUBNET" -j RETURN 2>/dev/null; then
    ok "NAT RETURN rule already present"
elif sudo -n iptables -t nat -I POSTROUTING -s 192.168.122.0/24 -d "$DOCKER_SUBNET" -j RETURN 2>/dev/null; then
    ok "NAT RETURN rule installed"
else
    skip "NAT RETURN rule (needs passwordless host sudo; hop may still work)"
fi

# ── 6. Ansible deploy ────────────────────────────────────────────────────────
phase "6. Ansible deployment"
info "fetching an LLNG auto-approve cookie for device-code enrolment…"
COOKIE="$("$LLNG" --llng-url http://auth.example.com \
    --curl-opts "--resolve auth.example.com:80:$GW_IP" \
    --login dwho --password dwho llng_cookie 2>/dev/null | tr -d '\r\n')"
[ -n "$COOKIE" ] || die "could not obtain LLNG cookie"
export ANSIBLE_HOST_KEY_CHECKING=False
if ansible-playbook -i "$INVENTORY" "$ANSIBLE_DIR/playbook.yml" \
        --extra-vars "ob_llng_cookie='$COOKIE'" >/tmp/ob-test-play.log 2>&1; then
    ok "playbook completed (failed=0)"
else
    bad "playbook FAILED — see /tmp/ob-test-play.log"
    tail -25 /tmp/ob-test-play.log
fi

# ── 7. Infra assertions ──────────────────────────────────────────────────────
phase "7. Assertions — NSS / token lifecycle / perms"
for vm in "${ALL_VMS[@]}"; do
    check "$vm: getent passwd dwho resolves (NSS)" \
        mssh "${IP[$vm]}" 'getent passwd dwho >/dev/null'
    check "$vm: ob-heartbeat.timer active" \
        mssh "${IP[$vm]}" 'systemctl is-active --quiet ob-heartbeat.timer'
    check "$vm: /var/lib/open-bastion is 711 (recorder traversable)" \
        mssh "${IP[$vm]}" '[ "$(sudo stat -c %a /var/lib/open-bastion)" = 711 ]'
    check "$vm: sessions/ is 3771 root:ob-sessions" \
        mssh "${IP[$vm]}" '[ "$(sudo stat -c "%a %U:%G" /var/lib/open-bastion/sessions)" = "3771 root:ob-sessions" ]'
done

# ── 8. Connection assertions (need a dwho SSO cert) ──────────────────────────
phase "8. Assertions — ob-ssh hop + ob-scp (needs dwho SSO cert)"
if [ ! -f "$DWHO_KEY" ] || [ ! -f "$DWHO_CERT" ]; then
    skip "ob-ssh / ob-scp end-to-end — no dwho cert at $DWHO_KEY (set OB_DWHO_KEY/OB_DWHO_CERT)"
else
    DWHO=(ssh -i "$DWHO_KEY" -o "CertificateFile=$DWHO_CERT" -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)
    BIP="${IP[$BASTION]}"; B1="${IP[lab-b]}"; B2="${IP[lab-c]}"

    check "dwho SSO cert logs into the bastion" \
        "${DWHO[@]}" "dwho@$BIP" 'true'

    # ob-ssh takes [user@]host [port], NOT a remote command — feed it on stdin.
    if out="$("${DWHO[@]}" "dwho@$BIP" "echo 'echo HOP_OK_\$(hostname)' | ob-ssh dwho@$B1 2>/dev/null" 2>/dev/null)" \
       && echo "$out" | grep -q "HOP_OK_lab-b"; then
        ok "ob-ssh hop bastion->lab-b (ran on the backend)"
    else
        bad "ob-ssh hop bastion->lab-b"
    fi

    # ob-scp bastion -> backend
    if "${DWHO[@]}" "dwho@$BIP" "set -e
         echo ob-scp-payload-\$\$ > /tmp/ob_src.txt
         ob-scp /tmp/ob_src.txt dwho@$B1:/tmp/ob_dst.txt
         echo 'cat /tmp/ob_dst.txt' | ob-ssh dwho@$B1 2>/dev/null | grep -q ob-scp-payload" >/dev/null 2>&1; then
        ok "ob-scp bastion->lab-b (verified on backend)"
    else
        bad "ob-scp bastion->lab-b"
    fi

    # ob-scp backend -> backend (forced through the bastion via scp -3)
    if "${DWHO[@]}" "dwho@$BIP" "set -e
         ob-scp dwho@$B1:/tmp/ob_dst.txt dwho@$B2:/tmp/ob_relay.txt
         echo 'cat /tmp/ob_relay.txt' | ob-ssh dwho@$B2 2>/dev/null | grep -q ob-scp-payload" >/dev/null 2>&1; then
        ok "ob-scp lab-b->lab-c (scp -3 through the bastion)"
    else
        bad "ob-scp lab-b->lab-c"
    fi

    # Session recording on the bastion (the #127 traversal-perms regression).
    if mssh "$BIP" 'sudo find /var/lib/open-bastion/sessions -name "*.typescript" | grep -q .'; then
        ok "bastion recorded the session (recorder traversed sessions/)"
    else
        bad "bastion produced no session recording"
    fi
fi

# ── teardown + summary ───────────────────────────────────────────────────────
if [ "${KEEP_VMS:-0}" != "1" ] && [ "${SKIP_RECREATE:-0}" != "1" ]; then
    phase "Teardown"
    for vm in "${ALL_VMS[@]}"; do "$MKVM" rm "$vm" >/dev/null 2>&1 || true; done
    ok "VMs destroyed (set KEEP_VMS=1 to keep them)"
fi

phase "Summary"
printf '%spassed=%d%s  %sfailed=%d%s  %sskipped=%d%s\n' \
    "$GRN" "$PASS" "$NC" "$RED" "$FAIL" "$NC" "$YLW" "$SKIP" "$NC"
[ "$FAIL" -eq 0 ] || exit 1
echo "All assertions passed."
