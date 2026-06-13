#!/usr/bin/env bash
# shellcheck shell=bash
#
# Shared helpers for the local-test harnesses (deploy-ansible.sh / deploy-shell.sh).
# Source this file; do not run it directly.
#
# All configuration is env-overridable — see the table in README.md.

# ── locations ────────────────────────────────────────────────────────────────
LT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LT_DIR/.." && pwd)"
VM="$LT_DIR/vm/mkvm.sh"
SSO_DIR="$LT_DIR/sso"
APTREPO="$SSO_DIR/aptrepo"
# shellcheck disable=SC2034  # consumed by the sourcing deploy-*.sh scripts
CONFIG_DIR="$LT_DIR/config"
WORK="${OB_LT_WORK:-$LT_DIR/.work}"   # generated roles/installers/cookie (git-ignored)

# ── config (env-overridable) ─────────────────────────────────────────────────
GW_IP="${GW_IP:-192.168.122.1}"
APT_PORT="${APT_PORT:-8088}"
SSH_KEY="${OB_SSH_KEY:-$HOME/.ssh/id_oblab}"
DEB="open-bastion_0.2.3_amd64.deb"
BASTION_VM="${OB_BASTION_VM:-lab-a}"
read -ra BACKEND_VMS <<< "${OB_BACKEND_VMS:-lab-b lab-c}"
ALL_VMS=("$BASTION_VM" "${BACKEND_VMS[@]}")
# dwho SSO cert for the connection-phase checks (minted out of band; absent => skip)
DWHO_KEY="${OB_DWHO_KEY:-/tmp/ob-e2e/id_dwho}"
DWHO_CERT="${OB_DWHO_CERT:-/tmp/ob-e2e/id_dwho-cert.pub}"
# SSO login used to fetch the device-code auto-approval cookie
SSO_USER="${OB_SSO_USER:-dwho}"; SSO_PASS="${OB_SSO_PASS:-dwho}"

LLNG="${LLNG:-$(command -v llng || true)}"; [ -n "$LLNG" ] || LLNG="$HOME/bin/llng"

SSH_BASE=(-o IdentityAgent=none -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=8 -i "$SSH_KEY")

declare -A IP   # filled by recreate_vms

# ── output + scoreboard ──────────────────────────────────────────────────────
RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;34m'; NC=$'\033[0m'
PASS=0; FAIL=0; SKIP=0
phase(){ printf '\n%s== %s ==%s\n' "$BLU" "$*" "$NC"; }
info(){  printf '%s[..]%s %s\n' "$YLW" "$NC" "$*"; }
ok(){    printf '%s[OK]%s %s\n' "$GRN" "$NC" "$*"; PASS=$((PASS+1)); }
bad(){   printf '%s[!!]%s %s\n' "$RED" "$NC" "$*"; FAIL=$((FAIL+1)); }
skip(){  printf '%s[--]%s %s (skipped)\n' "$YLW" "$NC" "$*"; SKIP=$((SKIP+1)); }
die(){   printf '%s[FATAL]%s %s\n' "$RED" "$NC" "$*" >&2; exit 2; }
check(){ local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

dssh(){  ssh "${SSH_BASE[@]}" "debian@$1" "${@:2}"; }            # mgmt as debian (port 22, pre-lockdown)
ipof(){  "$VM" ip "$1" 2>/dev/null; }
summary(){ phase "Summary"; printf '%spassed=%d%s  %sfailed=%d%s  %sskipped=%d%s\n' \
           "$GRN" "$PASS" "$NC" "$RED" "$FAIL" "$NC" "$YLW" "$SKIP" "$NC"; [ "$FAIL" -eq 0 ]; }

# ── 0. preflight ─────────────────────────────────────────────────────────────
preflight(){
    phase "Preflight"
    local t
    for t in virsh virt-install docker ansible-playbook dpkg-buildpackage \
             dpkg-scanpackages qemu-img cloud-localds ssh-keygen jq curl python3; do
        command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
    done
    [ -x "$LLNG" ] || die "llng client not found (set \$LLNG)"
    [ -f "$SSH_KEY" ] || die "lab SSH key not found: $SSH_KEY"
    [ -x "$VM" ] || die "mkvm.sh not executable: $VM"
    mkdir -p "$WORK" "$APTREPO"
    ok "tools present; llng=$LLNG"
}

# ── 1. build + stage the .deb (repack libsodium dep for trixie; LAB-ONLY) ─────
build_deb(){
    phase "Build + stage .deb"
    if [ "${SKIP_BUILD:-0}" = "1" ] && [ -f "$APTREPO/$DEB" ]; then
        skip "package build (reusing $APTREPO/$DEB)"
    else
        info "dpkg-buildpackage (compiles PAM + NSS C modules)…"
        ( cd "$REPO_ROOT" && dpkg-buildpackage -us -uc -b ) >"$WORK/build.log" 2>&1 \
            || die "package build failed — see $WORK/build.log"
        # LAB-ONLY: this host builds against libsodium26 (so.26) but trixie ships
        # libsodium23 (so.18). Repack the Depends 26->23 so vanilla apt install
        # works on the VMs; a runtime .so.26->.so.23 symlink (bootstrap) covers
        # the linker. NEVER needed in production: the public repo .deb is built
        # per-distro in CI and depends on the matching libsodium.
        local r="$WORK/deb-repack"; rm -rf "$r"; dpkg-deb -R "$REPO_ROOT/../$DEB" "$r"
        sed -i 's/libsodium26 (>= [0-9.]*)/libsodium23 (>= 1.0.18)/; s/libsodium26/libsodium23/' "$r/DEBIAN/control"
        dpkg-deb --build --root-owner-group "$r" "$APTREPO/$DEB" >/dev/null
        ok "built + repacked (libsodium23) into the repo"
    fi
    ( cd "$APTREPO" && dpkg-scanpackages -m . >Packages 2>/dev/null && gzip -kf Packages )
    if ! curl -fsS "http://$GW_IP:$APT_PORT/Packages" >/dev/null 2>&1; then
        info "starting APT http server on $GW_IP:$APT_PORT…"
        ( cd "$APTREPO" && setsid python3 -m http.server "$APT_PORT" --bind "$GW_IP" >"$WORK/apt.log" 2>&1 & )
        sleep 1
    fi
    check "APT repo reachable" curl -fsS "http://$GW_IP:$APT_PORT/Packages" -o /dev/null
}

# ── 2. SSO ───────────────────────────────────────────────────────────────────
ensure_sso(){
    phase "Test SSO"
    if ! docker ps --format '{{.Names}}' | grep -qx ob-sso; then
        info "starting + configuring ob-sso…"
        docker compose -f "$SSO_DIR/docker-compose.yml" up -d >/dev/null 2>&1 || die "docker compose up failed"
        sleep 5
        bash "$SSO_DIR/configure.sh" >"$WORK/sso.log" 2>&1 || die "configure.sh failed — see $WORK/sso.log"
    fi
    check "SSO device endpoint answers" bash -c \
      "curl -fsS -H 'Host: auth.example.com' -d 'client_id=pam-access&client_secret=pamsecret&scope=pam:server offline_access' http://$GW_IP/oauth2/device | jq -e .device_code >/dev/null"
}

# ── 3. recreate VMs + bootstrap ──────────────────────────────────────────────
recreate_vms(){
    phase "Recreate VMs"
    local v
    for v in "${ALL_VMS[@]}"; do "$VM" rm "$v" >/dev/null 2>&1 || true; done
    for v in "${ALL_VMS[@]}"; do "$VM" create "$v" >/dev/null 2>&1 && ok "created $v" || bad "create $v"; done
    info "waiting for DHCP leases…"
    for v in "${ALL_VMS[@]}"; do
        for _ in $(seq 1 50); do IP[$v]="$(ipof "$v")"; [ -n "${IP[$v]}" ] && break; sleep 3; done
        [ -n "${IP[$v]:-}" ] && ok "$v -> ${IP[$v]}" || die "no lease for $v"
    done
}

# bootstrap_vm <vm> [install_pkg]  — lab adaptations kept OUT of the generated
# artefacts: SSO host entry, trusted (unsigned) apt source, libsodium .so.26
# symlink, /run dir for the enroll-state file. install_pkg=1 also apt-installs
# the package (the shell path uses --skip-install).
bootstrap_vm(){
    local v="$1" install_pkg="${2:-0}" ip="${IP[$1]}"
    for _ in $(seq 1 50); do dssh "$ip" true 2>/dev/null && break; sleep 3; done
    dssh "$ip" "sudo INSTALL_PKG=$install_pkg GW=$GW_IP APT_PORT=$APT_PORT bash -s" <<'BS' >/dev/null 2>&1
set -e
grep -q auth.example.com /etc/hosts || echo "$GW auth.example.com" >> /etc/hosts
mkdir -p /run/open-bastion && chmod 750 /run/open-bastion
echo "deb [trusted=yes] http://$GW:$APT_PORT/ ./" > /etc/apt/sources.list.d/oblab.list
export DEBIAN_FRONTEND=noninteractive
for t in 1 2 3; do apt-get update -qq && apt-get install -y -qq libsodium23 && break || sleep 5; done
ln -sf libsodium.so.23 /usr/lib/x86_64-linux-gnu/libsodium.so.26
ldconfig
if [ "$INSTALL_PKG" = "1" ]; then
    for t in 1 2 3; do apt-get install -y -qq open-bastion && break || sleep 5; done
fi
BS
    ok "$v bootstrapped"
}

# ── cookie + device-code approval ────────────────────────────────────────────
get_cookie(){
    COOKIE=$("$LLNG" --llng-url http://auth.example.com \
        --curl-opts "--resolve auth.example.com:80:$GW_IP" \
        --login "$SSO_USER" --password "$SSO_PASS" llng_cookie 2>/dev/null | tr -d '\r\n')
    [ -n "$COOKIE" ] || die "could not obtain LLNG cookie"
}

# approve_device <vm-ip> — poll the enroll-state file the target's ob-enroll
# writes (OB_ENROLL_STATE_FILE) and approve the device code via the gateway.
approve_device(){
    local ip="$1" uc page csrf
    for _ in $(seq 1 45); do
        uc=$(dssh "$ip" 'sudo cat /run/open-bastion/enroll-state.json 2>/dev/null' 2>/dev/null \
             | jq -r '.user_code // empty' 2>/dev/null)
        [ -n "$uc" ] && break; sleep 2
    done
    [ -n "$uc" ] || { echo "approve($ip): no user_code" >&2; return 1; }
    page=$(curl -s -H "Host: auth.example.com" -b "$COOKIE" "http://$GW_IP/device?user_code=$uc")
    csrf=$(printf '%s' "$page" | grep -oE 'name="token" value="[^"]+"' | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')
    [ -n "$csrf" ] || { echo "approve($ip): no csrf" >&2; return 1; }
    curl -s -o /dev/null -H "Host: auth.example.com" -b "$COOKIE" \
        --data "user_code=$uc&action=approve&token=$csrf" "http://$GW_IP/device"
}

# ── e2e verification (shared) ────────────────────────────────────────────────
# Uses the dwho SSO cert if present; otherwise skips the connection phase.
verify_e2e(){
    phase "Assertions — e2e (dwho cert)"
    if [ ! -f "$DWHO_KEY" ] || [ ! -f "$DWHO_CERT" ]; then
        skip "connection phase — no dwho cert at $DWHO_KEY (set OB_DWHO_KEY/OB_DWHO_CERT)"
        return 0
    fi
    local D=(ssh -i "$DWHO_KEY" -o "CertificateFile=$DWHO_CERT" -o IdentitiesOnly=yes
             -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
             -o NumberOfPasswordPrompts=0 -o ConnectTimeout=15)
    local B="${IP[$BASTION_VM]}" b1="${IP[${BACKEND_VMS[0]}]}" b2="${IP[${BACKEND_VMS[1]}]}"
    check "dwho cert logs into the bastion (no password fallback)" \
        "${D[@]}" "dwho@$B" 'true'
    if "${D[@]}" "dwho@$B" "echo 'echo HOP_\$(hostname)' | ob-ssh dwho@$b1 2>/dev/null" 2>/dev/null | grep -q "HOP_"; then
        ok "ob-ssh hop bastion->${BACKEND_VMS[0]} (ran on the backend)"
    else bad "ob-ssh hop bastion->${BACKEND_VMS[0]}"; fi
    check "getent passwd dwho on bastion (NSS)" "${D[@]}" "dwho@$B" 'getent passwd dwho >/dev/null'
    if "${D[@]}" "dwho@$B" "set -e
         echo ob-lt-payload-\$\$ > /tmp/s.txt
         ob-scp /tmp/s.txt dwho@$b1:/tmp/s1.txt
         ob-scp dwho@$b1:/tmp/s1.txt dwho@$b2:/tmp/s2.txt
         echo 'cat /tmp/s2.txt' | ob-ssh dwho@$b2 2>/dev/null | grep -q ob-lt-payload" >/dev/null 2>&1; then
        ok "ob-scp bastion->backend and backend->backend (scp -3)"
    else bad "ob-scp transfers"; fi
}
