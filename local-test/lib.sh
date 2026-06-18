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
VM="$LT_DIR/mkvm.sh"
SSO_DIR="$LT_DIR/sso"
APTREPO="$SSO_DIR/aptrepo"
# shellcheck disable=SC2034  # consumed by the sourcing deploy-*.sh scripts
CONFIG_DIR="$LT_DIR/config"
WORK="${OB_LT_WORK:-$LT_DIR/.work}"   # generated roles/installers/cookie (git-ignored)

# ── config (env-overridable) ─────────────────────────────────────────────────
GW_IP="${GW_IP:-192.168.122.1}"
APT_PORT="${APT_PORT:-8088}"
SSH_KEY="${OB_SSH_KEY:-$HOME/.ssh/id_oblab}"
# Derived from debian/changelog (what dpkg-buildpackage names the .deb), so it
# never goes stale across releases.
DEB="open-bastion_$(dpkg-parsechangelog -l "$REPO_ROOT/debian/changelog" -S Version)_amd64.deb"
BASTION_VM="${OB_BASTION_VM:-lab-a}"
read -ra BACKEND_VMS <<< "${OB_BACKEND_VMS:-lab-b lab-c}"
# A standalone host (bastion+backend in one) — deployed with the ob-builder
# standalone role via ob-standalone-setup. Only the Ansible harness uses it; it
# appends $STANDALONE_VM to ALL_VMS itself. Set OB_STANDALONE_VM="" to skip it.
STANDALONE_VM="${OB_STANDALONE_VM-lab-d}"
ALL_VMS=("$BASTION_VM" "${BACKEND_VMS[@]}")
# Security scenario fed to ob-builder for every role (token-only|token+unix|
# keys+llng|mixed|max-security). Lets the harness exercise all PAM modes.
SCENARIO="${OB_SCENARIO:-token-only}"
# dwho SSO cert for the connection-phase checks (minted out of band; absent => skip)
DWHO_KEY="${OB_DWHO_KEY:-/tmp/ob-e2e/id_dwho}"
DWHO_CERT="${OB_DWHO_CERT:-/tmp/ob-e2e/id_dwho-cert.pub}"
# SSO login used to fetch the device-code auto-approval cookie
SSO_USER="${OB_SSO_USER:-dwho}"; SSO_PASS="${OB_SSO_PASS:-dwho}"

LLNG="${LLNG:-$(command -v llng || true)}"; [ -n "$LLNG" ] || LLNG="$HOME/bin/llng"

# Service-account lab key. Generated once per run; SVC_FP is its SHA256
# fingerprint, injected into the standalone ob-builder config so the deployed
# service-accounts.conf matches this very key (see deploy-shell.sh).
SVC_KEY="${OB_SVC_KEY:-$WORK/svc_backup}"
SVC_FP=""
# Service-account username for the check. Must NOT collide with a system user
# (e.g. 'backup', 'www-data'): pam_openbastion only sets shell/home when it
# CREATES the account, so an existing system user (nologin) would break login.
SVC_NAME="${OB_SVC_NAME:-obdeploy}"

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
    # Auto-detect the genericcloud golden image (mkvm.sh honours $OB_GOLDEN) so
    # the operator need not export it. Search vm/ first, then the throwaway
    # local/VM/ tree where it usually lives.
    if [ -z "${OB_GOLDEN:-}" ]; then
        local g
        g=$(ls -1t "$LT_DIR"/vm/debian-*-genericcloud-*.qcow2 \
                   "$REPO_ROOT"/local/VM/debian-*-genericcloud-*.qcow2 2>/dev/null | head -1 || true)
        [ -n "$g" ] && export OB_GOLDEN="$g"
    fi
    [ -n "${OB_GOLDEN:-}" ] || die "no genericcloud golden image (put one in vm/ or set OB_GOLDEN)"
    mkdir -p "$WORK" "$APTREPO"
    ok "tools present; llng=$LLNG; golden=$(basename "$OB_GOLDEN")"
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
    # An explicit -f disables Compose's automatic override merge, so opt the
    # gitignored docker-compose.override.yml back in when present (used to mount
    # unreleased local plugin working copies — see that file's header).
    local compose_files=(-f "$SSO_DIR/docker-compose.yml")
    [ -f "$SSO_DIR/docker-compose.override.yml" ] && \
        compose_files+=(-f "$SSO_DIR/docker-compose.override.yml")
    if ! docker ps --format '{{.Names}}' | grep -qx ob-sso; then
        info "starting + configuring ob-sso…"
        docker compose "${compose_files[@]}" up -d >/dev/null 2>&1 || die "docker compose up failed"
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
mkdir -p /run/open-bastion && chmod 711 /run/open-bastion
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

# Mint a dwho SSO certificate (server_group=bastion) via the portal's /ssh/sign
# endpoint using the approval cookie, so the connection-phase and standalone
# assertions can run instead of being skipped. No-op if a cert already exists or
# signing fails (the dependent checks then skip, as before). Needs $COOKIE.
mint_dwho_cert(){
    [ -n "${COOKIE:-}" ] || return 0
    mkdir -p "$(dirname "$DWHO_KEY")"
    rm -f "$DWHO_KEY" "$DWHO_KEY.pub" "$DWHO_CERT"
    # The SSHCA enforces per-user label uniqueness among non-expired certs, and
    # the label defaults to the key comment. Repeated lab runs would reuse the
    # same comment and trip "label already used for another key", so stamp a
    # unique label/comment on every mint.
    local label="oblab-dwho-$(date +%s)-$$"
    ssh-keygen -t ed25519 -f "$DWHO_KEY" -N "" -C "$label" -q
    local pub resp cert
    pub=$(cat "$DWHO_KEY.pub")
    resp=$(curl -s -H "Host: auth.example.com" -b "$COOKIE" -H "Content-Type: application/json" \
        -d "{\"public_key\":\"$pub\",\"server_group\":\"bastion\",\"label\":\"$label\"}" "http://$GW_IP/ssh/sign" 2>/dev/null)
    cert=$(printf '%s' "$resp" | jq -r '.certificate // empty' 2>/dev/null)
    if [ -n "$cert" ] && printf '%s' "$cert" | grep -q "ssh-ed25519-cert"; then
        printf '%s\n' "$cert" > "$DWHO_CERT"
        ok "minted dwho SSO cert -> $DWHO_CERT"
    else
        rm -f "$DWHO_KEY" "$DWHO_KEY.pub" "$DWHO_CERT"
        skip "mint dwho cert (sign endpoint said: ${resp:0:100})"
    fi
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

# ── standalone verification ──────────────────────────────────────────────────
# A standalone host is bastion+backend in one, with no bastion in front: a user
# logs into it directly. Assert the NSS + direct-login path, and (Mode E only,
# where ob-bastion-setup configures sudo) that sudo AND sudo -i require the LLNG
# token via pam_openbastion — the regression guard for this fix.
verify_standalone(){
    [ -n "$STANDALONE_VM" ] || return 0
    phase "Assertions — standalone ($STANDALONE_VM, scenario=$SCENARIO)"
    # A standalone is a bastion (ForceCommand session recorder), so the debian
    # mgmt key cannot run plain commands and Mode E disables it entirely. Every
    # check therefore goes through the dwho SSO certificate, like verify_e2e.
    if [ ! -f "$DWHO_KEY" ] || [ ! -f "$DWHO_CERT" ]; then
        skip "standalone checks — no dwho cert at $DWHO_KEY (set OB_DWHO_KEY/OB_DWHO_CERT)"
        return 0
    fi
    local s="${IP[$STANDALONE_VM]}"
    local D=(ssh -i "$DWHO_KEY" -o "CertificateFile=$DWHO_CERT" -o IdentitiesOnly=yes
             -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
             -o NumberOfPasswordPrompts=0 -o ConnectTimeout=15)
    check "dwho cert logs into standalone directly (no bastion in front)" \
        "${D[@]}" "dwho@$s" 'true'
    check "getent passwd dwho on standalone (NSS)" \
        "${D[@]}" "dwho@$s" 'getent passwd dwho >/dev/null'
    # Mode E is the only scenario where ob-bastion-setup configures sudo; assert
    # both sudo and sudo -i require the LLNG token (the fix this PR validates).
    if [ "$SCENARIO" = "max-security" ]; then
        check "standalone /etc/pam.d/sudo requires LLNG token (pam_openbastion)" \
            "${D[@]}" "dwho@$s" 'grep -q pam_openbastion /etc/pam.d/sudo'
        check "standalone /etc/pam.d/sudo-i requires LLNG token (pam_openbastion)" \
            "${D[@]}" "dwho@$s" 'grep -q pam_openbastion /etc/pam.d/sudo-i'
    fi
}

# ── service-account verification ──────────────────────────────────────────────
# Validates the ob-builder service-keys feature end-to-end: ob-builder deposits
# service-accounts.conf (fingerprint only), and we perform the documented manual
# SSH-layer authorization (the ob-service-account-keys AuthorizedKeysCommand
# helper, which also covers Mode E's `AuthorizedKeysFile none`), then assert the
# 'backup' service account logs in with its own key — no SSO, no bastion cert.

# Generate the lab service key once and compute its SHA256 fingerprint.
gen_service_key(){
    [ -f "$SVC_KEY" ] || ssh-keygen -t ed25519 -f "$SVC_KEY" -N "" -C "oblab-svc-backup" -q
    SVC_FP=$(ssh-keygen -lf "$SVC_KEY.pub" 2>/dev/null | awk '{print $2}')
}

# Provision the SSH-layer authorization for the 'backup' service account on <vm>.
# This is the manual step ob-builder deliberately does NOT do (it only writes the
# fingerprint to service-accounts.conf): deploy the ob-service-account-keys
# AuthorizedKeysCommand helper + the account's public key so sshd will present
# it. Works in all PAM modes, including Mode E (AuthorizedKeysFile none). MUST
# run while the debian mgmt user can still SSH — i.e. before *-setup locks port 22.
provision_service_helper(){
    local v="$1" ip="${IP[$1]}"
    local helper="$REPO_ROOT/scripts/ob-service-account-keys"
    [ -f "$helper" ] || { skip "service helper missing ($helper)"; return 0; }
    [ -n "$SVC_FP" ] || { skip "service key not generated"; return 0; }
    scp "${SSH_BASE[@]}" "$helper" "debian@$ip:/tmp/ob-service-account-keys" >/dev/null 2>&1 \
        || { bad "$v: could not copy service helper"; return 0; }
    local pub; pub=$(cat "$SVC_KEY.pub")
    if dssh "$ip" "sudo OB_SVC_PUB='$pub' OB_SVC_NAME='$SVC_NAME' bash -s" <<'BS' >/dev/null 2>&1
set -e
install -m 0755 -o root -g root /tmp/ob-service-account-keys /usr/local/sbin/ob-service-account-keys
mkdir -p /etc/open-bastion/service-accounts.d
printf '%s\n' "$OB_SVC_PUB" > "/etc/open-bastion/service-accounts.d/${OB_SVC_NAME}.pub"
chown root:root "/etc/open-bastion/service-accounts.d/${OB_SVC_NAME}.pub"
chmod 0644 "/etc/open-bastion/service-accounts.d/${OB_SVC_NAME}.pub"
cat > /etc/ssh/sshd_config.d/09-open-bastion-service-keys.conf <<'CONF'
AuthorizedKeysCommand /usr/local/sbin/ob-service-account-keys %u
AuthorizedKeysCommandUser nobody
CONF
BS
    then ok "$v: provisioned service-account SSH authorization (${SVC_NAME}.pub + AuthorizedKeysCommand)"
    else bad "$v: failed to provision service-account SSH authorization"; fi
}

# Assert the 'backup' service account authenticates with its key (direct,
# no SSO/cert). Run after the target is deployed (service-accounts.conf present).
verify_service_accounts(){
    local v="${1:-$STANDALONE_VM}"
    [ -n "$v" ] || return 0
    phase "Assertions — service account '$SVC_NAME' on $v (direct key auth)"
    if [ -z "$SVC_FP" ] || [ ! -f "$SVC_KEY" ]; then
        skip "service-account check — no lab service key (gen_service_key not run)"
        return 0
    fi
    local ip="${IP[$v]}"
    local S=(ssh -i "$SVC_KEY" -o IdentityAgent=none -o IdentitiesOnly=yes
             -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
             -o NumberOfPasswordPrompts=0 -o ConnectTimeout=15)
    # Exit 0 ⇒ sshd accepted the key (AuthorizedKeysCommand) AND pam_openbastion
    # matched the fingerprint in service-accounts.conf and authorized the account
    # (auto-creating it). A wrong/unknown key would fail with 255.
    if "${S[@]}" "$SVC_NAME@$ip" true >/dev/null 2>&1; then
        ok "service account '$SVC_NAME' logs in with its key (fingerprint matched, no SSO)"
    else
        bad "service account '$SVC_NAME' login failed — see sshd/pam logs on $v"
    fi
}
