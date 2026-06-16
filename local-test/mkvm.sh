#!/usr/bin/env bash
#
# mkvm.sh — spin up Debian test VMs from an immutable "golden" genericcloud
# image, using qcow2 overlays + a cloud-init NoCloud seed, managed by libvirt
# on the shared NAT network "default" (virbr0, 192.168.122.0/24).
#
# Each VM:
#   * boots from its own copy-on-write overlay (golden stays untouched),
#   * gets a unique cloud-init instance-id  -> SSH host key regenerated at
#     first boot (every server gets a distinct host key),
#   * gets its hostname, the `debian` user, your SSH pubkey and a console
#     password from the seed,
#   * is attached to the libvirt "default" NAT network, so VMs can reach each
#     other by IP (bastion <-> backend) and reach the Internet through NAT.
#
# Why libvirt (and not raw qemu + user networking)? user-mode networking
# isolates each VM in its own 10.0.2.0/24, so a bastion cannot talk to a
# backend. The libvirt "default" network is a real shared L2 (virbr0) with
# DHCP/DNS via dnsmasq and NAT to the outside. libvirtd (running as root)
# creates the tap device, so no setuid qemu-bridge-helper is involved.
#
# Privileges: managing qemu:///system requires membership in the `libvirt`
# group (Debian polkit rule 60-libvirt.rules). If the current login session
# isn't in that group yet (e.g. you were just added and haven't re-logged),
# this script re-executes itself under `sg libvirt` so virsh/virt-install
# work without a re-login. One-time setup, if needed:
#     sudo adduser "$USER" libvirt && sudo adduser "$USER" kvm
#
# Acceleration: KVM is used automatically when /dev/kvm is available.
#
# Usage:
#   ./mkvm.sh create <name> [--hostname H] [--key PUBKEY] [--size 10G]
#                           [--mem MB] [--vcpus N]   # define + first boot
#   ./mkvm.sh start  <name>                          # (re)boot a defined VM
#   ./mkvm.sh stop   <name> [--force]                # graceful / forced off
#   ./mkvm.sh ssh    <name> [remote command…]        # ssh debian@<VM IP>
#   ./mkvm.sh ip     <name>                          # print the VM's IPv4
#   ./mkvm.sh console <name>                         # attach serial console
#   ./mkvm.sh ls                                     # list VMs + IP + state
#   ./mkvm.sh rm     <name>                          # destroy + undefine + files
#
# Console: quit the serial console with  Ctrl-] .
#
set -euo pipefail

# --- re-exec under the libvirt group if the session isn't in it yet ---------
if ! id -nG 2>/dev/null | tr ' ' '\n' | grep -qx libvirt; then
    if command -v sg >/dev/null 2>&1 && getent group libvirt 2>/dev/null | grep -qw "$(id -un)"; then
        exec sg libvirt -c "$(printf '%q ' "$0" "$@")"
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# VM artifacts (qcow2 overlays, cloud-init seeds, the golden image, *.port) live
# in a machine-local, git-ignored subdir (see .gitignore: local-test/vm/) so the
# multi-hundred-MB images never enter the source archive. Override with OB_VM_DIR.
VM_DIR="${OB_VM_DIR:-$SCRIPT_DIR/vm}"
mkdir -p "$VM_DIR"
cd "$VM_DIR"

# --- configuration (override via env) --------------------------------------
GUEST_USER="${OB_VM_USER:-debian}"
CONSOLE_PASSWORD="${OB_VM_PASSWORD:-debian}"   # for serial/console login only
MEM_MB="${OB_VM_MEM:-1024}"
VCPUS="${OB_VM_CPUS:-2}"
LIBVIRT_NET="${OB_VM_NET:-default}"
# Dedicated, passphrase-less lab key. We use it explicitly with the ssh agent
# DISABLED (IdentityAgent=none): a forwarded/foreign agent on this host hangs
# during signing, so never rely on it for the lab VMs.
OB_SSH_KEY="${OB_SSH_KEY:-$HOME/.ssh/id_oblab}"

VIRSH=(virsh -c qemu:///system)

err()  { printf '\033[0;31m[ERROR]\033[0m %s\n' "$*" >&2; }
info() { printf '\033[0;32m[INFO]\033[0m %s\n'  "$*"; }
die()  { err "$*"; exit 1; }

require_name() { [ -n "${1:-}" ] || die "VM name required."; }

# --- locate the golden image -----------------------------------------------
resolve_golden() {
    if [ -n "${OB_GOLDEN:-}" ]; then
        [ -f "$OB_GOLDEN" ] || die "OB_GOLDEN not found: $OB_GOLDEN"
        printf '%s\n' "$OB_GOLDEN"; return
    fi
    local g
    g=$(ls -1t debian-*-genericcloud-*.qcow2 2>/dev/null | head -1 || true)
    [ -n "$g" ] || die "No golden image found. Put debian-*-genericcloud-*.qcow2 in $VM_DIR, or set OB_GOLDEN."
    printf '%s/%s\n' "$VM_DIR" "$g"
}

# --- pick a default SSH public key -----------------------------------------
default_pubkey() {
    # Prefer the dedicated lab key so `ssh` (agent disabled) can authenticate.
    [ -f "$OB_SSH_KEY.pub" ] && { printf '%s\n' "$OB_SSH_KEY.pub"; return; }
    local k
    for k in id_oblab id_debian id_ed25519 id_rsa infra; do
        [ -f "$HOME/.ssh/$k.pub" ] && { printf '%s\n' "$HOME/.ssh/$k.pub"; return; }
    done
    k=$(ls -1 "$HOME"/.ssh/*.pub 2>/dev/null | head -1 || true)
    [ -n "$k" ] || die "No SSH public key in ~/.ssh — pass --key PATH."
    printf '%s\n' "$k"
}

# --- ensure the libvirt NAT network is up ----------------------------------
ensure_network() {
    if ! "${VIRSH[@]}" net-info "$LIBVIRT_NET" >/dev/null 2>&1; then
        die "libvirt network '$LIBVIRT_NET' is not defined."
    fi
    if ! "${VIRSH[@]}" net-list --name 2>/dev/null | grep -qx "$LIBVIRT_NET"; then
        info "Starting libvirt network '$LIBVIRT_NET'…"
        "${VIRSH[@]}" net-start "$LIBVIRT_NET" >/dev/null
        "${VIRSH[@]}" net-autostart "$LIBVIRT_NET" >/dev/null 2>&1 || true
    fi
}

# --- build the cloud-init NoCloud seed iso ---------------------------------
build_seed() {
    local name="$1" hostname="$2" pubkey="$3" seed="$4"
    local tmp; tmp=$(mktemp -d)
    cat > "$tmp/meta-data" <<EOF
instance-id: iid-$name
local-hostname: $hostname
EOF
    {
        echo "#cloud-config"
        echo "hostname: $hostname"
        echo "fqdn: $hostname.test.local"
        echo "manage_etc_hosts: true"
        echo "ssh_pwauth: true"
        echo "users:"
        echo "  - name: $GUEST_USER"
        echo "    groups: [sudo]"
        echo "    sudo: \"ALL=(ALL) NOPASSWD:ALL\""
        echo "    shell: /bin/bash"
        echo "    lock_passwd: false"
        echo "    ssh_authorized_keys:"
        echo "      - $(cat "$pubkey")"
        echo "chpasswd:"
        echo "  expire: false"
        echo "  users:"
        echo "    - {name: $GUEST_USER, password: $CONSOLE_PASSWORD, type: text}"
        # SSH host keys are regenerated per-instance by cloud-init's ssh module
        # (genericcloud ships without baked-in host keys) — nothing to do here.
    } > "$tmp/user-data"
    cloud-localds "$seed" "$tmp/user-data" "$tmp/meta-data"
    rm -rf "$tmp"
}

# ---------------------------------------------------------------------------
cmd_create() {
    local name="${1:-}"; shift || true
    require_name "$name"
    local hostname="$name" pubkey="" size="" mem="$MEM_MB" vcpus="$VCPUS"
    while [ $# -gt 0 ]; do
        case "$1" in
            --hostname) hostname="$2"; shift 2 ;;
            --key)      pubkey="$2";   shift 2 ;;
            --size)     size="$2";     shift 2 ;;
            --mem)      mem="$2";      shift 2 ;;
            --vcpus)    vcpus="$2";    shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done
    ensure_network
    "${VIRSH[@]}" dominfo "$name" >/dev/null 2>&1 && die "Domain '$name' already exists (use: $0 rm $name)."

    local golden; golden=$(resolve_golden)
    [ -z "$pubkey" ] && pubkey=$(default_pubkey)
    [ -f "$pubkey" ] || die "Public key not found: $pubkey"

    local overlay="$VM_DIR/$name.qcow2"
    local seed="$VM_DIR/$name-seed.iso"
    [ -e "$overlay" ] && die "$overlay already exists (use: $0 rm $name)."

    info "Golden : $golden"
    info "Overlay: $overlay (backing, copy-on-write)"
    qemu-img create -q -f qcow2 -b "$golden" -F qcow2 "$overlay"
    [ -n "$size" ] && { qemu-img resize -q "$overlay" "$size"; info "Resized overlay to $size (cloud-init grows rootfs at boot)"; }

    build_seed "$name" "$hostname" "$pubkey" "$seed"
    info "Seed   : $seed (instance-id=iid-$name, host=$hostname)"

    # Define + first boot via virt-install --import.
    #
    # --video vga is REQUIRED even though we run headless (--graphics none):
    # the Debian genericcloud image's GRUB enters an endless reboot loop at
    # the kernel hand-off when the guest has no video adapter at all, which is
    # exactly what a bare "--graphics none" produces. A dummy VGA device with
    # no display backend is enough to make it boot.
    #
    # --os-variant generic gives sane virtio defaults; virt-install >=4 refuses
    # to run without OS info, so if "generic" is somehow unknown we retry with
    # VIRTINSTALL_OSINFO_DISABLE_REQUIRE=1 (osinfo-db may be absent).
    local common=(
        --connect qemu:///system
        --name "$name"
        --memory "$mem" --vcpus "$vcpus"
        --disk "path=$overlay,format=qcow2,bus=virtio"
        --disk "path=$seed,device=cdrom"
        --network "network=$LIBVIRT_NET,model=virtio"
        --graphics none
        --video vga
        --import --noautoconsole
    )
    info "Defining + booting '$name' on network '$LIBVIRT_NET'…"
    if ! virt-install "${common[@]}" --os-variant generic >/dev/null 2>&1; then
        VIRTINSTALL_OSINFO_DISABLE_REQUIRE=1 virt-install "${common[@]}" >/dev/null
    fi
    info "Booted. Get its address with: $0 ip $name   |   log in: $0 ssh $name"
}

cmd_start() {
    local name="${1:-}"; require_name "$name"
    ensure_network
    "${VIRSH[@]}" start "$name"
}

cmd_stop() {
    local name="${1:-}"; shift || true
    require_name "$name"
    if [ "${1:-}" = "--force" ]; then
        "${VIRSH[@]}" destroy "$name"
    else
        "${VIRSH[@]}" shutdown "$name"
    fi
}

# print the first IPv4 leased to the VM (from libvirt's dnsmasq leases)
get_ip() {
    local name="$1"
    "${VIRSH[@]}" domifaddr "$name" --source lease 2>/dev/null \
        | awk '/ipv4/ {split($4, a, "/"); print a[1]; exit}'
}

cmd_ip() {
    local name="${1:-}"; require_name "$name"
    local ip; ip=$(get_ip "$name")
    [ -n "$ip" ] || die "No IPv4 lease yet for '$name' (still booting? try again)."
    printf '%s\n' "$ip"
}

wait_ip() {
    local name="$1" ip i
    for i in $(seq 1 30); do
        ip=$(get_ip "$name")
        [ -n "$ip" ] && { printf '%s\n' "$ip"; return 0; }
        sleep 2
    done
    return 1
}

cmd_ssh() {
    local name="${1:-}"; shift || true
    require_name "$name"
    local ip; ip=$(wait_ip "$name") || die "No IPv4 lease for '$name' (is it running?)."
    exec ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o IdentitiesOnly=yes \
        -o IdentityAgent=none \
        -i "$OB_SSH_KEY" \
        "$GUEST_USER@$ip" "$@"
}

cmd_console() {
    local name="${1:-}"; require_name "$name"
    exec "${VIRSH[@]}" console "$name"
}

cmd_ls() {
    printf '%-20s %-10s %s\n' "NAME" "STATE" "IPV4"
    local name state ip
    while read -r name state; do
        [ -n "$name" ] || continue
        ip=$(get_ip "$name")
        printf '%-20s %-10s %s\n' "$name" "$state" "${ip:--}"
    done < <("${VIRSH[@]}" list --all --name 2>/dev/null | while read -r n; do
        [ -n "$n" ] || continue
        s=$("${VIRSH[@]}" domstate "$n" 2>/dev/null || echo "?")
        printf '%s %s\n' "$n" "$s"
    done)
}

cmd_rm() {
    local name="${1:-}"; require_name "$name"
    "${VIRSH[@]}" destroy "$name" >/dev/null 2>&1 || true
    "${VIRSH[@]}" undefine "$name" >/dev/null 2>&1 || true
    rm -f "$VM_DIR/$name.qcow2" "$VM_DIR/$name-seed.iso" "$VM_DIR/$name.port"
    info "Removed VM '$name' (domain undefined, overlay + seed deleted)."
}

case "${1:-}" in
    create)  shift; cmd_create  "$@" ;;
    start|run) shift; cmd_start "$@" ;;
    stop)    shift; cmd_stop    "$@" ;;
    ssh)     shift; cmd_ssh     "$@" ;;
    ip)      shift; cmd_ip      "$@" ;;
    console) shift; cmd_console "$@" ;;
    ls)      shift; cmd_ls      "$@" ;;
    rm)      shift; cmd_rm      "$@" ;;
    ""|-h|--help)
        sed -n '2,55p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    *) die "Unknown command: $1 (try --help)" ;;
esac
