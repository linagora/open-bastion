#!/usr/bin/env bash
# shellcheck shell=bash source=lib.sh
#
# Two-phase SHELL-INSTALLER deploy (ob-builder --output-shell), same logic as
# deploy-ansible.sh:
#   1. ob-builder builds the bastion installer -> enrol -> ob-bastion-id
#   2. ob-builder builds the backend installer (allowed_bastions=bastion_id)
#   3. verify the cert hop + ob-scp
#
# The bastion is deployed in two installer invocations on purpose: ob-bastion-id
# needs the server token (written by enrolment) but ob-bastion-setup then locks
# port 22, after which a plain `debian` SSH is refused. So we enrol first
# (--skip-setup), read the id while port 22 still answers, then run setup
# (--skip-enroll). NOT run in CI (needs VMs).
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SHIMBIN="$WORK/shimbin"; mkdir -p "$SHIMBIN"
ln -sf "$SSO_DIR/ob-builder-curl-shim.sh" "$SHIMBIN/curl"
obbuild(){ PATH="$SHIMBIN:$PATH" "$REPO_ROOT/admin-builder/ob-builder" "$@" --allow-http; }

# Standalone host: only the harness wires it in (lib.sh keeps it out of the
# shared VM set). Same as deploy-ansible.sh — append it here so it is recreated,
# bootstrapped and deployed. Set OB_STANDALONE_VM="" to skip it.
[ -n "$STANDALONE_VM" ] && ALL_VMS+=("$STANDALONE_VM")

# run_installer <vm> <installer> [extra installer args…]
# Copies the installer and runs it as root with the lab flags. --skip-install
# (package pre-installed in bootstrap, unsigned repo), --force (postinst already
# created /etc/open-bastion), --insecure (http SSO), --yes (unattended), and
# OB_ENROLL_STATE_FILE preserved so approve_device can find the user_code.
run_installer(){
    local v="$1" inst="$2"; shift 2; local ip="${IP[$v]}"
    scp "${SSH_BASE[@]}" "$inst" "debian@$ip:/tmp/ob-installer.sh" >/dev/null 2>&1
    dssh "$ip" 'chmod +x /tmp/ob-installer.sh'
    dssh "$ip" "sudo --preserve-env=OB_ENROLL_STATE_FILE OB_ENROLL_STATE_FILE=/run/open-bastion/enroll-state.json \
                /tmp/ob-installer.sh --skip-install --force --insecure --yes $*"
}

preflight; build_deb; ensure_sso; recreate_vms
phase "Bootstrap VMs (incl. package install — shell path uses --skip-install)"
for v in "${ALL_VMS[@]}"; do bootstrap_vm "$v" 1; done
get_cookie
mint_dwho_cert   # so the connection-phase + standalone assertions actually run
[ -n "$STANDALONE_VM" ] && gen_service_key   # lab key for the service-account check

# ── Phase 1: bastion installer — enrol, read bastion_id, then setup ──────────
phase "Phase 1 — bastion (ob-builder --output-shell, scenario=$SCENARIO)"
sed "s/^scenario:.*/scenario: $SCENARIO/" "$CONFIG_DIR/build-bastion.yml" > "$WORK/build-bastion.yml"
obbuild --config "$WORK/build-bastion.yml" --output-shell "$WORK/boot-bastion.sh" >"$WORK/gen-bastion.log" 2>&1 \
    && ok "generated bastion installer" || { bad "ob-builder bastion failed"; cat "$WORK/gen-bastion.log"; }

info "enrol the bastion (--skip-setup), approving the device code in parallel"
( approve_device "${IP[$BASTION_VM]}" ) &
run_installer "$BASTION_VM" "$WORK/boot-bastion.sh" --skip-setup >"$WORK/bastion-enroll.log" 2>&1
wait
BID="$(dssh "${IP[$BASTION_VM]}" 'sudo ob-bastion-id 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
[ -n "$BID" ] && ok "bastion enrolled; ob-bastion-id=$BID" || { bad "ob-bastion-id failed"; BID="ob-bastion"; }

info "run bastion setup (--skip-enroll; this locks port 22)"
run_installer "$BASTION_VM" "$WORK/boot-bastion.sh" --skip-enroll >"$WORK/bastion-setup.log" 2>&1 \
    && ok "bastion setup complete" || bad "bastion setup failed — see $WORK/bastion-setup.log"

# ── Phase 2: backend installer with allowed_bastions=bastion_id ──────────────
phase "Phase 2 — backends (ob-builder --output-shell, allowed_bastions=$BID, scenario=$SCENARIO)"
sed -e "s/^allowed_bastions:.*/allowed_bastions: $BID/" \
    -e "s/^scenario:.*/scenario: $SCENARIO/" "$CONFIG_DIR/build-backend.yml" > "$WORK/build-backend.yml"
obbuild --config "$WORK/build-backend.yml" --output-shell "$WORK/boot-backend.sh" >"$WORK/gen-backend.log" 2>&1 \
    && ok "generated backend installer" || bad "ob-builder backend failed"
get_cookie   # refresh: the lab SSO uses short TTLs and bastion setup can outlast the initial cookie
for v in "${BACKEND_VMS[@]}"; do
    ( approve_device "${IP[$v]}" ) &
    run_installer "$v" "$WORK/boot-backend.sh" >"$WORK/$v.log" 2>&1
    wait
    grep -q "Setup complete\|5/5\|Role-specific setup" "$WORK/$v.log" && ok "$v deployed" || bad "$v deploy — see $WORK/$v.log"
done

# ── Phase 3: standalone installer (bastion+backend in one, no bastion in front) ─
# A standalone does not need a bastion_id, so it is a single installer run like a
# backend: enrol + setup in one go, approving the device code in parallel. In
# Mode E this locks port 22 afterwards, which is fine — every assertion goes
# through the dwho SSO cert (see verify_standalone).
if [ -n "$STANDALONE_VM" ]; then
    phase "Phase 3 — standalone (ob-builder --output-shell, scenario=$SCENARIO)"
    sed "s/^scenario:.*/scenario: $SCENARIO/" "$CONFIG_DIR/build-standalone.yml" > "$WORK/build-standalone.yml"
    # Exercise the ob-builder service-keys feature: declare a 'backup' service
    # account whose fingerprint is the lab key's, so the generated installer
    # deposits a matching service-accounts.conf. (verify_service_accounts then
    # logs in as backup with that key.)
    if [ -n "$SVC_FP" ]; then
        cat >> "$WORK/build-standalone.yml" <<EOF

service_accounts:
  - name: backup
    key_fingerprint: "$SVC_FP"
    sudo_allowed: false
    shell: /bin/bash
    home: /var/lib/backup
    gecos: Lab Backup Service Account
EOF
    fi
    obbuild --config "$WORK/build-standalone.yml" --output-shell "$WORK/boot-standalone.sh" >"$WORK/gen-standalone.log" 2>&1 \
        && ok "generated standalone installer (incl. service account)" || { bad "ob-builder standalone failed"; cat "$WORK/gen-standalone.log"; }
    # SSH-layer authorization for the service account — the documented manual step
    # ob-builder does not do. Must run before setup locks port 22.
    provision_service_helper "$STANDALONE_VM"
    get_cookie   # refresh before enrolling: the initial cookie may have expired by now (short lab TTLs)
    ( approve_device "${IP[$STANDALONE_VM]}" ) &
    run_installer "$STANDALONE_VM" "$WORK/boot-standalone.sh" >"$WORK/$STANDALONE_VM.log" 2>&1
    wait
    grep -q "Setup complete\|5/5\|Role-specific setup" "$WORK/$STANDALONE_VM.log" \
        && ok "$STANDALONE_VM deployed" || bad "$STANDALONE_VM deploy — see $WORK/$STANDALONE_VM.log"
fi

verify_e2e
verify_standalone
verify_service_accounts
summary
