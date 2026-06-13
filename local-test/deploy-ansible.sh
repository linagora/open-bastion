#!/usr/bin/env bash
# shellcheck shell=bash source=lib.sh
#
# Two-phase ANSIBLE deploy, exactly as the Ansible quick-start documents:
#   1. ob-builder generates the bastion role        -> deploy to the bastion
#   2. ob-bastion-id on the bastion gives bastion_id -> feed the backend allowlist
#   3. ob-builder generates the backend role         -> deploy to the backends
#   4. verify the cert hop + ob-scp end to end
#
# The ob-builder-generated role is used UNCHANGED; lab-only quirks live in the
# inventory overrides written here (see README.md). NOT run in CI (needs VMs).
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export ANSIBLE_HOST_KEY_CHECKING=False

# curl shim as `curl` on PATH so ob-builder resolves auth.example.com -> gateway
# (the shim self-locates its dummy CA via readlink, so the symlink is enough).
SHIMBIN="$WORK/shimbin"; mkdir -p "$SHIMBIN"
ln -sf "$SSO_DIR/ob-builder-curl-shim.sh" "$SHIMBIN/curl"
obbuild(){ PATH="$SHIMBIN:$PATH" "$REPO_ROOT/admin-builder/ob-builder" "$@" --allow-http; }

# Common lab-only inventory vars (kept out of the generated role).
_inv_vars(){ cat <<EOF
    ansible_user: debian
    ansible_ssh_private_key_file: $SSH_KEY
    ansible_port: 22
    ansible_ssh_common_args: >-
      -o IdentityAgent=none -o IdentitiesOnly=yes
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    ansible_python_interpreter: /usr/bin/python3
    ob_approve_base_url: "http://$GW_IP"
    ob_approve_host: "auth.example.com"
    ob_apt_sources_list_line: "deb [trusted=yes] http://$GW_IP:$APT_PORT/ ./"
    ob_verify_ssl: false
EOF
}

preflight; build_deb; ensure_sso; recreate_vms
phase "Bootstrap VMs"; for v in "${ALL_VMS[@]}"; do bootstrap_vm "$v" 0; done
get_cookie

# ── Phase 1: generate + deploy the bastion, capture bastion_id ───────────────
phase "Phase 1 — bastion (ob-builder + ansible)"
rm -rf "$WORK/role-bastion"
obbuild --config "$CONFIG_DIR/build-bastion.yml" --output-ansible "$WORK/role-bastion" >"$WORK/gen-bastion.log" 2>&1 \
    && ok "generated bastion role" || { bad "ob-builder bastion failed"; cat "$WORK/gen-bastion.log"; }
cat > "$WORK/role-bastion/inv.yml" <<EOF
all:
  vars:
$(_inv_vars)
  children:
    bastions:
      hosts:
        $BASTION_VM: { ansible_host: ${IP[$BASTION_VM]}, ob_server_group: bastion }
EOF
cat > "$WORK/role-bastion/deploy.yml" <<'EOF'
- hosts: bastions
  become: true
  roles: [open-bastion]
  post_tasks:
    - name: Capture bastion_id
      ansible.builtin.command: ob-bastion-id
      register: _bid
      changed_when: false
    - ansible.builtin.copy:
        content: "{{ _bid.stdout }}\n"
        dest: "{{ bid_out }}"
      delegate_to: localhost
      become: false
EOF
( cd "$WORK/role-bastion" && ansible-playbook -i inv.yml deploy.yml \
    --extra-vars "ob_llng_cookie='$COOKIE' bid_out=$WORK/bastion-id.txt" ) >"$WORK/deploy-bastion.log" 2>&1
if grep -q "failed=0" "$WORK/deploy-bastion.log" && [ -s "$WORK/bastion-id.txt" ]; then
    BID="$(cat "$WORK/bastion-id.txt")"; ok "bastion deployed; bastion_id=$BID"
else bad "bastion deploy failed — see $WORK/deploy-bastion.log"; tail -20 "$WORK/deploy-bastion.log"; BID=""; fi

# ── Phase 2: generate + deploy the backends with allowed_bastions=bastion_id ─
phase "Phase 2 — backends (ob-builder + ansible)"
sed "s/^allowed_bastions:.*/allowed_bastions: ${BID:-ob-bastion}/" "$CONFIG_DIR/build-backend.yml" > "$WORK/build-backend.yml"
rm -rf "$WORK/role-backend"
obbuild --config "$WORK/build-backend.yml" --output-ansible "$WORK/role-backend" >"$WORK/gen-backend.log" 2>&1 \
    && ok "generated backend role (allowed_bastions=${BID:-ob-bastion})" || bad "ob-builder backend failed"
{ echo "all:"; echo "  vars:"; _inv_vars; echo "  children:"; echo "    backends:"; echo "      hosts:"
  echo "        ${BACKEND_VMS[0]}: { ansible_host: ${IP[${BACKEND_VMS[0]}]}, ob_server_group: backend }"
  echo "        ${BACKEND_VMS[1]}: { ansible_host: ${IP[${BACKEND_VMS[1]}]}, ob_server_group: backend }"
} > "$WORK/role-backend/inv.yml"
( cd "$WORK/role-backend" && ansible-playbook -i inv.yml playbook.yml \
    --extra-vars "ob_llng_cookie='$COOKIE'" ) >"$WORK/deploy-backends.log" 2>&1
if grep -q "failed=0" "$WORK/deploy-backends.log" && ! grep -q "failed=[1-9]" "$WORK/deploy-backends.log"; then
    ok "backends deployed"
else bad "backend deploy failed — see $WORK/deploy-backends.log"; tail -20 "$WORK/deploy-backends.log"; fi

verify_e2e
summary
