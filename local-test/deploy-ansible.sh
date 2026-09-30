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
obbuild(){ PATH="$SHIMBIN:$PATH" "$REPO_ROOT/admin-builder/ob-builder" "$@" --insecure; }

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

# The standalone host is part of the Ansible lab only (the shell harness leaves
# it out), so add it to the VM set here rather than in the shared lib.
[ -n "$STANDALONE_VM" ] && ALL_VMS+=("$STANDALONE_VM")

preflight; build_deb; ensure_sso; recreate_vms
phase "Bootstrap VMs"; for v in "${ALL_VMS[@]}"; do bootstrap_vm "$v" 0; done
get_cookie
mint_dwho_cert   # so the connection-phase + standalone assertions actually run

# ── Phase 1: generate + deploy the bastion, capture bastion_id ───────────────
phase "Phase 1 — bastion (ob-builder + ansible, scenario=$SCENARIO)"
rm -rf "$WORK/role-bastion"
sed "s/^scenario:.*/scenario: $SCENARIO/" "$CONFIG_DIR/build-bastion.yml" > "$WORK/build-bastion.yml"
obbuild --config "$WORK/build-bastion.yml" --output-ansible "$WORK/role-bastion" >"$WORK/gen-bastion.log" 2>&1 \
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
    # ob-bastion-id needs root to read the server token. In Mode E sudo is locked
    # to LLNG tokens, so the mgmt user cannot become root at all and a become
    # failure isn't catchable with failed_when -- hence the skip. `ob_max_security`
    # is passed from the harness below; it used to be tested here and set
    # nowhere, so the guard never fired.
    - name: Capture bastion_id
      ansible.builtin.command: ob-bastion-id
      register: _bid
      changed_when: false
      failed_when: false
      when: not (ob_max_security | default(false) | bool)
    - ansible.builtin.copy:
        content: "{{ _bid.stdout }}\n"
        dest: "{{ bid_out }}"
      delegate_to: localhost
      become: false
      when: (_bid.rc | default(1)) == 0 and (_bid.stdout | default('') | length) > 0
    # Ship the verdict out even on failure, so the harness can tell "skipped
    # because Mode E" from "ran and failed". Without it every non-zero rc --
    # including the migration failure this whole change is about -- looks
    # exactly like the Mode E skip, and the run stays green with the hop
    # allowlist untested.
    - ansible.builtin.copy:
        content: "{{ _bid.rc | default('skipped') }}\n{{ _bid.stderr | default('') }}\n"
        dest: "{{ bid_out }}.status"
      delegate_to: localhost
      become: false
EOF
_maxsec=false; [ "$SCENARIO" = "max-security" ] && _maxsec=true
( cd "$WORK/role-bastion" && ansible-playbook -i inv.yml deploy.yml \
    --extra-vars "ob_llng_cookie='$COOKIE' bid_out=$WORK/bastion-id.txt ob_max_security=$_maxsec" ) >"$WORK/deploy-bastion.log" 2>&1
if grep -q "failed=0" "$WORK/deploy-bastion.log"; then
    BID="$([ -s "$WORK/bastion-id.txt" ] && cat "$WORK/bastion-id.txt" || true)"
    _bid_rc="$(head -1 "$WORK/bastion-id.txt.status" 2>/dev/null || echo skipped)"
    if [ -n "$BID" ]; then
        ok "bastion deployed; bastion_id=$BID"
    elif [ "$_bid_rc" = "skipped" ]; then
        # Mode E only: the capture task is skipped because sudo is locked to
        # LLNG tokens and the mgmt user cannot read the server token. A known
        # condition, so it does not fail the run -- but there is no usable
        # placeholder either. bastion_id is a portal-assigned device id, not
        # the client_id, so a literal never matches the hop certificate's
        # key-id and would refuse every hop. Empty means "accept any vouched
        # bastion": the allowlist is not exercised, and the run says so.
        skip "hop allowlist enforcement (Mode E: capture skipped, allowed_bastions left EMPTY)"
    else
        # The task ran and ob-bastion-id failed -- exactly the shape of the
        # portal migration this change is about (endpoint removed, 403, no
        # identity). That is a real failure and must weigh on the verdict, the
        # way deploy-shell.sh already treats it.
        bad "ob-bastion-id failed (rc=$_bid_rc) — allowed_bastions left EMPTY, the hop allowlist is NOT under test in this run"
        tail -n +2 "$WORK/bastion-id.txt.status" 2>/dev/null | sed 's/^/      /'
    fi
else bad "bastion deploy failed — see $WORK/deploy-bastion.log"; tail -20 "$WORK/deploy-bastion.log"; BID=""; fi

# ── Phase 2: generate + deploy the backends with allowed_bastions=bastion_id ─
phase "Phase 2 — backends (ob-builder + ansible)"
sed -e "s/^allowed_bastions:.*/allowed_bastions: ${BID}/" \
    -e "s/^scenario:.*/scenario: $SCENARIO/" "$CONFIG_DIR/build-backend.yml" > "$WORK/build-backend.yml"
rm -rf "$WORK/role-backend"
obbuild --config "$WORK/build-backend.yml" --output-ansible "$WORK/role-backend" >"$WORK/gen-backend.log" 2>&1 \
    && ok "generated backend role (allowed_bastions=${BID:-<empty>})" || bad "ob-builder backend failed"
{ echo "all:"; echo "  vars:"; _inv_vars; echo "  children:"; echo "    backends:"; echo "      hosts:"
  echo "        ${BACKEND_VMS[0]}: { ansible_host: ${IP[${BACKEND_VMS[0]}]}, ob_server_group: backend }"
  echo "        ${BACKEND_VMS[1]}: { ansible_host: ${IP[${BACKEND_VMS[1]}]}, ob_server_group: backend }"
} > "$WORK/role-backend/inv.yml"
get_cookie   # refresh: the lab SSO uses short TTLs and the bastion phase can outlast the initial cookie
( cd "$WORK/role-backend" && ansible-playbook -i inv.yml playbook.yml \
    --extra-vars "ob_llng_cookie='$COOKIE'" ) >"$WORK/deploy-backends.log" 2>&1
if grep -q "failed=0" "$WORK/deploy-backends.log" && ! grep -q "failed=[1-9]" "$WORK/deploy-backends.log"; then
    ok "backends deployed"
else bad "backend deploy failed — see $WORK/deploy-backends.log"; tail -20 "$WORK/deploy-backends.log"; fi

# ── Phase 3: generate + deploy a standalone host (bastion+backend in one) ────
if [ -n "$STANDALONE_VM" ]; then
    phase "Phase 3 — standalone (ob-builder + ansible, scenario=$SCENARIO)"
    rm -rf "$WORK/role-standalone"
    sed "s/^scenario:.*/scenario: $SCENARIO/" "$CONFIG_DIR/build-standalone.yml" > "$WORK/build-standalone.yml"
    obbuild --config "$WORK/build-standalone.yml" --output-ansible "$WORK/role-standalone" >"$WORK/gen-standalone.log" 2>&1 \
        && ok "generated standalone role" || { bad "ob-builder standalone failed"; cat "$WORK/gen-standalone.log"; }
    cat > "$WORK/role-standalone/inv.yml" <<EOF
all:
  vars:
$(_inv_vars)
  children:
    standalones:
      hosts:
        $STANDALONE_VM: { ansible_host: ${IP[$STANDALONE_VM]}, ob_server_group: bastion }
EOF
    cat > "$WORK/role-standalone/deploy.yml" <<'EOF'
- hosts: standalones
  become: true
  roles: [open-bastion]
EOF
    get_cookie   # refresh before enrolling: the initial cookie may have expired by now (short lab TTLs)
    ( cd "$WORK/role-standalone" && ansible-playbook -i inv.yml deploy.yml \
        --extra-vars "ob_llng_cookie='$COOKIE'" ) >"$WORK/deploy-standalone.log" 2>&1
    if grep -q "failed=0" "$WORK/deploy-standalone.log" && ! grep -q "failed=[1-9]" "$WORK/deploy-standalone.log"; then
        ok "standalone deployed"
    else bad "standalone deploy failed — see $WORK/deploy-standalone.log"; tail -20 "$WORK/deploy-standalone.log"; fi
fi

verify_e2e
verify_standalone
summary
