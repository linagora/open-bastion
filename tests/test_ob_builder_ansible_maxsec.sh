#!/bin/bash
# test_ob_builder_ansible_maxsec.sh
#
# The generated Ansible role under maximum security (#361). The setup locks
# sudo to SSO tokens on every role, so Ansible's become stops working on the
# host the moment the setup returns:
#   - what needs root runs before the lock, or in the setup's own task: the
#     bastion id (read by the bastion play, handed to the backends as a host
#     fact) and the sshd service-keys check;
#   - a host already locked is recognised without become, before facts are
#     gathered, and skipped;
#   - the backend's collector takes the bastion play's id, does not probe a
#     locked bastion, and names it in its assert with the way out;
#   - with ansible_become_token_cmd (#377), a locked host is played with the
#     ob_sudo_sso become method: the command runs each time sudo asks for a
#     password, and sudo gets the token it prints; the host is not enrolled
#     again.
#
# The static checks read the generated tree. The functional ones run
# ansible-playbook on localhost (connection local, no root) over the generated
# tasks, and skip when ansible-playbook or PyYAML is missing.

# Variables set here are read by the eval'd ob-builder and ob-bastion-setup.
# shellcheck disable=SC2034

set -u

TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$REPO_ROOT/admin-builder/ob-builder"
export OB_BUILDER_LIB_DIR="$REPO_ROOT/admin-builder/lib"
export OB_BUILDER_SHARE="$REPO_ROOT/admin-builder"

TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

test_pass() { echo -e "${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); return 0; }
test_fail() {
    echo -e "${RED}✗${NC} $1"
    [ -n "${2:-}" ] && echo -e "  ${YELLOW}Details:${NC} $2"
    ((TESTS_FAILED++))
    return 0
}

eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
BUILD_DATE="2026-01-01T00:00:00Z"
export OB_BUILDER_NON_INTERACTIVE=1

FAKE_WORK="$TEST_TMPDIR/work"
mkdir -p "$FAKE_WORK"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake ca\n' > "$FAKE_WORK/ca.pub"
: > "$FAKE_WORK/krl"
FAKE_KEYRING="$TEST_TMPDIR/keyring.gpg"
: > "$FAKE_KEYRING"

TREE="$TEST_TMPDIR/tree"
BR="$TREE/roles/open-bastion-bastion"
KR="$TREE/roles/open-bastion-backend"
SR="$TREE/roles/open-bastion-standalone"

render_tree() {
    local cfg="$TEST_TMPDIR/build.yml" rc=0
    cat > "$cfg" <<YML
deployment_slug: demo
scenario: max-security
portal_url: https://sso.example.com
client_id: pam-access
client_secret_mode: prompt
server_group: default
target_role: "bastion,standalone,backend"
auto_enroll_setup: yes
allowed_bastions: null
YML
    (
        fetch_sso_assets() {
            WORK_DIR="$FAKE_WORK"; SSO_CA_FINGERPRINT="SHA256:fake"
            printf '{"keys":[]}\n' > "$WORK_DIR/jwks.json"
        }
        main --config "$cfg" --repo-keyring "$FAKE_KEYRING" --output-ansible "$TREE"
    ) >"$TEST_TMPDIR/render.log" 2>&1 || rc=$?
    return "$rc"
}

# Line of the first match of an ERE in a file, 0 when none.
line_of() { grep -nE -m1 -- "$1" "$2" 2>/dev/null | cut -d: -f1 | grep . || echo 0; }

# ── Static checks on the generated tree ────────────────────────────────────

test_bastion_reads_its_id_before_the_lock() {
    local t="$BR/tasks/bastion.yml" bad="" id setup
    id=$(line_of 'name: Read the bastion id' "$t")
    setup=$(line_of 'name: Configure bastion' "$t")
    { [ "$id" -gt 0 ] && [ "$id" -lt "$setup" ]; } || bad="$bad id-not-before-setup($id/$setup)"
    grep -qF 'ob_bastion_id: "{{ _ob_bastion_id_self.stdout | trim }}"' "$t" || bad="$bad no-host-fact"
    # After the setup, the backend play of the run must know not to probe it.
    [ "$(line_of 'ob_sudo_locked: true' "$t")" -gt "$setup" ] || bad="$bad lock-not-noted"
    [ -z "$bad" ] && test_pass "bastion: id read before ob-bastion-setup and kept as a host fact" \
                  || test_fail "bastion id is not read before the lock" "$bad"
}

test_lock_detected_before_any_become() {
    local r t bad="" slurp skip facts
    for r in "$BR" "$KR" "$SR"; do
        t="$r/tasks/main.yml"
        slurp=$(line_of 'src: /etc/pam.d/sudo' "$t")
        skip=$(awk '/name: Skip the hosts whose sudo only takes SSO tokens/{print NR; exit}' "$t")
        facts=$(line_of 'ansible\.builtin\.setup:' "$t")
        { [ "$slurp" -gt 0 ] && [ "${skip:-0}" -gt "$slurp" ] && [ "$facts" -gt "${skip:-0}" ]; } \
            || bad="$bad ${r##*-}(order:$slurp/${skip:-0}/$facts)"
        # Every task before the skip is controller-side or opts out of become.
        python3 - "$t" <<'PY' 2>/dev/null || bad="$bad ${r##*-}(become-before-skip)"
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))
controller = {'ansible.builtin.meta', 'ansible.builtin.assert', 'ansible.builtin.set_fact', 'ansible.builtin.debug', 'ansible.builtin.include_vars'}
for t in tasks:
    if t.get('name') == 'Skip the hosts whose sudo only takes SSO tokens':
        sys.exit(0)
    if not (set(t) & controller) and t.get('become') is not False:
        sys.exit(1)
sys.exit(1)
PY
    done
    [ -z "$bad" ] && test_pass "every role: sudo lock read without become, host skipped before facts" \
                  || test_fail "a locked host could be asked for sudo" "$bad"
}

test_sshd_check_runs_with_the_setup() {
    local r f bad=""
    for r in bastion backend standalone; do
        f="$TREE/roles/open-bastion-$r/tasks/$r.yml"
        grep -qE '^        ob_setup_cmd$' "$f" || bad="$bad $r(no-wrapper)"
        grep -qE '^  register: ob_setup_run$' "$f" || bad="$bad $r(no-register)"
    done
    f="$BR/tasks/main.yml"
    # The check after the dispatch only runs when no setup ran (it has root).
    grep -A8 'name: Check sshd serves the service-account keys' "$f" \
        | grep -qF 'when: ob_setup_run is not defined or ob_setup_run is skipped' \
        || bad="$bad fallback-unguarded"
    # Issue point 3: cloud-init's drop-in is root-only.
    [ "$(grep -c '2>/dev/null' "$BR/vars/main.yml")" -ge 2 ] || bad="$bad grep-stderr"
    grep -qE '^ +"\$@" \|\| exit \$\?$' "$BR/vars/main.yml" || bad="$bad setup-rc-lost"
    [ -z "$bad" ] && test_pass "every role: sshd service-keys check runs in the setup's task, quietly" \
                  || test_fail "the sshd check would need become after the setup" "$bad"
}

test_backend_uses_the_bastion_fact() {
    local f="$KR/tasks/_bastion-id.yml" b="$KR/tasks/backend.yml" bad=""
    grep -qF "hostvars[ob_bastion_host].ob_bastion_id" "$f" || bad="$bad no-hostvars"
    grep -qF "hostvars[ob_bastion_host].ob_sudo_locked" "$f" || bad="$bad probes-locked"
    # #338: an unreachable bastion still reaches the assert; and a refused
    # become is an error failed_when does not see.
    grep -qF 'ignore_unreachable: true' "$f" || bad="$bad no-ignore-unreachable"
    grep -qF 'ignore_errors: true' "$f" || bad="$bad no-ignore-errors"
    grep -qF 'Set ob_bastion_allowed_bastions explicitly' "$b" || bad="$bad assert-no-way-out"
    grep -qF '/var/lib/open-bastion/bastion-id' "$b" || bad="$bad assert-no-kept-file"
    # #377: the id the bastion keeps is read without become, before the probe
    # as root, and a kept id spares the probe.
    python3 - "$f" <<'PY' || bad="$bad kept-id-read"
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))
names = [t.get('name', '') for t in tasks]
kept = [t for t in tasks if t.get('ansible.builtin.command') == 'ob-bastion-id --cached']
probe = [t for t in tasks if t.get('ansible.builtin.command') == 'ob-bastion-id']
assert len(kept) == 1 and len(probe) == 1
assert kept[0].get('become') is False
assert tasks.index(kept[0]) < tasks.index(probe[0])
assert any('_ob_bastion_id_kept.stdout' in w for w in probe[0]['when'])
PY
    [ -z "$bad" ] && test_pass "backend: bastion id from the bastion play or the kept file, locked bastions not probed" \
                  || test_fail "backend collector check failed" "$bad"
}

# #377: a locked host is played when ansible_become_token_cmd is set. The switch
# to the ob_sudo_sso become method happens only then, and only on a locked
# host (the first run keeps the deploy account's own password), after the lock
# is read and before the skip, which the option disarms along with its
# warning. The plugin ships with every role, and a locked host, enrolled by
# definition, is not enrolled again.
test_become_token_option() {
    local r t bad=""
    for r in "$BR" "$KR" "$SR"; do
        t="$r/tasks/main.yml"
        grep -qE '^ansible_become_token_cmd: ""$' "$r/defaults/main.yml" || bad="$bad ${r##*-}(no-default)"
        grep -qE "^    name = 'ob_sudo_sso'$" "$r/become_plugins/ob_sudo_sso.py" 2>/dev/null \
            || bad="$bad ${r##*-}(no-plugin)"
        grep -qE '^ob_become_via_sso: .*ansible_become_token_cmd' "$r/vars/main.yml" || bad="$bad ${r##*-}(no-helper)"
        python3 - "$t" "$r/tasks/${r##*-}.yml" <<'PY' 2>/dev/null || bad="$bad ${r##*-}(tasks)"
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))
by = {t.get('name'): t for t in tasks}
names = [t.get('name') for t in tasks]
sw = by["Take sudo's password from the SSO at every prompt"]
assert sw['ansible.builtin.set_fact']['ansible_become_method'] == 'ob_sudo_sso'
assert set(sw['when']) == {'ob_sudo_locked | bool', 'ob_become_via_sso | bool'}
assert names.index('Check whether sudo only takes SSO tokens') < names.index(sw['name'])
for n in ('Warn that the role leaves this host alone', 'Skip the hosts whose sudo only takes SSO tokens'):
    assert names.index(sw['name']) < names.index(n)
    assert set(by[n]['when']) == {'ob_sudo_locked | bool', 'not (ob_become_via_sso | bool)'}, n
enrol = [t for t in yaml.safe_load(open(sys.argv[2])) if t.get('ansible.builtin.include_tasks') == '_enroll.yml']
assert len(enrol) == 1
assert 'not (ob_sudo_locked | default(false) | bool)' in enrol[0]['when']
PY
    done
    [ -z "$bad" ] && test_pass "every role: ansible_become_token_cmd switches a locked host to ob_sudo_sso, disarms the skip, and skips the enrolment" \
                  || test_fail "ansible_become_token_cmd is not wired as #377 says" "$bad"
}

# A plain YAML scalar holding ": " is a mapping, not a string: ansible-core
# >= 2.19 refuses it as a conditional at run time, which --syntax-check does
# not see (#364).
test_conditionals_are_strings() {
    if ! python3 -c 'import yaml' 2>/dev/null; then
        echo -e "${YELLOW}SKIP${NC} conditional types (PyYAML missing)"
        return 0
    fi
    local bad
    bad=$(python3 - "$TREE" <<'PY'
import os, sys, yaml
KEYS = ('when', 'changed_when', 'failed_when', 'until')
bad = []
def walk(node, path):
    if isinstance(node, list):
        for x in node:
            walk(x, path)
    elif isinstance(node, dict):
        for k in KEYS:
            if k in node:
                v = node[k]
                for c in (v if isinstance(v, list) else [v]):
                    if not isinstance(c, (str, bool)):
                        bad.append('%s:%s:%s' % (path, node.get('name', '?'), k))
        for v in node.values():
            walk(v, path)
n = 0
for root, _, files in os.walk(sys.argv[1]):
    for f in files:
        if f.endswith('.yml'):
            p = os.path.join(root, f)
            walk(yaml.safe_load(open(p)), os.path.relpath(p, sys.argv[1]))
            n += 1
print(' '.join(bad) if n else 'no-yaml-found')
PY
)
    [ -z "$bad" ] && test_pass "every role: all when/changed_when/failed_when/until are strings" \
                  || test_fail "a conditional is not a string (unquoted ': ')" "$bad"
}

# ── Functional checks (ansible-playbook on localhost) ──────────────────────

have_ansible() {
    command -v ansible-playbook >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null
}

run_play() { # PLAYBOOK INVENTORY LOG
    ANSIBLE_HOME="$TEST_TMPDIR/ansible-home" \
    ANSIBLE_LOCAL_TEMP="$TEST_TMPDIR/ansible-tmp" \
    ANSIBLE_REMOTE_TEMP="$TEST_TMPDIR/ansible-rtmp" \
    ANSIBLE_HOST_KEY_CHECKING=False ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=0 \
    ANSIBLE_SSH_ARGS="-o ConnectTimeout=3 -o BatchMode=yes" \
        ansible-playbook -i "$2" "$1" >"$3" 2>&1
}

# The stack exactly as ob-bastion-setup --max-security writes it.
write_mode_e_stack() {
    local out="$1"
    (
        content=$(cat "$REPO_ROOT/scripts/ob-bastion-setup")
        content="${content%main \"\$@\"}"
        content=$(echo "$content" | sed -E 's/^set -e(uo pipefail)?$//')
        eval "$content"
        parse_args -p https://x --max-security >/dev/null 2>&1
        PAM_SUDO="$out"; PAM_SUDO_I="$out-i"
        backup_file() { :; }; groupadd() { :; }; write_open_bastion_sudoers() { :; }
        configure_max_security_sudo >/dev/null 2>&1
    )
    [ -s "$out" ]
}

test_lock_detection_runs() {
    if ! have_ansible; then
        echo -e "${YELLOW}SKIP${NC} lock detection run (ansible-playbook or PyYAML missing)"
        return 0
    fi
    local d="$TEST_TMPDIR/detect" got
    mkdir -p "$d"
    write_mode_e_stack "$d/mode-e" || { test_fail "could not render the Mode E sudo stack"; return; }
    # The hand edit service-accounts.rst documents lets an account through.
    sed 's/^account    required     pam_openbastion.so$/account    sufficient   pam_succeed_if.so quiet user in ansible\n&/' \
        "$d/mode-e" > "$d/mode-e-edited"
    printf '#%%PAM-1.0\nsession required pam_limits.so\n@include common-auth\n@include common-account\n@include common-session-noninteractive\n' \
        > "$d/distro"
    # The backend stack of the other scenarios: local accounts keep sudo.
    printf 'auth sufficient pam_unix.so\nauth required pam_openbastion.so service_type=sudo\naccount sufficient pam_localuser.so\naccount required pam_openbastion.so service_type=sudo\nsession required pam_unix.so\n' \
        > "$d/backend"
    # The two detection tasks of the generated role, reading a fixture.
    python3 - "$BR/tasks/main.yml" "$d/detect.yml" <<'PY' || { test_fail "detection tasks not found"; return; }
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))
keep = [t for t in tasks if t.get('name') in ('Read the sudo PAM stack', 'Check whether sudo only takes SSO tokens')]
assert len(keep) == 2
keep[0]['ansible.builtin.slurp']['src'] = '{{ fx.value }}'
keep.append({'ansible.builtin.set_fact': {'res': "{{ res | default({}) | combine({fx.key: ob_sudo_locked | bool}) }}"}})
yaml.safe_dump(keep, open(sys.argv[2], 'w'))
PY
    cat > "$d/play.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: $d/detect.yml
      loop: "{{ fixtures | dict2items }}"
      loop_control: { loop_var: fx }
      vars:
        fixtures:
          mode_e: $d/mode-e
          mode_e_edited: $d/mode-e-edited
          distro: $d/distro
          backend: $d/backend
          missing: $d/nonexistent
    - ansible.builtin.copy:
        content: "{{ res | to_json }}"
        dest: $d/result.json
EOF
    printf 'all:\n  hosts:\n    localhost:\n      ansible_python_interpreter: "{{ ansible_playbook_python }}"\n' > "$d/inv.yml"
    run_play "$d/play.yml" "$d/inv.yml" "$d/log" || { test_fail "lock detection play failed" "$(tail -20 "$d/log")"; return; }
    got=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(" ".join(f"{k}={str(r[k]).lower()}" for k in sorted(r)))' "$d/result.json")
    [ "$got" = "backend=false distro=false missing=false mode_e=true mode_e_edited=false" ] \
        && test_pass "lock detection: the Mode E stack is locked; hand-edited, distro, backend and missing stacks are not" \
        || test_fail "lock detection gave the wrong verdict" "$got"
}

test_setup_wrapper_runs() {
    if ! have_ansible; then
        echo -e "${YELLOW}SKIP${NC} setup wrapper run (ansible-playbook or PyYAML missing)"
        return 0
    fi
    local d="$TEST_TMPDIR/wrap" got
    mkdir -p "$d"
    cat > "$d/play.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files: [$BR/vars/main.yml]
  tasks:
    - ansible.builtin.command:
        argv: "{{ ob_setup_cmd + ['sh', '-c', 'echo setup-ran; exit 3'] }}"
      register: failed_setup
      failed_when: false
    - ansible.builtin.command:
        argv: "{{ ob_setup_cmd + ['echo', 'setup ran', 'with args'] }}"
      register: good_setup
    - ansible.builtin.copy:
        content: "{{ {'f': failed_setup, 'g': good_setup} | to_json }}"
        dest: $d/result.json
EOF
    printf 'all:\n  hosts:\n    localhost:\n      ansible_python_interpreter: "{{ ansible_playbook_python }}"\n' > "$d/inv.yml"
    run_play "$d/play.yml" "$d/inv.yml" "$d/log" || { test_fail "setup wrapper play failed" "$(tail -20 "$d/log")"; return; }
    got=$(python3 - "$d/result.json" <<'PY'
import json, re, sys
r = json.load(open(sys.argv[1]))
f, g = r['f'], r['g']
bad = []
if f['rc'] != 3 or 'ob-service-keys-sshd' in f['stdout']:
    bad.append('failed-setup-rc=%s' % f['rc'])
if g['rc'] != 0 or g['stdout_lines'][0] != 'setup ran with args':
    bad.append('args-lost')
if not re.fullmatch(r'ob-service-keys-sshd: (yes|no)', g['stdout_lines'][-1]):
    bad.append('no-verdict')
if g['stderr']:
    bad.append('stderr=' + g['stderr'])
print(' '.join(bad))
PY
)
    [ -z "$got" ] && test_pass "setup wrapper: passes argv, keeps the setup's rc, ends with the sshd verdict, no stderr" \
                  || test_fail "setup wrapper misbehaves" "$got"
}

test_backend_collection_runs() {
    if ! have_ansible; then
        echo -e "${YELLOW}SKIP${NC} backend collection run (ansible-playbook or PyYAML missing)"
        return 0
    fi
    local d="$TEST_TMPDIR/collect" got
    mkdir -p "$d"
    python3 - "$KR/tasks/backend.yml" "$d/assert.yml" <<'PY' || { test_fail "assert task not found"; return; }
import sys, yaml
t = [t for t in yaml.safe_load(open(sys.argv[1])) if t.get('name') == 'Check every bastion answered']
assert len(t) == 1
t[0].pop('when', None)
yaml.safe_dump(t, open(sys.argv[2], 'w'))
PY
    # bastion-1: id read by its own play; bastion-2: locked by an earlier run;
    # bastion-3: no fact, unreachable -- the probe is tried and the backend
    # still reaches the assert (#338). The stand-in ob-bastion-id logs its
    # arguments, and keeps an id only once "$d/kept" exists (#377).
    mkdir -p "$d/bin"
    cat > "$d/bin/ob-bastion-id" <<EOF
#!/bin/sh
echo "args:\$*" >> "$d/calls"
[ "\$*" = --cached ] && [ -e "$d/kept" ] && { echo id-kept; exit 0; }
exit 4
EOF
    chmod +x "$d/bin/ob-bastion-id"
    cat > "$d/inv.yml" <<'EOF'
all:
  vars:
    ansible_python_interpreter: "{{ ansible_playbook_python }}"
  hosts:
    backend-1: { ansible_connection: local }
  children:
    bastions:
      hosts:
        bastion-1: { ansible_connection: local, ob_bastion_id: id-1 }
        bastion-2: { ansible_connection: local, ob_sudo_locked: true }
        bastion-3: { ansible_host: 127.0.0.1, ansible_port: 1 }
EOF
    cat > "$d/play.yml" <<EOF
- hosts: backend-1
  gather_facts: false
  vars: { ob_bastion_group: bastions, ob_max_security: true }
  tasks:
    - ansible.builtin.set_fact: { ob_bastion_id_list: [], ob_bastion_missing_list: [] }
    - ansible.builtin.include_tasks: $KR/tasks/_bastion-id.yml
      loop: "{{ groups[ob_bastion_group] }}"
      loop_control: { loop_var: ob_bastion_host }
    - block:
        - ansible.builtin.include_tasks: $d/assert.yml
      rescue:
        - ansible.builtin.set_fact: { assert_msg: "{{ ansible_failed_result.msg }}" }
    - ansible.builtin.copy:
        content: "{{ {'ids': ob_bastion_id_list, 'missing': ob_bastion_missing_list, 'msg': assert_msg | default('')} | to_json }}"
        dest: $d/result.json
EOF
    PATH="$d/bin:$PATH" run_play "$d/play.yml" "$d/inv.yml" "$d/log" \
        || { test_fail "backend collection play failed" "$(tail -20 "$d/log")"; return; }
    got=$(python3 - "$d/result.json" "$d/calls" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); calls = open(sys.argv[2]).read().splitlines()
bad = []
if r['ids'] != ['id-1', '', '']:
    bad.append('ids=%s' % r['ids'])
if r['missing'] != ['bastion-2', 'bastion-3']:
    bad.append('missing=%s' % r['missing'])
if 'bastion-2, bastion-3' not in r['msg'] or '/var/lib/open-bastion/bastion-id' not in r['msg']:
    bad.append('msg=' + r['msg'])
# bastion-1 has its fact; bastion-2 is asked for its kept id only, never
# probed as root (bastion-3 is unreachable and runs nothing).
if calls != ['args:--cached']:
    bad.append('calls=%s' % calls)
print(' '.join(bad))
PY
)
    [ -z "$got" ] && test_pass "backend collection: bastion fact used, locked bastion not probed, both named with the way out" \
                  || test_fail "backend collection misbehaves" "$got"

    # A later run (#377): the locked bastion now keeps its id, read without
    # sudo; only the unreachable one is left.
    : > "$d/calls"; touch "$d/kept"; rm -f "$d/result.json"
    PATH="$d/bin:$PATH" run_play "$d/play.yml" "$d/inv.yml" "$d/log2" \
        || { test_fail "backend collection play failed (kept id)" "$(tail -20 "$d/log2")"; return; }
    got=$(python3 - "$d/result.json" "$d/calls" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); calls = open(sys.argv[2]).read().splitlines()
bad = []
if r['ids'] != ['id-1', 'id-kept', '']:
    bad.append('ids=%s' % r['ids'])
if r['missing'] != ['bastion-3']:
    bad.append('missing=%s' % r['missing'])
if calls != ['args:--cached']:
    bad.append('calls=%s' % calls)
print(' '.join(bad))
PY
)
    [ -z "$got" ] && test_pass "backend collection: a locked bastion's kept id is read without sudo (#377)" \
                  || test_fail "kept id not used" "$got"
}

# The generated switch task, then tasks that become root through a stand-in
# sudo that logs the password it is given, in a role whose become_plugins/
# is the generated one (found by Ansible as in the shipped tree, without
# ANSIBLE_BECOME_PLUGINS): before the switch sudo gets the deploy
# account's password from the inventory; after it, one fresh token per task
# that becomes root, minted at sudo's prompt only (none for a task without
# become, none when sudo does not ask, as with a valid timestamp), whatever
# the inventory's password, and whatever command a module of the host returns
# as a fact (Ansible drops ansible_become_* keys from returned facts: that
# is why the variable is named so); on an unlocked host, no switch and no
# token.
test_become_token_runs() {
    if ! have_ansible; then
        echo -e "${YELLOW}SKIP${NC} become token run (ansible-playbook or PyYAML missing)"
        return 0
    fi
    local d="$TEST_TMPDIR/token" got
    mkdir -p "$d/bin"
    # Ansible's sudo: -H -S [-n] [-p PROMPT] -u root CMD... The prompt is only
    # given with a password, which Ansible sends once it sees the prompt. A
    # "$d/cached" file is a valid sudo timestamp: no prompt.
    cat > "$d/bin/sudo" <<EOF
#!/bin/bash
prompt=""
while [ \$# -gt 0 ]; do
    case "\$1" in
        -p) prompt="\$2"; shift 2 ;;
        -u) shift 2 ;;
        -H|-S|-n) shift ;;
        *) break ;;
    esac
done
if [ -e "$d/cached" ]; then
    echo cached >> "$d/passwords"
elif [ -n "\$prompt" ]; then
    printf '%s' "\$prompt" >&2
    IFS= read -rs pw
    echo "\$pw" >> "$d/passwords"
else
    echo none >> "$d/passwords"
fi
exec "\$@"
EOF
    cat > "$d/bin/mint" <<EOF
#!/bin/sh
n=\$(( \$(cat "$d/count" 2>/dev/null || echo 0) + 1 ))
echo "\$n" > "$d/count"
echo "token-\$n"
EOF
    chmod +x "$d/bin/sudo" "$d/bin/mint"
    mkdir -p "$d/roles/token/tasks" "$d/roles/token/library"
    cp -r "$BR/become_plugins" "$d/roles/token/"
    # A module of a compromised host returning the command as a fact.
    cat > "$d/roles/token/library/ob_test_fact.py" <<EOF
#!/usr/bin/python3
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={})
m.exit_json(changed=False, ansible_facts={'ansible_become_token_cmd': '/bin/echo injected-token'})
EOF
    python3 - "$BR/tasks/main.yml" "$d/roles/token/tasks/main.yml" "$d" <<'PY' || { test_fail "switch task not found"; return; }
import sys, yaml
t = [t for t in yaml.safe_load(open(sys.argv[1])) if t.get('name') == "Take sudo's password from the SSO at every prompt"]
assert len(t) == 1
d = sys.argv[3]
tasks = [
    {'ansible.builtin.command': '/bin/true'},
    t[0],
    {'ansible.builtin.command': '/bin/true'},
    {'ansible.builtin.command': '/bin/true'},
    {'ob_test_fact': {}, 'become': False},
    {'ansible.builtin.command': '/bin/true', 'become': False},
    {'ansible.builtin.debug': {'msg': 'no root needed'}},
    {'ansible.builtin.command': '/bin/true'},
    {'ansible.builtin.file': {'path': d + '/cached', 'state': 'touch'}, 'become': False},
    {'ansible.builtin.command': '/bin/true'},
]
yaml.safe_dump(tasks, open(sys.argv[2], 'w'))
PY
    cat > "$d/play.yml" <<EOF
- hosts: localhost
  connection: local
  become: true
  gather_facts: false
  vars_files: [$BR/vars/main.yml]
  vars:
    ansible_become_exe: $d/bin/sudo
    ansible_become_token_cmd: $d/bin/mint
    ob_sudo_locked: true
  roles:
    - token
EOF
    # ansible_become_pass is the alias an inventory often holds: the stock
    # sudo takes it, the switched one must not.
    printf 'all:\n  hosts:\n    localhost:\n      ansible_python_interpreter: "{{ ansible_playbook_python }}"\n      ansible_become_pass: deploypw\n' > "$d/inv.yml"
    run_play "$d/play.yml" "$d/inv.yml" "$d/log" \
        || { test_fail "become token play failed" "$(tail -20 "$d/log")"; return; }
    got="$(tr '\n' ' ' < "$d/passwords")minted=$(cat "$d/count" 2>/dev/null || echo 0)"
    [ "$got" = "deploypw token-1 token-2 token-3 cached minted=3" ] \
        && test_pass "become token: the inventory password before the switch, then one fresh token per sudo prompt and none otherwise, a host's fact ignored (#377)" \
        || test_fail "sudo did not get one fresh token per prompt" "$got"

    # Not locked: no switch, the deploy account's own password stays in use.
    : > "$d/passwords"; rm -f "$d/count" "$d/cached"
    sed -i 's/^    ob_sudo_locked: true$/    ob_sudo_locked: false/' "$d/play.yml"
    run_play "$d/play.yml" "$d/inv.yml" "$d/log2" \
        || { test_fail "become token play failed (unlocked)" "$(tail -20 "$d/log2")"; return; }
    got=$(tr '\n' ' ' < "$d/passwords")
    [ "$got" = "deploypw deploypw deploypw deploypw cached " ] && [ ! -e "$d/count" ] \
        && test_pass "become token: an unlocked host keeps its own become password, no token minted" \
        || test_fail "the switch happened on an unlocked host" "passwords: $got"
}

if ! render_tree; then
    test_fail "ob-builder could not render the max-security tree" "$(tail -5 "$TEST_TMPDIR/render.log")"
else
    test_bastion_reads_its_id_before_the_lock
    test_lock_detected_before_any_become
    test_sshd_check_runs_with_the_setup
    test_backend_uses_the_bastion_fact
    test_become_token_option
    test_conditionals_are_strings
    test_lock_detection_runs
    test_setup_wrapper_runs
    test_backend_collection_runs
    test_become_token_runs
fi

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo "Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
