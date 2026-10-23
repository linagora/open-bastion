#!/bin/bash
# test_ob_builder_ansible_jwks.sh
#
# The generated Ansible role deploys the portal's JWKS once (#371). A later
# run used to copy the build-time JWKS over the one ob-heartbeat had rotated
# since, and to pass it to the setup with --sso-jwks: once the portal dropped
# its old key, every host under response_signing = required refused every
# SSO login. Now:
#   - the JWKS is deployed when the host has none the modules load, when the
#     host enrols as another client_id, or when ob_sso_jwks_force is set;
#   - otherwise it is kept, and the setup gets neither --sso-jwks nor
#     --sso-jwks-sha256 (which would replace it, or refuse it as a mismatch).
#
# The static checks read the generated tree. The functional one runs the
# decision tasks with ansible-playbook on localhost (connection local, no
# root) over fixtures, and skips when ansible-playbook or PyYAML is missing.

# Variables set here are read by the eval'd ob-builder.
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
response_signing: required
auto_enroll_setup: yes
allowed_bastions: null
YML
    (
        fetch_sso_assets() {
            WORK_DIR="$FAKE_WORK"; SSO_CA_FINGERPRINT="SHA256:fake"
            printf '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}\n' \
                > "$WORK_DIR/jwks.json"
            SSO_JWKS_SHA256=$(sha256sum < "$WORK_DIR/jwks.json" | awk '{print $1}')
            SSO_JWKS_CLIENT_ID="pam-access"
        }
        main --config "$cfg" --repo-keyring "$FAKE_KEYRING" --output-ansible "$TREE"
    ) >"$TEST_TMPDIR/render.log" 2>&1 || rc=$?
    return "$rc"
}

# ── Static checks on the generated tree ────────────────────────────────────

test_role_carries_the_jwks() {
    local bad="" r
    for r in bastion backend standalone; do
        grep -qE '^ob_response_signing: "required"$' "$TREE/roles/open-bastion-$r/defaults/main.yml" \
            || bad="$bad $r(mode)"
        grep -qE '^ob_sso_jwks_force: false$' "$TREE/roles/open-bastion-$r/defaults/main.yml" \
            || bad="$bad $r(no-force-default)"
    done
    [ -z "$bad" ] && test_pass "every role: built with a JWKS, required, ob_sso_jwks_force off by default" \
                  || test_fail "the rendered roles do not carry the JWKS settings" "$bad"
}

test_deploy_follows_the_decision() {
    local bad
    bad=$(python3 - "$TREE" <<'PY' 2>&1
import sys, yaml
tree = sys.argv[1]
bad = []
for r in ('bastion', 'backend', 'standalone'):
    tasks = yaml.safe_load(open(f'{tree}/roles/open-bastion-{r}/tasks/main.yml'))
    names = [t.get('name') for t in tasks]
    try:
        check = names.index('Check the JWKS already on the host')
        decide = names.index('Decide whether to deploy the portal\'s JWKS')
        deploy = names.index('Deploy the portal\'s JWKS')
        conf = names.index('Deploy openbastion.conf')
    except ValueError as e:
        bad.append(f'{r}({e})'); continue
    # Decided before the copy, and before openbastion.conf is rewritten
    # with the new client_id.
    if not check < decide < deploy < conf:
        bad.append(f'{r}(order)')
    if tasks[deploy].get('when') != 'ob_sso_jwks_deploy | bool':
        bad.append(f'{r}(deploy-when={tasks[deploy].get("when")})')
    # Whatever its source, the modules' loader checks it before it lands.
    if not str(tasks[deploy]['ansible.builtin.copy'].get('validate', '')).startswith(
            '/usr/sbin/ob-verify-response check-jwks --anchor '):
        bad.append(f'{r}(deploy-not-validated)')
    # openbastion.conf holds client_secret: the read must not print it.
    if tasks[names.index('Read the client_id the host enrols as')].get('no_log') is not True:
        bad.append(f'{r}(conf-read-logged)')
    # The setup gets the JWKS options only when the role deployed it.
    setup = [t for t in yaml.safe_load(open(f'{tree}/roles/open-bastion-{r}/tasks/{r}.yml'))
             if 'ob-' in str(t.get('name', '')) and 'setup' in str(t.get('name', ''))
             and 'ansible.builtin.command' in t]
    if len(setup) != 1:
        bad.append(f'{r}(setup-tasks={len(setup)})'); continue
    argv = setup[0]['ansible.builtin.command']['argv']
    if 'ob_sso_jwks_src' in argv:
        bad.append(f'{r}(setup-keys-on-src)')
    if argv.count('if ob_sso_jwks_deploy | default(false) | bool') != 2:
        bad.append(f'{r}(setup-not-on-decision)')
print(' '.join(bad))
PY
)
    [ -z "$bad" ] && test_pass "every role: JWKS copy and setup's --sso-jwks follow the keep/deploy decision" \
                  || test_fail "the JWKS is still deployed on every run" "$bad"
}

# ── Functional check (ansible-playbook on localhost) ───────────────────────

have_ansible() {
    command -v ansible-playbook >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null
}

run_play() { # PLAYBOOK INVENTORY LOG
    ANSIBLE_HOME="$TEST_TMPDIR/ansible-home" \
    ANSIBLE_LOCAL_TEMP="$TEST_TMPDIR/ansible-tmp" \
    ANSIBLE_REMOTE_TEMP="$TEST_TMPDIR/ansible-rtmp" \
    ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=0 \
        ansible-playbook -i "$2" "$1" >"$3" 2>&1
}

test_decision_runs() {
    if ! have_ansible; then
        echo -e "${YELLOW}SKIP${NC} keep/deploy decision run (ansible-playbook or PyYAML missing)"
        return 0
    fi
    local d="$TEST_TMPDIR/decide" got
    mkdir -p "$d"
    # Stand in for ob-verify-response check-jwks --anchor (which may not be
    # built where this runs) with a stub that loads a fixture only when it
    # says "loadable".
    printf '#!/bin/sh\n# check-jwks --anchor --quiet FILE\ngrep -qs loadable "$4"\n' > "$d/verify"
    chmod +x "$d/verify"
    echo loadable > "$d/jwks-ok"
    echo garbage > "$d/jwks-bad"
    printf 'portal_url = https://sso.example.com\nclient_id = pam-access\n' > "$d/conf-same"
    printf 'portal_url = https://sso.example.com\nclient_id=pam-access  \n' > "$d/conf-same-spacing"
    printf 'portal_url = https://sso.example.com\nclient_id = other-rp\n' > "$d/conf-other"
    # The three decision tasks of the generated role, reading fixtures.
    python3 - "$BR/tasks/main.yml" "$d/decide.yml" "$d/verify" <<'PY' || { test_fail "decision tasks not found"; return; }
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))
names = ('Check the JWKS already on the host', 'Read the client_id the host enrols as',
         'Decide whether to deploy the portal\'s JWKS')
keep = [t for t in tasks if t.get('name') in names]
assert len(keep) == 3
keep[0]['ansible.builtin.command']['argv'][0] = sys.argv[3]
keep[1]['ansible.builtin.slurp']['src'] = '{{ fx.value.conf }}'
keep.append({'ansible.builtin.set_fact': {'res': "{{ res | default({}) | combine({fx.key: ob_sso_jwks_deploy | bool}) }}"}})
yaml.safe_dump(keep, open(sys.argv[2], 'w'))
PY
    cat > "$d/play.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files: [$BR/vars/main.yml]
  vars:
    ob_client_id: pam-access
  tasks:
    - ansible.builtin.include_tasks: $d/decide.yml
      loop: "{{ fixtures | dict2items }}"
      loop_control: { loop_var: fx }
      vars:
        ob_sso_jwks_src: "{{ fx.value.src | default('sso-jwks.json') }}"
        ob_sso_jwks_file: "{{ fx.value.jwks }}"
        ob_sso_jwks_force: "{{ fx.value.force | default(false) }}"
        ob_sso_jwks_fetch: "{{ fx.value.fetch | default(false) }}"
        fixtures:
          kept:          { jwks: $d/jwks-ok,  conf: $d/conf-same }
          kept_spacing:  { jwks: $d/jwks-ok,  conf: $d/conf-same-spacing }
          no_jwks:       { jwks: $d/missing,  conf: $d/conf-same }
          bad_jwks:      { jwks: $d/jwks-bad, conf: $d/conf-same }
          other_rp:      { jwks: $d/jwks-ok,  conf: $d/conf-other }
          no_conf:       { jwks: $d/jwks-ok,  conf: $d/missing }
          forced:        { jwks: $d/jwks-ok,  conf: $d/conf-same, force: true }
          no_src:        { jwks: $d/missing,  conf: $d/missing, src: '' }
          fetch_no_src:  { jwks: $d/missing,  conf: $d/missing, src: '', fetch: true }
          fetch_kept:    { jwks: $d/jwks-ok,  conf: $d/conf-same, src: '', fetch: true }
    - ansible.builtin.copy:
        content: "{{ res | to_json }}"
        dest: $d/result.json
EOF
    printf 'all:\n  hosts:\n    localhost:\n      ansible_python_interpreter: "{{ ansible_playbook_python }}"\n' > "$d/inv.yml"
    run_play "$d/play.yml" "$d/inv.yml" "$d/log" || { test_fail "decision play failed" "$(tail -20 "$d/log")"; return; }
    got=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(" ".join(f"{k}={str(r[k]).lower()}" for k in sorted(r)))' "$d/result.json")
    [ "$got" = "bad_jwks=true fetch_kept=false fetch_no_src=true forced=true kept=false kept_spacing=false no_conf=true no_jwks=true no_src=false other_rp=true" ] \
        && test_pass "decision: a loadable JWKS of the same client_id is kept; missing, unloadable, other RP, no conf or forced redeploys; ob_sso_jwks_fetch counts as a JWKS" \
        || test_fail "the keep/deploy decision is wrong" "$got"
}

# ob_sso_jwks_fetch (#371): the controller fetches the JWKS of the host's
# ob_client_id when it is to be deployed, writes it in canonical form, and the
# modules' loader checks it before it replaces the host's. Against a local
# portal stand-in; ob-verify-response is a stub refusing a kid "reject".
test_fetch_runs() {
    if ! have_ansible; then
        echo -e "${YELLOW}SKIP${NC} play-time JWKS fetch run (ansible-playbook or PyYAML missing)"
        return 0
    fi
    local d="$TEST_TMPDIR/fetch" got port pid rc sha canon
    mkdir -p "$d/out"
    cat > "$d/portal.py" <<'PY'
import json, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
log = open(sys.argv[1], 'a', buffering=1)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        cid = urllib.parse.parse_qs(u.query).get('client_id', [''])[0]
        log.write(cid + '\n')
        if u.path != '/oauth2/jwks':
            self.send_response(404); self.end_headers(); return
        # Keys deliberately unsorted and indented: the role must canonicalise.
        doc = {'a': 1} if cid == 'not-a-jwks' else \
              {'keys': [{'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', 'kty': 'OKP',
                         'kid': cid, 'crv': 'Ed25519'}]}
        if cid == 'with-private':
            doc['keys'][0]['d'] = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A'
        body = json.dumps(doc, indent=2, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)
s = ThreadingHTTPServer(('127.0.0.1', 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
PY
    : > "$d/requests"
    python3 "$d/portal.py" "$d/requests" > "$d/port" 2>/dev/null &
    pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$d/port" ] && break; sleep 0.2; done
    port=$(cat "$d/port")
    [ -n "$port" ] || { kill "$pid" 2>/dev/null; test_fail "portal stand-in did not start"; return; }
    printf '#!/bin/sh\n# check-jwks --anchor --quiet FILE\n! grep -qs reject "$4"\n' > "$d/verify"
    chmod +x "$d/verify"
    # The URL check, fetch, check, keep and deploy tasks of the generated role, on the
    # controller itself, without root.
    python3 - "$BR/tasks/main.yml" "$d/fetch.yml" "$d/verify" <<'PY' || { kill "$pid"; test_fail "fetch tasks not found"; return; }
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))
names = ('Check the JWKS URL', "Fetch the portal's JWKS for the host's client_id",
         'Check the fetched JWKS', 'Keep the fetched JWKS', "Deploy the portal's JWKS")
keep = [t for t in tasks if t.get('name') in names]
assert len(keep) == 5
for t in keep:
    t.pop('delegate_to', None); t.pop('become', None)
cp = keep[4]['ansible.builtin.copy']
cp.pop('owner'); cp.pop('group')
assert cp['validate'].startswith('/usr/sbin/ob-verify-response ')
cp['validate'] = cp['validate'].replace('/usr/sbin/ob-verify-response', sys.argv[3])
yaml.safe_dump([{'block': keep,
                 'rescue': [{'ansible.builtin.set_fact': {'failed_case': True}}]},
                {'ansible.builtin.set_fact': {'res': "{{ res | default({}) | combine({fx.key: "
                  "'failed' if failed_case | default(false) else "
                  "(lookup('file', ob_sso_jwks_file, errors='ignore') | default('', true))}) }}"}},
                {'ansible.builtin.set_fact': {'failed_case': False}}],
               open(sys.argv[2], 'w'))
PY
    canon='{"keys":[{"crv":"Ed25519","kid":"ob-backends","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}'
    sha=$(printf '%s\n' "$canon" | sha256sum | cut -d' ' -f1)
    # The pin of a non-ASCII kid, computed as the docs say: jq -S -c . | sha256sum.
    local sha_utf8=""
    if command -v jq >/dev/null 2>&1; then
        sha_utf8=$(python3 -c 'import sys, urllib.request; sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1]).read())' \
            "http://127.0.0.1:$port/oauth2/jwks?client_id=cl%C3%A9" | jq -S -c . | sha256sum | cut -d' ' -f1)
    fi
    # A valid anchor already in place, which a refused JWKS must leave alone.
    echo previous > "$d/out/refused.json"
    echo previous > "$d/out/private.json"
    cat > "$d/play.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    ob_sso_jwks_fetch: true
  tasks:
    - ansible.builtin.include_tasks: $d/fetch.yml
      loop: "{{ fixtures | dict2items }}"
      loop_control: { loop_var: fx }
      vars:
        ob_client_id: "{{ fx.value.cid }}"
        ob_sso_jwks_deploy: "{{ fx.value.deploy | default(true) }}"
        ob_sso_jwks_fetch_sha256: "{{ fx.value.pin | default('') }}"
        ob_sso_jwks_url: "{{ fx.value.url | default('http://127.0.0.1:$port/oauth2/jwks') }}"
        ob_sso_jwks_file: "$d/out/{{ fx.key }}.json"
        # The stand-in speaks http: only a test setup may fetch keys in clear.
        ob_verify_ssl: "{{ fx.value.verify | default(false) }}"
        fixtures:
          fetched:     { cid: ob-backends }
          pinned:      { cid: ob-backends, pin: "$(tr a-f A-F <<<"$sha")" }
          wrong_pin:   { cid: ob-backends, pin: "${sha%?}x" }
          not_a_jwks:  { cid: not-a-jwks }
          http_404:    { cid: ob-backends, url: "http://127.0.0.1:$port/nope" }
          refused:     { cid: reject }
          private:     { cid: with-private }
          non_ascii:   { cid: "clé", pin: "$sha_utf8" }
          cleartext:   { cid: ob-backends, verify: true }
          kept:        { cid: kept-host, deploy: false }
    - ansible.builtin.copy:
        content: "{{ res | to_json }}"
        dest: $d/result.json
EOF
    printf 'all:\n  hosts:\n    localhost:\n      ansible_python_interpreter: "{{ ansible_playbook_python }}"\n' > "$d/inv.yml"
    rc=0
    run_play "$d/play.yml" "$d/inv.yml" "$d/log" || rc=$?
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    [ "$rc" -eq 0 ] || { test_fail "fetch play failed" "$(tail -20 "$d/log")"; return; }
    got=$(python3 - "$d/result.json" "$canon" "$d/requests" "$d/out" <<'PY'
import json, os, sys
r = json.load(open(sys.argv[1])); canon = sys.argv[2]
want = {'fetched': canon, 'pinned': canon, 'wrong_pin': 'failed', 'not_a_jwks': 'failed',
        'http_404': 'failed', 'refused': 'failed', 'private': 'failed', 'cleartext': 'failed',
        'kept': ''}
bad = [f'{k}={r.get(k)!r}' for k in want if r.get(k) != want[k]]
# Written in UTF-8, as jq writes it, and matching a pin computed with jq.
if r.get('non_ascii') != canon.replace('ob-backends', 'clé'):
    bad.append(f"non_ascii={r.get('non_ascii')!r}")
# The file holds the canonical form and its newline, as `jq -S -c .` writes it.
p = os.path.join(sys.argv[4], 'fetched.json')
if not os.path.exists(p) or open(p).read() != canon + '\n':
    bad.append('not-canonical-on-disk')
for k in ('refused', 'private'):
    if open(os.path.join(sys.argv[4], k + '.json')).read() != 'previous\n':
        bad.append(f'{k}-anchor-replaced')
if 'kept-host' in open(sys.argv[3]).read().split():
    bad.append('kept-host-fetched')
print(' '.join(bad))
PY
)
    [ -z "$got" ] && test_pass "fetch: the JWKS of the host's client_id, canonical (UTF-8), pinned or not; a wrong pin, a non-JWKS, an HTTP error, a private key, a cleartext URL or a key the loader refuses leaves the anchor alone; a kept JWKS is not fetched" \
                  || test_fail "play-time JWKS fetch misbehaves" "$got"
}

# The setup gets --sso-jwks only when the role deployed the JWKS, and
# --sso-jwks-sha256 only for the build's JWKS: under ob_sso_jwks_fetch the
# hash would come from the same controller, canonicalised by Python.
test_setup_args_run() {
    if ! have_ansible; then
        echo -e "${YELLOW}SKIP${NC} setup arguments run (ansible-playbook or PyYAML missing)"
        return 0
    fi
    local d="$TEST_TMPDIR/setupargs" got r bad=""
    mkdir -p "$d"
    for r in bastion backend standalone; do
        python3 - "$TREE/roles/open-bastion-$r/tasks/$r.yml" "$d/$r.yml" <<'PY' || { bad="$bad $r(no-task)"; continue; }
import sys, yaml
t = [t for t in yaml.safe_load(open(sys.argv[1]))
     if 'setup' in str(t.get('name', '')) and 'ansible.builtin.command' in t]
assert len(t) == 1
yaml.safe_dump([{'ansible.builtin.set_fact': {'res': "{{ res | default({}) | combine({fx.key: "
                 + t[0]['ansible.builtin.command']['argv'].strip()[2:-2].strip() + "}) }}"}}],
               open(sys.argv[2], 'w'))
PY
        cat > "$d/play-$r.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files: [$TREE/roles/open-bastion-$r/defaults/main.yml, $TREE/roles/open-bastion-$r/vars/main.yml]
  vars:
    ob_client_secret: ""
    ob_bastion_id_list: [id-1]
  tasks:
    - ansible.builtin.include_tasks: $d/$r.yml
      loop: "{{ fixtures | dict2items }}"
      loop_control: { loop_var: fx }
      vars:
        ob_sso_jwks_deploy: "{{ fx.value.deploy }}"
        ob_sso_jwks_fetch: "{{ fx.value.fetch }}"
        fixtures:
          build:  { deploy: true,  fetch: false }
          fetch:  { deploy: true,  fetch: true }
          kept:   { deploy: false, fetch: false }
    - ansible.builtin.copy:
        content: "{{ res | to_json }}"
        dest: $d/result-$r.json
EOF
        printf 'all:\n  hosts:\n    localhost:\n      ansible_python_interpreter: "{{ ansible_playbook_python }}"\n' > "$d/inv.yml"
        run_play "$d/play-$r.yml" "$d/inv.yml" "$d/log-$r" || { bad="$bad $r(play:$(grep -m1 -o 'msg.*' "$d/log-$r" | cut -c1-150))"; continue; }
        got=$(python3 - "$d/result-$r.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
def opts(a): return ('J' if '--sso-jwks' in a else '-') + ('S' if '--sso-jwks-sha256' in a else '-')
print(' '.join(f'{k}={opts(r[k])}' for k in sorted(r)))
PY
)
        [ "$got" = "build=JS fetch=J- kept=--" ] || bad="$bad $r($got)"
    done
    [ -z "$bad" ] && test_pass "every role: the setup gets --sso-jwks and its SHA-256 for the build's JWKS, --sso-jwks alone for a fetched one, neither when kept" \
                  || test_fail "the setup arguments do not follow the JWKS source" "$bad"
}

if ! render_tree; then
    test_fail "ob-builder could not render the tree" "$(tail -5 "$TEST_TMPDIR/render.log")"
else
    test_role_carries_the_jwks
    test_deploy_follows_the_decision
    test_decision_runs
    test_fetch_runs
    test_setup_args_run
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
