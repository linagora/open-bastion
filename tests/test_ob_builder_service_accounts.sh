#!/bin/bash
#
# Test suite for ob-builder service-account support.
#
# Sources ob-builder (with `set -euo pipefail` and the `main "$@"` call
# stripped) and exercises the service-account parsing, validation and INI
# rendering helpers directly. OB_BUILDER_LIB_DIR / OB_BUILDER_SHARE are exported
# so ob-builder's lib/template auto-detection short-circuits.
#

set -u

TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# ob-builder defines its own SCRIPT_DIR, and the eval below overwrites ours.
# Keep the repository root under a name it does not use.
OB_REPO_ROOT="$SCRIPT_DIR"
BUILDER="$SCRIPT_DIR/admin-builder/ob-builder"
export OB_BUILDER_LIB_DIR="$SCRIPT_DIR/admin-builder/lib"
export OB_BUILDER_SHARE="$SCRIPT_DIR/admin-builder"

TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

test_pass() { echo -e "${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); }
test_fail() {
    echo -e "${RED}✗${NC} $1"
    [ -n "${2:-}" ] && echo -e "  ${YELLOW}Details:${NC} $2"
    ((TESTS_FAILED++))
}

# Source ob-builder definitions into THIS shell (functions + globals), with the
# top-level `set -euo pipefail` and the final `main "$@"` removed so nothing
# runs and a failing helper does not kill the harness.
# shellcheck disable=SC1090
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
BUILD_DATE="2026-01-01T00:00:00Z"

# Test 1: syntax check
test_syntax() {
    if bash -n "$BUILDER" 2>/dev/null; then
        test_pass "Syntax check: bash -n passes"
    else
        test_fail "Syntax check failed"
    fi
}

# Test 2: validators mirror the C rules
test_validators() {
    local ok=true
    is_valid_service_username "ansible"  || ok=false
    is_valid_service_username "_svc-1"   || ok=false
    is_valid_service_username "Ansible"  && ok=false   # uppercase first char
    is_valid_service_username "1svc"     && ok=false   # leading digit
    is_valid_fingerprint "SHA256:abcDEF123+/="  || ok=false
    is_valid_fingerprint "MD5:aa:bb:cc"  || ok=false
    is_valid_fingerprint "abc123"        && ok=false   # no prefix
    is_valid_fingerprint "SHA256:bad spaces" && ok=false
    is_valid_abs_path ""                 || ok=false   # empty OK
    is_valid_abs_path "/bin/bash"        || ok=false
    is_valid_abs_path "relative/path"    && ok=false
    $ok && test_pass "validators: username / fingerprint / path" \
         || test_fail "validators returned wrong result"
}

# Test 3: parse a YAML service_accounts block
test_parse_block() {
    local cfg="$TEST_TMPDIR/cfg.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
portal_url: https://sso.example.com
service_accounts:
  - name: ansible
    key_fingerprint: "SHA256:abc123"
    sudo_allowed: true
    sudo_nopasswd: true
    shell: /bin/bash
    home: /var/lib/ansible
    gecos: Ansible Automation
  - name: backup
    key_fingerprint: "SHA256:xyz789"
    sudo_allowed: false
    shell: /bin/sh
auto_enroll_setup: prompt
YML
    SERVICE_ACCOUNTS_RECORDS=()
    _parse_service_accounts_block "$cfg"

    local ok=true
    [ "${#SERVICE_ACCOUNTS_RECORDS[@]}" -eq 2 ] || { ok=false; echo "  count=${#SERVICE_ACCOUNTS_RECORDS[@]}"; }
    [ "$(_sa_field 1 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "ansible" ] || ok=false
    [ "$(_sa_field 2 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "SHA256:abc123" ] || ok=false
    [ "$(_sa_field 3 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "true" ] || ok=false
    [ "$(_sa_field 5 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "/bin/bash" ] || ok=false
    [ "$(_sa_field 7 "${SERVICE_ACCOUNTS_RECORDS[0]}")" = "Ansible Automation" ] || ok=false
    [ "$(_sa_field 1 "${SERVICE_ACCOUNTS_RECORDS[1]}")" = "backup" ] || ok=false
    [ "$(_sa_field 3 "${SERVICE_ACCOUNTS_RECORDS[1]}")" = "false" ] || ok=false
    $ok && test_pass "parse: service_accounts block → 2 records, fields correct" \
         || test_fail "parse: block parsing wrong"
}

# Test 4: a config with no service_accounts yields zero records
test_parse_none() {
    local cfg="$TEST_TMPDIR/none.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
portal_url: https://sso.example.com
YML
    SERVICE_ACCOUNTS_RECORDS=()
    _parse_service_accounts_block "$cfg"
    [ "${#SERVICE_ACCOUNTS_RECORDS[@]}" -eq 0 ] \
        && test_pass "parse: no service_accounts → 0 records" \
        || test_fail "parse: expected 0 records, got ${#SERVICE_ACCOUNTS_RECORDS[@]}"
}

# Test 5: record validation
test_record_validation() {
    local ok=true
    validate_service_account_record "$(_sa_pack ansible SHA256:abc true false /bin/bash /var/lib/ansible '' '' '')" || ok=false
    validate_service_account_record "$(_sa_pack BadName SHA256:abc false false '' '' '' '' '')" && ok=false
    validate_service_account_record "$(_sa_pack svc nofingerprint false false '' '' '' '' '')" && ok=false
    validate_service_account_record "$(_sa_pack svc SHA256:abc false false relpath '' '' '' '')" && ok=false
    $ok && test_pass "validate_service_account_record: accepts valid, rejects bad" \
         || test_fail "record validation wrong"
}

# Test 6: INI rendering
test_render_conf() {
    SERVICE_ACCOUNTS_RECORDS=(
        "$(_sa_pack ansible SHA256:abc123 true true /bin/bash /var/lib/ansible 'Ansible Automation' '' '')"
        "$(_sa_pack backup SHA256:xyz789 false false /bin/sh '' '' '' '')"
    )
    local out rc
    out=$(_render_service_accounts_conf); rc=$?
    local ok=true
    # Must return 0 even when the last account has no uid/gid — otherwise the
    # `$(...)` assignment trips `set -e` in ob-builder (regression guard).
    [ "$rc" -eq 0 ] || { ok=false; echo "  non-zero return: $rc"; }
    grep -q '^\[ansible\]$'                      <<<"$out" || ok=false
    grep -q '^key_fingerprint = SHA256:abc123$'  <<<"$out" || ok=false
    grep -q '^sudo_allowed = true$'              <<<"$out" || ok=false
    grep -q '^sudo_nopasswd = true$'             <<<"$out" || ok=false
    grep -q '^gecos = Ansible Automation$'       <<<"$out" || ok=false
    grep -q '^home = /var/lib/ansible$'          <<<"$out" || ok=false
    grep -q '^\[backup\]$'                       <<<"$out" || ok=false
    grep -q '^sudo_allowed = false$'             <<<"$out" || ok=false
    # backup has no home/gecos → those keys absent in its section is not trivially
    # grep-able, but the file must not carry an empty 'home =' line anywhere.
    grep -q '^home = $'                          <<<"$out" && ok=false
    $ok && test_pass "render: INI output well-formed" \
         || test_fail "render: INI output wrong" "$out"
}

echo "=========================================="
echo "Testing ob-builder service-account support"
echo "=========================================="
echo ""


# ─────────────────────────────────────────────────────────────────────────
# public_key: the field service-accounts.conf could never carry (#263)
# ─────────────────────────────────────────────────────────────────────────

# Test: the fingerprint is derived from the key, and matches ssh-keygen exactly.
#
# This is the copy-error class the field report ran into from the other side: a
# fingerprint maintained apart from the key it describes matches nothing, and
# the failure appears at login with the key looking correct in every listing.
test_fingerprint_derived_from_key() {
    command -v ssh-keygen >/dev/null 2>&1 || { echo "SKIP: ssh-keygen required"; return; }
    local d="$TEST_TMPDIR/deriv"; mkdir -p "$d"
    ssh-keygen -t ed25519 -f "$d/k" -N "" -q -C "svc@test"
    local pub expected cfg
    pub=$(cat "$d/k.pub")
    expected=$(ssh-keygen -lf "$d/k.pub" | awk '{print $2}')

    cfg="$d/cfg.yml"
    cat > "$cfg" <<YML
deployment_slug: demo
service_accounts:
  - name: svc
    public_key: "$pub"
YML
    SERVICE_ACCOUNTS_RECORDS=()
    _parse_service_accounts_block "$cfg" >/dev/null 2>&1

    local got_fp got_pub
    got_fp=$(_sa_field 2 "${SERVICE_ACCOUNTS_RECORDS[0]:-}")
    got_pub=$(_sa_field 10 "${SERVICE_ACCOUNTS_RECORDS[0]:-}")
    if [ "$got_fp" = "$expected" ] && [ "$got_pub" = "$pub" ]; then
        test_pass "key_fingerprint is derived from public_key, and the key is kept"
    else
        test_fail "key_fingerprint is derived from public_key, and the key is kept" \
                  "fp='$got_fp' expected='$expected'"
    fi
}

# Test: a fingerprint that does not describe the key stops the build.
#
# A warning would not do. The bundle would install cleanly and refuse the login
# on the target, which is the most expensive place to find out.
test_mismatch_is_rejected() {
    command -v ssh-keygen >/dev/null 2>&1 || { echo "SKIP: ssh-keygen required"; return; }
    local d="$TEST_TMPDIR/mismatch"; mkdir -p "$d"
    ssh-keygen -t ed25519 -f "$d/k" -N "" -q -C "svc@test"
    local pub; pub=$(cat "$d/k.pub")

    # Drive the reconciliation directly: the variables it reads are the parser's,
    # so they are set here and consumed through dynamic scope -- which shellcheck
    # cannot follow, hence the directive.
    # shellcheck disable=SC2034
    local name="svc" fp="SHA256:StaleFromAPreviousRotation0000000000000000" pubkey="$pub"
    if _sa_reconcile_key >/dev/null 2>&1; then
        test_fail "a key_fingerprint that does not match public_key is rejected" \
                  "_sa_reconcile_key returned 0"
    else
        test_pass "a key_fingerprint that does not match public_key is rejected"
    fi

    # And the matching pair is accepted.
    # shellcheck disable=SC2034
    fp=$(ssh-keygen -lf "$d/k.pub" | awk '{print $2}')
    if _sa_reconcile_key >/dev/null 2>&1; then
        test_pass "a matching key_fingerprint/public_key pair is accepted"
    else
        test_fail "a matching key_fingerprint/public_key pair is accepted"
    fi
}

# Test: public_key_file is read at build time.
# A path would be a promise the installer cannot keep -- the target has no
# access to the builder's filesystem.
test_public_key_file() {
    command -v ssh-keygen >/dev/null 2>&1 || { echo "SKIP: ssh-keygen required"; return; }
    local d="$TEST_TMPDIR/keyfile"; mkdir -p "$d"
    ssh-keygen -t ed25519 -f "$d/k" -N "" -q -C "svc@file"
    cp "$d/k.pub" "$d/svc.pub"

    # RELATIVE path: it must resolve against the config file's directory, not the
    # builder's cwd. Run from elsewhere so a cwd-relative resolution fails.
    local cfg="$d/cfg.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
service_accounts:
  - name: svc
    public_key_file: svc.pub
YML
    # A subshell: the parser calls `_sa_reconcile_key || exit 1`, and this suite
    # sources ob-builder in-process -- a parser-driven failure would otherwise
    # kill the whole run mid-way with no diagnostics and later tests never run.
    local got
    got=$( cd / && SERVICE_ACCOUNTS_RECORDS=() ; \
           _parse_service_accounts_block "$cfg" >/dev/null 2>&1 ; \
           _sa_field 10 "${SERVICE_ACCOUNTS_RECORDS[0]:-}" )
    case "$got" in
        ssh-ed25519\ *svc@file)
            test_pass "public_key_file is read at build time, relative to the config file" ;;
        *)  test_fail "public_key_file is read at build time, relative to the config file" \
                      "got '$got'" ;;
    esac
}

# Test: a malformed key is dropped rather than deployed.
test_bad_key_is_dropped() {
    local cfg="$TEST_TMPDIR/badkey.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
service_accounts:
  - name: svc
    key_fingerprint: "SHA256:abc"
    public_key: "not-an-ssh-key at all"
YML
    # A key that cannot be used is now a build ERROR, not a silent drop: warning
    # and continuing shipped a garbage key while a merely stale fingerprint
    # killed the build -- the asymmetry the review caught. Subshell, because the
    # refusal is an `exit 1` inside a sourced parser.
    local rc=0
    ( SERVICE_ACCOUNTS_RECORDS=(); _parse_service_accounts_block "$cfg" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        test_pass "a value that is not an SSH public key stops the build"
    else
        test_fail "a value that is not an SSH public key stops the build" "exited 0"
    fi
}

# Test: the renderer emits one "<name> <key>" line per account that has a key.
test_render_keys() {
    SERVICE_ACCOUNTS_RECORDS=(
        "$(_sa_pack a "SHA256:1" false false "" "" "" "" "" "ssh-ed25519 AAAA a@h")"
        "$(_sa_pack b "SHA256:2" false false "" "" "" "" "" "")"
        "$(_sa_pack c "SHA256:3" false false "" "" "" "" "" "ssh-rsa BBBB c@h")"
    )
    local out; out=$(_render_service_account_keys)
    local n; n=$(printf '%s\n' "$out" | grep -c .)
    if [ "$n" -eq 2 ] \
       && printf '%s' "$out" | grep -q '^a ssh-ed25519 AAAA a@h$' \
       && printf '%s' "$out" | grep -q '^c ssh-rsa BBBB c@h$'; then
        test_pass "only accounts with a key are rendered, one line each"
    else
        test_fail "only accounts with a key are rendered, one line each" "$out"
    fi
}

# Test: both artefact templates deploy the keys, and neither is silent about
# the sshd half. Deploying <name>.pub without an AuthorizedKeysCommand leaves
# the account still unable to log in -- the failure #263 reported.
test_templates_deploy_and_warn() {
    local sh_t="$OB_REPO_ROOT/admin-builder/templates/shell/installer.sh.in"
    local an_t="$OB_REPO_ROOT/admin-builder/templates/ansible/role/tasks/main.yml.in"
    local bad=""
    grep -q 'SERVICE_ACCOUNT_KEYS_B64' "$sh_t"          || bad="$bad shell(no-placeholder)"
    grep -q 'service-accounts.d/\${_sa_name}.pub' "$sh_t" || bad="$bad shell(no-deploy)"
    grep -q 'enable-service-keys' "$sh_t"                || bad="$bad shell(no-sshd-warning)"
    grep -q 'ob_service_account_keys' "$an_t"            || bad="$bad ansible(no-var)"
    grep -q 'service-accounts.d/' "$an_t"                || bad="$bad ansible(no-deploy)"
    grep -q 'enable-service-keys' "$an_t"                || bad="$bad ansible(no-sshd-warning)"
    if [ -z "$bad" ]; then
        test_pass "both templates deploy <name>.pub and warn when sshd cannot serve it"
    else
        test_fail "both templates deploy <name>.pub and warn when sshd cannot serve it" "$bad"
    fi
}

# ─────────────────────────────────────────────────────────────────────────
# Guards for the two mistakes made while writing the above
# ─────────────────────────────────────────────────────────────────────────

# Test: --help contains no live command substitution.
#
# The usage text is an UNQUOTED heredoc, so a backtick or $( ) in it is
# EXECUTED when --help runs. It happened twice: `ob-bastion-setup
# --enable-service-keys` and `service_keys: false` were both run as commands and
# --help printed an empty gap where the text should be. A reader sees a
# half-sentence; on a hostile config value it would be worse than cosmetic.
test_help_has_no_substitution() {
    local out bad=""
    out=$("$BUILDER" --help 2>&1) || true

    # Nothing executed: the rendered help must not contain an empty "set  to"
    # style gap, and the source block must carry no backtick or $( ).
    local blk
    blk=$(awk '/^    cat << EOF$/{f=1;next} f&&/^EOF$/{exit} f' "$BUILDER")
    printf '%s' "$blk" | grep -q '`'      && bad="$bad backtick-in-help"
    printf '%s' "$blk" | grep -q '\$('    && bad="$bad command-substitution-in-help"

    # And the help really renders (a failed substitution can empty it).
    printf '%s' "$out" | grep -q 'SERVICE ACCOUNTS' || bad="$bad help-section-missing"

    if [ -z "$bad" ]; then
        test_pass "--help contains no live command substitution"
    else
        test_fail "--help contains no live command substitution" "$bad"
    fi
}

# Test: the RENDERED artefacts, not the .in templates.
#
# The previous version grepped the raw .in text, so a ph_set-side typo or a
# missing placeholder entry left "@@SERVICE_ACCOUNT_KEYS_B64@@" literally in the
# installer -- where `[ -n "@@...@@" ]` is truthy and `base64 -d` decodes a
# placeholder -- and the suite stayed green. Same class as the #DEBHELPER# token
# that shipped a broken postinst.
test_rendered_artifacts() {
    local d="$TEST_TMPDIR/render"; mkdir -p "$d"
    local tpl="$OB_REPO_ROOT/admin-builder/templates/shell/installer.sh.in"
    [ -f "$tpl" ] || { test_fail "rendered installer is sound" "template missing"; return; }

    # Minimal placeholder set: enough for the service-account paths.
    SERVICE_ACCOUNTS_RECORDS=(
        "$(_sa_pack svc "SHA256:x" false false "" "" "" "" "" "ssh-ed25519 AAAAB svc@h")"
    )
    local keys keys_b64 conf conf_b64
    keys=$(_render_service_account_keys); keys_b64=$(base64_string "$keys")
    conf=$(_render_service_accounts_conf); conf_b64=$(base64_string "$conf")

    local out="$d/installer.sh"
    sed -e "s|@@SERVICE_ACCOUNT_KEYS_B64@@|$keys_b64|g" \
        -e "s|@@SERVICE_ACCOUNTS_CONF_B64@@|$conf_b64|g" \
        -e "s|@@SERVICE_KEYS_SETUP_BOOL@@|true|g" \
        -e "s|@@[A-Z0-9_]*@@|x|g" "$tpl" > "$out"

    local bad=""
    grep -q '@@' "$out" && bad="$bad placeholder-left-in-artifact"
    bash -n "$out" 2>/dev/null || bad="$bad artifact-does-not-parse"
    grep -q 'service-accounts.d/${_sa_name}.pub' "$out" || bad="$bad no-key-deploy"
    grep -q 'Removed stale' "$out"        || bad="$bad no-stale-cleanup"
    grep -q 'enable-service-keys' "$out"  || bad="$bad setup-flag-not-passed"
    grep -q 'chmod 0711 /etc/open-bastion' "$out" || bad="$bad parent-not-traversable"

    # The key really survives the round trip.
    printf '%s' "$keys_b64" | base64 -d | grep -q '^svc ssh-ed25519 AAAAB svc@h$' \
        || bad="$bad key-not-in-blob"

    if [ -z "$bad" ]; then
        test_pass "the rendered installer carries the keys, the flag and a traversable parent"
    else
        test_fail "the rendered installer carries the keys, the flag and a traversable parent" "$bad"
    fi
}

# A name here that is not a defined function used to be a shell error the script
# walked past, leaving the suite green with a test that never ran -- it happened
# while adding the last three. Fail loudly instead.
for _t in test_syntax test_validators test_parse_block test_parse_none \
          test_record_validation test_render_conf \
          test_fingerprint_derived_from_key test_mismatch_is_rejected \
          test_public_key_file test_bad_key_is_dropped test_render_keys \
          test_templates_deploy_and_warn test_help_has_no_substitution \
          test_rendered_artifacts; do
    if declare -F "$_t" >/dev/null; then
        "$_t"
    else
        test_fail "$_t is listed as a test but is not defined"
    fi
done


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
