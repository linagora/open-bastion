#!/bin/bash
# test_ob_builder_client_id_per_role.sh
#
# One ob-builder run, several relying parties (#371). The portal signs the
# answers of a host with the keys it assigns to the host's RP, so a bastion
# and its backends on two RPs need two JWKS. The config's `roles:` block gives
# a role its own client_id (and, with client_secret_mode=embedded, its secret);
# the build then fetches one JWKS per distinct client_id and every artefact
# carries the client_id, secret and JWKS of its own role.
#
# Checked: both config parsers (the awk fallback must not let the block's
# client_id override the top-level one), refused blocks, the rendered shell
# installers, Ansible roles and portal checklists, the per-RP fetch failure
# rules, and the --save-config round trip.

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

FAKE_KEYRING="$TEST_TMPDIR/keyring.gpg"
printf 'not-a-real-keyring\n' > "$FAKE_KEYRING"
FETCH_LOG="$TEST_TMPDIR/fetched"

# A config with a bastion on pam-access and backends on ob-backends.
# $1: client_secret_mode, $2: extra lines for the backend's block.
write_config() {
    cat > "$TEST_TMPDIR/build.yml" <<YML
deployment_slug: demo
scenario: token-only
portal_url: https://sso.example.com
client_id: pam-access
client_secret_mode: ${1:-embedded}
embedded_client_secret: "sec-bastion"
server_group: default
target_role: "bastion,backend"
response_signing: ${RS:-prefer}
auto_enroll_setup: yes
allowed_bastions: ""
roles:
  backend:
    client_id: ob-backends   # the backends' RP
${2-    embedded_client_secret: \"sec-backend\"}
YML
}

# Run "$@" in a subshell holding ob-builder's functions, the portal stubbed:
# each JWKS names its client_id in its kid; FAIL_JWKS lists the client_ids
# whose JWKS cannot be fetched.
with_builder() {
    (
        eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
        BUILD_DATE="2026-01-01T00:00:00Z"
        export OB_BUILDER_NON_INTERACTIVE=1
        sso_validate_url() { :; }
        sso_fetch_ca() {
            printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake ca\n' > "$2"
            SSO_CA_FINGERPRINT="SHA256:fake"
        }
        sso_fetch_krl() { : > "$2"; }
        sso_fetch_jwks() {
            echo "$3" >> "$FETCH_LOG"
            case " ${FAIL_JWKS:-} " in *" $3 "*) return 1 ;; esac
            printf '{"keys":[{"crv":"Ed25519","kid":"k-%s","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}\n' "$3" > "$2"
        }
        "$@"
    )
}

# Render the two roles of build.yml into $TEST_TMPDIR/$1/{shell,tree}.
build() {
    local d="$TEST_TMPDIR/$1"
    rm -rf "$d"; mkdir -p "$d/shell"; : > "$FETCH_LOG"
    with_builder main --config "$TEST_TMPDIR/build.yml" --repo-keyring "$FAKE_KEYRING" \
        --output-shell "$d/shell" --output-ansible "$d/tree" >"$d.log" 2>&1
}

# The value of a `key: "value"` line of a role's defaults.
role_default() {
    sed -n "s/^$2: \"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" "$TEST_TMPDIR/$1/tree/roles/open-bastion-$3/defaults/main.yml"
}

# ── Config parsing ─────────────────────────────────────────────────────────

test_roles_block_parsed() {
    local got bad="" parser
    write_config
    for parser in yq awk; do
        [ "$parser" = yq ] && ! command -v yq >/dev/null 2>&1 && continue
        got=$(with_builder eval '
            if [ "'"$parser"'" = awk ]; then
                _load_config_awk "$TEST_TMPDIR/build.yml" 2>/dev/null
                _parse_roles_block "$TEST_TMPDIR/build.yml"
            else
                load_config "$TEST_TMPDIR/build.yml" >/dev/null 2>&1
            fi
            printf "%s|%s|%s|%s|%s" "$CLIENT_ID" "$EMBEDDED_CLIENT_SECRET" \
                "$(role_client_id bastion)" "$(role_client_id backend)" "$(role_embedded_secret backend)"')
        [ "$got" = "pam-access|sec-bastion|pam-access|ob-backends|sec-backend" ] || bad="$bad $parser:$got"
    done
    [ -z "$bad" ] && test_pass "config: roles.backend read by every parser, top-level client_id and secret untouched" \
                  || test_fail "the roles block is misread" "$bad"
}

test_roles_block_refused() {
    local bad="" rc case_ body
    for case_ in unknown-role unknown-key misindented twice flow-map flow-list scalar; do
        case "$case_" in
            flow-map)     body='roles: {backend: {client_id: x}}' ;;
            flow-list)    body='roles: [backend]' ;;
            scalar)       body='roles: backend' ;;
            unknown-role) body=$'roles:\n  frontend:\n    client_id: x' ;;
            unknown-key)  body=$'roles:\n  backend:\n    clientid: x' ;;
            misindented)  body=$'roles:\n    backend:\n  client_id: x' ;;
            twice)        body=$'roles:\n  backend:\n    client_id: x\nroles:\n  bastion:\n    client_id: y' ;;
        esac
        printf 'client_id: pam-access\n%s\n' "$body" > "$TEST_TMPDIR/bad.yml"
        rc=0
        with_builder _parse_roles_block "$TEST_TMPDIR/bad.yml" >/dev/null 2>&1 || rc=$?
        [ "$rc" -ne 0 ] || bad="$bad $case_-accepted"
    done
    [ -z "$bad" ] && test_pass "config: unknown role, unknown key, misindented line, a second roles: and flow forms are refused" \
                  || test_fail "a malformed roles block is accepted" "$bad"
}

test_embedded_needs_role_secret() {
    local rc=0 out
    write_config embedded ""
    out=$(with_builder eval 'load_config "$TEST_TMPDIR/build.yml"; REPO_KEYRING="$FAKE_KEYRING"; validate_inputs' 2>&1) || rc=$?
    if [ "$rc" -ne 0 ] && grep -q 'roles.backend.embedded_client_secret' <<<"$out"; then
        test_pass "embedded: a role on another RP without its own secret stops the build, naming the key"
    else
        test_fail "embedded: the top-level secret would be shipped for another RP" "rc=$rc $(tail -2 <<<"$out")"
    fi
}

# ── Rendered artefacts ─────────────────────────────────────────────────────

test_artefacts_per_role() {
    local bad="" r cid sec d="$TEST_TMPDIR/two" f kid
    write_config
    build two || { test_fail "build with two relying parties failed" "$(tail -5 "$d.log")"; return; }
    [ "$(sort "$FETCH_LOG" | tr '\n' ' ')" = "ob-backends pam-access " ] || bad="$bad fetched=[$(tr '\n' ' ' < "$FETCH_LOG")]"
    for r in bastion backend; do
        if [ "$r" = bastion ]; then cid=pam-access; sec="sec-bastion"; else cid=ob-backends; sec="sec-backend"; fi
        # Ansible role.
        f="$d/tree/roles/open-bastion-$r/files/sso-jwks.json"
        kid=$(jq -r '.keys[0].kid' "$f" 2>/dev/null)
        [ "$kid" = "k-$cid" ] || bad="$bad $r:role-jwks=$kid"
        [ "$(role_default two ob_client_id "$r")" = "$cid" ] || bad="$bad $r:ob_client_id"
        [ "$(role_default two ob_sso_jwks_client_id "$r")" = "$cid" ] || bad="$bad $r:ob_sso_jwks_client_id"
        [ "$(role_default two ob_sso_jwks_sha256 "$r")" = "$(sha256sum < "$f" | cut -d' ' -f1)" ] \
            || bad="$bad $r:ob_sso_jwks_sha256"
        [ "$(role_default two ob_client_secret "$r")" = "$sec" ] || bad="$bad $r:ob_client_secret"
        [ "$(role_default two ob_response_signing "$r")" = "prefer" ] || bad="$bad $r:mode"
        # Shell installer.
        f="$d/shell/bootstrap-demo-$r.sh"
        grep -qx "CLIENT_ID_EMBEDDED=\"$cid\"" "$f" || bad="$bad $r:installer-client"
        grep -qx "SSO_JWKS_CLIENT_ID=\"$cid\"" "$f" || bad="$bad $r:installer-jwks-client"
        grep -qx "EMBEDDED_CLIENT_SECRET_B64=\"$(printf '%s' "$sec" | base64 -w0)\"" "$f" \
            || bad="$bad $r:installer-secret"
        grep -q "k-$cid" <<<"$(grep -A1 "<< 'OB_JWKS_EOF'" "$f" | tail -1 | base64 -d 2>/dev/null)" \
            || bad="$bad $r:installer-jwks"
        # Portal checklist.
        grep -q "$cid" "$d/tree/PORTAL-CHECKLIST-$r.md" || bad="$bad $r:checklist"
    done
    # The other role's secret is in neither artefact.
    grep -q 'sec-backend' "$d/tree/roles/open-bastion-bastion/defaults/main.yml" && bad="$bad backend-secret-in-bastion"
    [ -z "$bad" ] && test_pass "artefacts: each role carries its own client_id, secret and JWKS (installer, role, checklist)" \
                  || test_fail "a role carries another role's relying party" "$bad"
}

test_same_rp_fetched_once() {
    local d="$TEST_TMPDIR/one"
    write_config prompt $'    client_id: pam-access'
    build one || { test_fail "build with one relying party failed" "$(tail -5 "$d.log")"; return; }
    if [ "$(cat "$FETCH_LOG")" = "pam-access" ] \
       && cmp -s "$d/tree/roles/open-bastion-bastion/files/sso-jwks.json" "$d/tree/roles/open-bastion-backend/files/sso-jwks.json"; then
        test_pass "a role restating the top-level client_id shares its JWKS, fetched once"
    else
        test_fail "the same relying party is fetched twice or differs" "fetched=[$(tr '\n' ' ' < "$FETCH_LOG")]"
    fi
}

test_fetch_failure_per_rp() {
    local d="$TEST_TMPDIR/fail" bad="" rc=0
    write_config
    FAIL_JWKS=ob-backends build fail || bad="$bad prefer-build-failed"
    [ "$(role_default fail ob_response_signing bastion)" = "prefer" ] || bad="$bad bastion-mode"
    [ "$(role_default fail ob_response_signing backend)" = "off" ] || bad="$bad backend-not-off"
    [ -e "$d/tree/roles/open-bastion-backend/files/sso-jwks.json" ] && bad="$bad backend-has-jwks"
    RS=required write_config
    FAIL_JWKS=ob-backends build fail-req >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 0 ] && grep -q 'client_id ob-backends' "$TEST_TMPDIR/fail-req.log" || bad="$bad required-not-stopped(rc=$rc)"
    [ -z "$bad" ] && test_pass "fetch failure: prefer turns only that RP's roles off, required stops the build naming it" \
                  || test_fail "a JWKS failure leaks to the other relying party" "$bad"
}

# A role secret outside client_secret_mode=embedded is ignored, as the build
# says: it must not reach artefacts that are not restricted as secret ones.
test_role_secret_not_embedded_in_prompt_mode() {
    local d="$TEST_TMPDIR/prompt" bad=""
    write_config prompt
    build prompt || { test_fail "prompt-mode build failed" "$(tail -5 "$d.log")"; return; }
    grep -rq 'sec-backend' "$d" && bad="$bad role-secret-written"
    grep -rq 'sec-bastion' "$d" && bad="$bad top-secret-written"
    grep -q 'roles.backend.embedded_client_secret is ignored' "$d.log" || bad="$bad no-warning"
    [ -z "$bad" ] && test_pass "prompt mode: no embedded secret, top-level or per role, reaches the artefacts" \
                  || test_fail "a secret leaks into unrestricted artefacts" "$bad"
}

# ── --save-config ──────────────────────────────────────────────────────────

test_save_config_round_trip() {
    local got saved="$TEST_TMPDIR/saved.yml"
    write_config
    with_builder eval 'load_config "$TEST_TMPDIR/build.yml" >/dev/null 2>&1
        REPO_KEYRING="$FAKE_KEYRING"; validate_inputs >/dev/null 2>&1
        SAVE_CONFIG_SECRET=1; render_config_yaml "'"$saved"'"' > "$saved" 2>/dev/null
    got=$(with_builder eval 'load_config "'"$saved"'" >/dev/null 2>&1
        printf "%s|%s|%s|%s" "$CLIENT_ID" "$(role_client_id bastion)" "$(role_client_id backend)" "$(role_embedded_secret backend)"')
    if [ "$got" = "pam-access|pam-access|ob-backends|sec-backend" ] && grep -q '^roles:$' "$saved"; then
        test_pass "--save-config: the roles block is written and read back"
    else
        test_fail "--save-config loses the per-role relying party" "$got"
    fi
}

test_roles_block_parsed
test_roles_block_refused
test_embedded_needs_role_secret
test_artefacts_per_role
test_same_rp_fetched_once
test_fetch_failure_per_rp
test_role_secret_not_embedded_in_prompt_mode
test_save_config_round_trip

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
