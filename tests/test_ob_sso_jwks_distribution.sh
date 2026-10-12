#!/bin/bash
# test_ob_sso_jwks_distribution.sh -- the portal's JWKS reaches the hosts (#339).
#
# The PAM and NSS modules check the portal's signed answers against
# /var/lib/open-bastion/jwks/sso-jwks.json. That file is the trust anchor, so how it gets
# there matters as much as the verifier:
#
#   - ob-builder fetches it for EVERY role (it used to for backend/bundle only),
#     from jwks_uri?client_id=<client_id>, refuses anything the C verifier could
#     not use, embeds it in the shell installer with its SHA-256 and ships it in
#     the Ansible role with a task that deploys it;
#   - the setup script installs it from --sso-jwks, or fetches it and trusts it
#     only on a matching --sso-jwks-sha256 or an interactive confirmation, keeps
#     a JWKS already on the host, and never writes prefer/required without one.
#
# No network: curl is a shell function serving fixtures.
# shellcheck disable=SC2034  # variables are read by the sourced functions
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"
BUILDER="$ROOT_DIR/admin-builder/ob-builder"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

for _cmd in jq sha256sum base64; do
    command -v "$_cmd" >/dev/null 2>&1 || { echo "SKIP: $_cmd not installed"; exit 0; }
done

# shellcheck source=tests/lib_setup_script.sh
. "$TESTS_DIR/lib_setup_script.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK" "$SETUP_LINK_DIR"' EXIT

# An Ed25519 key (RFC 8037 A.2) and an RSA key, in an order and spacing the
# portal could serve: key order is not stable across fetches, so everything
# is compared in canonical form (jq -S -c .).
JWKS_GOOD='{ "keys": [ {"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kty":"OKP","crv":"Ed25519","kid":"k1","use":"sig","alg":"EdDSA"} ] }'
JWKS_OTHER='{"keys":[{"kty":"RSA","kid":"r2","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB"}]}'
JWKS_GOOD_FP=$(printf '%s' "$JWKS_GOOD" | jq -S -c . | sha256sum | awk '{print $1}')
JWKS_OTHER_FP=$(printf '%s' "$JWKS_OTHER" | jq -S -c . | sha256sum | awk '{print $1}')
# What the C verifier cannot use, each for its own reason.
BAD_JWKS=(
    '{"keys":[]}'
    '{"keys":[{"kty":"oct","kid":"h","k":"c2VjcmV0"}]}'
    '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}]}'
    '{"keys":[{"kty":"RSA","kid":"e","n":"x","e":"AQAB","use":"enc"}]}'
    '{"keys":[{"kty":"EC","kid":"s","key_ops":["sign"]}]}'
    '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}'
    '[{"kty":"OKP","kid":"k1"}]'
    'not json'
    '{"keys":[{"kty":"RSA","kid":"short","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7","e":"AQAB"}]}'
    '{"keys":[{"kty":"EC","kid":"k256k1","crv":"secp256k1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}'
    '{"keys":[{"kty":"OKP","crv":"X25519","kid":"x","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}'
)

# ═════════════════════════════════════════════════════════════════════════════
# ob-builder
# ═════════════════════════════════════════════════════════════════════════════

# Run "$@" in a subshell with ob-builder's definitions loaded and the portal
# replaced by a curl function: it logs every URL to $WORK/curl.log and answers
# /oauth2/jwks with $FAKE_JWKS (empty = failure).
with_builder() {
    (
        export OB_BUILDER_LIB_DIR="$ROOT_DIR/admin-builder/lib"
        export OB_BUILDER_SHARE="$ROOT_DIR/admin-builder"
        eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
        curl() {
            local out="" url="" a
            while [ $# -gt 0 ]; do
                case "$1" in
                    -o) out="$2"; shift 2 ;;
                    -D|-H|--connect-timeout|--max-time) shift 2 ;;
                    -*) shift ;;
                    *) url="$1"; shift ;;
                esac
            done
            printf '%s\n' "$url" >> "$WORK/curl.log"
            case "$url" in
                */oauth2/jwks*|*/jwks*)
                    [ -n "${FAKE_JWKS:-}" ] || return 22
                    a="$FAKE_JWKS" ;;
                *) return 22 ;;
            esac
            if [ -n "$out" ]; then printf '%s' "$a" > "$out"; else printf '%s' "$a"; fi
        }
        "$@"
    )
}

test_jwks_url() {
    local got bad=""
    got=$(with_builder eval 'SSO_JWKS_URI=""; sso_jwks_url https://sso.example.com/ pam-access')
    [ "$got" = "https://sso.example.com/oauth2/jwks?client_id=pam-access" ] || bad="$bad default:$got"
    got=$(with_builder eval 'SSO_JWKS_URI="https://sso.example.com/oauth2/jwks"; sso_jwks_url https://sso.example.com "a b&c"')
    [ "$got" = "https://sso.example.com/oauth2/jwks?client_id=a%20b%26c" ] || bad="$bad encoded:$got"
    got=$(with_builder eval 'SSO_JWKS_URI="https://sso.example.com/jwks?x=1"; sso_jwks_url https://sso.example.com pam-access')
    [ "$got" = "https://sso.example.com/jwks?x=1&client_id=pam-access" ] || bad="$bad query:$got"
    if [ -z "$bad" ]; then
        pass "ob-builder: JWKS URL is jwks_uri (or /oauth2/jwks) with ?client_id= / &client_id=, encoded"
    else
        fail "ob-builder: JWKS URL" "$bad"
    fi
}

test_builder_fetch_valid() {
    local out rc=0
    : > "$WORK/curl.log"
    out=$(FAKE_JWKS="$JWKS_GOOD" with_builder eval '
        log_step() { :; }; log_info() { :; }
        SSO_JWKS_URI=""
        sso_fetch_jwks https://sso.example.com "$WORK/b.json" pam-access || exit 1
        printf "%s %s\n" "$SSO_JWKS_SHA256" "$SSO_JWKS_CLIENT_ID"') || rc=$?
    local bad=""
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    [ "$out" = "$JWKS_GOOD_FP pam-access" ] || bad="$bad sha/client:$out"
    [ "$(sha256sum "$WORK/b.json" 2>/dev/null | awk '{print $1}')" = "$JWKS_GOOD_FP" ] || bad="$bad file-not-canonical"
    grep -qx 'https://sso.example.com/oauth2/jwks?client_id=pam-access' "$WORK/curl.log" || bad="$bad url:$(cat "$WORK/curl.log")"
    if [ -z "$bad" ]; then
        pass "ob-builder: sso_fetch_jwks writes the canonical JWKS of the RP and its SHA-256"
    else
        fail "ob-builder: sso_fetch_jwks" "$bad"
    fi
}

test_builder_fetch_invalid() {
    local j bad="" rc
    for j in "${BAD_JWKS[@]}"; do
        rm -f "$WORK/bad.json"
        rc=0
        FAKE_JWKS="$j" with_builder eval '
            log_step() { :; }; log_info() { :; }; log_error() { :; }
            sso_fetch_jwks https://sso.example.com "$WORK/bad.json" pam-access' || rc=$?
        { [ "$rc" -ne 0 ] && [ ! -e "$WORK/bad.json" ]; } || bad="$bad [$j]"
    done
    if [ -z "$bad" ]; then
        pass "ob-builder: a JWKS the verifier cannot use is refused (${#BAD_JWKS[@]} shapes)"
    else
        fail "ob-builder: unusable JWKS accepted" "$bad"
    fi
}

# fetch_sso_assets for each role, with the CA/KRL/discovery steps stubbed.
fetch_for() {
    local roles="$1" mode="${2:-prefer}" client="${3-pam-access}"
    with_builder eval '
        log_step() { :; }; log_info() { :; }; log_warn() { echo "WARN $*"; }
        mktemp_dir() { mkdir -p "$WORK/wd"; printf "%s" "$WORK/wd"; }
        sso_validate_url() { SSO_JWKS_URI=""; return 0; }
        sso_fetch_ca() { echo ca > "$2"; }
        sso_fetch_krl() { : > "$2"; }
        rm -rf "$WORK/wd"
        IFS=" " read -r -a TARGET_ROLES <<< "'"$roles"'"
        RESPONSE_SIGNING='"$mode"'; CLIENT_ID="'"$client"'"
        PORTAL_URL=https://sso.example.com; SCENARIO=token-only; PAM_MODE=A
        fetch_sso_assets
        echo "EFFECTIVE=$(effective_response_signing)"'
}

test_builder_fetch_every_role() {
    local spec out bad=""
    for spec in "bastion" "standalone" "backend" "bastion backend" "bastion standalone"; do
        : > "$WORK/curl.log"
        out=$(FAKE_JWKS="$JWKS_GOOD" fetch_for "$spec" 2>&1)
        grep -qx 'https://sso.example.com/oauth2/jwks?client_id=pam-access' "$WORK/curl.log" \
            || bad="$bad [$spec:no-fetch]"
        [ -s "$WORK/wd/jwks.json" ] || bad="$bad [$spec:no-file]"
        grep -q '^EFFECTIVE=prefer$' <<<"$out" || bad="$bad [$spec:$out]"
    done
    if [ -z "$bad" ]; then
        pass "ob-builder: the JWKS is fetched with client_id for every role (bastion, standalone, backend, several at once)"
    else
        fail "ob-builder: JWKS not fetched for every role" "$bad"
    fi
}

test_builder_fetch_failure() {
    local out rc=0 bad=""
    out=$(FAKE_JWKS="" fetch_for bastion required 2>&1) || rc=$?
    { [ "$rc" -ne 0 ] && grep -q 'response_signing = required needs it' <<<"$out"; } || bad="$bad required-not-fatal(rc=$rc)"
    rc=0
    out=$(FAKE_JWKS='{"keys":[]}' fetch_for bastion required 2>&1) || rc=$?
    [ "$rc" -ne 0 ] || bad="$bad required-unusable-not-fatal"
    rc=0
    out=$(FAKE_JWKS="" fetch_for bastion prefer 2>&1) || rc=$?
    { [ "$rc" -eq 0 ] && grep -q '^EFFECTIVE=off$' <<<"$out" && grep -q 'No usable JWKS' <<<"$out" \
      && [ ! -e "$WORK/wd/jwks.json" ]; } || bad="$bad prefer-down(rc=$rc)"
    rc=0
    out=$(FAKE_JWKS='{"keys":[{"kty":"RSA","n":"x","e":"AQAB"}]}' fetch_for bastion prefer 2>&1) || rc=$?
    { [ "$rc" -eq 0 ] && grep -q '^EFFECTIVE=off$' <<<"$out"; } || bad="$bad prefer-no-kid(rc=$rc)"
    rc=0
    out=$(FAKE_JWKS="" fetch_for bastion off 2>&1) || rc=$?
    { [ "$rc" -eq 0 ] && grep -q '^EFFECTIVE=off$' <<<"$out" && [ ! -e "$WORK/wd/jwks.json" ]; } \
        || bad="$bad off-fatal(rc=$rc)"
    rc=0
    : > "$WORK/curl.log"
    out=$(FAKE_JWKS="$JWKS_GOOD" fetch_for bastion prefer "" 2>&1) || rc=$?
    { [ "$rc" -eq 0 ] && grep -q '^EFFECTIVE=off$' <<<"$out" && ! grep -q jwks "$WORK/curl.log"; } \
        || bad="$bad no-client-id(rc=$rc,$out)"
    if [ -z "$bad" ]; then
        pass "ob-builder: no usable JWKS stops a required build; prefer, off or no client_id give artefacts with off"
    else
        fail "ob-builder: JWKS fetch failure handling" "$bad"
    fi
}

test_builder_mode_option() {
    local cfg="$WORK/mode.yml" out bad="" rc
    printf 'not-a-real-keyring\n' > "$WORK/keyring.gpg"
    cat > "$cfg" <<'YML'
deployment_slug: demo
scenario: token-only
portal_url: https://sso.example.com
client_id: pam-access
client_secret_mode: none
server_group: prod
target_role: bastion
response_signing: required
YML
    # yq when installed, the awk parser otherwise: both read the key.
    out=$(with_builder eval 'load_config "'"$cfg"'" >/dev/null 2>&1; echo "$RESPONSE_SIGNING"')
    [ "$out" = "required" ] || bad="$bad yaml:$out"
    out=$(with_builder eval 'RESPONSE_SIGNING_SET=0; parse_args --response-signing off; load_config "'"$cfg"'" >/dev/null 2>&1; echo "$RESPONSE_SIGNING"')
    [ "$out" = "off" ] || bad="$bad cli-wins:$out"
    rc=0
    with_builder eval 'load_config "'"$cfg"'" >/dev/null 2>&1; RESPONSE_SIGNING=sometimes; REPO_KEYRING="$WORK/keyring.gpg"; validate_inputs' >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 0 ] || bad="$bad invalid-accepted"
    rc=0
    with_builder eval 'load_config "'"$cfg"'" >/dev/null 2>&1; CLIENT_ID=""; REPO_KEYRING="$WORK/keyring.gpg"; validate_inputs' >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 0 ] || bad="$bad required-without-client-id-accepted"
    out=$(with_builder eval 'load_config "'"$cfg"'" >/dev/null 2>&1; RESPONSE_SIGNING=""; REPO_KEYRING="$WORK/keyring.gpg"; validate_inputs >/dev/null 2>&1; echo "$RESPONSE_SIGNING"' 2>/dev/null)
    [ "$out" = "prefer" ] || bad="$bad default:$out"
    out=$(with_builder eval 'load_config "'"$cfg"'" >/dev/null 2>&1; REPO_KEYRING="$WORK/keyring.gpg"; validate_inputs >/dev/null 2>&1; TARGET_ROLES=(bastion); BUILD_DATE=now; render_config_yaml x.yml')
    grep -q '^response_signing: "required"$' <<<"$out" || bad="$bad not-saved"
    grep -q -- '--response-signing MODE' <<<"$(bash "$BUILDER" --help 2>&1)" || bad="$bad not-in-help"
    if [ -z "$bad" ]; then
        pass "ob-builder: --response-signing / response_signing: (CLI wins, default prefer, validated, saved)"
    else
        fail "ob-builder: response_signing option" "$bad"
    fi
}

# Render one role's artefacts from a WORK_DIR holding a JWKS fetched for
# $1 (client_id), with RESPONSE_SIGNING=$2, into $WORK/art-$3.
render_artefacts() {
    local jwks_client="$1" mode="$2" tag="$3" role="${4:-bastion}"
    rm -rf "$WORK/art-$tag"; mkdir -p "$WORK/art-$tag/wd"
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake ca\n' \
        > "$WORK/art-$tag/wd/ca.pub"
    : > "$WORK/art-$tag/wd/krl"
    printf 'not-a-real-keyring\n' > "$WORK/art-$tag/keyring.gpg"
    if [ -n "$jwks_client" ]; then
        printf '%s' "$JWKS_GOOD" | jq -S -c . > "$WORK/art-$tag/wd/jwks.json"
    fi
    with_builder eval '
        log_step() { :; }; log_info() { :; }
        DEPLOYMENT_SLUG=demo; SCENARIO=token-only; PAM_MODE=A
        PORTAL_URL=https://sso.example.com; CLIENT_ID=pam-access
        CLIENT_ID_POLICY=modifiable; CLIENT_SECRET_MODE=none; EMBEDDED_CLIENT_SECRET=""
        SERVER_GROUP=prod; SERVER_GROUP_POLICY=modifiable; ALLOWED_BASTIONS=""
        AUTO_ENROLL_SETUP=yes; SELF_DELETE=no; ENABLE_HARDENING=no; ENABLE_AUDIT_TRACE=no
        DISABLE_SESSION_RECORDER=no; ANSIBLE_AUTO_APPROVE=no; SERVICE_ACCOUNTS_RECORDS=()
        REPO_KEYRING="$WORK/art-'"$tag"'/keyring.gpg"; WORK_DIR="$WORK/art-'"$tag"'/wd"
        SSO_CA_FINGERPRINT=SHA256:fake; SSO_JWKS_CLIENT_ID="'"$jwks_client"'"
        RESPONSE_SIGNING='"$mode"'; BUILD_DATE=now; DRY_RUN=0; INSECURE=0; SIGN_WITH=""
        TARGET_ROLES=('"$role"'); TARGET_ROLE='"$role"'
        render_shell_installer "$WORK/art-'"$tag"'/install.sh" '"$role"'
        render_ansible_role "$WORK/art-'"$tag"'/role" '"$role"'
    ' >/dev/null 2>&1
}

# Load the generated installer's functions (without running main) and run "$@".
with_installer() {
    local inst="$1"
    shift
    (
        eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$inst")"
        chown() { :; }
        SSO_JWKS_FILE="$WORK/inst-jwks/sso-jwks.json"
        rm -rf "$WORK/inst-jwks"; mkdir -p "$WORK/inst-jwks"
        CLIENT_ID=pam-access; SERVER_GROUP=prod; PORTAL_URL=https://sso.example.com
        "$@"
    )
}

test_installer_embeds_jwks() {
    local bad="" out rc inst="$WORK/art-emb/install.sh"
    render_artefacts pam-access prefer emb
    [ -f "$inst" ] || { fail "installer: not rendered"; return; }
    bash -n "$inst" || bad="$bad syntax"
    grep -qx "SSO_JWKS_SHA256=\"$JWKS_GOOD_FP\"" "$inst" || bad="$bad no-sha"
    grep -qx 'SSO_JWKS_CLIENT_ID="pam-access"' "$inst" || bad="$bad no-client"
    grep -qx 'RESPONSE_SIGNING_DEFAULT="prefer"' "$inst" || bad="$bad no-mode"
    grep -qx 'response_signing = ##RESPONSE_SIGNING##' "$inst" || bad="$bad conf-no-mode"
    grep -qx 'sso_jwks_file = /var/lib/open-bastion/jwks/sso-jwks.json' "$inst" || bad="$bad conf-no-file"
    # (@@VAR@@ is the installer's own comment about the syntax.)
    grep -o '@@[A-Z_]*@@' "$inst" | grep -vqx '@@VAR@@' && bad="$bad unresolved-placeholder"
    # Written from the embedded copy, byte for byte, 0644, regular file.
    out=$(with_installer "$inst" eval 'resolve_response_signing; write_sso_jwks >/dev/null; echo "$RESPONSE_SIGNING_EFFECTIVE"') || bad="$bad write-failed"
    [ "$out" = "prefer" ] || bad="$bad effective:$out"
    [ "$(sha256sum "$WORK/inst-jwks/sso-jwks.json" 2>/dev/null | awk '{print $1}')" = "$JWKS_GOOD_FP" ] \
        || bad="$bad content"
    [ "$(stat -c '%a %F' "$WORK/inst-jwks/sso-jwks.json" 2>/dev/null)" = "644 regular file" ] \
        || bad="$bad mode:$(stat -c '%a %F' "$WORK/inst-jwks/sso-jwks.json" 2>/dev/null)"
    # The setup run gets the mode, the file and its fingerprint.
    out=$(with_installer "$inst" eval 'resolve_response_signing; OPT_DRY_RUN=true; step_setup' 2>&1)
    grep -q -- "--response-signing prefer --sso-jwks $WORK/inst-jwks/sso-jwks.json --sso-jwks-sha256 $JWKS_GOOD_FP" <<<"$out" \
        || bad="$bad setup-args:$(grep 'Would run' <<<"$out")"
    # Tampered: refused before anything is written.
    sed "s|^$(base64 -w0 < "$WORK/art-emb/wd/jwks.json")\$|$(printf '%s' "$JWKS_OTHER" | jq -S -c . | base64 -w0)|" \
        "$inst" > "$WORK/tampered.sh"
    rc=0
    with_installer "$WORK/tampered.sh" eval 'resolve_response_signing; write_sso_jwks' >/dev/null 2>&1 || rc=$?
    { [ "$rc" -ne 0 ] && [ ! -e "$WORK/inst-jwks/sso-jwks.json" ]; } || bad="$bad tampered-accepted(rc=$rc)"
    if [ -z "$bad" ]; then
        pass "installer: embeds the JWKS, writes it 0644 after checking its SHA-256, hands it to setup"
    else
        fail "installer: JWKS embedding" "$bad"
    fi
}

test_installer_other_client_id() {
    local bad="" out rc inst="$WORK/art-emb/install.sh"
    [ -f "$inst" ] || render_artefacts pam-access prefer emb
    out=$(with_installer "$inst" eval 'CLIENT_ID=other; resolve_response_signing 2>/dev/null; write_sso_jwks; echo "$RESPONSE_SIGNING_EFFECTIVE"; OPT_DRY_RUN=true; step_setup 2>&1')
    grep -qx off <<<"$out" || bad="$bad not-off"
    [ -e "$WORK/inst-jwks/sso-jwks.json" ] && bad="$bad written"
    grep -q -- '--response-signing off' <<<"$out" || bad="$bad setup-not-off"
    grep -q -- '--sso-jwks ' <<<"$out" && bad="$bad setup-got-jwks"
    rc=0
    with_installer "$inst" eval 'CLIENT_ID=other; OPT_RESPONSE_SIGNING=required; resolve_response_signing' >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 0 ] || bad="$bad required-accepted"
    render_artefacts "" prefer none
    out=$(with_installer "$WORK/art-none/install.sh" eval 'resolve_response_signing 2>/dev/null; echo "$RESPONSE_SIGNING_EFFECTIVE"')
    [ "$out" = "off" ] || bad="$bad no-jwks:$out"
    grep -qx 'RESPONSE_SIGNING_DEFAULT="off"' "$WORK/art-none/install.sh" || bad="$bad no-jwks-default"
    if [ -z "$bad" ]; then
        pass "installer: another client_id or no JWKS gives off (required is refused), never a foreign JWKS"
    else
        fail "installer: foreign/no JWKS" "$bad"
    fi
}

test_ansible_role_jwks() {
    local bad="" r="$WORK/art-emb/role/roles/open-bastion-bastion" f t
    [ -d "$r" ] || render_artefacts pam-access prefer emb
    cmp -s "$r/files/sso-jwks.json" "$WORK/art-emb/wd/jwks.json" || bad="$bad files/sso-jwks.json"
    [ -e "$r/files/jwks.json" ] && bad="$bad old-name"
    grep -qx 'ob_response_signing: "prefer"' "$r/defaults/main.yml" || bad="$bad default-mode"
    grep -qx 'ob_sso_jwks_src: "sso-jwks.json"' "$r/defaults/main.yml" || bad="$bad default-src"
    grep -qx "ob_sso_jwks_sha256: \"$JWKS_GOOD_FP\"" "$r/defaults/main.yml" || bad="$bad default-sha"
    grep -qx 'ob_sso_jwks_client_id: "pam-access"' "$r/defaults/main.yml" || bad="$bad default-client"
    grep -qx 'ob_sso_jwks_file: /var/lib/open-bastion/jwks/sso-jwks.json' "$r/defaults/main.yml" || bad="$bad default-file"
    # The deploy task: root:root 0644, to the configured path, before the conf.
    awk '/name: Deploy the portal.s JWKS/,/^$/' "$r/tasks/main.yml" > "$WORK/task.txt"
    grep -q 'src: "{{ ob_sso_jwks_src }}"' "$WORK/task.txt" || bad="$bad task-src"
    grep -q 'dest: "{{ ob_sso_jwks_file }}"' "$WORK/task.txt" || bad="$bad task-dest"
    grep -q "owner: root" "$WORK/task.txt" && grep -q "group: root" "$WORK/task.txt" \
        && grep -q "mode: '0644'" "$WORK/task.txt" || bad="$bad task-perms"
    [ "$(grep -n "Deploy the portal.s JWKS" "$r/tasks/main.yml" | cut -d: -f1)" -lt \
      "$(grep -n "name: Deploy openbastion.conf" "$r/tasks/main.yml" | cut -d: -f1)" ] || bad="$bad task-order"
    grep -q "name: Check the signed-answers settings" "$r/tasks/main.yml" || bad="$bad no-assert"
    # One tree per role: each carries only its own tasks/<role>.yml.
    for f in bastion backend standalone; do
        t="$WORK/art-emb/role/roles/open-bastion-$f/tasks/$f.yml"
        [ "$f" = bastion ] || { [ -f "$t" ] || render_artefacts pam-access prefer "emb-$f" "$f"; t="$WORK/art-emb-$f/role/roles/open-bastion-$f/tasks/$f.yml"; }
        grep -q "'--response-signing', ob_response_signing" "$t" || bad="$bad $f-mode"
        grep -q "'--sso-jwks', ob_sso_jwks_file" "$t" || bad="$bad $f-jwks"
        grep -q "'--sso-jwks-sha256', ob_sso_jwks_sha256" "$t" || bad="$bad $f-sha"
    done
    grep -q "^response_signing = {{ ob_response_signing" "$r/templates/openbastion.conf.j2" || bad="$bad j2-mode"
    grep -q "^sso_jwks_file = {{ ob_sso_jwks_file" "$r/templates/openbastion.conf.j2" || bad="$bad j2-file"
    grep -q 'ob_bastion_jwt' "$r/README.md" && bad="$bad stale-jwt-vars-in-readme"
    # No JWKS: off, nothing to copy.
    [ -d "$WORK/art-none/role" ] || render_artefacts "" prefer none
    grep -qx 'ob_response_signing: "off"' "$WORK/art-none/role/roles/open-bastion-bastion/defaults/main.yml" || bad="$bad none-mode"
    grep -qx 'ob_sso_jwks_src: ""' "$WORK/art-none/role/roles/open-bastion-bastion/defaults/main.yml" || bad="$bad none-src"
    [ -e "$WORK/art-none/role/roles/open-bastion-bastion/files/sso-jwks.json" ] && bad="$bad none-file"
    if [ -z "$bad" ]; then
        pass "ansible: role ships files/sso-jwks.json, deploys it root:root 0644 and passes it to setup"
    else
        fail "ansible: JWKS in the role" "$bad"
    fi
}

# With ansible installed: render openbastion.conf.j2 and run the assertion.
test_ansible_runtime() {
    command -v ansible-playbook >/dev/null 2>&1 || { pass "ansible: runtime checks (SKIP: ansible-playbook not installed)"; return; }
    command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null \
        || { pass "ansible: runtime checks (SKIP: python3-yaml not installed)"; return; }
    local d="$WORK/art-emb/role" bad="" out
    [ -d "$d" ] || render_artefacts pam-access prefer emb
    printf 'all:\n  hosts:\n    localhost:\n      ansible_connection: local\n' > "$d/inv.yml"
    python3 - "$d" <<'PY'
import sys, yaml
d = sys.argv[1]
tasks = yaml.safe_load(open(d + '/roles/open-bastion-bastion/tasks/main.yml'))
check = [t for t in tasks if t.get('name') == 'Check the signed-answers settings'][0]
render = {'name': 'render', 'ansible.builtin.template': {
    'src': d + '/roles/open-bastion-bastion/templates/openbastion.conf.j2', 'dest': d + '/rendered.conf'}}
# The inventory declares ob_role since a tree only configures its own hosts.
pb = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
       'vars': {'ob_role': 'bastion'},
       'vars_files': [d + '/roles/open-bastion-bastion/defaults/main.yml'], 'tasks': [check, render]}]
yaml.safe_dump(pb, open(d + '/check.yml', 'w'))
PY
    out=$(ANSIBLE_NOCOLOR=1 ansible-playbook -i "$d/inv.yml" "$d/check.yml" 2>&1) || bad="$bad default-failed"
    grep -qx 'response_signing = prefer' "$d/rendered.conf" 2>/dev/null || bad="$bad rendered-mode"
    grep -qx 'sso_jwks_file = /var/lib/open-bastion/jwks/sso-jwks.json' "$d/rendered.conf" 2>/dev/null || bad="$bad rendered-file"
    ANSIBLE_NOCOLOR=1 ansible-playbook -i "$d/inv.yml" "$d/check.yml" -e ob_client_id=other >/dev/null 2>&1 \
        && bad="$bad other-client-accepted"
    ANSIBLE_NOCOLOR=1 ansible-playbook -i "$d/inv.yml" "$d/check.yml" -e "ob_client_id=other ob_response_signing=off" >/dev/null 2>&1 \
        || bad="$bad off-refused"
    grep -qx 'response_signing = off' "$d/rendered.conf" 2>/dev/null || bad="$bad rendered-off"
    grep -q '^sso_jwks_file' "$d/rendered.conf" 2>/dev/null && bad="$bad off-names-file"
    if [ -z "$bad" ]; then
        pass "ansible: the template and the client_id/JWKS assertion behave"
    else
        fail "ansible: runtime checks" "$bad"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# The setup script (every role)
# ═════════════════════════════════════════════════════════════════════════════

# Run "$@" with the setup script loaded as NAME, paths under $WORK/host, and the
# portal answering /oauth2/jwks with $PORTAL_JWKS (empty = failure).
with_setup() {
    local name="$1"
    shift
    (
        load_setup_as "$name" || exit 99
        chown() { :; }
        curl() {
            local out="" url=""
            while [ $# -gt 0 ]; do
                case "$1" in
                    -o) out="$2"; shift 2 ;;
                    --connect-timeout) shift 2 ;;
                    -*) shift ;;
                    *) url="$1"; shift ;;
                esac
            done
            printf '%s\n' "$url" >> "$WORK/curl.log"
            [ -n "${PORTAL_JWKS:-}" ] || return 22
            printf '%s' "$PORTAL_JWKS" > "$out"
        }
        SSO_JWKS_FILE="$WORK/host/sso-jwks.json"
        # The shape filter alone, unless a test names a helper.
        OB_VERIFY_RESPONSE="${TEST_VERIFY_RESPONSE:-}"
        OB_CONFIG="$WORK/host/openbastion.conf"
        NSS_OB_CONF="$WORK/host/nss_openbastion.conf"
        BACKUP_DIR="$WORK/host/backup"
        PORTAL_URL="https://sso.example.com"; SERVER_GROUP=prod; CLIENT_ID=pam-access
        OB_TOKEN=/var/lib/open-bastion/token
        "$@"
    )
}

reset_host() {
    rm -rf "$WORK/host"; mkdir -p "$WORK/host"; : > "$WORK/curl.log"
}

# Prints "rc effective result" after install_sso_jwks with the given args.
install_with() {
    local name="$1"
    shift
    with_setup "$name" eval 'parse_args -p https://sso.example.com '"$*"' >/dev/null || exit 98
        PORTAL_URL=https://sso.example.com
        install_sso_jwks >"$WORK/install.log" 2>&1; rc=$?
        echo "$rc $RESPONSE_SIGNING_EFFECTIVE $SSO_JWKS_RESULT"' </dev/null
}

test_setup_options() {
    local bad="" out
    with_setup ob-bastion-setup eval 'parse_args -p https://x --response-signing sometimes' >/dev/null 2>&1 \
        && bad="$bad bad-mode"
    with_setup ob-bastion-setup eval 'parse_args -p https://x --sso-jwks /nonexistent' >/dev/null 2>&1 \
        && bad="$bad missing-file"
    with_setup ob-bastion-setup eval 'parse_args -p https://x --sso-jwks-sha256 1234' >/dev/null 2>&1 \
        && bad="$bad short-sha"
    out=$(with_setup ob-bastion-setup eval 'parse_args -p https://x --sso-jwks-sha256 "SHA256:'"$(tr 'a-f' 'A-F' <<<"${JWKS_GOOD_FP:0:2}")"':'"${JWKS_GOOD_FP:2}"'"; echo "$SSO_JWKS_SHA256"')
    [ "$out" = "$JWKS_GOOD_FP" ] || bad="$bad normalize:$out"
    out=$(with_setup ob-backend-setup eval 'parse_args -p https://x --response-signing required; echo "$RESPONSE_SIGNING"')
    [ "$out" = "required" ] || bad="$bad mode:$out"
    for out in "$(bash "$(setup_command ob-bastion-setup)" --help 2>&1)" \
               "$(bash "$(setup_command ob-backend-setup)" --help 2>&1)"; do
        grep -q -- '--sso-jwks-sha256 HEX' <<<"$out" && grep -q -- '--response-signing MODE' <<<"$out" \
            || bad="$bad help"
    done
    # An allowlist-only update contacts no portal: these options need the full setup.
    with_setup ob-backend-setup eval 'parse_args --allowed-bastions b1 --response-signing off
        [[ " ${SETUP_OPTS_GIVEN[*]} " == *" --response-signing "* ]]' >/dev/null 2>&1 || bad="$bad allowlist-only"
    if [ -z "$bad" ]; then
        pass "setup: --response-signing, --sso-jwks and --sso-jwks-sha256 are parsed and checked"
    else
        fail "setup: JWKS options" "$bad"
    fi
}

test_setup_explicit_file() {
    local bad="" out name
    printf '%s' "$JWKS_GOOD" > "$WORK/given.json"
    for name in ob-bastion-setup ob-standalone-setup ob-backend-setup; do
        reset_host
        out=$(install_with "$name" --sso-jwks "$WORK/given.json" --yes)
        [ "$out" = "0 prefer installed" ] || bad="$bad [$name:$out]"
        [ "$(stat -c '%a %F' "$WORK/host/sso-jwks.json" 2>/dev/null)" = "644 regular file" ] || bad="$bad [$name:perms]"
        [ "$(sha256sum < "$WORK/host/sso-jwks.json" | awk '{print $1}')" = "$JWKS_GOOD_FP" ] || bad="$bad [$name:not-canonical]"
        [ -s "$WORK/curl.log" ] && bad="$bad [$name:fetched]"
    done
    # A symlink planted at the path is replaced, not written through.
    reset_host
    : > "$WORK/victim"
    ln -s "$WORK/victim" "$WORK/host/sso-jwks.json"
    out=$(install_with ob-bastion-setup --sso-jwks "$WORK/given.json" --yes)
    { [ ! -L "$WORK/host/sso-jwks.json" ] && [ ! -s "$WORK/victim" ]; } || bad="$bad symlink-followed"
    # The installer passes the file it wrote itself: source = destination.
    reset_host
    printf '%s' "$JWKS_GOOD" | jq -S -c . > "$WORK/host/sso-jwks.json"
    out=$(install_with ob-bastion-setup --sso-jwks "$WORK/host/sso-jwks.json" --sso-jwks-sha256 "$JWKS_GOOD_FP" --yes)
    { [ "$out" = "0 prefer installed" ] \
      && [ "$(sha256sum < "$WORK/host/sso-jwks.json" | awk '{print $1}')" = "$JWKS_GOOD_FP" ]; } \
        || bad="$bad same-path:$out"
    # Matching / mismatching fingerprint.
    reset_host
    out=$(install_with ob-bastion-setup --sso-jwks "$WORK/given.json" --sso-jwks-sha256 "$JWKS_GOOD_FP" --yes)
    [ "$out" = "0 prefer installed" ] || bad="$bad sha-match:$out"
    reset_host
    out=$(install_with ob-bastion-setup --sso-jwks "$WORK/given.json" --sso-jwks-sha256 "$JWKS_OTHER_FP" --yes)
    { [ "${out%% *}" != 0 ] && [ ! -e "$WORK/host/sso-jwks.json" ] && grep -q 'mismatch' "$WORK/install.log"; } \
        || bad="$bad sha-mismatch-accepted:$out"
    if [ -z "$bad" ]; then
        pass "setup (every role): --sso-jwks installs the canonical JWKS, root:root 0644, atomically; a wrong SHA-256 is refused"
    else
        fail "setup: --sso-jwks" "$bad"
    fi
}

test_setup_invalid_file() {
    local bad="" j out
    for j in "${BAD_JWKS[@]}"; do
        reset_host
        printf '%s' "$j" > "$WORK/bad.json"
        out=$(install_with ob-bastion-setup --sso-jwks "$WORK/bad.json" --yes)
        { [ "${out%% *}" != 0 ] && [ ! -e "$WORK/host/sso-jwks.json" ]; } || bad="$bad [$j:$out]"
    done
    if [ -z "$bad" ]; then
        pass "setup: --sso-jwks with a JWKS the verifier cannot use is refused (${#BAD_JWKS[@]} shapes)"
    else
        fail "setup: unusable --sso-jwks accepted" "$bad"
    fi
}

test_setup_fetch_fingerprint() {
    local bad="" out
    reset_host
    out=$(PORTAL_JWKS="$JWKS_GOOD" install_with ob-backend-setup --sso-jwks-sha256 "$JWKS_GOOD_FP" --yes)
    [ "$out" = "0 prefer installed" ] || bad="$bad match:$out"
    grep -qx 'https://sso.example.com/oauth2/jwks?client_id=pam-access' "$WORK/curl.log" || bad="$bad url:$(cat "$WORK/curl.log")"
    reset_host
    out=$(PORTAL_JWKS="$JWKS_OTHER" install_with ob-backend-setup --sso-jwks-sha256 "$JWKS_GOOD_FP" --yes)
    { [ "${out%% *}" != 0 ] && [ ! -e "$WORK/host/sso-jwks.json" ] && grep -q 'fingerprint mismatch' "$WORK/install.log"; } \
        || bad="$bad mismatch-accepted:$out"
    # Even under prefer: a fingerprint given and not matched is not "no JWKS".
    if [ -z "$bad" ]; then
        pass "setup: a fetched JWKS is installed only when it matches --sso-jwks-sha256; a mismatch aborts"
    else
        fail "setup: fetch with fingerprint" "$bad"
    fi
}

test_setup_fallback_off() {
    local bad="" out
    # --yes without a JWKS or a fingerprint: nobody can vouch for a fetch.
    reset_host
    out=$(PORTAL_JWKS="$JWKS_GOOD" install_with ob-bastion-setup --yes)
    [ "$out" = "0 off unavailable" ] || bad="$bad yes:$out"
    [ -s "$WORK/curl.log" ] && bad="$bad yes-fetched"
    [ -e "$WORK/host/sso-jwks.json" ] && bad="$bad yes-written"
    grep -q 'writing response_signing = off' "$WORK/install.log" || bad="$bad no-warning"
    # Portal down or not a JWKS.
    reset_host
    out=$(PORTAL_JWKS="" install_with ob-bastion-setup)
    [ "$out" = "0 off unavailable" ] || bad="$bad down:$out"
    reset_host
    out=$(PORTAL_JWKS='{"keys":[]}' install_with ob-bastion-setup)
    [ "$out" = "0 off unavailable" ] || bad="$bad invalid:$out"
    # required is never silently downgraded.
    reset_host
    out=$(PORTAL_JWKS="$JWKS_GOOD" install_with ob-bastion-setup --yes --response-signing required)
    [ "${out%% *}" != 0 ] || bad="$bad required-downgraded:$out"
    # off asks for nothing.
    reset_host
    out=$(PORTAL_JWKS="$JWKS_GOOD" install_with ob-bastion-setup --response-signing off)
    [ "$out" = "0 off off" ] || bad="$bad off:$out"
    [ -s "$WORK/curl.log" ] && bad="$bad off-fetched"
    if [ -z "$bad" ]; then
        pass "setup: no JWKS -> response_signing = off with a warning (required refused); off fetches nothing"
    else
        fail "setup: fallback to off" "$bad"
    fi
}

test_setup_interactive() {
    local bad="" out
    reset_host
    out=$(PORTAL_JWKS="$JWKS_GOOD" with_setup ob-bastion-setup eval 'parse_args -p https://sso.example.com >/dev/null
        install_sso_jwks >"$WORK/install.log" 2>&1 <<<"y"; echo "$? $RESPONSE_SIGNING_EFFECTIVE $SSO_JWKS_RESULT"')
    [ "$out" = "0 prefer installed" ] || bad="$bad yes:$out"
    grep -q "SHA-256: $JWKS_GOOD_FP" "$WORK/install.log" || bad="$bad fp-not-shown"
    grep -q "kid=k1" "$WORK/install.log" || bad="$bad keys-not-shown"
    reset_host
    out=$(PORTAL_JWKS="$JWKS_GOOD" with_setup ob-bastion-setup eval 'parse_args -p https://sso.example.com >/dev/null
        install_sso_jwks >"$WORK/install.log" 2>&1 <<<""; echo "$? $RESPONSE_SIGNING_EFFECTIVE $SSO_JWKS_RESULT"')
    [ "$out" = "0 off declined" ] || bad="$bad default-no:$out"
    [ -e "$WORK/host/sso-jwks.json" ] && bad="$bad declined-written"
    if [ -z "$bad" ]; then
        pass "setup: by hand, a fetched JWKS is shown with its SHA-256 and installed only on an explicit yes"
    else
        fail "setup: interactive confirmation" "$bad"
    fi
}

test_setup_keeps_existing() {
    local bad="" out
    # A JWKS already on the host (perhaps rotated by the signed heartbeat) is
    # kept: a TLS-only refetch must not replace it.
    reset_host
    printf '%s' "$JWKS_GOOD" | jq -S -c . > "$WORK/host/sso-jwks.json"
    chmod 0644 "$WORK/host/sso-jwks.json"
    out=$(PORTAL_JWKS="$JWKS_OTHER" install_with ob-bastion-setup --yes)
    [ "$out" = "0 prefer kept" ] || bad="$bad kept:$out"
    [ -s "$WORK/curl.log" ] && bad="$bad fetched"
    # Not when the modules would refuse it: group-writable is no trust anchor.
    chmod 0664 "$WORK/host/sso-jwks.json"
    : > "$WORK/curl.log"
    out=$(PORTAL_JWKS="$JWKS_GOOD" install_with ob-bastion-setup --sso-jwks-sha256 "$JWKS_GOOD_FP" --yes)
    [ "$out" = "0 prefer installed" ] || bad="$bad unsafe-kept:$out"
    [ "$(stat -c '%a' "$WORK/host/sso-jwks.json")" = 644 ] || bad="$bad unsafe-perms"
    if [ -z "$bad" ]; then
        pass "setup: a usable JWKS already on the host is kept, an unsafe one is replaced"
    else
        fail "setup: existing JWKS" "$bad"
    fi
}

test_setup_conf_keys() {
    local bad="" out name
    for name in ob-bastion-setup ob-standalone-setup ob-backend-setup; do
        reset_host
        out=$(with_setup "$name" eval 'RESPONSE_SIGNING_EFFECTIVE=prefer; render_openbastion_settings')
        grep -qx 'response_signing = prefer' <<<"$out" || bad="$bad [$name:ob-mode]"
        grep -qx "sso_jwks_file = $WORK/host/sso-jwks.json" <<<"$out" || bad="$bad [$name:ob-file]"
        out=$(with_setup "$name" eval 'ob_nss_force_shell_block() { :; }; RESPONSE_SIGNING_EFFECTIVE=prefer; render_nss_conf')
        grep -qx 'response_signing = prefer' <<<"$out" || bad="$bad [$name:nss-mode]"
        grep -qx 'client_id = pam-access' <<<"$out" || bad="$bad [$name:nss-client]"
        grep -qx "sso_jwks_file = $WORK/host/sso-jwks.json" <<<"$out" || bad="$bad [$name:nss-file]"
    done
    # off: the mode is written, no file named.
    out=$(with_setup ob-bastion-setup eval 'RESPONSE_SIGNING_EFFECTIVE=off; render_openbastion_settings; ob_nss_force_shell_block() { :; }; render_nss_conf')
    [ "$(grep -cx 'response_signing = off' <<<"$out")" = 2 ] || bad="$bad off-mode"
    grep -q '^sso_jwks_file' <<<"$out" && bad="$bad off-names-file"
    # Rewritten wholesale: an operator's sso_issuer survives, and so does the
    # mode they switched to (a re-run must not turn required back into prefer).
    reset_host
    printf 'portal_url = https://x\nresponse_signing = required\nsso_issuer = https://issuer.example\n# sso_issuer = https://commented\n' \
        > "$WORK/host/openbastion.conf"
    printf 'sso_issuer = https://nss-issuer.example\n' > "$WORK/host/nss_openbastion.conf"
    out=$(with_setup ob-bastion-setup eval 'resolve_response_signing >/dev/null; echo "MODE=$RESPONSE_SIGNING"
        RESPONSE_SIGNING_EFFECTIVE=required; render_openbastion_settings
        ob_nss_force_shell_block() { :; }; render_nss_conf')
    grep -qx 'MODE=required' <<<"$out" || bad="$bad mode-not-kept"
    grep -qx 'sso_issuer = https://issuer.example' <<<"$out" || bad="$bad issuer-not-kept"
    grep -qx 'sso_issuer = https://nss-issuer.example' <<<"$out" || bad="$bad nss-issuer-not-kept"
    out=$(with_setup ob-bastion-setup eval 'parse_args -p https://x --response-signing off >/dev/null; resolve_response_signing; echo "$RESPONSE_SIGNING"')
    [ "$out" = off ] || bad="$bad option-not-winning:$out"
    if [ -z "$bad" ]; then
        pass "setup (every role): openbastion.conf and nss_openbastion.conf get response_signing, sso_jwks_file, client_id; sso_issuer and the mode survive a re-run"
    else
        fail "setup: configuration keys" "$bad"
    fi
}

test_setup_dry_run() {
    local bad="" out
    reset_host
    printf '%s' "$JWKS_GOOD" > "$WORK/given.json"
    out=$(install_with ob-bastion-setup --sso-jwks "$WORK/given.json" --dry-run --yes)
    [ "$out" = "0 prefer dry-run" ] || bad="$bad given:$out"
    reset_host
    out=$(PORTAL_JWKS="$JWKS_GOOD" install_with ob-bastion-setup --sso-jwks-sha256 "$JWKS_GOOD_FP" --dry-run --yes)
    [ "$out" = "0 prefer dry-run" ] || bad="$bad fetched:$out"
    [ -n "$(ls -A "$WORK/host")" ] && bad="$bad wrote:$(ls -A "$WORK/host")"
    if [ -z "$bad" ]; then
        pass "setup: --dry-run validates the JWKS and writes nothing"
    else
        fail "setup: dry-run" "$bad"
    fi
}

# The C verifier has the last word when ob-verify-response is installed: a
# JWKS of the right shape it cannot load (a point off the curve...) is refused.
test_setup_uses_verifier() {
    local bad="" out vr
    printf '%s' "$JWKS_GOOD" > "$WORK/given.json"
    printf '#!/bin/sh\n[ "$1 $2" = "check-jwks --quiet" ] && [ -f "$3" ] && exit %s; exit 2\n' 1 > "$WORK/vr-no"
    printf '#!/bin/sh\n[ "$1 $2" = "check-jwks --quiet" ] && [ -f "$3" ] && exit %s; exit 2\n' 0 > "$WORK/vr-yes"
    chmod +x "$WORK/vr-no" "$WORK/vr-yes"
    reset_host
    out=$(TEST_VERIFY_RESPONSE="$WORK/vr-no" install_with ob-bastion-setup --sso-jwks "$WORK/given.json" --yes)
    [ "${out%% *}" != 0 ] || bad="$bad refused-by-verifier-accepted:$out"
    reset_host
    out=$(TEST_VERIFY_RESPONSE="$WORK/vr-yes" install_with ob-bastion-setup --sso-jwks "$WORK/given.json" --yes)
    [ "$out" = "0 prefer installed" ] || bad="$bad accepted-by-verifier-refused:$out"
    # The real one, when built: the Ed25519 key loads; an EC point off the curve does not.
    vr="${OB_BUILD_DIR:-$ROOT_DIR/build}/ob-verify-response"
    if [ -x "$vr" ] && "$vr" check-jwks --quiet "$WORK/given.json" >/dev/null 2>&1; then
        reset_host
        out=$(TEST_VERIFY_RESPONSE="$vr" install_with ob-bastion-setup --sso-jwks "$WORK/given.json" --yes)
        [ "$out" = "0 prefer installed" ] || bad="$bad real-good:$out"
        printf '%s' '{"keys":[{"kty":"EC","crv":"P-256","kid":"off","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}]}' \
            > "$WORK/offcurve.json"
        reset_host
        out=$(TEST_VERIFY_RESPONSE="$vr" install_with ob-bastion-setup --sso-jwks "$WORK/offcurve.json" --yes)
        [ "${out%% *}" != 0 ] || bad="$bad real-offcurve-accepted:$out"
    fi
    if [ -z "$bad" ]; then
        pass "setup: ob-verify-response check-jwks has the last word on a JWKS when installed"
    else
        fail "setup: verifier check" "$bad"
    fi
}

# main() puts the JWKS in place in phase 1 (rolled back on failure), before the
# configuration that names it, and needs jq and sha256sum.
test_setup_main_wiring() {
    local bad="" body
    body=$(sed -n '/^main() {/,/^}/p' "$SETUP_SCRIPT")
    local l_ca l_jwks l_conf
    l_ca=$(grep -n 'download_ca_key ||' <<<"$body" | cut -d: -f1)
    l_jwks=$(grep -n 'install_sso_jwks || { rollback_on_failure; exit 1; }' <<<"$body" | cut -d: -f1)
    l_conf=$(grep -n 'configure_pam_openbastion ||' <<<"$body" | cut -d: -f1)
    { [ -n "$l_jwks" ] && [ "$l_ca" -lt "$l_jwks" ] && [ "$l_jwks" -lt "$l_conf" ]; } || bad="$bad order"
    grep -q 'for cmd in curl sshd sed jq sha256sum; do' <<<"$body" || bad="$bad commands"
    # The installer hands the embedded copy over rather than letting setup refetch.
    grep -q 'add_signing_setup_opts' "$ROOT_DIR/admin-builder/templates/shell/installer.sh.in" || bad="$bad installer"
    # Both filters stay the same text.
    local f1 f2
    f1=$(sed -n "/^SSO_JWKS_FILTER='/,/)'\$/p" "$ROOT_DIR/admin-builder/lib/sso-discovery.sh" | sed '1s/^SSO_JWKS_FILTER=//')
    f2=$(sed -n "/^OB_JWKS_FILTER='/,/)'\$/p" "$SETUP_SCRIPT" | sed '1s/^OB_JWKS_FILTER=//')
    { [ -n "$f1" ] && [ "$f1" = "$f2" ]; } || bad="$bad filters-differ"
    if [ -z "$bad" ]; then
        pass "setup: JWKS installed in phase 1 before openbastion.conf; ob-builder and setup share one filter"
    else
        fail "setup: wiring" "$bad"
    fi
}

# The JWKS is state (ob-heartbeat rotates it), so it lives under
# /var/lib/open-bastion/jwks, root:root 0755: the package makes the directory,
# and so do the setup and the installer (which runs before the package) when it
# is missing, with /var/lib/open-bastion 0711 as the package makes it.
test_jwks_directory() {
    local bad="" out d
    printf '%s' "$JWKS_GOOD" > "$WORK/given.json"
    # Setup: parent and directory missing.
    rm -rf "$WORK/vl"; mkdir -p "$WORK/vl"; reset_host
    out=$(with_setup ob-bastion-setup eval 'SSO_JWKS_FILE="$WORK/vl/ob/jwks/sso-jwks.json"
        parse_args -p https://sso.example.com --sso-jwks "$WORK/given.json" --yes >/dev/null || exit 98
        install_sso_jwks >"$WORK/install.log" 2>&1; echo "$?"' </dev/null)
    [ "$out" = 0 ] || bad="$bad setup-rc:$out"
    [ "$(stat -c '%a' "$WORK/vl/ob" 2>/dev/null)" = 711 ] || bad="$bad setup-parent:$(stat -c '%a' "$WORK/vl/ob" 2>&1)"
    [ "$(stat -c '%a' "$WORK/vl/ob/jwks" 2>/dev/null)" = 755 ] || bad="$bad setup-dir"
    [ "$(stat -c '%a' "$WORK/vl/ob/jwks/sso-jwks.json" 2>/dev/null)" = 644 ] || bad="$bad setup-file"
    # Setup: an existing directory with a loose mode is put back to 0755.
    chmod 0775 "$WORK/vl/ob/jwks"
    out=$(with_setup ob-bastion-setup eval 'SSO_JWKS_FILE="$WORK/vl/ob/jwks/sso-jwks.json"
        parse_args -p https://sso.example.com --sso-jwks "$WORK/given.json" --yes >/dev/null || exit 98
        install_sso_jwks >"$WORK/install.log" 2>&1; echo "$?"' </dev/null)
    [ "$(stat -c '%a' "$WORK/vl/ob/jwks" 2>/dev/null)" = 755 ] || bad="$bad setup-dir-not-reasserted"
    # Installer, before the package.
    [ -f "$WORK/art-emb/install.sh" ] || render_artefacts pam-access prefer emb
    rm -rf "$WORK/vl"; mkdir -p "$WORK/vl"
    with_installer "$WORK/art-emb/install.sh" eval 'SSO_JWKS_FILE="$WORK/vl/ob/jwks/sso-jwks.json"
        resolve_response_signing; write_sso_jwks' >/dev/null 2>&1 || bad="$bad installer-failed"
    [ "$(stat -c '%a' "$WORK/vl/ob" 2>/dev/null)" = 711 ] || bad="$bad installer-parent"
    [ "$(stat -c '%a' "$WORK/vl/ob/jwks" 2>/dev/null)" = 755 ] || bad="$bad installer-dir"
    [ "$(sha256sum < "$WORK/vl/ob/jwks/sso-jwks.json" 2>/dev/null | awk '{print $1}')" = "$JWKS_GOOD_FP" ] \
        || bad="$bad installer-file"
    # Defaults and packaging.
    grep -qx 'SSO_JWKS_FILE="/var/lib/open-bastion/jwks/sso-jwks.json"' "$SETUP_SCRIPT" || bad="$bad setup-default"
    grep -qx 'SSO_JWKS_FILE="/var/lib/open-bastion/jwks/sso-jwks.json"' \
        "$ROOT_DIR/admin-builder/templates/shell/installer.sh.in" || bad="$bad installer-default"
    grep -qx 'var/lib/open-bastion/jwks' "$ROOT_DIR/debian/open-bastion.dirs" || bad="$bad deb-dirs"
    d=$(awk '/^%post$/{f=1; next} f && /^%(pre|preun|postun|posttrans|files|changelog)( |$)/{exit} f' \
        "$ROOT_DIR/rpm/open-bastion.spec")
    grep -qx 'mkdir -p /var/lib/open-bastion/jwks' <<<"$d" && grep -qx 'chmod 755 /var/lib/open-bastion/jwks' <<<"$d" \
        || bad="$bad rpm-post"
    grep -q 'name: Create the directory of the portal.s JWKS' \
        "$ROOT_DIR/admin-builder/templates/ansible/role/tasks/main.yml.in" || bad="$bad ansible-dir"
    # Nothing still points at the old place.
    out=$(cd "$ROOT_DIR" && grep -rln '/etc/open-bastion/sso-jwks' scripts admin-builder config doc include nss src systemd debian rpm 2>/dev/null)
    [ -z "$out" ] || bad="$bad old-path-in:$(tr '\n' ' ' <<<"$out")"
    if [ -z "$bad" ]; then
        pass "JWKS under /var/lib/open-bastion/jwks (0755, parent 0711): setup, installer, Ansible and packages make the directory"
    else
        fail "JWKS directory" "$bad"
    fi
}

echo "=== portal JWKS distribution (#339) ==="
run_test test_jwks_url
run_test test_builder_fetch_valid
run_test test_builder_fetch_invalid
run_test test_builder_fetch_every_role
run_test test_builder_fetch_failure
run_test test_builder_mode_option
run_test test_installer_embeds_jwks
run_test test_installer_other_client_id
run_test test_ansible_role_jwks
run_test test_ansible_runtime
run_test test_setup_options
run_test test_setup_explicit_file
run_test test_setup_invalid_file
run_test test_setup_fetch_fingerprint
run_test test_setup_fallback_off
run_test test_setup_interactive
run_test test_setup_keeps_existing
run_test test_setup_conf_keys
run_test test_setup_dry_run
run_test test_setup_uses_verifier
run_test test_setup_main_wiring
run_test test_jwks_directory

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
