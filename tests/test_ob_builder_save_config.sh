#!/bin/bash
#
# Test suite for ob-builder --save-config (#311): the questionnaire's answers,
# defaults included, saved as a YAML that --config replays to the same state.
#
# Sources ob-builder like the other test_ob_builder_*.sh suites (with
# `set -euo pipefail` and the `main "$@"` call stripped). The round trip runs
# through the awk parser always, and through yq when one is on the PATH.
#

# Most variables set here are read by the sourced ob-builder functions.
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

# shellcheck disable=SC1090
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
BUILD_DATE="2026-01-01T00:00:00Z"
# Sourced, $0 is this suite; the header names the command the admin runs.
PROG_NAME="ob-builder"
unset OB_BUILDER_NON_INTERACTIVE

# Scripted answers for the prompt helpers (same harness as the interactive
# suite): the queue lives in files because the prompts run inside $(...).
ANS_FILE="$TEST_TMPDIR/answers"
ANS_IDX="$TEST_TMPDIR/answers.idx"
ANS_OWNER=""
set_answers() {
    ANS_OWNER=$BASHPID
    printf '%s\n' "$@" > "$ANS_FILE"
    echo 0 > "$ANS_IDX"
}
answers_left() { echo $(( $(wc -l < "$ANS_FILE") - $(cat "$ANS_IDX") )); }
_next_answer_into() {
    local n total
    n=$(cat "$ANS_IDX"); total=$(wc -l < "$ANS_FILE")
    if [ "$n" -ge "$total" ]; then
        echo "answers exhausted" >&2
        kill -TERM "$ANS_OWNER" 2>/dev/null
        exit 1
    fi
    echo $((n + 1)) > "$ANS_IDX"
    printf -v "$1" '%s' "$(sed -n "$((n + 1))p" "$ANS_FILE")"
}
_ob_read_line()   { _next_answer_into "$1"; }
_ob_read_secret() { _next_answer_into "$1"; }

FAKE_KEYRING="$TEST_TMPDIR/keyring.gpg"
printf 'not-a-real-keyring\n' > "$FAKE_KEYRING"

# A real key, so the record carries a public key the loader re-derives.
PUBKEY=""
PUBKEY_FP=""
if command -v ssh-keygen >/dev/null 2>&1; then
    ssh-keygen -t ed25519 -f "$TEST_TMPDIR/svc" -N "" -q -C "svc@test"
    PUBKEY=$(cat "$TEST_TMPDIR/svc.pub")
    PUBKEY_FP=$(ssh-keygen -lf "$TEST_TMPDIR/svc.pub" | awk '{print $2}')
fi

# Every variable a config sets, back to what a fresh ob-builder starts with.
reset_state() {
    DEPLOYMENT_SLUG=""; SCENARIO=""; PORTAL_URL=""
    CLIENT_ID=""; CLIENT_ID_POLICY=""; CLIENT_SECRET_MODE=""; EMBEDDED_CLIENT_SECRET=""
    SERVER_GROUP=""; SERVER_GROUP_POLICY=""; TARGET_ROLE=""; TARGET_ROLES=()
    AUTO_ENROLL_SETUP=""; SERVICE_KEYS_SETUP=""; SELF_DELETE=""; ALLOWED_BASTIONS=""
    ANSIBLE_AUTO_APPROVE=""; ENABLE_HARDENING=""; ENABLE_AUDIT_TRACE=""
    DISABLE_SESSION_RECORDER=""; SERVICE_ACCOUNTS_RECORDS=()
    REPO_KEYRING=""; REPO_KEYRING_SET=0
    APT_URL="$DEFAULT_APT_URL"; APT_URL_SET=0
    APT_SUITE="$DEFAULT_APT_SUITE"; APT_SUITE_SET=0
    APT_COMPONENT="$DEFAULT_APT_COMPONENT"; APT_COMPONENT_SET=0
    SIGN_WITH=""; SIGN_WITH_SET=0
    INSECURE=0; CONFIG_INSECURE=""; unset OB_BUILDER_INSECURE
    SAVE_CONFIG=""; SAVE_CONFIG_SECRET=0
    OUTPUT_SHELL=""; OUTPUT_ANSIBLE=""; BUNDLE=0; DRY_RUN=0
}

# A state that exercises every key: several roles, --insecure, an embedded
# secret, a non-default repo, signing, accounts with and without a key, and
# values needing each quoting form.
set_rich_state() {
    reset_state
    DEPLOYMENT_SLUG="acme"
    SCENARIO="token+unix"
    PORTAL_URL="http://sso.acme.test"
    INSECURE=1
    CLIENT_ID="ob-bastion"; CLIENT_ID_POLICY="fixed"
    CLIENT_SECRET_MODE="embedded"; EMBEDDED_CLIENT_SECRET='s3"cr\et#x'
    SERVER_GROUP="prod"; SERVER_GROUP_POLICY="fixed"
    TARGET_ROLES=(bastion backend); TARGET_ROLE="bastion"
    ALLOWED_BASTIONS="b-1,b-2"
    ENABLE_HARDENING="yes"; ENABLE_AUDIT_TRACE="no"; DISABLE_SESSION_RECORDER="yes"
    AUTO_ENROLL_SETUP="prompt"; SELF_DELETE="no"; ANSIBLE_AUTO_APPROVE="yes"
    SERVICE_KEYS_SETUP="false"
    APT_URL="https://mirror.acme.test/ob"; APT_SUITE="bookworm"; APT_COMPONENT="main extra"
    REPO_KEYRING="$FAKE_KEYRING"
    SIGN_WITH="0xDEADBEEF"
    SAVE_CONFIG_SECRET=1
    SERVICE_ACCOUNTS_RECORDS=(
        "$(_sa_pack ci-ansible "SHA256:abcdefABCDEF0123456789+/abcdefABCDEF0123456" true true /bin/bash /home/ci-ansible "Ansible \"CI\" bot" 6001 6001 "")"
    )
    if [ -n "$PUBKEY" ]; then
        SERVICE_ACCOUNTS_RECORDS+=("$(_sa_pack backup "$PUBKEY_FP" false false "" "" "" "" "" "$PUBKEY")")
    fi
}

# The state a config determines, one line per variable.
snapshot() {
    local r
    printf '%s\n' "$DEPLOYMENT_SLUG" "$SCENARIO" "$PORTAL_URL" "$INSECURE" \
        "$CLIENT_ID" "$CLIENT_ID_POLICY" "$CLIENT_SECRET_MODE" "$EMBEDDED_CLIENT_SECRET" \
        "$SERVER_GROUP" "$SERVER_GROUP_POLICY" "${TARGET_ROLES[*]}" "$ALLOWED_BASTIONS" \
        "$ENABLE_HARDENING" "$ENABLE_AUDIT_TRACE" "$DISABLE_SESSION_RECORDER" \
        "$AUTO_ENROLL_SETUP" "$SELF_DELETE" "$ANSIBLE_AUTO_APPROVE" "$SERVICE_KEYS_SETUP" \
        "$APT_URL" "$APT_SUITE" "$APT_COMPONENT" "$REPO_KEYRING" "$SIGN_WITH"
    for r in "${SERVICE_ACCOUNTS_RECORDS[@]}"; do
        printf '%s\n' "${r//$_OB_SA_US/|}"
    done
}

# load_config with the parser chosen: "awk", or "yq" (whichever is on PATH).
load_with() {
    local parser="$1" f="$2"
    if [ "$parser" = "yq" ]; then _load_config_yq "$f"; else _load_config_awk "$f"; fi
    _parse_service_accounts_block "$f"
    _normalise_config_values
}

PARSERS="awk"
command -v yq >/dev/null 2>&1 && PARSERS="awk yq"

# ── Round trip ─────────────────────────────────────────────────────────────

test_round_trip() {
    local parser want got cfg="$TEST_TMPDIR/rich.yml"
    want=$( set_rich_state; validate_inputs >/dev/null 2>&1; snapshot )
    ( set_rich_state; validate_inputs >/dev/null 2>&1; save_config "$cfg" >/dev/null 2>&1 )
    if [ ! -s "$cfg" ]; then
        test_fail "round trip: no config written"
        return
    fi
    for parser in $PARSERS; do
        got=$( reset_state; load_with "$parser" "$cfg" 2>/dev/null; validate_inputs >/dev/null 2>&1; snapshot )
        if [ "$got" = "$want" ]; then
            test_pass "round trip ($parser): replaying the saved config restores every answer"
        else
            test_fail "round trip ($parser): state differs" "$(diff <(echo "$want") <(echo "$got"))"
        fi
    done
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
        if python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$cfg" 2>/dev/null; then
            test_pass "round trip: the saved config is valid YAML"
        else
            test_fail "round trip: the saved config is not valid YAML"
        fi
    fi
    [ "$(stat -c %a "$cfg")" = "600" ] && test_pass "config with the secret is written 0600" \
                                      || test_fail "config with the secret is $(stat -c %a "$cfg")"
}

# The defaults of an unasked key are written, not left out.
test_defaults_written() {
    local cfg="$TEST_TMPDIR/defaults.yml" ok=true k
    (
        reset_state
        DEPLOYMENT_SLUG="d"; SCENARIO="max-security"; PORTAL_URL="https://sso.test"
        TARGET_ROLE="backend"; REPO_KEYRING="$DEFAULT_REPO_KEYRING"
        validate_inputs >/dev/null 2>&1
        save_config "$cfg" >/dev/null 2>&1
    )
    for k in client_id_policy client_secret_mode server_group_policy auto_enroll_setup \
             self_delete enable_hardening enable_audit_trace disable_session_recorder \
             ansible_auto_approve insecure apt_url apt_suite apt_component sign_with; do
        grep -q "^$k: " "$cfg" 2>/dev/null || { ok=false; echo "  missing $k"; }
    done
    grep -q '^# repo_keyring: ' "$cfg" || { ok=false; echo "  default keyring not commented"; }
    grep -q '^# service_keys: ' "$cfg" || { ok=false; echo "  service_keys hint missing"; }
    grep -q '^service_accounts:' "$cfg" && { ok=false; echo "  empty service_accounts written"; }
    [ "$(stat -c %a "$cfg" 2>/dev/null)" = "644" ] || { ok=false; echo "  mode not 644"; }
    $ok && test_pass "every key is written with its default; default keyring stays a comment" \
         || test_fail "defaults missing from the saved config"
}

# Without consent the secret stays out, and the replay says why it fails.
test_secret_left_out() {
    local cfg="$TEST_TMPDIR/nosecret.yml" ok=true out
    out=$( set_rich_state; SAVE_CONFIG_SECRET=0; validate_inputs >/dev/null 2>&1; save_config "$cfg" 2>&1 )
    grep -q 's3' "$cfg" && { ok=false; echo "  secret written"; }
    grep -q '^# embedded_client_secret: ""$' "$cfg" || { ok=false; echo "  no placeholder"; }
    grep -q 'left out' <<<"$out" || { ok=false; echo "  no warning"; }
    [ "$(stat -c %a "$cfg")" = "644" ] || { ok=false; echo "  mode not 644"; }
    out=$( reset_state; load_with awk "$cfg" 2>/dev/null; validate_inputs 2>&1 )
    grep -q 'requires embedded_client_secret' <<<"$out" || { ok=false; echo "  replay: $out"; }
    $ok && test_pass "embedded secret left out by default; replay asks for it explicitly" \
         || test_fail "secret handling in the saved config"
}

# An account the questionnaire built (no key) gets a public_key_file hint.
test_account_without_key() {
    local cfg="$TEST_TMPDIR/nokey.yml"
    ( set_rich_state; validate_inputs >/dev/null 2>&1; save_config "$cfg" >/dev/null 2>&1 )
    if grep -q '^    # public_key_file: keys/ci-ansible.pub$' "$cfg"; then
        test_pass "account without a key: public_key_file hint written"
    else
        test_fail "no public_key_file hint for the keyless account"
    fi
}

# ── Quoting ────────────────────────────────────────────────────────────────

test_yaml_str() {
    local ok=true
    [ "$(_yaml_str 'plain')" = '"plain"' ] || ok=false
    [ "$(_yaml_str '')" = '""' ] || ok=false
    [ "$(_yaml_str 'a"b')" = "'a\"b'" ] || ok=false
    [ "$(_yaml_str 'a\b')" = "'a\\b'" ] || ok=false
    [ "$(_yaml_str "it's")" = "\"it's\"" ] || ok=false
    _yaml_str "a\"b'c" >/dev/null && ok=false
    _yaml_str 'a #b' >/dev/null && ok=false
    _yaml_str $'a\nb' >/dev/null && ok=false
    _yaml_str $'a\rb' >/dev/null && ok=false
    _yaml_str $'a\x7fb' >/dev/null && ok=false
    _yaml_str $'a\xc2\x85b' >/dev/null && ok=false
    _yaml_str $'caf\xe9' >/dev/null && ok=false          # Latin-1, not UTF-8
    [ "$(_yaml_str $'a\tb')" = $'"a\tb"' ] || ok=false
    [ "$(_yaml_str 'café')" = '"café"' ] || ok=false
    $ok && test_pass "_yaml_str: double, single or refused, never a value read back differently" \
         || test_fail "_yaml_str quoting is wrong"
}

test_unwritable_value_fails() {
    local cfg="$TEST_TMPDIR/bad.yml" out rc
    out=$( set_rich_state; validate_inputs >/dev/null 2>&1
           SIGN_WITH="key #1"; save_config "$cfg" 2>&1 ); rc=$?
    if [ "$rc" -ne 0 ] && grep -q "'sign_with' cannot be written" <<<"$out" && [ ! -e "$cfg" ]; then
        test_pass "a value YAML cannot carry stops the save and names the key"
    else
        test_fail "unwritable value not refused (rc=$rc)" "$out"
    fi
}

# ── Loader fixes ───────────────────────────────────────────────────────────

# Unquoted YAML booleans: yq returns true/false, `// …` used to drop false.
test_yaml_booleans() {
    local cfg="$TEST_TMPDIR/bools.yml" parser got
    cat > "$cfg" << 'EOF'
self_delete: false
enable_hardening: true
insecure: true
EOF
    for parser in $PARSERS; do
        got=$( reset_state; load_with "$parser" "$cfg" 2>/dev/null
               printf '%s|%s|%s|%s' "$SELF_DELETE" "$ENABLE_HARDENING" "$INSECURE" "${OB_BUILDER_INSECURE:-}" )
        if [ "$got" = "no|yes|1|1" ]; then
            test_pass "booleans ($parser): false kept, true/false read as yes/no, insecure applied"
        else
            test_fail "booleans ($parser) read as '$got'"
        fi
    done
}

test_insecure_key() {
    local ok=true cfg="$TEST_TMPDIR/ins.yml"
    printf 'insecure: "maybe"\n' > "$cfg"
    ( reset_state; load_with awk "$cfg" ) >/dev/null 2>&1 && ok=false
    printf 'insecure: "no"\n' > "$cfg"
    [ "$( reset_state; INSECURE=1; load_with awk "$cfg" 2>/dev/null; echo "$INSECURE" )" = 1 ] || ok=false
    $ok && test_pass "insecure: invalid value refused, 'no' does not undo --insecure" \
         || test_fail "insecure key handling"
}

test_sign_with_cli_wins() {
    local cfg="$TEST_TMPDIR/sign.yml" got
    printf 'sign_with: "FROMCFG"\n' > "$cfg"
    got=$( reset_state; SIGN_WITH="CLI"; SIGN_WITH_SET=1; load_with awk "$cfg" 2>/dev/null; echo "$SIGN_WITH" )
    [ "$got" = "CLI" ] && test_pass "sign_with: --sign-with wins over the config" \
                       || test_fail "sign_with from config overrode the CLI: $got"
}

test_target_role_list() {
    local ok=true got
    got=$( reset_state; TARGET_ROLE="bastion, backend standalone"; DEPLOYMENT_SLUG=x
           SCENARIO=max-security; PORTAL_URL=https://s.test; REPO_KEYRING="$FAKE_KEYRING"
           validate_inputs >/dev/null 2>&1; echo "${TARGET_ROLES[*]}|$TARGET_ROLE" )
    [ "$got" = "bastion backend standalone|bastion" ] || { ok=false; echo "  list: $got"; }
    ( reset_state; TARGET_ROLE="bastion,bastion"; DEPLOYMENT_SLUG=x; SCENARIO=max-security
      PORTAL_URL=https://s.test; REPO_KEYRING="$FAKE_KEYRING"; validate_inputs ) 2>&1 \
        | grep -q 'twice' || { ok=false; echo "  duplicate accepted"; }
    ( reset_state; TARGET_ROLE="bastion,standalone"; BUNDLE=1; DEPLOYMENT_SLUG=x; SCENARIO=max-security
      PORTAL_URL=https://s.test; REPO_KEYRING="$FAKE_KEYRING"; validate_inputs ) 2>&1 \
        | grep -q 'single target_role' || { ok=false; echo "  bundle with two roles accepted"; }
    ( reset_state; TARGET_ROLE=""; DEPLOYMENT_SLUG=x; SCENARIO=max-security
      PORTAL_URL=https://s.test; REPO_KEYRING="$FAKE_KEYRING"; validate_inputs ) 2>&1 \
        | grep -q 'target_role is required' || { ok=false; echo "  empty role accepted"; }
    $ok && test_pass "target_role: comma/space list, duplicates, --bundle and empty refused" \
         || test_fail "target_role list handling"
}

# ── Questionnaire and CLI ──────────────────────────────────────────────────

test_questionnaire_offer() {
    local got
    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=embedded
           cd "$TEST_TMPDIR"   # the default path is relative to the cwd
           set_answers "" "" "y"   # save: yes, default path, include the secret
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s|%s' "$SAVE_CONFIG" "$SAVE_CONFIG_SECRET" "$(answers_left)" )
    [ "$got" = "./ob-builder-lab.yml|1|0" ] && test_pass "questionnaire: save offered with a default path, secret on consent" \
                                            || test_fail "questionnaire save offer gave '$got'"
    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=prompt
           set_answers "n"
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s' "$SAVE_CONFIG" "$(answers_left)" )
    [ "$got" = "|0" ] && test_pass "questionnaire: declining saves nothing" \
                      || test_fail "questionnaire decline gave '$got'"
    got=$( reset_state; SAVE_CONFIG=/x.yml; CLIENT_SECRET_MODE=embedded
           set_answers ""   # secret: default no
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s|%s' "$SAVE_CONFIG" "$SAVE_CONFIG_SECRET" "$(answers_left)" )
    [ "$got" = "/x.yml|0|0" ] && test_pass "questionnaire: --save-config path not re-asked, secret still asked" \
                              || test_fail "questionnaire with --save-config gave '$got'"
}

test_cli_refuses_overwrite() {
    local cfg="$TEST_TMPDIR/same.yml" out rc
    printf 'deployment_slug: x\n' > "$cfg"
    out=$(bash "$BUILDER" --config "$cfg" --save-config "$cfg" --output-shell "$TEST_TMPDIR/o.sh" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && grep -q 'would overwrite the --config file' <<<"$out" \
       && [ "$(cat "$cfg")" = "deployment_slug: x" ]; then
        test_pass "--save-config refuses to overwrite the --config file"
    else
        test_fail "--save-config over --config not refused (rc=$rc)" "$out"
    fi
}

test_dry_run_writes_nothing() {
    local cfg="$TEST_TMPDIR/dry.yml" existing="$TEST_TMPDIR/dry-existing.yml" out
    ( set_rich_state; DRY_RUN=1; validate_inputs >/dev/null 2>&1; save_config "$cfg" >/dev/null 2>&1 )
    [ ! -e "$cfg" ] && test_pass "--dry-run: the config is not written" \
                    || test_fail "--dry-run wrote the config"

    # An existing target is reported as replaced, and nothing is claimed about
    # a write that does not happen.
    printf 'deployment_slug: stale-marker\n' > "$existing"
    out=$( set_rich_state; DRY_RUN=1; validate_inputs >/dev/null 2>&1; save_config "$existing" 2>&1 )
    if grep -q 'Would replace the existing config' <<<"$out" \
       && ! grep -q 'not carried over' <<<"$out" && grep -q 'stale-marker' "$existing"; then
        test_pass "--dry-run: an existing config is reported as replaced, not touched"
    else
        test_fail "--dry-run reported a write it did not do" "$out"
    fi
}

test_replay_command_in_header() {
    local cfg="$TEST_TMPDIR/hdr.yml"
    ( set_rich_state; OUTPUT_SHELL="./b oot.sh"; OUTPUT_ANSIBLE="./role"; SIGN_WITH=""
      validate_inputs >/dev/null 2>&1; save_config "$cfg" >/dev/null 2>&1 )
    if grep -qF "#   ob-builder --config ${cfg} --output-shell ./b\\ oot.sh --output-ansible ./role" "$cfg"; then
        test_pass "header: replay command with the output paths, shell-quoted"
    else
        test_fail "header lacks the replay command" "$(head -3 "$cfg")"
    fi
}

# Consent given, secret unquotable: said so, not silently dropped.
test_secret_unquotable_warns() {
    local cfg="$TEST_TMPDIR/badsecret.yml" out
    out=$( set_rich_state; EMBEDDED_CLIENT_SECRET=$'ab\'c"d'
           validate_inputs >/dev/null 2>&1; save_config "$cfg" 2>&1 )
    if grep -q 'could not be written' <<<"$out" && grep -q '^# embedded_client_secret: ""$' "$cfg"; then
        test_pass "consented but unquotable secret: placeholder written and a warning"
    else
        test_fail "unquotable secret dropped silently" "$out"
    fi
}

# A key comment YAML cannot carry is dropped, not fatal: sshd ignores it.
test_pubkey_comment_dropped() {
    [ -n "$PUBKEY" ] || { echo "SKIP: ssh-keygen required"; return; }
    local cfg="$TEST_TMPDIR/keycomment.yml" got rc
    ( set_rich_state
      SERVICE_ACCOUNTS_RECORDS=("$(_sa_pack backup "$PUBKEY_FP" false false "" "" "" "" "" "${PUBKEY% *} host #3")")
      validate_inputs >/dev/null 2>&1; save_config "$cfg" >/dev/null 2>&1 ); rc=$?
    got=$( reset_state; load_with awk "$cfg" 2>/dev/null; _sa_field 10 "${SERVICE_ACCOUNTS_RECORDS[0]}" )
    if [ "$rc" -eq 0 ] && [ "$got" = "$(cut -d' ' -f1,2 <<<"$PUBKEY")" ]; then
        test_pass "public key with an unwritable comment: saved without the comment"
    else
        test_fail "public key comment handling (rc=$rc)" "$got"
    fi
}

test_gecos_checked_on_entry() {
    local got
    got=$( reset_state
           set_answers "y" "svc" "SHA256:abcdefABCDEF0123456789+/abcdefABCDEF0123456" "n" \
               "Ops #2" "Ops 2" "" "" "" "" "n"
           collect_service_accounts_interactive >/dev/null 2>&1
           printf '%s|%s' "$(_sa_field 7 "${SERVICE_ACCOUNTS_RECORDS[0]}")" "$(answers_left)" )
    [ "$got" = "Ops 2|0" ] && test_pass "questionnaire: a GECOS the config cannot carry is asked again" \
                           || test_fail "GECOS not re-asked: '$got'"
}

test_sign_with_checked_early() {
    local out rc
    out=$( set_rich_state; SIGN_WITH="0xNOPE-NOT-A-KEY"; OUTPUT_SHELL="$TEST_TMPDIR/x.sh"
           validate_inputs 2>&1 ); rc=$?
    if [ "$rc" -ne 0 ] && grep -q "No usable GPG secret key '0xNOPE-NOT-A-KEY'" <<<"$out"; then
        test_pass "sign_with: an unusable key stops the build before the SSO fetch"
    else
        test_fail "unusable sign_with key accepted (rc=$rc)" "$out"
    fi
}

test_null_string_round_trip() {
    local cfg="$TEST_TMPDIR/null.yml" parser got
    ( set_rich_state; SERVER_GROUP="null"; validate_inputs >/dev/null 2>&1; save_config "$cfg" >/dev/null 2>&1 )
    for parser in $PARSERS; do
        got=$( reset_state; load_with "$parser" "$cfg" 2>/dev/null; echo "$SERVER_GROUP" )
        [ "$got" = "null" ] && test_pass "server_group \"null\" ($parser): kept as the string" \
                            || test_fail "server_group \"null\" ($parser) read as '$got'"
    done
}

test_keyring_saved_absolute() {
    local cfg="$TEST_TMPDIR/kr.yml"
    ( cd "$TEST_TMPDIR" && set_rich_state && REPO_KEYRING="keyring.gpg" \
      && validate_inputs >/dev/null 2>&1; save_config "$cfg" >/dev/null 2>&1 )
    grep -qx "repo_keyring: \"$(realpath "$FAKE_KEYRING")\"" "$cfg" \
        && test_pass "relative repo_keyring saved as an absolute path" \
        || test_fail "repo_keyring not absolute" "$(grep repo_keyring "$cfg")"
}

test_directory_path_refused() {
    local out rc got
    out=$( set_rich_state; validate_inputs >/dev/null 2>&1; save_config "$TEST_TMPDIR" 2>&1 ); rc=$?
    [ "$rc" -ne 0 ] && grep -q 'is a directory' <<<"$out" \
        && test_pass "--save-config refuses a directory" \
        || test_fail "directory accepted as --save-config (rc=$rc)" "$out"
    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=prompt
           set_answers "y" "$TEST_TMPDIR" "/tmp/x.yml"
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s' "$SAVE_CONFIG" "$(answers_left)" )
    [ "$got" = "/tmp/x.yml|0" ] && test_pass "questionnaire: a directory path is asked again" \
                                || test_fail "questionnaire directory path gave '$got'"
}

# The default path is the same on every run for a given slug, and it names the
# file the README tells the operator to complete by hand: it must not be
# replaced on Enter alone.
test_questionnaire_overwrite_guard() {
    local existing="$TEST_TMPDIR/hand.yml" got
    printf 'deployment_slug: hand\n# embedded_client_secret: fill me\n' > "$existing"
    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=prompt
           set_answers "y" "$existing" "n" "$TEST_TMPDIR/other.yml"
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s|%s' "$SAVE_CONFIG" "$(answers_left)" "$(tr '\n' '/' < "$existing")" )
    [ "$got" = "$TEST_TMPDIR/other.yml|0|deployment_slug: hand/# embedded_client_secret: fill me/" ] \
        && test_pass "questionnaire: refusing the overwrite re-asks the path, file untouched" \
        || test_fail "questionnaire overwrite refusal gave '$got'"

    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=prompt
           set_answers "y" "$existing" "y"
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s|%s' "$SAVE_CONFIG" "$SAVE_CONFIG_SECRET" "$(answers_left)" )
    [ "$got" = "$existing|0|0" ] \
        && test_pass "questionnaire: accepting the overwrite keeps the path" \
        || test_fail "questionnaire overwrite accept gave '$got'"

    # ask_yesno answers its default without asking when non-interactive: the
    # probe must not spin on the re-ask, nor keep a path it could not confirm.
    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=prompt
           cd "$TEST_TMPDIR"; printf 'deployment_slug: keepme\n' > ./ob-builder-lab.yml
           export OB_BUILDER_NON_INTERACTIVE=1
           set_answers
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s|%s' "$SAVE_CONFIG" "$(cat "$ANS_IDX")" "$(cat ./ob-builder-lab.yml)" )
    [ "$got" = "|0|deployment_slug: keepme" ] \
        && test_pass "questionnaire: an existing default path is not saved non-interactively" \
        || test_fail "non-interactive overwrite guard gave '$got'"

    # The directory branch is re-asked too, so it needs the same way out: with
    # no input to consume it would spin on the default path forever.
    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=prompt
           cd "$TEST_TMPDIR"; rm -f ./ob-builder-lab.yml; mkdir ./ob-builder-lab.yml
           export OB_BUILDER_NON_INTERACTIVE=1
           set_answers
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s' "$SAVE_CONFIG" "$(cat "$ANS_IDX")" )
    [ "$got" = "|0" ] \
        && test_pass "questionnaire: a directory default path is not saved non-interactively" \
        || test_fail "non-interactive directory guard gave '$got'"

    # Refusing the overwrite and then pressing Enter skips the save: the second
    # path prompt has no default, so the operator is not trapped.
    got=$( reset_state; DEPLOYMENT_SLUG=lab; CLIENT_SECRET_MODE=prompt
           set_answers "y" "$existing" "n" ""
           collect_save_config_interactive >/dev/null 2>&1
           printf '%s|%s|%s' "$SAVE_CONFIG" "$(answers_left)" "$(tr '\n' '/' < "$existing")" )
    [ "$got" = "|0|deployment_slug: hand/# embedded_client_secret: fill me/" ] \
        && test_pass "questionnaire: an empty answer after a refusal skips the save" \
        || test_fail "no way out of the re-ask gave '$got'"
}

# Replacing a file the operator may have completed by hand is said out loud.
test_overwrite_warns_about_hand_edits() {
    local cfg="$TEST_TMPDIR/stale.yml" out
    printf 'deployment_slug: stale-marker\n' > "$cfg"
    out=$( set_rich_state; validate_inputs >/dev/null 2>&1; save_config "$cfg" 2>&1 )
    if grep -q 'already exists' <<<"$out" && ! grep -q 'stale-marker' "$cfg"; then
        test_pass "save_config warns before replacing an existing file"
    else
        test_fail "replacing an existing config was silent (or not replaced)" "$out"
    fi
}

echo "Parsers under test: $PARSERS"
[ -n "$PUBKEY" ] || echo "SKIP: ssh-keygen missing, round trip runs without a public key"

test_round_trip
test_defaults_written
test_secret_left_out
test_account_without_key
test_yaml_str
test_unwritable_value_fails
test_yaml_booleans
test_insecure_key
test_sign_with_cli_wins
test_target_role_list
test_questionnaire_offer
test_cli_refuses_overwrite
test_dry_run_writes_nothing
test_replay_command_in_header
test_secret_unquotable_warns
test_pubkey_comment_dropped
test_gecos_checked_on_entry
test_sign_with_checked_early
test_null_string_round_trip
test_keyring_saved_absolute
test_directory_path_refused
test_questionnaire_overwrite_guard
test_overwrite_warns_about_hand_edits

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
