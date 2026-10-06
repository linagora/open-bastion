#!/bin/bash
#
# Test suite for ob-builder --insecure propagation and the full interactive
# mode (#308).
#
# A bundle built for an http:// portal used to install verify_ssl = true, which
# pam_openbastion refuses for an http portal: nobody could log in. --insecure
# now also drives the generated artefacts. The questionnaire, run without
# --config, covers every option and may target several roles in one run.
#
# Sources ob-builder like the other test_ob_builder_*.sh suites (with
# `set -euo pipefail` and the `main "$@"` call stripped).
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
unset OB_BUILDER_NON_INTERACTIVE

# Scripted answers for the prompt helpers. The prompts run inside $(...), so
# the queue lives in files. Running past the end kills the test's subshell
# ($ANS_OWNER) instead of looping forever on an empty answer.
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

# Fake SSO assets for rendering.
FAKE_WORK="$TEST_TMPDIR/work"
mkdir -p "$FAKE_WORK"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake ca\n' > "$FAKE_WORK/ca.pub"
: > "$FAKE_WORK/krl"
FAKE_KEYRING="$TEST_TMPDIR/keyring.gpg"
printf 'not-a-real-keyring\n' > "$FAKE_KEYRING"

set_baseline() {
    DEPLOYMENT_SLUG="demo"
    SCENARIO="max-security"
    PORTAL_URL="http://sso.example.com"
    CLIENT_ID="pam-access"
    CLIENT_ID_POLICY="modifiable"
    CLIENT_SECRET_MODE="prompt"
    EMBEDDED_CLIENT_SECRET=""
    SERVER_GROUP="default"
    SERVER_GROUP_POLICY="modifiable"
    TARGET_ROLE="bastion"
    TARGET_ROLES=()
    ALLOWED_BASTIONS=""
    AUTO_ENROLL_SETUP="yes"
    SELF_DELETE="no"
    ENABLE_HARDENING="no"
    ENABLE_AUDIT_TRACE="no"
    DISABLE_SESSION_RECORDER="no"
    ANSIBLE_AUTO_APPROVE="no"
    SERVICE_ACCOUNTS_RECORDS=()
    REPO_KEYRING="$FAKE_KEYRING"
    WORK_DIR="$FAKE_WORK"
    SSO_CA_FINGERPRINT="SHA256:fake"
    OUTPUT_SHELL=""
    OUTPUT_ANSIBLE=""
    BUNDLE=0
    DRY_RUN=0
}

# ── Artefact defaults driven by --insecure ─────────────────────────────────

test_mode_settings_no_verify_ssl() {
    local m ok=true
    for m in A B C D E; do
        _mode_settings_conf "$m" | grep -q verify_ssl && ok=false
    done
    _mode_settings_conf E | grep -q '^min_tls_version = 13$' || ok=false
    $ok && test_pass "_mode_settings_conf: no hardcoded verify_ssl, Mode E keeps min_tls_version" \
         || test_fail "_mode_settings_conf still emits verify_ssl or lost min_tls_version"
}

test_conf_template_placeholder() {
    if grep -q '^verify_ssl = ##VERIFY_SSL##$' "$REPO_ROOT/admin-builder/templates/shell/openbastion.conf.in"; then
        test_pass "shell conf template carries verify_ssl = ##VERIFY_SSL##"
    else
        test_fail "shell conf template lacks the ##VERIFY_SSL## placeholder"
    fi
}

# Value of placeholder $1 in the current map.
ph_get() {
    local i
    for ((i=0; i<${#_PH_KEYS[@]}; i++)); do
        [ "${_PH_KEYS[$i]}" = "$1" ] && { printf '%s' "${_PH_VALS[$i]}"; return 0; }
    done
    return 1
}

test_placeholders_follow_insecure() {
    local ok=true desc=""
    set_baseline
    INSECURE=1
    build_placeholder_map bastion
    [ "$(ph_get INSECURE_DEFAULT)" = "yes" ] || { ok=false; desc="INSECURE_DEFAULT not yes"; }
    [ "$(ph_get VERIFY_SSL_BOOL)" = "false" ] || { ok=false; desc="VERIFY_SSL_BOOL not false"; }
    INSECURE=0
    build_placeholder_map bastion
    [ "$(ph_get INSECURE_DEFAULT)" = "no" ]  || { ok=false; desc="INSECURE_DEFAULT not no"; }
    [ "$(ph_get VERIFY_SSL_BOOL)" = "true" ] || { ok=false; desc="VERIFY_SSL_BOOL not true"; }
    $ok && test_pass "build_placeholder_map: INSECURE_DEFAULT / VERIFY_SSL_BOOL follow --insecure" \
         || test_fail "placeholders do not follow INSECURE" "$desc"
}

test_recorder_optout_per_role() {
    local ok=true
    set_baseline
    DISABLE_SESSION_RECORDER="yes"
    build_placeholder_map bastion
    [ "$(ph_get DISABLE_SESSION_RECORDER)" = "yes" ] || ok=false
    [ "$(ph_get DISABLE_SESSION_RECORDER_BOOL)" = "true" ] || ok=false
    build_placeholder_map backend
    [ "$(ph_get DISABLE_SESSION_RECORDER)" = "no" ] || ok=false
    [ "$(ph_get DISABLE_SESSION_RECORDER_BOOL)" = "false" ] || ok=false
    $ok && test_pass "build_placeholder_map: recorder opt-out kept for bastion, dropped for backend" \
         || test_fail "recorder opt-out is not role-scoped"
}

test_parse_insecure_flags() {
    local ok=true out
    out=$( INSECURE=0; parse_args --allow-http 2>&1; echo "INSECURE=$INSECURE ENV=${OB_BUILDER_INSECURE:-}" )
    grep -q 'INSECURE=1 ENV=1' <<<"$out" || ok=false
    grep -qi 'deprecated' <<<"$out" || ok=false
    out=$( INSECURE=0; parse_args --insecure 2>&1; echo "INSECURE=$INSECURE ENV=${OB_BUILDER_INSECURE:-}" )
    grep -q 'INSECURE=1 ENV=1' <<<"$out" || ok=false
    grep -qi 'deprecated' <<<"$out" && ok=false
    $ok && test_pass "parse_args: --insecure and deprecated --allow-http both set INSECURE=1" \
         || test_fail "parse_args did not handle --insecure/--allow-http" "$out"
}

test_validate_http_needs_insecure() {
    local ok=true
    ( set_baseline; INSECURE=0; validate_inputs ) >/dev/null 2>&1 && ok=false
    ( set_baseline; INSECURE=0; validate_inputs ) 2>&1 | grep -q 'use --insecure' || ok=false
    ( set_baseline; INSECURE=1; validate_inputs ) >/dev/null 2>&1 || ok=false
    $ok && test_pass "validate_inputs: http portal refused without --insecure, accepted with it" \
         || test_fail "validate_inputs http/--insecure handling is wrong"
}

# ── Secret prompts ─────────────────────────────────────────────────────────

test_ask_secret_confirm() {
    local got
    got=$( set_answers "" "s3cret" "typo" "s3cret" "s3cret"; ask_secret_confirm "Secret" 2>/dev/null )
    if [ "$got" = "s3cret" ]; then
        test_pass "ask_secret_confirm: re-asks on empty and mismatch, returns the confirmed value"
    else
        test_fail "ask_secret_confirm returned '$got'"
    fi
}

# ── Multiple roles ─────────────────────────────────────────────────────────

test_multi_role_loop() {
    local got
    got=$(
        TARGET_ROLES=()
        set_answers "" "backend" "bastion" "bogus" "standalone"
        collect_target_roles_interactive >/dev/null 2>&1
        printf '%s' "${TARGET_ROLES[*]}|$TARGET_ROLE"
    )
    if [ "$got" = "bastion backend standalone|bastion" ]; then
        test_pass "role loop: default first role, rejects duplicate/invalid, stops after all three"
    else
        test_fail "role loop produced '$got'"
    fi
    got=$(
        TARGET_ROLES=()
        set_answers "backend" ""
        collect_target_roles_interactive >/dev/null 2>&1
        printf '%s' "${TARGET_ROLES[*]}"
    )
    [ "$got" = "backend" ] && test_pass "role loop: empty answer finishes" \
                           || test_fail "role loop single role produced '$got'"
}

test_output_plan() {
    local got ok=true
    got=$(
        set_baseline
        OUTPUT_SHELL="./out/"; OUTPUT_ANSIBLE="./ansible-demo/"
        TARGET_ROLES=(bastion backend)
        build_output_plan
        printf '%s,' "${_PLAN_ROLES[@]}" "${_PLAN_SHELL[@]}" "${_PLAN_ANSIBLE[@]}"
    )
    [ "$got" = "bastion,backend,./out/bootstrap-demo-bastion.sh,./out/bootstrap-demo-backend.sh,./ansible-demo-bastion,./ansible-demo-backend," ] \
        || { ok=false; echo "multi: $got"; }
    got=$(
        set_baseline
        OUTPUT_SHELL="."; OUTPUT_ANSIBLE="./ansible-demo"
        TARGET_ROLES=(standalone)
        build_output_plan
        printf '%s,' "${_PLAN_ROLES[@]}" "${_PLAN_SHELL[@]}" "${_PLAN_ANSIBLE[@]}"
    )
    [ "$got" = "standalone,./bootstrap-demo-standalone.sh,./ansible-demo," ] || { ok=false; echo "single: $got"; }
    got=$(
        set_baseline
        OUTPUT_SHELL="/tmp/b"; BUNDLE=1
        TARGET_ROLE=backend; TARGET_ROLES=(backend)
        build_output_plan
        printf '%s,' "${_PLAN_ROLES[@]}" "${_PLAN_SHELL[@]}"
    )
    [ "$got" = "backend,bastion,/tmp/b/bootstrap-demo-backend.sh,/tmp/b/bootstrap-demo-bastion.sh," ] || { ok=false; echo "bundle: $got"; }
    $ok && test_pass "build_output_plan: installers named bootstrap-<slug>-<role>.sh in --output-shell DIR" \
         || test_fail "build_output_plan derived wrong paths"
}

# --output-shell names a directory; a file name is refused rather than
# silently turned into a directory.
test_check_output_shell_dir() {
    local ok=true p
    mkdir -p "$TEST_TMPDIR/csd/dir" "$TEST_TMPDIR/csd/odd.sh"
    : > "$TEST_TMPDIR/csd/file"
    for p in "$TEST_TMPDIR/csd/new" "$TEST_TMPDIR/csd/new/" "$TEST_TMPDIR/csd/dir" \
             "$TEST_TMPDIR/csd/odd.sh" "." "$TEST_TMPDIR/csd/x.sh/"; do
        check_output_shell_dir "$p" >/dev/null || { ok=false; echo "refused: $p"; }
    done
    for p in "boot.sh" "$TEST_TMPDIR/csd/boot.sh" "$TEST_TMPDIR/csd/file"; do
        check_output_shell_dir "$p" >/dev/null && { ok=false; echo "accepted: $p"; }
    done
    grep -q 'takes a directory' <<< "$(check_output_shell_dir "$TEST_TMPDIR/csd/a/boot.sh")" \
        || { ok=false; echo "no explanation"; }
    $ok && test_pass "check_output_shell_dir: directories accepted, *.sh and existing files refused" \
         || test_fail "check_output_shell_dir accepted or refused the wrong paths"
}

# The real script (with set -euo pipefail): refused before anything is
# written, the config not even read.
test_cli_refuses_shell_file() {
    local ok=true out rc cfg="$TEST_TMPDIR/refuse.yml"
    printf 'deployment_slug: demo\n' > "$cfg"
    out=$(cd "$TEST_TMPDIR" && bash "$BUILDER" --config "$cfg" --output-shell "$TEST_TMPDIR/boot.sh" 2>&1); rc=$?
    { [ "$rc" -ne 0 ] && grep -q 'takes a directory, not a file name' <<< "$out" \
      && [ ! -e "$TEST_TMPDIR/boot.sh" ] && ! grep -q 'Loading config' <<< "$out"; } \
        || { ok=false; echo "*.sh (rc=$rc): $out"; }
    : > "$TEST_TMPDIR/plainfile"
    out=$(bash "$BUILDER" --config "$cfg" --output-shell "$TEST_TMPDIR/plainfile" 2>&1); rc=$?
    { [ "$rc" -ne 0 ] && grep -q 'exists but is not one' <<< "$out"; } \
        || { ok=false; echo "regular file (rc=$rc): $out"; }
    $ok && test_pass "ob-builder --output-shell FILE: refused with an explanation, nothing written" \
         || test_fail "ob-builder --output-shell FILE not refused"
}

# Whole run through main(): DIR created, files named by ob-builder, checklists
# in DIR and not in the current directory.
test_main_writes_into_dir() {
    local ok=true cfg="$TEST_TMPDIR/maindir.yml" dir="$TEST_TMPDIR/shell-out/sub" cwd="$TEST_TMPDIR/cwd" rc=0 f
    mkdir -p "$cwd"
    cat > "$cfg" <<YML
deployment_slug: demo
scenario: max-security
portal_url: https://sso.example.com
client_id: pam-access
client_secret_mode: prompt
server_group: default
target_role: bastion
YML
    (
        cd "$cwd" || exit 1
        fetch_sso_assets() {
            WORK_DIR="$FAKE_WORK"; SSO_CA_FINGERPRINT="SHA256:fake"
            printf '{"keys":[]}\n' > "$WORK_DIR/jwks.json"
        }
        main --config "$cfg" --bundle --repo-keyring "$FAKE_KEYRING" --output-shell "$dir"
    ) >"$TEST_TMPDIR/maindir.log" 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || { ok=false; echo "main failed (rc=$rc)"; tail -5 "$TEST_TMPDIR/maindir.log"; }
    for f in bootstrap-demo-bastion.sh bootstrap-demo-backend.sh \
             PORTAL-CHECKLIST-bastion.md PORTAL-CHECKLIST-backend.md; do
        [ -f "$dir/$f" ] || { ok=false; echo "missing $dir/$f"; }
    done
    [ -x "$dir/bootstrap-demo-bastion.sh" ] || { ok=false; echo "installer not executable"; }
    [ -z "$(ls -A "$cwd")" ] || { ok=false; echo "written in the cwd: $(ls -A "$cwd")"; }
    grep -qF "Portal checklist: $dir/PORTAL-CHECKLIST-backend.md" "$TEST_TMPDIR/maindir.log" \
        || { ok=false; echo "summary does not name the checklist in DIR"; }
    $ok && test_pass "main: --output-shell DIR created, bootstrap-<slug>-<role>.sh and checklists inside it" \
         || test_fail "main did not write the shell artefacts into --output-shell DIR"
}

# Full questionnaire, two roles, outputs and repo options asked.
test_questionnaire_full() {
    local got
    got=$(
        set_baseline
        DEPLOYMENT_SLUG=""; SCENARIO=""; PORTAL_URL=""; CLIENT_ID=""; CLIENT_ID_POLICY=""
        CLIENT_SECRET_MODE=""; SERVER_GROUP_POLICY=""; unset SERVER_GROUP
        TARGET_ROLE=""; AUTO_ENROLL_SETUP=""; SELF_DELETE=""; ENABLE_HARDENING=""
        ENABLE_AUDIT_TRACE=""; DISABLE_SESSION_RECORDER=""; ANSIBLE_AUTO_APPROVE=""
        unset ALLOWED_BASTIONS
        REPO_KEYRING=""; INSECURE=0
        local -a a=(
            "lab"                   # slug
            "both" "x.sh" "" ""     # outputs: a file name re-asked, then default paths
            ""                      # scenario (default)
            "http://sso.lab" "n"    # http refused once...
            "http://sso.lab" "y"    # ...then accepted with --insecure
            "" ""                   # client_id policy, client_id
            "embedded" "x" "y" "x" "x"   # secret mode, mismatch then match
            "" "grp"                # server_group policy, server_group
            "bastion" "backend" ""  # roles
            "b1"                    # allowed bastions (backend present)
            "" ""                   # hardening, audit trace
            "yes"                   # disable recorder (bastion present)
            "n"                     # no service accounts
            "" ""                   # auto enroll, self-delete
            ""                      # ansible auto-approve
            "" "" "" "$FAKE_KEYRING" ""   # apt url/suite/component, keyring, sign-with
            "n"                     # do not save the answers
        )
        set_answers "${a[@]}"
        run_questionnaire >/dev/null 2>&1
        validate_inputs >/dev/null 2>&1
        build_output_plan
        printf '%s|' "$OUTPUT_SHELL" "$OUTPUT_ANSIBLE" "$INSECURE" "${OB_BUILDER_INSECURE:-}" \
            "$PORTAL_URL" "$EMBEDDED_CLIENT_SECRET" "${TARGET_ROLES[*]}" "$ALLOWED_BASTIONS" \
            "$DISABLE_SESSION_RECORDER" "$APT_URL" "$REPO_KEYRING" "${_PLAN_SHELL[*]}" "$(answers_left)"
    )
    local want=".|./ansible-lab|1|1|http://sso.lab|x|bastion backend|b1|yes|$DEFAULT_APT_URL|$FAKE_KEYRING|./bootstrap-lab-bastion.sh ./bootstrap-lab-backend.sh|0|"
    if [ "$got" = "$want" ]; then
        test_pass "questionnaire: outputs, http -> --insecure, confirmed secret, two roles, repo options"
    else
        test_fail "questionnaire result mismatch" "got:  $got
  want: $want"
    fi
}

# CLI values are not asked again; one CLI output skips the output question.
test_questionnaire_skips_cli_values() {
    local got
    got=$(
        set_baseline
        DEPLOYMENT_SLUG="lab"; OUTPUT_ANSIBLE="/tmp/role"; TARGET_ROLE=""
        APT_URL_SET=1; APT_SUITE_SET=1; APT_COMPONENT_SET=1; REPO_KEYRING_SET=1
        INSECURE=1; PORTAL_URL="http://sso.lab"
        set_answers "standalone" "" "n" "n"   # roles, no service accounts, no save
        run_questionnaire >/dev/null 2>&1
        printf '%s|' "$OUTPUT_SHELL" "$OUTPUT_ANSIBLE" "${TARGET_ROLES[*]}" "$(answers_left)"
    )
    if [ "$got" = "|/tmp/role|standalone|0|" ]; then
        test_pass "questionnaire: CLI output / repo options / --insecure are not re-asked"
    else
        test_fail "questionnaire asked for CLI-provided values" "$got"
    fi
}

# ── Rendered installer ─────────────────────────────────────────────────────

test_rendered_installer() {
    local out="$TEST_TMPDIR/installer.sh" ok=true desc=""
    (
        set_baseline
        INSECURE=1
        TEMPLATES_DIR="$REPO_ROOT/admin-builder/templates"
        render_shell_installer "$out" bastion
    ) >/dev/null 2>&1 || { ok=false; desc="render failed"; }
    if [ -s "$out" ]; then
        bash -n "$out" 2>/dev/null || { ok=false; desc="bash -n failed"; }
        grep -q '^INSECURE_DEFAULT="yes"$' "$out" || { ok=false; desc="INSECURE_DEFAULT not yes"; }
        grep -qF "_RED=\$'\\033[0;31m'" "$out" || { ok=false; desc="colors not in \$'...' form"; }
        grep -q '^verify_ssl = ##VERIFY_SSL##$' "$out" || { ok=false; desc="conf lacks runtime verify_ssl"; }
        grep -q '^min_tls_version = 13$' "$out" || { ok=false; desc="Mode E settings lost"; }
        grep -v '^[[:space:]]*#' "$out" | grep -qE '@@[A-Z_]+@@' && { ok=false; desc="unexpanded @@ placeholder"; }
        if command -v shellcheck >/dev/null 2>&1; then
            shellcheck -S warning -e SC2050 "$out" >/dev/null 2>&1 || { ok=false; desc="shellcheck warnings"; }
        fi
    else
        ok=false
    fi
    (
        set_baseline
        INSECURE=0; PORTAL_URL="https://sso.example.com"
        TEMPLATES_DIR="$REPO_ROOT/admin-builder/templates"
        render_shell_installer "$out" bastion
    ) >/dev/null 2>&1
    grep -q '^INSECURE_DEFAULT="no"$' "$out" || { ok=false; desc="INSECURE_DEFAULT not no"; }
    $ok && test_pass "rendered installer: INSECURE_DEFAULT, \$'\\033' colors, runtime verify_ssl, valid bash" \
         || test_fail "rendered installer check failed" "$desc"
}

# The installer resolves verify_ssl from its effective --insecure, and asks
# the client_secret twice.
test_installer_runtime() {
    local out="$TEST_TMPDIR/installer-rt.sh" ok=true desc="" fn
    (
        set_baseline
        INSECURE=1
        TEMPLATES_DIR="$REPO_ROOT/admin-builder/templates"
        render_shell_installer "$out" bastion
    ) >/dev/null 2>&1
    fn="$TEST_TMPDIR/installer-fn.sh"
    sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$out" > "$fn"
    local got
    # shellcheck disable=SC1090
    got=$( . "$fn"; echo "$OPT_INSECURE"; OPT_DRY_RUN=true; CLIENT_SECRET_MODE=none
           step_config 2>&1 | grep -o 'verify_ssl   = [a-z]*' )
    [ "$got" = $'true\nverify_ssl   = false' ] || { ok=false; desc="insecure default: $got"; }
    grep -q 'Confirm client_secret' "$out" || { ok=false; desc="no secret confirmation"; }
    grep -q 'ob-bastion-id' "$out" || { ok=false; desc="no bastion id in summary"; }
    $ok && test_pass "installer: --insecure on by default when built insecure, secret confirmed, bastion ID shown" \
         || test_fail "installer runtime check failed" "$desc"
}

# ── Ansible role ───────────────────────────────────────────────────────────

test_rendered_ansible() {
    local out="$TEST_TMPDIR/role" ok=true desc=""
    (
        set_baseline
        INSECURE=1
        TEMPLATES_DIR="$REPO_ROOT/admin-builder/templates"
        render_ansible_role "$out" bastion
    ) >/dev/null 2>&1 || { ok=false; desc="render failed"; }
    local r="$out/roles/open-bastion"
    grep -q '^ob_verify_ssl: false$' "$r/defaults/main.yml" 2>/dev/null || { ok=false; desc="ob_verify_ssl not false"; }
    grep -q 'verify_ssl = {{' "$r/templates/openbastion.conf.j2" 2>/dev/null || { ok=false; desc="conf.j2 verify_ssl not templated"; }
    [ "$(grep -c "else \['-k'\]" "$r/tasks/_enroll.yml" 2>/dev/null)" = 2 ] || { ok=false; desc="ob-enroll -k missing"; }
    [ "$(grep -c 'validate_certs:' "$r/tasks/_enroll.yml" 2>/dev/null)" = 2 ] || { ok=false; desc="validate_certs missing"; }
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
        python3 -c 'import sys,yaml; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' \
            "$r/defaults/main.yml" "$r/tasks/_enroll.yml" 2>/dev/null || { ok=false; desc="invalid YAML"; }
    fi
    $ok && test_pass "ansible role: ob_verify_ssl false, templated verify_ssl, ob-enroll -k, validate_certs" \
         || test_fail "ansible role check failed" "$desc"
}

# ── openbastion.conf option reference (#310) ───────────────────────────────

# The installer writes the conf before the package that ships the reference is
# installed, so it appends the reference after step_install, once.
test_installer_conf_reference() {
    local out="$TEST_TMPDIR/installer-ref.sh" ok=true desc="" fn
    local conf="$TEST_TMPDIR/ref.conf" ref="$REPO_ROOT/config/openbastion.conf.reference"
    local marker='openbastion.conf reference: every option'
    (
        set_baseline
        TEMPLATES_DIR="$REPO_ROOT/admin-builder/templates"
        render_shell_installer "$out" bastion
    ) >/dev/null 2>&1
    fn="$TEST_TMPDIR/installer-ref-fn.sh"
    sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$out" > "$fn"
    printf 'portal_url = https://sso.example.com\n' > "$conf"
    chmod 0600 "$conf"
    (
        # shellcheck disable=SC1090
        . "$fn"
        set -euo pipefail
        append_conf_reference "$conf" "$ref"
        append_conf_reference "$conf" "$ref"
        append_conf_reference "$conf" "$TEST_TMPDIR/absent"
    ) >/dev/null 2>&1 || { ok=false; desc="append failed"; }
    [ "$(head -1 "$conf")" = "portal_url = https://sso.example.com" ] || { ok=false; desc="settings not first"; }
    [ "$(grep -c "$marker" "$conf")" = 1 ] || { ok=false; desc="reference not appended exactly once"; }
    [ "$(stat -c %a "$conf")" = 600 ] || { ok=false; desc="mode not kept"; }
    tail -n +3 "$conf" | cmp -s - "$ref" || { ok=false; desc="reference altered"; }
    awk '/^    step_install$/ { i = NR } /^    step_conf_reference$/ { r = NR }
         END { exit !(i && r == i + 1) }' "$out" || { ok=false; desc="not run right after step_install"; }
    if $ok; then
        test_pass "installer: appends the packaged option reference to openbastion.conf, once"
    else
        test_fail "installer conf reference check failed" "$desc"
    fi
}

test_ansible_conf_reference() {
    local out="$TEST_TMPDIR/role-ref" ok=true desc=""
    (
        set_baseline
        TEMPLATES_DIR="$REPO_ROOT/admin-builder/templates"
        render_ansible_role "$out" bastion
    ) >/dev/null 2>&1 || { ok=false; desc="render failed"; }
    local r="$out/roles/open-bastion"
    awk '/ansible.builtin.slurp:/ { s = NR }
         /src: \/usr\/share\/open-bastion\/openbastion.conf.reference/ && s { e = 1 }
         /register: ob_conf_reference/ && e { g = NR }
         /^- name: Deploy openbastion.conf$/ { d = NR }
         END { exit !(g && d > g) }' "$r/tasks/main.yml" 2>/dev/null \
        || { ok=false; desc="reference not read before the conf is deployed"; }
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import jinja2' 2>/dev/null; then
        local rendered
        rendered=$(python3 -I - "$r/templates/openbastion.conf.j2" \
                   "$REPO_ROOT/config/openbastion.conf.reference" <<'PY'
import base64, sys, jinja2
env = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
env.filters['b64decode'] = lambda s: base64.b64decode(s).decode()
env.filters['bool'] = bool
t = env.from_string(open(sys.argv[1]).read())
ctx = dict(ob_role='bastion', ob_pam_mode='E', ob_portal_url='https://x',
           ob_client_id='c', ob_client_secret='', ob_server_group='g',
           ob_verify_ssl=True, ob_service_accounts_enabled=False,
           ob_conf_reference={'content': base64.b64encode(
               open(sys.argv[2], 'rb').read()).decode()})
print(t.render(**ctx))
PY
        ) || { ok=false; desc="template does not render"; }
        sed '/openbastion.conf reference: every option/,$d' <<< "$rendered" \
            | grep -q '^portal_url = https://x$' || { ok=false; desc="settings not above the reference"; }
        grep -q '^# approved_home_prefixes = /home:/var/home$' <<< "$rendered" \
            || { ok=false; desc="reference not rendered"; }
    else
        grep -q 'ob_conf_reference.content | b64decode' "$r/templates/openbastion.conf.j2" \
            || { ok=false; desc="template does not append the reference"; }
    fi
    if $ok; then
        test_pass "ansible role: reads the packaged option reference and appends it to openbastion.conf"
    else
        test_fail "ansible conf reference check failed" "$desc"
    fi
}

test_recap_bundle_recorder() {
    local ok=true out
    out=$(
        set_baseline
        TARGET_ROLE=backend; TARGET_ROLES=(backend); BUNDLE=1
        DISABLE_SESSION_RECORDER="yes"
        build_output_plan
        print_recap 2>&1
    )
    grep -q 'disabled (opt-out)' <<< "$out" || { ok=false; echo "$out" | grep -i recording; }
    set_baseline
    DISABLE_SESSION_RECORDER="yes"
    build_placeholder_map bastion
    [ "$(ph_get DISABLE_SESSION_RECORDER)" = "yes" ] || ok=false
    build_placeholder_map backend
    [ "$(ph_get DISABLE_SESSION_RECORDER)" = "no" ] || ok=false
    $ok && test_pass "recap: bundle with backend primary reports the companion bastion's recorder opt-out" \
         || test_fail "recap ignores the bundled bastion's recorder opt-out"
}

# "&" in a value must not expand to the match (bash >= 5.2 patsub_replacement).
test_ampersand_values() {
    local ok=true tpl="$TEST_TMPDIR/amp.in" out
    printf 'k = @@AMP_KEY@@\n' > "$tpl"
    out=$(
        set_baseline
        DRY_RUN=0
        _PH_KEYS=(AMP_KEY); _PH_VALS=('a&b&&c')
        render_template "$tpl" "$TEST_TMPDIR/amp.out" 644 >/dev/null 2>&1
        cat "$TEST_TMPDIR/amp.out"
    )
    [ "$out" = "k = a&b&&c" ] || { ok=false; echo "render_template: $out"; }
    out=$(
        set_baseline
        INSECURE=1; PORTAL_URL="http://a&b.example.com"
        TEMPLATES_DIR="$REPO_ROOT/admin-builder/templates"
        render_shell_installer "$TEST_TMPDIR/amp-inst.sh" bastion >/dev/null 2>&1
        grep -F 'a&b.example.com' "$TEST_TMPDIR/amp-inst.sh" | head -1
    )
    [ -n "$out" ] || { ok=false; echo "installer lost the & value"; }
    $ok && test_pass "render: '&' in placeholder values is preserved" \
         || test_fail "'&' in a value was expanded"
}

# EOF on stdin without a tty must abort, not loop.
test_prompt_eof() {
    local rc=0
    timeout 5 bash -c '
        . "$1/common.sh"; . "$1/prompts.sh"
        _ob_has_tty() { return 1; }
        ask_secret_confirm "Secret"
    ' _ "$OB_BUILDER_LIB_DIR" </dev/null >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && test_pass "prompts: EOF on stdin aborts instead of looping" \
        || test_fail "ask_secret_confirm at EOF did not abort (rc=$rc)"
    rc=0
    timeout 5 bash -c '
        set -e
        . "$1/common.sh"; . "$1/prompts.sh"
        _ob_has_tty() { return 1; }
        x=$(ask "Q"); echo "reached"
    ' _ "$OB_BUILDER_LIB_DIR" </dev/null >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && test_pass "prompts: ask at EOF fails the caller under set -e" \
        || test_fail "ask at EOF did not fail the caller (rc=$rc)"
}

echo "=========================================="
echo "Testing ob-builder --insecure and interactive mode (#308)"
echo "=========================================="
echo ""

test_mode_settings_no_verify_ssl
test_conf_template_placeholder
test_placeholders_follow_insecure
test_recorder_optout_per_role
test_parse_insecure_flags
test_validate_http_needs_insecure
test_ask_secret_confirm
test_multi_role_loop
test_output_plan
test_check_output_shell_dir
test_cli_refuses_shell_file
test_main_writes_into_dir
test_questionnaire_full
test_questionnaire_skips_cli_values
test_rendered_installer
test_installer_runtime
test_rendered_ansible
test_installer_conf_reference
test_ansible_conf_reference
test_recap_bundle_recorder
test_ampersand_values
test_prompt_eof

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
