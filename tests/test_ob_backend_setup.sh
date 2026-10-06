#!/bin/bash
# test_ob_backend_setup.sh -- the backend role of the setup script.
#
# ob-backend-setup is a symlink to scripts/ob-bastion-setup, which takes its
# default role from the name it is invoked under (#288). Everything here goes
# through that name, exactly as an admin runs it: the script is loaded or run
# as "ob-backend-setup", never as ob-bastion-setup with the role patched in.
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# shellcheck source=tests/lib_pam_stack.sh
. "$TESTS_DIR/lib_pam_stack.sh"
# shellcheck source=tests/lib_setup_script.sh
. "$TESTS_DIR/lib_setup_script.sh"

# The command under test, and its definitions loaded under the same name.
BACKEND=$(setup_command ob-backend-setup)
source_script() { load_setup_as "$1"; }

# ── Test 1: Syntax check ──
test_syntax() {
    if bash -n "$BACKEND" 2>/dev/null; then
        pass "Syntax check"
    else
        fail "Syntax check"
    fi
}

# ── Test 2: --version / --help ──
test_version() {
    local out
    out=$(bash "$BACKEND" --version 2>&1)
    if echo "$out" | grep -q "version"; then
        pass "--version outputs version"
    else
        fail "--version outputs version" "$out"
    fi
}

test_help() {
    local out
    out=$(bash "$BACKEND" --help 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "--help outputs usage"
    else
        fail "--help outputs usage" "$out"
    fi
}

# ── Test 3: Unknown option rejected ──
test_unknown_option() {
    if bash "$BACKEND" --bogus 2>/dev/null; then
        fail "Unknown option rejected"
    else
        pass "Unknown option rejected"
    fi
}

# ── Test 4: Missing portal URL exits with error ──
test_missing_portal() {
    if bash "$BACKEND" -g mygroup 2>/dev/null; then
        fail "Missing portal URL exits with error"
    else
        pass "Missing portal URL exits with error"
    fi
}

# ── Test 5: Missing server-group exits with error ──
test_missing_server_group() {
    if bash "$BACKEND" -p "https://x" 2>/dev/null; then
        fail "Missing server-group exits with error"
    else
        pass "Missing server-group exits with error"
    fi
}

# ── Test 6: parse_args sets all variables correctly ──
test_parse_args_sets_variables() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://auth.example.com" -g "prod" -n -y -k --no-sudo --no-create-user
        local ok=true
        [ "$PORTAL_URL" = "https://auth.example.com" ] || ok=false
        [ "$SERVER_GROUP" = "prod" ] || ok=false
        [ "$DRY_RUN" = "true" ] || ok=false
        [ "$NON_INTERACTIVE" = "true" ] || ok=false
        [ "$VERIFY_SSL" = "false" ] || ok=false
        [ "$ENABLE_SUDO" = "false" ] || ok=false
        [ "$CREATE_USERS" = "false" ] || ok=false
        if $ok; then exit 0; else exit 1; fi
    )
    if [ $? -eq 0 ]; then
        pass "parse_args sets all variables correctly"
    else
        fail "parse_args sets all variables correctly"
    fi
}

# ── Test 7: --no-sudo sets ENABLE_SUDO=false ──
test_no_sudo() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --no-sudo
        [ "$ENABLE_SUDO" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--no-sudo sets ENABLE_SUDO=false"
    else
        fail "--no-sudo sets ENABLE_SUDO=false"
    fi
}

# ── Test 7b: sudo config provisions the open-bastion-sudo group + sudoers rule (#154) ──
# ob-backend-setup used to configure only PAM for sudo, never the sudoers
# drop-in, so SSO users always got "not in the sudoers file" on backends.
test_sudo_creates_sudoers_rule() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        configure_pam_sudo 2>&1
    )
    if echo "$out" | grep -q "open-bastion-sudo" \
       && echo "$out" | grep -q "/etc/sudoers.d/open-bastion"; then
        pass "configure_pam_sudo provisions open-bastion-sudo group + sudoers rule (#154)"
    else
        fail "configure_pam_sudo provisions sudoers rule (#154)" "$out"
    fi
}

# ── Test 7c: --no-sudo skips the sudoers rule entirely ──
test_no_sudo_skips_sudoers() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --no-sudo --dry-run
        configure_pam_sudo 2>&1
    )
    if echo "$out" | grep -q "sudoers.d/open-bastion"; then
        fail "--no-sudo must not provision a sudoers rule" "$out"
    else
        pass "--no-sudo skips the sudoers rule"
    fi
}

# ── Test 7d: Mode E provisions the sudoers rule itself ──
# The Mode E sudo stack is useless to an SSO user without the group and its
# sudoers rule. On a backend configure_pam_sudo happened to create them first;
# Mode E must not depend on that ordering, as it does not on a bastion.
test_max_security_sudo_provisions_sudoers() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --max-security --dry-run
        configure_max_security_sudo 2>&1
    )
    if grep -q "Would create group open-bastion-sudo" <<<"$out" \
       && grep -q "/etc/sudoers.d/open-bastion" <<<"$out"; then
        pass "Mode E sudo provisions the open-bastion-sudo group + sudoers rule"
    else
        fail "Mode E sudo provisions the open-bastion-sudo group + sudoers rule" "$out"
    fi
}

# ── Test 7e: --no-sudo and --max-security are refused together ──
# Mode E rewrites /etc/pam.d/sudo whatever --no-sudo says, so the pair cannot
# both be honoured; the run must stop before touching anything.
test_no_sudo_conflicts_with_max_security() {
    local out rc
    out=$(bash "$BACKEND" -p "https://x.example.com" -g g \
              --no-sudo --max-security --dry-run --yes 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ] && grep -q -- "--no-sudo cannot be combined with --max-security" <<<"$out"; then
        pass "--no-sudo with --max-security is refused"
    else
        fail "--no-sudo with --max-security is refused" "rc=$rc $out"
    fi
}

# ── Test 7f: NSS is configured with the lockdown, not before enrollment ──
# Phase 1 is for files nothing reads until sshd/PAM are switched over, because
# those are what rollback_on_failure takes back when enrollment fails.
# nsswitch.conf is live the moment it is written and was never restored, so a
# rolled-back backend kept "openbastion" in it with its config file deleted.
test_nss_not_in_rollback_phase() {
    local body enroll nss
    body=$(sed -n '/^main() {/,/^}/p' "$SETUP_SCRIPT")
    enroll=$(grep -n 'while ! enroll_server' <<<"$body" | cut -d: -f1)
    nss=$(grep -n '^[[:space:]]*configure_nss ' <<<"$body" | cut -d: -f1)
    if [ -n "$enroll" ] && [ -n "$nss" ] && [ "$(wc -l <<<"$nss")" -eq 1 ] \
       && [ "$nss" -gt "$enroll" ] \
       && ! grep -q 'configure_nss.*rollback_on_failure' <<<"$body"; then
        pass "NSS is configured after enrollment, outside the rollback phase"
    else
        fail "NSS is configured after enrollment, outside the rollback phase" \
             "enroll@${enroll:-?} nss@${nss:-?}"
    fi
}

# ── Test 7g: install_principals_helper, for real (#288 review) ──
# Every other test stops at --dry-run, which returns before the allowlist is
# written: replacing the call to install_allowed_bastions with `:` left the
# whole suite green. This runs the real path with `install` and `systemctl`
# stubbed and the allowlist redirected, and pins what matters: the backend
# helper is the one installed, the allowlist is written first (the backend
# helper with no allowlist accepts direct SSO certificates), and a failed
# write stops the step instead of being ignored under a suspended errexit.
test_install_helper_real_path() {
    local tmp out rc bad=""
    tmp=$(mktemp -d)
    # The run; $1 is where the allowlist goes.
    run_install() {
        (
            load_setup_as ob-backend-setup || exit 99
            parse_args -p "https://x" -g g --allowed-bastions "b1, b2" >/dev/null 2>&1 || exit 98
            normalize_allowed_bastions
            OB_ALLOWED_BASTIONS_FILE="$1"
            BACKUP_DIR="$tmp/backup"
            OB_DATA_DIR="$(cd "$TESTS_DIR/../share" && pwd)"
            export OB_DATA_DIR
            install() {
                case "$*" in
                    *ob-ssh-principals.*)
                        if [ -f "$OB_ALLOWED_BASTIONS_FILE" ]; then
                            echo "allowlist-before-helper" >> "$tmp/install.log"
                        fi ;;
                esac
                printf '%s\n' "$*" >> "$tmp/install.log"
            }
            systemctl() { :; }
            install_principals_helper >/dev/null 2>&1
        )
    }

    run_install "$tmp/etc/open-bastion/allowed_bastions"
    rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    [ "$(cat "$tmp/etc/open-bastion/allowed_bastions" 2>/dev/null)" = "b1 b2" ] \
        || bad="$bad allowlist-content"
    [ "$(stat -c %a "$tmp/etc/open-bastion/allowed_bastions" 2>/dev/null)" = 644 ] \
        || bad="$bad allowlist-mode"
    [ "$(stat -c %a "$tmp/etc/open-bastion" 2>/dev/null)" = 711 ] || bad="$bad dir-mode"
    grep -q 'ob-ssh-principals\.backend /usr/local/sbin/ob-ssh-principals$' "$tmp/install.log" \
        || bad="$bad backend-helper"
    grep -q '^allowlist-before-helper$' "$tmp/install.log" || bad="$bad order"

    # The allowlist cannot be written (its directory is a file): the step fails
    # and the helper is never installed.
    rm -f "$tmp/install.log"
    : > "$tmp/not-a-dir"
    run_install "$tmp/not-a-dir/allowed_bastions"
    rc=$?
    [ "$rc" -ne 0 ] || bad="$bad failed-write-ignored"
    grep -q 'ob-ssh-principals\.' "$tmp/install.log" 2>/dev/null \
        && bad="$bad helper-installed-without-allowlist"

    rm -rf "$tmp"
    if [ -z "$bad" ]; then
        pass "install_principals_helper writes the allowlist first, then the backend helper"
    else
        fail "install_principals_helper writes the allowlist first, then the backend helper" "$bad"
    fi
}

# ── Test 8: --no-create-user sets CREATE_USERS=false ──
test_no_create_user() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --no-create-user
        [ "$CREATE_USERS" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--no-create-user sets CREATE_USERS=false"
    else
        fail "--no-create-user sets CREATE_USERS=false"
    fi
}

# ── Test 9: --dry-run sets DRY_RUN=true ──
test_dry_run() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        [ "$DRY_RUN" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--dry-run sets DRY_RUN=true"
    else
        fail "--dry-run sets DRY_RUN=true"
    fi
}

# ── Test 10: confirm() in non-interactive mode ──
test_confirm_noninteractive() {
    (
        source_script "ob-backend-setup"
        NON_INTERACTIVE=true
        confirm "Test?" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "confirm() returns 0 in non-interactive mode"
    else
        fail "confirm() returns 0 in non-interactive mode"
    fi
}

# ── Test 11: backup_file works correctly ──
test_backup_file() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local srcfile="$tmpdir/original.conf"
    echo "test content" > "$srcfile"
    (
        source_script "ob-backend-setup"
        BACKUP_DIR="$tmpdir/backups"
        backup_file "$srcfile"
        [ -f "$tmpdir/backups/original.conf" ] || exit 1
        local backed
        backed=$(cat "$tmpdir/backups/original.conf")
        [ "$backed" = "test content" ] && exit 0 || exit 1
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "backup_file works correctly"
    else
        fail "backup_file works correctly"
    fi
}

# ── Test 12: Portal URL trailing slash stripped ──
test_trailing_slash() {
    (
        source_script "ob-backend-setup"
        PORTAL_URL="https://auth.example.com/"
        PORTAL_URL="${PORTAL_URL%/}"
        [ "$PORTAL_URL" = "https://auth.example.com" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "Portal URL trailing slash stripped"
    else
        fail "Portal URL trailing slash stripped"
    fi
}

# ── Test 13: --max-security sets MAX_SECURITY=true ──
test_max_security() {
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --max-security
        [ "$MAX_SECURITY" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--max-security sets MAX_SECURITY=true"
    else
        fail "--max-security sets MAX_SECURITY=true"
    fi
}

# ── Test 14: default node_role is backend, --node-role overrides ──
test_node_role_default() {
    (
        source_script "ob-backend-setup"
        PORTAL_URL="https://x"; OB_TOKEN="/v/t"; SERVER_GROUP="g"
        CLIENT_ID=""; CLIENT_SECRET=""; VERIFY_SSL=true
        # Capture first: piping into `grep -q` makes grep exit on first match,
        # which SIGPIPEs render_openbastion_conf and trips `set -o pipefail`.
        local conf; conf=$(render_openbastion_conf)
        grep -q "^node_role = backend$" <<<"$conf" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "default node_role is backend"
    else
        fail "default node_role is backend"
    fi
}

# The backend's own settings stay above the option reference, active.
test_conf_carries_reference() {
    if (
        source_script "ob-backend-setup"
        PORTAL_URL="https://x"; OB_TOKEN="/v/t"; SERVER_GROUP="g"
        CLIENT_ID=""; CLIENT_SECRET=""; VERIFY_SSL=true; CREATE_USERS=false
        # shellcheck disable=SC2034  # read by render_openbastion_conf
        OB_CONFIG="/nonexistent"
        # shellcheck disable=SC2034
        OB_CONFIG_REFERENCE="$TESTS_DIR/../config/openbastion.conf.reference"
        local conf marker='openbastion.conf reference: every option'
        conf=$(render_openbastion_conf)
        sed "/$marker/,\$d" <<<"$conf" | grep -q '^create_user_enabled = false$' || exit 1
        sed -n "/$marker/,\$p" <<<"$conf" | grep -q '^# create_user = false$' || exit 1
        sed -n "/$marker/,\$p" <<<"$conf" | grep -qE '^[[:space:]]*[a-z_]+[[:space:]]*=' && exit 1
        exit 0
    ); then
        pass "backend conf: settings, then the commented option reference"
    else
        fail "backend conf: settings, then the commented option reference"
    fi
}

test_node_role_override() {
    local rc1 rc2
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --node-role bastion
        [ "$NODE_ROLE" = "bastion" ] && exit 0 || exit 1
    )
    rc1=$?
    # invalid role: parse_args errors out (exits non-zero)
    (
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --node-role bogus 2>/dev/null
    )
    rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -ne 0 ]; then
        pass "--node-role accepts valid role and rejects invalid"
    else
        fail "--node-role accepts valid role and rejects invalid"
    fi
}

# -- The fresh-OTP opt-in (#178) --
#
# sudo caches its own credential (timestamp_timeout, 15 min, idle-based and
# rearmed on each use). While it is valid sudo skips the PAM auth phase
# entirely, so pam_openbastion never runs and no LLNG one-time token is asked
# for. --enable-sudo-fresh-otp scopes timestamp_timeout=0 to the SSO group so
# every elevation goes through PAM. It must stay OFF by default: turning it on
# changes the prompt cadence for every SSO user on an upgraded fleet.
test_sudo_fresh_otp_optin() {
    local off on ok=1

    off=$(
        source_script "ob-backend-setup"
        SUDO_FRESH_OTP=false
        render_open_bastion_sudoers "# header"
    )
    on=$(
        source_script "ob-backend-setup"
        SUDO_FRESH_OTP=true
        render_open_bastion_sudoers "# header"
    )

    grep -q '^%open-bastion-sudo ALL=(ALL) ALL$' <<<"$off" \
        || { ok=0; echo "    (default drop-in lost its sudo rule)"; }
    grep -q 'timestamp_timeout' <<<"$off" \
        && { ok=0; echo "    (timestamp_timeout applied without the flag)"; }
    grep -q '^Defaults:%open-bastion-sudo timestamp_timeout=0$' <<<"$on" \
        || { ok=0; echo "    (--enable-sudo-fresh-otp did not scope timestamp_timeout=0)"; }
    grep -q '^%open-bastion-sudo ALL=(ALL) ALL$' <<<"$on" \
        || { ok=0; echo "    (opt-in drop-in lost its sudo rule)"; }
    grep -q 'enable-sudo-fresh-otp' <<<"$(bash "$BACKEND" --help 2>&1)" \
        || { ok=0; echo "    (not documented in --help)"; }

    if command -v visudo >/dev/null 2>&1; then
        local tmp; tmp=$(mktemp)
        printf '%s\n' "$on" > "$tmp"
        visudo -cf "$tmp" >/dev/null 2>&1 \
            || { ok=0; echo "    (opt-in drop-in fails visudo)"; }
        rm -f "$tmp"
    fi

    if [ "$ok" -eq 1 ]; then
        pass "--enable-sudo-fresh-otp is opt-in, scoped, and documented"
    else
        fail "--enable-sudo-fresh-otp is opt-in, scoped, and documented"
    fi
}

# ── The allowed-bastions list is validated and normalised (#182) ──
#
# The list is written to a world-readable file consumed by the principals
# helper, which compares each entry against a bastion_id it has already
# restricted to [A-Za-z0-9._-]. A typo outside that charset would sit there
# matching nothing (every hop denied, unexplained), and a whitespace-only value
# would silently mean "any bastion" while looking configured.
test_allowed_bastions_normalised() {
    local rc1 rc2 rc3 rc4
    (
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b1, b2 ;b3"
        normalize_allowed_bastions
        [ "$BASTION_ALLOWED_IDS" = "b1 b2 b3" ] && exit 0 || exit 1
    )
    rc1=$?
    (
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="   "
        normalize_allowed_bastions
        [ -z "$BASTION_ALLOWED_IDS" ] && exit 0 || exit 1
    )
    rc2=$?
    (
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="ok,bad id!"
        normalize_allowed_bastions 2>/dev/null
    )
    rc3=$?
    # `--allowed-bastions --dry-run`: the next option taken as the list.
    (
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="--dry-run"
        normalize_allowed_bastions 2>/dev/null
    )
    rc4=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$rc3" -ne 0 ] && [ "$rc4" -ne 0 ]; then
        pass "allowed-bastions list normalised, blank collapses, junk and options rejected"
    else
        fail "allowed-bastions validation" "rc=$rc1/$rc2/$rc3/$rc4"
    fi
}

# ── A glob in the list must be refused, not silently rewritten (#236 review) ──
#
# Splitting the raw list runs pathname expansion as well as word splitting, so
# 'b[1]' used to become whichever file matched in the CURRENT DIRECTORY -- the
# typo was accepted as a different, valid-looking id instead of being refused.
# The test runs from a directory seeded with files that the globs match, which
# is the only condition under which the bug is observable.
test_allowed_bastions_no_glob() {
    local tmp rc out ok=1
    tmp=$(mktemp -d)
    : > "$tmp/b1"
    : > "$tmp/b2"

    # 'b[1]' matches the file b1; must still be rejected as an invalid id.
    out=$(
        cd "$tmp" || exit 99
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b[1]"
        normalize_allowed_bastions 2>&1
        printf 'RESULT=%s\n' "$BASTION_ALLOWED_IDS"
    )
    rc=$?
    [ "$rc" -ne 0 ] || { ok=0; echo "    (glob 'b[1]' accepted, rc=$rc: $out)"; }
    grep -q 'RESULT=b1' <<<"$out" && { ok=0; echo "    (glob 'b[1]' rewritten to the file b1)"; }

    # 'b*' matches two files; must not turn into a two-entry allowlist.
    out=$(
        cd "$tmp" || exit 99
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b*"
        normalize_allowed_bastions 2>&1
        printf 'RESULT=%s\n' "$BASTION_ALLOWED_IDS"
    )
    rc=$?
    [ "$rc" -ne 0 ] || { ok=0; echo "    (glob 'b*' accepted, rc=$rc: $out)"; }
    grep -q 'RESULT=b1 b2' <<<"$out" && { ok=0; echo "    (glob 'b*' expanded to the cwd)"; }

    # A legitimate list must still normalise with globbing restored afterwards.
    out=$(
        cd "$tmp" || exit 99
        source_script "ob-backend-setup"
        BASTION_ALLOWED_IDS="b1,b2"
        normalize_allowed_bastions
        printf 'RESULT=%s|GLOB=%s\n' "$BASTION_ALLOWED_IDS" "$(case $- in *f*) echo off ;; *) echo on ;; esac)"
    )
    grep -q 'RESULT=b1 b2|GLOB=on' <<<"$out" \
        || { ok=0; echo "    (valid list broken, or globbing left disabled: $out)"; }

    rm -rf "$tmp"
    if [ "$ok" -eq 1 ]; then
        pass "globs in the allowed-bastions list are refused, not expanded"
    else
        fail "globs in the allowed-bastions list are refused, not expanded"
    fi
}

# ── An empty list must be an explicit interactive choice (#236 review) ──
#
# Pressing Enter used to accept "any bastion" -- the exposure #182 is about --
# as the path of least resistance. It now re-asks and takes only an explicit
# "y". Non-interactive runs keep the empty default: an upgrade must not start
# refusing hops that worked yesterday.
test_allowed_bastions_empty_is_explicit() {
    local out ok=1

    # Enter, then "n", then a real id: the empty answer must not stick.
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=false
        ALLOW_ANY_BASTION=false
        BASTION_ALLOWED_IDS=""
        # NOT a pipe: a pipeline would run the function in a subshell and
        # throw away the assignment this test is about.
        prompt_allowed_bastions >/dev/null 2>&1 <<<$'\nn\nb1'
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[b1\]' <<<"$out" \
        || { ok=0; echo "    (declining 'any bastion' did not re-ask: $out)"; }

    # A separators-only answer must not slip past the gate either: the
    # normaliser collapses whitespace AND ',;' to nothing, so each of these
    # reaches the empty list while looking like an answer (#236 review).
    local blank
    for blank in '   ' ',,' ' ; , '; do
        out=$(
            source_script "ob-backend-setup"
            NON_INTERACTIVE=false
            ALLOW_ANY_BASTION=false
            BASTION_ALLOWED_IDS=""
            prompt_allowed_bastions >/dev/null 2>&1 <<<"$blank"$'\nn\nb1'
            printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
        )
        grep -q 'RESULT=\[b1\]' <<<"$out" \
            || { ok=0; echo "    (blank answer '$blank' bypassed the gate: $out)"; }
    done

    # Enter, then "y": empty, on the record.
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=false
        ALLOW_ANY_BASTION=false
        BASTION_ALLOWED_IDS=""
        prompt_allowed_bastions >/dev/null 2>&1 <<<$'\ny'
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[\]' <<<"$out" \
        || { ok=0; echo "    (explicit 'y' did not leave the list empty: $out)"; }

    # --allow-any-bastion answers up front, without a prompt (no stdin at all).
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=false
        ALLOW_ANY_BASTION=true
        BASTION_ALLOWED_IDS=""
        prompt_allowed_bastions >/dev/null 2>&1 </dev/null
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[\]' <<<"$out" \
        || { ok=0; echo "    (--allow-any-bastion still prompted: $out)"; }

    # A non-interactive run keeps the legacy empty default, unprompted.
    out=$(
        source_script "ob-backend-setup"
        NON_INTERACTIVE=true
        ALLOW_ANY_BASTION=false
        BASTION_ALLOWED_IDS=""
        prompt_allowed_bastions >/dev/null 2>&1 </dev/null
        printf 'RESULT=[%s]\n' "$BASTION_ALLOWED_IDS"
    )
    grep -q 'RESULT=\[\]' <<<"$out" \
        || { ok=0; echo "    (--yes run no longer keeps the empty default: $out)"; }

    # Both options must be discoverable, since the prompt now depends on them.
    local help
    help=$(bash "$BACKEND" --help 2>&1)
    grep -q -- '--allowed-bastions' <<<"$help" \
        || { ok=0; echo "    (--allowed-bastions missing from --help)"; }
    grep -q -- '--allow-any-bastion' <<<"$help" \
        || { ok=0; echo "    (--allow-any-bastion missing from --help)"; }

    if [ "$ok" -eq 1 ]; then
        pass "empty allowed-bastions is an explicit choice, and both flags documented"
    else
        fail "empty allowed-bastions is an explicit choice, and both flags documented"
    fi
}

# ── --allowed-bastions without --portal updates a configured backend (#323) ──
#
# The documented way to fill the allowlist after an installer run is
# `ob-backend-setup --allowed-bastions <ids>`. It must rewrite that file alone
# -- no questionnaire, no sshd/PAM/enrollment step -- and refuse on a host that
# is not a configured backend. main() runs under `set -euo pipefail`, as the
# real command does (the harness strips it), against a scratch root.

# $1 = "backend", "bastion" or "none" (sshd drop-in present); the allowlist
# starts as "old1 old2". Prints the root.
make_update_root() {
    local root
    root=$(mktemp -d)
    mkdir -p "$root/etc/open-bastion" "$root/etc/ssh/sshd_config.d"
    echo "portal_url = https://auth.example.com" > "$root/etc/open-bastion/openbastion.conf"
    if [ "$1" != "none" ]; then
        echo "# managed" > "$root/etc/ssh/sshd_config.d/00-open-bastion-$1.conf"
    fi
    printf 'old1 old2\n' > "$root/etc/open-bastion/allowed_bastions"
    chmod 644 "$root/etc/open-bastion/allowed_bastions"
    printf '%s' "$root"
}

# $1 = root, then the options. Every step of the full setup is replaced by a
# marker in $root/full-setup.log; stdin is closed, so any question fails.
run_update() {
    local root="$1"
    shift
    (
        load_setup_as ob-backend-setup || exit 99
        set -euo pipefail
        OB_CONFIG="$root/etc/open-bastion/openbastion.conf"
        OB_ALLOWED_BASTIONS_FILE="$root/etc/open-bastion/allowed_bastions"
        SSHD_CONFIG="$root/etc/ssh/sshd_config"
        SSHD_CONFIG_DIR="$root/etc/ssh/sshd_config.d"
        BACKUP_DIR="$root/backup"
        check_root() { :; }
        # The full setup looks for sshd before its first step.
        mkdir -p "$root/bin" && printf '#!/bin/sh\n' > "$root/bin/sshd" && chmod +x "$root/bin/sshd"
        PATH="$root/bin:$PATH"
        local f
        for f in prompt_required_settings preflight_sshd_config download_ca_key \
                 prepare_principals_helper configure_pam_openbastion enroll_server \
                 configure_sshd configure_pam_sshd configure_pam_sudo configure_nss \
                 restart_sshd; do
            eval "$f() { echo $f >> '$root/full-setup.log'; exit 42; }"
        done
        main "$@"
    ) </dev/null
}

test_allowed_bastions_update_configured_backend() {
    local root out rc bad=""
    root=$(make_update_root backend)
    local conf_before; conf_before=$(cat "$root/etc/open-bastion/openbastion.conf")

    out=$(run_update "$root" --allowed-bastions "b1, b2" 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "b1 b2" ] || bad="$bad content"
    [ "$(stat -c %a "$root/etc/open-bastion/allowed_bastions")" = 644 ] || bad="$bad mode"
    [ "$(stat -c %a "$root/etc/open-bastion")" = 711 ] || bad="$bad dir-mode"
    [ -e "$root/full-setup.log" ] && bad="$bad full-setup:$(tr '\n' ',' < "$root/full-setup.log")"
    [ "$(cat "$root/etc/open-bastion/openbastion.conf")" = "$conf_before" ] || bad="$bad conf-changed"
    grep -q 'old1 old2' <<<"$out" || bad="$bad old-list-not-reported"
    grep -q 'Continue with' <<<"$out" && bad="$bad asked-to-continue"
    [ "$(cat "$root/backup/allowed_bastions" 2>/dev/null)" = "old1 old2" ] || bad="$bad no-backup"
    compgen -G "$root/etc/open-bastion/allowed_bastions.*" >/dev/null && bad="$bad temp-file-left"

    # Same list again: nothing is rewritten.
    rm -rf "$root/backup"
    out=$(run_update "$root" --allowed-bastions "b1;b2" 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || bad="$bad same-rc=$rc"
    grep -q 'unchanged' <<<"$out" || bad="$bad same-not-reported"
    [ -e "$root/backup" ] && bad="$bad same-rewritten"

    # --dry-run reports and writes nothing.
    out=$(run_update "$root" --allowed-bastions b3 --dry-run 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || bad="$bad dry-rc=$rc"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "b1 b2" ] || bad="$bad dry-run-wrote"
    grep -q 'DRY-RUN.*b3' <<<"$out" || bad="$bad dry-run-silent"

    # --insecure, kept from a full-setup command line, is accepted.
    out=$(run_update "$root" --allowed-bastions "b1 b2" --insecure 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || bad="$bad insecure-rc=$rc"
    [ -e "$root/full-setup.log" ] && bad="$bad insecure-full-setup"

    # --yes --allow-any-bastion empties it, unprompted.
    out=$(run_update "$root" --allow-any-bastion --yes 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || bad="$bad any-rc=$rc"
    [ -z "$(tr -d '[:space:]' < "$root/etc/open-bastion/allowed_bastions")" ] \
        || bad="$bad any-not-empty"
    [ -e "$root/full-setup.log" ] && bad="$bad full-setup-later"

    rm -rf "$root"
    if [ -z "$bad" ]; then
        pass "--allowed-bastions without --portal updates only the allowlist of a configured backend"
    else
        fail "--allowed-bastions without --portal updates only the allowlist of a configured backend" "$bad"
    fi
}

test_allowed_bastions_update_refusals() {
    local root out rc bad=""

    # Not set up: no backend drop-in.
    root=$(make_update_root none)
    out=$(run_update "$root" --allowed-bastions b1 2>&1)
    rc=$?
    [ "$rc" -eq 1 ] || bad="$bad unconfigured-rc=$rc"
    grep -q -- '--portal' <<<"$out" || bad="$bad unconfigured-no-hint"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "old1 old2" ] || bad="$bad unconfigured-wrote"
    rm -rf "$root"

    # Backend drop-in but no openbastion.conf.
    root=$(make_update_root backend)
    rm -f "$root/etc/open-bastion/openbastion.conf"
    run_update "$root" --allowed-bastions b1 >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 1 ] || bad="$bad no-conf-rc=$rc"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "old1 old2" ] || bad="$bad no-conf-wrote"
    rm -rf "$root"

    # A bastion.
    root=$(make_update_root bastion)
    out=$(run_update "$root" --allowed-bastions b1 2>&1)
    rc=$?
    [ "$rc" -eq 1 ] || bad="$bad bastion-rc=$rc"
    grep -q 'configured as a bastion' <<<"$out" || bad="$bad bastion-msg"
    rm -rf "$root"

    # An invalid id, on a configured backend: the list is left as it was.
    root=$(make_update_root backend)
    out=$(run_update "$root" --allowed-bastions 'b1,bad/id' 2>&1)
    rc=$?
    [ "$rc" -eq 1 ] || bad="$bad invalid-rc=$rc"
    grep -q "Invalid bastion id.*bad/id" <<<"$out" || bad="$bad invalid-msg"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "old1 old2" ] || bad="$bad invalid-wrote"

    # Another setup option without --portal: refused, not half-applied.
    out=$(run_update "$root" --allowed-bastions b1 --no-sudo 2>&1)
    rc=$?
    [ "$rc" -eq 1 ] || bad="$bad extra-opt-rc=$rc"
    grep -q -- '--no-sudo' <<<"$out" || bad="$bad extra-opt-msg"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "old1 old2" ] || bad="$bad extra-opt-wrote"

    # An empty answer with nobody to ask: refused, not an endless prompt loop.
    out=$(run_update "$root" --allowed-bastions "" 2>&1)
    rc=$?
    [ "$rc" -eq 1 ] || bad="$bad empty-eof-rc=$rc"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "old1 old2" ] || bad="$bad empty-eof-wrote"

    # With --portal, it is the full setup, as before.
    run_update "$root" -p https://auth.example.com --allowed-bastions b1 >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 42 ] || bad="$bad portal-rc=$rc"
    [ -s "$root/full-setup.log" ] || bad="$bad portal-not-full-setup"
    [ "$(cat "$root/etc/open-bastion/allowed_bastions")" = "old1 old2" ] || bad="$bad portal-updated-only"
    rm -rf "$root"

    if [ -z "$bad" ]; then
        pass "--allowed-bastions update refuses unconfigured hosts, bastions, bad ids and extra options"
    else
        fail "--allowed-bastions update refuses unconfigured hosts, bastions, bad ids and extra options" "$bad"
    fi
}

# ── Test 18: the generated sshd PAM auth stack is fail-closed (#180) ──
# A bare "auth required pam_permit.so" made pam_authenticate() succeed for any
# password if sshd ever ran the stack (PasswordAuthentication /
# KbdInteractiveAuthentication yes with UsePAM yes). The stack now denies
# outright: sshd never calls pam_authenticate() for a certificate login, so the
# only thing that reaches it is a password/keyboard-interactive attempt.
# tests/test_ob_pam_runtime.sh proves the denial by running the stack.
test_pam_sshd_fail_closed() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        configure_pam_sshd 2>&1
    )
    assert_auth_stack_denies "generated /etc/pam.d/sshd auth stack denies" "$out"
}

# ── Test 19: the generated sudo PAM auth stack is fail-closed (#180) ──
test_pam_sudo_fail_closed() {
    local out
    out=$(
        source_script "ob-backend-setup"
        parse_args -p "https://x" -g "g" --dry-run
        configure_pam_sudo 2>&1
    )
    assert_auth_stack_fail_closed "generated /etc/pam.d/sudo auth stack is fail-closed" "$out"
}

# ── Run all tests ──
echo "=== Testing ob-backend-setup ==="
run_test test_syntax
run_test test_version
run_test test_help
run_test test_unknown_option
run_test test_missing_portal
run_test test_missing_server_group
run_test test_parse_args_sets_variables
run_test test_no_sudo
run_test test_sudo_creates_sudoers_rule
run_test test_no_sudo_skips_sudoers
run_test test_max_security_sudo_provisions_sudoers
run_test test_no_sudo_conflicts_with_max_security
run_test test_nss_not_in_rollback_phase
run_test test_install_helper_real_path
run_test test_no_create_user
run_test test_dry_run
run_test test_confirm_noninteractive
run_test test_backup_file
run_test test_trailing_slash
run_test test_max_security
run_test test_node_role_default
run_test test_node_role_override
run_test test_conf_carries_reference
run_test test_allowed_bastions_normalised
run_test test_allowed_bastions_no_glob
run_test test_allowed_bastions_empty_is_explicit
run_test test_allowed_bastions_update_configured_backend
run_test test_allowed_bastions_update_refusals

run_test test_sudo_fresh_otp_optin
run_test test_pam_sshd_fail_closed
run_test test_pam_sudo_fail_closed

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
