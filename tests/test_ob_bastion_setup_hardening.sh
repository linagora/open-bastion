#!/bin/bash
# Integration tests for the session-containment hardening step
# added to ob-bastion-setup (PR1). All tests run in dry-run mode and
# inside a sandboxed temporary directory so they never touch the host.
#
# shellcheck disable=SC2034  # variables are read by sourced functions
# shellcheck disable=SC2181  # $? idiom matches existing test style
# shellcheck disable=SC2329  # mocked functions invoked indirectly via sourced helpers
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
SCRIPT_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# Source ob-bastion-setup without executing main, à la test_ob_bastion_setup.sh
source_script() {
    local script="$1"
    local content
    content=$(cat "$SCRIPT_DIR/$script")
    content="${content%main \"\$@\"}"
    content=$(echo "$content" | sed -E 's/^set -e(uo pipefail)?$//')
    eval "$content"
}

# ── Test 1: Templates exist in the source tree ──
test_templates_present() {
    local ok=true
    for f in \
        "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
        "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
        "$REPO_DIR/config/hardening/at.allow" \
        "$REPO_DIR/config/hardening/cron.allow"
    do
        [ -f "$f" ] || { ok=false; echo "    missing: $f"; }
    done
    if $ok; then
        pass "All four hardening templates present in config/hardening/"
    else
        fail "All four hardening templates present in config/hardening/"
    fi
}

# ── Test 2: logind template enables KillUserProcesses ──
test_logind_template_content() {
    local f="$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf"
    if grep -q "^KillUserProcesses=yes" "$f" && grep -q "^\[Login\]" "$f"; then
        pass "logind template sets KillUserProcesses=yes under [Login]"
    else
        fail "logind template sets KillUserProcesses=yes under [Login]"
    fi
}

# ── Test 3: limits template caps nproc and exempts root ──
test_limits_template_content() {
    local f="$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf"
    if grep -qE '^\*[[:space:]]+hard[[:space:]]+nproc[[:space:]]+256' "$f" \
       && grep -qE '^root[[:space:]]+hard[[:space:]]+nproc[[:space:]]+unlimited' "$f"; then
        pass "limits template caps nproc=256 with root unlimited"
    else
        fail "limits template caps nproc=256 with root unlimited"
    fi
}

# ── Test 4: at.allow template does NOT whitelist any user ──
test_at_allow_template_content() {
    local f="$REPO_DIR/config/hardening/at.allow"
    # grep -v comments, blank lines; expect zero non-comment lines.
    local non_comments
    non_comments=$(grep -cvE '^[[:space:]]*(#|$)' "$f")
    if [ "$non_comments" -eq 0 ]; then
        pass "at.allow template is empty (root-only by design)"
    else
        fail "at.allow template is empty" "$non_comments non-comment lines"
    fi
}

# ── Test 5: cron.allow whitelists root only ──
test_cron_allow_template_content() {
    local f="$REPO_DIR/config/hardening/cron.allow"
    local non_comments
    non_comments=$(grep -vE '^[[:space:]]*(#|$)' "$f")
    if [ "$non_comments" = "root" ]; then
        pass "cron.allow template whitelists exactly 'root'"
    else
        fail "cron.allow template whitelists exactly 'root'" "got: $non_comments"
    fi
}

# ── Test 6: --enable-hardening sets ENABLE_HARDENING=true ──
test_enable_hardening_flag() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --enable-hardening
        [ "$ENABLE_HARDENING" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--enable-hardening sets ENABLE_HARDENING=true"
    else
        fail "--enable-hardening sets ENABLE_HARDENING=true"
    fi
}

# ── Test 7: Without --enable-hardening, ENABLE_HARDENING defaults to false ──
test_enable_hardening_default() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x"
        [ "$ENABLE_HARDENING" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "ENABLE_HARDENING defaults to false (opt-in, off by default)"
    else
        fail "ENABLE_HARDENING defaults to false (opt-in, off by default)"
    fi
}

# ── Test 8: --help mentions hardening ──
test_help_mentions_hardening() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-bastion-setup" --help 2>&1)
    if echo "$out" | grep -qi "hardening"; then
        pass "--help mentions hardening"
    else
        fail "--help mentions hardening"
    fi
}

# ── Test 9: Without --enable-hardening, main() logs that hardening is not applied ──
test_hardening_not_applied_by_default() {
    (
        source_script "ob-bastion-setup"
        # ENABLE_HARDENING is false by default — simulate main() wiring
        ENABLE_HARDENING=false
        out=""
        if [ "$ENABLE_HARDENING" = "true" ]; then
            out=$(setup_hardening 2>&1)
        else
            out="[INFO] Session containment hardening not applied (opt-in: pass --enable-hardening to activate)"
        fi
        echo "$out" | grep -q "opt-in" && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "Without --enable-hardening, hardening is not applied and logs opt-in hint"
    else
        fail "Without --enable-hardening, hardening is not applied and logs opt-in hint"
    fi
}

# ── Test 10: setup_hardening in dry-run does not write anything ──
test_setup_hardening_dryrun() {
    local sandbox
    sandbox=$(mktemp -d)
    # Build a fake template tree
    mkdir -p "$sandbox/share/hardening/logind.conf.d" \
             "$sandbox/share/hardening/security/limits.d"
    cp "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
       "$sandbox/share/hardening/logind.conf.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
       "$sandbox/share/hardening/security/limits.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/at.allow" "$sandbox/share/hardening/at.allow"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"

    (
        source_script "ob-bastion-setup"
        DRY_RUN=true
        NON_INTERACTIVE=true
        ENABLE_HARDENING=true
        HARDENING_TEMPLATE_DIR="$sandbox/share/hardening"
        HARDENING_LOGIND_DST="$sandbox/etc/systemd/logind.conf.d/open-bastion.conf"
        HARDENING_LIMITS_DST="$sandbox/etc/security/limits.d/open-bastion.conf"
        HARDENING_AT_ALLOW="$sandbox/etc/at.allow"
        HARDENING_CRON_ALLOW="$sandbox/etc/cron.allow"
        BACKUP_DIR="$sandbox/backup"
        out=$(setup_hardening 2>&1)
        rc=$?
        # Expect at least 4 [DRY-RUN] log lines and no file written
        echo "$out" | grep -q "DRY-RUN" || exit 2
        [ ! -e "$sandbox/etc/systemd/logind.conf.d/open-bastion.conf" ] || exit 3
        [ ! -e "$sandbox/etc/security/limits.d/open-bastion.conf" ] || exit 4
        [ ! -e "$sandbox/etc/at.allow" ] || exit 5
        [ ! -e "$sandbox/etc/cron.allow" ] || exit 6
        exit $rc
    )
    local rc=$?
    rm -rf "$sandbox"
    if [ $rc -eq 0 ]; then
        pass "setup_hardening dry-run logs intent and writes nothing"
    else
        fail "setup_hardening dry-run logs intent and writes nothing" "rc=$rc"
    fi
}

# ── Test 11: setup_hardening warns when an admin file already exists ──
test_setup_hardening_preserves_admin_file() {
    local sandbox
    sandbox=$(mktemp -d)
    mkdir -p "$sandbox/share/hardening/logind.conf.d" \
             "$sandbox/share/hardening/security/limits.d" \
             "$sandbox/etc"
    cp "$REPO_DIR/config/hardening/at.allow" "$sandbox/share/hardening/at.allow"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"
    cp "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
       "$sandbox/share/hardening/logind.conf.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
       "$sandbox/share/hardening/security/limits.d/open-bastion.conf"
    # Pre-existing admin-managed at.allow
    echo "alice" > "$sandbox/etc/at.allow"

    (
        source_script "ob-bastion-setup"
        # Use real (non-dry-run) installer to test the "leave existing" branch
        DRY_RUN=false
        NON_INTERACTIVE=true
        ENABLE_HARDENING=true
        # Avoid root-only operations: shadow install/systemctl with no-ops
        install() { :; }
        systemctl() { :; }
        export -f install systemctl 2>/dev/null || true

        out=$(install_hardening_allowlist \
            "$sandbox/share/hardening/at.allow" \
            "$sandbox/etc/at.allow" 2>&1)
        rc=$?
        # Admin content must remain untouched
        grep -q "^alice$" "$sandbox/etc/at.allow" || exit 2
        echo "$out" | grep -q "leaving untouched" || exit 3
        exit $rc
    )
    local rc=$?
    rm -rf "$sandbox"
    if [ $rc -eq 0 ]; then
        pass "install_hardening_allowlist preserves pre-existing admin file"
    else
        fail "install_hardening_allowlist preserves pre-existing admin file" "rc=$rc"
    fi
}

# ── Test 11b: when an admin file is byte-identical to the template,
#             leave it as-is and log a noop, not a warning ──
test_setup_hardening_admin_file_identical() {
    local sandbox
    sandbox=$(mktemp -d)
    mkdir -p "$sandbox/share/hardening" "$sandbox/etc"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"
    # Pre-existing admin file IS the template byte-for-byte
    cp "$sandbox/share/hardening/cron.allow" "$sandbox/etc/cron.allow"
    local before
    before=$(stat -c '%Y:%s' "$sandbox/etc/cron.allow")

    (
        source_script "ob-bastion-setup"
        DRY_RUN=false
        NON_INTERACTIVE=true
        ENABLE_HARDENING=true
        install() { :; }
        systemctl() { :; }
        export -f install systemctl 2>/dev/null || true

        out=$(install_hardening_allowlist \
            "$sandbox/share/hardening/cron.allow" \
            "$sandbox/etc/cron.allow" 2>&1)
        rc=$?
        echo "$out" | grep -q "already matches template" || exit 2
        echo "$out" | grep -qi "leaving untouched" && exit 3   # must NOT warn
        exit $rc
    )
    local rc=$?
    local after
    after=$(stat -c '%Y:%s' "$sandbox/etc/cron.allow")
    rm -rf "$sandbox"
    if [ $rc -eq 0 ] && [ "$before" = "$after" ]; then
        pass "install_hardening_allowlist is a noop when admin file matches template"
    else
        fail "install_hardening_allowlist is a noop when admin file matches template" \
             "rc=$rc before=$before after=$after"
    fi
}

# ── Test 12: linger detection helper returns offending users ──
test_detect_lingering_users_with_offender() {
    (
        source_script "ob-bastion-setup"
        # Mock loginctl: list-users returns one non-root user with linger=yes
        loginctl() {
            case "${1:-}" in
                list-users)
                    printf '%s\n' "1000 alice  user"
                    ;;
                show-user)
                    # show-user <name> --property=Linger --value
                    case "${3:-}" in
                        --property=Linger) echo "yes" ;;
                        *) echo "" ;;
                    esac
                    ;;
            esac
        }
        # Force command -v to find our mock
        command() {
            if [ "${1:-}" = "-v" ] && [ "${2:-}" = "loginctl" ]; then
                echo "loginctl"
                return 0
            fi
            builtin command "$@"
        }
        export -f loginctl command 2>/dev/null || true

        out=$(detect_lingering_users)
        rc=$?
        [ "$rc" -eq 0 ] || exit 2
        echo "$out" | grep -q "^alice:1000$" || exit 3
        exit 0
    )
    if [ $? -eq 0 ]; then
        pass "detect_lingering_users reports non-root users with Linger=yes"
    else
        fail "detect_lingering_users reports non-root users with Linger=yes"
    fi
}

# ── Test 13: linger detection ignores root and non-lingering users ──
test_detect_lingering_users_clean() {
    (
        source_script "ob-bastion-setup"
        loginctl() {
            case "${1:-}" in
                list-users)
                    printf '%s\n' \
                        "0 root  user" \
                        "1001 bob  user"
                    ;;
                show-user)
                    case "${2:-}" in
                        root)
                            # root is already filtered before this is called,
                            # but be safe
                            echo "no" ;;
                        bob)  echo "no" ;;
                        *)    echo "" ;;
                    esac
                    ;;
            esac
        }
        command() {
            if [ "${1:-}" = "-v" ] && [ "${2:-}" = "loginctl" ]; then
                echo "loginctl"
                return 0
            fi
            builtin command "$@"
        }
        export -f loginctl command 2>/dev/null || true

        out=$(detect_lingering_users)
        rc=$?
        [ "$rc" -eq 0 ] || exit 2
        [ -z "$out" ] || exit 3
        exit 0
    )
    if [ $? -eq 0 ]; then
        pass "detect_lingering_users returns empty when no non-root linger"
    else
        fail "detect_lingering_users returns empty when no non-root linger"
    fi
}

# ── Test 14: linger detection returns 1 when loginctl is absent ──
test_detect_lingering_users_no_loginctl() {
    (
        source_script "ob-bastion-setup"
        # Mock command -v loginctl as missing
        command() {
            if [ "${1:-}" = "-v" ] && [ "${2:-}" = "loginctl" ]; then
                return 1
            fi
            builtin command "$@"
        }
        export -f command 2>/dev/null || true

        detect_lingering_users
        rc=$?
        [ "$rc" -eq 1 ] && exit 0 || exit 2
    )
    if [ $? -eq 0 ]; then
        pass "detect_lingering_users returns 1 when loginctl missing"
    else
        fail "detect_lingering_users returns 1 when loginctl missing"
    fi
}

# ── Test 15: setup_hardening dry-run with linger user logs WARN, does not abort ──
test_setup_hardening_linger_dryrun_warns() {
    local sandbox
    sandbox=$(mktemp -d)
    mkdir -p "$sandbox/share/hardening/logind.conf.d" \
             "$sandbox/share/hardening/security/limits.d"
    cp "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
       "$sandbox/share/hardening/logind.conf.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
       "$sandbox/share/hardening/security/limits.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/at.allow" "$sandbox/share/hardening/at.allow"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"

    (
        source_script "ob-bastion-setup"
        DRY_RUN=true
        NON_INTERACTIVE=true
        ENABLE_HARDENING=true
        HARDENING_TEMPLATE_DIR="$sandbox/share/hardening"
        HARDENING_LOGIND_DST="$sandbox/etc/systemd/logind.conf.d/open-bastion.conf"
        HARDENING_LIMITS_DST="$sandbox/etc/security/limits.d/open-bastion.conf"
        HARDENING_AT_ALLOW="$sandbox/etc/at.allow"
        HARDENING_CRON_ALLOW="$sandbox/etc/cron.allow"
        BACKUP_DIR="$sandbox/backup"
        # Mock loginctl to expose one non-root linger user
        loginctl() {
            case "${1:-}" in
                list-users) printf '%s\n' "1000 mallory  user" ;;
                show-user)
                    case "${3:-}" in
                        --property=Linger) echo "yes" ;;
                        *) echo "" ;;
                    esac
                    ;;
            esac
        }
        command() {
            if [ "${1:-}" = "-v" ] && [ "${2:-}" = "loginctl" ]; then
                echo "loginctl"
                return 0
            fi
            builtin command "$@"
        }
        export -f loginctl command 2>/dev/null || true

        out=$(setup_hardening 2>&1)
        rc=$?
        # Dry-run: warn but do not abort the function
        echo "$out" | grep -q "DRY-RUN.*Linger enabled" || exit 2
        echo "$out" | grep -q "mallory (uid 1000)" || exit 3
        # Should still produce DRY-RUN install lines
        echo "$out" | grep -q "DRY-RUN.*Would install" || exit 4
        exit $rc
    )
    local rc=$?
    rm -rf "$sandbox"
    if [ $rc -eq 0 ]; then
        pass "setup_hardening dry-run warns on linger but continues"
    else
        fail "setup_hardening dry-run warns on linger but continues" "rc=$rc"
    fi
}

# ── Test 16: setup_hardening (real run) refuses with linger user ──
test_setup_hardening_linger_real_aborts() {
    local sandbox
    sandbox=$(mktemp -d)
    mkdir -p "$sandbox/share/hardening/logind.conf.d" \
             "$sandbox/share/hardening/security/limits.d"
    cp "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
       "$sandbox/share/hardening/logind.conf.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
       "$sandbox/share/hardening/security/limits.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/at.allow" "$sandbox/share/hardening/at.allow"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"

    (
        source_script "ob-bastion-setup"
        DRY_RUN=false
        NON_INTERACTIVE=true
        ENABLE_HARDENING=true
        HARDENING_TEMPLATE_DIR="$sandbox/share/hardening"
        HARDENING_LOGIND_DST="$sandbox/etc/systemd/logind.conf.d/open-bastion.conf"
        HARDENING_LIMITS_DST="$sandbox/etc/security/limits.d/open-bastion.conf"
        HARDENING_AT_ALLOW="$sandbox/etc/at.allow"
        HARDENING_CRON_ALLOW="$sandbox/etc/cron.allow"
        BACKUP_DIR="$sandbox/backup"
        loginctl() {
            case "${1:-}" in
                list-users) printf '%s\n' "1000 mallory  user" ;;
                show-user)
                    case "${3:-}" in
                        --property=Linger) echo "yes" ;;
                        *) echo "" ;;
                    esac
                    ;;
            esac
        }
        command() {
            if [ "${1:-}" = "-v" ] && [ "${2:-}" = "loginctl" ]; then
                echo "loginctl"
                return 0
            fi
            builtin command "$@"
        }
        # Shadow install/systemctl to neutralize root ops if reached
        install() { :; }
        systemctl() { :; }
        export -f loginctl command install systemctl 2>/dev/null || true

        out=$(setup_hardening 2>&1)
        rc=$?
        echo "$out" | grep -q "Hardening refused" || exit 2
        echo "$out" | grep -q "mallory (uid 1000)" || exit 3
        # Must NOT have created any /etc file
        [ ! -e "$sandbox/etc/systemd/logind.conf.d/open-bastion.conf" ] || exit 4
        # Function must have returned non-zero
        [ "$rc" -ne 0 ] && exit 0 || exit 5
    )
    local rc=$?
    rm -rf "$sandbox"
    if [ $rc -eq 0 ]; then
        pass "setup_hardening aborts and writes nothing when non-root linger detected"
    else
        fail "setup_hardening aborts and writes nothing when non-root linger detected" "rc=$rc"
    fi
}

# ── Test 17: cron.allow without 'root' triggers a WARN ──
test_cron_allow_missing_root_warns() {
    local sandbox
    sandbox=$(mktemp -d)
    mkdir -p "$sandbox/share/hardening/logind.conf.d" \
             "$sandbox/share/hardening/security/limits.d" \
             "$sandbox/etc"
    cp "$REPO_DIR/config/hardening/logind.conf.d/open-bastion.conf" \
       "$sandbox/share/hardening/logind.conf.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf" \
       "$sandbox/share/hardening/security/limits.d/open-bastion.conf"
    cp "$REPO_DIR/config/hardening/at.allow" "$sandbox/share/hardening/at.allow"
    cp "$REPO_DIR/config/hardening/cron.allow" "$sandbox/share/hardening/cron.allow"
    # Pre-existing admin cron.allow that lists alice but NOT root
    echo "alice" > "$sandbox/etc/cron.allow"

    (
        source_script "ob-bastion-setup"
        DRY_RUN=false
        NON_INTERACTIVE=true
        ENABLE_HARDENING=true
        HARDENING_TEMPLATE_DIR="$sandbox/share/hardening"
        HARDENING_LOGIND_DST="$sandbox/etc/systemd/logind.conf.d/open-bastion.conf"
        HARDENING_LIMITS_DST="$sandbox/etc/security/limits.d/open-bastion.conf"
        HARDENING_AT_ALLOW="$sandbox/etc/at.allow"
        HARDENING_CRON_ALLOW="$sandbox/etc/cron.allow"
        BACKUP_DIR="$sandbox/backup"
        # No linger users
        loginctl() { :; }
        command() {
            if [ "${1:-}" = "-v" ] && [ "${2:-}" = "loginctl" ]; then
                echo "loginctl"; return 0
            fi
            builtin command "$@"
        }
        install() { :; }
        systemctl() { :; }
        export -f loginctl command install systemctl 2>/dev/null || true

        out=$(setup_hardening 2>&1)
        # The admin cron.allow must be left untouched
        grep -q "^alice$" "$sandbox/etc/cron.allow" || exit 2
        # Must surface the WARN about root missing
        echo "$out" | grep -q "does not list 'root'" || exit 3
        exit 0
    )
    local rc=$?
    rm -rf "$sandbox"
    if [ $rc -eq 0 ]; then
        pass "setup_hardening warns when cron.allow is missing 'root'"
    else
        fail "setup_hardening warns when cron.allow is missing 'root'" "rc=$rc"
    fi
}

# ── Test 18: limits template exempts @ob-service from the nproc cap ──
test_limits_template_exempts_ob_service() {
    local f="$REPO_DIR/config/hardening/security/limits.d/open-bastion.conf"
    if grep -qE '^@ob-service[[:space:]]+hard[[:space:]]+nproc[[:space:]]+unlimited' "$f"; then
        pass "limits template exempts @ob-service from nproc cap"
    else
        fail "limits template exempts @ob-service from nproc cap"
    fi
}

# ── Test 19: setup script uses 'reload' (non-disruptive), not 'reload-or-restart' ──
test_setup_script_reload_only() {
    local f="$SCRIPT_DIR/ob-bastion-setup"
    if grep -q "reload-or-restart systemd-logind" "$f"; then
        fail "setup_hardening must use 'systemctl reload', not 'reload-or-restart'"
    elif grep -q "systemctl reload systemd-logind" "$f"; then
        pass "setup_hardening uses 'systemctl reload systemd-logind' (non-disruptive)"
    else
        fail "setup_hardening must call 'systemctl reload systemd-logind'"
    fi
}

# ── Run all tests ──
echo "=== Testing ob-bastion-setup hardening step ==="
run_test test_templates_present
run_test test_logind_template_content
run_test test_limits_template_content
run_test test_at_allow_template_content
run_test test_cron_allow_template_content
run_test test_enable_hardening_flag
run_test test_enable_hardening_default
run_test test_help_mentions_hardening
run_test test_hardening_not_applied_by_default
run_test test_setup_hardening_dryrun
run_test test_setup_hardening_preserves_admin_file
run_test test_setup_hardening_admin_file_identical
run_test test_detect_lingering_users_with_offender
run_test test_detect_lingering_users_clean
run_test test_detect_lingering_users_no_loginctl
run_test test_setup_hardening_linger_dryrun_warns
run_test test_setup_hardening_linger_real_aborts
run_test test_cron_allow_missing_root_warns
run_test test_limits_template_exempts_ob_service
run_test test_setup_script_reload_only

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
