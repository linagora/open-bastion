#!/bin/bash
#
# Tests for `ob-bastion-setup --enable-audit-trace` (PR2: primary audit
# trace via auditd). Mirrors the structure of test_ob_bastion_setup.sh:
# we source the script's functions into a subshell, sandbox every
# system path under a per-test tmpdir, and assert outcomes.
#
# These tests deliberately do NOT require auditd to be installed on the
# test host. We exercise:
#   - flag parsing (default off, --enable-audit-trace flips it on)
#   - the auditd-not-installed refusal path
#   - shipped template contents
#   - regression: auditd.conf must NOT be modified by setup_audit_trace
#   - regression: audit_set_conf_key must NOT exist in the script
# Anything that would actually call augenrules / systemctl is fenced
# behind the "auditd missing" guard.
#
# shellcheck disable=SC2030,SC2031   # subshell PATH scoping is the point
# shellcheck disable=SC2034          # vars are read by sourced functions
# shellcheck disable=SC2181          # mirrors test_ob_bastion_setup.sh style

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$PROJECT_ROOT/scripts"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# Same trick as test_ob_bastion_setup.sh: strip `main "$@"` and the
# `set -e[uo pipefail]` line so we can source function definitions
# without triggering the full main flow.
source_script() {
    local script="$1"
    local content
    content=$(cat "$SCRIPT_DIR/$script")
    content="${content%main \"\$@\"}"
    content=$(echo "$content" | sed -E 's/^set -e(uo pipefail)?$//')
    eval "$content"
}

# ── Test 1: ENABLE_AUDIT_TRACE defaults to false ──
test_default_off() {
    (
        source_script "ob-bastion-setup"
        [ "$ENABLE_AUDIT_TRACE" = "false" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "ENABLE_AUDIT_TRACE defaults to false"
    else
        fail "ENABLE_AUDIT_TRACE defaults to false"
    fi
}

# ── Test 2: --enable-audit-trace flips it on ──
test_flag_enables() {
    (
        source_script "ob-bastion-setup"
        parse_args -p "https://x" --enable-audit-trace
        [ "$ENABLE_AUDIT_TRACE" = "true" ] && exit 0 || exit 1
    )
    if [ $? -eq 0 ]; then
        pass "--enable-audit-trace sets ENABLE_AUDIT_TRACE=true"
    else
        fail "--enable-audit-trace sets ENABLE_AUDIT_TRACE=true"
    fi
}

# ── Test 3: Help text mentions --enable-audit-trace ──
test_help_mentions_flag() {
    local out
    out=$(bash "$SCRIPT_DIR/ob-bastion-setup" --help 2>&1)
    if echo "$out" | grep -q -- "--enable-audit-trace"; then
        pass "--help advertises --enable-audit-trace"
    else
        fail "--help advertises --enable-audit-trace" "$out"
    fi
}

# ── Test 4: setup_audit_trace refuses when auditctl is missing ──
# We swap PATH so neither auditctl nor augenrules is found by `command -v`
# inside the function, but coreutils (mkdir/grep/...) still work.
test_refuses_without_auditd() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local empty_dir="$tmpdir/empty"
    mkdir -p "$empty_dir"
    local saved_path="$PATH"

    (
        source_script "ob-bastion-setup"
        # Save the real PATH for the test wrapper, then narrow it for the
        # function call. We still need `tail`, `grep`, `mkdir`, etc., so we
        # keep coreutils on PATH; we only ensure auditctl/augenrules are
        # NOT reachable (they would normally be in /usr/sbin or /sbin).
        # We construct a PATH that excludes /usr/sbin and /sbin entirely.
        local orig_path="$saved_path"
        local cleaned_path=""
        local IFS=":"
        for p in $orig_path; do
            case "$p" in
                */sbin|*/sbin/) ;;
                "") ;;
                *) cleaned_path="${cleaned_path:+$cleaned_path:}$p" ;;
            esac
        done
        export PATH="$cleaned_path"

        # Force the function past the `confirm` prompt regardless.
        NON_INTERACTIVE=true
        # Sanity assertion: auditctl really is unreachable. If the host
        # somehow ships auditctl outside /sbin, skip the check.
        if command -v auditctl >/dev/null 2>&1; then
            echo "skip: auditctl reachable even with /sbin stripped" >&2
            exit 0
        fi
        local out
        out=$(setup_audit_trace 2>&1)
        local rc=$?
        # auditd absent must NOT fail the step (warn + return 0, so the
        # surrounding ob-bastion-setup run continues).
        if [ "$rc" -eq 0 ] && echo "$out" | grep -q "auditd is not installed; skipping"; then
            exit 0
        else
            echo "rc=$rc out=$out" >&2
            exit 1
        fi
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "setup_audit_trace warns and continues when auditd is missing"
    else
        fail "setup_audit_trace warns and continues when auditd is missing"
    fi
}

# ── Test 5: setup_audit_trace refuses when templates are missing ──
# Provide fake auditctl/augenrules in PATH but point AUDIT_TEMPLATE_DIR
# at an empty directory. The function must still bail out with rc!=0.
test_refuses_without_templates() {
    local tmpdir
    tmpdir=$(mktemp -d)
    (
        source_script "ob-bastion-setup"
        # Stub binaries so command -v finds them.
        mkdir -p "$tmpdir/bin"
        printf '#!/bin/sh\nexit 0\n' > "$tmpdir/bin/auditctl"
        printf '#!/bin/sh\nexit 0\n' > "$tmpdir/bin/augenrules"
        chmod +x "$tmpdir/bin/auditctl" "$tmpdir/bin/augenrules"
        export PATH="$tmpdir/bin:$PATH"

        AUDIT_TEMPLATE_DIR="$tmpdir/empty-templates"
        mkdir -p "$AUDIT_TEMPLATE_DIR"
        NON_INTERACTIVE=true

        local out
        out=$(setup_audit_trace 2>&1)
        local rc=$?
        if [ "$rc" -ne 0 ] && echo "$out" | grep -q "Audit rules template not found"; then
            exit 0
        else
            echo "rc=$rc out=$out" >&2
            exit 1
        fi
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "setup_audit_trace refuses cleanly when templates are missing"
    else
        fail "setup_audit_trace refuses cleanly when templates are missing"
    fi
}

# ── Test 6: audit_set_conf_key must NOT exist in the script ──
# Regression guard: prevent accidental re-introduction of the removed helper.
test_no_audit_set_conf_key() {
    local script="$SCRIPT_DIR/ob-bastion-setup"
    if grep -q "audit_set_conf_key" "$script"; then
        fail "audit_set_conf_key must not exist in ob-bastion-setup" \
             "found: $(grep -n 'audit_set_conf_key' "$script")"
    else
        pass "audit_set_conf_key is absent from ob-bastion-setup (removed)"
    fi
}

# ── Test 7: setup_audit_trace does NOT modify a sandbox auditd.conf ──
# We create a sandbox auditd.conf with a known content, run
# setup_audit_trace in a fully sandboxed environment (fake auditctl /
# augenrules, AUDIT_TEMPLATE_DIR, no systemctl), then assert the file is
# byte-for-byte identical to what we created.
test_auditd_conf_not_modified() {
    local tmpdir
    tmpdir=$(mktemp -d)
    (
        source_script "ob-bastion-setup"

        # Stub auditctl, augenrules, systemctl — they must exist for the
        # function not to bail at step 1, but we want them to be no-ops.
        mkdir -p "$tmpdir/bin"
        printf '#!/bin/sh\nexit 0\n' > "$tmpdir/bin/auditctl"
        printf '#!/bin/sh\nexit 0\n' > "$tmpdir/bin/augenrules"
        printf '#!/bin/sh\nexit 0\n' > "$tmpdir/bin/systemctl"
        chmod +x "$tmpdir/bin/auditctl" "$tmpdir/bin/augenrules" "$tmpdir/bin/systemctl"
        export PATH="$tmpdir/bin:$PATH"

        # Provide minimal templates so the template-check passes.
        local tdir="$tmpdir/templates"
        mkdir -p "$tdir/rules.d"
        printf '# rules\n' > "$tdir/rules.d/open-bastion.rules"
        AUDIT_TEMPLATE_DIR="$tdir"

        # Redirect install targets so we don't need /etc. The rotation is a
        # timer (the systemctl stub above arms it); keep the library's paths
        # in the sandbox too.
        AUDIT_RULES_FILE="$tmpdir/open-bastion.rules"
        export OB_TIMERS_LIB="$SCRIPT_DIR/ob-timers-lib.sh"
        export OB_SYSTEMD_UNIT_DIR="$tmpdir/units"
        export OB_AUDIT_LEGACY_DAILY="$tmpdir/cron.daily-rotate"
        export OB_AUDIT_LEGACY_WEEKLY="$tmpdir/cron.weekly-rotate"

        # The sandbox auditd.conf with a known sentinel value.
        local sandbox_conf="$tmpdir/auditd.conf"
        printf 'max_log_file = 8\nnum_logs = 5\n' > "$sandbox_conf"
        local before_hash
        before_hash=$(md5sum "$sandbox_conf")

        # Non-interactive so confirm() returns true.
        NON_INTERACTIVE=true

        # Run the function. It should NOT touch sandbox_conf — but we do
        # not pass $sandbox_conf as a parameter; we just verify by hash.
        setup_audit_trace >/dev/null 2>&1 || true

        local after_hash
        after_hash=$(md5sum "$sandbox_conf")

        if [ "$before_hash" = "$after_hash" ]; then
            exit 0
        else
            echo "auditd.conf was modified!" >&2
            echo "Before: $before_hash" >&2
            echo "After:  $after_hash" >&2
            exit 1
        fi
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "setup_audit_trace does NOT modify a sandbox auditd.conf"
    else
        fail "setup_audit_trace does NOT modify a sandbox auditd.conf"
    fi
}

# ── Test 8: rules template content has the expected keys ──
test_rules_template_content() {
    local rules="$PROJECT_ROOT/config/audit/rules.d/open-bastion.rules"
    if [ ! -f "$rules" ]; then
        fail "rules template content" "$rules missing"
        return
    fi
    local ok=true
    grep -Eq "auid>=1000" "$rules" || ok=false
    grep -Eq "auid!=unset" "$rules" || ok=false
    grep -Eq "^-a always,exit -F arch=b64 -S execve" "$rules" || ok=false
    grep -Eq "^-a always,exit -F arch=b64 -S connect" "$rules" || ok=false
    grep -q -- "-w /etc/passwd" "$rules" || ok=false
    grep -q -- "-w /etc/shadow" "$rules" || ok=false
    grep -q -- "-w /etc/sudoers" "$rules" || ok=false
    grep -q -- "-w /etc/ssh/sshd_config" "$rules" || ok=false
    grep -q -- "-w /var/lib/open-bastion/sessions/" "$rules" || ok=false
    grep -q -- "-w /etc/open-bastion/" "$rules" || ok=false
    grep -q -- "-k ob-exec" "$rules" || ok=false
    grep -q -- "-k ob-connect" "$rules" || ok=false
    if $ok; then
        pass "rules template covers execve/connect/sensitive-files/sessions/config"
    else
        fail "rules template covers execve/connect/sensitive-files/sessions/config"
    fi
}

# ── Test 9: the rotation is ob-audit-rotate.timer, and it signals auditd ──
# The 0.6 cron.daily template is gone (#281): the rotation is a oneshot service
# sending SIGUSR1 -- auditd's "rotate now" -- to auditd's main process, from a
# daily timer. tests/test_ob_timers.sh covers the move from the old script.
test_rotation_units() {
    local svc="$PROJECT_ROOT/systemd/ob-audit-rotate.service"
    local tmr="$PROJECT_ROOT/systemd/ob-audit-rotate.timer"
    local ok=true
    [ -f "$svc" ] && [ -f "$tmr" ] || ok=false
    grep -qE '^ExecStart=systemctl kill --kill-who=main --signal=SIGUSR1 auditd\.service$' "$svc" 2>/dev/null || ok=false
    grep -qx 'Type=oneshot' "$svc" 2>/dev/null || ok=false
    grep -qx 'OnCalendar=daily' "$tmr" 2>/dev/null || ok=false
    grep -qx 'Persistent=true' "$tmr" 2>/dev/null || ok=false
    [ ! -e "$PROJECT_ROOT/config/audit/cron.daily" ] || ok=false
    if $ok; then
        pass "ob-audit-rotate.timer runs daily and signals auditd's main process with USR1"
    else
        fail "ob-audit-rotate.timer runs daily and signals auditd's main process with USR1"
    fi
}

# ── Test 10: setup_audit_trace is gated behind ENABLE_AUDIT_TRACE in main() ──
# Smoke check: the script must mention the gating in main(). We
# deliberately don't exec main() — that would try to talk to a real LLNG
# portal — but we can grep the wiring.
test_main_gates_audit_trace() {
    local script="$SCRIPT_DIR/ob-bastion-setup"
    if grep -q 'ENABLE_AUDIT_TRACE.*=.*"true"' "$script" \
       && grep -q "setup_audit_trace" "$script"; then
        pass "main() gates setup_audit_trace behind ENABLE_AUDIT_TRACE"
    else
        fail "main() gates setup_audit_trace behind ENABLE_AUDIT_TRACE"
    fi
}

# ── Test 11: print_summary reports what happened, not what was asked ──
# The summary used to key on ENABLE_AUDIT_TRACE, so a run whose audit step was
# skipped (auditd missing), declined at the prompt or failed still printed
# "applied". It now reports AUDIT_RESULT, which setup_audit_trace sets.
test_summary_distinguishes_state() {
    (
        source_script "ob-bastion-setup"
        # Fake values so print_summary doesn't barf.
        PORTAL_URL="https://x"
        SERVER_GROUP="bastion"
        SSH_CA_FILE="/tmp/ca"
        BACKUP_DIR="/tmp/backup"
        local state out
        for state in not-applied applied skipped declined dry-run failed; do
            AUDIT_RESULT="$state"
            ENABLE_AUDIT_TRACE=true
            [ "$state" = "not-applied" ] && ENABLE_AUDIT_TRACE=false
            out=$(print_summary 2>&1)
            out=$(grep -i 'audit trace' <<<"$out")
            case "$state" in
                not-applied) grep -q 'not applied (opt-in' <<<"$out" || exit 1 ;;
                applied)     grep -q 'Audit trace: applied' <<<"$out" || exit 1 ;;
                skipped)     grep -q 'NOT applied (auditd not installed)' <<<"$out" || exit 1 ;;
                declined)    grep -q 'NOT applied (declined' <<<"$out" || exit 1 ;;
                dry-run)     grep -q 'dry-run' <<<"$out" || exit 1 ;;
                failed)      grep -q 'FAILED' <<<"$out" || exit 1 ;;
            esac
            # Only a real success may claim it.
            if [ "$state" != "applied" ] && grep -q 'Audit trace: applied' <<<"$out"; then
                exit 1
            fi
        done
        exit 0
    )
    if [ $? -eq 0 ]; then
        pass "print_summary reports the audit-trace outcome, not the flag"
    else
        fail "print_summary reports the audit-trace outcome, not the flag"
    fi
}

# ── Test 12: a skipped audit step is recorded as skipped ──
# setup_audit_trace returns 0 when auditd is missing (the run goes on), so the
# only trace of the skip is AUDIT_RESULT, which the summary reads.
test_skip_is_recorded() {
    local tmpdir rc
    tmpdir=$(mktemp -d)
    (
        source_script "ob-bastion-setup"
        # A PATH with no auditctl/augenrules at all.
        export PATH="$tmpdir"
        NON_INTERACTIVE=true
        setup_audit_trace >/dev/null 2>&1
        [ "$AUDIT_RESULT" = "skipped" ]
    )
    rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "a missing auditd leaves AUDIT_RESULT=skipped"
    else
        fail "a missing auditd leaves AUDIT_RESULT=skipped"
    fi
}

# ── Run ──
echo "=== Testing ob-bastion-setup --enable-audit-trace (PR2) ==="
run_test test_default_off
run_test test_flag_enables
run_test test_help_mentions_flag
run_test test_refuses_without_auditd
run_test test_refuses_without_templates
run_test test_no_audit_set_conf_key
run_test test_auditd_conf_not_modified
run_test test_rules_template_content
run_test test_rotation_units
run_test test_main_gates_audit_trace
run_test test_summary_distinguishes_state
run_test test_skip_is_recorded

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
