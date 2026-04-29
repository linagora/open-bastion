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
#   - the audit_set_conf_key idempotent in-place edit
#   - shipped template contents
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
        if [ "$rc" -ne 0 ] && echo "$out" | grep -q "auditd is not installed"; then
            exit 0
        else
            echo "rc=$rc out=$out" >&2
            exit 1
        fi
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "setup_audit_trace refuses cleanly when auditd is missing"
    else
        fail "setup_audit_trace refuses cleanly when auditd is missing"
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

# ── Test 6: audit_set_conf_key replaces an existing key in place ──
test_conf_key_replace_existing() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local conf="$tmpdir/auditd.conf"
    cat > "$conf" <<EOF
# auditd.conf
log_file = /var/log/audit/audit.log
max_log_file = 8
num_logs = 5
log_format = ENRICHED
EOF
    (
        source_script "ob-bastion-setup"
        audit_set_conf_key "$conf" "max_log_file" "50"
        audit_set_conf_key "$conf" "num_logs" "7"
        # Replacing twice must be idempotent.
        audit_set_conf_key "$conf" "max_log_file" "50"
        grep -q "^max_log_file = 50$" "$conf" || exit 1
        grep -q "^num_logs = 7$" "$conf" || exit 1
        # Original unrelated keys preserved.
        grep -q "^log_file = /var/log/audit/audit.log$" "$conf" || exit 1
        grep -q "^log_format = ENRICHED$" "$conf" || exit 1
        # Old values gone.
        grep -q "^max_log_file = 8$" "$conf" && exit 1
        grep -q "^num_logs = 5$" "$conf" && exit 1
        # File should not have grown duplicate keys.
        local cnt
        cnt=$(grep -c "^max_log_file " "$conf")
        [ "$cnt" -eq 1 ] || exit 1
        cnt=$(grep -c "^num_logs " "$conf")
        [ "$cnt" -eq 1 ] || exit 1
        exit 0
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "audit_set_conf_key replaces existing key idempotently"
    else
        fail "audit_set_conf_key replaces existing key idempotently"
    fi
}

# ── Test 7: audit_set_conf_key appends when key is absent ──
test_conf_key_append_absent() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local conf="$tmpdir/auditd.conf"
    cat > "$conf" <<EOF
log_file = /var/log/audit/audit.log
log_format = ENRICHED
EOF
    (
        source_script "ob-bastion-setup"
        audit_set_conf_key "$conf" "max_log_file_action" "ROTATE"
        grep -q "^max_log_file_action = ROTATE$" "$conf" || exit 1
        # Pre-existing keys untouched.
        grep -q "^log_file = /var/log/audit/audit.log$" "$conf" || exit 1
        # Single occurrence after multiple calls.
        audit_set_conf_key "$conf" "max_log_file_action" "ROTATE"
        local cnt
        cnt=$(grep -c "^max_log_file_action " "$conf")
        [ "$cnt" -eq 1 ] || exit 1
        exit 0
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "audit_set_conf_key appends absent key (and stays idempotent)"
    else
        fail "audit_set_conf_key appends absent key (and stays idempotent)"
    fi
}

# ── Test 8: audit_set_conf_key does not touch commented lines ──
test_conf_key_skips_comments() {
    local tmpdir
    tmpdir=$(mktemp -d)
    local conf="$tmpdir/auditd.conf"
    cat > "$conf" <<EOF
# max_log_file = 8
# default-shipped commented example
EOF
    (
        source_script "ob-bastion-setup"
        audit_set_conf_key "$conf" "max_log_file" "50"
        # The commented line must remain.
        grep -q "^# max_log_file = 8$" "$conf" || exit 1
        # The new live line was appended, not substituted into the comment.
        grep -q "^max_log_file = 50$" "$conf" || exit 1
        exit 0
    )
    local rc=$?
    rm -rf "$tmpdir"
    if [ $rc -eq 0 ]; then
        pass "audit_set_conf_key leaves commented lines alone"
    else
        fail "audit_set_conf_key leaves commented lines alone"
    fi
}

# ── Test 9: rules template content has the expected keys ──
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

# ── Test 10: cron.daily template is a valid /bin/sh script that calls SIGUSR1 ──
test_cron_template_content() {
    local cron="$PROJECT_ROOT/config/audit/cron.daily/open-bastion-audit-rotate"
    if [ ! -f "$cron" ]; then
        fail "cron template content" "$cron missing"
        return
    fi
    local ok=true
    head -1 "$cron" | grep -q "^#!/bin/sh" || ok=false
    grep -q "USR1" "$cron" || ok=false
    [ -x "$cron" ] || ok=false
    # Must pass `bash -n` cleanly.
    bash -n "$cron" 2>/dev/null || ok=false
    if $ok; then
        pass "cron.daily template is valid (shebang, executable, signals USR1)"
    else
        fail "cron.daily template is valid (shebang, executable, signals USR1)"
    fi
}

# ── Test 11: setup_audit_trace is gated behind ENABLE_AUDIT_TRACE in main() ──
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

# ── Test 12: print_summary distinguishes applied vs not applied ──
test_summary_distinguishes_state() {
    (
        source_script "ob-bastion-setup"
        # Fake values so print_summary doesn't barf.
        PORTAL_URL="https://x"
        SERVER_GROUP="bastion"
        SSH_CA_FILE="/tmp/ca"
        BACKUP_DIR="/tmp/backup"
        ENABLE_AUDIT_TRACE=false
        local out_off
        out_off=$(print_summary 2>&1)
        ENABLE_AUDIT_TRACE=true
        local out_on
        out_on=$(print_summary 2>&1)
        echo "$out_off" | grep -qi "audit trace" || exit 1
        echo "$out_off" | grep -qi "not applied" || exit 1
        echo "$out_on" | grep -qi "applied" || exit 1
        exit 0
    )
    if [ $? -eq 0 ]; then
        pass "print_summary reports audit-trace state"
    else
        fail "print_summary reports audit-trace state"
    fi
}

# ── Run ──
echo "=== Testing ob-bastion-setup --enable-audit-trace (PR2) ==="
run_test test_default_off
run_test test_flag_enables
run_test test_help_mentions_flag
run_test test_refuses_without_auditd
run_test test_refuses_without_templates
run_test test_conf_key_replace_existing
run_test test_conf_key_append_absent
run_test test_conf_key_skips_comments
run_test test_rules_template_content
run_test test_cron_template_content
run_test test_main_gates_audit_trace
run_test test_summary_distinguishes_state

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
