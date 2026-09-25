#!/bin/bash
# test_ob_timers.sh
#
# The cron jobs of 0.6 are systemd timers now (#281):
#
#   /etc/cron.d/open-bastion-krl               -> ob-krl-refresh.timer
#   /etc/cron.daily/open-bastion-audit-rotate  -> ob-audit-rotate.timer
#
# Two callers move a host from one to the other -- the setup when it runs
# again, ob-post-upgrade when an upgrade is finished -- through one library,
# scripts/ob-timers-lib.sh. What must hold, whichever runs:
#
#   1. the interval the old job had is the interval the timer gets;
#   2. the old job is removed only once the timer is enabled AND active, so a
#      host is never left with neither;
#   3. a job an administrator reshaped is not guessed at: it stays, and says so;
#   4. a drop-in that is not ours is never overwritten;
#   5. a new run without --krl-refresh-interval keeps the schedule the host has;
#   6. --dry-run changes nothing and says what would change.
#
# systemctl is a stand-in keeping unit state in files (lib_fake_systemctl.sh);
# every system path is redirected under a temporary directory, so this runs
# unprivileged.
#
# shellcheck disable=SC1090,SC1091  # the sandbox env and the library are per-test paths
# shellcheck disable=SC2034         # variables are read by the sourced setup functions
# shellcheck disable=SC2016         # single-quoted $ is literal file content
# shellcheck disable=SC2329         # install() shadows the command inside the setup

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$ROOT_DIR/tests"
LIB="$ROOT_DIR/scripts/ob-timers-lib.sh"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    if ! declare -F "$1" >/dev/null; then
        fail "$1 is listed as a test but is not defined"
        return
    fi
    "$@"
}

# shellcheck source=tests/lib_fake_systemctl.sh
. "$TESTS_DIR/lib_fake_systemctl.sh"
# shellcheck source=tests/lib_setup_script.sh
. "$TESTS_DIR/lib_setup_script.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK" "$SETUP_LINK_DIR"' EXIT

# The cron file ob-bastion-setup 0.6 wrote, with a given interval.
legacy_krl_cron() {
    cat > "$1" <<EOF
# Open Bastion KRL refresh (Mode E - Maximum Security)
# Downloads Key Revocation List every $2 minutes
*/$2 * * * * root /usr/local/bin/open-bastion-refresh-krl >/dev/null 2>&1
EOF
}

# The refresh script it generated (the part the library looks for).
legacy_krl_script() {
    printf '#!/bin/bash\ncurl -sf "https://sso.example.com/ssh/revoked" -o "$tmp"\n' > "$1"
}

# The 0.6 audit rotation, as installed from its template.
legacy_audit() {
    cat > "$1" <<'EOF'
#!/bin/sh
# Open Bastion: rotate auditd logs daily so that with num_logs=7
# (configured in /etc/audit/auditd.conf) we keep ~1 week of history.
# Installed by `ob-bastion-setup --enable-audit-trace`.
systemctl kill -s USR1 auditd 2>/dev/null || true
EOF
    chmod 755 "$1"
}

# A sandbox: fake systemctl first in PATH, every path the library touches
# redirected. Prints the directory; the caller sources the variables file.
sandbox() {
    local d="$WORK/$1"
    rm -rf "$d"
    mkdir -p "$d/etc/cron.d" "$d/etc/cron.daily" "$d/etc/cron.weekly" \
             "$d/usr/local/bin" "$d/units"
    fake_systemctl "$d/sysd"
    cat > "$d/env" <<EOF
export PATH="$d/sysd/bin:\$PATH"
export OB_SYSTEMD_UNIT_DIR="$d/units"
export OB_KRL_LEGACY_CRON="$d/etc/cron.d/open-bastion-krl"
export OB_KRL_LEGACY_SCRIPT="$d/usr/local/bin/open-bastion-refresh-krl"
export OB_AUDIT_LEGACY_DAILY="$d/etc/cron.daily/open-bastion-audit-rotate"
export OB_AUDIT_LEGACY_WEEKLY="$d/etc/cron.weekly/open-bastion-audit-rotate"
export OB_TIMERS_LIB="$LIB"
EOF
    printf '%s' "$d"
}

KRL_DROPIN_REL="units/ob-krl-refresh.timer.d/schedule.conf"
AUDIT_DROPIN_REL="units/ob-audit-rotate.timer.d/schedule.conf"

echo "=== systemd timers replacing the 0.6 cron jobs (#281) ==="

# ── 1. The old job's interval is parsed, and only the shape the setup wrote ──
test_legacy_interval_parsing() {
    local d bad="" n rc
    d=$(sandbox parse)
    (
        . "$d/env"; . "$LIB"
        f="$OB_KRL_LEGACY_CRON"
        for n in 1 5 10 30 59 60; do
            legacy_krl_cron "$f" "$n"
            ob_krl_legacy_interval && [ "$OB_TIMERS_INTERVAL" = "$n" ] || echo "bad:$n"
        done
        # Shapes that cannot be translated faithfully are reported, not guessed.
        for line in '*/10 8-18 * * * root /usr/local/bin/open-bastion-refresh-krl' \
                    '0,30 * * * * root /usr/local/bin/open-bastion-refresh-krl' \
                    '*/10 * * * * alice /usr/local/bin/open-bastion-refresh-krl' \
                    '*/0 * * * * root /usr/local/bin/open-bastion-refresh-krl' \
                    '*/90 * * * * root /usr/local/bin/open-bastion-refresh-krl' \
                    '*/10 * * * * root /usr/local/bin/something-else'; do
            printf '%s\n' "$line" > "$f"
            rc=0; ob_krl_legacy_interval || rc=$?
            [ "$rc" -eq 1 ] || echo "accepted:$line"
        done
        # Two jobs: which one would the timer be? Not ours to pick.
        { legacy_krl_cron /dev/stdout 10; echo '*/5 * * * * root /usr/local/bin/open-bastion-refresh-krl'; } > "$f"
        rc=0; ob_krl_legacy_interval || rc=$?
        [ "$rc" -eq 1 ] || echo "accepted:two-jobs"
        # MAILTO= and comments are not jobs.
        { echo 'MAILTO=root'; legacy_krl_cron /dev/stdout 15; } > "$f"
        ob_krl_legacy_interval && [ "$OB_TIMERS_INTERVAL" = 15 ] || echo "bad:mailto"
        rm -f "$f"
        rc=0; ob_krl_legacy_interval || rc=$?
        [ "$rc" -eq 2 ] || echo "absent:rc=$rc"
    ) > "$WORK/parse.out" 2>&1
    bad=$(tr '\n' ' ' < "$WORK/parse.out")
    if [ -z "${bad// }" ]; then
        pass "*/N for N in 1..60 is carried over; any other shape is reported, not guessed"
    else
        fail "legacy interval parsing" "$bad"
    fi
}

# ── 2. Migration: same interval, then the old job goes ───────────────────────
test_krl_migration() {
    local d bad=""
    d=$(sandbox krl-migrate)
    (
        . "$d/env"; . "$LIB"
        legacy_krl_cron "$OB_KRL_LEGACY_CRON" 10
        legacy_krl_script "$OB_KRL_LEGACY_SCRIPT"
        ob_krl_timer_setup || { echo "rc:$OB_TIMERS_MSG"; exit; }
        [ "$OB_TIMERS_SCHEDULE" = "every 10 min" ] || echo "schedule:$OB_TIMERS_SCHEDULE"
    ) > "$WORK/krl.out" 2>&1
    [ -s "$WORK/krl.out" ] && bad="$bad $(tr '\n' ' ' < "$WORK/krl.out")"
    grep -qxF '# Open Bastion timer schedule' "$d/$KRL_DROPIN_REL" 2>/dev/null || bad="$bad no-mark"
    # An empty OnCalendar= first: a drop-in otherwise ADDS a trigger to the
    # packaged */30 instead of replacing it.
    [ "$(grep '^OnCalendar=' "$d/$KRL_DROPIN_REL" 2>/dev/null | tr '\n' ' ')" = "OnCalendar= OnCalendar=*:0/10 " ] \
        || bad="$bad dropin:$(tr '\n' '|' < "$d/$KRL_DROPIN_REL" 2>/dev/null)"
    [ -e "$d/sysd/state/ob-krl-refresh.timer.enabled" ] || bad="$bad not-enabled"
    [ -e "$d/sysd/state/ob-krl-refresh.timer.active" ] || bad="$bad not-active"
    [ ! -e "$d/etc/cron.d/open-bastion-krl" ] || bad="$bad cron-left"
    [ ! -e "$d/usr/local/bin/open-bastion-refresh-krl" ] || bad="$bad script-left"
    # daemon-reload before the (re)start, or the drop-in is not seen.
    [ "$(grep -nE '^daemon-reload' "$d/sysd/calls" | head -1 | cut -d: -f1)" -lt \
      "$(grep -nE '^restart ob-krl-refresh.timer' "$d/sysd/calls" | head -1 | cut -d: -f1)" ] 2>/dev/null \
        || bad="$bad no-reload-before-restart"
    if [ -z "$bad" ]; then
        pass "a */10 cron job becomes the timer every 10 min, then the job and its script go"
    else
        fail "KRL cron job migration" "$bad"
    fi
}

# ── 3. Never neither: the job stays if the timer does not run ────────────────
test_never_neither() {
    local d knob bad=""
    for knob in fail-enable fail-start; do
        d=$(sandbox "never-$knob")
        touch "$d/sysd/$knob"
        (
                . "$d/env"; . "$LIB"
            legacy_krl_cron "$OB_KRL_LEGACY_CRON" 10
            legacy_krl_script "$OB_KRL_LEGACY_SCRIPT"
            legacy_audit "$OB_AUDIT_LEGACY_DAILY"
            ob_krl_timer_setup && echo "krl-rc0"
            grep -q 'kept' <<<"$OB_TIMERS_WARN" || echo "krl-no-warning"
            ob_audit_timer_setup && echo "audit-rc0"
            grep -q 'kept' <<<"$OB_TIMERS_WARN" || echo "audit-no-warning"
        ) > "$WORK/never.out" 2>&1
        [ -s "$WORK/never.out" ] && bad="$bad $knob:$(tr '\n' ' ' < "$WORK/never.out")"
        [ -e "$d/etc/cron.d/open-bastion-krl" ] || bad="$bad $knob:cron-removed"
        [ -e "$d/usr/local/bin/open-bastion-refresh-krl" ] || bad="$bad $knob:script-removed"
        [ -e "$d/etc/cron.daily/open-bastion-audit-rotate" ] || bad="$bad $knob:audit-removed"
    done
    if [ -z "$bad" ]; then
        pass "when the timer cannot be enabled or started, the cron job is kept and the call fails"
    else
        fail "never neither" "$bad"
    fi
}

# ── 4. A reshaped job stays, next to the timer ───────────────────────────────
test_reshaped_job_kept() {
    local d bad=""
    d=$(sandbox reshaped)
    (
        . "$d/env"; . "$LIB"
        echo '*/5 8-18 * * 1-5 root /usr/local/bin/open-bastion-refresh-krl' > "$OB_KRL_LEGACY_CRON"
        legacy_krl_script "$OB_KRL_LEGACY_SCRIPT"
        ob_krl_timer_setup || echo "rc:$OB_TIMERS_MSG"
        grep -q 'left in place' <<<"$OB_TIMERS_WARN" || echo "no-warning"
        [ "$OB_TIMERS_SCHEDULE" = "every 30 min" ] || echo "schedule:$OB_TIMERS_SCHEDULE"
    ) > "$WORK/reshaped.out" 2>&1
    [ -s "$WORK/reshaped.out" ] && bad="$bad $(tr '\n' ' ' < "$WORK/reshaped.out")"
    [ -e "$d/etc/cron.d/open-bastion-krl" ] || bad="$bad cron-removed"
    [ -e "$d/sysd/state/ob-krl-refresh.timer.active" ] || bad="$bad timer-not-armed"
    [ ! -e "$d/$KRL_DROPIN_REL" ] || bad="$bad guessed-a-dropin"
    if [ -z "$bad" ]; then
        pass "a cron job with a reshaped schedule is kept and reported, not translated"
    else
        fail "reshaped job" "$bad"
    fi
}

# ── 5. A drop-in that is not ours is never overwritten ───────────────────────
test_foreign_dropin_untouched() {
    local d bad="" before
    d=$(sandbox foreign)
    mkdir -p "$d/units/ob-krl-refresh.timer.d"
    printf '[Timer]\nOnCalendar=\nOnCalendar=*:0/2\n' > "$d/$KRL_DROPIN_REL"
    before=$(md5sum < "$d/$KRL_DROPIN_REL")
    (
        . "$d/env"; . "$LIB"
        ob_krl_timer_setup 15 || echo "rc:$OB_TIMERS_MSG"
        grep -q 'not written by Open Bastion' <<<"$OB_TIMERS_WARN" || echo "no-warning"
        # Removing "ours" for the default must not remove theirs either.
        ob_krl_timer_setup 30 || echo "rc30:$OB_TIMERS_MSG"
    ) > "$WORK/foreign.out" 2>&1
    [ -s "$WORK/foreign.out" ] && bad="$bad $(tr '\n' ' ' < "$WORK/foreign.out")"
    [ "$(md5sum < "$d/$KRL_DROPIN_REL" 2>/dev/null)" = "$before" ] || bad="$bad overwritten"
    if [ -z "$bad" ]; then
        pass "an administrator's schedule.conf is neither overwritten nor removed"
    else
        fail "foreign drop-in" "$bad"
    fi
}

# ── 6. No interval, no old job: the schedule the host has is kept ────────────
test_rerun_keeps_schedule() {
    local d bad=""
    d=$(sandbox rerun)
    (
        . "$d/env"; . "$LIB"
        ob_krl_timer_setup 10 || echo "first:$OB_TIMERS_MSG"
        ob_krl_timer_setup || echo "second:$OB_TIMERS_MSG"
        grep -q 'as set in' <<<"$OB_TIMERS_SCHEDULE" || echo "schedule:$OB_TIMERS_SCHEDULE"
    ) > "$WORK/rerun.out" 2>&1
    [ -s "$WORK/rerun.out" ] && bad="$bad $(tr '\n' ' ' < "$WORK/rerun.out")"
    grep -qx 'OnCalendar=\*:0/10' "$d/$KRL_DROPIN_REL" 2>/dev/null || bad="$bad dropin-lost"
    # ...and an explicit 30 takes the host back to the packaged schedule.
    (
        . "$d/env"; . "$LIB"
        ob_krl_timer_setup 30 || echo "third:$OB_TIMERS_MSG"
    ) >> "$WORK/rerun.out" 2>&1
    [ ! -e "$d/$KRL_DROPIN_REL" ] || bad="$bad default-kept-dropin"
    if [ -z "$bad" ]; then
        pass "a run without an interval keeps the drop-in; an explicit 30 removes it"
    else
        fail "re-run keeps the schedule" "$bad"
    fi
}

# ── 7. Audit rotation: daily, weekly, edited ─────────────────────────────────
test_audit_migration() {
    local d bad=""
    # daily
    d=$(sandbox audit-daily)
    ( . "$d/env"; . "$LIB"; legacy_audit "$OB_AUDIT_LEGACY_DAILY"
      ob_audit_timer_setup || echo "rc:$OB_TIMERS_MSG" ) > "$WORK/audit.out" 2>&1
    [ -s "$WORK/audit.out" ] && bad="$bad daily:$(tr '\n' ' ' < "$WORK/audit.out")"
    [ ! -e "$d/etc/cron.daily/open-bastion-audit-rotate" ] || bad="$bad daily:left"
    [ ! -e "$d/$AUDIT_DROPIN_REL" ] || bad="$bad daily:dropin"
    [ -e "$d/sysd/state/ob-audit-rotate.timer.active" ] || bad="$bad daily:not-armed"
    # weekly (doc/audit.rst told admins they could move it there)
    d=$(sandbox audit-weekly)
    ( . "$d/env"; . "$LIB"; legacy_audit "$OB_AUDIT_LEGACY_WEEKLY"
      ob_audit_timer_setup || echo "rc:$OB_TIMERS_MSG" ) > "$WORK/audit.out" 2>&1
    [ -s "$WORK/audit.out" ] && bad="$bad weekly:$(tr '\n' ' ' < "$WORK/audit.out")"
    [ ! -e "$d/etc/cron.weekly/open-bastion-audit-rotate" ] || bad="$bad weekly:left"
    grep -qx 'OnCalendar=weekly' "$d/$AUDIT_DROPIN_REL" 2>/dev/null || bad="$bad weekly:no-dropin"
    # edited: kept, warned
    d=$(sandbox audit-edited)
    ( . "$d/env"; . "$LIB"
      printf '#!/bin/sh\n/usr/local/sbin/my-own-rotation\n' > "$OB_AUDIT_LEGACY_DAILY"
      ob_audit_timer_setup || echo "rc:$OB_TIMERS_MSG"
      grep -q 'edited' <<<"$OB_TIMERS_WARN" || echo "no-warning" ) > "$WORK/audit.out" 2>&1
    [ -s "$WORK/audit.out" ] && bad="$bad edited:$(tr '\n' ' ' < "$WORK/audit.out")"
    [ -e "$d/etc/cron.daily/open-bastion-audit-rotate" ] || bad="$bad edited:removed"
    if [ -z "$bad" ]; then
        pass "the audit rotation moves to the timer daily or weekly; an edited script is kept"
    else
        fail "audit rotation migration" "$bad"
    fi
}

# ── 8. Dry run: every decision, no change ────────────────────────────────────
test_dry_run_changes_nothing() {
    local d bad="" before after
    d=$(sandbox dry)
    (
        . "$d/env"
        legacy_krl_cron "$OB_KRL_LEGACY_CRON" 10
        legacy_krl_script "$OB_KRL_LEGACY_SCRIPT"
        legacy_audit "$OB_AUDIT_LEGACY_WEEKLY"
    )
    before=$(find "$d" -path "$d/sysd" -prune -o -print | sort | xargs md5sum 2>/dev/null)
    (
        . "$d/env"; . "$LIB"
        OB_TIMERS_DRY_RUN=true
        ob_krl_timer_setup || echo "krl-rc"
        grep -q 'would write .*every 10 min' <<<"$OB_TIMERS_DONE" || echo "krl-plan:$OB_TIMERS_DONE"
        grep -q 'would then remove' <<<"$OB_TIMERS_DONE" || echo "krl-plan-remove"
        ob_audit_timer_setup || echo "audit-rc"
        grep -q 'would write .*weekly' <<<"$OB_TIMERS_DONE" || echo "audit-plan:$OB_TIMERS_DONE"
    ) > "$WORK/dry.out" 2>&1
    after=$(find "$d" -path "$d/sysd" -prune -o -print | sort | xargs md5sum 2>/dev/null)
    [ -s "$WORK/dry.out" ] && bad="$bad $(tr '\n' ' ' < "$WORK/dry.out")"
    [ "$before" = "$after" ] || bad="$bad files-changed"
    grep -qvE '^(is-enabled|is-active)' "$d/sysd/calls" && bad="$bad systemctl-changed-state"
    if [ -z "$bad" ]; then
        pass "OB_TIMERS_DRY_RUN plans the migration and changes no file and no unit"
    else
        fail "dry run" "$bad"
    fi
}

# ── 9. The setup: Mode E downloads with ob-krl-refresh and arms the timer ────
test_setup_download_krl() {
    local d bad="" out
    d=$(sandbox setup-krl)
    # A stand-in for ob-krl-refresh: records its arguments, writes a list.
    cat > "$d/ob-krl-refresh" <<EOF
#!/bin/bash
echo "\$*" > "$d/refresh.args"
printf 'SSHKRL\n' > "\${4}"
EOF
    chmod +x "$d/ob-krl-refresh"
    legacy_krl_cron "$d/etc/cron.d/open-bastion-krl" 20
    legacy_krl_script "$d/usr/local/bin/open-bastion-refresh-krl"
    out=$(
        . "$d/env"
        load_setup_as ob-bastion-setup
        parse_args -p "https://sso.example.com" --max-security --yes
        KRL_REFRESH_BIN="$d/ob-krl-refresh"
        SSH_REVOKED_KEYS="$d/revoked_keys"
        OB_CONFIG="$d/openbastion.conf"
        download_krl 2>&1 || echo "RC=$?"
        echo "SUMMARY=$KRL_SCHEDULE"
    )
    grep -q 'RC=' <<<"$out" && bad="$bad rc"
    [ "$(cat "$d/refresh.args" 2>/dev/null)" = "--config $d/openbastion.conf --output $d/revoked_keys" ] \
        || bad="$bad args:$(cat "$d/refresh.args" 2>/dev/null)"
    [ -s "$d/revoked_keys" ] || bad="$bad no-list"
    grep -qx 'OnCalendar=\*:0/20' "$d/$KRL_DROPIN_REL" 2>/dev/null || bad="$bad interval-not-carried"
    [ -e "$d/sysd/state/ob-krl-refresh.timer.active" ] || bad="$bad timer-not-armed"
    [ ! -e "$d/etc/cron.d/open-bastion-krl" ] || bad="$bad cron-left"
    grep -q 'SUMMARY=every 20 min' <<<"$out" || bad="$bad summary"
    # Nothing writes a cron job any more.
    grep -qE 'CRONEOF|cron_file=|/etc/cron\.(d|daily)/[^ ]* *<<' "$SETUP_SCRIPT" && bad="$bad setup-still-writes-cron"
    if [ -z "$bad" ]; then
        pass "setup Mode E: ob-krl-refresh fetches, the 0.6 job's interval is carried to the timer"
    else
        fail "setup download_krl" "$bad :: $(tr '\n' ' ' <<<"$out")"
    fi
}

# ── 10. The setup: a failed download keeps an existing list, or creates one ──
test_setup_download_failure() {
    local d bad="" out
    d=$(sandbox setup-krl-fail)
    printf '#!/bin/sh\nexit 2\n' > "$d/ob-krl-refresh"; chmod +x "$d/ob-krl-refresh"
    out=$(
        . "$d/env"
        load_setup_as ob-backend-setup
        parse_args -p "https://sso.example.com" -g g --max-security --yes
        KRL_REFRESH_BIN="$d/ob-krl-refresh"
        SSH_REVOKED_KEYS="$d/revoked_keys"
        download_krl 2>&1 || echo "RC=$?"
    )
    [ -f "$d/revoked_keys" ] && [ ! -s "$d/revoked_keys" ] || bad="$bad no-empty-list"
    [ "$(stat -c %a "$d/revoked_keys" 2>/dev/null)" = "644" ] || bad="$bad mode"
    printf 'previous\n' > "$d/revoked_keys"
    out=$(
        . "$d/env"
        load_setup_as ob-backend-setup
        parse_args -p "https://sso.example.com" -g g --max-security --yes
        KRL_REFRESH_BIN="$d/ob-krl-refresh"
        SSH_REVOKED_KEYS="$d/revoked_keys"
        download_krl 2>&1 || echo "RC=$?"
    )
    [ "$(cat "$d/revoked_keys")" = "previous" ] || bad="$bad list-clobbered"
    if [ -z "$bad" ]; then
        pass "setup: a failed first download creates an empty list, and never clobbers one"
    else
        fail "setup download failure" "$bad"
    fi
}

# ── 11. The setup's interval option ──────────────────────────────────────────
test_setup_interval_option() {
    local bad="" v out rc cmd d
    cmd=$(setup_command ob-bastion-setup)
    for v in 0 61 abc -5 1.5 ''; do
        out=$("$cmd" -p https://x.example.com --max-security --krl-refresh-interval "$v" --dry-run --yes 2>&1); rc=$?
        { [ "$rc" -ne 0 ] && grep -q 'between 1 and 60' <<<"$out"; } || bad="$bad accepted:'$v'"
    done
    out=$("$cmd" -p https://x.example.com --krl-refresh-interval 10 --dry-run --yes 2>&1); rc=$?
    { [ "$rc" -ne 0 ] && grep -q 'max-security' <<<"$out"; } || bad="$bad accepted-without-mode-e"
    # A valid one reaches the drop-in.
    d=$(sandbox setup-interval)
    printf '#!/bin/sh\nexit 2\n' > "$d/ob-krl-refresh"; chmod +x "$d/ob-krl-refresh"
    (
        . "$d/env"
        load_setup_as ob-bastion-setup
        parse_args -p "https://sso.example.com" --max-security --krl-refresh-interval 5 --yes
        KRL_REFRESH_BIN="$d/ob-krl-refresh"
        SSH_REVOKED_KEYS="$d/revoked_keys"
        download_krl >/dev/null 2>&1
    )
    grep -qx 'OnCalendar=\*:0/5' "$d/$KRL_DROPIN_REL" 2>/dev/null || bad="$bad dropin"
    if [ -z "$bad" ]; then
        pass "--krl-refresh-interval takes 1..60 with --max-security only, and writes the drop-in"
    else
        fail "--krl-refresh-interval" "$bad"
    fi
}

# ── 12. The setup's dry run describes the timer and touches nothing ──────────
test_setup_dry_run() {
    local d out bad=""
    d=$(sandbox setup-dry)
    legacy_krl_cron "$d/etc/cron.d/open-bastion-krl" 10
    out=$(
        . "$d/env"
        load_setup_as ob-bastion-setup
        parse_args -p "https://sso.example.com" --max-security --dry-run --yes
        SSH_REVOKED_KEYS="$d/revoked_keys"
        download_krl 2>&1
    )
    grep -q '\[DRY-RUN\] Would enable ob-krl-refresh.timer (every 10 min)' <<<"$out" || bad="$bad no-enable-line"
    grep -q '\[DRY-RUN\] Would write .*schedule.conf (every 10 min)' <<<"$out" || bad="$bad no-dropin-line"
    grep -qi 'cron job for KRL' <<<"$out" && bad="$bad mentions-cron-job"
    [ -e "$d/etc/cron.d/open-bastion-krl" ] || bad="$bad cron-removed"
    [ ! -e "$d/revoked_keys" ] || bad="$bad list-written"
    [ ! -e "$d/$KRL_DROPIN_REL" ] || bad="$bad dropin-written"
    grep -qvE '^(is-enabled|is-active)' "$d/sysd/calls" && bad="$bad systemctl-called"
    if [ -z "$bad" ]; then
        pass "setup --dry-run says it would enable the timer and write the drop-in, and does neither"
    else
        fail "setup dry run" "$bad :: $(tr '\n' ' ' <<<"$out")"
    fi
}

# ── 13. The setup's audit trace arms the rotation timer ──────────────────────
test_setup_audit_trace() {
    local d bad="" out
    d=$(sandbox setup-audit)
    printf '#!/bin/sh\nexit 0\n' > "$d/sysd/bin/auditctl"
    printf '#!/bin/sh\nexit 0\n' > "$d/sysd/bin/augenrules"
    chmod +x "$d/sysd/bin/auditctl" "$d/sysd/bin/augenrules"
    mkdir -p "$d/templates/rules.d"
    printf '# rules\n' > "$d/templates/rules.d/open-bastion.rules"
    legacy_audit "$d/etc/cron.daily/open-bastion-audit-rotate"
    out=$(
        . "$d/env"
        load_setup_as ob-bastion-setup
        parse_args -p "https://sso.example.com" --enable-audit-trace --yes
        AUDIT_TEMPLATE_DIR="$d/templates"
        AUDIT_RULES_FILE="$d/open-bastion.rules"
        # install -o root would need root; the rules copy is not under test here.
        install() { cp "${@: -2}"; }
        setup_audit_trace 2>&1 || echo "RC=$?"
        echo "RESULT=$AUDIT_RESULT"
    )
    grep -q 'RESULT=applied' <<<"$out" || bad="$bad result"
    [ -e "$d/sysd/state/ob-audit-rotate.timer.enabled" ] || bad="$bad not-enabled"
    [ ! -e "$d/etc/cron.daily/open-bastion-audit-rotate" ] || bad="$bad cron-left"
    # The rotation is armed before auditd is restarted.
    [ "$(grep -n 'ob-audit-rotate.timer' "$d/sysd/calls" | head -1 | cut -d: -f1)" -lt \
      "$(grep -n 'restart auditd\|is-active --quiet auditd' "$d/sysd/calls" | head -1 | cut -d: -f1)" ] 2>/dev/null \
        || bad="$bad order"
    # A timer that cannot be armed fails the step before auditd is touched.
    d=$(sandbox setup-audit-fail)
    printf '#!/bin/sh\nexit 0\n' > "$d/sysd/bin/auditctl"
    printf '#!/bin/sh\nexit 0\n' > "$d/sysd/bin/augenrules"
    chmod +x "$d/sysd/bin/auditctl" "$d/sysd/bin/augenrules"
    mkdir -p "$d/templates/rules.d"
    printf '# rules\n' > "$d/templates/rules.d/open-bastion.rules"
    touch "$d/sysd/fail-enable"
    out=$(
        . "$d/env"
        load_setup_as ob-bastion-setup
        parse_args -p "https://sso.example.com" --enable-audit-trace --yes
        AUDIT_TEMPLATE_DIR="$d/templates"
        AUDIT_RULES_FILE="$d/open-bastion.rules"
        setup_audit_trace 2>&1 || echo "RC=$?"
        echo "RESULT=$AUDIT_RESULT"
    )
    grep -q 'RESULT=failed' <<<"$out" || bad="$bad fail:result"
    [ ! -e "$d/open-bastion.rules" ] || bad="$bad fail:rules-installed"
    grep -q 'auditd' "$d/sysd/calls" && bad="$bad fail:auditd-touched"
    if [ -z "$bad" ]; then
        pass "--enable-audit-trace arms ob-audit-rotate.timer first and replaces the cron.daily script"
    else
        fail "setup audit trace" "$bad :: $(tr '\n' ' ' <<<"$out")"
    fi
}

# ── 14. ob-post-upgrade migrates, in a dry run, and re-asserts Mode E ────────
test_post_upgrade() {
    local d bad="" out rc
    d=$(sandbox post-upgrade)
    mkdir -p "$d/sshd"
    printf 'node_role = bastion\n' > "$d/ob.conf"
    printf 'AuthorizedPrincipalsCommand /x %%u %%f %%t %%k\n' > "$d/sshd/00-open-bastion-bastion.conf"
    legacy_krl_cron "$d/etc/cron.d/open-bastion-krl" 15
    legacy_audit "$d/etc/cron.daily/open-bastion-audit-rotate"
    out=$(
        . "$d/env"
        OB_CONFIG="$d/ob.conf" OB_SSHD_CONFIG_DIR="$d/sshd" \
            "$ROOT_DIR/scripts/ob-post-upgrade" --dry-run 2>&1
    ); rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    grep -q 'would carry over the interval .*every 15 min' <<<"$out" || bad="$bad no-carry"
    grep -q 'would enable ob-krl-refresh.timer (every 15 min)' <<<"$out" || bad="$bad no-krl-enable"
    grep -q 'would enable ob-audit-rotate.timer (daily)' <<<"$out" || bad="$bad no-audit-enable"
    [ -e "$d/etc/cron.d/open-bastion-krl" ] || bad="$bad dry-removed"

    # Mode E with no old job and no armed timer: it is re-asserted.
    rm -f "$d/etc/cron.d/open-bastion-krl" "$d/etc/cron.daily/open-bastion-audit-rotate"
    printf 'RevokedKeys /etc/ssh/revoked_keys\n' > "$d/sshd/60-max-security.conf"
    out=$(
        . "$d/env"
        OB_CONFIG="$d/ob.conf" OB_SSHD_CONFIG_DIR="$d/sshd" \
            "$ROOT_DIR/scripts/ob-post-upgrade" --dry-run 2>&1
    )
    grep -q 'would enable ob-krl-refresh.timer' <<<"$out" || bad="$bad mode-e-not-reasserted"
    # ...and reported as fine once it is.
    touch "$d/sysd/state/ob-krl-refresh.timer.enabled" "$d/sysd/state/ob-krl-refresh.timer.active"
    out=$(
        . "$d/env"
        OB_CONFIG="$d/ob.conf" OB_SSHD_CONFIG_DIR="$d/sshd" \
            "$ROOT_DIR/scripts/ob-post-upgrade" --dry-run 2>&1
    )
    grep -q 'ob-krl-refresh.timer is enabled and active' <<<"$out" || bad="$bad mode-e-ok-not-reported"
    # A host that is not in Mode E and has no old job is not given a timer.
    rm -f "$d/sshd/60-max-security.conf" "$d/sysd/state/"*
    out=$(
        . "$d/env"
        OB_CONFIG="$d/ob.conf" OB_SSHD_CONFIG_DIR="$d/sshd" \
            "$ROOT_DIR/scripts/ob-post-upgrade" --dry-run 2>&1
    )
    grep -q 'krl-refresh' <<<"$out" && bad="$bad timer-on-non-mode-e"
    if [ -z "$bad" ]; then
        pass "ob-post-upgrade plans both migrations, and re-arms the KRL timer on Mode E only"
    else
        fail "ob-post-upgrade" "$bad :: $(tr '\n' ' ' <<<"$out")"
    fi
}

# ── 15. The package says so, and does not do it itself ───────────────────────
test_postinst_notice_only() {
    local bad="" f
    for f in "$ROOT_DIR/debian/open-bastion.postinst" "$ROOT_DIR/rpm/open-bastion.spec"; do
        grep -q "run 'ob-post-upgrade' to replace them" "$f" || bad="$bad no-notice:$(basename "$f")"
        # The package must not remove the old jobs: that is ob-post-upgrade's,
        # which arms the timer first.
        grep -nE 'rm .*(cron\.d/open-bastion-krl|open-bastion-refresh-krl|open-bastion-audit-rotate)' "$f" \
            && bad="$bad removes-jobs:$(basename "$f")"
    done
    if [ -z "$bad" ]; then
        pass "the postinst and %post point at ob-post-upgrade and remove nothing themselves"
    else
        fail "package scripts" "$bad"
    fi
}

run_test test_legacy_interval_parsing
run_test test_krl_migration
run_test test_never_neither
run_test test_reshaped_job_kept
run_test test_foreign_dropin_untouched
run_test test_rerun_keeps_schedule
run_test test_audit_migration
run_test test_dry_run_changes_nothing
run_test test_setup_download_krl
run_test test_setup_download_failure
run_test test_setup_interval_option
run_test test_setup_dry_run
run_test test_setup_audit_trace
run_test test_post_upgrade
run_test test_postinst_notice_only

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
