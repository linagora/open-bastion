# shellcheck shell=bash
# The OB_* results are read by the scripts that source this file.
# shellcheck disable=SC2034
#
# ob-timers-lib.sh - the systemd timers that replaced Open Bastion's cron jobs
#
# Sourced by ob-bastion-setup (and its ob-backend-setup / ob-standalone-setup
# names) and by ob-post-upgrade. Up to 0.6, the setup wrote two cron jobs:
#
#   /etc/cron.d/open-bastion-krl            Mode E KRL refresh, every 30 min,
#                                           running a script it generated into
#                                           /usr/local/bin/open-bastion-refresh-krl
#   /etc/cron.daily/open-bastion-audit-rotate
#                                           auditd rotation (--enable-audit-trace)
#
# They are now ob-krl-refresh.timer and ob-audit-rotate.timer (#281). Both the
# setup (when it runs again) and ob-post-upgrade (when an upgrade is finished)
# replace an old job with its timer, and must do it the same way -- one copy,
# here, for the reason share/ exists: two copies of the same migration drift.
#
# The rule both follow: the old job is removed only once its timer is enabled
# and active. A host may briefly have both (harmless: each refresh is atomic,
# and one extra rotation is one extra log file); it never has neither.
#
# Functions print nothing: the two callers report differently. The two entry
# points, ob_krl_timer_setup and ob_audit_timer_setup, leave their results in
#
#   OB_TIMERS_DONE      what was done, one sentence per line
#   OB_TIMERS_WARN      what was left for a human, one sentence per line
#   OB_TIMERS_SCHEDULE  the schedule now in effect, in words
#   OB_TIMERS_MSG       why the timer could not be armed, when they return 1
#
# With OB_TIMERS_DRY_RUN=true they take every decision exactly as for real and
# change nothing; OB_TIMERS_DONE then says what would have been done.
#
# Copyright (C) 2026 Linagora
# License: AGPL-3.0

# Paths, overridable so the test suite can run all of this unprivileged. On a
# real host none of them is set and the defaults apply.
: "${OB_SYSTEMD_UNIT_DIR:=/etc/systemd/system}"
: "${OB_KRL_LEGACY_CRON:=/etc/cron.d/open-bastion-krl}"
: "${OB_KRL_LEGACY_SCRIPT:=/usr/local/bin/open-bastion-refresh-krl}"
: "${OB_AUDIT_LEGACY_DAILY:=/etc/cron.daily/open-bastion-audit-rotate}"
: "${OB_AUDIT_LEGACY_WEEKLY:=/etc/cron.weekly/open-bastion-audit-rotate}"

OB_KRL_TIMER="ob-krl-refresh.timer"
OB_AUDIT_TIMER="ob-audit-rotate.timer"
# The interval ob-krl-refresh.timer ships with (OnCalendar=*:0/30).
OB_KRL_DEFAULT_INTERVAL=30

# First line of every drop-in written here. It is what tells OUR file from one
# an administrator wrote: ours may be rewritten or removed, theirs never.
OB_TIMERS_MARK="# Open Bastion timer schedule"

OB_TIMERS_MSG=""
OB_TIMERS_INTERVAL=""
OB_TIMERS_SCHEDULE=""
OB_TIMERS_DONE=""
OB_TIMERS_WARN=""
: "${OB_TIMERS_DRY_RUN:=false}"

_ob_timers_dry() { [ "$OB_TIMERS_DRY_RUN" = "true" ]; }

# Record an action: the first sentence in a dry run, the second otherwise.
_ob_timers_done() {
    if _ob_timers_dry; then
        OB_TIMERS_DONE+="$1"$'\n'
    else
        OB_TIMERS_DONE+="$2"$'\n'
    fi
}
_ob_timers_warn() { OB_TIMERS_WARN+="$1"$'\n'; }

# An interval in minutes the timer can express exactly as `*:0/N`, which is
# also what cron's `*/N` in the minute field meant: 1 to 60, plain decimal.
ob_krl_interval_valid() {
    [[ "${1:-}" =~ ^[1-9][0-9]?$ ]] && [ "$1" -le 60 ]
}

# OnCalendar= value for a refresh every N minutes. systemd refuses a repetition
# as long as the range (*:0/60), where cron's */60 simply meant minute 0: that
# one is spelled as the hourly run it is.
ob_krl_oncalendar() {
    if [ "$1" = "60" ]; then
        printf '*:00'
    else
        printf '*:0/%s' "$1"
    fi
}

# Read the interval of the old KRL cron job.
#   0  found and understood; the interval is in OB_TIMERS_INTERVAL
#   1  found, but not the shape the setup wrote: an administrator changed the
#      schedule into something this cannot translate faithfully
#   2  no old job
#
# The only shape accepted is the one the setup generated, with any N:
#     */N * * * * root /usr/local/bin/open-bastion-refresh-krl ...
# Anything else (hours restricted, a list of minutes, another user) is left for
# a human, because a wrong guess would silently change how fast a revocation
# reaches this host.
ob_krl_legacy_interval() {
    OB_TIMERS_INTERVAL=""
    OB_TIMERS_MSG=""
    [ -e "$OB_KRL_LEGACY_CRON" ] || return 2

    local line jobs=0 n=""
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        # Environment lines (MAILTO=, SHELL=...) are not jobs.
        [[ "$line" =~ ^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*= ]] && continue
        jobs=$((jobs + 1))
        if [[ "$line" =~ ^[[:space:]]*\*/([0-9]+)[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*[[:space:]]+root[[:space:]]+[^[:space:]]*open-bastion-refresh-krl([[:space:]]|$) ]]; then
            n="${BASH_REMATCH[1]}"
        fi
    done < "$OB_KRL_LEGACY_CRON"

    if [ "$jobs" -eq 1 ] && ob_krl_interval_valid "$n"; then
        OB_TIMERS_INTERVAL="$n"
        return 0
    fi
    OB_TIMERS_MSG="$OB_KRL_LEGACY_CRON does not hold the single '*/N * * * * root ...open-bastion-refresh-krl' job the setup wrote"
    return 1
}

# The old audit rotation, by where it was installed.
#   0  found; OB_TIMERS_SCHEDULE is daily or weekly (doc/audit.rst told admins
#      they could move the file to cron.weekly)
#   1  found, but edited: it no longer carries the line the setup installed
#   2  none
ob_audit_legacy_schedule() {
    OB_TIMERS_SCHEDULE=""
    OB_TIMERS_MSG=""
    local f found=""
    for f in "$OB_AUDIT_LEGACY_WEEKLY" "$OB_AUDIT_LEGACY_DAILY"; do
        [ -e "$f" ] || continue
        found="$f"
        # shellcheck disable=SC2016  # the backquotes are literal text
        if ! grep -q 'Installed by `ob-bastion-setup --enable-audit-trace`' "$f" 2>/dev/null; then
            OB_TIMERS_MSG="$f has been edited since the setup installed it"
            return 1
        fi
    done
    [ -n "$found" ] || return 2
    if [ -e "$OB_AUDIT_LEGACY_WEEKLY" ]; then
        OB_TIMERS_SCHEDULE="weekly"
    else
        OB_TIMERS_SCHEDULE="daily"
    fi
    return 0
}

# Path of the schedule drop-in for a timer.
ob_timer_dropin() {
    printf '%s/%s.d/schedule.conf' "$OB_SYSTEMD_UNIT_DIR" "$1"
}

# Set a timer's OnCalendar= through its drop-in; an empty value means "the
# packaged schedule", i.e. no drop-in of ours.
#   0  done (written, removed, or already right)
#   1  a drop-in of the same name that is not ours is in the way, or the write
#      failed; nothing was changed, OB_TIMERS_MSG says which
ob_timer_set_schedule() {
    local unit="$1" oncalendar="$2" file tmp
    file=$(ob_timer_dropin "$unit")
    OB_TIMERS_MSG=""

    if [ -e "$file" ] && ! head -n 1 "$file" | grep -qxF "$OB_TIMERS_MARK"; then
        OB_TIMERS_MSG="$file was not written by Open Bastion and was left as it is"
        return 1
    fi

    _ob_timers_dry && return 0

    if [ -z "$oncalendar" ]; then
        rm -f "$file"
        rmdir "$(dirname "$file")" 2>/dev/null || true
        return 0
    fi

    mkdir -p "$(dirname "$file")" || {
        OB_TIMERS_MSG="cannot create $(dirname "$file")"; return 1; }
    tmp=$(mktemp "$file.XXXXXX") || {
        OB_TIMERS_MSG="cannot write in $(dirname "$file")"; return 1; }
    if ! {
        printf '%s\n' "$OB_TIMERS_MARK"
        printf '# Written by ob-bastion-setup or ob-post-upgrade; rewritten by the next\n'
        printf '# run that is given a schedule. Remove the first line to keep your own.\n'
        printf '[Timer]\n'
        printf 'OnCalendar=\n'
        printf 'OnCalendar=%s\n' "$oncalendar"
    } > "$tmp" || ! chmod 0644 "$tmp" || ! mv -f "$tmp" "$file"; then
        rm -f "$tmp"
        OB_TIMERS_MSG="cannot write $file"
        return 1
    fi
    return 0
}

# Is the timer both enabled (survives a reboot) and active (armed now)?
ob_timer_ready() {
    systemctl is-enabled --quiet "$1" 2>/dev/null \
        && systemctl is-active --quiet "$1" 2>/dev/null
}

# Enable and (re)start a timer, picking up a drop-in written just before.
# A restart, not just `enable --now`: an already running timer keeps the
# schedule it was started with until it is restarted.
ob_timer_enable() {
    local unit="$1"
    OB_TIMERS_MSG=""
    _ob_timers_dry && return 0
    if ! command -v systemctl >/dev/null 2>&1; then
        OB_TIMERS_MSG="systemctl is not available"
        return 1
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl enable "$unit" >/dev/null 2>&1 \
       && systemctl restart "$unit" >/dev/null 2>&1 \
       && ob_timer_ready "$unit"; then
        return 0
    fi
    OB_TIMERS_MSG="could not enable and start $unit (see: systemctl status $unit)"
    return 1
}

# Remove the old KRL job. Only called once ob-krl-refresh.timer is ready. The
# script is removed only if it is the one the setup generated: /usr/local is
# the administrator's, and a file there that does something else is theirs.
ob_krl_remove_legacy() {
    _ob_timers_dry && return 0
    rm -f "$OB_KRL_LEGACY_CRON"
    if [ -f "$OB_KRL_LEGACY_SCRIPT" ] \
       && grep -q '/ssh/revoked' "$OB_KRL_LEGACY_SCRIPT" 2>/dev/null; then
        rm -f "$OB_KRL_LEGACY_SCRIPT"
    fi
}

# Remove the old audit rotation. Only called once ob-audit-rotate.timer is
# ready, and only after ob_audit_legacy_schedule returned 0 (unedited files).
ob_audit_remove_legacy() {
    _ob_timers_dry && return 0
    rm -f "$OB_AUDIT_LEGACY_DAILY" "$OB_AUDIT_LEGACY_WEEKLY"
}

# ── The two entry points ────────────────────────────────────────────────────

# Arm ob-krl-refresh.timer, replacing the 0.6 cron job if the host has one.
#
#   ob_krl_timer_setup [MINUTES]
#
# MINUTES, when given, is the interval to set (--krl-refresh-interval). Without
# it the old job's interval is carried over, and without an old job the
# schedule is left as it is: the packaged 30 minutes, or a drop-in written
# earlier -- running the setup again must not reset what a host was given.
#
# Returns 1 when the timer could not be armed. The old job, if any, is then
# still there: it is removed only after the timer runs.
ob_krl_timer_setup() {
    local interval="${1:-}" rc=0 legacy_msg="" dropin oncalendar
    OB_TIMERS_DONE=""; OB_TIMERS_WARN=""; OB_TIMERS_MSG=""
    dropin=$(ob_timer_dropin "$OB_KRL_TIMER")

    ob_krl_legacy_interval || rc=$?
    if [ "$rc" -eq 1 ]; then
        legacy_msg="$OB_TIMERS_MSG"
    elif [ "$rc" -eq 0 ] && [ -z "$interval" ]; then
        interval="$OB_TIMERS_INTERVAL"
        _ob_timers_done \
            "would carry over the interval of $OB_KRL_LEGACY_CRON: every $interval min" \
            "carried over the interval of $OB_KRL_LEGACY_CRON: every $interval min"
    fi

    # The schedule.
    OB_TIMERS_SCHEDULE="every $OB_KRL_DEFAULT_INTERVAL min"
    [ -e "$dropin" ] && OB_TIMERS_SCHEDULE="as set in $dropin"
    if [ -n "$interval" ]; then
        oncalendar=""
        if [ "$interval" != "$OB_KRL_DEFAULT_INTERVAL" ]; then
            oncalendar=$(ob_krl_oncalendar "$interval")
        fi
        if ob_timer_set_schedule "$OB_KRL_TIMER" "$oncalendar"; then
            OB_TIMERS_SCHEDULE="every $interval min"
            if [ -n "$oncalendar" ]; then
                _ob_timers_done "would write $dropin (every $interval min)" \
                                "wrote $dropin (every $interval min)"
            elif [ -e "$dropin" ]; then
                _ob_timers_done "would remove $dropin (back to every $interval min)" \
                                "removed $dropin (back to every $interval min)"
            fi
        else
            _ob_timers_warn "$OB_TIMERS_MSG; its schedule applies, not every $interval min"
        fi
    fi

    # The timer. Nothing below runs unless it is armed: never neither.
    if ! ob_timer_enable "$OB_KRL_TIMER"; then
        if [ -e "$OB_KRL_LEGACY_CRON" ]; then
            _ob_timers_warn "$OB_KRL_LEGACY_CRON was kept and still refreshes the list"
        else
            _ob_timers_warn "nothing refreshes the revocation list until: systemctl enable --now $OB_KRL_TIMER"
        fi
        return 1
    fi
    _ob_timers_done "would enable $OB_KRL_TIMER ($OB_TIMERS_SCHEDULE)" \
                    "enabled $OB_KRL_TIMER ($OB_TIMERS_SCHEDULE)"

    # The old job, now redundant.
    case "$rc" in
        0)  ob_krl_remove_legacy
            _ob_timers_done "would then remove $OB_KRL_LEGACY_CRON and $OB_KRL_LEGACY_SCRIPT" \
                            "removed $OB_KRL_LEGACY_CRON and $OB_KRL_LEGACY_SCRIPT, which it replaces" ;;
        1)  _ob_timers_warn "$legacy_msg, so it was left in place and runs alongside $OB_KRL_TIMER; port its schedule to $dropin (see ob-krl-refresh(8)), then delete it" ;;
    esac
    return 0
}

# Arm ob-audit-rotate.timer, replacing the 0.6 cron rotation if the host has
# one. The schedule follows the old job (daily, or weekly for a file moved to
# cron.weekly as doc/audit.rst allowed); without one it is left as it is.
ob_audit_timer_setup() {
    local rc=0 legacy_msg="" dropin schedule
    OB_TIMERS_DONE=""; OB_TIMERS_WARN=""; OB_TIMERS_MSG=""
    dropin=$(ob_timer_dropin "$OB_AUDIT_TIMER")

    ob_audit_legacy_schedule || rc=$?
    schedule="$OB_TIMERS_SCHEDULE"
    [ "$rc" -eq 1 ] && legacy_msg="$OB_TIMERS_MSG"

    OB_TIMERS_SCHEDULE="daily"
    [ -e "$dropin" ] && OB_TIMERS_SCHEDULE="as set in $dropin"
    if [ "$rc" -eq 0 ]; then
        local oncalendar=""
        [ "$schedule" = "weekly" ] && oncalendar="weekly"
        if ob_timer_set_schedule "$OB_AUDIT_TIMER" "$oncalendar"; then
            OB_TIMERS_SCHEDULE="$schedule"
            if [ -n "$oncalendar" ]; then
                _ob_timers_done "would write $dropin ($schedule)" "wrote $dropin ($schedule)"
            fi
        else
            _ob_timers_warn "$OB_TIMERS_MSG; its schedule applies, not $schedule"
        fi
    fi

    if ! ob_timer_enable "$OB_AUDIT_TIMER"; then
        if [ "$rc" -ne 2 ]; then
            _ob_timers_warn "the cron rotation was kept and still rotates the audit log"
        else
            _ob_timers_warn "nothing rotates the audit log until: systemctl enable --now $OB_AUDIT_TIMER"
        fi
        return 1
    fi
    _ob_timers_done "would enable $OB_AUDIT_TIMER ($OB_TIMERS_SCHEDULE)" \
                    "enabled $OB_AUDIT_TIMER ($OB_TIMERS_SCHEDULE)"

    case "$rc" in
        0)  ob_audit_remove_legacy
            _ob_timers_done "would then remove the cron rotation it replaces" \
                            "removed the cron rotation it replaces" ;;
        1)  _ob_timers_warn "$legacy_msg: left in place, so the audit log now rotates twice; delete it once $OB_AUDIT_TIMER does what it did (doc/audit.rst)" ;;
    esac
    return 0
}
