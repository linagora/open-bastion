#!/bin/bash
# test_ob_systemd_units.sh
#
# Keeps systemd unit files in exactly one place (issue #254).
#
# Units used to exist twice: in systemd/, and again as debian/open-bastion.<unit>
# for dh_installsystemd's package.NAME.socket form. The two drifted. `a9a28d8`
# added hardening to systemd/ob-cert@.service and systemd/ob-record@.service --
# UMask=0077, SystemCallFilter=@system-service, SystemCallErrorNumber=EPERM --
# and the debian/ copies, last touched three months earlier, never got it. The
# copies happened to be the ones nothing installed, so no shipped unit lost the
# hardening; the damage was that two files looked authoritative and one was
# silently wrong. It survived two releases because nothing checked.
#
# So this test does not check the drift that existed. It checks the property
# that makes drift impossible:
#
#   1. no unit content lives anywhere but systemd/;
#   2. every unit dh_installsystemd is told to handle is actually staged into
#      the package by debian/open-bastion.install, since that is now the only
#      thing that puts unit files in the package;
#   3. every unit the RPM lists exists in systemd/ too;
#   4. the hardening directives that went missing are present in the units that
#      are supposed to have them -- the specific regression, pinned.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

echo "=== systemd unit files (issue #254) ==="

# ── 1. systemd/ is the only home for unit content ────────────────────────────
test_no_duplicate_unit_files() {
    local dupes=""
    local f
    # Anything in debian/ that looks like a unit: the package.NAME.unit form
    # dh_installsystemd accepts, and the bare debian/<package>.<type> form.
    #
    # No exemptions. An earlier draft of this test exempted
    # debian/open-bastion.{service,timer} as "the package's own unit" -- they
    # were not: they were byte-identical dead copies of
    # systemd/ob-heartbeat.{service,timer}, left behind by the rename in
    # b915a19, installed by nothing. Exempting them would have frozen into the
    # test exactly the situation it exists to prevent.
    for f in "$ROOT_DIR"/debian/*.service "$ROOT_DIR"/debian/*.socket \
             "$ROOT_DIR"/debian/*.timer "$ROOT_DIR"/debian/*.mount; do
        [ -e "$f" ] || continue
        dupes="$dupes $(basename "$f")"
    done
    if [ -z "$dupes" ]; then
        pass "no unit file content under debian/"
    else
        fail "no unit file content under debian/" \
             "these duplicate systemd/ and will drift:$dupes"
    fi
}

# ── 2. Every unit debian/rules names is staged by debian/open-bastion.install ─
# dh_installsystemd no longer carries its own copy, so it can only find a unit
# that .install has already put in the package tree. A unit named in rules but
# missing from .install would produce enable/disable snippets for a file that is
# not there -- the socket would be "enabled" and then fail to start.
test_rules_units_are_installed() {
    local missing="" unit
    # Across every .install file: ob-session-monitor.service belongs to the
    # -desktop binary package, not to open-bastion.
    while read -r unit; do
        [ -n "$unit" ] || continue
        grep -qE "systemd/$unit( |\$)" "$ROOT_DIR"/debian/*.install \
            || missing="$missing $unit"
    done < <(grep -oE '(ob|open)-[a-z-]+\.(socket|timer|service)$' \
                  "$ROOT_DIR/debian/rules" | sort -u)

    if [ -z "$missing" ]; then
        pass "every unit named in debian/rules is staged by .install"
    else
        fail "every unit named in debian/rules is staged by .install" \
             "not installed:$missing"
    fi
}

# ── 3. Every @.service template has its .socket, and both exist in systemd/ ───
test_templates_have_sockets() {
    local bad="" tmpl base
    for tmpl in "$ROOT_DIR"/systemd/*@.service; do
        [ -e "$tmpl" ] || continue
        base="$(basename "$tmpl" '@.service')"
        [ -f "$ROOT_DIR/systemd/$base.socket" ] || bad="$bad $base.socket"
        # A template that is not installed cannot be spawned by its socket.
        grep -q "systemd/$base@.service" \
             "$ROOT_DIR/debian/open-bastion.install" || bad="$bad $base@.service(not-installed)"
    done
    if [ -z "$bad" ]; then
        pass "every @.service template has its .socket and is installed"
    else
        fail "every @.service template has its .socket and is installed" "$bad"
    fi
}

# ── 4. The RPM lists only units that exist ───────────────────────────────────
test_rpm_units_exist() {
    local missing="" unit
    while read -r unit; do
        [ -n "$unit" ] || continue
        [ -f "$ROOT_DIR/systemd/$unit" ] || missing="$missing $unit"
    done < <(grep -oE '%\{_unitdir\}/[^[:space:]]+' "$ROOT_DIR/rpm/open-bastion.spec" \
             | sed 's|%{_unitdir}/||' | sort -u)

    if [ -z "$missing" ]; then
        pass "every unit the RPM lists exists in systemd/"
    else
        fail "every unit the RPM lists exists in systemd/" "missing:$missing"
    fi
}

# ── 5. The hardening that went missing, pinned ───────────────────────────────
# This is the specific regression #254 is about. Every socket-activated
# @.service in this tree runs as root, so these three are not optional dressing.
test_socket_services_are_hardened() {
    local bad="" svc name d
    for svc in "$ROOT_DIR"/systemd/*@.service; do
        [ -e "$svc" ] || continue
        name="$(basename "$svc")"
        for d in NoNewPrivileges=true ProtectSystem=strict PrivateTmp=true \
                 UMask=0077 SystemCallFilter=@system-service \
                 SystemCallErrorNumber=EPERM; do
            grep -qF "$d" "$svc" || bad="$bad $name:${d%%=*}"
        done
    done
    if [ -z "$bad" ]; then
        pass "socket-activated services keep their hardening directives"
    else
        fail "socket-activated services keep their hardening directives" "$bad"
    fi
}

# ── 6. Every timer has its service, and both ship everywhere ─────────────────
# The timers that replaced the cron jobs of 0.6 (#281) are new units: a timer
# whose service is not shipped starts nothing, and CMake, Debian and RPM each
# have their own list.
test_timers_have_services_and_ship() {
    local bad="" tmr base u
    for tmr in "$ROOT_DIR"/systemd/*.timer; do
        base="$(basename "$tmr" .timer)"
        [ -f "$ROOT_DIR/systemd/$base.service" ] || bad="$bad $base.service:missing"
        for u in "$base.timer" "$base.service"; do
            grep -q "systemd/$u" "$ROOT_DIR/CMakeLists.txt" || bad="$bad $u:cmake"
            grep -qE "systemd/$u( |\$)" "$ROOT_DIR/debian/open-bastion.install" || bad="$bad $u:deb"
            grep -q "%{_unitdir}/$u" "$ROOT_DIR/rpm/open-bastion.spec" || bad="$bad $u:rpm"
        done
    done
    if [ -z "$bad" ]; then
        pass "every timer has its service, installed by CMake, Debian and RPM"
    else
        fail "every timer has its service, installed by CMake, Debian and RPM" "$bad"
    fi
}

# ── 7. The KRL and audit timers are enabled by the setup, not the package ────
# A package cannot know whether a host is in Mode E or runs the audit trace;
# enabling these at install would refresh a KRL nobody reads, or signal an
# auditd that is not there, on every host. Both packagings must say so, and
# still stop them on removal.
test_opt_in_timers_not_enabled_at_install() {
    local bad="" t
    for t in ob-krl-refresh ob-audit-rotate; do
        grep -qE "dh_installsystemd .*--no-enable --no-start --name=$t $t\.timer" "$ROOT_DIR/debian/rules" \
            || bad="$bad $t:deb-enables"
        grep -qE "^%systemd_post $t\.timer" "$ROOT_DIR/rpm/open-bastion.spec" && bad="$bad $t:rpm-enables"
        grep -qE "enable .*$t\.timer" "$ROOT_DIR/rpm/open-bastion.spec" && bad="$bad $t:rpm-enables"
        grep -qE "^%systemd_preun $t\.timer" "$ROOT_DIR/rpm/open-bastion.spec" || bad="$bad $t:rpm-no-preun"
    done
    # ...and the setup is what enables them, through the timers library.
    grep -q 'ob_krl_timer_setup' "$ROOT_DIR/scripts/ob-bastion-setup" || bad="$bad setup-no-krl-timer"
    grep -q 'ob_audit_timer_setup' "$ROOT_DIR/scripts/ob-bastion-setup" || bad="$bad setup-no-audit-timer"
    if [ -z "$bad" ]; then
        pass "ob-krl-refresh and ob-audit-rotate timers are not enabled at install; the setup enables them"
    else
        fail "opt-in timers are not enabled at install" "$bad"
    fi
}

# ── 8. ob-krl-refresh.service may write /etc/ssh, and nothing else ───────────
# It runs as root and writes the file sshd trusts. The rename that makes the
# replacement atomic needs the directory writable; the sshd configuration in
# that directory must stay read-only, and the service needs no capability.
test_krl_service_sandbox() {
    local svc="$ROOT_DIR/systemd/ob-krl-refresh.service" bad="" d
    for d in ProtectSystem=strict ReadWritePaths=/etc/ssh NoNewPrivileges=yes \
             PrivateTmp=yes SystemCallFilter=@system-service; do
        grep -qx "$d" "$svc" || bad="$bad missing:$d"
    done
    grep -qx 'CapabilityBoundingSet=' "$svc" || bad="$bad capabilities"
    [ "$(grep -c '^ReadWritePaths=' "$svc")" = "1" ] || bad="$bad extra-rw-paths"
    grep -qE '^ReadOnlyPaths=.*/etc/ssh/sshd_config( |$)' "$svc" || bad="$bad sshd_config-writable"
    grep -qE '^ReadOnlyPaths=.*/etc/ssh/sshd_config\.d( |$)' "$svc" || bad="$bad sshd_config.d-writable"
    # It must reach the portal.
    grep -qx 'PrivateNetwork=yes' "$svc" && bad="$bad no-network"
    grep -q 'network-online.target' "$svc" || bad="$bad not-after-network"
    if [ -z "$bad" ]; then
        pass "ob-krl-refresh.service: /etc/ssh writable, sshd config read-only, no capabilities, network"
    else
        fail "ob-krl-refresh.service sandbox" "$bad"
    fi
}

# ── 9. systemd itself accepts the timer units and the drop-ins we write ──────
# systemd-analyze verify exits 0 on an unknown key or a bad value -- it warns
# and ignores the line -- so any output is a failure too. The ExecStart= paths
# are pointed at the source tree, where the programs exist.
test_units_verify() {
    # Not the word "SKIP": tests/test_ob_mutation.sh reads it as "the whole
    # suite skipped", and this suite guards a catalogue entry that must run in
    # the mutation job, whose container has no systemd-analyze.
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        echo "  (not checked: systemd-analyze is not installed)"
        return
    fi
    local work bad="" u out n
    work=$(mktemp -d)
    # verify also loads what our units pull in (network-online.target and its
    # dependencies) from the host, and prints whatever it thinks of those. On a
    # CI runner VM, full of units that are not ours, that was enough to fail
    # this check with nothing wrong in systemd/. Only lines about our units,
    # our copies, or the markers below count.
    _ours() { grep -E "ob-|$work|^rc\$|^write:" || true; }
    for u in "$ROOT_DIR"/systemd/*.timer "$ROOT_DIR"/systemd/ob-heartbeat.service \
             "$ROOT_DIR"/systemd/ob-session-prune.service \
             "$ROOT_DIR"/systemd/ob-krl-refresh.service \
             "$ROOT_DIR"/systemd/ob-audit-rotate.service; do
        sed "s|^ExecStart=/usr/sbin/|ExecStart=$ROOT_DIR/scripts/|" "$u" > "$work/$(basename "$u")"
    done
    out=$(cd "$work" && systemd-analyze verify --man=no ./*.timer ./*.service 2>&1) \
        || bad="$bad rc"
    out=$(_ours <<<"$out")
    [ -z "$out" ] || bad="$bad $(tr '\n' ' ' <<<"$out")"

    # Every interval --krl-refresh-interval accepts, through the drop-in the
    # timers library writes.
    for n in 1 7 10 15 30 45 59 60; do
        out=$(
            OB_SYSTEMD_UNIT_DIR="$work"
            # shellcheck source=scripts/ob-timers-lib.sh
            . "$ROOT_DIR/scripts/ob-timers-lib.sh"
            ob_timer_set_schedule ob-krl-refresh.timer "$(ob_krl_oncalendar "$n")" || echo "write:$OB_TIMERS_MSG"
            cd "$work" && SYSTEMD_UNIT_PATH="$work:" \
                systemd-analyze verify --man=no "$work/ob-krl-refresh.timer" 2>&1 || echo "rc"
        )
        out=$(_ours <<<"$out")
        # shellcheck disable=SC2031  # n is only read in the subshell
        [ -z "$out" ] || bad="$bad interval-$n:$(tr '\n' ' ' <<<"$out")"
    done
    rm -rf "$work"
    if [ -z "$bad" ]; then
        pass "systemd-analyze verify accepts the timers, their services and every schedule drop-in"
    else
        fail "systemd-analyze verify" "$bad"
    fi
}

run_test test_no_duplicate_unit_files
run_test test_rules_units_are_installed
run_test test_templates_have_sockets
run_test test_rpm_units_exist
run_test test_socket_services_are_hardened
run_test test_timers_have_services_and_ship
run_test test_opt_in_timers_not_enabled_at_install
run_test test_krl_service_sandbox
run_test test_units_verify

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
