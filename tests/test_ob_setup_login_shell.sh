#!/bin/bash
# test_ob_setup_login_shell.sh -- who gets ob-login-shell, and how (#293).
#
# On a host that records sessions, sshd runs the ForceCommand through the login
# shell, and bash or zsh read the user's startup files before the recorder.
# libnss_openbastion hands out /usr/sbin/ob-login-shell instead when
# nss_openbastion.conf says `force_shell`. These tests pin who writes that key,
# and when:
#
#   - the setup writes it on the bastion and standalone roles, and only when
#     sessions are recorded: not on a backend (no ForceCommand), not under
#     --disable-session-recorder (no recorder). default_shell stays bash
#     everywhere: on a recording host it is the recorded session's shell;
#   - the setup refuses to force a launcher that is not installed (that would
#     lock every SSO user out), lists it in /etc/shells, and pins
#     PermitUserEnvironment off next to the ForceCommand;
#   - ob-post-upgrade adds the key to a recording host set up before, and only
#     there, leaving the rest of the file byte for byte and an administrator's
#     own force_shell alone;
#   - the shared library (scripts/ob-login-shell-lib.sh) that both use.
# shellcheck disable=SC2034  # variables are read by the loaded script's functions
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"
LIB="$ROOT_DIR/scripts/ob-login-shell-lib.sh"
POST="$ROOT_DIR/scripts/ob-post-upgrade"

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

# shellcheck source=tests/lib_setup_script.sh
. "$TESTS_DIR/lib_setup_script.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK" "$SETUP_LINK_DIR"' EXIT
export OB_LOGIN_SHELL_LIB="$LIB"

echo "=== the SSO login shell on a recording host (#293) ==="

# The NSS configuration the setup renders as NAME with ARGS (dry run).
render_nss_as() {
    local name="$1"
    shift
    (
        load_setup_as "$name" || exit 99
        parse_args -p "https://x.example.com" -g g --dry-run "$@" >/dev/null 2>&1 || exit 98
        load_login_shell_lib || exit 97
        render_nss_conf
    )
}

forces_launcher() { grep -qx 'force_shell = /usr/sbin/ob-login-shell' <<<"$1"; }

# ── 1. Which roles force the launcher ────────────────────────────────────────
test_force_shell_by_role() {
    local bad="" out
    for spec in "ob-bastion-setup:yes" "ob-standalone-setup:yes" "ob-backend-setup:no" \
                "ob-bastion-setup --node-role backend:no" \
                "ob-backend-setup --node-role bastion:yes" \
                "ob-bastion-setup --disable-session-recorder:no" \
                "ob-standalone-setup --disable-session-recorder:no"; do
        local want="${spec##*:}" cmd="${spec%:*}"
        # shellcheck disable=SC2086  # the command and its options split on purpose
        out=$(render_nss_as $cmd)
        [ -n "$out" ] || { bad="$bad [$cmd]:no-output"; continue; }
        grep -qx 'default_shell = /bin/bash' <<<"$out" || bad="$bad [$cmd]:default_shell"
        if [ "$want" = yes ]; then
            forces_launcher "$out" || bad="$bad [$cmd]:not-forced"
        else
            grep -q '^force_shell' <<<"$out" && bad="$bad [$cmd]:forced"
        fi
    done
    if [ -z "$bad" ]; then
        pass "force_shell on bastion and standalone when recording; not on a backend, not with --disable-session-recorder"
    else
        fail "force_shell follows the role and the recorder" "$bad"
    fi
}

# ── 2. The sshd drop-in pins PermitUserEnvironment next to the ForceCommand ──
test_dropin_pins_user_environment() {
    local bad="" out
    out=$( load_setup_as ob-bastion-setup || exit 99
           parse_args -p https://x.example.com -g g --dry-run >/dev/null 2>&1
           configure_sshd 2>&1 )
    grep -qx 'PermitUserEnvironment no' <<<"$out" || bad="$bad bastion:missing"
    out=$( load_setup_as ob-bastion-setup || exit 99
           parse_args -p https://x.example.com -g g --dry-run --disable-session-recorder >/dev/null 2>&1
           configure_sshd 2>&1 )
    grep -q 'PermitUserEnvironment' <<<"$out" && bad="$bad no-recorder:present"
    if [ -z "$bad" ]; then
        pass "a recording bastion's drop-in pins PermitUserEnvironment no (~/.ssh/environment is the user's file)"
    else
        fail "the drop-in pins PermitUserEnvironment no" "$bad"
    fi
}

# Run configure_nss for real against files in $WORK. $1 = the launcher path
# the lib should check, $2... = setup arguments.
configure_nss_in_work() {
    local launcher="$1"
    shift
    rm -rf "${WORK:?}/etc"
    mkdir -p "$WORK/etc"
    printf 'passwd:         files systemd\ngroup:          files systemd\n' > "$WORK/etc/nsswitch.conf"
    printf '/bin/sh\n/bin/bash\n' > "$WORK/etc/shells"
    (
        load_setup_as ob-bastion-setup || exit 99
        parse_args -p https://x.example.com -g g "$@" >/dev/null 2>&1 || exit 98
        # shellcheck source=scripts/ob-login-shell-lib.sh
        . "$LIB"
        OB_LOGIN_SHELL="$launcher"
        ob_restart_nscd() { echo "nscd-restarted" >> "$WORK/etc/nscd"; }
        NSSWITCH_CONF="$WORK/etc/nsswitch.conf"
        NSS_OB_CONF="$WORK/etc/nss_openbastion.conf"
        SHELLS_FILE="$WORK/etc/shells"
        BACKUP_DIR="$WORK/backup"
        configure_nss
    ) >"$WORK/out" 2>&1
}

# ── 3. The setup writes the key, registers the shell, restarts nscd ──────────
test_setup_writes_and_registers() {
    local bad="" fake="$WORK/ob-login-shell"
    printf '#!/bin/sh\n' > "$fake"
    chmod 755 "$fake"
    configure_nss_in_work "$fake" || bad="$bad rc:$(tail -3 "$WORK/out")"
    grep -qx "force_shell = $fake" "$WORK/etc/nss_openbastion.conf" 2>/dev/null || bad="$bad conf"
    [ "$(stat -c %a "$WORK/etc/nss_openbastion.conf" 2>/dev/null)" = 644 ] || bad="$bad mode"
    [ "$(grep -cxF "$fake" "$WORK/etc/shells")" = 1 ] || bad="$bad shells"
    grep -q nscd-restarted "$WORK/etc/nscd" 2>/dev/null || bad="$bad nscd"
    grep -q 'openbastion' "$WORK/etc/nsswitch.conf" || bad="$bad nsswitch"
    if [ -z "$bad" ]; then
        pass "a recording bastion's NSS config forces the launcher, /etc/shells lists it, nscd is restarted"
    else
        fail "the setup writes force_shell and registers the launcher" "$bad"
    fi
}

test_setup_refuses_missing_launcher() {
    local rc=0
    configure_nss_in_work "$WORK/not-installed" || rc=$?
    if [ "$rc" -ne 0 ] && [ ! -e "$WORK/etc/nss_openbastion.conf" ] \
       && grep -q 'is missing' "$WORK/out"; then
        pass "no launcher installed: the setup refuses before writing NSS, rather than lock SSO users out"
    else
        fail "no launcher installed: the setup refuses" "rc=$rc $(tail -2 "$WORK/out")"
    fi
}

test_setup_without_recorder_keeps_bash() {
    local bad=""
    configure_nss_in_work "$WORK/not-installed" --disable-session-recorder || bad="$bad rc"
    grep -q '^force_shell' "$WORK/etc/nss_openbastion.conf" 2>/dev/null && bad="$bad forced"
    grep -qF "$WORK/not-installed" "$WORK/etc/shells" && bad="$bad registered"
    if [ -z "$bad" ]; then
        pass "without a recorder, no launcher is needed or forced"
    else
        fail "without a recorder, no launcher is needed or forced" "$bad"
    fi
}

# ── 4. The library ───────────────────────────────────────────────────────────
test_lib_force_launcher() {
    local bad="" conf="$WORK/nss.conf" before rc
    (
        # shellcheck source=scripts/ob-login-shell-lib.sh
        . "$LIB"
        # The file an older setup wrote.
        printf '# old\nportal_url = https://x\ndefault_shell = /bin/bash\n# force_shell = /bin/sh\nhome_base = /home' > "$conf"
        chmod 644 "$conf"
        before=$(cat "$conf")
        ob_nss_force_launcher "$conf" || echo "rc=$?"
        [ "$(ob_nss_force_shell_value "$conf")" = /usr/sbin/ob-login-shell ] || echo "not-forced"
        [ "$(head -c ${#before} "$conf")" = "$before" ] || echo "rest-changed"
        [ "$(stat -c %a "$conf")" = 644 ] || echo "mode"
        [ "$(grep -c '^force_shell' "$conf")" = 1 ] || echo "count"
        # Idempotent.
        cp "$conf" "$conf.1"
        ob_nss_force_launcher "$conf" || echo "rc2=$?"
        cmp -s "$conf" "$conf.1" || echo "rewritten"
        # An administrator's own value is theirs.
        printf 'force_shell = "/usr/local/sbin/mine"\n' > "$conf"
        rc=0; ob_nss_force_launcher "$conf" || rc=$?
        [ "$rc" = 2 ] || echo "other-value-rc=$rc"
        [ "$(cat "$conf")" = 'force_shell = "/usr/local/sbin/mine"' ] || echo "other-value-changed"
        [ "$(ob_nss_force_shell_value "$conf")" = /usr/local/sbin/mine ] || echo "value-quotes"
    ) > "$WORK/lib.out" 2>&1
    bad=$(tr '\n' ' ' < "$WORK/lib.out")
    if [ -z "$bad" ]; then
        pass "ob_nss_force_launcher appends the key once, keeps the rest byte for byte, leaves another value alone"
    else
        fail "ob_nss_force_launcher" "$bad"
    fi
}

test_lib_records_sessions() {
    local bad="" d="$WORK/sshd.d" main="$WORK/sshd_config"
    (
        # shellcheck source=scripts/ob-login-shell-lib.sh
        . "$LIB"
        rm -rf "$d"; mkdir -p "$d"; : > "$main"
        ob_host_records_sessions "$d" "$main" && echo "empty:yes"
        printf 'ForceCommand /usr/sbin/ob-session-recorder\n' > "$d/00-open-bastion-bastion.conf"
        ob_host_records_sessions "$d" "$main" || echo "bastion:no"
        printf '# Session recording disabled via --disable-session-recorder\n' > "$d/00-open-bastion-bastion.conf"
        ob_host_records_sessions "$d" "$main" && echo "disabled:yes"
        printf '#ForceCommand /usr/sbin/ob-session-recorder\n' > "$d/00-open-bastion-bastion.conf"
        ob_host_records_sessions "$d" "$main" && echo "commented:yes"
        rm -f "$d"/*
        printf 'ForceCommand /usr/sbin/ob-session-recorder\n' > "$d/00-open-bastion-backend.conf"
        ob_host_records_sessions "$d" "$main" && echo "backend-name:yes"
        rm -rf "$d"
        printf 'TrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\nForceCommand /usr/sbin/ob-session-recorder\n' > "$main"
        ob_host_records_sessions "$d" "$main" || echo "main-block:no"
        printf 'ForceCommand /usr/sbin/ob-session-recorder\n' > "$main"
        ob_host_records_sessions "$d" "$main" && echo "main-not-ours:yes"
    ) > "$WORK/rec.out" 2>&1
    bad=$(tr '\n' ' ' < "$WORK/rec.out")
    if [ -z "$bad" ]; then
        pass "a host records when the setup's sshd block (drop-in, or sshd_config without drop-ins) has the recorder ForceCommand"
    else
        fail "ob_host_records_sessions" "$bad"
    fi
}

test_lib_register_shell() {
    local out
    out=$(
        # shellcheck source=scripts/ob-login-shell-lib.sh
        . "$LIB"
        printf '/bin/sh\n' > "$WORK/shells"
        ob_register_login_shell "$WORK/shells"
        ob_register_login_shell "$WORK/shells"
        cat "$WORK/shells"
    )
    if [ "$out" = $'/bin/sh\n/usr/sbin/ob-login-shell' ]; then
        pass "the launcher is listed in /etc/shells once"
    else
        fail "the launcher is listed in /etc/shells once" "$out"
    fi
}

# ── 5. ob-post-upgrade ───────────────────────────────────────────────────────
post_upgrade_dry() {  # $1 = drop-in content ("" for none), $2 = NSS config content
    local d="$WORK/pu"
    rm -rf "$d"
    mkdir -p "$d/sshd.d"
    printf 'node_role = bastion\n' > "$d/ob.conf"
    if [ -n "$1" ]; then
        printf 'AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %%u %%f %%t %%k\n%s\n' \
            "$1" > "$d/sshd.d/00-open-bastion-bastion.conf"
    fi
    printf '%s\n' "$2" > "$d/nss.conf"
    OB_CONFIG="$d/ob.conf" OB_SSHD_CONFIG_DIR="$d/sshd.d" OB_SSHD_CONFIG="$d/none" \
        OB_NSS_CONF="$d/nss.conf" OB_SHELLS_FILE="$d/shells" \
        "$POST" --dry-run 2>&1
}

test_post_upgrade_switches_recording_hosts() {
    local bad="" out
    out=$(post_upgrade_dry "ForceCommand /usr/sbin/ob-session-recorder" "default_shell = /bin/bash")
    grep -q 'would make /usr/sbin/ob-login-shell the login shell' <<<"$out" || bad="$bad not-proposed"
    out=$(post_upgrade_dry "ForceCommand /usr/sbin/ob-session-recorder" \
          $'default_shell = /bin/bash\nforce_shell = /usr/sbin/ob-login-shell')
    grep -q 'SSO users log in through /usr/sbin/ob-login-shell' <<<"$out" || bad="$bad not-seen-as-done"
    grep -q 'would make' <<<"$out" && bad="$bad proposed-twice"
    out=$(post_upgrade_dry "# Session recording disabled via --disable-session-recorder" \
          "default_shell = /bin/bash")
    grep -q 'would make' <<<"$out" && bad="$bad forced-without-recorder"
    out=$(post_upgrade_dry "ForceCommand /usr/sbin/ob-session-recorder" \
          "force_shell = /usr/local/sbin/mine")
    grep -q 'forces the login shell /usr/local/sbin/mine' <<<"$out" || bad="$bad admin-value-not-reported"
    grep -q 'would make' <<<"$out" && bad="$bad admin-value-overridden"
    if [ -z "$bad" ]; then
        pass "ob-post-upgrade forces the launcher on a recording host that lacks it, and nowhere else"
    else
        fail "ob-post-upgrade forces the launcher on recording hosts" "$bad"
    fi
}

# ob-post-upgrade writes nss_openbastion.conf through the library and nowhere
# else: the one write it makes to configuration, and it has to stay that.
test_post_upgrade_writes_nss_only_through_lib() {
    local hits
    hits=$(grep -nE '>[^&]*\$\{?NSS_CONF|sed -i[^#]*NSS_CONF|mv [^#]*NSS_CONF' "$POST" \
           | grep -vE '^[0-9]+:[[:space:]]*#')
    if [ -z "$hits" ] && grep -q 'ob_nss_force_launcher "\$NSS_CONF"' "$POST"; then
        pass "ob-post-upgrade changes nss_openbastion.conf only through ob_nss_force_launcher"
    else
        fail "ob-post-upgrade changes nss_openbastion.conf only through the library" "$hits"
    fi
}

# ── 6. Packaging ─────────────────────────────────────────────────────────────
# The postinst lists the launcher in /etc/shells on every configure, and tells
# a recording host that still hands out bash to run ob-post-upgrade.
test_postinst_registers_and_warns() {
    local bad="" d="$WORK/pi" out
    rm -rf "$d"
    mkdir -p "$d/bin" "$d/sshd.d"
    sed -n '/^note_login_shell() {/,/^}/p' "$ROOT_DIR/debian/open-bastion.postinst" > "$d/fn.sh"
    [ -s "$d/fn.sh" ] || { fail "the postinst registers and warns" "note_login_shell not found"; return; }
    printf '#!/bin/sh\necho "$1" >> "%s/added"\n' "$d" > "$d/bin/add-shell"
    chmod +x "$d/bin/add-shell"
    run_pi() { (cd "$d" && PATH="$d/bin:$PATH" sh -c '. ./fn.sh; note_login_shell "$1" "$2"' _ "$d/sshd.d" "$d/nss.conf" 2>&1); }

    printf 'ForceCommand /usr/sbin/ob-session-recorder\n' > "$d/sshd.d/00-open-bastion-bastion.conf"
    printf 'default_shell = /bin/bash\n' > "$d/nss.conf"
    out=$(run_pi)
    grep -q 'ACTION REQUIRED' <<<"$out" && grep -q 'ob-post-upgrade' <<<"$out" || bad="$bad no-warning"
    grep -qx /usr/sbin/ob-login-shell "$d/added" 2>/dev/null || bad="$bad not-added"

    printf 'force_shell = /usr/sbin/ob-login-shell\n' >> "$d/nss.conf"
    out=$(run_pi)
    [ -z "$out" ] || bad="$bad warns-when-done"
    printf '# Session recording disabled\n' > "$d/sshd.d/00-open-bastion-bastion.conf"
    printf 'default_shell = /bin/bash\n' > "$d/nss.conf"
    out=$(run_pi)
    [ -z "$out" ] || bad="$bad warns-without-recorder"
    rm -f "$d/sshd.d/"*
    out=$(run_pi)
    [ -z "$out" ] || bad="$bad warns-on-unconfigured-host"
    [ "$(grep -c . "$d/added")" = 4 ] || bad="$bad not-added-every-time"
    if [ -z "$bad" ]; then
        pass "the postinst lists the launcher in /etc/shells, and asks a recording host still on bash to run ob-post-upgrade"
    else
        fail "the postinst registers the launcher and warns" "$bad"
    fi
}

test_packages_ship_and_unregister() {
    local bad="" f
    for f in usr/sbin/ob-login-shell usr/lib/open-bastion/ob-login-shell-lib.sh \
             usr/share/man/man8/ob-login-shell.8; do
        grep -qx "$f" "$ROOT_DIR/debian/open-bastion.install" || bad="$bad deb:$f"
    done
    grep -q 'remove-shell /usr/sbin/ob-login-shell' "$ROOT_DIR/debian/open-bastion.postrm" \
        || bad="$bad postrm"
    for f in '%{_sbindir}/ob-login-shell' '%{_prefix}/lib/open-bastion/ob-login-shell-lib.sh' \
             '%{_mandir}/man8/ob-login-shell.8*'; do
        grep -qxF "$f" "$ROOT_DIR/rpm/open-bastion.spec" || bad="$bad rpm:$f"
    done
    grep -q '>> /etc/shells' "$ROOT_DIR/rpm/open-bastion.spec" || bad="$bad rpm-post"
    grep -q 'ob-login-shell\$#d. /etc/shells' "$ROOT_DIR/rpm/open-bastion.spec" || bad="$bad rpm-postun"
    if [ -z "$bad" ]; then
        pass "both packages ship the launcher, its library and man page, and take it out of /etc/shells on removal"
    else
        fail "the packages ship and unregister the launcher" "$bad"
    fi
}

run_test test_force_shell_by_role
run_test test_dropin_pins_user_environment
run_test test_setup_writes_and_registers
run_test test_setup_refuses_missing_launcher
run_test test_setup_without_recorder_keeps_bash
run_test test_lib_force_launcher
run_test test_lib_records_sessions
run_test test_lib_register_shell
run_test test_post_upgrade_switches_recording_hosts
run_test test_post_upgrade_writes_nss_only_through_lib
run_test test_postinst_registers_and_warns
run_test test_packages_ship_and_unregister

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
