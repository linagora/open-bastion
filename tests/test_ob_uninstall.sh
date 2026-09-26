#!/bin/bash
# test_ob_uninstall.sh
#
# Runs ob-uninstall for real (not --dry-run) against a fake root (OB_ROOT),
# with the system commands stubbed through PATH. Fixtures that depend on
# what the setup writes are made by the setup's own functions.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/ob-uninstall"

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

[ -f "$SCRIPT" ] || { echo "SKIP: $SCRIPT not found"; exit 0; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# Its EXIT trap is replaced by ours below, which also removes its directory.
# shellcheck source=tests/lib_setup_script.sh
. "$ROOT_DIR/tests/lib_setup_script.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK" "$SETUP_LINK_DIR"' EXIT

echo "=== ob-uninstall ==="

SECRET="s3cr3t+Client/Secret=="
REFRESH="rt-THE-refresh-token-0123"
ACCESS="at-THE-access-token-4567"

# Stubs log their argv to $STUB_LOG. The sshd stub answers `sshd -t` from
# STUB_SSHD_FAIL: it cannot validate the sandbox's sshd configuration.
STUBS="$WORK/stubs"
mkdir -p "$STUBS"

cat > "$STUBS/systemctl" <<'EOF'
#!/bin/bash
# A reload records the host's state at that instant: what matters is the
# order of changes, which a log of commands cannot show.
if [ "$1" = "reload-or-restart" ]; then
    st() { if grep -qE "$2" "$OB_ROOT$1" 2>/dev/null; then echo dirty; else echo clean; fi; }
    ex() { if [ -e "$OB_ROOT$1" ]; then echo present; else echo absent; fi; }
    echo "systemctl $* pam=$(st /etc/pam.d/sshd pam_openbastion) nss=$(st /etc/nsswitch.conf openbastion) ca=$(ex /etc/ssh/open-bastion_ca.pub) helper=$(ex /usr/local/sbin/ob-ssh-principals)" >> "$STUB_LOG"
    exit 0
fi
echo "systemctl $*" >> "$STUB_LOG"
case "$1" in
    is-active)
        [ "$2" = "--quiet" ] && shift
        case " ${STUB_ACTIVE:-} " in *" $2 "*) exit 0 ;; *) exit 3 ;; esac ;;
    is-enabled)
        if [ "$2" = "atd" ]; then echo "${STUB_ATD_STATE:-enabled}"; [ "${STUB_ATD_STATE:-enabled}" = enabled ]; exit; fi
        [ "$2" = "--quiet" ] && [ "$3" = "atd" ] && exit 0
        exit 1 ;;
    disable)
        case "$3" in
            ob-fp.socket) echo "Failed to disable unit: Unit file ob-fp.socket does not exist." >&2; exit 1 ;;
        esac
        exit 0 ;;
esac
exit 0
EOF

cat > "$STUBS/sshd" <<'EOF'
#!/bin/bash
echo "sshd $*" >> "$STUB_LOG"
if [ -n "${STUB_SSHD_FAIL:-}" ]; then
    echo "/etc/ssh/sshd_config line 3: Bad configuration option: Frobnicate" >&2
    exit 255
fi
exit 0
EOF

cat > "$STUBS/curl" <<'EOF'
#!/bin/bash
# One line per call in each file: argv (space-joined) and the body.
printf '%s ' "$@" >> "$STUB_CURL_ARGV"; echo >> "$STUB_CURL_ARGV"
cat >> "$STUB_CURL_BODY"; echo >> "$STUB_CURL_BODY"
echo "curl" >> "$STUB_LOG"
rc="${STUB_CURL_RC:-0}"
[ "$rc" = 0 ] && printf 200 || printf 401
exit "$rc"
EOF

cat > "$STUBS/ob-client-jwt" <<'EOF'
#!/bin/bash
printf '%s ' "$@" >> "$STUB_JWT_ARGV"; echo >> "$STUB_JWT_ARGV"
cat > "$STUB_JWT_STDIN"
echo "ob-client-jwt" >> "$STUB_LOG"
printf 'eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ4In0.SIGNATURE'
EOF

# STUB_DEBCONF_MODE: what `debconf-show open-bastion` reports.
cat > "$STUBS/debconf-show" <<'EOF'
#!/bin/bash
[ -n "${STUB_DEBCONF_MODE:-}" ] && echo "* open-bastion/pam-mode: $STUB_DEBCONF_MODE"
echo "  open-bastion/portal-url: https://auth.example.com"
exit 0
EOF
cat > "$STUBS/debconf-set-selections" <<'EOF'
#!/bin/bash
echo "debconf-set-selections $(cat)" >> "$STUB_LOG"
EOF

for c in visudo groupdel augenrules loginctl restorecon; do
    printf '#!/bin/bash\necho "%s $*" >> "$STUB_LOG"\nexit 0\n' "$c" > "$STUBS/$c"
done
# Never let the host's real login name decide the lockout guard.
printf '#!/bin/bash\nexit 1\n' > "$STUBS/logname"
chmod +x "$STUBS"/*

wr() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

OB_PAM_SSHD='# PAM configuration for SSH with LemonLDAP::NG bastion
auth       required     pam_deny.so
account    required     pam_openbastion.so ssh_cert_aware=true
session    required     pam_unix.so
session    optional     pam_openbastion.so'
OB_PAM_SUDO='# PAM configuration for sudo with Open Bastion (Mode E - Maximum Security)
auth       sufficient   pam_openbastion.so
auth       required     pam_deny.so
account    required     pam_openbastion.so
session    required     pam_unix.so'

# A bastion after two setup runs (Mode E, hardening, audit, service keys):
# the first backed up the distro files, the second our own.
mkroot_bastion() {
    local r="$1"
    mkdir -p "$r"
    printf 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n' | wr "$r/etc/passwd"
    printf 'root:*:19000:0:99999:7:::\nadmin:$6$salt$hash:19000:0:99999:7:::\n' | wr "$r/etc/shadow"
    printf 'root:x:0:\nopen-bastion-sudo:x:999:\n' | wr "$r/etc/group"
    printf 'root:*::\nopen-bastion-sudo:!::\n' | wr "$r/etc/gshadow"
    printf '#includedir /etc/sudoers.d\n' | wr "$r/etc/sudoers"
    mkdir -p "$r/var/lib/dpkg"

    printf 'Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nUsePAM yes\n' | wr "$r/etc/ssh/sshd_config"
    printf '# LemonLDAP::NG Bastion Configuration\nTrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\nAuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %%u %%f %%t %%k\nForceCommand /usr/sbin/ob-session-recorder\n' \
        | wr "$r/etc/ssh/sshd_config.d/00-open-bastion-bastion.conf"
    printf '# Open Bastion service-account SSH layer\nAuthorizedKeysCommand /usr/sbin/ob-service-account-keys %%u\n' \
        | wr "$r/etc/ssh/sshd_config.d/09-open-bastion-service-keys.conf"
    printf 'PasswordAuthentication yes\n' | wr "$r/etc/ssh/sshd_config.d/50-cloud-init.conf"
    printf '# Open Bastion Maximum Security Configuration (Mode E)\nAuthorizedKeysFile none\nRevokedKeys /etc/ssh/revoked_keys\n' \
        | wr "$r/etc/ssh/sshd_config.d/60-max-security.conf"
    echo "ssh-ed25519 AAAAca" | wr "$r/etc/ssh/open-bastion_ca.pub"
    echo "SSHKRL" | wr "$r/etc/ssh/revoked_keys"

    echo "$OB_PAM_SSHD" | wr "$r/etc/pam.d/sshd"
    echo "$OB_PAM_SUDO" | wr "$r/etc/pam.d/sudo"
    echo "$OB_PAM_SUDO" | wr "$r/etc/pam.d/sudo-i"
    echo "@include common-auth" | wr "$r/etc/pam.d/login"
    for f in common-auth common-account common-session common-password common-session-noninteractive; do
        echo "# $f" | wr "$r/etc/pam.d/$f"
    done

    local b1="$r/var/backup/open-bastion-setup-20260101-000000"
    local b2="$r/var/backup/open-bastion-setup-20260201-000000"
    echo "# distro sshd (oldest)" | wr "$b1/sshd"
    echo "# distro sudo (oldest)" | wr "$b1/sudo"
    echo "# distro sudo-i (oldest)" | wr "$b1/sudo-i"
    echo "Include /etc/ssh/sshd_config.d/*.conf" | wr "$b1/sshd_config"
    # The setup's own copy keeps the secret in clear.
    printf 'client_secret = %s\n' "$SECRET" | wr "$b1/openbastion.conf"
    echo "$OB_PAM_SSHD" | wr "$b2/sshd"
    echo "$OB_PAM_SUDO" | wr "$b2/sudo"
    echo "$OB_PAM_SUDO" | wr "$b2/sudo-i"

    # Tabs on the group line: the edit must remove a word, not re-flow the line.
    printf '# nsswitch\npasswd:         files openbastion systemd\ngroup:\tfiles\topenbastion\tsystemd\nshadow:         files openbastion\nhosts:          files dns\n' \
        | wr "$r/etc/nsswitch.conf"

    printf '# Open Bastion Mode E: defense-in-depth sudo authorization\n%%open-bastion-sudo ALL=(ALL) ALL\n' \
        | wr "$r/etc/sudoers.d/open-bastion"
    printf 'admin ALL=(ALL) ALL\n' | wr "$r/etc/sudoers.d/90-local"

    { printf 'portal_url = https://auth.example.com/\n'
      printf 'server_token_file = /var/lib/open-bastion/token\n'
      printf 'node_role = bastion\n'
      printf 'client_id = bastion-rp\n'
      printf 'client_secret = %s\n' "$SECRET"
      printf 'verify_ssl = false # lab\n'; } | wr "$r/etc/open-bastion/openbastion.conf"
    echo "PORTAL_URL=x" | wr "$r/etc/open-bastion/ssh-proxy.conf"
    echo "sessions_dir = x" | wr "$r/etc/open-bastion/session-recorder.conf"
    echo "portal_url = x" | wr "$r/etc/open-bastion/nss_openbastion.conf"
    echo "svc key_fingerprint=SHA256:x" | wr "$r/etc/open-bastion/service-accounts.conf"
    echo "ssh-ed25519 AAAAsvc" | wr "$r/etc/open-bastion/service-accounts.d/svc.pub"

    printf '{"access_token":"%s","refresh_token":"%s"}\n' "$ACCESS" "$REFRESH" | wr "$r/var/lib/open-bastion/token"
    echo "recording" | wr "$r/var/lib/open-bastion/sessions/alice/20260301-rec.cast"
    echo "cached" | wr "$r/var/cache/open-bastion/auth/x"
    echo "alice" | wr "$r/var/cache/nss_llng/byname/alice"

    echo "#!/bin/sh" | wr "$r/usr/local/sbin/ob-ssh-principals"
    echo "d /run/open-bastion/ssh-fp" | wr "$r/etc/tmpfiles.d/open-bastion-ssh-fp.conf"

    echo "[Login]" | wr "$r/etc/systemd/logind.conf.d/open-bastion.conf"
    echo "* hard nproc 512" | wr "$r/etc/security/limits.d/open-bastion.conf"
    echo "root" | wr "$r/usr/share/open-bastion/hardening/at.allow"
    echo "root" | wr "$r/usr/share/open-bastion/hardening/cron.allow"
    printf 'root\nbob\n' | wr "$r/etc/at.allow"          # admin-edited
    echo "root" | wr "$r/etc/cron.allow"                 # ours, verbatim

    echo "-a always,exit" | wr "$r/etc/audit/rules.d/open-bastion.rules"
    # The KRL timer's drop-in, as --krl-refresh-interval 10 writes it.
    real_timer_dropin "$r" ob-krl-refresh.timer '*:0/10' \
        || echo "fixture: ob_timer_set_schedule failed" >&2
}

# Cron jobs of a host never migrated to the timers.
add_legacy_cron() {
    local r="$1"
    echo "*/30 * * * * root /usr/local/bin/open-bastion-refresh-krl >/dev/null 2>&1" \
        | wr "$r/etc/cron.d/open-bastion-krl"
    printf '#!/bin/bash\ncurl -sf "https://auth.example.com/ssh/revoked" -o "$tmp"\n' \
        | wr "$r/usr/local/bin/open-bastion-refresh-krl"
    printf '#!/bin/sh\n# Installed by `ob-bastion-setup --enable-audit-trace`\n' \
        | wr "$r/etc/cron.weekly/open-bastion-audit-rotate"
}

# A backend with no setup backup of its PAM stacks.
mkroot_backend() {
    local r="$1"
    mkroot_bastion "$r"
    rm -rf "$r/var/backup" "$r/etc/ssh/sshd_config.d/00-open-bastion-bastion.conf"
    printf '# LemonLDAP::NG Backend Configuration\nTrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\n' \
        | wr "$r/etc/ssh/sshd_config.d/00-open-bastion-backend.conf"
    echo "bastion-a" | wr "$r/etc/open-bastion/allowed_bastions"
    sed -i 's/^node_role = .*/node_role = backend/' "$r/etc/open-bastion/openbastion.conf"
}

# Under OB_ROOT, ob-uninstall keeps PATH: RUN_PATH decides what it finds.
RUN_PATH="$STUBS:$PATH"
run_un() {
    local r="$1"
    shift
    : > "$r.log"
    rm -f "$r.curl-argv" "$r.curl-body" "$r.jwt-argv" "$r.jwt-stdin"
    env OB_ROOT="$r" PATH="${RUN_PATH_OVERRIDE:-$RUN_PATH}" STUB_LOG="$r.log" \
        STUB_CURL_ARGV="$r.curl-argv" STUB_CURL_BODY="$r.curl-body" \
        STUB_JWT_ARGV="$r.jwt-argv" STUB_JWT_STDIN="$r.jwt-stdin" \
        SUDO_USER="${SUDO_USER_OVERRIDE:-admin}" \
        bash "$SCRIPT" "$@" > "$WORK/out" 2>&1
}

tree_sum() {
    (cd "$1" && find . -printf '%p %m\n' | sort && find . -type f -exec sha256sum {} + | sort)
}

backup_dir_of() {
    local d
    for d in "$1"/var/backup/open-bastion-uninstall-*; do
        [ -d "$d" ] && { printf '%s' "$d"; return; }
    done
}

# real_setup_run ROOT NAME TS [VAR=value | function]...
# Runs the setup's own functions as NAME against ROOT, backing up into
# open-bastion-setup-TS. The sudoers writer and groupadd reach the real
# /etc whatever the paths, so they are no-ops.
real_setup_run() {
    local r="$1" name="$2" ts="$3"
    shift 3
    (
        PATH="$STUBS:$PATH"
        export STUB_LOG=/dev/null
        load_setup_as "$name" || exit 99
        # shellcheck disable=SC2034  # read by the loaded functions
        {
            SSHD_CONFIG="$r/etc/ssh/sshd_config"; SSHD_CONFIG_DIR="$r/etc/ssh/sshd_config.d"
            PAM_SSHD="$r/etc/pam.d/sshd"; PAM_SUDO="$r/etc/pam.d/sudo"; PAM_SUDO_I="$r/etc/pam.d/sudo-i"
            BACKUP_DIR="$r/var/backup/open-bastion-setup-$ts"
            DRY_RUN=false; MAX_SECURITY=true; NON_INTERACTIVE=true
        }
        write_open_bastion_sudoers() { :; }
        groupadd() { :; }
        info() { :; }; warn() { :; }; step() { :; }
        local a
        for a in "$@"; do
            case "$a" in
                *=*) eval "$a" ;;
                *)   "$a" || exit 1 ;;
            esac
        done
    )
}

# The schedule drop-in ob-timers-lib.sh writes for a timer, in root $1.
real_timer_dropin() {
    (
        # shellcheck disable=SC2034  # read by the sourced library
        OB_SYSTEMD_UNIT_DIR="$1/etc/systemd/system"
        # shellcheck source=scripts/ob-timers-lib.sh
        . "$ROOT_DIR/scripts/ob-timers-lib.sh"
        ob_timer_set_schedule "$2" "$3"
    )
}

test_syntax() {
    if bash -n "$SCRIPT" 2>/dev/null; then
        pass "ob-uninstall parses"
    else
        fail "ob-uninstall parses" "$(bash -n "$SCRIPT" 2>&1)"
    fi
}

test_nothing_configured() {
    local r="$WORK/empty"
    mkdir -p "$r/etc/pam.d" "$r/etc/ssh/sshd_config.d"
    echo "@include common-auth" > "$r/etc/pam.d/sshd"
    if run_un "$r" -y && grep -q "nothing to do" "$WORK/out" && [ ! -d "$r/var/backup" ]; then
        pass "a host that was never set up: 'nothing to do', exit 0, no backup dir"
    else
        fail "a host that was never set up: 'nothing to do', exit 0" "$(cat "$WORK/out")"
    fi
}

test_dry_run_is_inert() {
    local r="$WORK/dry" before after
    mkroot_bastion "$r"
    before=$(tree_sum "$r")
    STUB_DEBCONF_MODE=mode-c run_un "$r" --dry-run
    local rc=$?
    after=$(tree_sum "$r")
    if [ "$rc" -eq 0 ] && [ "$before" = "$after" ] \
       && ! grep -qE 'disable|groupdel|curl|reload|debconf-set-selections|ob-client-jwt' "$r.log" \
       && grep -q 'restore' "$WORK/out"; then
        pass "--dry-run prints the plan, exits 0, and changes nothing (tree checksum, no calls)"
    else
        fail "--dry-run changes nothing" "rc=$rc; calls: $(tr '\n' ';' < "$r.log")"
    fi
}

FULL="$WORK/full"
test_full_run() {
    mkroot_bastion "$FULL"
    STUB_ACTIVE="ssh auditd" STUB_ATD_STATE=masked run_un "$FULL" -y
    local rc=$? bad="" d="$FULL/etc/ssh/sshd_config.d"
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    for f in 00-open-bastion-bastion.conf 09-open-bastion-service-keys.conf 60-max-security.conf; do
        [ -e "$d/$f" ] && bad="$bad kept:$f"
    done
    [ -f "$d/50-cloud-init.conf" ] || bad="$bad removed:50-cloud-init.conf"
    grep -q '^Include ' "$FULL/etc/ssh/sshd_config" || bad="$bad dropped-Include"
    for f in etc/ssh/open-bastion_ca.pub etc/ssh/revoked_keys usr/local/sbin/ob-ssh-principals \
             etc/tmpfiles.d/open-bastion-ssh-fp.conf etc/open-bastion/openbastion.conf \
             etc/open-bastion/ssh-proxy.conf etc/open-bastion/session-recorder.conf \
             etc/open-bastion/nss_openbastion.conf etc/sudoers.d/open-bastion \
             etc/systemd/logind.conf.d/open-bastion.conf etc/security/limits.d/open-bastion.conf \
             etc/cron.allow etc/audit/rules.d/open-bastion.rules \
             etc/systemd/system/ob-krl-refresh.timer.d var/lib/open-bastion/token; do
        [ -e "$FULL/$f" ] && bad="$bad kept:$f"
    done
    [ -f "$FULL/etc/sudoers.d/90-local" ] || bad="$bad removed:sudoers.d/90-local"
    [ -f "$FULL/etc/open-bastion/service-accounts.conf" ] || bad="$bad removed:service-accounts.conf"
    [ -f "$FULL/etc/open-bastion/service-accounts.d/svc.pub" ] || bad="$bad removed:service-accounts.d"
    [ -n "$(find "$FULL/var/cache" -type f)" ] && bad="$bad cache-not-purged"
    grep -q 'groupdel open-bastion-sudo' "$FULL.log" || bad="$bad no-groupdel"
    grep -q 'sshd -t' "$FULL.log" || bad="$bad no-sshd-t"
    grep -q 'reload systemd-logind' "$FULL.log" || bad="$bad no-logind-reload"
    grep -q 'restart systemd-logind' "$FULL.log" && bad="$bad RESTARTED-logind"
    grep -q 'augenrules --load' "$FULL.log" || bad="$bad no-augenrules"
    grep -q 'restart auditd' "$FULL.log" || bad="$bad no-auditd-restart"
    grep -q 'reload-or-restart ssh' "$FULL.log" || bad="$bad no-sshd-reload"
    grep -q 'unmask atd' "$FULL.log" || bad="$bad atd-not-unmasked"
    # One reload, before any PAM or NSS change and after the CA and the helper
    # are gone: from then on no certificate is accepted.
    [ "$(grep -c 'reload-or-restart' "$FULL.log")" = 1 ] || bad="$bad reload-count"
    grep -q 'reload-or-restart ssh pam=dirty nss=dirty ca=absent helper=absent' "$FULL.log" \
        || bad="$bad reload-state:'$(grep reload-or-restart "$FULL.log")'"
    grep -q 'systemctl daemon-reload' "$FULL.log" || bad="$bad no-daemon-reload"
    for u in ob-heartbeat.timer ob-cert.socket ob-record.socket ob-fp.socket ob-session-prune.timer \
             ob-krl-refresh.timer ob-audit-rotate.timer; do
        grep -q "disable --now $u" "$FULL.log" || bad="$bad not-disabled:$u"
    done
    # A missing unit is not worth a warning.
    grep -q 'could not disable ob-fp.socket' "$WORK/out" && bad="$bad warned-on-missing-unit"
    if [ -z "$bad" ]; then
        pass "a full run removes every Open Bastion file and keeps everything else"
    else
        fail "a full run removes every Open Bastion file and keeps everything else" "$bad"
    fi
}

test_foreign_dropins_kept() {
    local r="$WORK/foreign" d bad=""
    mkroot_bastion "$r"
    d="$r/etc/ssh/sshd_config.d"
    printf 'AuthorizedKeysCommand /opt/ldap-keys %%u\n' > "$d/09-open-bastion-service-keys.conf"
    printf 'AuthorizedKeysFile none\n' > "$d/60-max-security.conf"
    run_un "$r" -y
    [ -f "$d/09-open-bastion-service-keys.conf" ] || bad="$bad removed-foreign-09"
    [ -f "$d/60-max-security.conf" ] || bad="$bad removed-foreign-60"
    [ -e "$d/00-open-bastion-bastion.conf" ] && bad="$bad kept-00"
    # The foreign 60- no longer names revoked_keys, so the KRL still goes.
    [ -e "$r/etc/ssh/revoked_keys" ] && bad="$bad kept-revoked_keys"
    if [ -z "$bad" ]; then
        pass "a 09-/60- drop-in without our header is left alone"
    else
        fail "a 09-/60- drop-in without our header is left alone" "$bad"
    fi
}

test_still_referenced_kept() {
    local r="$WORK/stillref" bad=""
    mkroot_bastion "$r"
    printf 'Match Group ops\n    TrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\n    RevokedKeys /etc/ssh/revoked_keys\n' \
        > "$r/etc/ssh/sshd_config.d/40-site.conf"
    run_un "$r" -y
    [ -f "$r/etc/ssh/open-bastion_ca.pub" ] || bad="$bad removed-ca"
    [ -f "$r/etc/ssh/revoked_keys" ] || bad="$bad removed-krl"
    [ -f "$r/etc/ssh/sshd_config.d/40-site.conf" ] || bad="$bad removed-foreign"
    grep -q '40-site.conf' "$WORK/out" || bad="$bad not-reported"
    if [ -z "$bad" ]; then
        pass "the CA key and KRL stay while a foreign sshd drop-in still reads them, and that is reported"
    else
        fail "files still referenced by a foreign sshd drop-in are kept" "$bad"
    fi
}

test_pam_oldest_clean_backup() {
    local bad=""
    grep -q 'distro sshd (oldest)' "$FULL/etc/pam.d/sshd" || bad="$bad sshd"
    grep -q 'distro sudo (oldest)' "$FULL/etc/pam.d/sudo" || bad="$bad sudo"
    grep -q 'distro sudo-i (oldest)' "$FULL/etc/pam.d/sudo-i" || bad="$bad sudo-i"
    grep -q pam_openbastion "$FULL"/etc/pam.d/* && bad="$bad residue"
    [ "$(stat -c %a "$FULL/etc/pam.d/sshd")" = "644" ] || bad="$bad mode"
    # PAM would read a leftover temporary file in pam.d as a service.
    local t
    for t in "$FULL"/etc/pam.d/*.ob-uninstall.*; do
        [ -e "$t" ] && bad="$bad tmpfile-left"
    done
    if [ -z "$bad" ]; then
        pass "PAM stacks come back from the oldest setup backup that does not load pam_openbastion"
    else
        fail "PAM stacks come back from the oldest clean setup backup" "$bad"
    fi
}

test_pam_oldest_of_two_clean() {
    local r="$WORK/twoclean"
    mkroot_bastion "$r"
    echo "# distro sshd (newer, also clean)" > "$r/var/backup/open-bastion-setup-20260201-000000/sshd"
    run_un "$r" -y
    if grep -q 'distro sshd (oldest)' "$r/etc/pam.d/sshd"; then
        pass "with two clean backups, the oldest is restored"
    else
        fail "with two clean backups, the oldest is restored" "$(head -1 "$r/etc/pam.d/sshd")"
    fi
}

test_pam_debconf_orig() {
    local r="$WORK/debconf" bad=""
    mkroot_bastion "$r"
    echo "# debconf original sshd" | wr "$r/var/backups/open-bastion/sshd.orig"
    # A dirty .orig must be neither used nor left for postrm purge to restore.
    echo "$OB_PAM_SUDO" | wr "$r/var/backups/open-bastion/sudo.orig"
    run_un "$r" -y
    grep -q 'debconf original sshd' "$r/etc/pam.d/sshd" || bad="$bad sshd-not-from-orig"
    grep -q 'distro sudo (oldest)' "$r/etc/pam.d/sudo" || bad="$bad sudo-from-dirty-orig"
    [ -e "$r/var/backups/open-bastion/sudo.orig" ] && bad="$bad dirty-orig-left-for-postrm"
    [ -f "$r/var/backups/open-bastion/sshd.orig" ] || bad="$bad clean-orig-removed"
    if [ -z "$bad" ]; then
        pass "a clean debconf .orig is restored first; a dirty one is removed so postrm cannot restore it"
    else
        fail "debconf .orig handling" "$bad"
    fi
}

# debconf-only host: no sshd drop-in, no setup backup.
test_debconf_only_host() {
    local r="$WORK/debconfonly" bad=""
    mkdir -p "$r/etc/pam.d" "$r/etc/ssh/sshd_config.d"
    printf 'root:x:0:0::/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n' > "$r/etc/passwd"
    echo "$OB_PAM_SSHD" > "$r/etc/pam.d/sshd"
    echo "# debconf original sshd" | wr "$r/var/backups/open-bastion/sshd.orig"
    echo "portal_url = https://auth.example.com" | wr "$r/etc/open-bastion/openbastion.conf"
    STUB_SSHD_FAIL=1 run_un "$r" -y
    local rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    grep -q 'debconf original sshd' "$r/etc/pam.d/sshd" || bad="$bad pam-not-restored"
    grep -q 'sshd -t' "$r.log" && bad="$bad validated-untouched-sshd"
    [ -e "$r/etc/open-bastion/openbastion.conf" ] && bad="$bad conf-kept"
    if [ -z "$bad" ]; then
        pass "a debconf-only host: PAM from .orig, and an sshd we did not touch is not blamed on us"
    else
        fail "a debconf-only host" "$bad"
    fi
}

BACKEND="$WORK/backend"
test_pam_generic_debian() {
    local bad=""
    mkroot_backend "$BACKEND"
    run_un "$BACKEND" -y
    local rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    grep -q '^# Restored by ob-uninstall (no pre-Open-Bastion backup found)$' "$BACKEND/etc/pam.d/sshd" \
        || bad="$bad no-header"
    for l in '@include common-auth' 'account    required     pam_nologin.so' '@include common-account' \
             'session    required     pam_loginuid.so' '@include common-session' \
             'session    required     pam_limits.so' '@include common-password'; do
        grep -qxF "$l" "$BACKEND/etc/pam.d/sshd" || bad="$bad sshd-missing:'$l'"
    done
    grep -qxF '@include common-session-noninteractive' "$BACKEND/etc/pam.d/sudo" || bad="$bad sudo"
    grep -qxF '@include common-session-noninteractive' "$BACKEND/etc/pam.d/sudo-i" || bad="$bad sudo-i"
    grep -q pam_openbastion "$BACKEND"/etc/pam.d/* && bad="$bad residue"
    [ -e "$BACKEND/etc/ssh/sshd_config.d/00-open-bastion-backend.conf" ] && bad="$bad kept-backend-dropin"
    [ -e "$BACKEND/etc/open-bastion/allowed_bastions" ] && bad="$bad kept-allowed_bastions"
    if [ -z "$bad" ]; then
        pass "backend with no backup: generic Debian stacks, backend drop-in and allowlist removed"
    else
        fail "backend with no backup: generic Debian stacks" "$bad"
    fi
}

test_sudo_i_created_by_setup() {
    local r="$WORK/sudoi" bad=""
    mkroot_bastion "$r"
    rm -f "$r/var/backup/open-bastion-setup-20260101-000000/sudo-i"
    run_un "$r" -y
    [ -e "$r/etc/pam.d/sudo-i" ] && bad="$bad sudo-i-still-there"
    grep -q 'distro sudo (oldest)' "$r/etc/pam.d/sudo" || bad="$bad sudo"
    if [ -z "$bad" ]; then
        pass "a sudo-i the setup created (absent from its oldest backup) is removed"
    else
        fail "a sudo-i the setup created is removed" "$bad"
    fi
}

test_no_family_refused() {
    local r="$WORK/nofamily" before after
    mkroot_backend "$r"
    rm -f "$r"/etc/pam.d/common-*
    before=$(tree_sum "$r")
    run_un "$r" -y
    local rc=$?
    after=$(tree_sum "$r")
    if [ "$rc" -eq 1 ] && [ "$before" = "$after" ] && grep -q 'no generic stack' "$WORK/out"; then
        pass "no backup and no known distro family: refused, exit 1, nothing changed"
    else
        fail "no backup and no known distro family: refused" "rc=$rc"
    fi
}

test_nsswitch_edit() {
    local f="$FULL/etc/nsswitch.conf" bad=""
    grep -qx 'passwd:         files systemd' "$f" || bad="$bad passwd:'$(grep ^passwd "$f")'"
    grep -qx "$(printf 'group:\tfiles\tsystemd')" "$f" || bad="$bad group:'$(grep ^group "$f")'"
    grep -qx 'shadow:         files' "$f" || bad="$bad shadow"
    grep -qx 'hosts:          files dns' "$f" || bad="$bad hosts"
    grep -q openbastion "$f" && bad="$bad residue"
    if [ -z "$bad" ]; then
        pass "nsswitch.conf: 'openbastion' removed, other sources and lines kept"
    else
        fail "nsswitch.conf edit" "$bad"
    fi
}

test_recordings_kept() {
    if [ "$(cat "$FULL/var/lib/open-bastion/sessions/alice/20260301-rec.cast" 2>/dev/null)" = "recording" ] \
       && grep -q '/var/lib/open-bastion/sessions' "$WORK/full.out"; then
        pass "session recordings are untouched and their location is printed"
    else
        fail "session recordings are untouched and their location is printed"
    fi
}

test_allowlists() {
    local bad=""
    [ "$(cat "$FULL/etc/at.allow" 2>/dev/null)" = "$(printf 'root\nbob')" ] || bad="$bad at.allow-changed"
    [ -e "$FULL/etc/cron.allow" ] && bad="$bad cron.allow-kept"
    if [ -z "$bad" ]; then
        pass "at.allow that differs from the template is kept; a verbatim cron.allow is removed"
    else
        fail "allowlists" "$bad"
    fi
}

test_backup_contents() {
    local b bad="" f
    b=$(backup_dir_of "$FULL")
    [ -n "$b" ] || { fail "a backup directory is created"; return; }
    for f in etc/ssh/sshd_config.d/00-open-bastion-bastion.conf \
             etc/ssh/sshd_config.d/09-open-bastion-service-keys.conf \
             etc/pam.d/sshd etc/pam.d/sudo etc/pam.d/sudo-i etc/nsswitch.conf \
             etc/sudoers.d/open-bastion etc/open-bastion/openbastion.conf \
             etc/open-bastion/nss_openbastion.conf etc/ssh/open-bastion_ca.pub \
             etc/cron.allow etc/group; do
        [ -f "$b/$f" ] || bad="$bad missing:$f"
    done
    grep -q pam_openbastion "$b/etc/pam.d/sshd" || bad="$bad pam-backup-is-not-the-old-file"
    grep -q ' openbastion ' "$b/etc/nsswitch.conf" || bad="$bad nss-backup-is-not-the-old-file"
    # A live credential is not copied around.
    [ -e "$b/var/lib/open-bastion/token" ] && bad="$bad TOKEN-BACKED-UP"
    [ "$(stat -c %a "$b")" = "700" ] || bad="$bad mode:$(stat -c %a "$b")"
    grep -q "${b#"$FULL"}" "$WORK/full.out" || bad="$bad dir-not-printed"
    # Secrets are redacted in the backup; the setup's own copy is reported.
    grep -qx 'client_secret = <redacted by ob-uninstall>' "$b/etc/open-bastion/openbastion.conf" \
        || bad="$bad not-redacted"
    grep -rqF "$SECRET" "$b" && bad="$bad SECRET-IN-BACKUP"
    grep -qx 'portal_url = https://auth.example.com/' "$b/etc/open-bastion/openbastion.conf" \
        || bad="$bad redaction-ate-other-lines"
    [ -f "$FULL/var/backup/open-bastion-setup-20260101-000000/openbastion.conf" ] || bad="$bad setup-backup-deleted"
    grep -q 'shred' "$WORK/full.out" && grep -q 'open-bastion-setup-20260101-000000/openbastion.conf' "$WORK/full.out" \
        || bad="$bad setup-secret-not-reported"
    if [ -z "$bad" ]; then
        pass "the uninstall backup (0700) holds every file it touched, under its full path, but not the token"
    else
        fail "the uninstall backup" "$bad"
    fi
}

test_revocation() {
    local bad="" argv jargv
    argv=$(cat "$FULL.curl-argv" 2>/dev/null)
    jargv=$(cat "$FULL.jwt-argv" 2>/dev/null)
    [ -n "$argv" ] || { fail "the token is revoked" "curl was not called"; return; }
    [ "$(grep -c . "$FULL.curl-body")" = 2 ] || bad="$bad expected-2-requests"
    case "$argv$jargv" in *"$SECRET"*|*"$REFRESH"*|*"$ACCESS"*|*SIGNATURE*) bad="$bad SECRET-ON-ARGV" ;; esac
    case "$argv" in *" https://auth.example.com/oauth2/revoke "*) ;; *) bad="$bad url" ;; esac
    case "$argv" in *" --data-binary @- "*) ;; *) bad="$bad no-data-binary" ;; esac
    case "$argv" in *" -k "*) ;; *) bad="$bad no-k(verify_ssl=false)" ;; esac
    grep -q "^token=$REFRESH&token_hint=refresh_token&token_type_hint=refresh_token&client_id=bastion-rp&" \
        "$FULL.curl-body" || bad="$bad refresh-body"
    grep -q "^token=$ACCESS&token_hint=access_token&token_type_hint=access_token&client_id=bastion-rp&" \
        "$FULL.curl-body" || bad="$bad access-body"
    [ "$(grep -c 'client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=eyJ' "$FULL.curl-body")" = 2 ] \
        || bad="$bad no-assertion"
    grep -q 'client_secret' "$FULL.curl-body" && bad="$bad RAW-SECRET-SENT"
    [ "$(cat "$FULL.jwt-stdin" 2>/dev/null)" = "$SECRET" ] || bad="$bad secret-not-on-jwt-stdin"
    case "$jargv" in *"--client-id bastion-rp --audience https://auth.example.com/oauth2/token"*) ;;
        *) bad="$bad jwt-args:'$jargv'" ;; esac
    grep -q 'request accepted' "$WORK/full.out" || bad="$bad wording"
    grep -q 'answers 200 even for a token it does not know' "$WORK/full.out" || bad="$bad no-200-caveat"
    if [ -z "$bad" ]; then
        pass "both tokens revoked with a client_secret_jwt assertion; secret only on ob-client-jwt's stdin"
    else
        fail "revocation request" "$bad"
    fi
}

test_revocation_public_client() {
    local r="$WORK/public" bad=""
    mkroot_bastion "$r"
    sed -i '/^client_secret/d' "$r/etc/open-bastion/openbastion.conf"
    run_un "$r" -y
    [ -e "$r.jwt-argv" ] && bad="$bad jwt-called"
    grep -q 'client_assertion' "$r.curl-body" && bad="$bad assertion-sent"
    [ "$(grep -c '&client_id=bastion-rp$' "$r.curl-body")" = 2 ] || bad="$bad body:'$(cat "$r.curl-body")'"
    if [ -z "$bad" ]; then
        pass "a public client revokes with its client_id alone"
    else
        fail "public-client revocation" "$bad"
    fi
}

test_revocation_without_jwt_helper() {
    local r="$WORK/nojwt" bad="" nojwt="$WORK/stubs-nojwt"
    mkroot_bastion "$r"
    rm -rf "$nojwt"; cp -a "$STUBS" "$nojwt"; rm -f "$nojwt/ob-client-jwt"
    RUN_PATH_OVERRIDE="$nojwt:$PATH" run_un "$r" -y
    local rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    [ -e "$r.curl-body" ] && bad="$bad SENT-WITHOUT-ASSERTION"
    grep -q 'ob-client-jwt is missing' "$WORK/out" || bad="$bad not-reported"
    if [ -z "$bad" ]; then
        pass "without ob-client-jwt a confidential client does not revoke rather than send its secret"
    else
        fail "no ob-client-jwt" "$bad"
    fi
}

test_no_revoke() {
    local r="$WORK/norevoke"
    mkroot_bastion "$r"
    run_un "$r" -y --no-revoke
    local rc=$?
    if [ "$rc" -eq 0 ] && ! grep -q '^curl' "$r.log" && [ ! -e "$r/var/lib/open-bastion/token" ] \
       && grep -q 'LLNG Manager' "$WORK/out"; then
        pass "--no-revoke does not call curl, still deletes the token, and says to revoke it by hand"
    else
        fail "--no-revoke" "rc=$rc"
    fi
}

test_revocation_failure_is_not_fatal() {
    local r="$WORK/revokefail"
    mkroot_bastion "$r"
    STUB_CURL_RC=22 run_un "$r" -y
    local rc=$?
    if [ "$rc" -eq 0 ] && [ ! -e "$r/var/lib/open-bastion/token" ] \
       && grep -q 'may still be valid' "$WORK/out"; then
        pass "a failed revocation warns and the run still completes"
    else
        fail "a failed revocation warns and the run still completes" "rc=$rc"
    fi
}

test_sso_only_invoker_refused() {
    local r="$WORK/lockout" before after bad=""
    mkroot_bastion "$r"
    before=$(tree_sum "$r")
    SUDO_USER_OVERRIDE=alice run_un "$r" -y
    local rc=$?
    after=$(tree_sum "$r")
    [ "$rc" -eq 1 ] || bad="$bad rc=$rc"
    [ "$before" = "$after" ] || bad="$bad changed"
    grep -q "'alice' is not in /etc/passwd" "$WORK/out" || bad="$bad no-explanation"
    SUDO_USER_OVERRIDE=alice run_un "$r" -y --force
    rc=$?
    [ "$rc" -eq 0 ] || bad="$bad force-rc=$rc"
    [ -e "$r/etc/ssh/sshd_config.d/00-open-bastion-bastion.conf" ] && bad="$bad force-did-nothing"
    if [ -z "$bad" ]; then
        pass "an SSO-only SUDO_USER is refused before any change; --force overrides"
    else
        fail "lockout guard" "$bad"
    fi
}

test_sshd_t_failure_rolls_back() {
    local r="$WORK/sshdfail" bad="" pam_before
    mkroot_bastion "$r"
    pam_before=$(cat "$r/etc/pam.d/sshd")
    STUB_SSHD_FAIL=1 run_un "$r" -y
    local rc=$?
    [ "$rc" -eq 1 ] || bad="$bad rc=$rc"
    for f in 00-open-bastion-bastion.conf 09-open-bastion-service-keys.conf 60-max-security.conf; do
        [ -f "$r/etc/ssh/sshd_config.d/$f" ] || bad="$bad not-restored:$f"
    done
    [ "$(cat "$r/etc/pam.d/sshd")" = "$pam_before" ] || bad="$bad PAM-TOUCHED"
    grep -q ' openbastion ' "$r/etc/nsswitch.conf" || bad="$bad NSS-TOUCHED"
    [ -e "$r/var/lib/open-bastion/token" ] || bad="$bad token-gone"
    grep -qE 'disable|reload' "$r.log" && bad="$bad units-or-reload-touched"
    grep -q 'Bad configuration option' "$WORK/out" || bad="$bad sshd-output-not-shown"
    if [ -z "$bad" ]; then
        pass "sshd -t failure: sshd drop-ins restored, nothing else touched, exit 1"
    else
        fail "sshd -t failure rolls back" "$bad"
    fi
}

test_appended_sshd_config() {
    local r="$WORK/appended" bad="" before after
    mkroot_bastion "$r"
    rm -rf "$r/etc/ssh/sshd_config.d"
    printf 'Port 22\n\n# LemonLDAP::NG Bastion Configuration\nTrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\n' \
        > "$r/etc/ssh/sshd_config"
    # The newer setup backup already has our block; the older one does not.
    printf 'Port 22\nTrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\n' \
        > "$r/var/backup/open-bastion-setup-20260201-000000/sshd_config"
    printf 'Port 22\n# pristine\n' > "$r/var/backup/open-bastion-setup-20260101-000000/sshd_config"
    run_un "$r" -y
    grep -q '# pristine' "$r/etc/ssh/sshd_config" || bad="$bad not-restored"
    [ -e "$r/etc/ssh/open-bastion_ca.pub" ] && bad="$bad ca-kept"

    # No clean backup and no block shape to cut: refused, before any change.
    r="$WORK/appended2"
    mkroot_bastion "$r"
    rm -rf "$r/etc/ssh/sshd_config.d" "$r/var/backup"
    printf 'Port 22\nTrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\n' > "$r/etc/ssh/sshd_config"
    before=$(tree_sum "$r")
    run_un "$r" -y
    local rc=$?
    after=$(tree_sum "$r")
    [ "$rc" -eq 1 ] || bad="$bad unrestorable-rc=$rc"
    [ "$before" = "$after" ] || bad="$bad unrestorable-changed"
    if [ -z "$bad" ]; then
        pass "an appended sshd_config block is undone from the oldest clean backup, or refused with none"
    else
        fail "appended sshd_config block" "$bad"
    fi
}

test_residual_exit_2() {
    local r="$WORK/residual"
    mkroot_bastion "$r"
    printf 'auth required pam_openbastion.so\n' > "$r/etc/pam.d/lightdm"
    run_un "$r" -y
    local rc=$?
    if [ "$rc" -eq 2 ] && grep -q '/etc/pam.d/lightdm' "$WORK/out" \
       && [ ! -e "$r/etc/ssh/sshd_config.d/00-open-bastion-bastion.conf" ]; then
        pass "a display-manager stack still loading pam_openbastion is listed, exit 2"
    else
        fail "residual pam_openbastion -> exit 2" "rc=$rc"
    fi
}

test_requires_root() {
    if [ "$(id -u)" -eq 0 ]; then
        pass "(running as root: root check not exercised)"
        return
    fi
    local out
    out=$(env -u OB_ROOT bash "$SCRIPT" -y 2>&1)
    local rc=$?
    if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'must run as root'; then
        pass "a real (non-dry) run as non-root is refused"
    else
        fail "a real (non-dry) run as non-root is refused" "rc=$rc"
    fi
}

# create_user writes SSO users into /etc/passwd with a locked password: each
# criterion must refuse on its own and say which one matched.
test_lockout_criteria() {
    local r="$WORK/lockout2" bad="" u rc
    mkroot_bastion "$r"
    cat >> "$r/etc/passwd" <<'EOP'
alice:x:10123:10123::/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
carol:x:1002:1002::/home/carol:/bin/bash
dave:x:1003:1003::/home/dave:/bin/bash
EOP
    cat >> "$r/etc/shadow" <<'EOP'
alice:$6$salt$hash:19000:0:99999:7:::
bob:$6$salt$hash:19000:0:99999:7:::
carol:!:19000:0:99999:7:::
dave:!:19000:0:99999:7:::
EOP
    sed -i 's/^open-bastion-sudo:x:999:$/open-bastion-sudo:x:999:bob/' "$r/etc/group"
    echo "ssh-ed25519 AAAAdave" | wr "$r/home/dave/.ssh/authorized_keys"
    for u in "alice:uid 10123, inside the Open Bastion range 10000..60000" \
             "bob:member of open-bastion-sudo" \
             "carol:no usable password (shadow field '!') and no /home/carol/.ssh/authorized_keys"; do
        SUDO_USER_OVERRIDE="${u%%:*}" run_un "$r" -y --dry-run
        rc=$?
        [ "$rc" -eq 1 ] || bad="$bad ${u%%:*}-rc=$rc"
        grep -qF "${u#*:}" "$WORK/out" || bad="$bad ${u%%:*}-reason-missing"
    done
    # A local admin with a locked password but a key is not locked out.
    SUDO_USER_OVERRIDE=dave run_un "$r" -y --dry-run || bad="$bad dave-refused"
    # The range comes from nss_openbastion.conf when it says so.
    printf 'min_uid = 20000\nmax_uid = 30000\n' >> "$r/etc/open-bastion/nss_openbastion.conf"
    SUDO_USER_OVERRIDE=alice run_un "$r" -y --dry-run || bad="$bad alice-refused-outside-custom-range"
    if [ -z "$bad" ]; then
        pass "an SSO user in /etc/passwd is refused by uid range, open-bastion-sudo, or no way to log in"
    else
        fail "lockout guard criteria" "$bad"
    fi
}

test_debconf_pam_mode() {
    local r="$WORK/debconfmode" bad="" b
    mkroot_bastion "$r"
    STUB_DEBCONF_MODE=mode-c run_un "$r" -y
    grep -qx 'debconf-set-selections open-bastion open-bastion/pam-mode select none' "$r.log" \
        || bad="$bad not-reset"
    b=$(backup_dir_of "$r")
    grep -qx 'open-bastion open-bastion/pam-mode select mode-c' "$b/debconf-selections" 2>/dev/null \
        || bad="$bad previous-not-saved"
    grep -q 'open-bastion/pam-mode: mode-c -> none' "$WORK/out" || bad="$bad not-in-plan"
    r="$WORK/debconfnone"
    mkroot_bastion "$r"
    STUB_DEBCONF_MODE=none run_un "$r" -y
    grep -q debconf-set-selections "$r.log" && bad="$bad touched-when-none"
    if [ -z "$bad" ]; then
        pass "a debconf pam-mode other than none is reset (it would re-arm PAM) and saved in the backup"
    else
        fail "debconf pam-mode" "$bad"
    fi
}

test_sudoers_fresh_otp_rerun() {
    local r="$WORK/freshotp" bad=""
    mkroot_bastion "$r"
    printf '%s\n' "# --enable-sudo-fresh-otp: no sudo credential caching for SSO users (#178)" \
        "Defaults:%open-bastion-sudo timestamp_timeout=0" \
        "# Open Bastion: defense-in-depth sudo authorization" \
        "%open-bastion-sudo ALL=(ALL) ALL" > "$r/etc/sudoers.d/open-bastion"
    run_un "$r" -y
    [ -e "$r/etc/sudoers.d/open-bastion" ] && bad="$bad kept-ours"
    r="$WORK/sudoersforeign"
    mkroot_bastion "$r"
    printf '# Open Bastion notes: our own rule, by the ops team\n%%ops ALL=(ALL) ALL\n' \
        > "$r/etc/sudoers.d/open-bastion"
    run_un "$r" -y
    [ -f "$r/etc/sudoers.d/open-bastion" ] || bad="$bad removed-foreign"
    if [ -z "$bad" ]; then
        pass "a --enable-sudo-fresh-otp sudoers drop-in is recognised; a lookalike header is not"
    else
        fail "sudoers ownership" "$bad"
    fi
}

# One backend --max-security run backs sudo and sudo-i up twice
# (configure_pam_sudo, then Mode E): the only copy left is our own.
test_single_run_backend_maxsec() {
    local r="$WORK/single-backend" bad="" b="" ts=20260301-120000
    mkroot_backend "$r"
    echo "# distro sshd" > "$r/etc/pam.d/sshd"
    echo "# distro sudo" > "$r/etc/pam.d/sudo"
    echo "# distro sudo-i" > "$r/etc/pam.d/sudo-i"
    real_setup_run "$r" ob-backend-setup "$ts" \
        configure_sshd configure_pam_sshd configure_pam_sudo \
        configure_max_security_sshd configure_max_security_sudo \
        || { fail "single backend run" "the setup's own functions failed"; return; }
    b="$r/var/backup/open-bastion-setup-$ts"
    # The premise, checked rather than assumed.
    grep -q '# distro sshd' "$b/sshd" || bad="$bad premise:sshd-backup"
    grep -q pam_openbastion "$b/sudo" || bad="$bad premise:sudo-backup-is-clean"
    grep -q pam_openbastion "$b/sudo-i" || bad="$bad premise:sudo-i-backup-is-clean"
    run_un "$r" -y
    grep -q '# distro sshd' "$r/etc/pam.d/sshd" || bad="$bad sshd"
    grep -q '^# Restored by ob-uninstall' "$r/etc/pam.d/sudo" || bad="$bad sudo-not-generic"
    grep -q '^# Restored by ob-uninstall' "$r/etc/pam.d/sudo-i" || bad="$bad sudo-i-not-generic"
    if [ -z "$bad" ]; then
        pass "one backend --max-security run (only dirty sudo copies): generic stacks, not our own"
    else
        fail "single backend run" "$bad"
    fi
}

# Without sshd_config.d, one Mode E run leaves only a backup of
# sshd_config that already has the main block: the blocks are cut out.
test_appended_single_run_strip() {
    local r bad="" b ts=20260301-120000 role expected rc before after
    for role in ob-bastion-setup:enabled ob-bastion-setup:disabled ob-standalone-setup:enabled; do
        r="$WORK/strip-${role%%:*}-${role#*:}"
        mkroot_bastion "$r"
        rm -rf "$r/etc/ssh/sshd_config.d" "$r"/var/backup/*
        printf 'Port 22\nUsePAM yes\n' > "$r/etc/ssh/sshd_config"
        local dsr=false
        [ "${role#*:}" = disabled ] && dsr=true
        real_setup_run "$r" "${role%%:*}" "$ts" "DISABLE_SESSION_RECORDER=$dsr" \
            configure_sshd configure_max_security_sshd \
            || { bad="$bad $role:setup-failed"; continue; }
        b="$r/var/backup/open-bastion-setup-$ts"
        grep -q 'TrustedUserCAKeys' "$b/sshd_config" || bad="$bad $role:premise:backup-is-clean"
        # An administrator's edit after the setup.
        printf 'Match User backup\n    PasswordAuthentication no\n' >> "$r/etc/ssh/sshd_config"
        expected=$(printf 'Port 22\nUsePAM yes\nMatch User backup\n    PasswordAuthentication no')
        run_un "$r" -y
        rc=$?
        [ "$rc" -eq 0 ] || bad="$bad $role:rc=$rc"
        [ "$(cat "$r/etc/ssh/sshd_config")" = "$expected" ] \
            || bad="$bad $role:result:'$(cat "$r/etc/ssh/sshd_config")'"
        [ -e "$r/etc/ssh/open-bastion_ca.pub" ] && bad="$bad $role:ca-kept"
        [ -e "$r/etc/ssh/revoked_keys" ] && bad="$bad $role:krl-kept"
    done

    # Two Mode E runs: one main block (never appended twice), two Mode E blocks.
    r="$WORK/strip-backend"
    mkroot_backend "$r"
    rm -rf "$r/etc/ssh/sshd_config.d" "$r"/var/backup/*
    printf 'Port 2222\n' > "$r/etc/ssh/sshd_config"
    real_setup_run "$r" ob-backend-setup 20260301-120000 configure_sshd configure_max_security_sshd \
        && real_setup_run "$r" ob-backend-setup 20260302-120000 configure_sshd configure_max_security_sshd \
        || bad="$bad backend:setup-failed"
    [ "$(grep -c '^# Open Bastion Maximum Security Configuration (Mode E)$' "$r/etc/ssh/sshd_config")" = 2 ] \
        || bad="$bad backend:premise:two-mode-e-blocks"
    [ "$(grep -c '^# LemonLDAP::NG Backend Configuration$' "$r/etc/ssh/sshd_config")" = 1 ] \
        || bad="$bad backend:premise:one-main-block"
    run_un "$r" -y
    [ "$(cat "$r/etc/ssh/sshd_config")" = "Port 2222" ] || bad="$bad backend-result:'$(cat "$r/etc/ssh/sshd_config")'"

    # A block whose end line is not the one we write: refused, untouched.
    r="$WORK/strip3"
    mkroot_bastion "$r"
    rm -rf "$r/etc/ssh/sshd_config.d" "$r"/var/backup/*
    printf 'Port 22\n\n# LemonLDAP::NG Bastion Configuration\nTrustedUserCAKeys /etc/ssh/open-bastion_ca.pub\nX11Forwarding no\n' \
        > "$r/etc/ssh/sshd_config"
    before=$(tree_sum "$r")
    run_un "$r" -y
    rc=$?
    after=$(tree_sum "$r")
    [ "$rc" -eq 1 ] && [ "$before" = "$after" ] || bad="$bad unknown-shape-rc=$rc"
    grep -q 'could not be cut out safely' "$WORK/out" || bad="$bad unknown-shape-message"
    if [ -z "$bad" ]; then
        pass "blocks the real setup appended (bastion, recorder off, standalone, backend x2 Mode E) are cut out exactly; an unknown shape is refused"
    else
        fail "appended sshd_config, strip fallback" "$bad"
    fi
}

test_timer_dropins() {
    local r="$WORK/timers" bad="" b
    mkroot_bastion "$r"
    # An administrator's drop-in for the other timer, and a file of theirs
    # next to ours.
    printf '[Timer]\nOnCalendar=\nOnCalendar=hourly\n' \
        | wr "$r/etc/systemd/system/ob-audit-rotate.timer.d/schedule.conf"
    printf '[Timer]\nRandomizedDelaySec=5min\n' \
        | wr "$r/etc/systemd/system/ob-krl-refresh.timer.d/zz-local.conf"
    run_un "$r" -y
    [ -e "$r/etc/systemd/system/ob-krl-refresh.timer.d/schedule.conf" ] && bad="$bad ours-kept"
    [ -f "$r/etc/systemd/system/ob-krl-refresh.timer.d/zz-local.conf" ] || bad="$bad theirs-removed"
    [ -f "$r/etc/systemd/system/ob-audit-rotate.timer.d/schedule.conf" ] || bad="$bad foreign-schedule-removed"
    grep -q 'systemctl daemon-reload' "$r.log" || bad="$bad no-daemon-reload"
    b=$(backup_dir_of "$r")
    head -n 1 "$b/etc/systemd/system/ob-krl-refresh.timer.d/schedule.conf" 2>/dev/null \
        | grep -qxF '# Open Bastion timer schedule' || bad="$bad not-backed-up"
    # The timers are stopped before the drop-ins go.
    [ "$(grep -n 'disable --now ob-krl-refresh.timer' "$r.log" | cut -d: -f1)" -lt \
      "$(grep -n 'daemon-reload' "$r.log" | cut -d: -f1)" ] 2>/dev/null || bad="$bad order"
    if [ -z "$bad" ]; then
        pass "the timers' schedule drop-ins we wrote go (then daemon-reload); an administrator's stay"
    else
        fail "timer drop-ins" "$bad"
    fi
}

test_legacy_cron_host() {
    local r="$WORK/legacy" bad="" b f
    mkroot_bastion "$r"
    rm -rf "$r/etc/systemd/system"
    add_legacy_cron "$r"
    echo "0 * * * * root /usr/local/bin/other-job" | wr "$r/etc/cron.d/site-job"
    run_un "$r" -y
    b=$(backup_dir_of "$r")
    for f in etc/cron.d/open-bastion-krl usr/local/bin/open-bastion-refresh-krl \
             etc/cron.weekly/open-bastion-audit-rotate; do
        [ -e "$r/$f" ] && bad="$bad kept:$f"
        [ -f "$b/$f" ] || bad="$bad not-backed-up:$f"
    done
    [ -f "$r/etc/cron.d/site-job" ] || bad="$bad removed-site-job"
    grep -q 'daemon-reload' "$r.log" && bad="$bad needless-daemon-reload"

    # A /usr/local script that is not the generated one is the administrator's.
    r="$WORK/legacy2"
    mkroot_bastion "$r"
    add_legacy_cron "$r"
    printf '#!/bin/bash\necho site script\n' > "$r/usr/local/bin/open-bastion-refresh-krl"
    run_un "$r" -y
    [ -f "$r/usr/local/bin/open-bastion-refresh-krl" ] || bad="$bad removed-foreign-script"
    [ -e "$r/etc/cron.d/open-bastion-krl" ] && bad="$bad kept-cron-job"
    if [ -z "$bad" ]; then
        pass "a 0.6 host's cron jobs are removed (and backed up); a /usr/local script that is not ours stays"
    else
        fail "legacy cron jobs" "$bad"
    fi
}

test_missing_sshd_refused() {
    local r="$WORK/nosshd" farm="$WORK/farm" stubs="$WORK/stubs-nosshd" d f before after
    mkroot_bastion "$r"
    rm -rf "$farm" "$stubs"; mkdir -p "$farm"
    cp -a "$STUBS" "$stubs"; rm -f "$stubs/sshd"
    # Everything the test's PATH offers, except sshd.
    local IFS=:
    for d in $PATH; do
        for f in "$d"/*; do
            [ -x "$f" ] && [ "${f##*/}" != sshd ] && [ ! -e "$farm/${f##*/}" ] && ln -s "$f" "$farm/${f##*/}"
        done
    done
    unset IFS
    before=$(tree_sum "$r")
    RUN_PATH_OVERRIDE="$stubs:$farm" run_un "$r" -y
    local rc=$?
    after=$(tree_sum "$r")
    if [ "$rc" -eq 1 ] && [ "$before" = "$after" ] && grep -q 'no sshd binary' "$WORK/out"; then
        pass "no sshd to validate with: refused, exit 1, nothing changed"
    else
        fail "no sshd to validate with: refused" "rc=$rc"
    fi
}

test_pam_llng() {
    local r="$WORK/llng" bad=""
    mkroot_bastion "$r"
    printf 'auth required pam_deny.so\naccount required pam_llng.so\n' > "$r/etc/pam.d/sshd"
    printf 'auth required pam_llng.so\n' > "$r/etc/pam.d/gdm-password"
    run_un "$r" -y
    local rc=$?
    grep -q 'distro sshd (oldest)' "$r/etc/pam.d/sshd" || bad="$bad sshd-not-restored"
    [ "$rc" -eq 2 ] || bad="$bad rc=$rc"
    grep -q '/etc/pam.d/gdm-password' "$WORK/out" || bad="$bad residual-not-listed"
    if [ -z "$bad" ]; then
        pass "a stack loading pam_llng is restored, and a residual one is reported (exit 2)"
    else
        fail "pam_llng" "$bad"
    fi
}

test_authselect_symlink() {
    local r="$WORK/authselect" bad="" b
    mkroot_bastion "$r"
    printf 'passwd:     sss files systemd\ngroup:      sss files systemd\n' | wr "$r/etc/authselect/nsswitch.conf"
    # The setup's `sed -i` turned the link into a file; its backup kept the link.
    ln -s /etc/authselect/nsswitch.conf "$r/var/backup/open-bastion-setup-20260101-000000/nsswitch.conf"
    run_un "$r" -y
    [ -L "$r/etc/nsswitch.conf" ] || bad="$bad not-a-link"
    [ "$(readlink "$r/etc/nsswitch.conf")" = /etc/authselect/nsswitch.conf ] || bad="$bad target"
    grep -q '^passwd:     sss files systemd$' "$r/etc/authselect/nsswitch.conf" || bad="$bad target-edited"
    b=$(backup_dir_of "$r")
    [ -f "$b/etc/nsswitch.conf" ] && [ ! -L "$b/etc/nsswitch.conf" ] \
        && grep -q openbastion "$b/etc/nsswitch.conf" || bad="$bad regular-file-not-backed-up"

    # A link whose target is gone: the file is edited instead.
    r="$WORK/authselect2"
    mkroot_bastion "$r"
    ln -s /etc/authselect/nsswitch.conf "$r/var/backup/open-bastion-setup-20260101-000000/nsswitch.conf"
    run_un "$r" -y
    [ -f "$r/etc/nsswitch.conf" ] && [ ! -L "$r/etc/nsswitch.conf" ] || bad="$bad dangling-link-restored"
    grep -q openbastion "$r/etc/nsswitch.conf" && bad="$bad not-edited"
    if [ -z "$bad" ]; then
        pass "nsswitch.conf goes back to authselect's symlink when the setup broke it (and only if its target exists)"
    else
        fail "authselect symlink" "$bad"
    fi
}

test_nonroot_dry_run_partial() {
    if [ "$(id -u)" -eq 0 ]; then
        pass "(running as root: unreadable files cannot be simulated)"
        return
    fi
    local r="$WORK/partial" bad=""
    mkroot_bastion "$r"
    chmod 000 "$r/etc/open-bastion/openbastion.conf" "$r/etc/sudoers.d/open-bastion" "$r/etc/shadow"
    run_un "$r" --dry-run
    local rc=$?
    [ "$rc" -eq 0 ] || bad="$bad rc=$rc"
    grep -q 'PARTIAL PLAN' "$WORK/out" || bad="$bad no-notice"
    grep -q 'sudo ob-uninstall --dry-run' "$WORK/out" || bad="$bad no-hint"
    grep -q 'unknown   /etc/sudoers.d/open-bastion' "$WORK/out" || bad="$bad sudoers-not-unknown"
    chmod 600 "$r/etc/open-bastion/openbastion.conf" "$r/etc/sudoers.d/open-bastion" "$r/etc/shadow"
    if [ -z "$bad" ]; then
        pass "a non-root dry run names what it could not read and says to use sudo"
    else
        fail "non-root dry run" "$bad"
    fi
}

run_test test_syntax
run_test test_nothing_configured
run_test test_dry_run_is_inert
run_test test_full_run
cp "$WORK/out" "$WORK/full.out"
run_test test_foreign_dropins_kept
run_test test_still_referenced_kept
run_test test_pam_oldest_clean_backup
run_test test_pam_oldest_of_two_clean
run_test test_pam_debconf_orig
run_test test_debconf_only_host
run_test test_pam_generic_debian
run_test test_sudo_i_created_by_setup
run_test test_no_family_refused
run_test test_nsswitch_edit
run_test test_recordings_kept
run_test test_allowlists
run_test test_backup_contents
run_test test_revocation
run_test test_revocation_public_client
run_test test_revocation_without_jwt_helper
run_test test_no_revoke
run_test test_revocation_failure_is_not_fatal
run_test test_sso_only_invoker_refused
run_test test_sshd_t_failure_rolls_back
run_test test_appended_sshd_config
run_test test_residual_exit_2
run_test test_requires_root
run_test test_lockout_criteria
run_test test_debconf_pam_mode
run_test test_sudoers_fresh_otp_rerun
run_test test_single_run_backend_maxsec
run_test test_appended_single_run_strip
run_test test_timer_dropins
run_test test_legacy_cron_host
run_test test_missing_sshd_refused
run_test test_pam_llng
run_test test_authselect_symlink
run_test test_nonroot_dry_run_partial

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
