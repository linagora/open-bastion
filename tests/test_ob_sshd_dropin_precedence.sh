#!/bin/bash
#
# test_ob_sshd_dropin_precedence.sh
#
# Regression test for the cert-only lockdown being silently defeated by a
# distro sshd drop-in. Cloud images ship /etc/ssh/sshd_config.d/50-cloud-init.conf
# with `PasswordAuthentication yes`. sshd uses the FIRST value seen for keywords
# like PasswordAuthentication, and Include expands the drop-in dir alphabetically,
# so the open-bastion drop-in MUST sort before 50-cloud-init.conf or its
# `PasswordAuthentication no` loses and password auth stays enabled.
#
# This test has the setup script write its drop-in, under each role, into a
# scratch sshd_config.d and takes the name from there, then asserts, via a real
# `sshd -T`, that with a competing 50-cloud-init.conf the resolved
# PasswordAuthentication is `no`. A negative control with the legacy 50- name
# proves the ordering is what matters.
#
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0

# shellcheck source=tests/lib_setup_script.sh
. "$SCRIPT_DIR/tests/lib_setup_script.sh"

# The drop-in name the setup script writes when invoked as $1 (so a future
# rename back to 50- fails here). Rendered, not grepped: one script writes both
# names and picks one at run time.
written_dropin() {
    local d
    d=$(mktemp -d)
    mkdir -p "$d/sshd_config.d" "$d/bin"
    : > "$d/sshd_config"
    printf '#!/bin/sh\nexit 0\n' > "$d/bin/sshd"
    chmod +x "$d/bin/sshd"
    (
        load_setup_as "$1" || exit 1
        parse_args -p https://x.example.com -g g >/dev/null 2>&1
        SSHD_CONFIG_DIR="$d/sshd_config.d"
        SSHD_CONFIG="$d/sshd_config"
        BACKUP_DIR="$d/backup"
        PATH="$d/bin:$PATH"
        configure_sshd >/dev/null 2>&1
    )
    find "$d/sshd_config.d" -name '*-open-bastion-*.conf' -printf '%f\n' | head -1
    rm -rf "$d"
}

bastion_dropin=$(written_dropin ob-bastion-setup)
backend_dropin=$(written_dropin ob-backend-setup)
case "$bastion_dropin" in *-open-bastion-bastion.conf) ;; *) bastion_dropin="" ;; esac
case "$backend_dropin" in *-open-bastion-backend.conf) ;; *) backend_dropin="" ;; esac
echo "bastion drop-in: $bastion_dropin"
echo "backend drop-in: $backend_dropin"

# Fail fast: an empty name (grep matched nothing) would vacuously "sort first"
# below and let a real regression slip through.
if [ -z "$bastion_dropin" ] || [ -z "$backend_dropin" ]; then
    echo "FAIL: could not extract the open-bastion sshd drop-in name from the setup scripts"
    exit 1
fi

# Static check: must sort before 50-cloud-init.conf.
for d in "$bastion_dropin" "$backend_dropin"; do
    first=$(printf '%s\n50-cloud-init.conf\n' "$d" | LC_ALL=C sort | head -1)
    if [ "$first" = "$d" ] && [ "$d" != "50-cloud-init.conf" ]; then
        echo "ok   $d sorts before 50-cloud-init.conf"
    else
        echo "FAIL $d does NOT sort before 50-cloud-init.conf (password auth would stay enabled)"
        fail=1
    fi
done

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available — static ordering check only"
    exit $fail
fi

# Dynamic check: real sshd -T with both drop-ins present.
RUNNER=$(mktemp)
# Replaces lib_setup_script.sh's EXIT trap, so it takes over its directory too.
trap 'rm -f "$RUNNER"; rm -rf "$SETUP_LINK_DIR"' EXIT
cat > "$RUNNER" <<DRIVER
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server >/dev/null
mkdir -p /etc/ssh/sshd_config.d /run/sshd
grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || \
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

# Distro drop-in enabling password auth (as cloud-init does).
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/50-cloud-init.conf

# open-bastion drop-in at the REAL name, disabling it.
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
    > "/etc/ssh/sshd_config.d/$backend_dropin"
got=\$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print \$2}')
echo "with $backend_dropin → passwordauthentication=\$got"
[ "\$got" = "no" ] || { echo "FAIL: password auth not disabled"; exit 1; }

# Negative control: legacy 50- name loses to 50-cloud-init.conf.
rm -f "/etc/ssh/sshd_config.d/$backend_dropin"
printf 'PasswordAuthentication no\n' > /etc/ssh/sshd_config.d/50-open-bastion-backend.conf
ctl=\$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print \$2}')
echo "with legacy 50-open-bastion-backend.conf → passwordauthentication=\$ctl (expected yes: proves ordering matters)"
[ "\$ctl" = "yes" ] || { echo "FAIL: negative control expected yes, got \$ctl — ordering is NOT what defeats cloud-init, test is not proving the regression"; exit 1; }
echo "PRECEDENCE_OK"
DRIVER

echo "=== sshd drop-in precedence e2e (docker) ==="
out=$(docker run --rm -v "$RUNNER":/run.sh:ro debian:trixie bash /run.sh 2>&1)
echo "$out"
echo "$out" | grep -q "PRECEDENCE_OK" || fail=1

[ "$fail" -eq 0 ] && echo "PASS: open-bastion sshd drop-in wins the PasswordAuthentication race" \
                  || echo "FAIL: drop-in precedence regression"
exit $fail
