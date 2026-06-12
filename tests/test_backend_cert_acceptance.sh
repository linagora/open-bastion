#!/bin/bash
# test_backend_cert_acceptance.sh
#
# End-to-end guard for the bastion→backend "accept only this bastion" property.
# This is the assertion whose ABSENCE let the broken LLNG_BASTION_JWT/SendEnv
# transport ship: the backend rejected every session and no test noticed.
#
# It stands up a real OpenSSH sshd configured exactly as ob-backend-setup does
# (TrustedUserCAKeys + the ob-ssh-principals AuthorizedPrincipalsCommand that
# checks the cert key-id), in a throwaway Debian container, and verifies that:
#   - a bastion-vouched cert (key-id "bastion=<id>;user=<u>;…") is ACCEPTED,
#   - a direct user SSO cert, a wrong bastion_id, a cert/login user mismatch, a
#     principal mismatch and an off-bastion source-address are all DENIED.
#
# The principals helper is extracted from scripts/ob-backend-setup so there is a
# single source of truth. Certs are signed by a local test CA whose structure is
# identical to what LLNG /pam/bastion-cert issues (the sshd acceptance logic does
# not care which CA, only that it is the trusted one).
#
# Requires docker. Skips (exit 0) when docker is unavailable.

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_SETUP="$SCRIPT_DIR/scripts/ob-backend-setup"

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available"
    exit 0
fi
if [ ! -f "$BACKEND_SETUP" ]; then
    echo "FAIL: $BACKEND_SETUP not found"
    exit 1
fi

# Extract the ob-ssh-principals helper from ob-backend-setup (single source).
HELPER=$(mktemp)
trap 'rm -f "$HELPER"' EXIT
awk "/cat > \"\\\$script_path\" << 'PRINCIPALS'/{f=1;next} /^PRINCIPALS\$/{f=0} f" \
    "$BACKEND_SETUP" > "$HELPER"
if [ ! -s "$HELPER" ]; then
    echo "FAIL: could not extract ob-ssh-principals helper from ob-backend-setup"
    exit 1
fi

# In-container e2e driver.
RUNNER=$(mktemp)
trap 'rm -f "$HELPER" "$RUNNER"' EXIT
cat > "$RUNNER" <<'DRIVER'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssh-server openssh-client >/dev/null

useradd -m -s /bin/bash dwho
usermod -p '*' dwho   # unlock (UsePAM no would refuse a locked account)

mkdir -p /ca; ssh-keygen -t ed25519 -N '' -q -f /ca/ca -C test-ca
install -d -m0700 /run/open-bastion/ssh-fp
chown nobody:nogroup /run/open-bastion/ssh-fp 2>/dev/null || chown nobody:nobody /run/open-bastion/ssh-fp
mkdir -p /etc/open-bastion
printf 'pam-access\n' > /etc/open-bastion/allowed_bastions
chmod 644 /etc/open-bastion/allowed_bastions
cp /helper /usr/local/sbin/ob-ssh-principals
chmod 755 /usr/local/sbin/ob-ssh-principals

mkdir -p /etc/ssh/sshd_config.d /run/sshd
cat > /etc/ssh/sshd_config.d/50-open-bastion-backend.conf <<EOF
TrustedUserCAKeys /ca/ca.pub
AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f %i
AuthorizedPrincipalsCommandUser nobody
PubkeyAuthentication yes
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
ExposeAuthInfo yes
PermitRootLogin no
EOF
grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config \
    || echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
/usr/sbin/sshd -p 2222
sleep 1

mint() { # $1 keyid  $2 principal  $3 source-address(optional) -> echoes keydir
  local d; d=$(mktemp -d)
  ssh-keygen -t ed25519 -N '' -q -f "$d/id" -C eph
  local opts=(-s /ca/ca -I "$1" -n "$2" -V '+120s')
  [ -n "${3:-}" ] && opts+=(-O "source-address=$3")
  ssh-keygen "${opts[@]}" "$d/id.pub" >/dev/null 2>&1
  echo "$d"
}
try() { # $1 keydir -> CONNECTED / DENIED
  ssh -i "$1/id" -o CertificateFile="$1/id-cert.pub" -o IdentitiesOnly=yes \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o BatchMode=yes -o ConnectTimeout=5 -p 2222 dwho@127.0.0.1 \
      'echo CONNECTED' 2>/dev/null || echo "DENIED"
}

fail=0
expect() { # $1 label  $2 expected  $3 actual
  if [ "$2" = "$3" ]; then printf 'ok   %-58s [%s]\n' "$1" "$3"
  else printf 'FAIL %-58s expected %s got %s\n' "$1" "$2" "$3"; fail=1; fi
}

expect "vouched cert, src=127.0.0.1"          CONNECTED "$(try "$(mint 'bastion=pam-access;user=dwho;target=b1' dwho 127.0.0.1)")"
expect "vouched cert, no source-address"      CONNECTED "$(try "$(mint 'bastion=pam-access;user=dwho;target=b1' dwho '')")"
expect "deny direct SSO cert (no bastion=)"   DENIED    "$(try "$(mint 'dwho@llng-1' dwho '')")"
expect "deny wrong bastion id"                DENIED    "$(try "$(mint 'bastion=evil;user=dwho;target=b1' dwho '')")"
expect "deny cert-user != login"              DENIED    "$(try "$(mint 'bastion=pam-access;user=root;target=b1' dwho '')")"
expect "deny off-bastion source-address"      DENIED    "$(try "$(mint 'bastion=pam-access;user=dwho;target=b1' dwho 10.0.0.1)")"
expect "deny principal mismatch"              DENIED    "$(try "$(mint 'bastion=pam-access;user=dwho;target=b1' root '')")"

exit $fail
DRIVER

echo "=== backend cert-acceptance e2e (docker) ==="
docker run --rm \
    -v "$HELPER":/helper:ro \
    -v "$RUNNER":/run.sh:ro \
    debian:trixie bash /run.sh
rc=$?
if [ $rc -eq 0 ]; then
    echo "PASS: backend accepts only bastion-vouched certs"
else
    echo "FAIL: backend acceptance matrix had failures"
fi
exit $rc
