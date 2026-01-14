#!/bin/bash
# LLNG Backend Entrypoint (Unconfigured)
# This simulates a fresh installation with just the PAM/NSS modules installed
# No LLNG configuration is done - everything must be configured manually

set -e

echo "=== SSH Backend Starting (Unconfigured) ==="
echo ""
echo "This server has the LLNG PAM/NSS modules installed but NOT configured."
echo "You must:"
echo "  1. Configure /etc/open-bastion/openbastion.conf"
echo "  2. Configure /etc/open-bastion/nss_openbastion.conf"
echo "  3. Configure /etc/nsswitch.conf to use 'openbastion'"
echo "  4. Configure /etc/pam.d/sshd"
echo "  5. Enroll the server using ob-enroll"
echo ""
echo "See docker/README.md for step-by-step instructions."
echo ""

# Generate SSH host keys if not present
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

# Ensure sshd_config.d is included (standard Debian behavior)
if ! grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

echo "=== Backend Started ==="
echo "SSH listening on port 22"
echo ""

# Execute the command (sshd)
exec "$@"
