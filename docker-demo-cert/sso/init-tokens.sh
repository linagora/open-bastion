#!/bin/bash
# LemonLDAP::NG init script
# Pre-creates server tokens for bastion and backend at startup

echo "=== Initializing LLNG server tokens ==="

# Session storage directories
SESSIONS_DIR="/var/lib/lemonldap-ng/sessions"
LOCK_DIR="${SESSIONS_DIR}/lock"
SSH_DIR="/var/lib/lemonldap-ng/ssh"

# Pre-defined server tokens (must match docker-compose.yml LLNG_SERVER_TOKEN values)
SERVER_TOKEN="5f3284b425bbd083e1c47dc737acbffb0f04ecdbecd942486f2e13220b03abfa"

# Ensure directories exist with correct ownership
mkdir -p "$SESSIONS_DIR" "$LOCK_DIR" "$SSH_DIR"

# Remove any existing session file with this ID (might have wrong format)
rm -f "$SESSIONS_DIR/$SERVER_TOKEN"

chown -R www-data:www-data /var/lib/lemonldap-ng

echo "Pre-creating server token..."

# Create server token session using LLNG's Session module directly
# This ensures the correct serialization format (JSON, not Storable)
perl -e '
    use strict;
    use warnings;
    use Lemonldap::NG::Common::Session;

    my $sessions_dir = $ARGV[0];
    my $lock_dir = $ARGV[1];
    my $target_id = $ARGV[2];
    my $now = time();
    my $expires = $now + 31536000;  # 1 year

    # Create session with LLNG Session module (which handles JSON serialization)
    my $session = Lemonldap::NG::Common::Session->new({
        storageModule => "Apache::Session::File",
        storageModuleOptions => {
            Directory => $sessions_dir,
            LockDirectory => $lock_dir,
        },
        id => $target_id,
        force => 1,  # Force creation with specific ID
        kind => "OIDCI",
        info => {
            _session_kind   => "OIDCI",
            _utime          => $now,
            grant_type      => "device_code",
            scope           => "pam pam:server",
            client_id       => "pam-access",
            _type           => "access_token",
            rp              => "pam-access",
            _pamServer      => 1,
            _pamServerGroup => "bastion",
            _pamHostname    => "bastion-server",
            _pamEnrolledAt  => $now,
            _pamLastSeen    => $now,
            _pamStatus      => "active",
            expires_at      => $expires,
        },
    });

    if ($session->error) {
        die "Error creating session: " . $session->error . "\n";
    }

    print "Created server token with ID: " . $session->id . "\n";
' "$SESSIONS_DIR" "$LOCK_DIR" "$SERVER_TOKEN"

chown -R www-data:www-data "$SESSIONS_DIR"
echo "Server tokens created"
