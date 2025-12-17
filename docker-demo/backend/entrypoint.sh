#!/bin/bash
# LLNG Backend Entrypoint
# Downloads CA key from SSO and configures sshd with user creation

set -e

PORTAL_URL="${LLNG_PORTAL_URL:-http://sso}"
SERVER_GROUP="${LLNG_SERVER_GROUP:-backend}"
CLIENT_ID="${LLNG_CLIENT_ID:-pam-access}"
CLIENT_SECRET="${LLNG_CLIENT_SECRET:-pamsecret}"
ADMIN_USER="${LLNG_ADMIN_USER:-dwho}"
ADMIN_PASSWORD="${LLNG_ADMIN_PASSWORD:-dwho}"
SSH_CA_FILE="/etc/ssh/llng_ca.pub"
TOKEN_FILE="/etc/security/llng_server_token"

echo "=== LLNG Backend Starting ==="
echo "Portal URL: $PORTAL_URL"
echo "Server Group: $SERVER_GROUP"

# Wait for SSO to be available
echo "Waiting for SSO..."
for i in {1..60}; do
    if curl -sf "$PORTAL_URL/" >/dev/null 2>&1; then
        echo "SSO is available"
        break
    fi
    sleep 1
done

# Download SSH CA public key
echo "Downloading SSH CA public key..."
for i in {1..10}; do
    if curl -sf "$PORTAL_URL/ssh/ca" -o "$SSH_CA_FILE" 2>/dev/null; then
        echo "CA key saved to $SSH_CA_FILE"
        cat "$SSH_CA_FILE"
        break
    fi
    echo "Retry $i..."
    sleep 2
done

if [ ! -f "$SSH_CA_FILE" ]; then
    echo "WARNING: Could not download CA key, SSH cert auth may not work"
fi

# Configure sshd for certificate authentication
cat > /etc/ssh/sshd_config.d/llng-backend.conf << EOF
# LemonLDAP::NG Backend Configuration

# Trust LLNG SSH CA
TrustedUserCAKeys $SSH_CA_FILE

# Enable certificate authentication
PubkeyAuthentication yes

# Disable password authentication
PasswordAuthentication no
KbdInteractiveAuthentication no

# No agent forwarding on backend
AllowAgentForwarding no

# Use PAM for authorization and user creation
UsePAM yes

# Security settings
X11Forwarding no
PermitRootLogin no
EOF

# Enroll server via Device Authorization Grant
echo "=== Server Enrollment via Device Authorization ==="
COOKIE_FILE="/tmp/admin_cookies"
touch "$COOKIE_FILE"

# Step 1: Get login token
echo "Getting login token..."
LOGIN_TOKEN=$(curl -s "$PORTAL_URL/" | grep -oP 'name="token" value="\K[^"]+' | head -1)
echo "  Token: $LOGIN_TOKEN"

# Step 2: Login as admin (don't follow redirect, cookie is set on 302 response)
echo "Logging in as $ADMIN_USER..."
LOGIN_RESP=$(curl -s -c "$COOKIE_FILE" \
    -d "user=$ADMIN_USER" \
    -d "password=$ADMIN_PASSWORD" \
    -d "token=$LOGIN_TOKEN" \
    "$PORTAL_URL/")

# Verify login succeeded by checking cookie file
if grep -q "lemonldap" "$COOKIE_FILE"; then
    echo "Admin login successful"
else
    echo "ERROR: Failed to login as admin"
    echo "Cookie file contents:"
    cat "$COOKIE_FILE" || true
    exit 1
fi

# Step 3: Initiate Device Authorization Grant
echo "Initiating Device Authorization Grant..."
DEVICE_RESP=$(curl -s -X POST "$PORTAL_URL/oauth2/device" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "scope=pam pam:server")
echo "  Device response: $DEVICE_RESP"

DEVICE_CODE=$(echo "$DEVICE_RESP" | jq -r '.device_code // empty')
USER_CODE=$(echo "$DEVICE_RESP" | jq -r '.user_code // empty')

if [ -z "$DEVICE_CODE" ] || [ -z "$USER_CODE" ]; then
    echo "ERROR: Failed to get device code"
    echo "Response: $DEVICE_RESP"
    exit 1
fi

echo "Device code obtained, user code: $USER_CODE"

# Step 4: Approve the device code as admin
# Remove dashes from user_code for URL
USER_CODE_CLEAN=$(echo "$USER_CODE" | tr -d '-')

echo "Approving device code..."
# First GET the device page to get the form token
DEVICE_PAGE=$(curl -s -b "$COOKIE_FILE" "$PORTAL_URL/device?user_code=$USER_CODE_CLEAN")
FORM_TOKEN=$(echo "$DEVICE_PAGE" | grep -oP 'name="token" value="\K[^"]+' | head -1)

# POST approval
APPROVE_RESP=$(curl -s -b "$COOKIE_FILE" -X POST "$PORTAL_URL/device" \
    -d "user_code=$USER_CODE_CLEAN" \
    -d "action=approve" \
    -d "token=$FORM_TOKEN")

if echo "$APPROVE_RESP" | grep -q "approved\|success\|authorized"; then
    echo "Device code approved"
else
    # Check if approval worked by trying to get token
    echo "Checking approval status..."
fi

# Step 5: Poll for access token
echo "Polling for access token..."
for i in {1..30}; do
    TOKEN_RESP=$(curl -s -X POST "$PORTAL_URL/oauth2/token" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
        -d "device_code=$DEVICE_CODE" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET")

    ACCESS_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.access_token // empty')

    if [ -n "$ACCESS_TOKEN" ]; then
        echo "Access token obtained!"
        # Extract additional token info
        REFRESH_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.refresh_token // empty')
        EXPIRES_IN=$(echo "$TOKEN_RESP" | jq -r '.expires_in // 3600')
        NOW=$(date +%s)
        EXPIRES_AT=$((NOW + EXPIRES_IN))
        # Save in JSON format with metadata
        cat > "$TOKEN_FILE" << TOKENEOF
{
  "access_token": "$ACCESS_TOKEN",
  "refresh_token": "${REFRESH_TOKEN:-}",
  "expires_at": $EXPIRES_AT,
  "enrolled_at": $NOW
}
TOKENEOF
        chmod 600 "$TOKEN_FILE"
        echo "Token saved in JSON format (expires at: $(date -d "@$EXPIRES_AT" 2>/dev/null || echo "$EXPIRES_AT"))"
        break
    fi

    ERROR=$(echo "$TOKEN_RESP" | jq -r '.error // empty')
    if [ "$ERROR" = "authorization_pending" ] || [ "$ERROR" = "slow_down" ]; then
        sleep 2
    elif [ -n "$ERROR" ]; then
        echo "ERROR: Token request failed: $ERROR"
        echo "Response: $TOKEN_RESP"
        exit 1
    fi
done

if [ ! -f "$TOKEN_FILE" ]; then
    echo "ERROR: Failed to obtain access token after polling"
    exit 1
fi

echo "Server enrollment complete"
rm -f "$COOKIE_FILE"

# Create PAM LLNG configuration
cat > /etc/security/pam_llng.conf << EOF
# LemonLDAP::NG PAM configuration for Backend

portal_url = $PORTAL_URL
server_group = $SERVER_GROUP

# Client credentials
client_id = $CLIENT_ID
client_secret = $CLIENT_SECRET

# Server token for authorization
server_token_file = $TOKEN_FILE

# HTTP settings
timeout = 10
verify_ssl = false

# Cache settings
cache_enabled = true
cache_dir = /var/cache/pam_llng
cache_ttl = 300

# User creation
create_user = true
create_home = true
default_shell = /bin/bash

# Logging
log_level = info
EOF

chmod 600 /etc/security/pam_llng.conf

# Create NSS LLNG configuration
cat > /etc/nss_llng.conf << EOF
# LemonLDAP::NG NSS configuration

portal_url = $PORTAL_URL
server_token_file = $TOKEN_FILE

# Cache settings
cache_ttl = 300

# UID/GID range for dynamic users
min_uid = 10000
max_uid = 60000
default_gid = 100

# Defaults
default_shell = /bin/bash
default_home_base = /home
EOF

chmod 644 /etc/nss_llng.conf

# Configure NSS to use LLNG for user/group resolution
sed -i 's/^passwd:.*/passwd:         files llng/' /etc/nsswitch.conf
sed -i 's/^group:.*/group:          files llng/' /etc/nsswitch.conf
echo "NSS configured to use LLNG"

# Configure PAM to create home directories on first login
cat > /etc/pam.d/sshd << EOF
# PAM configuration for SSH with LemonLDAP::NG
auth       required     pam_permit.so
account    required     pam_llng.so
session    required     pam_unix.so
session    optional     pam_mkhomedir.so skel=/etc/skel umask=0022
EOF

# Ensure sshd_config.d is included
if ! grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

# NSS module now resolves users dynamically from LLNG
# Test that NSS is working
echo "Testing NSS module..."
if getent passwd dwho >/dev/null 2>&1; then
    echo "  NSS module working: $(getent passwd dwho)"
else
    echo "  WARNING: NSS module not working, falling back to static users"
    for user in dwho rtyler; do
        if ! getent passwd "$user" >/dev/null 2>&1; then
            useradd -m -s /bin/bash "$user" 2>/dev/null && echo "  Created user: $user"
        fi
    done
fi

echo "=== Backend Configuration Complete ==="
echo "SSH listening on port 22"
echo "Users can connect with SSH certificates from LLNG"
echo "Sudo available for authorized users (rtyler)"

# Execute the command (sshd)
exec "$@"
