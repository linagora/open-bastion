#!/bin/bash
# LLNG Bastion Entrypoint - Token-based authentication
# Uses LLNG tokens as SSH passwords (no SSH certificates)

set -e

PORTAL_URL="${LLNG_PORTAL_URL:-http://sso}"
SERVER_GROUP="${LLNG_SERVER_GROUP:-bastion}"
CLIENT_ID="${LLNG_CLIENT_ID:-pam-access}"
CLIENT_SECRET="${LLNG_CLIENT_SECRET:-pamsecret}"
ADMIN_USER="${LLNG_ADMIN_USER:-dwho}"
ADMIN_PASSWORD="${LLNG_ADMIN_PASSWORD:-dwho}"
TOKEN_FILE="/etc/security/llng_server_token"

echo "=== LLNG Bastion Starting (Token Auth Mode) ==="
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

# Configure sshd for password authentication via PAM
cat > /etc/ssh/sshd_config.d/llng-bastion.conf << EOF
# LemonLDAP::NG Bastion Configuration (Token Auth Mode)

# Disable public key authentication
PubkeyAuthentication no

# Enable password authentication via PAM
PasswordAuthentication yes
KbdInteractiveAuthentication yes

# Allow agent forwarding for ProxyJump to backend
AllowAgentForwarding yes
AllowTcpForwarding yes

# Use PAM for authentication AND authorization
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

# Step 3: Initiate Device Authorization Grant with PKCE (RFC 7636)
echo "Initiating Device Authorization Grant with PKCE..."

# Generate PKCE code_verifier (32 bytes of random data, base64url encoded)
CODE_VERIFIER=$(head -c 32 /dev/urandom | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
# Generate code_challenge = BASE64URL(SHA256(code_verifier))
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
echo "  PKCE enabled (code_challenge_method=S256)"

DEVICE_RESP=$(curl -s -X POST "$PORTAL_URL/oauth2/device" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "scope=pam pam:server" \
    -d "code_challenge=$CODE_CHALLENGE" \
    -d "code_challenge_method=S256")
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

# Step 5: Poll for access token (with PKCE code_verifier)
echo "Polling for access token..."
for i in {1..30}; do
    TOKEN_RESP=$(curl -s -X POST "$PORTAL_URL/oauth2/token" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
        -d "device_code=$DEVICE_CODE" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET" \
        -d "code_verifier=$CODE_VERIFIER")

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
# LemonLDAP::NG PAM configuration for Bastion (Token Auth Mode)

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

# Start nscd for caching NSS lookups (runs as root, can read server token)
if command -v nscd >/dev/null 2>&1; then
    mkdir -p /var/run/nscd
    nscd -i passwd 2>/dev/null || true
    nscd 2>/dev/null &
    echo "nscd started for NSS caching"
fi

# Configure PAM for token-based authentication
# pam_llng.so in auth validates the LLNG token as password
cat > /etc/pam.d/sshd << EOF
# PAM configuration for SSH with LemonLDAP::NG (Token Auth Mode)
# User enters their LLNG token as password

# Authentication: LLNG token validation
auth       sufficient   pam_llng.so
auth       required     pam_deny.so

# Authorization: LLNG checks user access to server group
account    required     pam_llng.so

# Session management
session    required     pam_unix.so
session    optional     pam_mkhomedir.so skel=/etc/skel umask=0022
EOF

# Fix session recording directory permissions
chmod 1777 /var/lib/llng-sessions

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

echo "=== Bastion Configuration Complete (Token Auth Mode) ==="
echo "SSH listening on port 22"
echo "Users connect with: ssh -p 2222 <username>@localhost"
echo "Password: Use your LLNG access token"

# Execute the command (sshd)
exec "$@"
