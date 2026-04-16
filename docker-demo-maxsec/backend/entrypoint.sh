#!/bin/bash
# Open Bastion Maximum Security Backend Entrypoint (Mode E)
# - Downloads CA key from SSO
# - Downloads KRL (Key Revocation List)
# - Configures sshd for certificate-only auth
# - Sets up KRL refresh cron
# - Configures bastion JWT verification

set -e

PORTAL_URL="${LLNG_PORTAL_URL:-http://sso}"
SERVER_GROUP="${LLNG_SERVER_GROUP:-backend}"
CLIENT_ID="${LLNG_CLIENT_ID:-pam-access}"
CLIENT_SECRET="${LLNG_CLIENT_SECRET:-pamsecret}"
ADMIN_USER="${LLNG_ADMIN_USER:-dwho}"
ADMIN_PASSWORD="${LLNG_ADMIN_PASSWORD:-dwho}"
SSH_CA_FILE="/etc/ssh/llng_ca.pub"
SSH_REVOKED_KEYS="/etc/ssh/revoked_keys"
TOKEN_FILE="/etc/open-bastion/server_token.json"
KRL_REFRESH_INTERVAL=30

echo "=== Open Bastion Maximum Security Backend Starting (Mode E) ==="
echo "Portal URL: $PORTAL_URL"
echo "Server Group: $SERVER_GROUP"
echo "Security: SSO certificates only + sudo via LLNG token + KRL mandatory"

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

# Download Key Revocation List (KRL)
echo "Downloading Key Revocation List..."
if curl -sf "$PORTAL_URL/ssh/revoked" -o "${SSH_REVOKED_KEYS}.tmp" 2>/dev/null \
   && head -c 6 "${SSH_REVOKED_KEYS}.tmp" | grep -q "SSHKRL"; then
    mv "${SSH_REVOKED_KEYS}.tmp" "$SSH_REVOKED_KEYS"
    echo "KRL saved to $SSH_REVOKED_KEYS"
else
    rm -f "${SSH_REVOKED_KEYS}.tmp"
    touch "$SSH_REVOKED_KEYS"
    echo "KRL not available yet, created empty revocation file"
fi
chmod 644 "$SSH_REVOKED_KEYS"

# Set up KRL refresh cron job (validates KRL format before replacing)
echo "Setting up KRL refresh cron (every ${KRL_REFRESH_INTERVAL} min)..."
cat > /etc/cron.d/open-bastion-krl << CRONEOF
*/${KRL_REFRESH_INTERVAL} * * * * root tmp=\$(mktemp /tmp/open-bastion-krl.XXXXXX) && curl -sf -o "\$tmp" "${PORTAL_URL}/ssh/revoked" && head -c 6 "\$tmp" | grep -q SSHKRL && mv "\$tmp" "${SSH_REVOKED_KEYS}" || rm -f "\$tmp"
CRONEOF
chmod 644 /etc/cron.d/open-bastion-krl
cron

# Configure sshd for maximum security (Mode E)
cat > /etc/ssh/sshd_config.d/llng-backend.conf << EOF
# Open Bastion Maximum Security Configuration (Mode E)

# Trust LLNG SSH CA
TrustedUserCAKeys $SSH_CA_FILE

# Enable certificate authentication
PubkeyAuthentication yes

# MAXIMUM SECURITY: No unsigned keys allowed
AuthorizedKeysFile none

# MAXIMUM SECURITY: Key Revocation List (mandatory)
RevokedKeys $SSH_REVOKED_KEYS

# Disable password authentication
PasswordAuthentication no
KbdInteractiveAuthentication no

# Expose certificate info for audit
ExposeAuthInfo yes

# No agent forwarding on backend
AllowAgentForwarding no

# Use PAM for authorization and user creation
UsePAM yes

# Security settings
X11Forwarding no
PermitRootLogin no

# Accept bastion JWT environment variable from SSH connection
AcceptEnv LLNG_BASTION_JWT
EOF

# Enroll server via Device Authorization Grant
# Ensure config directory exists before enrollment
mkdir -p /etc/open-bastion

echo "=== Server Enrollment via Device Authorization ==="
COOKIE_FILE="/tmp/admin_cookies"
touch "$COOKIE_FILE"

echo "Getting login token..."
LOGIN_TOKEN=$(curl -s "$PORTAL_URL/" | grep -oP 'name="token" value="\K[^"]+' | head -1)
echo "  Token: $LOGIN_TOKEN"

echo "Logging in as $ADMIN_USER..."
LOGIN_RESP=$(curl -s -c "$COOKIE_FILE" \
    -d "user=$ADMIN_USER" \
    -d "password=$ADMIN_PASSWORD" \
    -d "token=$LOGIN_TOKEN" \
    "$PORTAL_URL/")

if grep -q "lemonldap" "$COOKIE_FILE"; then
    echo "Admin login successful"
else
    echo "ERROR: Failed to login as admin"
    cat "$COOKIE_FILE" || true
    exit 1
fi

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
    exit 1
fi

echo "Device code obtained, user code: $USER_CODE"

USER_CODE_CLEAN=$(echo "$USER_CODE" | tr -d '-')

echo "Approving device code..."
DEVICE_PAGE=$(curl -s -b "$COOKIE_FILE" "$PORTAL_URL/device?user_code=$USER_CODE_CLEAN")
FORM_TOKEN=$(echo "$DEVICE_PAGE" | grep -oP 'name="token" value="\K[^"]+' | head -1)

APPROVE_RESP=$(curl -s -b "$COOKIE_FILE" -X POST "$PORTAL_URL/device" \
    -d "user_code=$USER_CODE_CLEAN" \
    -d "action=approve" \
    -d "token=$FORM_TOKEN")

if echo "$APPROVE_RESP" | grep -q "approved\|success\|authorized"; then
    echo "Device code approved"
else
    echo "Checking approval status..."
fi

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
        REFRESH_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.refresh_token // empty')
        EXPIRES_IN=$(echo "$TOKEN_RESP" | jq -r '.expires_in // 3600')
        NOW=$(date +%s)
        EXPIRES_AT=$((NOW + EXPIRES_IN))
        jq -n \
            --arg at "$ACCESS_TOKEN" \
            --arg rt "${REFRESH_TOKEN:-}" \
            --argjson ea "$EXPIRES_AT" \
            --argjson en "$NOW" \
            '{"access_token":$at,"refresh_token":$rt,"expires_at":$ea,"enrolled_at":$en}' \
            > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        echo "Token saved (expires at: $(date -d "@$EXPIRES_AT" 2>/dev/null || echo "$EXPIRES_AT"))"
        break
    fi

    ERROR=$(echo "$TOKEN_RESP" | jq -r '.error // empty')
    if [ "$ERROR" = "authorization_pending" ] || [ "$ERROR" = "slow_down" ]; then
        sleep 2
    elif [ -n "$ERROR" ]; then
        echo "ERROR: Token request failed: $ERROR"
        exit 1
    fi
done

if [ ! -f "$TOKEN_FILE" ]; then
    echo "ERROR: Failed to obtain access token after polling"
    exit 1
fi

echo "Server enrollment complete"
rm -f "$COOKIE_FILE"

# Create PAM configuration
mkdir -p /etc/open-bastion
cat > /etc/open-bastion/openbastion.conf << EOF
# Open Bastion PAM configuration for Backend (Mode E - Maximum Security)

portal_url = $PORTAL_URL
server_group = $SERVER_GROUP

client_id = $CLIENT_ID
client_secret = $CLIENT_SECRET

server_token_file = $TOKEN_FILE

timeout = 10
verify_ssl = false

cache_enabled = true
cache_dir = /var/cache/open-bastion
cache_ttl = 300

create_user = true
create_home = true
default_shell = /bin/bash

# Bastion JWT verification
bastion_jwt_required = true
bastion_jwt_issuer = $PORTAL_URL
bastion_jwt_jwks_url = $PORTAL_URL/.well-known/jwks.json
bastion_jwt_jwks_cache = /var/cache/open-bastion/jwks.json
bastion_jwt_cache_ttl = 3600
bastion_jwt_clock_skew = 60

log_level = info
EOF

chmod 600 /etc/open-bastion/openbastion.conf

# Create NSS configuration
cat > /etc/open-bastion/nss_openbastion.conf << EOF
# Open Bastion NSS configuration

portal_url = $PORTAL_URL
server_token_file = $TOKEN_FILE

cache_ttl = 300
min_uid = 10000
max_uid = 60000
default_gid = 100
default_shell = /bin/bash
default_home_base = /home
EOF

chmod 644 /etc/open-bastion/nss_openbastion.conf

# Configure NSS
sed -i 's/^passwd:.*/passwd:         files openbastion/' /etc/nsswitch.conf
sed -i 's/^group:.*/group:          files openbastion/' /etc/nsswitch.conf
echo "NSS configured"

# Start nscd
if command -v nscd >/dev/null 2>&1; then
    mkdir -p /var/run/nscd
    nscd -i passwd 2>/dev/null || true
    nscd 2>/dev/null &
    echo "nscd started"
fi

# Configure PAM for SSH (Mode E)
cat > /etc/pam.d/sshd << EOF
# PAM configuration for SSH with Open Bastion (Mode E - Maximum Security)
auth       required     pam_permit.so
account    required     pam_openbastion.so
session    required     pam_unix.so
session    optional     pam_mkhomedir.so skel=/etc/skel umask=0077
EOF

# Ensure sshd_config.d is included
if ! grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

# Test NSS
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

echo "=== Maximum Security Backend Configuration Complete (Mode E) ==="
echo "SSH listening on port 22"
echo "Authentication: SSO-signed certificates ONLY"
echo "Unsigned keys: REJECTED (AuthorizedKeysFile none)"
echo "KRL: ACTIVE (refreshed every ${KRL_REFRESH_INTERVAL} min)"
echo "sudo: requires fresh LLNG temporary token"
echo "Bastion JWT: REQUIRED"
echo ""
echo "Direct SSH connections without valid bastion JWT will be DENIED"

exec "$@"
