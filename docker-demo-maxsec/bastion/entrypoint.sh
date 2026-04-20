#!/bin/bash
# Open Bastion Maximum Security Bastion Entrypoint (Mode E)
# - Downloads CA key from SSO
# - Downloads KRL (Key Revocation List)
# - Configures sshd for certificate-only auth
# - Sets up KRL refresh cron

set -e

PORTAL_URL="${LLNG_PORTAL_URL:-http://sso}"
SERVER_GROUP="${LLNG_SERVER_GROUP:-bastion}"
CLIENT_ID="${LLNG_CLIENT_ID:-pam-access}"
CLIENT_SECRET="${LLNG_CLIENT_SECRET:-pamsecret}"
ADMIN_USER="${LLNG_ADMIN_USER:-dwho}"
ADMIN_PASSWORD="${LLNG_ADMIN_PASSWORD:-dwho}"
SSH_CA_FILE="/etc/ssh/llng_ca.pub"
SSH_REVOKED_KEYS="/etc/ssh/revoked_keys"
TOKEN_FILE="/etc/open-bastion/server_token.json"
KRL_REFRESH_INTERVAL=30

echo "=== Open Bastion Maximum Security Bastion Starting (Mode E) ==="
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
    # Create empty revocation file if KRL endpoint not available or invalid
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
# Start cron daemon
cron

# Shared directory where llng-principals drops the SSH key fingerprint so that
# pam_openbastion can forward it to LLNG (/pam/authorize + /pam/verify
# fingerprint binding). OpenSSH does NOT propagate SSH_USER_AUTH to the PAM
# environment during pam_acct_mgmt, so we need this out-of-band channel.
# Directory must be owned by the AuthorizedPrincipalsCommandUser and NOT be
# world-writable — otherwise an unprivileged local user could pre-create
# <pid>.fp with attacker-controlled content. Mode 0700 means only the
# principals helper can enumerate/create drops; root still reads via
# permission bypass. pam_openbastion additionally validates file ownership
# and mode at read time.
mkdir -p /run/open-bastion/ssh-fp
chown nobody:nogroup /run/open-bastion/ssh-fp
chmod 0700 /run/open-bastion/ssh-fp

# Create script to validate principals and record the SSH key fingerprint.
cat > /usr/local/bin/llng-principals << 'SCRIPT'
#!/bin/bash
# Called by sshd AuthorizedPrincipalsCommand (runs as nobody).
# Args: <username> <key-type> <key-base64> <fingerprint>
# Writes <fingerprint> to /run/open-bastion/ssh-fp/<sshd-session-pid>.fp so
# that pam_openbastion can pick it up in pam_acct_mgmt and forward it to
# LLNG for /pam/authorize fingerprint binding.
# User creation is handled by pam_openbastion (create_user=true in open_session).
USERNAME="$1"
FINGERPRINT="$4"

# Record the fingerprint against our sshd-session ancestor PID.
# Walk up /proc until we find the sshd-session process — pam_openbastion
# will converge on the same ancestor from its own position.
if [ -n "$FINGERPRINT" ] && [ -d /run/open-bastion/ssh-fp ]; then
    case "$FINGERPRINT" in
        SHA256:[A-Za-z0-9+/]*) : ;;
        *) FINGERPRINT="" ;;
    esac
fi
if [ -n "$FINGERPRINT" ]; then
    pid=$PPID
    i=0
    while [ "$pid" -gt 1 ] && [ $i -lt 16 ]; do
        comm=$(cat /proc/"$pid"/comm 2>/dev/null || echo "")
        case "$comm" in
            sshd-session|sshd) break ;;
        esac
        pid=$(awk '/^PPid:/ {print $2}' /proc/"$pid"/status 2>/dev/null)
        [ -z "$pid" ] && pid=0
        i=$((i + 1))
    done
    if [ "$pid" -gt 1 ]; then
        umask 077
        tmp=$(mktemp /run/open-bastion/ssh-fp/."$pid".XXXXXX 2>/dev/null) || tmp=""
        if [ -n "$tmp" ]; then
            printf '%s\n' "$FINGERPRINT" > "$tmp"
            mv -f "$tmp" /run/open-bastion/ssh-fp/"$pid".fp
        fi
    fi
fi

# Check if user is known (locally or via NSS/libnss_openbastion)
if getent passwd "$USERNAME" >/dev/null 2>&1; then
    echo "$USERNAME"
fi
SCRIPT
chmod 755 /usr/local/bin/llng-principals

# Configure sshd for maximum security (Mode E)
cat > /etc/ssh/sshd_config.d/llng-bastion.conf << EOF
# Open Bastion Maximum Security Configuration (Mode E)

# Trust LLNG SSH CA
TrustedUserCAKeys $SSH_CA_FILE

# Enable certificate authentication
PubkeyAuthentication yes

# MAXIMUM SECURITY: No unsigned keys allowed
AuthorizedKeysFile none

# MAXIMUM SECURITY: Key Revocation List (mandatory)
RevokedKeys $SSH_REVOKED_KEYS

# Create users on-the-fly via principals command
# %f = SHA256 fingerprint of the client key/cert (%F is the CA fingerprint);
# recorded out-of-band so pam_openbastion can forward it to LLNG for
# fingerprint binding on /pam/authorize and /pam/verify.
AuthorizedPrincipalsCommand /usr/local/bin/llng-principals %u %t %k %f
AuthorizedPrincipalsCommandUser nobody

# Disable password authentication
PasswordAuthentication no
KbdInteractiveAuthentication no

# ProxyJump requires TCP forwarding, but not SSH agent forwarding
AllowAgentForwarding no
AllowTcpForwarding yes

# Expose certificate info for audit
ExposeAuthInfo yes

# Use PAM for authorization
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

# Step 2: Login as admin
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

# Create PAM Open Bastion configuration
mkdir -p /etc/open-bastion
cat > /etc/open-bastion/openbastion.conf << EOF
# Open Bastion PAM configuration for Bastion (Mode E - Maximum Security)

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
cache_dir = /var/cache/open-bastion
cache_ttl = 300

# Logging
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

# Create SSH proxy configuration
cat > /etc/open-bastion/ssh-proxy.conf << EOF
# Open Bastion SSH Proxy configuration (Mode E)
PORTAL_URL=$PORTAL_URL
SERVER_TOKEN_FILE=$TOKEN_FILE
SERVER_GROUP=$SERVER_GROUP
TARGET_GROUP=backend
TIMEOUT=10
VERIFY_SSL=false
SSH_OPTIONS="-o StrictHostKeyChecking=no"
DEBUG=false
EOF
chmod 644 /etc/open-bastion/ssh-proxy.conf

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

# Session recording directory: match production permissions (1770 root:ob-sessions)
groupadd --system ob-sessions 2>/dev/null || true
mkdir -p /var/lib/open-bastion/sessions
chgrp ob-sessions /var/lib/open-bastion/sessions
chmod 1770 /var/lib/open-bastion/sessions

# Ensure sshd_config.d is included
if ! grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

# Test NSS
echo "Testing NSS module..."
if getent passwd dwho >/dev/null 2>&1; then
    echo "  NSS module working: $(getent passwd dwho)"
else
    echo "  ERROR: NSS module not resolving users from LLNG"
    exit 1
fi

echo "=== Maximum Security Bastion Configuration Complete (Mode E) ==="
echo "SSH listening on port 22"
echo "Authentication: SSO-signed certificates ONLY"
echo "Unsigned keys: REJECTED (AuthorizedKeysFile none)"
echo "KRL: ACTIVE (refreshed every ${KRL_REFRESH_INTERVAL} min)"
echo "sudo: requires fresh LLNG temporary token"
echo ""
echo "To connect to backend via bastion:"
echo "  From bastion: ob-ssh-proxy backend"

exec "$@"
