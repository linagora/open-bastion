#!/bin/bash
# Open Bastion Quick Start - server entrypoint
# Enrolls against LemonLDAP::NG via Device Authorization Grant,
# then configures PAM + NSS for token-based SSH authentication.

set -e

PORTAL_URL="${LLNG_PORTAL_URL:-http://sso:8080}"
SERVER_GROUP="${LLNG_SERVER_GROUP:-quick-start}"
CLIENT_ID="${LLNG_CLIENT_ID:-pam-access}"
CLIENT_SECRET="${LLNG_CLIENT_SECRET:-pamsecret}"
ADMIN_USER="${LLNG_ADMIN_USER:-dwho}"
ADMIN_PASSWORD="${LLNG_ADMIN_PASSWORD:-dwho}"
TOKEN_FILE="/etc/open-bastion/server_token.json"

echo "=== Open Bastion Quick Start ==="
echo "Portal: $PORTAL_URL  Group: $SERVER_GROUP"

echo "Waiting for SSO..."
for i in {1..60}; do
    if curl -sf "$PORTAL_URL/" >/dev/null 2>&1; then
        echo "SSO is available"
        break
    fi
    sleep 1
done

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/open-bastion.conf << EOF
PubkeyAuthentication no
PasswordAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
X11Forwarding no
PermitRootLogin no
EOF

echo "=== Server enrollment (Device Authorization Grant) ==="
COOKIE_FILE=$(mktemp /tmp/admin_cookies.XXXXXX)
chmod 600 "$COOKIE_FILE"
trap 'rm -f "$COOKIE_FILE"' EXIT

LOGIN_TOKEN=$(curl -s "$PORTAL_URL/" | grep -oP 'name="token" value="\K[^"]+' | head -1)

curl -s -c "$COOKIE_FILE" \
    -d "user=$ADMIN_USER" \
    -d "password=$ADMIN_PASSWORD" \
    -d "token=$LOGIN_TOKEN" \
    "$PORTAL_URL/" >/dev/null

if ! grep -q "lemonldap" "$COOKIE_FILE"; then
    echo "ERROR: admin login failed"
    exit 1
fi
echo "Admin login OK"

# PKCE
CODE_VERIFIER=$(head -c 32 /dev/urandom | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

DEVICE_RESP=$(curl -s -X POST "$PORTAL_URL/oauth2/device" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "scope=pam pam:server" \
    -d "code_challenge=$CODE_CHALLENGE" \
    -d "code_challenge_method=S256")

DEVICE_CODE=$(echo "$DEVICE_RESP" | jq -r '.device_code // empty' 2>/dev/null || true)
USER_CODE=$(echo "$DEVICE_RESP" | jq -r '.user_code // empty' 2>/dev/null || true)

if [ -z "$DEVICE_CODE" ] || [ -z "$USER_CODE" ]; then
    echo "ERROR: device code request failed."
    echo "The /oauth2/device endpoint did not return a JSON body with device_code."
    echo "This usually means the oidc-device-authorization plugin did not load in the portal."
    echo "Check:  docker exec ob-quickstart-sso curl -sf http://localhost:8080/oauth2/device -X POST -d 'client_id=$CLIENT_ID&scope=pam'"
    exit 1
fi
echo "Device code: $USER_CODE"

USER_CODE_CLEAN=$(echo "$USER_CODE" | tr -d '-')
DEVICE_PAGE=$(curl -s -b "$COOKIE_FILE" "$PORTAL_URL/device?user_code=$USER_CODE_CLEAN")
FORM_TOKEN=$(echo "$DEVICE_PAGE" | grep -oP 'name="token" value="\K[^"]+' | head -1)

curl -s -b "$COOKIE_FILE" -X POST "$PORTAL_URL/device" \
    -d "user_code=$USER_CODE_CLEAN" \
    -d "action=approve" \
    -d "token=$FORM_TOKEN" >/dev/null

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
        REFRESH_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.refresh_token // empty')
        EXPIRES_IN=$(echo "$TOKEN_RESP" | jq -r '.expires_in // 3600')
        NOW=$(date +%s)
        EXPIRES_AT=$((NOW + EXPIRES_IN))
        cat > "$TOKEN_FILE" << TOKENEOF
{
  "access_token": "$ACCESS_TOKEN",
  "refresh_token": "${REFRESH_TOKEN:-}",
  "expires_at": $EXPIRES_AT,
  "enrolled_at": $NOW
}
TOKENEOF
        chmod 600 "$TOKEN_FILE"
        echo "Server token obtained"
        break
    fi
    ERROR=$(echo "$TOKEN_RESP" | jq -r '.error // empty')
    if [ "$ERROR" = "authorization_pending" ] || [ "$ERROR" = "slow_down" ]; then
        sleep 2
    elif [ -n "$ERROR" ]; then
        echo "ERROR: token request failed: $ERROR"
        exit 1
    fi
done

if [ ! -f "$TOKEN_FILE" ]; then
    echo "ERROR: no access token after polling"
    exit 1
fi

cat > /etc/open-bastion/openbastion.conf << EOF
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
log_level = info
EOF
chmod 600 /etc/open-bastion/openbastion.conf

cat > /etc/open-bastion/nss_openbastion.conf << EOF
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

sed -i 's/^passwd:.*/passwd:         files openbastion/' /etc/nsswitch.conf
sed -i 's/^group:.*/group:          files openbastion/' /etc/nsswitch.conf

if command -v nscd >/dev/null 2>&1; then
    mkdir -p /var/run/nscd
    nscd -i passwd 2>/dev/null || true
    nscd 2>/dev/null &
fi

cat > /etc/pam.d/sshd << 'EOF'
# Open Bastion - token authentication
auth       sufficient   pam_openbastion.so
auth       required     pam_deny.so
account    required     pam_openbastion.so
session    required     pam_openbastion.so create_user=true
session    required     pam_unix.so
session    optional     pam_mkhomedir.so skel=/etc/skel umask=0022
EOF

cat > /etc/pam.d/sudo << 'EOF'
# Open Bastion - sudo authorization
auth       required     pam_openbastion.so service_type=sudo
account    required     pam_openbastion.so service_type=sudo
session    required     pam_unix.so
EOF

# Defense-in-depth sudo: only members of the open-bastion-sudo system
# group can sudo, and pam_openbastion syncs group membership from the
# /pam/authorize sudo_allowed flag on each login.
groupadd --system open-bastion-sudo 2>/dev/null || true
cat > /etc/sudoers.d/open-bastion << 'EOF'
%open-bastion-sudo ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers.d/open-bastion

if ! grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

echo "=== Quick Start server ready ==="
echo "SSH on port 22 (mapped to 2222 on the host)"
echo "Users: dwho / rtyler / msmith (rtyler has sudo)"

exec "$@"
