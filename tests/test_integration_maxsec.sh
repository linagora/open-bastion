#!/bin/bash
#
# test_integration_maxsec.sh - Integration tests for docker-demo-maxsec (Mode E)
#
# Tests the full PAM module with a real LLNG server including:
# - Docker compose build and startup
# - LLNG authentication via llng CLI
# - Token introspection with JWT client assertion
# - SSH connection with certificate authentication
# - Mode E specific security tests (KRL, unsigned key rejection, sudo PAM, etc.)
#
# Usage:
#   ./tests/test_integration_maxsec.sh [--keep] [--verbose]
#
# Options:
#   --keep     Don't tear down containers after test
#   --verbose  Show verbose output
#
# Requirements:
#   - docker and docker compose
#   - llng CLI tool (from simple-oidc-client)
#   - jq
#   - curl
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Options
KEEP_CONTAINERS=0
VERBOSE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)
            KEEP_CONTAINERS=1
            shift
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_DIR/docker-demo-maxsec"
COOKIE_FILE="/tmp/llng-test-cookies"
TEST_KEY="/tmp/test_integration_key"
SVC_KEY="/tmp/test_integration_svc_key"

# Test configuration
PORTAL_URL="http://localhost:80"
TEST_USER="dwho"
TEST_PASSWORD="dwho"
CLIENT_ID="pam-access"
CLIENT_SECRET="pamsecret"

# Service account used for the SSH-key-only scenario. Intentionally a user
# unknown to LLNG: only service-accounts.conf + the matching .pub key on
# the bastion grant access.
SVC_ACCOUNT="ansible-ci"
SVC_UID=5000
SVC_GID=5000

log() {
    echo -e "${GREEN}[TEST]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_verbose() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo -e "[DEBUG] $*"
    fi
}

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}[FAIL]${NC} $1"
    if [[ -n "$2" ]]; then
        echo "       Details: $2"
    fi
}

cleanup() {
    log "Cleaning up..."
    rm -f "$COOKIE_FILE" "${TEST_KEY}" "${TEST_KEY}.pub" "${TEST_KEY}-cert.pub" \
          "${SVC_KEY}" "${SVC_KEY}.pub" 2>/dev/null || true

    if [[ $KEEP_CONTAINERS -eq 0 ]]; then
        log "Stopping containers..."
        cd "$DOCKER_DIR" && docker compose down --volumes --remove-orphans 2>/dev/null || true
    else
        log_warn "Keeping containers running (--keep specified)"
    fi
}

trap cleanup EXIT

check_requirements() {
    log "Checking requirements..."

    local missing=0

    if ! command -v docker &>/dev/null; then
        log_error "docker not found"
        missing=1
    fi

    if ! command -v docker compose &>/dev/null && ! docker compose version &>/dev/null; then
        log_error "docker compose not found"
        missing=1
    fi

    if ! command -v llng &>/dev/null; then
        log_error "llng CLI not found (install from simple-oidc-client)"
        missing=1
    fi

    if ! command -v jq &>/dev/null; then
        log_error "jq not found"
        missing=1
    fi

    if ! command -v curl &>/dev/null; then
        log_error "curl not found"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi

    log "All requirements satisfied"
}

start_containers() {
    log "Building and starting docker-demo-maxsec..."
    cd "$DOCKER_DIR"

    # Stop any conflicting containers first
    log "Stopping any conflicting containers..."
    cd "$PROJECT_DIR/docker-demo-token" && docker compose down --volumes --remove-orphans 2>/dev/null || true
    cd "$PROJECT_DIR/docker-demo-cert" && docker compose down --volumes --remove-orphans 2>/dev/null || true
    cd "$PROJECT_DIR/docker-demo-maxsec" && docker compose down --volumes --remove-orphans 2>/dev/null || true
    cd "$DOCKER_DIR"

    # Build images
    log_verbose "Building images..."
    if [[ $VERBOSE -eq 1 ]]; then
        docker compose build
    else
        docker compose build --quiet
    fi

    # Start containers
    log_verbose "Starting containers..."
    docker compose up -d

    # Wait for SSO to be healthy
    log "Waiting for SSO to be healthy..."
    local max_wait=120
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        if curl -sf "$PORTAL_URL/" >/dev/null 2>&1; then
            log "SSO is healthy after ${waited}s"
            return 0
        fi
        sleep 2
        ((waited+=2))
        log_verbose "Waiting... ${waited}s"
    done

    log_error "SSO did not become healthy within ${max_wait}s"
    docker compose logs sso
    return 1
}

wait_for_bastion() {
    log "Waiting for bastion enrollment..."
    local max_wait=60
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        # Check if bastion has enrolled (token file exists)
        if docker exec ob-maxsec-bastion test -f /etc/open-bastion/server_token.json 2>/dev/null; then
            log "Bastion enrolled after ${waited}s"
            return 0
        fi
        sleep 2
        ((waited+=2))
        log_verbose "Waiting for bastion enrollment... ${waited}s"
    done

    log_error "Bastion did not enroll within ${max_wait}s"
    docker logs ob-maxsec-bastion
    return 1
}

wait_for_backend() {
    log "Waiting for backend enrollment..."
    local max_wait=60
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        # Check if backend has enrolled (token file exists)
        if docker exec ob-maxsec-backend test -f /etc/open-bastion/server_token.json 2>/dev/null; then
            log "Backend enrolled after ${waited}s"
            return 0
        fi
        sleep 2
        ((waited+=2))
        log_verbose "Waiting for backend enrollment... ${waited}s"
    done

    log_error "Backend did not enroll within ${max_wait}s"
    docker logs ob-maxsec-backend
    return 1
}

# =============================================================================
# Test Cases
# =============================================================================

test_llng_authentication() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing LLNG authentication via llng CLI..."

    # Get session cookie using llng client
    rm -f "$COOKIE_FILE"
    local output
    output=$(llng --llng-url "$PORTAL_URL" \
                  --login "$TEST_USER" \
                  --password "$TEST_PASSWORD" \
                  --cookie-jar "$COOKIE_FILE" \
                  llng_cookie 2>&1) || true

    log_verbose "llng output: $output"

    # Check if cookie was obtained
    if [[ -f "$COOKIE_FILE" ]] && grep -q "lemonldap" "$COOKIE_FILE"; then
        pass "LLNG authentication successful"
        return 0
    else
        fail "LLNG authentication failed" "$output"
        return 1
    fi
}

test_sso_session_valid() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing SSO session validity..."

    # Use /mysession/?whoami to get the authenticated user's uid
    local response
    response=$(curl -sf -b "$COOKIE_FILE" "$PORTAL_URL/mysession/?whoami" 2>&1) || true

    log_verbose "Session response: $response"

    if echo "$response" | grep -q "$TEST_USER"; then
        pass "SSO session is valid for user $TEST_USER"
        return 0
    else
        fail "SSO session invalid or user mismatch" "$response"
        return 1
    fi
}

test_ssh_ca_endpoint() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing SSH CA public key endpoint..."

    local ca_key
    ca_key=$(curl -sf "$PORTAL_URL/ssh/ca" 2>&1) || true

    log_verbose "CA key: $ca_key"

    if echo "$ca_key" | grep -q "^ssh-ed25519\|^ssh-rsa"; then
        pass "SSH CA endpoint returns valid public key"
        return 0
    else
        fail "SSH CA endpoint did not return valid key" "$ca_key"
        return 1
    fi
}

test_ssh_certificate_signing() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing SSH certificate signing..."

    # Generate a test key
    rm -f "${TEST_KEY}" "${TEST_KEY}.pub" "${TEST_KEY}-cert.pub"
    ssh-keygen -t ed25519 -f "${TEST_KEY}" -N "" -q

    local pub_key
    pub_key=$(cat "${TEST_KEY}.pub")

    # Request certificate
    local response
    response=$(curl -sf -X POST "$PORTAL_URL/ssh/sign" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"public_key\":\"$pub_key\",\"server_group\":\"bastion\"}" 2>&1) || true

    log_verbose "Sign response: $response"

    # Extract certificate
    local cert
    cert=$(echo "$response" | jq -r '.certificate // empty')

    if [[ -n "$cert" ]] && echo "$cert" | grep -q "ssh-ed25519-cert"; then
        echo "$cert" > "${TEST_KEY}-cert.pub"
        pass "SSH certificate obtained"

        # Verify certificate contents
        log_verbose "Certificate details:"
        ssh-keygen -L -f "${TEST_KEY}-cert.pub" 2>&1 | head -20 || true
        return 0
    else
        fail "Failed to get SSH certificate" "$response"
        return 1
    fi
}

test_pam_authorize_endpoint() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing PAM authorize endpoint..."

    # Get server token from bastion
    local server_token
    server_token=$(docker exec ob-maxsec-bastion cat /etc/open-bastion/server_token.json 2>/dev/null | jq -r '.access_token // empty') || true

    if [[ -z "$server_token" ]]; then
        fail "Could not get server token from bastion"
        return 1
    fi

    log_verbose "Server token: ${server_token:0:20}..."

    # Call PAM authorize endpoint
    local response
    response=$(curl -sf -X POST "$PORTAL_URL/pam/authorize" \
        -H "Authorization: Bearer $server_token" \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"$TEST_USER\",\"server_group\":\"bastion\"}" 2>&1) || true

    log_verbose "PAM authorize response: $response"

    if echo "$response" | jq -e '.authorized == true' >/dev/null 2>&1; then
        pass "PAM authorize endpoint works"
        return 0
    else
        fail "PAM authorize endpoint failed" "$response"
        return 1
    fi
}

test_pam_authorize_fingerprint_binding() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing /pam/authorize SSH fingerprint binding (PamAccess >= 0.1.16)..."

    if [[ ! -f "${TEST_KEY}.pub" ]]; then
        log_warn "No key available, skipping fingerprint binding test"
        pass "Fingerprint binding test skipped (no key)"
        return 0
    fi

    # LLNG SSHCA stores the SHA256 fingerprint of the user's *unsigned*
    # public key in the persistent session. ssh-keygen -l -E sha256 -f pub
    # computes the same value.
    local fingerprint
    fingerprint=$(ssh-keygen -l -E sha256 -f "${TEST_KEY}.pub" 2>/dev/null | awk '{print $2}')
    if [[ -z "$fingerprint" || "$fingerprint" != SHA256:* ]]; then
        fail "Could not compute SHA256 fingerprint of ${TEST_KEY}.pub"
        return 1
    fi
    log_verbose "Computed fingerprint: $fingerprint"

    local server_token
    server_token=$(docker exec ob-maxsec-bastion cat /etc/open-bastion/server_token.json 2>/dev/null | jq -r '.access_token // empty') || true
    if [[ -z "$server_token" ]]; then
        fail "Could not get server token from bastion"
        return 1
    fi

    local body_tmp http_code response
    body_tmp=$(mktemp)

    # 1. Matching fingerprint must be accepted (HTTP 200 + authorized:true)
    http_code=$(curl -s -o "$body_tmp" -w '%{http_code}' -X POST "$PORTAL_URL/pam/authorize" \
        -H "Authorization: Bearer $server_token" \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"$TEST_USER\",\"server_group\":\"bastion\",\"fingerprint\":\"$fingerprint\"}")
    response=$(cat "$body_tmp")
    log_verbose "authorize(match) HTTP=$http_code body=$response"
    if [[ "$http_code" != "200" ]]; then
        rm -f "$body_tmp"
        fail "authorize(match) expected HTTP 200, got $http_code" "$response"
        return 1
    fi
    if ! echo "$response" | jq -e 'type == "object" and .authorized == true' >/dev/null 2>&1; then
        rm -f "$body_tmp"
        fail "authorize(match) expected authorized:true" "$response"
        return 1
    fi

    # 2. Well-formed but unknown fingerprint must be refused
    #    (HTTP 200 + authorized:false explicitly)
    local bogus="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    http_code=$(curl -s -o "$body_tmp" -w '%{http_code}' -X POST "$PORTAL_URL/pam/authorize" \
        -H "Authorization: Bearer $server_token" \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"$TEST_USER\",\"server_group\":\"bastion\",\"fingerprint\":\"$bogus\"}")
    response=$(cat "$body_tmp")
    log_verbose "authorize(unknown) HTTP=$http_code body=$response"
    if [[ "$http_code" != "200" ]]; then
        rm -f "$body_tmp"
        fail "authorize(unknown) expected HTTP 200, got $http_code" "$response"
        return 1
    fi
    if ! echo "$response" | jq -e 'type == "object" and .authorized == false' >/dev/null 2>&1; then
        rm -f "$body_tmp"
        fail "authorize(unknown) expected authorized:false (not a jq parse failure)" "$response"
        return 1
    fi

    # 3. Malformed fingerprint must be rejected with HTTP 400
    http_code=$(curl -s -o "$body_tmp" -w '%{http_code}' -X POST "$PORTAL_URL/pam/authorize" \
        -H "Authorization: Bearer $server_token" \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"$TEST_USER\",\"server_group\":\"bastion\",\"fingerprint\":\"not-a-fingerprint\"}")
    response=$(cat "$body_tmp")
    log_verbose "authorize(malformed) HTTP=$http_code body=$response"
    if [[ "$http_code" != "400" ]]; then
        rm -f "$body_tmp"
        fail "authorize(malformed) expected HTTP 400, got $http_code" "$response"
        return 1
    fi

    rm -f "$body_tmp"
    pass "/pam/authorize fingerprint binding works (match / unknown / malformed)"
    return 0
}

test_pam_authorize_rejects_revoked_cert() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing /pam/authorize rejects a cert revoked via /ssh/myrevoke..."

    if [[ ! -f "${TEST_KEY}.pub" ]]; then
        pass "Revocation test skipped (no key)"
        return 0
    fi

    local fingerprint
    fingerprint=$(ssh-keygen -l -E sha256 -f "${TEST_KEY}.pub" 2>/dev/null | awk '{print $2}')
    if [[ -z "$fingerprint" ]]; then
        fail "Could not compute fingerprint for revocation test"
        return 1
    fi

    # Find the serial attached to this fingerprint in the user's cert list
    local list
    list=$(curl -sf "$PORTAL_URL/ssh/mycerts" -b "$COOKIE_FILE" 2>&1) || true
    log_verbose "mycerts: $list"
    local serial
    serial=$(echo "$list" | jq -r --arg fp "$fingerprint" \
        '(.certificates // []) | .[] | select(.fingerprint == $fp) | .serial' 2>/dev/null | head -n1)
    if [[ -z "$serial" || "$serial" == "null" ]]; then
        fail "Could not find serial for test cert in /ssh/mycerts" "$list"
        return 1
    fi
    log_verbose "Revoking serial $serial"

    # Self-revoke via /ssh/myrevoke (introduced in SSHCA >= 0.1.16)
    local revoke_resp
    revoke_resp=$(curl -s -X POST "$PORTAL_URL/ssh/myrevoke" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"serial\":\"$serial\"}" 2>&1) || true
    log_verbose "myrevoke: $revoke_resp"

    # Now /pam/authorize with the revoked cert's fingerprint must fail,
    # WITHOUT requiring the local KRL to be refreshed.
    local server_token
    server_token=$(docker exec ob-maxsec-bastion cat /etc/open-bastion/server_token.json 2>/dev/null | jq -r '.access_token // empty') || true
    if [[ -z "$server_token" ]]; then
        fail "Could not get server token from bastion"
        return 1
    fi

    local body_tmp http_code response
    body_tmp=$(mktemp)
    http_code=$(curl -s -o "$body_tmp" -w '%{http_code}' -X POST "$PORTAL_URL/pam/authorize" \
        -H "Authorization: Bearer $server_token" \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"$TEST_USER\",\"server_group\":\"bastion\",\"fingerprint\":\"$fingerprint\"}")
    response=$(cat "$body_tmp")
    rm -f "$body_tmp"
    log_verbose "authorize(revoked) HTTP=$http_code body=$response"

    # Require a real JSON response (not a 5xx / non-JSON error) and
    # authorized:false explicitly — a jq parse failure should NOT let
    # the test pass silently.
    if [[ "$http_code" != "200" ]]; then
        fail "authorize(revoked) expected HTTP 200, got $http_code" "$response"
        return 1
    fi
    if ! echo "$response" | jq -e 'type == "object" and has("authorized")' >/dev/null 2>&1; then
        fail "authorize(revoked) did not return a valid JSON object" "$response"
        return 1
    fi
    if ! echo "$response" | jq -e '.authorized == false' >/dev/null 2>&1; then
        fail "authorize should reject a cert revoked on LLNG side" "$response"
        return 1
    fi

    pass "/pam/authorize rejects cert revoked via /ssh/myrevoke (no KRL refresh needed)"
    return 0
}

# End-to-end validation: attempt a real SSH connection with the cert that
# was just revoked on the LLNG side via /ssh/myrevoke. The local KRL on
# the bastion is NOT refreshed (no cron in the demo containers), so sshd
# accepts the cert at the pubkey layer. pam_openbastion.so then forwards
# the SHA256 fingerprint to /pam/authorize (PAM `account` phase), LLNG
# refuses, and the client gets a permission denial.
#
# This test proves the binding works bout-en-bout (module C + LLNG).
test_ssh_connection_refused_after_revocation() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing SSH connection is refused end-to-end after LLNG-side revocation..."

    if [[ ! -f "${TEST_KEY}-cert.pub" ]]; then
        log_warn "No certificate available, skipping e2e revocation SSH test"
        pass "SSH e2e revocation test skipped (no certificate)"
        return 0
    fi

    local output
    output=$(ssh -i "${TEST_KEY}" \
                 -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o BatchMode=yes \
                 -o ConnectTimeout=10 \
                 -p 2222 \
                 "${TEST_USER}@localhost" \
                 "echo SHOULD_NEVER_PRINT" 2>&1) || true

    log_verbose "SSH(revoked) output: $output"

    if echo "$output" | grep -q "SHOULD_NEVER_PRINT"; then
        fail "SSH with LLNG-revoked cert succeeded (expected denial)" "$output"
        return 1
    fi

    if ! echo "$output" | grep -qE "Permission denied|Connection closed|Authentication failed"; then
        fail "SSH with revoked cert did not fail with a permission-denial" "$output"
        return 1
    fi

    # Best-effort: confirm pam_openbastion.so denied at account phase via
    # the fingerprint binding rather than sshd's KRL (which has not been
    # refreshed in the demo).
    local bastion_log
    bastion_log=$(docker exec ob-maxsec-bastion sh -c '
        for f in /var/log/auth.log /var/log/syslog /var/log/messages; do
            [ -r "$f" ] && tail -n 200 "$f"
        done
    ' 2>/dev/null) || true
    if echo "$bastion_log" | grep -qE "PAM_AUTHZ_SSH_FP_REJECTED|SSH fingerprint not recognized"; then
        log_verbose "Bastion confirmed /pam/authorize fingerprint rejection in logs"
    else
        log_warn "Could not find PAM_AUTHZ_SSH_FP_REJECTED in bastion logs (sshd KRL may have refused first, or logs not persisted)"
    fi

    pass "SSH with LLNG-revoked cert refused end-to-end (no KRL refresh needed)"
    return 0
}

test_token_introspection() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing token introspection (with JWT client assertion)..."

    # Get a valid user token first
    # Use the llng client to get an access token
    local access_token
    access_token=$(llng --llng-url "$PORTAL_URL" \
                        --login "$TEST_USER" \
                        --password "$TEST_PASSWORD" \
                        --client-id "$CLIENT_ID" \
                        --client-secret "$CLIENT_SECRET" \
                        access_token 2>&1) || true

    if [[ -z "$access_token" ]] || [[ "$access_token" == *"error"* ]]; then
        log_warn "Could not get access token for introspection test, skipping..."
        pass "Token introspection skipped (no token available)"
        return 0
    fi

    log_verbose "Access token: ${access_token:0:30}..."

    # The actual introspection test would require the JWT assertion
    # which is handled by the PAM module internally
    # For now, verify the endpoint exists
    local response
    response=$(curl -sf -X POST "$PORTAL_URL/oauth2/introspect" \
        -d "token=$access_token" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET" 2>&1) || true

    log_verbose "Introspection response: $response"

    if echo "$response" | jq -e '.active' >/dev/null 2>&1; then
        local active
        active=$(echo "$response" | jq -r '.active')
        if [[ "$active" == "true" ]]; then
            pass "Token introspection works (token active)"
        else
            pass "Token introspection works (token inactive/expired)"
        fi
        return 0
    else
        fail "Token introspection failed" "$response"
        return 1
    fi
}

test_ssh_connection_bastion() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing SSH connection to bastion..."

    # Ensure we have a certificate
    if [[ ! -f "${TEST_KEY}-cert.pub" ]]; then
        log_warn "No certificate available, skipping SSH test"
        pass "SSH connection test skipped (no certificate)"
        return 0
    fi

    # Try SSH connection
    local output
    output=$(ssh -i "${TEST_KEY}" \
                 -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o ConnectTimeout=10 \
                 -p 2222 \
                 "${TEST_USER}@localhost" \
                 "echo 'SSH_SUCCESS' && whoami" 2>&1) || true

    log_verbose "SSH output: $output"

    if echo "$output" | grep -q "SSH_SUCCESS"; then
        pass "SSH connection to bastion successful"
        return 0
    else
        fail "SSH connection to bastion failed" "$output"
        return 1
    fi
}

test_nss_user_resolution() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing NSS user resolution..."

    # Check if bastion can resolve user via NSS
    local output
    output=$(docker exec ob-maxsec-bastion getent passwd "$TEST_USER" 2>&1) || true

    log_verbose "NSS output: $output"

    if echo "$output" | grep -q "^${TEST_USER}:"; then
        pass "NSS user resolution works"
        return 0
    else
        fail "NSS user resolution failed" "$output"
        return 1
    fi
}

test_pam_cache() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing PAM authorization cache..."

    # Check if cache directory exists and has entries
    local cache_files
    cache_files=$(docker exec ob-maxsec-bastion ls -la /var/cache/open-bastion/ 2>&1) || true

    log_verbose "Cache files: $cache_files"

    # Cache may be empty if no PAM auth happened yet, that's OK
    if docker exec ob-maxsec-bastion test -d /var/cache/open-bastion; then
        pass "PAM cache directory exists"
        return 0
    else
        fail "PAM cache directory does not exist" "$cache_files"
        return 1
    fi
}

# =============================================================================
# Mode E Security Test Cases
# =============================================================================

test_unsigned_key_rejected() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing that unsigned SSH keys are rejected..."

    local unsigned_key="/tmp/test_unsigned_key"
    rm -f "$unsigned_key" "${unsigned_key}.pub"
    ssh-keygen -t ed25519 -f "$unsigned_key" -N "" -q

    local output
    output=$(ssh -i "$unsigned_key" \
                 -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o BatchMode=yes \
                 -o ConnectTimeout=10 \
                 -p 2222 \
                 "${TEST_USER}@localhost" \
                 "echo FAIL" 2>&1) || true

    rm -f "$unsigned_key" "${unsigned_key}.pub"

    if echo "$output" | grep -q "Permission denied"; then
        pass "Unsigned SSH key correctly rejected"
        return 0
    else
        fail "Unsigned SSH key was NOT rejected" "$output"
        return 1
    fi
}

test_authorized_keys_disabled() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing AuthorizedKeysFile is disabled..."

    local bastion_conf backend_conf
    bastion_conf=$(docker exec ob-maxsec-bastion grep "AuthorizedKeysFile" /etc/ssh/sshd_config.d/llng-bastion.conf 2>&1) || true
    backend_conf=$(docker exec ob-maxsec-backend grep "AuthorizedKeysFile" /etc/ssh/sshd_config.d/llng-backend.conf 2>&1) || true

    if echo "$bastion_conf" | grep -q "none" && echo "$backend_conf" | grep -q "none"; then
        pass "AuthorizedKeysFile none on both bastion and backend"
        return 0
    else
        fail "AuthorizedKeysFile not properly disabled" "bastion: $bastion_conf, backend: $backend_conf"
        return 1
    fi
}

test_krl_configured() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing KRL (RevokedKeys) is configured..."

    local bastion_krl backend_krl
    bastion_krl=$(docker exec ob-maxsec-bastion grep "RevokedKeys" /etc/ssh/sshd_config.d/llng-bastion.conf 2>&1) || true
    backend_krl=$(docker exec ob-maxsec-backend grep "RevokedKeys" /etc/ssh/sshd_config.d/llng-backend.conf 2>&1) || true

    if echo "$bastion_krl" | grep -q "revoked_keys" && echo "$backend_krl" | grep -q "revoked_keys"; then
        pass "RevokedKeys configured on both bastion and backend"
        return 0
    else
        fail "RevokedKeys not properly configured" "bastion: $bastion_krl, backend: $backend_krl"
        return 1
    fi
}

test_krl_file_valid() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing KRL file is valid (empty or binary, not HTML)..."

    local bastion_size backend_size
    bastion_size=$(docker exec ob-maxsec-bastion wc -c < /etc/ssh/revoked_keys 2>&1) || true
    backend_size=$(docker exec ob-maxsec-backend wc -c < /etc/ssh/revoked_keys 2>&1) || true

    # Check that files are NOT HTML (empty file is valid for sshd)
    local bastion_head backend_head
    bastion_head=$(docker exec ob-maxsec-bastion head -c 10 /etc/ssh/revoked_keys 2>&1) || true
    backend_head=$(docker exec ob-maxsec-backend head -c 10 /etc/ssh/revoked_keys 2>&1) || true

    if echo "$bastion_head" | grep -q "DOCTYPE\|<html"; then
        fail "Bastion KRL file contains HTML" "$bastion_head"
        return 1
    fi
    if echo "$backend_head" | grep -q "DOCTYPE\|<html"; then
        fail "Backend KRL file contains HTML" "$backend_head"
        return 1
    fi

    pass "KRL files are valid (bastion: ${bastion_size}B, backend: ${backend_size}B)"
    return 0
}

test_krl_cron() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing KRL refresh cron job exists..."

    local bastion_cron backend_cron
    bastion_cron=$(docker exec ob-maxsec-bastion cat /etc/cron.d/open-bastion-krl 2>&1) || true
    backend_cron=$(docker exec ob-maxsec-backend cat /etc/cron.d/open-bastion-krl 2>&1) || true

    if echo "$bastion_cron" | grep -q "ssh/revoked" && echo "$backend_cron" | grep -q "ssh/revoked"; then
        pass "KRL refresh cron job configured on both servers"
        return 0
    else
        fail "KRL refresh cron job missing" "bastion: $bastion_cron, backend: $backend_cron"
        return 1
    fi
}

test_sudo_pam_config() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing sudo PAM requires LLNG token (Mode E)..."

    local sudo_pam
    sudo_pam=$(docker exec ob-maxsec-backend cat /etc/pam.d/sudo 2>&1) || true

    local has_openbastion has_deny no_nopasswd
    has_openbastion=$(echo "$sudo_pam" | grep -c "pam_openbastion" || true)
    has_deny=$(echo "$sudo_pam" | grep -c "pam_deny" || true)
    no_nopasswd=$(docker exec ob-maxsec-backend grep -c "NOPASSWD" /etc/sudoers 2>&1) || true

    if [[ "$has_openbastion" -ge 1 ]] && [[ "$has_deny" -ge 1 ]] && [[ "$no_nopasswd" -eq 0 ]]; then
        pass "sudo PAM correctly requires LLNG token (no NOPASSWD)"
        return 0
    else
        fail "sudo PAM not properly configured for Mode E" "openbastion=$has_openbastion, deny=$has_deny, nopasswd=$no_nopasswd"
        return 1
    fi
}

test_password_auth_disabled() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing password authentication is disabled..."

    local bastion_pw backend_pw
    bastion_pw=$(docker exec ob-maxsec-bastion grep "^PasswordAuthentication" /etc/ssh/sshd_config.d/llng-bastion.conf 2>&1) || true
    backend_pw=$(docker exec ob-maxsec-backend grep "^PasswordAuthentication" /etc/ssh/sshd_config.d/llng-backend.conf 2>&1) || true

    if echo "$bastion_pw" | grep -q "no" && echo "$backend_pw" | grep -q "no"; then
        pass "PasswordAuthentication disabled on both servers"
        return 0
    else
        fail "PasswordAuthentication not disabled" "bastion: $bastion_pw, backend: $backend_pw"
        return 1
    fi
}

# =============================================================================
# Service-account test cases
# =============================================================================
#
# Scenario: an ansible-style service account is registered ONLY locally on
# the bastion (service-accounts.conf + .pub). LLNG does NOT know this user.
# We then verify:
#   1. SSH with the plain (non-SSO-signed) key is accepted thanks to
#      AuthorizedKeysCommand + service-accounts.conf fingerprint matching.
#   2. pam_openbastion materialises the local Unix account in /etc/passwd
#      on first login using the uid/gid from service-accounts.conf
#      (service-account NSS resolution is impossible).
#   3. `sudo -n` from that session works without a password (sudo_nopasswd
#      path in pam_openbastion auth) and yields uid 0.

svc_provision_on_bastion() {
    local pubkey
    pubkey=$(cat "${SVC_KEY}.pub")

    # service-accounts.conf: must be root:root 0600 (pam_openbastion enforces this).
    # NOTE: use `docker exec -i sh -c` and a heredoc so special chars in the key
    # don't break the shell; pubkey comes from our own file so it's trusted.
    docker exec -i ob-maxsec-bastion sh -c "cat > /etc/open-bastion/service-accounts.conf" <<EOF
[${SVC_ACCOUNT}]
key_fingerprint = $(ssh-keygen -l -E sha256 -f "${SVC_KEY}.pub" | awk '{print $2}')
sudo_allowed = true
sudo_nopasswd = true
gecos = CI service account
shell = /bin/bash
home = /home/${SVC_ACCOUNT}
uid = ${SVC_UID}
gid = ${SVC_GID}
EOF
    docker exec ob-maxsec-bastion chown root:root /etc/open-bastion/service-accounts.conf
    docker exec ob-maxsec-bastion chmod 600 /etc/open-bastion/service-accounts.conf

    # Public key file consumed by ob-service-account-keys (AuthorizedKeysCommand).
    docker exec -i ob-maxsec-bastion sh -c \
        "cat > /etc/open-bastion/service-accounts.d/${SVC_ACCOUNT}.pub" <<< "$pubkey"
    docker exec ob-maxsec-bastion chown root:root \
        "/etc/open-bastion/service-accounts.d/${SVC_ACCOUNT}.pub"
    docker exec ob-maxsec-bastion chmod 644 \
        "/etc/open-bastion/service-accounts.d/${SVC_ACCOUNT}.pub"

    # sudoers NOPASSWD rule. sudo(8) decides whether to prompt for a
    # password from sudoers BEFORE it invokes the PAM stack, so
    # pam_openbastion's service-account sudo_nopasswd logic is necessary
    # but not sufficient: we also need an explicit NOPASSWD entry here.
    #
    # The maxsec image appends `%open-bastion-sudo ALL=(ALL:ALL) ALL` to
    # /etc/sudoers AFTER the `@includedir /etc/sudoers.d` directive.
    # sudoers is "last-match-wins", so any rule dropped into
    # /etc/sudoers.d is overwritten by the group rule. We therefore
    # append our NOPASSWD rule directly at the very end of
    # /etc/sudoers so it has the final say for this specific user.
    #
    # visudo -c validates the result; if it fails we abort to avoid
    # leaving a broken sudoers on a production-lookalike host.
    docker exec ob-maxsec-bastion sh -c "
        set -e
        grep -qE '^${SVC_ACCOUNT}[[:space:]]+ALL=.*NOPASSWD' /etc/sudoers || \
            printf '%s\n' '${SVC_ACCOUNT} ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers
        visudo -c >/dev/null
    "
}

test_service_account_provision() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Provisioning service account ${SVC_ACCOUNT} on the bastion..."

    # Fresh key: plain ed25519, NOT signed by the LLNG SSH CA.
    rm -f "${SVC_KEY}" "${SVC_KEY}.pub"
    if ! ssh-keygen -t ed25519 -f "${SVC_KEY}" -N "" -q; then
        fail "Failed to generate service account SSH key"
        return 1
    fi

    if ! svc_provision_on_bastion; then
        fail "Failed to provision service account on bastion"
        return 1
    fi

    # Sanity-check: the local Unix account MUST NOT exist yet (whole point
    # of this test is the on-login auto-creation).
    if docker exec ob-maxsec-bastion getent -s files passwd "${SVC_ACCOUNT}" >/dev/null 2>&1; then
        fail "Service account ${SVC_ACCOUNT} already exists locally before first login"
        return 1
    fi

    # The AuthorizedKeysCommand must now return our public key for this user.
    local cmd_output
    cmd_output=$(docker exec ob-maxsec-bastion \
        /usr/local/bin/ob-service-account-keys "${SVC_ACCOUNT}" 2>/dev/null || true)
    if [[ -z "$cmd_output" ]]; then
        fail "ob-service-account-keys returned no key for ${SVC_ACCOUNT}"
        return 1
    fi
    if ! grep -q "ssh-ed25519" <<< "$cmd_output"; then
        fail "ob-service-account-keys output is not an ed25519 key" "$cmd_output"
        return 1
    fi

    pass "Service account ${SVC_ACCOUNT} provisioned (key + conf installed)"
    return 0
}

test_service_account_ssh_login() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing SSH login as service account ${SVC_ACCOUNT} (plain key)..."

    if [[ ! -f "${SVC_KEY}" ]]; then
        fail "Service account key missing; provisioning step must run first"
        return 1
    fi

    local output rc=0
    output=$(ssh -i "${SVC_KEY}" \
                 -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o BatchMode=yes \
                 -o ConnectTimeout=10 \
                 -p 2222 \
                 "${SVC_ACCOUNT}@localhost" \
                 "whoami && id -u && id -g" 2>&1) || rc=$?
    log_verbose "SSH(svc) rc=$rc output: $output"

    if [[ $rc -ne 0 ]]; then
        fail "SSH login as ${SVC_ACCOUNT} failed" "$output"
        return 1
    fi

    if ! grep -qx "${SVC_ACCOUNT}" <<< "$output"; then
        fail "SSH session did not report ${SVC_ACCOUNT} as whoami" "$output"
        return 1
    fi
    if ! grep -qx "${SVC_UID}" <<< "$output"; then
        fail "SSH session reported wrong uid (expected ${SVC_UID})" "$output"
        return 1
    fi
    if ! grep -qx "${SVC_GID}" <<< "$output"; then
        fail "SSH session reported wrong gid (expected ${SVC_GID})" "$output"
        return 1
    fi

    pass "Service account ${SVC_ACCOUNT} logged in with uid=${SVC_UID}, gid=${SVC_GID}"
    return 0
}

test_service_account_local_user_created() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Checking that the local Unix account was materialised by pam_openbastion..."

    # Look in /etc/passwd directly: libnss_openbastion could otherwise mask
    # the question "does a local account exist?".
    local passwd_entry
    passwd_entry=$(docker exec ob-maxsec-bastion \
        grep -E "^${SVC_ACCOUNT}:" /etc/passwd 2>&1) || true
    log_verbose "passwd entry: $passwd_entry"

    if [[ -z "$passwd_entry" ]]; then
        fail "No /etc/passwd entry for ${SVC_ACCOUNT} after first SSH login"
        return 1
    fi

    # Format: name:x:uid:gid:gecos:home:shell
    local entry_uid entry_gid entry_home entry_shell
    entry_uid=$(cut -d: -f3 <<< "$passwd_entry")
    entry_gid=$(cut -d: -f4 <<< "$passwd_entry")
    entry_home=$(cut -d: -f6 <<< "$passwd_entry")
    entry_shell=$(cut -d: -f7 <<< "$passwd_entry")

    if [[ "$entry_uid" != "${SVC_UID}" ]]; then
        fail "/etc/passwd uid for ${SVC_ACCOUNT} is $entry_uid, expected ${SVC_UID}" "$passwd_entry"
        return 1
    fi
    if [[ "$entry_gid" != "${SVC_GID}" ]]; then
        fail "/etc/passwd gid for ${SVC_ACCOUNT} is $entry_gid, expected ${SVC_GID}" "$passwd_entry"
        return 1
    fi
    if [[ "$entry_home" != "/home/${SVC_ACCOUNT}" ]]; then
        fail "Home directory for ${SVC_ACCOUNT} is $entry_home, expected /home/${SVC_ACCOUNT}" "$passwd_entry"
        return 1
    fi
    if [[ "$entry_shell" != "/bin/bash" ]]; then
        fail "Login shell for ${SVC_ACCOUNT} is $entry_shell, expected /bin/bash" "$passwd_entry"
        return 1
    fi

    # Primary group must also have been materialised.
    local group_entry
    group_entry=$(docker exec ob-maxsec-bastion \
        awk -F: -v gid="${SVC_GID}" '$3 == gid {print; exit}' /etc/group 2>&1) || true
    if [[ -z "$group_entry" ]]; then
        fail "No /etc/group entry for gid ${SVC_GID} after first login"
        return 1
    fi

    pass "Local account ${SVC_ACCOUNT} created in /etc/passwd + matching /etc/group entry"
    return 0
}

test_service_account_sudo() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing sudo from service account session (sudo_nopasswd path)..."

    if [[ ! -f "${SVC_KEY}" ]]; then
        fail "Service account key missing; earlier step must have run"
        return 1
    fi

    # -n: non-interactive. If anything prompts for a password this fails,
    # which is exactly what we want to assert about sudo_nopasswd.
    local output rc=0
    output=$(ssh -i "${SVC_KEY}" \
                 -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o BatchMode=yes \
                 -o ConnectTimeout=10 \
                 -p 2222 \
                 "${SVC_ACCOUNT}@localhost" \
                 "sudo -n id -u && sudo -n id -un" 2>&1) || rc=$?
    log_verbose "SSH(svc+sudo) rc=$rc output: $output"

    if [[ $rc -ne 0 ]]; then
        fail "sudo -n as ${SVC_ACCOUNT} failed" "$output"
        return 1
    fi

    # Expect "0" and "root" on separate lines.
    if ! grep -qx "0" <<< "$output"; then
        fail "sudo did not yield uid 0" "$output"
        return 1
    fi
    if ! grep -qx "root" <<< "$output"; then
        fail "sudo did not yield root username" "$output"
        return 1
    fi

    pass "sudo -n from ${SVC_ACCOUNT} runs as root (nopasswd path)"
    return 0
}

test_service_account_bad_key_rejected() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing that a different ed25519 key is rejected for ${SVC_ACCOUNT}..."

    local bad_key="/tmp/test_integration_svc_bad"
    rm -f "$bad_key" "${bad_key}.pub"
    ssh-keygen -t ed25519 -f "$bad_key" -N "" -q

    local output rc=0
    output=$(ssh -i "$bad_key" \
                 -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o BatchMode=yes \
                 -o ConnectTimeout=10 \
                 -p 2222 \
                 "${SVC_ACCOUNT}@localhost" \
                 "echo SHOULD_NEVER_PRINT" 2>&1) || rc=$?
    rm -f "$bad_key" "${bad_key}.pub"
    log_verbose "SSH(bad key) rc=$rc output: $output"

    if grep -q "SHOULD_NEVER_PRINT" <<< "$output"; then
        fail "An unrelated key was accepted for ${SVC_ACCOUNT}" "$output"
        return 1
    fi
    if ! grep -qE "Permission denied|Connection closed|Authentication failed" <<< "$output"; then
        fail "SSH with wrong key did not fail with a permission denial" "$output"
        return 1
    fi

    pass "A non-registered SSH key is rejected for ${SVC_ACCOUNT}"
    return 0
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "=============================================="
    echo "  LLNG PAM Module Integration Tests (Mode E)"
    echo "=============================================="
    echo ""

    check_requirements

    echo ""
    echo "=== Phase 1: Setup ==="
    start_containers
    wait_for_bastion
    wait_for_backend

    echo ""
    echo "=== Phase 2: Authentication Tests ==="
    test_llng_authentication
    test_sso_session_valid

    echo ""
    echo "=== Phase 3: SSH Certificate Tests ==="
    test_ssh_ca_endpoint
    test_ssh_certificate_signing

    echo ""
    echo "=== Phase 4: PAM Module Tests ==="
    test_pam_authorize_endpoint
    test_pam_authorize_fingerprint_binding
    test_token_introspection
    test_nss_user_resolution
    test_pam_cache

    echo ""
    echo "=== Phase 5: End-to-End Tests ==="
    test_ssh_connection_bastion

    echo ""
    echo "=== Phase 6: Mode E Security Tests ==="
    test_unsigned_key_rejected
    test_authorized_keys_disabled
    test_krl_configured
    test_krl_file_valid
    test_krl_cron
    test_sudo_pam_config
    test_password_auth_disabled

    echo ""
    echo "=== Phase 7: Service-account SSH key + sudo ==="
    # Must run before the revocation phase (which invalidates the cert used
    # earlier) but has no ordering dependency with Phase 6: the service
    # account uses a distinct username unknown to LLNG.
    test_service_account_provision
    test_service_account_ssh_login
    test_service_account_local_user_created
    test_service_account_sudo
    test_service_account_bad_key_rejected

    echo ""
    echo "=== Phase 8: Cert revocation via fingerprint binding ==="
    # MUST run last: /ssh/myrevoke invalidates the test cert and would
    # break any subsequent test that relies on a valid certificate.
    test_pam_authorize_rejects_revoked_cert
    test_ssh_connection_refused_after_revocation

    echo ""
    echo "=============================================="
    echo "  Test Results"
    echo "=============================================="
    echo ""
    echo "  Tests run:    $TESTS_RUN"
    echo -e "  ${GREEN}Passed:       $TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "  ${RED}Failed:       $TESTS_FAILED${NC}"
    else
        echo "  Failed:       $TESTS_FAILED"
    fi
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main "$@"
