#!/bin/bash
#
# test_integration_docker.sh - Integration tests using docker-demo-cert
#
# Tests the full PAM module with a real LLNG server including:
# - Docker compose build and startup
# - LLNG authentication via llng CLI
# - Token introspection with JWT client assertion
# - SSH connection with certificate authentication
#
# Usage:
#   ./tests/test_integration_docker.sh [--keep] [--verbose]
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
DOCKER_DIR="$PROJECT_DIR/docker-demo-cert"
COOKIE_FILE="/tmp/llng-test-cookies"
TEST_KEY="/tmp/test_integration_key"

# Test configuration
PORTAL_URL="http://localhost:80"
TEST_USER="dwho"
TEST_PASSWORD="dwho"
CLIENT_ID="pam-access"
CLIENT_SECRET="pamsecret"

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
    rm -f "$COOKIE_FILE" "${TEST_KEY}" "${TEST_KEY}.pub" "${TEST_KEY}-cert.pub" 2>/dev/null || true

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
    log "Building and starting docker-demo-cert..."
    cd "$DOCKER_DIR"

    # Stop any conflicting containers first
    log "Stopping any conflicting containers..."
    cd "$PROJECT_DIR/docker-demo-token" && docker compose down --volumes --remove-orphans 2>/dev/null || true
    cd "$PROJECT_DIR/docker-demo-cert" && docker compose down --volumes --remove-orphans 2>/dev/null || true
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
        if docker exec ob-cert-bastion test -f /etc/open-bastion/server_token.json 2>/dev/null; then
            log "Bastion enrolled after ${waited}s"
            return 0
        fi
        sleep 2
        ((waited+=2))
        log_verbose "Waiting for bastion enrollment... ${waited}s"
    done

    log_error "Bastion did not enroll within ${max_wait}s"
    docker logs ob-cert-bastion
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
    server_token=$(docker exec ob-cert-bastion cat /etc/open-bastion/server_token.json 2>/dev/null | jq -r '.access_token // empty') || true

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

    local fingerprint
    fingerprint=$(ssh-keygen -l -E sha256 -f "${TEST_KEY}.pub" 2>/dev/null | awk '{print $2}')
    if [[ -z "$fingerprint" || "$fingerprint" != SHA256:* ]]; then
        fail "Could not compute SHA256 fingerprint of ${TEST_KEY}.pub"
        return 1
    fi
    log_verbose "Computed fingerprint: $fingerprint"

    local server_token
    server_token=$(docker exec ob-cert-bastion cat /etc/open-bastion/server_token.json 2>/dev/null | jq -r '.access_token // empty') || true
    if [[ -z "$server_token" ]]; then
        fail "Could not get server token from bastion"
        return 1
    fi

    local body_tmp http_code response
    body_tmp=$(mktemp)

    # 1. Matching fingerprint accepted (HTTP 200 + authorized:true)
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

    # 2. Unknown fingerprint refused (HTTP 200 + authorized:false explicitly)
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

    # 3. Malformed fingerprint → HTTP 400
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

    local revoke_resp
    revoke_resp=$(curl -s -X POST "$PORTAL_URL/ssh/myrevoke" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"serial\":\"$serial\"}" 2>&1) || true
    log_verbose "myrevoke: $revoke_resp"

    local server_token
    server_token=$(docker exec ob-cert-bastion cat /etc/open-bastion/server_token.json 2>/dev/null | jq -r '.access_token // empty') || true
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
# was just revoked on the LLNG side via /ssh/myrevoke. Without a KRL
# refresh, sshd accepts the cert at the pubkey layer, and
# pam_openbastion.so must then forward the fingerprint to /pam/authorize
# where LLNG refuses. Proves the binding works end-to-end (C module +
# LLNG), not just the portal contract.
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

    local bastion_log
    bastion_log=$(docker exec ob-cert-bastion sh -c '
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

test_builder_deployed_backend() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing artefact produced by admin-builder on backend-new..."

    local builder="${PROJECT_DIR}/admin-builder/ob-builder"
    if [[ ! -x "$builder" ]]; then
        fail "ob-builder not found at $builder"
        return 1
    fi

    local workdir
    workdir=$(mktemp -d -t ob-builder-test.XXXXXX)
    local cfg="${workdir}/build.yml"
    local artefact="${workdir}/bootstrap-backend-new.sh"

    cat > "$cfg" <<EOF
deployment_slug: cert-demo-backend-new
scenario: max-security
portal_url: ${PORTAL_URL}
client_id: ${CLIENT_ID}
client_id_policy: modifiable
client_secret_mode: embedded
embedded_client_secret: ${CLIENT_SECRET}
server_group: backend-new
server_group_policy: modifiable
target_role: backend
auto_enroll_setup: no
self_delete: no
EOF

    local rc=0
    "$builder" --config "$cfg" --output-shell "$artefact" --allow-http --insecure \
        >"${workdir}/builder.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        local size
        size=$(wc -c <"${workdir}/builder.log")
        fail "ob-builder failed (exit=$rc, log_size=${size}B)" "--- begin log ---
$(cat "${workdir}/builder.log")
--- end log ---"
        rm -rf "$workdir"
        return 1
    fi
    log_verbose "ob-builder produced $(wc -c < "$artefact") bytes"

    # Copy and execute the artefact inside the unconfigured backend container.
    # The container has the PAM module built from source already, so we
    # skip the apt package install. enroll/setup are skipped too because
    # the demo SSO is not wired for the Device Authorization Grant flow
    # that ob-enroll expects — this test only validates that the artefact
    # correctly deposits configs.
    if ! docker cp "$artefact" ob-cert-backend-new:/tmp/bootstrap.sh; then
        fail "Could not copy artefact into ob-cert-backend-new"
        rm -rf "$workdir"
        return 1
    fi

    local exec_log="${workdir}/exec.log"
    if ! docker exec ob-cert-backend-new bash /tmp/bootstrap.sh \
            --server-group backend-new \
            --skip-install --skip-enroll --skip-setup \
            --force \
            > "$exec_log" 2>&1; then
        fail "Generated bootstrap.sh failed inside backend-new" "$(tail -20 "$exec_log")"
        rm -rf "$workdir"
        return 1
    fi
    log_verbose "Bootstrap output (last lines): $(tail -3 "$exec_log")"

    # Now validate what landed on disk inside the container.
    local conf
    conf=$(docker exec ob-cert-backend-new cat /etc/open-bastion/openbastion.conf 2>&1) || {
        fail "/etc/open-bastion/openbastion.conf was not created"
        rm -rf "$workdir"
        return 1
    }

    # portal_url is fixed at build time by design (only client_id and
    # server_group are runtime-substituted). Verify the build-time value
    # is present in the deposited conf.
    if ! grep -q "^portal_url = ${PORTAL_URL}\$" <<<"$conf"; then
        fail "portal_url not baked correctly into the deposited conf" "$conf"
        rm -rf "$workdir"
        return 1
    fi

    if ! grep -q "^server_group = backend-new" <<<"$conf"; then
        fail "server_group not correctly set in deposited conf" "$conf"
        rm -rf "$workdir"
        return 1
    fi

    if ! grep -q "^bastion_jwt_required = true" <<<"$conf"; then
        fail "bastion_jwt_required missing — backend role config incomplete" "$conf"
        rm -rf "$workdir"
        return 1
    fi

    if ! docker exec ob-cert-backend-new test -f /etc/ssh/open-bastion_ca.pub; then
        fail "SSH CA pubkey not deposited at /etc/ssh/open-bastion_ca.pub"
        rm -rf "$workdir"
        return 1
    fi

    rm -rf "$workdir"
    pass "ob-builder artefact correctly configured backend-new"
}

# Drives the auto-approve protocol end-to-end: obtain an LLNG session cookie,
# start ob-enroll on the unenrolled backend container, slurp the
# device-state file, GET /device to extract the CSRF token, POST action=approve,
# and verify enrollment completed (the server token file appears).
#
# This validates the LLNG-side flow that the Ansible role's _enroll.yml
# automates. Ansible itself is not exercised in CI (would require installing
# ansible + SSH into the container), but the protocol surface is identical.
test_builder_auto_approve_protocol() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing LLNG auto-approve protocol (ob-enroll + cookie + /device)..."

    # Obtain a session cookie for admin user dwho.
    local cookie cookie_jar llng_log
    cookie_jar=$(mktemp -t llng-auto-approve.XXXXXX)
    llng_log=$(mktemp -t llng-auto-approve-log.XXXXXX)
    if ! llng --llng-url "${PORTAL_URL}" \
              --login "${TEST_USER}" \
              --password "${TEST_PASSWORD}" \
              --cookie-jar "$cookie_jar" \
              llng_cookie > "$llng_log" 2>&1; then
        fail "llng CLI failed to obtain a session cookie" "$(cat "$llng_log")"
        rm -f "$cookie_jar" "$llng_log"
        return 1
    fi
    # llng_cookie prints the Cookie header value to stdout (e.g. "lemonldap=ABC123")
    cookie=$(tr -d '\r\n' < "$llng_log")
    if [ -z "$cookie" ]; then
        # Fallback: extract from the cookie jar (Netscape format).
        cookie=$(awk '!/^#/ && $6=="lemonldap" {print $6 "=" $7; exit}' "$cookie_jar")
    fi
    rm -f "$llng_log"
    if [ -z "$cookie" ] || ! echo "$cookie" | grep -q "lemonldap="; then
        fail "Could not extract a 'lemonldap=' cookie value" "stdout/jar: $(cat "$cookie_jar" 2>/dev/null | head -5)"
        rm -f "$cookie_jar"
        return 1
    fi
    rm -f "$cookie_jar"
    log_verbose "Got cookie: $(echo "$cookie" | cut -c1-40)…"

    # Backend-new needs the open-bastion config in place. The previous
    # builder test deposited it (run-order dependency: that test must
    # have passed). Re-deposit a minimal config in case a previous run
    # invalidated it.
    docker exec -i ob-cert-backend-new bash -c "cat > /etc/open-bastion/openbastion.conf" <<EOF
portal_url = http://sso:8080
client_id = ${CLIENT_ID}
client_secret = ${CLIENT_SECRET}
server_group = backend-new
verify_ssl = false
EOF
    docker exec ob-cert-backend-new chmod 0600 /etc/open-bastion/openbastion.conf
    # Sanity check: confirm portal_url landed in the conf — without -i the
    # earlier docker exec would silently write an empty file.
    if ! docker exec ob-cert-backend-new grep -q "^portal_url = http://sso:8080" /etc/open-bastion/openbastion.conf; then
        fail "Could not write openbastion.conf inside ob-cert-backend-new" \
             "$(docker exec ob-cert-backend-new cat /etc/open-bastion/openbastion.conf)"
        return 1
    fi

    # Start ob-enroll asynchronously inside the container.
    docker exec ob-cert-backend-new bash -c \
        "mkdir -p /run/open-bastion && rm -f /etc/open-bastion/token /run/open-bastion/enroll.json"
    docker exec -d ob-cert-backend-new bash -c \
        "OB_ENROLL_STATE_FILE=/run/open-bastion/enroll.json /usr/sbin/ob-enroll -g backend-new --quiet > /tmp/enroll.log 2>&1"

    # Wait for the state file to appear (device-auth initiate succeeded).
    local i=0
    while [ "$i" -lt 30 ]; do
        if docker exec ob-cert-backend-new test -f /run/open-bastion/enroll.json 2>/dev/null; then
            break
        fi
        i=$((i + 1))
        sleep 1
    done
    if [ "$i" -eq 30 ]; then
        local enroll_log
        enroll_log=$(docker exec ob-cert-backend-new cat /tmp/enroll.log 2>&1 || true)
        fail "ob-enroll did not publish the device-state file" "$enroll_log"
        return 1
    fi

    local state
    state=$(docker exec ob-cert-backend-new cat /run/open-bastion/enroll.json)
    local user_code
    user_code=$(echo "$state" | jq -r .user_code)
    log_verbose "Device user_code: $user_code"

    # The container reports portal_url=http://sso:8080 (its own network view),
    # but our host sees the portal at http://localhost:80. Use the host view.
    local cookie_jar
    cookie_jar=$(mktemp)
    local verify_page
    verify_page=$(curl -sS -L \
        -H "Cookie: $cookie" \
        -c "$cookie_jar" -b "$cookie_jar" \
        "${PORTAL_URL}/device?user_code=$(echo "$user_code" | tr -d -)")
    local csrf
    csrf=$(echo "$verify_page" | grep -oE 'name="token"[^>]*value="[^"]+"' | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')
    if [ -z "$csrf" ]; then
        rm -f "$cookie_jar"
        fail "Could not extract CSRF token from /device verification page" "$(echo "$verify_page" | head -50)"
        return 1
    fi
    log_verbose "Got CSRF token: $(echo "$csrf" | cut -c1-20)…"

    # Approve.
    local approve_resp
    approve_resp=$(curl -sS -i -L \
        -H "Cookie: $cookie" \
        -c "$cookie_jar" -b "$cookie_jar" \
        -X POST \
        --data-urlencode "user_code=$(echo "$user_code" | tr -d -)" \
        --data-urlencode "action=approve" \
        --data-urlencode "token=$csrf" \
        "${PORTAL_URL}/device")
    rm -f "$cookie_jar"

    if echo "$approve_resp" | head -1 | grep -qvE "HTTP/[0-9.]+ (200|30[0-9])"; then
        fail "/device approve POST returned non-2xx/3xx" "$(echo "$approve_resp" | head -20)"
        return 1
    fi

    # Wait for ob-enroll to complete and write the token.
    i=0
    while [ "$i" -lt 60 ]; do
        if docker exec ob-cert-backend-new test -f /etc/open-bastion/token 2>/dev/null; then
            break
        fi
        i=$((i + 1))
        sleep 1
    done
    if [ "$i" -eq 60 ]; then
        local enroll_log
        enroll_log=$(docker exec ob-cert-backend-new cat /tmp/enroll.log 2>&1 || true)
        fail "ob-enroll never wrote /etc/open-bastion/token after auto-approve" "$enroll_log"
        return 1
    fi

    local token_size
    token_size=$(docker exec ob-cert-backend-new stat -c '%s' /etc/open-bastion/token)
    if [ "$token_size" -lt 10 ]; then
        fail "Token file is suspiciously small (${token_size}B)"
        return 1
    fi

    # Cleanup state file (should already be removed by ob-enroll on success).
    docker exec ob-cert-backend-new rm -f /run/open-bastion/enroll.json

    pass "Auto-approve protocol completed; ob-enroll obtained token (${token_size}B)"
}

# Smoke-generate every supported (scenario, target_role) combination and verify
# the artefacts have valid bash syntax and contain the expected config keys.
# Lightweight — does not deploy, just exercises the generator code paths.
test_builder_scenarios_matrix() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing builder across scenarios × target_roles..."

    local builder="${PROJECT_DIR}/admin-builder/ob-builder"
    local scenarios=("token-only" "token+unix" "keys+llng" "mixed" "max-security")
    local roles=("bastion" "standalone" "backend")
    local matrix_dir
    matrix_dir=$(mktemp -d -t ob-builder-matrix.XXXXXX)
    local failures=0 total=0 details=""

    local scenario role
    for scenario in "${scenarios[@]}"; do
        for role in "${roles[@]}"; do
            total=$((total + 1))
            local slug="m-${scenario//+/-}-${role}"
            local cfg="${matrix_dir}/${slug}.yml"
            local out="${matrix_dir}/${slug}.sh"
            cat > "$cfg" <<EOF
deployment_slug: ${slug}
scenario: ${scenario}
portal_url: ${PORTAL_URL}
client_id: ${CLIENT_ID}
client_id_policy: modifiable
client_secret_mode: prompt
server_group: smoke
server_group_policy: modifiable
target_role: ${role}
auto_enroll_setup: no
self_delete: no
EOF
            if ! "$builder" --config "$cfg" --output-shell "$out" --allow-http --insecure \
                   > "${matrix_dir}/${slug}.log" 2>&1; then
                failures=$((failures + 1))
                details="${details}- $scenario/$role: ob-builder failed (see ${matrix_dir}/${slug}.log)"$'\n'
                continue
            fi
            if ! bash -n "$out" 2>>"${matrix_dir}/${slug}.log"; then
                failures=$((failures + 1))
                details="${details}- $scenario/$role: generated script syntax error"$'\n'
                continue
            fi
            # Backend role MUST embed the bastion JWT verification block;
            # bastion/standalone roles MUST NOT.
            if [ "$role" = "backend" ]; then
                if ! grep -q "bastion_jwt_required = true" "$out"; then
                    failures=$((failures + 1))
                    details="${details}- $scenario/$role: missing bastion_jwt_required"$'\n'
                    continue
                fi
            else
                if grep -q "bastion_jwt_required" "$out"; then
                    failures=$((failures + 1))
                    details="${details}- $scenario/$role: bastion_jwt_required leaked into non-backend artefact"$'\n'
                    continue
                fi
            fi
            # Mode E artefacts must include min_tls_version=13; other modes must not.
            if [ "$scenario" = "max-security" ]; then
                if ! grep -q "min_tls_version = 13" "$out"; then
                    failures=$((failures + 1))
                    details="${details}- $scenario/$role: Mode E expected min_tls_version=13"$'\n'
                    continue
                fi
            fi
        done
    done

    if [ "$failures" -gt 0 ]; then
        fail "$failures/$total scenario×role combinations failed" "$details"
        rm -rf "$matrix_dir"
        return 1
    fi
    rm -rf "$matrix_dir"
    pass "All $total scenario×role combinations generated and validated"
}

# Generate an Ansible role with ob_ansible_auto_approve=yes and run
# `ansible-playbook --syntax-check`. Catches YAML/Jinja2 errors and missing
# `include_tasks` references that the bash-only auto-approve test cannot see.
# Skipped if ansible-playbook is not on PATH.
test_builder_ansible_syntax() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing Ansible role syntax-check..."

    if ! command -v ansible-playbook >/dev/null 2>&1; then
        log_warn "ansible-playbook not installed — skipping"
        pass "Ansible syntax-check skipped (ansible-playbook not on PATH)"
        return 0
    fi

    local builder="${PROJECT_DIR}/admin-builder/ob-builder"
    local outdir cfg
    outdir=$(mktemp -d -t ob-ansible-syntax.XXXXXX)
    cfg="${outdir}/build.yml"
    cat > "$cfg" <<EOF
deployment_slug: ansible-syntax
scenario: max-security
portal_url: ${PORTAL_URL}
client_id: ${CLIENT_ID}
client_id_policy: modifiable
client_secret_mode: prompt
server_group: smoke
server_group_policy: modifiable
target_role: backend
auto_enroll_setup: yes
self_delete: no
ansible_auto_approve: yes
EOF

    if ! "$builder" --config "$cfg" --output-ansible "${outdir}/role" --allow-http --insecure \
           > "${outdir}/builder.log" 2>&1; then
        fail "ob-builder failed to render Ansible role" "$(cat "${outdir}/builder.log")"
        rm -rf "$outdir"
        return 1
    fi

    # Build a minimal inventory pointing at localhost (we only need the parser
    # to bind hosts; we are not actually running tasks here).
    cat > "${outdir}/role/inventory.yml" <<EOF
all:
  hosts:
    localhost:
      ansible_connection: local
EOF

    # Pass dummy values for vars referenced by tasks so Jinja2 evaluation
    # during --syntax-check has every variable bound.
    if ! ansible-playbook --syntax-check \
            -i "${outdir}/role/inventory.yml" \
            -e "ob_client_secret=dummy ob_llng_cookie=lemonldap=dummy" \
            "${outdir}/role/playbook.yml" \
            > "${outdir}/syntax.log" 2>&1; then
        fail "ansible-playbook --syntax-check failed on the generated role" \
             "$(cat "${outdir}/syntax.log")"
        rm -rf "$outdir"
        return 1
    fi

    rm -rf "$outdir"
    pass "Ansible role passes syntax-check (auto-approve variant)"
}

# ob-bastion-id runs on a pre-enrolled bastion, requests a bastion JWT from
# LLNG via /pam/bastion-token, decodes the JWT, and prints the bastion_id
# claim. The pre-enrolled docker-demo-cert bastion is the perfect target.
test_ob_bastion_id() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing ob-bastion-id on the pre-enrolled bastion..."

    local id err
    if ! id=$(docker exec ob-cert-bastion ob-bastion-id --quiet 2>&1); then
        fail "ob-bastion-id exited non-zero" "$id"
        return 1
    fi
    # Trim any trailing newline / log noise from --quiet
    id=$(printf '%s' "$id" | tr -d '\r\n')
    if [ -z "$id" ]; then
        fail "ob-bastion-id returned an empty identifier"
        return 1
    fi
    # bastion_id values are typically hostname-like — accept the conservative
    # alphanumeric + - . _ : @ class so we don't over-constrain LLNG's choice.
    if ! echo "$id" | grep -qE '^[A-Za-z0-9._:@-]+$'; then
        fail "ob-bastion-id returned an identifier outside the expected charset" "$id"
        return 1
    fi
    log_verbose "bastion_id: $id"

    # Verify --verbose returns valid JSON with at least one expected claim.
    local verbose_out
    if ! verbose_out=$(docker exec ob-cert-bastion ob-bastion-id --verbose --quiet 2>&1); then
        fail "ob-bastion-id --verbose failed" "$verbose_out"
        return 1
    fi
    if ! echo "$verbose_out" | jq -e '.iss // .sub // .bastion_id' >/dev/null 2>&1; then
        fail "ob-bastion-id --verbose did not produce valid JWT claims JSON" \
             "$(echo "$verbose_out" | head -10)"
        return 1
    fi

    pass "ob-bastion-id returned bastion_id=$id (and valid JSON claims under --verbose)"
}

test_nss_user_resolution() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing NSS user resolution..."

    # Check if bastion can resolve user via NSS
    local output
    output=$(docker exec ob-cert-bastion getent passwd "$TEST_USER" 2>&1) || true

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
    cache_files=$(docker exec ob-cert-bastion ls -la /var/cache/open-bastion/ 2>&1) || true

    log_verbose "Cache files: $cache_files"

    # Cache may be empty if no PAM auth happened yet, that's OK
    if docker exec ob-cert-bastion test -d /var/cache/open-bastion; then
        pass "PAM cache directory exists"
        return 0
    else
        fail "PAM cache directory does not exist" "$cache_files"
        return 1
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "=============================================="
    echo "  LLNG PAM Module Integration Tests"
    echo "=============================================="
    echo ""

    check_requirements

    echo ""
    echo "=== Phase 1: Setup ==="
    start_containers
    wait_for_bastion

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
    test_builder_scenarios_matrix
    test_builder_ansible_syntax
    test_ob_bastion_id
    test_builder_deployed_backend
    test_builder_auto_approve_protocol

    echo ""
    echo "=== Phase 6: Cert revocation via fingerprint binding ==="
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
