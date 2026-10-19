#!/bin/bash
#
# test_integration_token_svc.sh
#
# Integration test for docker-demo-token-svc: the Token authentication
# demo (LLNG tokens as SSH passwords) augmented with local service
# accounts (ansible, backup, ...) that authenticate via a plain SSH
# key listed in /etc/open-bastion/service-accounts.conf and are NOT
# signed by any SSH CA.
#
# Scope:
#   - bring up the docker-demo-token-svc stack
#   - verify a human user can still get an LLNG access token
#   - register a service account on the bastion at runtime, with the keys
#     of the pre-#353 format still in its section
#   - check that Open Bastion neither serves it through NSS nor creates it:
#     until the operator runs useradd, the login is refused (#353)
#   - create it the way the documentation says, then SSH with the plain key
#   - check that the session leaves its groups alone (open-bastion-sudo)
#   - check that Open Bastion grants no sudo, and that an operator sudoers
#     rule is what does
#   - check that a non-registered key is refused
#
# Usage:
#   ./tests/test_integration_token_svc.sh [--keep] [--verbose]
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

KEEP_CONTAINERS=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep) KEEP_CONTAINERS=1; shift ;;
        --verbose|-v) VERBOSE=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_DIR/docker-demo-token-svc"
COOKIE_FILE="/tmp/llng-token-svc-cookies"
SVC_KEY="/tmp/test_token_svc_key"

PORTAL_URL="http://localhost:80"
TEST_USER="dwho"
TEST_PASSWORD="dwho"

# Service account used for the SSH-key-only scenario. Unknown to LLNG.
# SVC_UID is what the operator's useradd gives it; service-accounts.conf
# still carries an obsolete, different uid that must be ignored.
SVC_ACCOUNT="ansible-ci"
SVC_UID=5000
SVC_GID=5000
SVC_STALE_UID=5999

log()      { echo -e "${GREEN}[TEST]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error(){ echo -e "${RED}[ERROR]${NC} $*"; }
log_verbose(){ [[ $VERBOSE -eq 1 ]] && echo -e "[DEBUG] $*" || true; }
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo -e "${GREEN}[PASS]${NC} $1"; }
fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}[FAIL]${NC} $1"
    [[ -n "$2" ]] && echo "       Details: $2"
}

cleanup() {
    log "Cleaning up..."
    rm -f "$COOKIE_FILE" "${SVC_KEY}" "${SVC_KEY}.pub" 2>/dev/null || true
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
    for cmd in docker jq curl ssh-keygen; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "$cmd not found"
            missing=1
        fi
    done
    if ! docker compose version &>/dev/null; then
        log_error "docker compose not found"
        missing=1
    fi
    [[ $missing -eq 1 ]] && exit 1
    log "All requirements satisfied"
}

start_containers() {
    log "Building and starting docker-demo-token-svc..."
    cd "$DOCKER_DIR"

    # Stop any conflicting compose projects sharing the :80 and :2222
    # bindings before we start our own.
    for d in docker-demo-token docker-demo-token-svc docker-demo-cert docker-demo-maxsec; do
        if [ -d "$PROJECT_DIR/$d" ]; then
            (cd "$PROJECT_DIR/$d" && docker compose down --volumes --remove-orphans 2>/dev/null) || true
        fi
    done
    cd "$DOCKER_DIR"

    if [[ $VERBOSE -eq 1 ]]; then
        docker compose build
    else
        docker compose build --quiet
    fi
    docker compose up -d

    log "Waiting for SSO to be healthy..."
    local waited=0
    while [[ $waited -lt 120 ]]; do
        if curl -sf "$PORTAL_URL/" >/dev/null 2>&1; then
            log "SSO is healthy after ${waited}s"
            return 0
        fi
        sleep 2
        ((waited+=2))
    done
    log_error "SSO did not become healthy within 120s"
    docker compose logs sso
    return 1
}

wait_for_bastion() {
    log "Waiting for bastion enrollment..."
    local waited=0
    while [[ $waited -lt 60 ]]; do
        if docker exec ob-token-svc-bastion test -f /etc/open-bastion/server_token.json 2>/dev/null; then
            log "Bastion enrolled after ${waited}s"
            return 0
        fi
        sleep 2
        ((waited+=2))
    done
    log_error "Bastion did not enroll within 60s"
    docker logs ob-token-svc-bastion
    return 1
}

# ---------------------------------------------------------------------
# Sanity tests (token path still works)
# ---------------------------------------------------------------------

test_llng_authentication() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing LLNG authentication via llng CLI..."

    rm -f "$COOKIE_FILE"
    local output
    output=$(llng --llng-url "$PORTAL_URL" \
                  --login "$TEST_USER" \
                  --password "$TEST_PASSWORD" \
                  --cookie-jar "$COOKIE_FILE" \
                  llng_cookie 2>&1) || true
    log_verbose "llng output: $output"

    if [[ -f "$COOKIE_FILE" ]] && grep -q "lemonldap" "$COOKIE_FILE"; then
        pass "LLNG authentication successful (human user path)"
    else
        fail "LLNG authentication failed" "$output"
    fi
}

test_bastion_service_accounts_file_present() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Checking that bastion has a blank service-accounts.conf + dir..."

    local perms
    perms=$(docker exec ob-token-svc-bastion stat -c '%u %a' /etc/open-bastion/service-accounts.conf 2>/dev/null || echo "missing")
    log_verbose "service-accounts.conf perms: $perms"
    if [[ "$perms" != "0 600" ]]; then
        fail "service-accounts.conf must be 0600 root:root, got: $perms"
        return 1
    fi

    local dir_perms
    dir_perms=$(docker exec ob-token-svc-bastion stat -c '%u %a' /etc/open-bastion/service-accounts.d 2>/dev/null || echo "missing")
    log_verbose "service-accounts.d perms: $dir_perms"
    if [[ "$dir_perms" != "0 755" ]]; then
        fail "service-accounts.d must be 0755 root:root, got: $dir_perms"
        return 1
    fi

    pass "service-accounts config scaffold in place"
}

# ---------------------------------------------------------------------
# Service account tests
# ---------------------------------------------------------------------

svc_ssh() {
    ssh -i "${SVC_KEY}" \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o ConnectTimeout=10 \
        -p 2222 \
        "${SVC_ACCOUNT}@localhost" "$@"
}

# Register the account with Open Bastion: service-accounts.conf + .pub. The
# section keeps the keys of a pre-#353 file; they must be ignored, not make the
# account invalid.
svc_provision_on_bastion() {
    local pubkey
    pubkey=$(cat "${SVC_KEY}.pub")
    local fp
    fp=$(ssh-keygen -l -E sha256 -f "${SVC_KEY}.pub" | awk '{print $2}')

    docker exec -i ob-token-svc-bastion sh -c "cat > /etc/open-bastion/service-accounts.conf" <<EOF
[${SVC_ACCOUNT}]
key_fingerprint = ${fp}
# Obsolete since #353: ignored with a warning.
sudo_allowed = true
sudo_nopasswd = true
gecos = CI service account
shell = /bin/bash
home = /home/${SVC_ACCOUNT}
uid = ${SVC_STALE_UID}
gid = ${SVC_STALE_UID}
EOF
    docker exec ob-token-svc-bastion chown root:root /etc/open-bastion/service-accounts.conf
    docker exec ob-token-svc-bastion chmod 600 /etc/open-bastion/service-accounts.conf

    docker exec -i ob-token-svc-bastion sh -c \
        "cat > /etc/open-bastion/service-accounts.d/${SVC_ACCOUNT}.pub" <<< "$pubkey"
    docker exec ob-token-svc-bastion chown root:root \
        "/etc/open-bastion/service-accounts.d/${SVC_ACCOUNT}.pub"
    docker exec ob-token-svc-bastion chmod 644 \
        "/etc/open-bastion/service-accounts.d/${SVC_ACCOUNT}.pub"
}

test_service_account_provision() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Registering service account ${SVC_ACCOUNT}..."

    rm -f "${SVC_KEY}" "${SVC_KEY}.pub"
    if ! ssh-keygen -t ed25519 -f "${SVC_KEY}" -N "" -q; then
        fail "Failed to generate service account SSH key"
        return 1
    fi
    if ! svc_provision_on_bastion; then
        fail "Failed to register service account on bastion"
        return 1
    fi

    # The NSS module used to synthesise the account out of the 0600 conf for
    # whoever could read it -- root included. It must not any more.
    local pwent
    if pwent=$(docker exec ob-token-svc-bastion getent passwd "${SVC_ACCOUNT}" 2>/dev/null); then
        fail "NSS resolves ${SVC_ACCOUNT} from service-accounts.conf" "$pwent"
        return 1
    fi

    local helper_out
    helper_out=$(docker exec ob-token-svc-bastion \
        /usr/sbin/ob-service-account-keys "${SVC_ACCOUNT}" 2>/dev/null || true)
    if ! grep -q "ssh-ed25519" <<< "$helper_out"; then
        fail "ob-service-account-keys returned no ed25519 key" "$helper_out"
        return 1
    fi

    pass "Service account ${SVC_ACCOUNT} registered (key + conf), not served by NSS"
}

test_service_account_not_created() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Checking that Open Bastion does not create ${SVC_ACCOUNT}..."

    local output rc=0
    output=$(svc_ssh "echo SHOULD_NEVER_PRINT" 2>&1) || rc=$?
    log_verbose "SSH(svc, no account) rc=$rc output: $output"
    if grep -q "SHOULD_NEVER_PRINT" <<< "$output"; then
        fail "${SVC_ACCOUNT} logged in without a Unix account" "$output"
        return 1
    fi
    if docker exec ob-token-svc-bastion grep -q "^${SVC_ACCOUNT}:" /etc/passwd 2>/dev/null; then
        fail "A login attempt created ${SVC_ACCOUNT} in /etc/passwd"
        return 1
    fi

    pass "Without useradd, ${SVC_ACCOUNT} is refused and nothing is created"
}

# What the operator does (doc/service-accounts.rst). This bastion does not
# record sessions, hence bash; a recording host gives /usr/sbin/ob-login-shell.
# The open-bastion-sudo membership stands for one left by an older release:
# the session must leave it as it is.
svc_create_account() {
    docker exec ob-token-svc-bastion sh -c "
        set -e
        groupadd -g ${SVC_GID} ${SVC_ACCOUNT}
        useradd -u ${SVC_UID} -g ${SVC_GID} --create-home \
            --shell /bin/bash ${SVC_ACCOUNT}
        groupadd -f open-bastion-sudo
        gpasswd -a ${SVC_ACCOUNT} open-bastion-sudo >/dev/null
    "
}

test_service_account_ssh_login() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Creating ${SVC_ACCOUNT} with useradd, then SSH login (plain key, no SSO)..."

    if [[ ! -f "${SVC_KEY}" ]]; then
        fail "Service account key missing; provisioning step must run first"
        return 1
    fi
    if ! svc_create_account; then
        fail "useradd of ${SVC_ACCOUNT} failed"
        return 1
    fi

    local output rc=0
    output=$(svc_ssh "whoami && id -u && id -g" 2>&1) || rc=$?
    log_verbose "SSH(svc) rc=$rc output: $output"

    if [[ $rc -ne 0 ]]; then
        fail "SSH login as ${SVC_ACCOUNT} failed" "$output"
        return 1
    fi
    if ! grep -qx "${SVC_ACCOUNT}" <<< "$output"; then
        fail "whoami did not report ${SVC_ACCOUNT}" "$output"
        return 1
    fi
    if ! grep -qx "${SVC_UID}" <<< "$output"; then
        fail "Wrong uid (expected the useradd one, ${SVC_UID}, not ${SVC_STALE_UID})" "$output"
        return 1
    fi
    if ! grep -qx "${SVC_GID}" <<< "$output"; then
        fail "Wrong gid (expected ${SVC_GID})" "$output"
        return 1
    fi

    pass "Service account ${SVC_ACCOUNT} logged in as the account useradd made (uid=${SVC_UID})"
}

test_service_account_groups_untouched() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Checking that the session left ${SVC_ACCOUNT}'s groups alone..."

    # Before #353 the session phase synced open-bastion-sudo from
    # LLNG_SUDO_ALLOWED; with no sudo right granted by Open Bastion any more,
    # running that sync for a service account would remove it.
    local members
    members=$(docker exec ob-token-svc-bastion getent group open-bastion-sudo | cut -d: -f4)
    if ! tr ',' '\n' <<< "$members" | grep -qx "${SVC_ACCOUNT}"; then
        fail "${SVC_ACCOUNT} was removed from open-bastion-sudo by the session" "$members"
        return 1
    fi

    pass "open-bastion-sudo membership of ${SVC_ACCOUNT} left as the operator set it"
}

test_service_account_sudo() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing sudo: nothing from Open Bastion, the operator's sudoers rule decides..."

    # 1. sudo_allowed/sudo_nopasswd are still in the conf and must grant
    #    nothing. A wrong password on stdin takes sudo through the auth stack,
    #    where the old sudo_nopasswd path returned PAM_SUCCESS without any
    #    proof. (An empty stdin would not: sudo gives up on a conversation
    #    that read nothing, whatever PAM answers.)
    local output rc=0
    output=$(svc_ssh "echo not-a-password | sudo -S -p '' id -u" 2>&1) || rc=$?
    log_verbose "SSH(svc+sudo, no rule) rc=$rc output: $output"
    if [[ $rc -eq 0 ]] || grep -qx "0" <<< "$output"; then
        fail "sudo succeeded for ${SVC_ACCOUNT} with no sudoers rule of the operator's" "$output"
        return 1
    fi

    # 2. The operator's rule. Appended at the end of /etc/sudoers so it wins
    #    over the image's "ALL ALL=(ALL:ALL) ALL" (sudoers is last-match-wins).
    if ! docker exec ob-token-svc-bastion sh -c "
        set -e
        grep -qE '^${SVC_ACCOUNT}[[:space:]]+ALL=.*NOPASSWD' /etc/sudoers || \
            printf '%s\n' '${SVC_ACCOUNT} ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers
        visudo -c >/dev/null
    "; then
        fail "Could not add the operator's sudoers rule"
        return 1
    fi
    rc=0
    output=$(svc_ssh "sudo -n id -u && sudo -n id -un" 2>&1) || rc=$?
    log_verbose "SSH(svc+sudo, NOPASSWD rule) rc=$rc output: $output"

    if [[ $rc -ne 0 ]]; then
        fail "sudo -n as ${SVC_ACCOUNT} failed with a NOPASSWD rule" "$output"
        return 1
    fi
    grep -qx "0" <<< "$output"    || { fail "sudo uid != 0" "$output"; return 1; }
    grep -qx "root" <<< "$output" || { fail "sudo user != root" "$output"; return 1; }

    pass "sudo for ${SVC_ACCOUNT}: refused without a sudoers rule, granted by one"
}

test_service_account_bad_key_rejected() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Testing that a different ed25519 key is rejected..."

    local bad_key="/tmp/test_token_svc_bad"
    rm -f "$bad_key" "${bad_key}.pub"
    ssh-keygen -t ed25519 -f "$bad_key" -N "" -q

    local output rc=0
    output=$(ssh -i "$bad_key" \
                 -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o BatchMode=yes \
                 -o PreferredAuthentications=publickey \
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
        fail "SSH with wrong key did not fail as expected" "$output"
        return 1
    fi

    pass "A non-registered SSH key is rejected for ${SVC_ACCOUNT}"
}

# ---------------------------------------------------------------------

main() {
    echo "=========================================================="
    echo "  Open Bastion Integration Tests - Token + Service Accounts"
    echo "=========================================================="
    echo ""
    check_requirements

    echo ""
    echo "=== Phase 1: Setup ==="
    start_containers
    wait_for_bastion

    echo ""
    echo "=== Phase 2: Sanity ==="
    test_llng_authentication
    test_bastion_service_accounts_file_present

    echo ""
    echo "=== Phase 3: Service account SSH key + sudo ==="
    test_service_account_provision
    test_service_account_not_created
    test_service_account_ssh_login
    test_service_account_groups_untouched
    test_service_account_sudo
    test_service_account_bad_key_rejected

    echo ""
    echo "=========================================================="
    echo "  Test Results"
    echo "=========================================================="
    echo "  Tests run:    $TESTS_RUN"
    echo -e "  ${GREEN}Passed:       $TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "  ${RED}Failed:       $TESTS_FAILED${NC}"
        echo ""
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo "  Failed:       $TESTS_FAILED"
        echo ""
        echo -e "${GREEN}All tests passed!${NC}"
    fi
}

main "$@"
