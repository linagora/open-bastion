#!/bin/bash
# test_ob_upgrade.sh
#
# Upgrades a v0.6.2-shaped host to this tree and checks it converges (#249).
#
# The other suites check the new code against a clean host. Nobody upgrades a
# clean host. What an operator actually has is a machine set up months ago,
# whose /run/open-bastion/ssh-fp is 0700 nobody and whose
# /usr/local/sbin/ob-ssh-principals writes that spool itself -- the trust root
# #249 removed -- and the helper is generated on the host, so installing the
# new package does not replace it.
#
# Both halves of that are asserted here, and the first is the reason
# ob-post-upgrade exists at all:
#
#   1. after installing the new package, the host is STILL on the old trust
#      root. If this ever stops being true, UPGRADE-NOTES is telling operators
#      to run something they no longer need, and the note should go.
#   2. after ob-post-upgrade, it is not: root owns the spool, the helper
#      deposits through ob-fp-submit, and nothing in openbastion.conf moved.
#
# The staged host records sessions, as a bastion set up by v0.6.2 does, which
# is what #293 is about: its SSO users log in through bash, which reads their
# own ~/.bashrc before the recorder. The package does not switch the users'
# shell; ob-post-upgrade does, adding force_shell and nothing else to
# nss_openbastion.conf. (What the postinst says about it is tested in
# tests/test_ob_setup_login_shell.sh: this container has no package lists, so
# the package is unpacked with `dpkg -i` and its postinst does not run here.)
#
# The old artefacts are not imitations: they are extracted from the v0.6.2 tag,
# so the test keeps describing the version people are actually upgrading from.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OLD_TAG="${OB_OLD_TAG:-v0.6.2}"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    if ! declare -F "$1" >/dev/null; then
        fail "$1 is listed as a test but is not defined"
        return
    fi
    "$@"
}

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker is required"; exit 0; }
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon not reachable"; exit 0; }
git -C "$ROOT_DIR" rev-parse "$OLD_TAG" >/dev/null 2>&1 \
    || { echo "SKIP: tag $OLD_TAG not in this checkout"; exit 0; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ── The package under test ───────────────────────────────────────────────────
DEB="${OB_DEB:-}"
if [ -z "$DEB" ]; then
    DEB=$(ls -t "$ROOT_DIR"/../open-bastion_*.deb 2>/dev/null | head -1)
fi
if [ -z "$DEB" ] || [ ! -f "$DEB" ]; then
    echo "  building the package under test (no .deb found)..."
    ( cd "$ROOT_DIR" && dpkg-buildpackage -b -us -uc -tc ) >"$WORK/build.log" 2>&1 || {
        echo "SKIP: could not build a .deb (see $WORK/build.log)"; exit 0; }
    DEB=$(ls -t "$ROOT_DIR"/../open-bastion_*.deb | head -1)
fi
cp "$DEB" "$WORK/new.deb"

# ── The host as v0.6.2 left it, from the tag itself ─────────────────────────
git -C "$ROOT_DIR" show "$OLD_TAG:scripts/ob-bastion-setup" \
    | awk "/cat > \"\\\$script_path\" << 'PRINCIPALS'/{f=1;next} /^PRINCIPALS\$/{f=0} f" \
    > "$WORK/old-helper"
if [ ! -s "$WORK/old-helper" ]; then
    echo "SKIP: could not extract the $OLD_TAG helper (heredoc shape changed)"
    exit 0
fi
# It must be the pre-#249 shape, or the test is upgrading from the wrong thing.
if grep -q 'ob-fp-submit' "$WORK/old-helper"; then
    echo "SKIP: the $OLD_TAG helper already deposits through the sink"
    exit 0
fi

cat > "$WORK/stage.sh" <<'STAGE'
set -e
# A host as ob-bastion-setup v0.6.2 left it.
mkdir -p /etc/open-bastion /usr/local/sbin /run/open-bastion/ssh-fp
cat > /etc/open-bastion/openbastion.conf <<'CONF'
portal_url = https://sso.example.com
server_group = prod
node_role = bastion
client_id = pam-access
CONF
chmod 600 /etc/open-bastion/openbastion.conf
install -m 0755 /tmp/old-helper /usr/local/sbin/ob-ssh-principals
# The old trust root: the spool belonged to the unprivileged helper user, and
# a drop deposited by it.
chmod 0711 /run/open-bastion
echo "SHA256:oldfingerprint" > /run/open-bastion/ssh-fp/4242.fp
chmod 0600 /run/open-bastion/ssh-fp/4242.fp
chown -R nobody:nogroup /run/open-bastion/ssh-fp
chmod 0700 /run/open-bastion/ssh-fp
sha256sum /etc/open-bastion/openbastion.conf > /tmp/conf.sha
# A recording bastion (#293): the ForceCommand in its drop-in (only that line:
# the old AuthorizedPrincipalsCommand would make ob-post-upgrade stop), and the
# NSS configuration v0.6.2 wrote, which hands SSO users bash.
mkdir -p /etc/ssh/sshd_config.d
printf 'ForceCommand /usr/sbin/ob-session-recorder\n' \
    > /etc/ssh/sshd_config.d/00-open-bastion-bastion.conf
cat > /etc/open-bastion/nss_openbastion.conf <<'NSS'
portal_url = https://sso.example.com
server_token_file = /var/lib/open-bastion/token
cache_ttl = 300
default_shell = /bin/bash
home_base = /home
NSS
chmod 644 /etc/open-bastion/nss_openbastion.conf
cp /etc/open-bastion/nss_openbastion.conf /tmp/nss.orig
STAGE

cat > "$WORK/run.sh" <<'RUNNER'
set -u
. /tmp/stage.sh
# stage.sh runs under `set -e` so a staging failure stops the run. The checks
# below must NOT: they report a return code, and with errexit still on
# `echo "### opu-rc: $?"` can only ever print 0 -- the assertion on it would be
# vacuous.
set +e

echo "### staged: $(stat -c '%U %a' /run/open-bastion/ssh-fp)"

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/new.deb >/dev/null 2>&1 \
    || dpkg -i /tmp/new.deb >/dev/null 2>&1 || true

# 1. The package alone must NOT have migrated the host.
echo "### after-package-owner: $(stat -c '%U' /run/open-bastion/ssh-fp)"
echo "### after-package-helper-uses-sink: $(grep -c ob-fp-submit /usr/local/sbin/ob-ssh-principals || true)"
echo "### after-package-force-shell: $(grep -c '^force_shell' /etc/open-bastion/nss_openbastion.conf || true)"

# 2. Now the command.
ob-post-upgrade >/tmp/opu.log 2>&1
echo "### opu-rc: $?"

echo "### after-opu-owner: $(stat -c '%U' /run/open-bastion/ssh-fp)"
echo "### after-opu-mode: $(stat -c '%a' /run/open-bastion/ssh-fp)"
echo "### after-opu-helper-uses-sink: $(grep -c ob-fp-submit /usr/local/sbin/ob-ssh-principals || true)"
echo "### backup-kept: $(ls /usr/local/sbin/ | grep -c 'ob-ssh-principals.bak-' || true)"
echo "### conf-unchanged: $(sha256sum -c /tmp/conf.sha >/dev/null 2>&1 && echo yes || echo NO)"
echo "### old-drop-still-there: $([ -f /run/open-bastion/ssh-fp/4242.fp ] && echo yes || echo no)"
echo "### after-opu-force-shell: $(sed -n 's/^force_shell = //p' /etc/open-bastion/nss_openbastion.conf)"
echo "### nss-rest-kept: $(head -c "$(stat -c %s /tmp/nss.orig)" /etc/open-bastion/nss_openbastion.conf | cmp -s - /tmp/nss.orig && echo yes || echo NO)"
echo "### login-shell-installed: $([ -x /usr/sbin/ob-login-shell ] && echo yes || echo no)"

# 3. Idempotent.
ob-post-upgrade >/tmp/opu2.log 2>&1
echo "### second-run-noop: $(grep -c 'nothing to do' /tmp/opu2.log || true)"
RUNNER

echo "=== upgrade from $OLD_TAG to this tree ==="
OUT=$(docker run --rm \
        -v "$WORK/new.deb":/tmp/new.deb:ro \
        -v "$WORK/old-helper":/tmp/old-helper:ro \
        -v "$WORK/stage.sh":/tmp/stage.sh:ro \
        -v "$WORK/run.sh":/tmp/run.sh:ro \
        debian:trixie bash /tmp/run.sh 2>&1) || true

field() { printf '%s\n' "$OUT" | sed -n "s/^### $1: //p" | tail -1; }

# ── 1. The staged host really is the old shape ──────────────────────────────
test_staged_host_is_old() {
    if [ "$(field staged)" = "nobody 700" ]; then
        pass "the staged host has the pre-#249 spool (0700 nobody)"
    else
        fail "the staged host has the pre-#249 spool (0700 nobody)" \
             "got '$(field staged)'; the rest of this run means nothing"
    fi
}

# ── 2. Installing the package is NOT enough ─────────────────────────────────
# This is the claim UPGRADE-NOTES makes, and the reason ob-post-upgrade exists.
test_package_alone_does_not_migrate() {
    local owner sink
    owner=$(field after-package-owner)
    sink=$(field after-package-helper-uses-sink)
    if [ "$owner" = "nobody" ] && [ "$sink" = "0" ]; then
        pass "installing the package leaves the old helper and the old trust root"
    else
        fail "installing the package leaves the old helper and the old trust root" \
             "owner=$owner sink-refs=$sink — if the package now migrates by itself, UPGRADE-NOTES should say so"
    fi
}

# ── 3. ob-post-upgrade converges the host ───────────────────────────────────
test_post_upgrade_migrates() {
    local bad=""
    [ "$(field opu-rc)" = "0" ]                       || bad="$bad rc=$(field opu-rc)"
    [ "$(field after-opu-owner)" = "root" ]           || bad="$bad owner=$(field after-opu-owner)"
    [ "$(field after-opu-mode)" = "700" ]             || bad="$bad mode=$(field after-opu-mode)"
    [ "$(field after-opu-helper-uses-sink)" != "0" ]  || bad="$bad helper-still-writes-spool"
    if [ -z "$bad" ]; then
        pass "ob-post-upgrade takes the spool to 0700 root and the helper to the sink"
    else
        fail "ob-post-upgrade takes the spool to 0700 root and the helper to the sink" "$bad"
    fi
}

# ── 4. It keeps what it must keep ───────────────────────────────────────────
test_keeps_config_and_backup() {
    local bad=""
    [ "$(field conf-unchanged)" = "yes" ] || bad="$bad openbastion.conf-modified"
    [ "$(field backup-kept)" != "0" ]     || bad="$bad no-backup-of-old-helper"
    if [ -z "$bad" ]; then
        pass "openbastion.conf is untouched and the old helper is kept"
    else
        fail "openbastion.conf is untouched and the old helper is kept" "$bad"
    fi
}

# ── 4b. The SSO login shell of a recording bastion (#293) ───────────────────
test_login_shell_switched() {
    local bad=""
    [ "$(field login-shell-installed)" = "yes" ]  || bad="$bad launcher-not-installed"
    [ "$(field after-package-force-shell)" = "0" ] || bad="$bad package-switched-it-alone"
    [ "$(field after-opu-force-shell)" = "/usr/sbin/ob-login-shell" ] \
        || bad="$bad force_shell='$(field after-opu-force-shell)'"
    [ "$(field nss-rest-kept)" = "yes" ]          || bad="$bad rest-of-nss-conf-changed"
    if [ -z "$bad" ]; then
        pass "a recording bastion: the package leaves the users' shell, ob-post-upgrade forces ob-login-shell"
    else
        fail "a recording bastion gets ob-login-shell as its SSO users' login shell" "$bad"
    fi
}

# ── 5. Running it again changes nothing ─────────────────────────────────────
test_idempotent() {
    if [ "$(field second-run-noop)" != "0" ]; then
        pass "a second run reports nothing to do"
    else
        fail "a second run reports nothing to do" "$(printf '%s' "$OUT" | tail -3)"
    fi
}

# ── 6. The legacy portal stays pinned ───────────────────────────────────────
#
# docker-demo-cert is the only thing in the tree that exercises ob-bastion-id's
# fallback to the legacy /pam/bastion-token probe, and it does so only because
# the portal it runs is old. On :latest that coverage would disappear the day
# an image ships the 0.6.0 plugins -- silently, with the suite still green.
# Checked here rather than in a comment, because a comment is what it was.
#
# (Verified while writing this: as of 2026-09-01, :latest is still the old
# generation -- LLNG 2.23.3, PamAccess 2.22.0, no /pam/whoami and no signature
# verification. So nothing is pinned away from a newer portal today; the pin is
# what keeps the legacy path covered once there is one.)
test_legacy_portal_is_pinned() {
    local df="$ROOT_DIR/docker-demo-cert/sso/Dockerfile"
    if grep -qE '^(FROM|ARG PORTAL_IMAGE=).*lemonldap-ng-portal:latest' "$df"; then
        fail "the legacy demo pins its portal image" \
             "it follows :latest, so the /pam/bastion-token fallback loses its only coverage when that moves"
    elif grep -qE 'lemonldap-ng-portal:[0-9]' "$df"; then
        pass "the legacy demo pins its portal image to a version"
    else
        fail "the legacy demo pins its portal image" "no portal image found in $df"
    fi
}

run_test test_staged_host_is_old
run_test test_package_alone_does_not_migrate
run_test test_post_upgrade_migrates
run_test test_keeps_config_and_backup
run_test test_login_shell_switched
run_test test_idempotent
run_test test_legacy_portal_is_pinned

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
