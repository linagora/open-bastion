#!/bin/bash
# test_ob_post_upgrade.sh
#
# Guards ob-post-upgrade, and the single-copy rule it exists to make possible.
#
# The sshd principals helper used to be an inline heredoc in ob-bastion-setup
# AND another in ob-backend-setup. Adding a third to ob-post-upgrade is how
# debian/ and systemd/ ended up shipping units that had silently drifted apart
# (#254), so the text moved to share/ and all three install from there. Test 1
# is what keeps it there.
#
# The rest is about the two things this command must never do. It repairs a
# host whose operator has lost the arguments they set it up with, which means
# it runs on production hosts, blind, possibly years later. If it ever enrols,
# it mints a new device id and every backend allowlist stops matching; if it
# ever writes openbastion.conf, it overwrites a decision it cannot know.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/ob-post-upgrade"

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

[ -x "$SCRIPT" ] || { echo "SKIP: $SCRIPT not found"; exit 0; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "=== ob-post-upgrade ==="

# ── 1. The helper text lives in exactly one place ────────────────────────────
test_helper_has_one_home() {
    local bad=""
    for f in "$ROOT_DIR"/share/ob-ssh-principals.bastion \
             "$ROOT_DIR"/share/ob-ssh-principals.backend \
             "$ROOT_DIR"/share/ob-fp-spool.tmpfiles; do
        [ -f "$f" ] || bad="$bad missing:$(basename "$f")"
    done
    # No script may carry the helper inline again. The shebang plus the
    # helper's own banner is the signature; a script that installs the shipped
    # file never contains it.
    # scripts/ AND tests/: a test that still extracts the helper from a heredoc
    # is how tests/test_backend_cert_acceptance.sh ended up silently broken --
    # it was the third consumer, and this check only looked at scripts/.
    # scripts/ AND tests/: a test that still extracts the helper from a heredoc
    # in the working tree is how tests/test_backend_cert_acceptance.sh ended up
    # silently broken -- it was the third consumer, and this check only looked
    # at scripts/.
    #
    # Two things are deliberately not flagged. This file, which carries the
    # patterns as search strings. And an extraction that goes through
    # `git show <tag>:` -- tests/test_ob_upgrade.sh stages a host from v0.6.2
    # and must keep reading the heredoc as it was then; history is not a second
    # copy to maintain.
    local f self
    self="$(basename "$0")"
    for f in "$ROOT_DIR"/scripts/* "$ROOT_DIR"/tests/*; do
        [ -f "$f" ] || continue
        [ "$(basename "$f")" = "$self" ] && continue
        if grep -q 'ob-ssh-principals — sshd AuthorizedPrincipalsCommand helper' "$f"; then
            bad="$bad inline-copy-in:$(basename "$f")"
        fi
        if grep -q "<< 'PRINCIPALS'" "$f" && ! grep -q 'git .*show' "$f"; then
            bad="$bad extracts-working-tree-heredoc-in:$(basename "$f")"
        fi
    done
    if [ -z "$bad" ]; then
        pass "the principals helper text lives only in share/"
    else
        fail "the principals helper text lives only in share/" "$bad"
    fi
}

# ── 2. Both installers use the shipped copy ──────────────────────────────────
test_all_installers_use_share() {
    local missing="" f
    for f in ob-bastion-setup ob-post-upgrade; do
        grep -q 'ob-ssh-principals\.' "$ROOT_DIR/scripts/$f" \
            || missing="$missing $f"
    done
    if [ -z "$missing" ]; then
        pass "the setup script and ob-post-upgrade read the shipped helper"
    else
        fail "the setup script and ob-post-upgrade read the shipped helper" "not:$missing"
    fi
}

# ── 3. It never enrols ───────────────────────────────────────────────────────
# The whole point of the command. Re-enrolling changes the device id, which no
# backend allowlist contains -- the one repair that breaks more than it fixes.
test_never_enrols() {
    local hits
    hits=$(grep -nE 'ob-enroll|/oauth2/(device|token)|device_code' "$SCRIPT" \
           | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vE 'error|Run ob-')
    if [ -z "$hits" ]; then
        pass "ob-post-upgrade cannot enrol: it calls nothing that would"
    else
        fail "ob-post-upgrade cannot enrol" "$hits"
    fi
}

# ── 4. It never writes configuration ─────────────────────────────────────────
test_never_writes_config() {
    local hits
    # Any redirection or install into the config dir, the token, sshd or PAM.
    hits=$(grep -nE '>[[:space:]]*"?\$?\{?(CONFIG_FILE|OB_TOKEN)|/etc/open-bastion/[a-z_]*\.conf"?[[:space:]]*$|>[^>]*sshd_config|>[^>]*/etc/pam\.d/' "$SCRIPT" \
           | grep -vE '^[0-9]+:[[:space:]]*#')
    if [ -z "$hits" ]; then
        pass "ob-post-upgrade writes no configuration file"
    else
        fail "ob-post-upgrade writes no configuration file" "$hits"
    fi
}

# ── 5. Role detection ────────────────────────────────────────────────────────
test_role_detection() {
    local bad="" role out
    for role in backend bastion standalone; do
        printf 'node_role = %s\n' "$role" > "$WORK/ob.conf"
        out=$(OB_CONFIG="$WORK/ob.conf" "$SCRIPT" --dry-run 2>&1)
        case "$role" in
            backend) echo "$out" | grep -q 'role: backend' || bad="$bad $role" ;;
            *)       echo "$out" | grep -q 'role: bastion' || bad="$bad $role" ;;
        esac
    done
    # No node_role: the allowlist is what tells a backend apart.
    printf 'portal_url = https://x\n' > "$WORK/ob.conf"
    out=$(OB_CONFIG="$WORK/ob.conf" "$SCRIPT" --dry-run 2>&1)
    echo "$out" | grep -q 'role: bastion' || bad="$bad no-node_role"

    # A value that is none of the three must stop, not guess.
    printf 'node_role = wat\n' > "$WORK/ob.conf"
    if OB_CONFIG="$WORK/ob.conf" "$SCRIPT" --dry-run >/dev/null 2>&1; then
        bad="$bad accepts-unknown-role"
    fi

    if [ -z "$bad" ]; then
        pass "the role is read from node_role, with the allowlist as fallback"
    else
        fail "the role is read from node_role, with the allowlist as fallback" "$bad"
    fi
}

# ── 6. An unconfigured host is refused, not "repaired" ───────────────────────
test_refuses_unconfigured_host() {
    if OB_CONFIG="$WORK/absent.conf" "$SCRIPT" --dry-run >/dev/null 2>&1; then
        fail "a host with no openbastion.conf is refused" "it exited 0"
    else
        pass "a host with no openbastion.conf is refused"
    fi
}

# ── 7. --dry-run changes nothing, and needs no root ──────────────────────────
test_dry_run_is_inert() {
    printf 'node_role = bastion\n' > "$WORK/ob.conf"
    local before after
    before=$(ls -la /usr/local/sbin/ob-ssh-principals /etc/tmpfiles.d/open-bastion-ssh-fp.conf 2>&1)
    OB_CONFIG="$WORK/ob.conf" "$SCRIPT" --dry-run >/dev/null 2>&1
    after=$(ls -la /usr/local/sbin/ob-ssh-principals /etc/tmpfiles.d/open-bastion-ssh-fp.conf 2>&1)
    if [ "$before" = "$after" ]; then
        pass "--dry-run touches nothing and runs unprivileged"
    else
        fail "--dry-run touches nothing" "state changed"
    fi
}

# ── 8. The shipped helpers are valid shell and deposit through the sink ──────
test_helpers_are_sound() {
    local bad="" f
    for f in "$ROOT_DIR"/share/ob-ssh-principals.*; do
        sh -n "$f" 2>/dev/null || bad="$bad syntax:$(basename "$f")"
        grep -q 'ob-fp-submit' "$f" || bad="$bad no-sink:$(basename "$f")"
        # It must not write the spool itself: that is the #249 trust root.
        grep -qE '>[[:space:]]*"?/run/open-bastion/ssh-fp' "$f" \
            && bad="$bad writes-spool-directly:$(basename "$f")"
    done
    if [ -z "$bad" ]; then
        pass "both shipped helpers parse and deposit through ob-fp-submit"
    else
        fail "both shipped helpers parse and deposit through ob-fp-submit" "$bad"
    fi
}

# ── 9. Every image that builds from source ships the data scripts/ reads ────
#
# share/ was added for this command, and eleven Dockerfiles that COPY a subset
# of the tree into /src/open-bastion did not know about it: `make install`
# failed inside the image and both docker suites went red in CI, twenty minutes
# after a local run that could not see the problem.
#
# The invariant is narrow on purpose. A generic "every directory CMake installs
# from" check would need to model the conditionals -- these images build with
# BUILD_BUILDER=OFF, INSTALL_DESKTOP=OFF and INSTALL_SYSTEMD=OFF, so
# admin-builder/, lightdm/ and systemd/ are legitimately absent. What is not
# conditional is that the setup scripts in scripts/ install data from share/:
# the two are one unit, and an image with one and not the other cannot build.
test_dockerfiles_ship_share() {
    local missing="" f
    while read -r f; do
        [ -n "$f" ] || continue
        grep -q "COPY share/ " "$f" \
            || missing="$missing ${f#"$ROOT_DIR"/}"
    done < <(grep -rl "COPY scripts/ /src/open-bastion/scripts/" \
                  --include=Dockerfile "$ROOT_DIR")

    if [ -z "$missing" ]; then
        pass "every image that builds scripts/ from source also ships share/"
    else
        fail "every image that builds scripts/ from source also ships share/" \
             "missing COPY share/:$missing"
    fi
}

# ── 10. sshd must already pass %t and %k, or the command refuses ────────────
#
# The v1 helper reads the key type and blob from argv 3 and 4. A host set up
# before 0.7.0 has a two-token line (%u %f) that no package upgrade rewrites,
# so installing the v1 helper there writes no .key drop -- and with
# ssh_key_policy_enabled = true the module denies every SSH login fail-closed.
#
# Worse, it would silence the warning that caught this: the postinst's
# "ACTION REQUIRED" fires only while the helper is pre-v1, and after this
# command the helper IS v1 while sshd has not moved.
test_refuses_stale_sshd_line() {
    local d="$WORK/sshd-old" bad=""
    mkdir -p "$d"
    printf 'node_role = bastion\n' > "$WORK/ob.conf"

    printf 'AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %%u %%f\n' \
        > "$d/00-open-bastion-bastion.conf"
    if OB_CONFIG="$WORK/ob.conf" OB_SSHD_CONFIG_DIR="$d" \
       "$SCRIPT" --dry-run >/dev/null 2>&1; then
        bad="$bad accepted-2-token-line"
    fi

    printf 'AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %%u %%f %%t %%k\n' \
        > "$d/00-open-bastion-bastion.conf"
    OB_CONFIG="$WORK/ob.conf" OB_SSHD_CONFIG_DIR="$d" \
        "$SCRIPT" --dry-run >/dev/null 2>&1 || bad="$bad refused-4-token-line"

    if [ -z "$bad" ]; then
        pass "a pre-0.7.0 AuthorizedPrincipalsCommand line is refused, a current one accepted"
    else
        fail "a pre-0.7.0 AuthorizedPrincipalsCommand line is refused, a current one accepted" "$bad"
    fi
}

# ── 11. The role comes from the sshd drop-in, not from node_role ────────────
#
# node_role used to be a reporting label: before #288, `ob-backend-setup
# --node-role bastion` configured a backend and recorded "bastion", and hosts
# set up that way still say so. Trusting it would install the BASTION helper on
# a backend -- no vouching, allowlist ignored, a direct SSO certificate
# accepted -- under a reassuring "[DONE] installed the bastion helper".
test_role_prefers_the_sshd_dropin() {
    local d="$WORK/sshd-role" bad=""
    mkdir -p "$d"
    printf 'AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %%u %%f %%i %%t %%k\n' \
        > "$d/00-open-bastion-backend.conf"
    # The lie: a backend labelled as a bastion.
    printf 'node_role = bastion\n' > "$WORK/ob.conf"

    # Capture, then grep. Piping the script straight into `grep -q` gives it
    # SIGPIPE the moment grep matches, and `set -o pipefail` up top turns that
    # 141 into a failed pipeline -- the assertion would report a miss on the
    # very output that matched.
    local out
    out=$(OB_CONFIG="$WORK/ob.conf" OB_SSHD_CONFIG_DIR="$d" "$SCRIPT" --dry-run 2>&1)
    printf '%s' "$out" | grep -q 'role: backend' || bad="$bad node_role-won"

    if [ -z "$bad" ]; then
        pass "a backend mislabelled node_role=bastion still gets the backend helper"
    else
        fail "a backend mislabelled node_role=bastion still gets the backend helper" "$bad"
    fi
}

run_test test_helper_has_one_home
run_test test_all_installers_use_share
run_test test_never_enrols
run_test test_never_writes_config
run_test test_role_detection
run_test test_refuses_unconfigured_host
run_test test_dry_run_is_inert
run_test test_helpers_are_sound
run_test test_dockerfiles_ship_share
run_test test_refuses_stale_sshd_line
run_test test_role_prefers_the_sshd_dropin

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
