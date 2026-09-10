#!/bin/bash
# test_ob_portal_prerequisites.sh
#
# R-P1 is the one risk in the study whose remediation the product cannot
# perform and cannot verify: `pamAccessServerGroups` and `pamAccessAllowedRps`
# are LemonLDAP::NG Manager settings, and asking the portal whether they are set
# would need an API that publishes the project's bastions, server groups and
# RPs -- which is not something an SSO should offer. Until they are set, any
# host enrolled in the project can declare itself a bastion and mint a hop
# voucher.
#
# 0.7.0 makes that a release prerequisite rather than a condition of employment
# left to the deployment (#268). The only enforcement available is that every
# path an operator takes says so, every time. This suite is what keeps that
# true: the text exists, it is SHIPPED (a helper that was not in the package is
# exactly how #263 happened), every setup script and ob-post-upgrade print it,
# and ob-builder writes the pre-filled checklist next to both artefact kinds.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEXT="$ROOT_DIR/share/ob-portal-prerequisites.txt"

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

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "=== portal-side prerequisite for R-P1 (#268) ==="

# ── 1. The text exists and says the load-bearing things ──────────────────────
test_text_content() {
    if [ ! -r "$TEXT" ]; then
        fail "share/ob-portal-prerequisites.txt exists" "missing"
        return
    fi
    local missing="" k
    for k in pamAccessServerGroups pamAccessAllowedRps allowed_bastions R-P1; do
        grep -q -- "$k" "$TEXT" || missing="$missing $k"
    done
    if [ -z "$missing" ]; then
        pass "the shipped text names the settings an operator has to change"
    else
        fail "the shipped text names the settings an operator has to change" \
             "absent:$missing"
    fi
}

# ── 2. It is actually in the packages ────────────────────────────────────────
# A file that exists in the tree and not in the .deb is a feature that works on
# the developer's machine only -- #263, exactly.
test_text_is_packaged() {
    local missing="" f
    grep -q 'share/ob-portal-prerequisites.txt' "$ROOT_DIR/CMakeLists.txt" \
        || missing="$missing CMakeLists.txt"
    for f in debian/open-bastion.install rpm/open-bastion.spec; do
        grep -q 'ob-portal-prerequisites.txt' "$ROOT_DIR/$f" \
            || missing="$missing $f"
    done
    if [ -z "$missing" ]; then
        pass "the text is installed by cmake, the .deb and the .rpm"
    else
        fail "the text is installed by cmake, the .deb and the .rpm" \
             "not in:$missing"
    fi
}

# ── 3. Every setup script prints it ──────────────────────────────────────────
# The function is extracted and run rather than grepped for: a test that checks
# the script MENTIONS the file passes just as well when the call site is gone.
test_setup_scripts_print_it() {
    local bad="" s out
    for s in ob-bastion-setup ob-backend-setup ob-desktop-setup; do
        local f="$ROOT_DIR/scripts/$s"
        if ! grep -q '^print_portal_prerequisites() {' "$f"; then
            bad="$bad no-function-in:$s"
            continue
        fi
        # The definition, and nothing else from the script.
        out=$(
            eval "$(awk '/^print_portal_prerequisites\(\) \{/,/^\}/' "$f")"
            # Stand in for the script's own data-dir lookup, which resolves
            # relative to $0.
            _ob_data_dir() { printf '%s' "$ROOT_DIR/share"; }
            OB_DATA_DIR="$ROOT_DIR/share" print_portal_prerequisites 2>&1
        )
        case "$out" in
            *pamAccessServerGroups*pamAccessAllowedRps*) ;;
            *) bad="$bad no-output-from:$s" ;;
        esac
        # The call site: the function must be reached from print_summary.
        grep -q '^    print_portal_prerequisites$' "$f" \
            || bad="$bad not-called-in:$s"
    done
    if [ -z "$bad" ]; then
        pass "the three setup scripts print the prerequisite"
    else
        fail "the three setup scripts print the prerequisite" "$bad"
    fi
}

# ── 4. ob-post-upgrade prints it, for real ───────────────────────────────────
# This is the command an operator runs when moving an existing host to 0.7.0,
# so it is the one path that reaches hosts that were set up before the
# prerequisite existed. Run it, do not read it.
test_post_upgrade_prints_it() {
    printf 'portal_url = https://sso.example.org\nnode_role = bastion\n' \
        > "$WORK/ob.conf"
    local out
    out=$(OB_CONFIG="$WORK/ob.conf" OB_DATA_DIR="$ROOT_DIR/share" \
          OB_SSHD_CONFIG_DIR="$WORK/sshd_config.d" \
          bash "$ROOT_DIR/scripts/ob-post-upgrade" --dry-run 2>&1)
    case "$out" in
        *pamAccessServerGroups*pamAccessAllowedRps*)
            pass "ob-post-upgrade --dry-run prints the prerequisite" ;;
        *)
            fail "ob-post-upgrade --dry-run prints the prerequisite" \
                 "not in its output" ;;
    esac
}

# ── 5. ob-builder writes the pre-filled checklist ────────────────────────────
# The Ansible role runs the setup script through a task whose stdout nobody
# reads, so for that artefact the file IS the notification.
test_builder_writes_checklist() {
    local tpl="$ROOT_DIR/admin-builder/templates/PORTAL-CHECKLIST.md.in"
    if [ ! -f "$tpl" ]; then
        fail "ob-builder ships a portal checklist template" "missing $tpl"
        return
    fi

    local out bad=""
    out=$(
        set +u
        SCRIPT_DIR_SAVED="$ROOT_DIR"
        export OB_BUILDER_LIB_DIR="$ROOT_DIR/admin-builder/lib"
        export OB_BUILDER_SHARE="$ROOT_DIR/admin-builder"
        # Same idiom as tests/test_ob_builder_service_accounts.sh: source the
        # definitions with `set -euo pipefail` and the main call removed.
        eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' \
                "$ROOT_DIR/admin-builder/ob-builder")"
        # Stub the two heavy renderers and the placeholder map: what is under
        # test is that run_outputs_for_role reaches the checklist for BOTH
        # artefact kinds, not what the installer contains.
        render_shell_installer() { : > "$1"; }
        render_ansible_role()    { mkdir -p "$1"; }
        build_placeholder_map() {
            ph_reset
            ph_set DEPLOYMENT_SLUG    "acme"
            ph_set OB_BUILDER_VERSION "test"
            ph_set BUILD_DATE         "2026-01-01T00:00:00Z"
            ph_set TARGET_ROLE        "$1"
            ph_set PORTAL_URL         "https://sso.example.org"
            ph_set CLIENT_ID          "pam-access"
            ph_set SERVER_GROUP       "prod"
        }
        DRY_RUN=0
        TEMPLATES_DIR="$SCRIPT_DIR_SAVED/admin-builder/templates"
        mkdir -p "$WORK/art"
        run_outputs_for_role bastion "$WORK/art/install.sh" "$WORK/art/role" \
            >/dev/null 2>&1
        echo done
    )
    [ "$out" = "done" ] || bad="$bad builder-run-failed"

    [ -f "$WORK/art/PORTAL-CHECKLIST-bastion.md" ] \
        || bad="$bad no-checklist-beside-installer"
    [ -f "$WORK/art/role/PORTAL-CHECKLIST.md" ] \
        || bad="$bad no-checklist-in-ansible-role"

    local f
    for f in "$WORK/art/PORTAL-CHECKLIST-bastion.md" "$WORK/art/role/PORTAL-CHECKLIST.md"; do
        [ -f "$f" ] || continue
        # An unresolved @@PLACEHOLDER@@ is a checklist that tells the operator
        # to configure a literal @@CLIENT_ID@@.
        grep -q '@@[A-Z_]*@@' "$f" && bad="$bad unresolved-placeholder-in:$(basename "$f")"
        grep -q 'pam-access' "$f" || bad="$bad client-id-not-filled-in:$(basename "$f")"
        grep -q 'pamAccessAllowedRps' "$f" || bad="$bad setting-missing-in:$(basename "$f")"
    done

    if [ -z "$bad" ]; then
        pass "ob-builder writes a pre-filled checklist for both artefact kinds"
    else
        fail "ob-builder writes a pre-filled checklist for both artefact kinds" "$bad"
    fi
}

run_test test_text_content
run_test test_text_is_packaged
run_test test_setup_scripts_print_it
run_test test_post_upgrade_prints_it
run_test test_builder_writes_checklist

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
