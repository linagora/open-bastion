#!/bin/bash
#
# Test suite for the protection of ob-builder artefacts that carry the OIDC
# client secret in clear text (#203).
#
# With client_secret_mode=embedded, the secret is written verbatim into the
# shell installer (0755) and into the Ansible role's defaults/main.yml (0644).
# Two accidents follow, and both were observed on a real build host: any local
# account could read the secret, and a tree generated inside a git working
# directory was one `git add -A` away from being published.
#
# These tests pin both guards, and pin that they stay out of the way for
# client_secret_mode=prompt/none, where no secret reaches the disk at all.
#

set -u

TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$SCRIPT_DIR/admin-builder/ob-builder"
export OB_BUILDER_LIB_DIR="$SCRIPT_DIR/admin-builder/lib"
export OB_BUILDER_SHARE="$SCRIPT_DIR/admin-builder"

TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

test_pass() { echo -e "${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); }
test_fail() {
    echo -e "${RED}✗${NC} $1"
    [ -n "${2:-}" ] && echo -e "  ${YELLOW}Details:${NC} $2"
    ((TESTS_FAILED++))
}

# Source ob-builder definitions into THIS shell (functions + globals), with the
# top-level `set -euo pipefail` and the final `main "$@"` removed so nothing
# runs and a failing helper does not kill the harness.
# shellcheck disable=SC1090
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
DRY_RUN=0

mode_of() { stat -c '%a' "$1"; }

# ── _tighten_if_embedded ────────────────────────────────────────────────────

test_tighten_embedded() {
    local f="$TEST_TMPDIR/installer.sh"
    : > "$f"; chmod 0755 "$f"

    CLIENT_SECRET_MODE=embedded
    _tighten_if_embedded "$f" "0700"

    if [ "$(mode_of "$f")" = "700" ]; then
        test_pass "embedded: shell installer tightened 0755 -> 0700"
    else
        test_fail "embedded: shell installer not tightened" "mode=$(mode_of "$f")"
    fi
}

test_tighten_defaults() {
    local f="$TEST_TMPDIR/main.yml"
    : > "$f"; chmod 0644 "$f"

    CLIENT_SECRET_MODE=embedded
    _tighten_if_embedded "$f" "0600"

    if [ "$(mode_of "$f")" = "600" ]; then
        test_pass "embedded: role defaults/main.yml tightened 0644 -> 0600"
    else
        test_fail "embedded: defaults/main.yml not tightened" "mode=$(mode_of "$f")"
    fi
}

test_tighten_noop_when_not_embedded() {
    local ok=true f
    for mode in prompt none; do
        f="$TEST_TMPDIR/keep-$mode"
        : > "$f"; chmod 0644 "$f"
        CLIENT_SECRET_MODE="$mode"
        _tighten_if_embedded "$f" "0600"
        [ "$(mode_of "$f")" = "644" ] || ok=false
    done
    $ok && test_pass "prompt/none: permissions left alone (no secret on disk)" \
         || test_fail "prompt/none: permissions were changed anyway"
}

test_tighten_missing_file() {
    CLIENT_SECRET_MODE=embedded
    if _tighten_if_embedded "$TEST_TMPDIR/does-not-exist" "0600"; then
        test_pass "missing file: returns success instead of aborting the build"
    else
        test_fail "missing file: non-zero exit would abort a set -e build"
    fi
}

test_tighten_dry_run() {
    local f="$TEST_TMPDIR/dryrun"
    : > "$f"; chmod 0644 "$f"

    CLIENT_SECRET_MODE=embedded
    DRY_RUN=1
    _tighten_if_embedded "$f" "0600"
    DRY_RUN=0

    if [ "$(mode_of "$f")" = "644" ]; then
        test_pass "dry-run: touches nothing"
    else
        test_fail "dry-run: modified the file" "mode=$(mode_of "$f")"
    fi
}

# ── _write_embedded_secret_gitignore ────────────────────────────────────────

test_gitignore_written() {
    local out="$TEST_TMPDIR/tree-embedded"
    mkdir -p "$out"

    CLIENT_SECRET_MODE=embedded
    _write_embedded_secret_gitignore "$out"

    if [ ! -f "$out/.gitignore" ]; then
        test_fail "embedded: no .gitignore written"
        return
    fi
    if grep -qx '\*' "$out/.gitignore"; then
        test_pass "embedded: the tree .gitignore ignores the whole directory"
    else
        test_fail "embedded: .gitignore does not ignore everything" \
                  "$(cat "$out/.gitignore")"
    fi
}

test_gitignore_actually_ignores() {
    command -v git >/dev/null 2>&1 || {
        test_pass "git not available: skipping the end-to-end ignore check"
        return
    }

    local repo="$TEST_TMPDIR/repo"
    mkdir -p "$repo"
    git -C "$repo" init -q 2>/dev/null || {
        test_pass "git init unavailable: skipping the end-to-end ignore check"
        return
    }

    local out="$repo/acme-setup-bastion"
    mkdir -p "$out/roles/open-bastion-bastion/defaults"
    echo 'ob_client_secret: "s3cr3t"' > "$out/roles/open-bastion-bastion/defaults/main.yml"

    CLIENT_SECRET_MODE=embedded
    _write_embedded_secret_gitignore "$out"

    git -C "$repo" add -A 2>/dev/null
    if git -C "$repo" diff --cached --name-only | grep -q 'main.yml'; then
        test_fail "git add -A still stages the secret-bearing file" \
                  "$(git -C "$repo" diff --cached --name-only)"
    else
        test_pass "git add -A no longer stages the embedded secret"
    fi
}

test_gitignore_not_written_when_not_embedded() {
    local ok=true out
    for mode in prompt none; do
        out="$TEST_TMPDIR/tree-$mode"
        mkdir -p "$out"
        CLIENT_SECRET_MODE="$mode"
        _write_embedded_secret_gitignore "$out"
        [ -f "$out/.gitignore" ] && ok=false
    done
    $ok && test_pass "prompt/none: no .gitignore (the tree is safe to version)" \
         || test_fail "prompt/none: an unnecessary .gitignore was written"
}

test_gitignore_dry_run() {
    local out="$TEST_TMPDIR/tree-dryrun"
    mkdir -p "$out"

    CLIENT_SECRET_MODE=embedded
    DRY_RUN=1
    _write_embedded_secret_gitignore "$out"
    DRY_RUN=0

    if [ -f "$out/.gitignore" ]; then
        test_fail "dry-run: wrote a .gitignore"
    else
        test_pass "dry-run: writes nothing"
    fi
}

echo "=========================================="
echo "ob-builder embedded-secret protection (#203)"
echo "=========================================="
echo ""

test_tighten_embedded
test_tighten_defaults
test_tighten_noop_when_not_embedded
test_tighten_missing_file
test_tighten_dry_run
test_gitignore_written
test_gitignore_actually_ignores
test_gitignore_not_written_when_not_embedded
test_gitignore_dry_run

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
