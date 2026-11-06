#!/bin/bash
# test_ob_release_manifest.sh
#
# Every release attaches MANIFEST.txt and SHA256SUMS so the set of published
# artifacts is pinned and verifiable. This checks the helper the release
# workflow runs: it lists exactly the collected files, excludes its own
# outputs on a rerun, and refuses to pin an empty release.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT_DIR/scripts/write-release-manifest"
RELEASE_YML="$ROOT_DIR/.github/workflows/release.yml"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

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

# The assets the release job collects, one of each kind.
make_assets() {
    local dir=$1
    mkdir -p "$dir"
    printf 'deb\n' > "$dir/open-bastion_0.7.0_amd64-bookworm.deb"
    printf 'rpm\n' > "$dir/open-bastion-0.7.0-1.el9.x86_64.rpm"
    printf '{}\n' > "$dir/open-bastion_0.7.0_amd64-bookworm-debian-bookworm-slim.sbom.json"
    printf '<testsuite/>\n' > "$dir/open-bastion-v0.7.0-ctest.xml"
}

asset_count() {
    find "$1" -maxdepth 1 -type f \
        ! -name MANIFEST.txt ! -name SHA256SUMS | wc -l
}

test_lists_and_hashes_every_asset() {
    local dir="$TMPDIR/assets" rc=0
    make_assets "$dir"

    "$MANIFEST" --tag v0.7.0 --commit 0123456789abcdef "$dir" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "writes the release manifest" "helper exited $rc"
        return
    fi

    # sha256sum -c is the check an auditor runs on the downloaded assets.
    if (cd "$dir" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1); then
        pass "SHA256SUMS verifies every asset"
    else
        fail "SHA256SUMS verifies every asset"
    fi

    if [ "$(wc -l < "$dir/SHA256SUMS")" -eq "$(asset_count "$dir")" ]; then
        pass "SHA256SUMS lists exactly the collected assets"
    else
        fail "SHA256SUMS lists exactly the collected assets" \
             "$(wc -l < "$dir/SHA256SUMS") line(s) for $(asset_count "$dir") asset(s)"
    fi

    local missing="" f
    for f in "$dir"/*; do
        [ -f "$f" ] || continue
        case "${f##*/}" in SHA256SUMS|MANIFEST.txt) continue ;; esac
        grep -qF "${f##*/}" "$dir/MANIFEST.txt" || missing="$missing ${f##*/}"
    done
    if [ -z "$missing" ]; then
        pass "MANIFEST.txt names every asset"
    else
        fail "MANIFEST.txt names every asset" "missing:$missing"
    fi

    if grep -qxF 'Open Bastion v0.7.0' "$dir/MANIFEST.txt" \
       && grep -qxF 'Commit: 0123456789abcdef' "$dir/MANIFEST.txt"; then
        pass "MANIFEST.txt records the tag and the commit"
    else
        fail "MANIFEST.txt records the tag and the commit"
    fi
}

test_rerun_does_not_pin_its_own_output() {
    local dir="$TMPDIR/rerun"
    make_assets "$dir"
    "$MANIFEST" --tag v0.7.0 --commit 0123456789abcdef "$dir" >/dev/null 2>&1
    cp "$dir/SHA256SUMS" "$TMPDIR/first-sums"
    "$MANIFEST" --tag v0.7.0 --commit 0123456789abcdef "$dir" >/dev/null 2>&1

    if cmp -s "$TMPDIR/first-sums" "$dir/SHA256SUMS"; then
        pass "a rerun produces the same SHA256SUMS"
    else
        fail "a rerun produces the same SHA256SUMS"
    fi
    if [ "$(wc -l < "$dir/SHA256SUMS")" -eq "$(asset_count "$dir")" ]; then
        pass "a rerun does not list MANIFEST.txt or SHA256SUMS"
    else
        fail "a rerun does not list MANIFEST.txt or SHA256SUMS"
    fi
}

test_empty_directory_is_refused() {
    local dir="$TMPDIR/empty" rc=0
    mkdir -p "$dir"
    "$MANIFEST" --tag v0.7.0 --commit 0123456789abcdef "$dir" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ] && [ ! -e "$dir/SHA256SUMS" ] && [ ! -e "$dir/MANIFEST.txt" ]; then
        pass "an empty release fails instead of pinning nothing"
    else
        fail "an empty release fails instead of pinning nothing" "rc=$rc"
    fi
}

test_release_workflow_uses_the_helper() {
    [ -f "$RELEASE_YML" ] || { pass "(no release workflow)"; return; }

    if grep -qE '^[[:space:]]*scripts/write-release-manifest([[:space:]]|$)' "$RELEASE_YML"; then
        pass "the release workflow calls write-release-manifest"
    else
        fail "the release workflow calls write-release-manifest"
    fi
    # The release must attach the manifest and the checksums alongside the
    # packages; a glob over the directory does that only if both live in it.
    if grep -qF 'release-assets/*' "$RELEASE_YML"; then
        pass "the release publishes every collected file"
    else
        fail "the release publishes every collected file"
    fi
}

run_test test_lists_and_hashes_every_asset
run_test test_rerun_does_not_pin_its_own_output
run_test test_empty_directory_is_refused
run_test test_release_workflow_uses_the_helper

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
