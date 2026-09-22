#!/bin/bash
# test_ob_changelog.sh
#
# Keeps CHANGELOG.md's structure to Keep a Changelog (issue #258).
#
# `## [Unreleased]` had grown fourteen `###` headings -- `### Security` four
# times, `### Changed` four times -- because each PR appended its own heading
# rather than adding a bullet under the existing one, and nothing merged them
# before a release. Every released section was clean, so this was purely an
# Unreleased problem, and it was invisible until someone counted.
#
# Merging them once fixes nothing durable: the next few PRs put it back. This
# is the part that lasts.
#
# It also checks the file still parses as Keep a Changelog at all: only the six
# defined section types, and a heading order that does not wander.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CHANGELOG="$ROOT_DIR/CHANGELOG.md"

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

[ -f "$CHANGELOG" ] || { echo "SKIP: CHANGELOG.md not found"; exit 0; }

echo "=== CHANGELOG.md structure (issue #258) ==="

# Keep a Changelog 1.1.0 defines exactly these six.
KAC_TYPES="Added Changed Deprecated Removed Fixed Security"

# Tests 2 and 3 look at [Unreleased] only, deliberately. Released sections are
# a record of what shipped, not a document to keep tidy: 0.6.0 and 0.2.1 carry
# `### Documentation` and `### Upgrade notes`, and the heading order wanders in
# six older releases. Retro-editing them would rewrite history to satisfy a
# test, and drift only ever happens in the section still being written. Test 1
# is the exception -- no released section repeats a heading today, and none
# should start.
unreleased() {
    awk '/^## \[Unreleased\]/{f=1; next} /^## \[/{f=0} f' "$CHANGELOG"
}

# ── 1. No `###` heading twice inside one `##` section ────────────────────────
test_no_duplicate_headings() {
    local dupes
    dupes=$(awk '
        /^## /   { section = $0; delete seen; next }
        /^### /  {
            h = substr($0, 5)
            if (h in seen) { printf "%s -> %s (line %d)\n", section, h, NR }
            seen[h] = 1
        }
    ' "$CHANGELOG")

    if [ -z "$dupes" ]; then
        pass "no section repeats a heading"
    else
        fail "no section repeats a heading" \
             "add the bullet under the existing heading instead: $(echo "$dupes" | tr '\n' ' ')"
    fi
}

# ── 2. Only the six Keep a Changelog types ──────────────────────────────────
# `### Known issues` used to live under Unreleased. It is real information, but
# it is not a change, and a seventh type is how the drift starts: put it in the
# prose under the version heading, or in the documentation.
test_only_known_types() {
    local bad="" h
    while read -r h; do
        [ -n "$h" ] || continue
        case " $KAC_TYPES " in
            *" $h "*) ;;
            *) bad="$bad '$h'" ;;
        esac
    done < <(unreleased | grep '^### ' | sed 's/^### //' | sort -u)

    if [ -z "$bad" ]; then
        pass "every heading is one of the six Keep a Changelog types"
    else
        fail "every heading is one of the six Keep a Changelog types" "found:$bad"
    fi
}

# ── 3. Headings appear in the documented order within a section ─────────────
# So a reader who knows the format can scan, and so two PRs adding the same
# type land in the same place.
test_heading_order() {
    local bad
    bad=$(unreleased | awk -v types="$KAC_TYPES" '
        BEGIN { n = split(types, t, " "); for (i = 1; i <= n; i++) rank[t[i]] = i }
        /^### / {
            h = substr($0, 5)
            if (!(h in rank)) next          # test 2 reports unknown types
            if (rank[h] < last) { printf "%s out of order\n", h }
            last = rank[h]
        }
    ')

    if [ -z "$bad" ]; then
        pass "headings follow the Added/Changed/Deprecated/Removed/Fixed/Security order"
    else
        fail "headings follow the Added/Changed/Deprecated/Removed/Fixed/Security order" \
             "in [Unreleased]: $(echo "$bad" | tr '\n' ' ')"
    fi
}

# ── 4. Unreleased exists, is first, and is not empty ────────────────────────
test_unreleased_section() {
    local first
    first=$(grep -m1 '^## ' "$CHANGELOG")
    if [ "$first" != "## [Unreleased]" ]; then
        fail "the first section is [Unreleased]" "found: $first"
        return
    fi
    local bullets
    bullets=$(unreleased | grep -c '^- ')
    if [ "$bullets" -gt 0 ]; then
        pass "[Unreleased] is first and carries $bullets entries"
    else
        fail "[Unreleased] is first and carries entries" "no bullets found"
    fi
}

# ── 5. Links used as pointers must resolve ──────────────────────────────────
# The file leans on relative links into doc/ instead of repeating what those
# documents say. A pointer to a file that has been moved or renamed is worse
# than the duplication it replaced: the reader gets nothing at all.
test_relative_links_resolve() {
    local broken="" target
    while read -r target; do
        [ -n "$target" ] || continue
        [ -e "$ROOT_DIR/${target%%#*}" ] || broken="$broken $target"
    done < <(grep -oE '\]\([A-Za-z0-9_./-]+\.(md|rst)[^)]*\)' "$CHANGELOG" \
             | sed 's/^](//; s/)$//' | sort -u)

    if [ -z "$broken" ]; then
        pass "every relative documentation link resolves"
    else
        fail "every relative documentation link resolves" "missing:$broken"
    fi
}

run_test test_no_duplicate_headings
run_test test_only_known_types
run_test test_heading_order
run_test test_unreleased_section
run_test test_relative_links_resolve

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
