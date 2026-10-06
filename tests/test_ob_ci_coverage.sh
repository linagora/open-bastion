#!/bin/bash
# test_ob_ci_coverage.sh
#
# Fails when a test file exists that CI never runs.
#
# tests/test_backend_cert_acceptance.sh was broken for the length of a whole
# branch and nothing noticed: the build job loops over `tests/test_ob_*.sh`,
# this file does not match that glob, and no job named it. It is the e2e guard
# for "a backend accepts a hop only from its allowlisted bastion" -- a security
# property -- and it was exiting 1 in silence.
#
# A test nobody runs is worse than a missing one: it looks like coverage on the
# list, in review, and in an audit. So the rule is mechanical -- every
# tests/test_*.sh is either matched by the loop or named in the workflow.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CI="$ROOT_DIR/.github/workflows/ci.yml"

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

[ -f "$CI" ] || { echo "SKIP: no $CI"; exit 0; }

echo "=== every test is reachable from CI ==="

# The glob the build job loops over. Read it from the workflow rather than
# hard-coding it, so narrowing the loop shows up here instead of silently
# orphaning half the suite.
loop_glob() {
    sed -n 's|.*for test in tests/\(test[A-Za-z_*]*\.sh\); do.*|\1|p' "$CI" | head -1
}

# Files the loop skips (`case "$test" in tests/a.sh|tests/b.sh) continue`).
# They match the glob but the loop does not run them, so another job must.
loop_skips() {
    # shellcheck disable=SC2016  # $test is literal text in ci.yml
    sed -n 's|.*case "\$test" in \(.*\)) continue.*|\1|p' "$CI" \
        | tr '|' '\n' | sed 's|^ *tests/||; s| *$||'
}

test_no_orphan_shell_tests() {
    local glob skips orphans="" f b
    glob=$(loop_glob)
    skips=$(loop_skips)
    if [ -z "$glob" ]; then
        fail "the workflow still loops over a tests/ glob" \
             "could not find 'for test in tests/...' in ci.yml"
        return
    fi
    for f in "$ROOT_DIR"/tests/test_*.sh; do
        [ -f "$f" ] || continue
        b=$(basename "$f")
        if printf '%s\n' "$skips" | grep -qxF "$b"; then
            grep -qE "bash[[:space:]]+tests/$b" "$CI" || orphans="$orphans $b"
            continue
        fi
        # shellcheck disable=SC2254  # the glob is data, and must stay unquoted
        case "$b" in
            $glob) continue ;;
        esac
        grep -q "$b" "$CI" || orphans="$orphans $b"
    done
    if [ -z "$orphans" ]; then
        pass "no test file is left unrun (loop: tests/$glob, plus those named in ci.yml)"
    else
        fail "no test file is left unrun" \
             "never executed by any job:$orphans"
    fi
}

# The C side has the same failure mode: a test built but never registered with
# ctest runs nowhere.
test_no_orphan_c_tests() {
    local cm="$ROOT_DIR/tests/CMakeLists.txt" orphans="" f b
    [ -f "$cm" ] || { pass "(no tests/CMakeLists.txt)"; return; }
    for f in "$ROOT_DIR"/tests/test_*.c; do
        [ -f "$f" ] || continue
        b=$(basename "$f" .c)
        grep -q "$b" "$cm" || orphans="$orphans $b"
    done
    if [ -z "$orphans" ]; then
        pass "every tests/test_*.c is referenced by tests/CMakeLists.txt"
    else
        fail "every tests/test_*.c is referenced by tests/CMakeLists.txt" "$orphans"
    fi
}

# The packages build with INSTALL_DESKTOP=ON, and so does every job that ran
# ctest: a build without Desktop SSO compiled but was never tested, which is how
# the authorization cache went unwritten there unnoticed (#318). Some job must
# configure without INSTALL_DESKTOP=ON and run ctest on that tree (#321).
test_ctest_without_desktop() {
    local jobs
    jobs=$(awk '
        /^jobs:/ { injobs = 1; next }
        !injobs { next }
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            if (job != "" && cfg && ctest && !desk) print job
            job = $1; sub(/:$/, "", job); cfg = ctest = desk = 0
            next
        }
        { line = $0; sub(/#.*/, "", line) }
        line ~ /cmake[[:space:]]+-B/ { cfg = 1 }
        line ~ /INSTALL_DESKTOP=ON/ { desk = 1 }
        line ~ /(^|[[:space:]])ctest([[:space:]]|$)/ { ctest = 1 }
        END { if (job != "" && cfg && ctest && !desk) print job }
    ' "$CI")
    if [ -n "$jobs" ]; then
        pass "ctest runs on a build without Desktop SSO (job: ${jobs//$'\n'/ })"
    else
        fail "ctest runs on a build without Desktop SSO" \
             "every job that runs ctest configures with INSTALL_DESKTOP=ON"
    fi
}

run_test test_no_orphan_shell_tests
run_test test_no_orphan_c_tests
run_test test_ctest_without_desktop

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
