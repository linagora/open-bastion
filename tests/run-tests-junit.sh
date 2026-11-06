#!/bin/bash
# run-tests-junit.sh -- run the whole suite and write JUnit evidence.
#
# Writes two files, each naming the commit under test and carrying a UTC
# timestamp:
#
#   ctest.xml        the C tests, as `ctest --output-junit` writes them
#   shell-tests.xml  one testcase per tests/test_ob_*.sh suite
#
# tests/test_ob_mutation.sh is left out: it needs root, rewrites the tree and
# takes tens of minutes. The mutation job runs it on its own.
#
# Usage: tests/run-tests-junit.sh [OPTIONS] [-- CTEST_ARGUMENTS...]
#
#   -b, --build-dir DIR   build tree to test (default: build)
#   -o, --output-dir DIR  where to write the XML files
#                         (default: BUILD_DIR/test-results)
#       --no-ctest        do not run the C tests
#       --no-shell        do not run the shell suites
#   -h, --help
#
# Arguments after `--` go to ctest, for a local `-R` or `-j`. ctest always
# runs with --output-on-failure.
#
# OB_TEST_COMMIT overrides the recorded commit, for a tree without .git (a
# source tarball, or rpmbuild's SOURCES).
#
# Needs ctest 3.21 or newer for --output-junit.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
    sed -n '2,/^set -u/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

die() { echo "run-tests-junit: $*" >&2; exit 2; }

BUILD_DIR="$ROOT_DIR/build"
OUTPUT_DIR=""
RUN_CTEST=1
RUN_SHELL=1
CTEST_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--build-dir)
            [ $# -ge 2 ] || die "$1 needs a directory"
            BUILD_DIR="$2"; shift 2 ;;
        -o|--output-dir)
            [ $# -ge 2 ] || die "$1 needs a directory"
            OUTPUT_DIR="$2"; shift 2 ;;
        --no-ctest) RUN_CTEST=0; shift ;;
        --no-shell) RUN_SHELL=0; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; CTEST_ARGS=("$@"); break ;;
        -*) die "unknown option: $1 (put ctest arguments after --)" ;;
        *) die "unexpected argument: $1 (put ctest arguments after --)" ;;
    esac
done

command -v iconv >/dev/null 2>&1 || die "iconv is required"

[ -d "$BUILD_DIR" ] || die "no build tree at $BUILD_DIR (configure and build it first)"
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
[ -n "$OUTPUT_DIR" ] || OUTPUT_DIR="$BUILD_DIR/test-results"
mkdir -p "$OUTPUT_DIR" || die "cannot create $OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# The shell suites are named relative to the tree, so the runner works from
# any directory, not only the repository root.
cd "$ROOT_DIR" || die "cannot enter $ROOT_DIR"

git_repo() { git -C "$ROOT_DIR" "$@" 2>/dev/null; }

# A source tarball unpacked inside another repository must not be reported as
# that repository's commit: only a checkout whose top level is ROOT_DIR counts.
GIT_TREE=0
if git_repo rev-parse --git-dir >/dev/null \
   && [ -z "$(git_repo rev-parse --show-prefix)" ]; then
    GIT_TREE=1
fi

if [ -n "${OB_TEST_COMMIT:-}" ]; then
    # An explicit commit wins over HEAD: describing HEAD here would name a
    # different commit than the one the report claims was tested.
    GIT_COMMIT="$OB_TEST_COMMIT"
    GIT_DESCRIBE="$OB_TEST_COMMIT"
    GIT_DIRTY=unknown
elif [ "$GIT_TREE" = 1 ]; then
    GIT_COMMIT="$(git_repo rev-parse HEAD)"
    # --match keeps `git describe` on the project's own tags; the tree also
    # carries plugin tags such as plugins-v0.6.1, which name another component.
    GIT_DESCRIBE="$(git_repo describe --tags --always --dirty --match 'v[0-9]*')" \
        || GIT_DESCRIBE="$GIT_COMMIT"
    # Untracked files are ignored, as they are by `describe --dirty` above, so
    # the two do not contradict each other.
    if [ -n "$(git_repo status --porcelain --untracked-files=no)" ]; then
        GIT_DIRTY=true
    else
        GIT_DIRTY=false
    fi
else
    GIT_COMMIT="${GITHUB_SHA:-unknown}"
    GIT_DESCRIBE="$GIT_COMMIT"
    GIT_DIRTY=unknown
fi

RUN_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Through sed rather than ${var//} because bash 5.2+ expands `&` in the
# replacement to the matched text, which would turn `<` into `<lt;`.
xml_attr() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&apos;/g"
}

# Test output may carry ANSI colour codes (the Ansible suites), control bytes
# and raw binary (key material, recordings), none of which is valid in XML 1.0.
# iconv -c drops invalid UTF-8 sequences rather than letting them poison the
# report, which matters most when a suite fails on binary data. The UTF-16LE
# round trip is what rejects the 5/6-byte forms above U+10FFFF, which glibc's
# UTF-8 to UTF-8 conversion passes through.
xml_text() {
    local esc
    esc=$(printf '\033')
    LC_ALL=C sed -e "s/${esc}\[[0-9;?]*[A-Za-z]//g" "$1" \
        | LC_ALL=C tr -d '\000-\010\013\014\016-\037' \
        | iconv -f UTF-8 -t UTF-16LE -c 2>/dev/null \
        | iconv -f UTF-16LE -t UTF-8 -c 2>/dev/null \
        | LC_ALL=C sed \
            -e 's/\xEF\xBF\xBE//g' -e 's/\xEF\xBF\xBF//g' \
            -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# xmllint is optional locally, installed in CI, where a malformed report must
# fail the run rather than be uploaded as evidence.
validate_report() {
    local file=$1
    command -v xmllint >/dev/null 2>&1 || return 0
    xmllint --noout "$file" 2>/dev/null && return 0
    echo "run-tests-junit: $file is not well-formed XML" >&2
    return 1
}

seconds() { awk -v ns="$1" 'BEGIN { printf "%.3f", ns / 1000000000 }'; }

# ctest knows the commit of nothing, and its timestamp attribute is local time.
# Add the commit, and the run time in UTC, as testsuite properties.
annotate_ctest_xml() {
    local xml="$OUTPUT_DIR/ctest.xml" tmp
    tmp=$(mktemp) || return 1
    if ! awk \
        -v commit="$(xml_attr "$GIT_COMMIT")" \
        -v describe="$(xml_attr "$GIT_DESCRIBE")" \
        -v dirty="$(xml_attr "$GIT_DIRTY")" \
        -v stamp="$(xml_attr "$RUN_TIMESTAMP")" '
        function properties() {
            print "\t<properties>"
            print "\t\t<property name=\"git.commit\" value=\"" commit "\"/>"
            print "\t\t<property name=\"git.describe\" value=\"" describe "\"/>"
            print "\t\t<property name=\"git.dirty\" value=\"" dirty "\"/>"
            print "\t\t<property name=\"run.timestamp\" value=\"" stamp "\"/>"
            print "\t</properties>"
        }
        !inserted && /^[[:space:]]*<testsuite([[:space:]]|>)/ { in_suite = 1 }
        in_suite && !inserted && /\/>[[:space:]]*$/ {
            # No test matched: ctest closes the testsuite on its own line.
            sub(/\/>[[:space:]]*$/, ">")
            print
            properties()
            print "</testsuite>"
            inserted = 1
            next
        }
        { print }
        in_suite && !inserted && />[[:space:]]*$/ {
            properties()
            inserted = 1
        }
        END { if (!inserted) exit 3 }
    ' "$xml" >"$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$xml"
}

ctest_rc=0
ctest_report=""
if [ "$RUN_CTEST" = 1 ]; then
    ctest_report="$OUTPUT_DIR/ctest.xml"
    echo "=== C tests (JUnit: $ctest_report) ==="
    rm -f "$ctest_report"
    ( cd "$BUILD_DIR" && \
      ctest --output-junit "$ctest_report" --output-on-failure "${CTEST_ARGS[@]}" ) \
        || ctest_rc=$?
    if [ ! -f "$ctest_report" ]; then
        echo "run-tests-junit: ctest wrote no JUnit report" >&2
        ctest_rc=1
    elif ! annotate_ctest_xml; then
        echo "run-tests-junit: cannot add the commit to $ctest_report" >&2
        ctest_rc=1
    elif ! validate_report "$ctest_report"; then
        ctest_rc=1
    fi
    if [ -f "$ctest_report" ]; then
        # ctest writes 0600; the report is meant to be read and archived.
        chmod 0644 "$ctest_report" 2>/dev/null || true
        if ! grep -q '<testcase' "$ctest_report"; then
            echo "run-tests-junit: ctest ran no test" >&2
            ctest_rc=1
        fi
    fi
fi

shell_rc=0
shell_report=""
if [ "$RUN_SHELL" = 1 ]; then
    shell_report="$OUTPUT_DIR/shell-tests.xml"
    echo "=== Shell test suites (JUnit: $shell_report) ==="

    fragments=$(mktemp) || die "cannot create a temporary file"
    trap 'rm -f "$fragments"' EXIT

    tests=0
    failures=0
    skipped=0
    total_ns=0

    for test in tests/test_ob_*.sh; do
        [ -f "$ROOT_DIR/$test" ] || continue
        name=${test##*/}
        case "$test" in tests/test_ob_mutation.sh) continue ;; esac

        log=$(mktemp) || die "cannot create a temporary file"
        start=$(date +%s%N)
        OB_BUILD_DIR="$BUILD_DIR" bash "$test" >"$log" 2>&1
        rc=$?
        end=$(date +%s%N)
        elapsed=$((end - start))
        total_ns=$((total_ns + elapsed))
        tests=$((tests + 1))

        # The suites exit 0 after printing SKIP when a dependency is missing.
        # A suite that also reports a pass ran, and is not a skip. Match the
        # substrings: the pass lines are `  PASS: x`, `2/2 passed`, or `ok`,
        # sometimes wrapped in ANSI colour codes.
        status=pass
        if [ "$rc" -eq 77 ]; then
            status=skip
        elif [ "$rc" -ne 0 ]; then
            status=fail
        elif grep -q 'SKIP' "$log" \
             && ! grep -qE 'PASS|passed|(^|[[:space:]])ok([[:space:]]|$)' "$log"; then
            status=skip
        fi

        case "$status" in
            skip)
                skipped=$((skipped + 1))
                echo "  SKIP  $name" ;;
            fail)
                failures=$((failures + 1))
                shell_rc=1
                echo "  FAIL  $name (exit $rc)"
                cat "$log" ;;
            *)
                echo "  PASS  $name" ;;
        esac

        {
            printf '\t<testcase name="%s" classname="shell" time="%s">\n' \
                "$(xml_attr "$name")" "$(seconds "$elapsed")"
            case "$status" in
                skip) printf '\t\t<skipped message="skipped"/>\n' ;;
                fail) printf '\t\t<failure message="exit status %s"/>\n' "$rc" ;;
            esac
            printf '\t\t<system-out>\n'
            xml_text "$log"
            printf '\t\t</system-out>\n'
            printf '\t</testcase>\n'
        } >>"$fragments"

        rm -f "$log"
    done

    if [ "$tests" -eq 0 ]; then
        echo "run-tests-junit: no tests/test_ob_*.sh suite found under $ROOT_DIR" >&2
        shell_rc=1
    fi

    tmp="$OUTPUT_DIR/shell-tests.xml.tmp"
    if ! {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        printf '<testsuite name="open-bastion shell tests" tests="%s" failures="%s" errors="0" skipped="%s" time="%s" timestamp="%s">\n' \
            "$tests" "$failures" "$skipped" "$(seconds "$total_ns")" "$(xml_attr "$RUN_TIMESTAMP")"
        printf '\t<properties>\n'
        printf '\t\t<property name="git.commit" value="%s"/>\n' "$(xml_attr "$GIT_COMMIT")"
        printf '\t\t<property name="git.describe" value="%s"/>\n' "$(xml_attr "$GIT_DESCRIBE")"
        printf '\t\t<property name="git.dirty" value="%s"/>\n' "$(xml_attr "$GIT_DIRTY")"
        printf '\t\t<property name="run.timestamp" value="%s"/>\n' "$(xml_attr "$RUN_TIMESTAMP")"
        printf '\t</properties>\n'
        cat "$fragments"
        echo '</testsuite>'
    } >"$tmp"; then
        rm -f "$tmp"
        echo "run-tests-junit: cannot write $shell_report" >&2
        shell_rc=1
    elif ! mv "$tmp" "$shell_report"; then
        rm -f "$tmp"
        echo "run-tests-junit: cannot replace $shell_report" >&2
        shell_rc=1
    elif ! validate_report "$shell_report"; then
        shell_rc=1
    fi

    echo "  $tests suite(s), $((tests - failures - skipped)) passed, $failures failed, $skipped skipped"
fi

status=0
[ "$ctest_rc" -ne 0 ] && status="$ctest_rc"
[ "$shell_rc" -ne 0 ] && status=1

echo
echo "Reports:"
[ -n "$ctest_report" ] && echo "  $ctest_report"
[ -n "$shell_report" ] && echo "  $shell_report"
exit "$status"
