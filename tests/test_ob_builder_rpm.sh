#!/bin/bash
# test_ob_builder_rpm.sh
#
# Guards the CMake builder-rpm target (issue #322): the open-bastion-builder
# RPM lands next to the .deb, at the path the target announces, and the target
# fails when rpmbuild fails or does not write that file.
#
# rpmbuild is replaced by a fake that places its output the way rpmbuild does
# (_rpmdir + _build_name_fmt, default "%{ARCH}/..."), so the test needs no RPM
# tooling.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

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

command -v cmake >/dev/null 2>&1 || { echo "SKIP: cmake is required"; exit 0; }
[ -f "$ROOT_DIR/admin-builder/rpm/open-bastion-builder.spec.in" ] \
    || { echo "SKIP: admin-builder/ tree not present"; exit 0; }

VERSION=$(sed -n 's/^project(open-bastion VERSION \([0-9.]*\).*/\1/p' "$ROOT_DIR/CMakeLists.txt")
PKG="open-bastion-builder"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

FAKE="$WORK/rpmbuild"
cat > "$FAKE" <<'EOF'
#!/bin/bash
# FAKE_DIST: value of %{?dist}. FAKE_MODE: ok | fail | silent.
echo "$*" >> "${FAKE_LOG:-/dev/null}"
if [ "${1:-}" = "--eval" ]; then
    [ "$2" = "%{?dist}" ] && echo "${FAKE_DIST:-}"
    exit 0
fi
case "${FAKE_MODE:-ok}" in
    fail) echo "error: fake rpmbuild failure" >&2; exit 1 ;;
    silent) exit 0 ;;
esac
rpmdir="" fmt='%{ARCH}/%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' spec=""
while [ $# -gt 0 ]; do
    case "$1" in
        --define)
            case "$2" in
                "_rpmdir "*) rpmdir=${2#_rpmdir } ;;
                "_build_name_fmt "*) fmt=${2#_build_name_fmt } ;;
            esac
            shift 2 ;;
        -bb) spec=$2; shift 2 ;;
        *) shift ;;
    esac
done
name=$(sed -n 's/^Name: *//p' "$spec")
version=$(sed -n 's/^Version: *//p' "$spec")
fmt=${fmt//%%/%}
fmt=${fmt//%\{NAME\}/$name}
fmt=${fmt//%\{VERSION\}/$version}
fmt=${fmt//%\{RELEASE\}/1${FAKE_DIST:-}}
fmt=${fmt//%\{ARCH\}/noarch}
mkdir -p "$(dirname "$rpmdir/$fmt")"
echo fake-rpm > "$rpmdir/$fmt"
echo "Wrote: $rpmdir/$fmt"
EOF
chmod 0755 "$FAKE"

# configure <build dir> <dist>
configure() {
    FAKE_DIST="$2" cmake -S "$ROOT_DIR" -B "$1" \
        -DBUILD_TESTING=OFF -DBUILD_MAN=OFF -DBUILD_DOC=OFF \
        -DRPMBUILD_EXECUTABLE="$FAKE" >"$1.configure.log" 2>&1
}

# build <build dir> <dist> <mode>
build() {
    FAKE_DIST="$2" FAKE_MODE="$3" FAKE_LOG="$1.rpmbuild.log" \
        cmake --build "$1" --target builder-rpm >"$1.build.log" 2>&1
}

B="$WORK/b"
if ! configure "$B" ""; then
    echo "SKIP: cannot configure the project (missing build dependencies?)"
    tail -5 "$B.configure.log"
    exit 0
fi

echo "=== CMake builder-rpm target (issue #322) ==="

test_rpm_next_to_deb() {
    local want="$B/$PKG-$VERSION-1.noarch.rpm"
    if ! build "$B" "" ok; then
        fail "builder-rpm succeeds with a working rpmbuild" "$(tail -3 "$B.build.log")"
        return
    fi
    if [ -f "$want" ]; then
        pass "the RPM is written at $(basename "$want") in the build directory"
    else
        fail "the RPM is written at $(basename "$want") in the build directory" \
            "$(cd "$B" && find . -name '*.rpm')"
    fi
}

test_no_host_rpmdb() {
    if grep -q -- '-bb' "$B.rpmbuild.log" && grep -- '-bb' "$B.rpmbuild.log" | grep -q -- '--nodeps'; then
        pass "rpmbuild does not check build dependencies against the host rpmdb"
    else
        fail "rpmbuild does not check build dependencies against the host rpmdb" \
            "$(cat "$B.rpmbuild.log")"
    fi
}

test_dist_in_file_name() {
    local d="$WORK/el" want
    want="$d/$PKG-$VERSION-1.el9.noarch.rpm"
    if ! configure "$d" ".el9" || ! build "$d" ".el9" ok; then
        fail "builder-rpm succeeds when %{?dist} is set" "$(tail -3 "$d.build.log" 2>/dev/null)"
        return
    fi
    if [ -f "$want" ]; then
        pass "the RPM file name carries %{?dist} ($(basename "$want"))"
    else
        fail "the RPM file name carries %{?dist} ($(basename "$want"))" \
            "$(cd "$d" && find . -name '*.rpm')"
    fi
}

test_rpmbuild_failure_fails_build() {
    if build "$B" "" fail; then
        fail "a failing rpmbuild fails the build"
    else
        pass "a failing rpmbuild fails the build"
    fi
}

# Runs after test_rpm_next_to_deb: a stale RPM from the previous build must not
# satisfy the check.
test_missing_output_fails_build() {
    if build "$B" "" silent; then
        fail "rpmbuild exiting 0 without writing the RPM fails the build"
    else
        pass "rpmbuild exiting 0 without writing the RPM fails the build"
    fi
}

run_test test_rpm_next_to_deb
run_test test_no_host_rpmdb
run_test test_dist_in_file_name
run_test test_rpmbuild_failure_fails_build
run_test test_missing_output_fails_build

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
