#!/bin/bash
# test_ob_desktop_packaging.sh
#
# Keeps Desktop SSO out of the open-bastion package (issue #317).
#
# The open-bastion-desktop package existed and the sources were split at
# compile time, yet ob-cache-admin -- which only administers the Desktop SSO
# credential cache -- was installed unconditionally and shipped in
# open-bastion, and so were the man pages of the three Desktop SSO commands.
# Nothing desktop belongs in the certified path, so this test pins it:
#
#   1. CMake installs each Desktop SSO file only under if(INSTALL_DESKTOP);
#   2. debian/open-bastion.install lists none of them, and
#      debian/open-bastion-desktop.install lists them all;
#   3. the same split holds between %files and %files desktop of the RPM;
#   4. open-bastion-desktop Breaks/Replaces the open-bastion that shipped
#      them, or the upgrade fails on a file conflict.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# The Desktop SSO commands; each ships with its section-8 man page.
DESKTOP_COMMANDS="ob-cache-admin ob-desktop-setup ob-session-monitor"

echo "=== Desktop SSO packaging (issue #317) ==="

# ── 1. CMake installs them only under if(INSTALL_DESKTOP) ────────────────────
# Prints every CMakeLists.txt line naming a Desktop SSO file outside an
# if(INSTALL_DESKTOP) block, nested ifs included.
cmake_outside_desktop() {
    awk -v cmds="$DESKTOP_COMMANDS" '
        BEGIN { n = split(cmds, c, " ") }
        {
            line = $0
            sub(/#.*/, "", line)
        }
        line ~ /^[[:space:]]*if[[:space:]]*\(/ {
            depth++
            desk[depth] = (line ~ /^[[:space:]]*if[[:space:]]*\([[:space:]]*INSTALL_DESKTOP[[:space:]]*\)/)
        }
        line ~ /^[[:space:]]*endif[[:space:]]*\(/ { if (depth > 0) depth--; next }
        {
            inside = 0
            for (d = 1; d <= depth; d++) if (desk[d]) inside = 1
            if (inside) next
            for (i = 1; i <= n; i++)
                if (line ~ ("scripts/" c[i] "([[:space:]]|$)") || index(line, c[i] ".8"))
                    print NR ": " $0
        }
    ' "$ROOT_DIR/CMakeLists.txt"
}

test_cmake_installs_desktop_only() {
    local out
    out=$(cmake_outside_desktop)
    if [ -z "$out" ]; then
        pass "CMake installs the Desktop SSO files only with INSTALL_DESKTOP"
    else
        fail "CMake installs Desktop SSO files outside if(INSTALL_DESKTOP)" \
             "$(echo "$out" | tr '\n' ' ')"
    fi
}

# ── 2. Debian: open-bastion-desktop, not open-bastion ────────────────────────
test_debian_split() {
    local core="$ROOT_DIR/debian/open-bastion.install"
    local desk="$ROOT_DIR/debian/open-bastion-desktop.install"
    local bad="" c
    for c in $DESKTOP_COMMANDS; do
        grep -qE "^usr/sbin/$c\$" "$core" && bad="$bad core:$c"
        grep -qE "^usr/share/man/man8/$c\.8\$" "$core" && bad="$bad core:$c.8"
        grep -qE "^usr/sbin/$c\$" "$desk" || bad="$bad missing:$c"
        grep -qE "^usr/share/man/man8/$c\.8\$" "$desk" || bad="$bad missing:$c.8"
    done
    if [ -z "$bad" ]; then
        pass "Debian ships the Desktop SSO commands and man pages in -desktop only"
    else
        fail "Debian .install split is wrong" "$bad"
    fi
}

# ── 3. RPM: %files desktop, not %files ───────────────────────────────────────
# Prints the body of one %files section (main when $1 is empty). A section
# runs to the next section header, not to the next line starting with %.
rpm_files_section() {
    awk -v want="%files${1:+ $1}" '
        /^%(files|package|description|prep|build|check|install|pre|post|preun|postun|posttrans|changelog)([[:space:]]|$)/ {
            infiles = ($0 == want)
            next
        }
        infiles { print }
    ' "$ROOT_DIR/rpm/open-bastion.spec"
}

test_rpm_split() {
    local core desk bad="" c
    core=$(rpm_files_section "")
    desk=$(rpm_files_section desktop)
    for c in $DESKTOP_COMMANDS; do
        grep -qF "%{_sbindir}/$c" <<<"$core" && bad="$bad core:$c"
        grep -qF "%{_mandir}/man8/$c.8" <<<"$core" && bad="$bad core:$c.8"
        grep -qxF "%{_sbindir}/$c" <<<"$desk" || bad="$bad missing:$c"
        grep -qF "%{_mandir}/man8/$c.8" <<<"$desk" || bad="$bad missing:$c.8"
    done
    if [ -z "$core" ] || [ -z "$desk" ]; then
        fail "RPM %files sections found" "could not read them from the spec"
    elif [ -z "$bad" ]; then
        pass "RPM ships the Desktop SSO commands and man pages in desktop only"
    else
        fail "RPM %files split is wrong" "$bad"
    fi
}

# ── 4. The move is declared to dpkg ──────────────────────────────────────────
test_debian_breaks_replaces() {
    local stanza
    stanza=$(awk '/^Package: /{p = ($2 == "open-bastion-desktop")} p' \
                 "$ROOT_DIR/debian/control")
    if grep -qE '^Breaks:.*open-bastion \(<<' <<<"$stanza" \
       && grep -qE '^Replaces:.*open-bastion \(<<' <<<"$stanza"; then
        pass "open-bastion-desktop Breaks/Replaces the older open-bastion"
    else
        fail "open-bastion-desktop Breaks/Replaces the older open-bastion" \
             "files moved from open-bastion would conflict on upgrade"
    fi
}

run_test test_cmake_installs_desktop_only
run_test test_debian_split
run_test test_rpm_split
run_test test_debian_breaks_replaces

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
