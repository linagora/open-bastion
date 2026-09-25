#!/bin/bash
# test_ob_mutation.sh
#
# Removes each security control in tests/mutation/catalogue, one at a time, and
# requires the suite that guards it to fail.
#
# The campaign that produced this file kept finding the same thing: a test that
# reported success with the control it was written for deleted. A grep matching
# the comment above a rule instead of the rule. An assertion that passed because
# the file it probed did not exist, not because the check refused it. A
# `grep -q` whose SIGPIPE, under pipefail, turned a match into a miss. None of
# those are coverage gaps -- the tests existed, ran, and were green. They were
# simply not testing anything, and nothing said so.
#
# A green suite is evidence only if it can go red. That is the property here,
# and it is checked mechanically rather than remembered.
#
# Two rules the runner enforces on itself, both learned the hard way:
#
#   - a mutation that does not apply is a HARD ERROR, never a pass. A sed that
#     silently matched nothing produced a meaningless "caught" more than once
#     while this was being written by hand;
#   - every file is restored from a copy taken before the run, and the
#     restoration is verified. `git checkout` was used once for this and wiped
#     uncommitted work.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CATALOGUE="${OB_MUTATION_CATALOGUE:-$ROOT_DIR/tests/mutation/catalogue}"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }

[ -f "$CATALOGUE" ] || { echo "  FAIL: no catalogue at $CATALOGUE"; exit 1; }

BACKUP=$(mktemp -d)
RESTORE_LIST=""

# Restore everything, always. A mutant left behind would be committed by the
# next person to run `git add -u`.
CREATED_LIST=""
REBUILD_NEEDED=0
restore_all() {
    local f
    for f in $CREATED_LIST; do rm -f "$ROOT_DIR/$f"; done
    CREATED_LIST=""
    for f in $RESTORE_LIST; do
        [ -f "$BACKUP/$(echo "$f" | tr '/' '_')" ] || continue
        cp "$BACKUP/$(echo "$f" | tr '/' '_')" "$ROOT_DIR/$f"
    done
}
cleanup() {
    restore_all
    # A source restored without a rebuild leaves the MUTATED BINARY in place --
    # invisible, and it would poison every test run on this machine afterwards.
    # An interrupt is exactly when that happens, so it belongs in the trap.
    if [ "$REBUILD_NEEDED" = "1" ] && [ -d "$ROOT_DIR/build" ]; then
        ( cd "$ROOT_DIR" && cmake --build build -j"$(nproc)" ) >/dev/null 2>&1
    fi
    rm -rf "$BACKUP"
}
trap cleanup EXIT INT TERM

backup_file() {
    local f="$1" flat
    flat=$(echo "$f" | tr '/' '_')
    [ -f "$BACKUP/$flat" ] && return 0
    cp "$ROOT_DIR/$f" "$BACKUP/$flat" || return 1
    RESTORE_LIST="$RESTORE_LIST $f"
}

# Apply one mutant with python, so the search text is a literal and the
# occurrence count is checked. Returns non-zero when it does not apply exactly
# once -- which the caller treats as an error, not as a result.
apply_mutant() {
    local file="$1" search="$2" replace="$3"
    python3 - "$ROOT_DIR/$file" "$search" "$replace" <<'PY'
import sys
path, search, replace = sys.argv[1], sys.argv[2], sys.argv[3]
search = search.replace('\\n', '\n')
replace = replace.replace('\\n', '\n')
s = open(path).read()
n = s.count(search)
if n != 1:
    sys.stderr.write("occurrences=%d\n" % n)
    sys.exit(2)
open(path, 'w').write(s.replace(search, replace))
PY
}

echo "=== mutation: every guarded control must be able to fail ==="

id=""; file=""; search=""; replace=""; suite=""; needs=""; create=""
run_stanza() {
    [ -n "$id" ] || return 0
    TESTS_RUN=$((TESTS_RUN + 1))

    # How to run the suite for this entry. Some controls only bite as root (a
    # name that must not reach the filesystem), others only as an ordinary user
    # (an ownership check whose expected owner IS root: as root the check is
    # vacuously satisfied, so removing it changes nothing). Running everything
    # at one privilege level reports the other half as surviving mutants --
    # which is what CI did, for src/ob-fp-daemon.c.
    local as=""

    if [ -z "$create" ] && [ ! -f "$ROOT_DIR/$file" ]; then
        fail "$id" "no such file: $file"
        return
    fi
    if [ ! -f "$ROOT_DIR/$suite" ]; then
        fail "$id" "no such suite: $suite"
        return
    fi

    # The suite must be GREEN before the mutation, or the result means nothing.
    local pre
    # Suites run with stdin on /dev/null: this loop reads the catalogue from
    # its stdin, and a suite that lets something read its own -- script(1)
    # forwards stdin into the session -- silently ate the rest of the
    # catalogue, which then looked like a shorter, all-green run.
    pre=$( cd "$ROOT_DIR" && $as bash "$suite" 2>&1 </dev/null ) || {
        fail "$id" "$suite already fails before the mutation; nothing can be concluded"
        # Say why. Without it a red baseline in CI is a dead end: the main loop
        # stops at this suite, before it reaches the one that failed, and that
        # one's output is printed nowhere.
        grep -E 'FAIL|rror' <<<"$pre" | head -20 | sed 's/^/        | /'
        return
    }
    # And it must actually RUN. A suite that skips exits 0 before and after, so
    # the mutant looks survived when in truth nothing was executed -- a missing
    # dependency reported as a coverage failure. Found in CI, where the job had
    # no socat and the fingerprint-spool suite skipped.
    case "$pre" in
        *SKIP*)
            fail "$id" "$suite SKIPPED here (missing dependency); it can neither confirm nor refute — install what it needs in this job"
            return ;;
    esac

    # An entry that cannot be exercised here must not read as a pass. In CI,
    # where the requirement is met, OB_MUTATION_STRICT makes it an error.
    if [ -n "$needs" ]; then
        case "$needs" in
            nonroot)
                if [ "$(id -u)" = "0" ]; then
                    if command -v setpriv >/dev/null 2>&1; then
                        as="setpriv --reuid=65534 --regid=65534 --clear-groups"
                    elif [ "${OB_MUTATION_STRICT:-0}" = "1" ]; then
                        fail "$id" "needs an unprivileged run and setpriv is unavailable (strict mode)"
                        return
                    else
                        echo "  ---- $id: needs an unprivileged run; not exercised here"
                        TESTS_RUN=$((TESTS_RUN - 1))
                        return
                    fi
                fi ;;
            root)
                if [ "$(id -u)" != "0" ]; then
                    if [ "${OB_MUTATION_STRICT:-0}" = "1" ]; then
                        fail "$id" "needs root and this run is unprivileged (strict mode)"
                    else
                        echo "  ---- $id: needs root to isolate this control; not exercised here"
                        TESTS_RUN=$((TESTS_RUN - 1))
                    fi
                    return
                fi ;;
        esac
    fi

    local rc=0
    if [ -n "$create" ]; then
        # Some controls are "this must not exist". Removing a line cannot express
        # that; creating the thing can.
        if [ -e "$ROOT_DIR/$create" ]; then
            fail "$id" "$create already exists; the mutant would not be a mutation"
            return
        fi
        CREATED_LIST="$CREATED_LIST $create"
        printf '%s\n' "$replace" > "$ROOT_DIR/$create" || {
            fail "$id" "cannot create $create"; return; }
    else
        backup_file "$file" || { fail "$id" "cannot back up $file"; return; }
        apply_mutant "$file" "$search" "$replace" 2>/dev/null || rc=$?
        if [ "$rc" -ne 0 ]; then
            fail "$id" "the mutation does not apply to $file (search text absent or ambiguous) — a mutant that is not applied proves nothing"
            restore_all
            return
        fi
        # A C mutant that is never compiled proves nothing: the suite would run
        # the previous binary and pass for the wrong reason.
        case "$file" in
            *.c|*.h)
                REBUILD_NEEDED=1
                # No build tree: the mutant could not be compiled, so the suite
                # would run the previous binary and pass for the wrong reason.
                # Report it rather than let it look caught.
                if [ ! -d "$ROOT_DIR/build" ]; then
                    if [ "${OB_MUTATION_STRICT:-0}" = "1" ]; then
                        fail "$id" "no build/ directory; a C mutant cannot be compiled (strict mode)"
                    else
                        echo "  ---- $id: no build/ directory; C mutant not exercised here"
                        TESTS_RUN=$((TESTS_RUN - 1))
                    fi
                    restore_all
                    return
                fi
                if ! ( cd "$ROOT_DIR" && cmake --build build -j"$(nproc)" ) >/dev/null 2>&1; then
                    fail "$id" "the mutated tree does not build; cannot conclude"
                    restore_all
                    ( cd "$ROOT_DIR" && cmake --build build -j"$(nproc)" ) >/dev/null 2>&1
                    return
                fi ;;
        esac
    fi

    local src=0
    ( cd "$ROOT_DIR" && $as bash "$suite" ) </dev/null >/dev/null 2>&1 || src=$?
    restore_all
    # Put the real binaries back before judging the next entry.
    case "$file" in
        *.c|*.h) ( cd "$ROOT_DIR" && cmake --build build -j"$(nproc)" ) >/dev/null 2>&1 ;;
    esac

    if [ "$src" -ne 0 ]; then
        pass "$id — $suite catches it"
    else
        fail "$id" "MUTANT SURVIVED: $suite is still green with the control removed ($file)"
        printf '        the control: %s\n' "$search"
    fi
}

while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        ''|\#*) continue ;;
    esac
    key=${line%%'||'*}; val=${line#*'||'}
    key=$(printf '%s' "$key" | tr -d ' \t')
    val=$(printf '%s' "$val" | sed 's/^ *//; s/ *$//')
    case "$key" in
        id)      run_stanza; id="$val"; file=""; search=""; replace=""; suite=""; needs=""; create="" ;;
        file)    file="$val" ;;
        search)  search="$val" ;;
        replace) replace="$val" ;;
        suite)   suite="$val" ;;
        needs)   needs="$val" ;;
        create)  create="$val" ;;
        why)     : ;;
        *)       echo "  (ignoring unknown key '$key')" ;;
    esac
done < "$CATALOGUE"
run_stanza

restore_all
# Prove the tree is as it was: a runner that leaves a mutant behind is worse
# than no runner.
# Verify restoration against the copies taken before each mutation, not against
# git. The backups ARE the ground truth, they are already in hand, and the check
# then works with no repository at all -- which matters: actions/checkout with
# no git preinstalled downloads a tarball, so the container job has no .git and
# the previous git-based check reported "not a git repository" as a failure.
# Reaching for git here was habit; the exact answer was already on disk.
dirty=""
for f in $RESTORE_LIST; do
    flat=$(echo "$f" | tr '/' '_')
    [ -f "$BACKUP/$flat" ] || continue
    cmp -s "$BACKUP/$flat" "$ROOT_DIR/$f" || dirty="$dirty $f"
done
for f in $CREATED_LIST; do
    [ -e "$ROOT_DIR/$f" ] && dirty="$dirty $f(created)"
done
if [ -n "$dirty" ]; then
    echo
    echo "  FAIL: these files are not what they were before the run:$dirty"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
