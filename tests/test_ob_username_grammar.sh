#!/bin/bash
#
# test_ob_username_grammar.sh - the shell side of the one user-name grammar
#
# The C components share ob_valid_username() (src/str_utils.c). The scripts
# cannot call it, so each carries the same regular expression. This suite
# keeps them in step:
#   - every script that validates a user name uses exactly that expression;
#   - no older grammar is left in the tree;
#   - the expression, and the ob-builder helper that wraps it, give the verdict
#     tests/username_corpus.txt expects on every line -- the corpus that
#     test_username_validator runs through the C function.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="$ROOT_DIR/tests/username_corpus.txt"
# ^[a-z_][a-z0-9_.-]{0,31}$, letters spelled out so the locale cannot widen it.
RE='^[abcdefghijklmnopqrstuvwxyz_][abcdefghijklmnopqrstuvwxyz0123456789_.-]{0,31}$'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$1"; }

# Runs <predicate> on every corpus name and lists the disagreements.
corpus_mismatches() {
    local predicate=$1 verdict name bad="" n=0
    while read -r verdict name; do
        case "$verdict" in ''|'#'*) continue ;; esac
        n=$((n + 1))
        if "$predicate" "$name"; then
            [ "$verdict" = valid ] || bad="$bad [$name accepted]"
        else
            [ "$verdict" = invalid ] || bad="$bad [$name refused]"
        fi
    done <"$CORPUS"
    [ "$n" -gt 0 ] || bad="empty corpus"
    printf '%s' "$bad"
}

matches_re() { [[ "$1" =~ $RE ]]; }

test_scripts_use_the_grammar() {
    local f bad=""
    for f in scripts/ob-session-recorder scripts/ob-service-account-keys \
             scripts/ob-bastion-setup scripts/ob-session-monitor \
             admin-builder/lib/validators.sh; do
        grep -qF -- "=~ $RE ]]" "$ROOT_DIR/$f" || bad="$bad $f"
    done
    if [ -z "$bad" ]; then
        pass "every script that validates a user name uses the same expression"
    else
        fail "every script that validates a user name uses the same expression" "missing in:$bad"
    fi
}

test_no_other_grammar() {
    local hits roots=()
    local d
    for d in scripts admin-builder src nss include tests config doc; do
        roots+=("$ROOT_DIR/$d")
    done
    # The grammar without the dot or without the length bound; a C loop or a
    # shell pattern that refuses every dotted name; the old wording.
    hits=$(grep -rnIE --exclude="$(basename "$0")" --exclude-dir=_build -- \
        '\[a-z_\]\[a-z0-9_-\]|\[a-z0-9_\.-\]\*\$|!a-z0-9_-\]'\
'|== '"'"'/'"'"' \|\| \*p == '"'"'\.'"'"'|\*\.\* *\) *continue'\
'|underscores, and hyphens|underscore, tiret' \
        "${roots[@]}" 2>/dev/null)
    # A shell expression written with a range: the locale can widen it.
    hits+=$(grep -rnIE --exclude="$(basename "$0")" --exclude-dir=_build -- \
        '=~ \^?\[a-z_\]' "${roots[@]}" 2>/dev/null)
    if [ -z "$hits" ]; then
        pass "no other user-name grammar is left in scripts, sources, tests, config or docs"
    else
        fail "no other user-name grammar is left in scripts, sources, tests, config or docs" "$hits"
    fi
}

test_regex_matches_corpus() {
    local bad
    bad=$(corpus_mismatches matches_re)
    if [ -z "$bad" ]; then
        pass "the shell expression agrees with the corpus"
    else
        fail "the shell expression agrees with the corpus" "$bad"
    fi
}

test_builder_matches_corpus() {
    local bad
    # shellcheck source=admin-builder/lib/validators.sh
    . "$ROOT_DIR/admin-builder/lib/validators.sh"
    bad=$(corpus_mismatches is_valid_service_username)
    if [ -z "$bad" ]; then
        pass "ob-builder's is_valid_service_username agrees with the corpus"
    else
        fail "ob-builder's is_valid_service_username agrees with the corpus" "$bad"
    fi
}

echo "User-name grammar (shell side)"
run_test test_scripts_use_the_grammar
run_test test_no_other_grammar
run_test test_regex_matches_corpus
run_test test_builder_matches_corpus

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
