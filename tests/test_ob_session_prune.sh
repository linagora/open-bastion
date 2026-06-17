#!/bin/bash
# Unit tests for ob-session-prune (session-recording retention).
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
SCRIPT_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"
PRUNE="$SCRIPT_DIR/ob-session-prune"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# Source the script body so its functions can be called in-process, dropping the
# trailing `main "$@"` and the `set -e` line (mirrors the other ob-* tests).
source_prune() {
    local content
    content=$(cat "$PRUNE")
    content="${content%main \"\$@\"}"
    content=$(echo "$content" | sed -E 's/^set -euo pipefail$//')
    eval "$content"
}

# Write a recorder-style config pointing at $1, with compress/retention $2/$3.
make_conf() {
    local dir="$1" comp="$2" ret="$3" conf
    conf=$(mktemp)
    cat > "$conf" <<EOF
sessions_dir = $dir
recording_compress_after_days = $comp
recording_retention_days = $ret
EOF
    echo "$conf"
}

# Build a recordings tree: alice/recent (now) + alice/mid (3d) + bob/old (400d),
# each as a <name>.typescript payload and a <name>.json metadata file.
seed_tree() {
    local root="$1"
    mkdir -p "$root/alice" "$root/bob"
    : > "$root/alice/recent.typescript"; : > "$root/alice/recent.json"
    : > "$root/alice/mid.typescript";    : > "$root/alice/mid.json"
    : > "$root/bob/old.typescript";      : > "$root/bob/old.json"
    touch -d '3 days ago'   "$root/alice/mid.typescript" "$root/alice/mid.json"
    touch -d '400 days ago' "$root/bob/old.typescript"   "$root/bob/old.json"
}

# Run main() against $1 (sessions dir) with compress=$2 / retention=$3, in a
# subshell so the script's exit calls don't abort the test. stat() is overridden
# to fake a root-owned config (the tests run unprivileged). Returns main's rc.
prune_tree() {
    local conf; conf=$(make_conf "$1" "$2" "$3")
    (
        source_prune
        stat() { echo "0:644"; }   # simulate root-owned, 0644 config
        CONFIG_FILE="$conf"
        main
    )
    local rc=$?
    rm -f "$conf"
    return $rc
}

# ── Syntax ──
test_syntax() {
    if bash -n "$PRUNE" 2>/dev/null; then pass "Syntax check"; else fail "Syntax check"; fi
}

# ── Config parsing ──
test_load_config() {
    local conf; conf=$(make_conf "/var/lib/open-bastion/sessions" 2 30)
    (
        source_prune
        stat() { echo "0:644"; }
        CONFIG_FILE="$conf"
        load_config
        [ "$SESSIONS_DIR" = "/var/lib/open-bastion/sessions" ] \
            && [ "$COMPRESS_AFTER_DAYS" = "2" ] \
            && [ "$RETENTION_DAYS" = "30" ]
    )
    local rc=$?
    rm -f "$conf"
    [ $rc -eq 0 ] && pass "load_config parses sessions_dir/compress/retention" \
                  || fail "load_config parses sessions_dir/compress/retention"
}

test_is_uint() {
    ( source_prune; is_uint 0 && is_uint 365 && ! is_uint "" && ! is_uint "-1" && ! is_uint "x" )
    [ $? -eq 0 ] && pass "is_uint accepts integers, rejects junk" \
                 || fail "is_uint accepts integers, rejects junk"
}

# ── Compression stage ──
test_compress_old_keeps_recent() {
    local base root; base=$(mktemp -d); root="$base/sessions"; seed_tree "$root"
    prune_tree "$root" 1 0   # compress >1d, no deletion
    local ok=true
    [ -e "$root/bob/old.typescript.gz" ]      || ok=false   # 400d compressed
    [ ! -e "$root/bob/old.typescript" ]       || ok=false
    [ -e "$root/alice/mid.typescript.gz" ]    || ok=false   # 3d compressed
    [ -e "$root/alice/recent.typescript" ]    || ok=false   # today: untouched
    [ ! -e "$root/alice/recent.typescript.gz" ] || ok=false
    [ -e "$root/bob/old.json" ]               || ok=false   # .json never compressed
    [ ! -e "$root/bob/old.json.gz" ]          || ok=false
    rm -rf "$base"
    $ok && pass "compress: old payloads gzipped, recent and .json untouched" \
        || fail "compress: old payloads gzipped, recent and .json untouched"
}

test_compress_disabled() {
    local base root; base=$(mktemp -d); root="$base/sessions"; seed_tree "$root"
    prune_tree "$root" 0 0   # compression disabled
    local ok=true
    [ -e "$root/bob/old.typescript" ]    || ok=false
    [ ! -e "$root/bob/old.typescript.gz" ] || ok=false
    rm -rf "$base"
    $ok && pass "compress disabled (0) leaves payloads as-is" \
        || fail "compress disabled (0) leaves payloads as-is"
}

# ── Retention stage ──
test_retention_deletes_old() {
    local base root; base=$(mktemp -d); root="$base/sessions"; seed_tree "$root"
    prune_tree "$root" 0 365   # delete >365d, no compression
    local ok=true
    [ ! -e "$root/bob/old.typescript" ]    || ok=false   # 400d deleted (payload)
    [ ! -e "$root/bob/old.json" ]          || ok=false   # 400d deleted (.json)
    [ ! -d "$root/bob" ]                   || ok=false   # emptied dir removed
    [ -e "$root/alice/recent.typescript" ] || ok=false   # today kept
    [ -e "$root/alice/mid.typescript" ]    || ok=false   # 3d kept
    [ -d "$root" ]                         || ok=false   # root never removed
    rm -rf "$base"
    $ok && pass "retention: >365d deleted (payload+json), empty dir pruned, recent kept" \
        || fail "retention: >365d deleted (payload+json), empty dir pruned, recent kept"
}

test_retention_zero_keeps_forever() {
    local base root; base=$(mktemp -d); root="$base/sessions"; seed_tree "$root"
    prune_tree "$root" 0 0   # retention disabled
    local ok=true
    [ -e "$root/bob/old.typescript" ] || ok=false   # even 400d survives
    [ -e "$root/bob/old.json" ]       || ok=false
    rm -rf "$base"
    $ok && pass "retention 0 keeps recordings forever" \
        || fail "retention 0 keeps recordings forever"
}

# ── Safety guards ──
test_guard_rejects_relative() {
    local conf; conf=$(make_conf "relative/sessions" 1 365)
    ( source_prune; stat() { echo "0:644"; }; CONFIG_FILE="$conf"; main ) 2>/dev/null
    local rc=$?
    rm -f "$conf"
    [ $rc -ne 0 ] && pass "guard refuses a non-absolute sessions_dir" \
                  || fail "guard refuses a non-absolute sessions_dir"
}

test_guard_rejects_root() {
    local conf; conf=$(make_conf "/" 1 365)
    ( source_prune; stat() { echo "0:644"; }; CONFIG_FILE="$conf"; main ) 2>/dev/null
    local rc=$?
    rm -f "$conf"
    [ $rc -ne 0 ] && pass "guard refuses sessions_dir = /" \
                  || fail "guard refuses sessions_dir = /"
}

test_missing_tree_noop() {
    prune_tree "/tmp/ob-prune-absent-$$/sessions" 1 365 2>/dev/null
    [ $? -eq 0 ] && pass "missing recordings tree is a clean no-op" \
                 || fail "missing recordings tree is a clean no-op"
}

# ── Run ──
echo "=== Testing ob-session-prune ==="
run_test test_syntax
run_test test_load_config
run_test test_is_uint
run_test test_compress_old_keeps_recent
run_test test_compress_disabled
run_test test_retention_deletes_old
run_test test_retention_zero_keeps_forever
run_test test_guard_rejects_relative
run_test test_guard_rejects_root
run_test test_missing_tree_noop

echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
