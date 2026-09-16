#!/bin/bash
# Runs the key-file refusal tests (tests/test_cache_key.c).
#
# The assertions live in C, next to the other unit tests, and ctest runs them
# directly. This wrapper exists because tests/mutation/catalogue names its
# suites as shell scripts: the mutation runner rebuilds the tree after applying
# a C mutant and then executes `bash <suite>`, so the entries for the key-file
# checks need one.
#
# The timeout is not decoration. read_key_file() opens the key file with
# O_NONBLOCK precisely so that a fifo left at that path is refused rather than
# parking the caller until a writer shows up; remove it and the suite HANGS
# instead of failing, and the mutation runner would wait forever. A hang is
# reported here as the failure it is.
#
# It fails rather than skips when the binary is missing: a skip would let the
# mutation runner conclude the control is covered when nothing ran at all.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${OB_BUILD_DIR:-$ROOT_DIR/build}/tests/test_cache_key"

echo "=== offline cache key file: what is refused (#268) ==="

if [ ! -x "$BIN" ]; then
    echo "  FAIL: $BIN is not built; configure and build the tree first"
    exit 1
fi

timeout 60 "$BIN"
rc=$?
if [ "$rc" -eq 124 ]; then
    echo "  FAIL: the suite timed out — read_key_file() is blocking on the fifo"
fi
exit "$rc"
