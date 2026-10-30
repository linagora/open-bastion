#!/bin/bash
# Runs the CrowdSec whitelist parser tests (tests/test_crowdsec.c).
#
# The assertions live in C, next to the other unit tests, and ctest runs them
# directly. This wrapper exists because tests/mutation/catalogue names its
# suites as shell scripts: the mutation runner rebuilds the tree after applying
# a C mutant and then executes `bash <suite>`, so the entry for the whitelist
# prefix needs one.
#
# It fails rather than skips when the binary is missing: a skip would let the
# mutation runner conclude the control is covered when nothing ran at all.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${OB_BUILD_DIR:-$ROOT_DIR/build}/tests/test_crowdsec"

echo "=== crowdsec whitelist parsing ==="

if [ ! -x "$BIN" ]; then
    echo "  FAIL: $BIN is not built; configure and build the tree first"
    exit 1
fi

exec "$BIN"
