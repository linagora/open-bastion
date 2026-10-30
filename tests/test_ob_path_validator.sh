#!/bin/bash
# Runs the path validator unit tests (tests/test_path_validator.c).
#
# The assertions live in C, next to the other unit tests, and ctest runs them
# directly. This wrapper exists because tests/mutation/catalogue names its
# suites as shell scripts: the mutation runner rebuilds the tree after applying
# a C mutant and then executes `bash <suite>`.
#
# It fails rather than skips when the binary is missing: a skip would let the
# mutation runner conclude the control is covered when nothing ran at all.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${OB_BUILD_DIR:-$ROOT_DIR/build}/tests/test_path_validator"

echo "=== path validator ==="

if [ ! -x "$BIN" ]; then
    echo "  FAIL: $BIN is not built; configure and build the tree first"
    exit 1
fi

exec "$BIN"
