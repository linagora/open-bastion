#!/bin/bash
# Runs the C suites that prove request_signing_secret and cert_pin reach the
# portal clients built from openbastion.conf (#332): the PAM module's client
# (tests/test_ob_client_signed.c) and libnss_openbastion
# (tests/test_nss_signed.c).
#
# The assertions live in C and ctest runs them directly. This wrapper exists
# because tests/mutation/catalogue names its suites as shell scripts: the
# mutation runner rebuilds the tree after applying a C mutant and then executes
# `bash <suite>`.
#
# It fails rather than skips when a binary is missing: a skip would let the
# mutation runner conclude the control is covered when nothing ran at all.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${OB_BUILD_DIR:-$ROOT_DIR/build}"

echo "=== portal clients: signed and pinned requests (#332) ==="

rc=0
for bin in test_ob_client_signed test_nss_signed; do
    if [ ! -x "$BUILD/tests/$bin" ]; then
        echo "  FAIL: $BUILD/tests/$bin is not built; configure and build the tree first"
        rc=1
        continue
    fi
    # Both start an in-process portal; a hang there must fail, not wait forever.
    timeout 120 "$BUILD/tests/$bin"
    r=$?
    [ "$r" -eq 124 ] && echo "  FAIL: $bin timed out"
    [ "$r" -ne 0 ] && rc=1
done
exit "$rc"
