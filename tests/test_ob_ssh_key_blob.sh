#!/bin/bash
# test_ob_ssh_key_blob.sh
#
# An ECDSA key blob that contradicts itself is refused (issue #401).
#
# The SSH key policy takes the size of an ECDSA key from its type name: for
# ecdsa-sha2-nistp384, 384. The blob also carries the curve name and the public
# point, and the decoder used to check neither, so a blob announcing nistp521
# under an ecdsa-sha2-nistp384 type was accepted and graded as a P-384 key. The
# size then describes material the key does not hold, and ssh_key_min_ecdsa_bits
# is compared against the wrong number. OpenSSH itself refuses such a key
# (sshkey_ecdsa_nid_from_name, SSH_ERR_EC_CURVE_MISMATCH), so the decoder must
# too: it is defence in depth on the spool path, and it is all there is if it is
# ever fed a blob sshd has not parsed.
#
# The unit suite (ctest test_ssh_key_policy) holds the fixtures; this suite
# compiles the decoder against them, so the mutation catalogue can remove the
# check and watch something fail. It also checks the LLNG ssh-ca plugin, whose
# decoder must stay in sync with the C one.

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

if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "SKIP: no C compiler"
    exit 0
fi
CC_BIN=$(command -v cc || command -v gcc)

# Under build/ when there is one: the harness workspace may confine /tmp to a
# single command, and this scratch directory has to outlive the first one.
SCRATCH_BASE="$ROOT_DIR/build"
[ -d "$SCRATCH_BASE" ] || SCRATCH_BASE="${TMPDIR:-/tmp}"
SCRATCH=$(mktemp -d "$SCRATCH_BASE/ob-ssh-key-blob.XXXXXX") \
    || { echo "  FAIL: cannot create a scratch directory"; exit 1; }
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

echo "=== ECDSA key blobs must agree with their own type (issue #401) ==="

# A valid P-256 key, then the same material with a curve name that names
# another curve, a point one byte short, and a compressed point. Every one of
# them is built here rather than committed, so the intent of each byte shows.
build_fixtures() {
    python3 - "$SCRATCH" <<'PY'
import base64, struct, sys
out = sys.argv[1]
point = b'\x04' + bytes(range(1, 65))   # P-256 uncompressed: 0x04 || X || Y
def s(b): return struct.pack('>I', len(b)) + b
def pub(name, algo, blob):
    open(f'{out}/{name}.b64', 'w').write(base64.b64encode(s(algo.encode()) + blob).decode())
t256, t384 = 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384'
pub('ok',           t256, s(b'nistp256') + s(point))
pub('wrong_curve',  t256, s(b'nistp384') + s(point))
pub('wrong_curve2', t384, s(b'nistp521') + s(point))
pub('short_point',  t256, s(b'nistp256') + s(point[:-1]))
pub('compressed',   t256, s(b'nistp256') + s(bytes([2]) + point[1:33]))
SQ = b'sk-ecdsa-sha2-nistp256@openssh.com'
pub('sk_ok',            SQ.decode(), s(b'nistp256') + s(point) + s(b'ssh:'))
pub('sk_wrong_curve',   SQ.decode(), s(b'nistp384') + s(point) + s(b'ssh:'))
PY
}

# A tiny driver: reads one base64 blob per argument, prints ACCEPTED/refused.
build_driver() {
    cat > "$SCRATCH/driver.c" <<'C'
#include <stdio.h>
#include <string.h>
#include "ssh_key_policy.h"
int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        char blob[4096], algo[128];
        ssh_key_type_t type;
        int bits;
        FILE *f = fopen(argv[i], "r");
        if (!f || !fgets(blob, sizeof blob, f)) return 2;
        fclose(f);
        blob[strcspn(blob, "\n")] = '\0';
        printf("%s %s\n", argv[i],
               ssh_key_blob_info(blob, algo, sizeof algo, &type, &bits)
                   ? "ACCEPTED" : "refused");
    }
    return 0;
}
C
    "$CC_BIN" -I"$ROOT_DIR/include" -o "$SCRATCH/driver" \
        "$SCRATCH/driver.c" "$ROOT_DIR/src/ssh_key_policy.c" || return 1
    build_fixtures
}

verdicts() {
    "$SCRATCH/driver" "$SCRATCH"/*.b64 | sed 's#^.*/##; s#\.b64 # #'
}

test_valid_ecdsa_still_accepted() {
    local out
    out=$(verdicts)
    if grep -q '^ok ACCEPTED$' <<<"$out" && grep -q '^sk_ok ACCEPTED$' <<<"$out"; then
        pass "a well-formed P-256 key and sk-ecdsa key are accepted"
    else
        fail "a well-formed P-256 key and sk-ecdsa key are accepted" "$out"
    fi
}

test_curve_mismatch_refused() {
    local out bad=""
    out=$(verdicts)
    local f
    for f in wrong_curve wrong_curve2 sk_wrong_curve; do
        grep -q "^$f refused$" <<<"$out" || bad="$bad $f"
    done
    if [ -z "$bad" ]; then
        pass "a curve name that contradicts the type is refused"
    else
        fail "a curve name that contradicts the type is refused" "accepted:$bad"
    fi
}

test_bad_point_refused() {
    local out bad=""
    out=$(verdicts)
    local f
    for f in short_point compressed; do
        grep -q "^$f refused$" <<<"$out" || bad="$bad $f"
    done
    if [ -z "$bad" ]; then
        pass "a point of the wrong size or form is refused"
    else
        fail "a point of the wrong size or form is refused" "accepted:$bad"
    fi
}

# The Perl twin in the LLNG plugin (SSHCA.pm, _parseSshPubKey) must apply the
# same rule; the C source says so next to the decoder, and nothing checked it.
test_perl_twin() {
    local pm="$ROOT_DIR/llng/plugins/ssh-ca/lib/Lemonldap/NG/Portal/Plugins/SSHCA.pm"
    if ! command -v perl >/dev/null 2>&1; then
        pass "the LLNG ssh-ca decoder is checked statically (no perl)"
        grep -q 'SSHCA_ECDSA_CURVES' "$pm" || fail "SSHCA.pm carries the curve table"
        return
    fi
    if ! grep -q 'SSHCA_ECDSA_CURVES' "$pm"; then
        fail "the LLNG ssh-ca decoder checks the curve name of ECDSA keys" \
             "SSHCA.pm has no curve table"
        return
    fi
    # Lift the tables and the helper out of the module: it pulls in the whole
    # LemonLDAP::NG stack at load time, which this suite does not need.
    perl - "$pm" "$SCRATCH" <<'PL' && pass "the LLNG ssh-ca decoder refuses the same blobs"
use strict; use warnings; use MIME::Base64 qw(decode_base64 encode_base64);
my ($pm, $dir) = @ARGV; my $src = do { local $/; open my $fh, '<', $pm or exit 1; <$fh> };
my @parts;
for my $re (qr/my %SSHCA_FIXED_KEY_TYPES = \(.*?\);\n/s,
            qr/my %SSHCA_ECDSA_CURVES = \(.*?\);\n/s,
            qr/sub _mpintBits \{.*?\n\}\n/s,
            qr/sub _parseSshPubKey \{.*?\n\}\n/s) {
    my ($p) = $src =~ /($re)/ or exit 1;
    push @parts, $p;
}
eval join('', @parts) or exit 1;
for my $f (sort glob "$dir/*.b64") {
    open my $fh, '<', $f or exit 1; my $b64 = <$fh>; chomp $b64;
    (my $name = $f) =~ s#.*/##; $name =~ s/\.b64$//;
    my $type = ($name =~ /^sk_/) ? 'sk-ecdsa-sha2-nistp256@openssh.com'
                                 : ($name eq 'wrong_curve2' ? 'ecdsa-sha2-nistp384'
                                                            : 'ecdsa-sha2-nistp256');
    my $ok = main->_parseSshPubKey("$type $b64 x") ? 'ACCEPTED' : 'refused';
    my $want = ($name eq 'ok' || $name eq 'sk_ok') ? 'ACCEPTED' : 'refused';
    print "    $name: $ok (want $want)\n";
    exit 1 if $ok ne $want;
}
exit 0;
PL
}

run_test build_driver 2>/dev/null || {
    echo "  FAIL: the decoder does not compile against the fixtures"
    echo
    echo "Tests run: 1, passed: 0, failed: 1"
    exit 1
}
test_valid_ecdsa_still_accepted
test_curve_mismatch_refused
test_bad_point_refused
test_perl_twin

echo
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
