#!/bin/bash
#
# The shell callers check the portal's signed answers (#339), and follow its
# key rotation only through answers they could check.
#
# ob-heartbeat, ob-session-monitor and ob-bastion-id take decisions from the
# portal's answers -- a fresh access token, "this user is gone, terminate the
# session", the bastion_id an operator pastes into allowed_bastions -- and
# until now those answers were trusted on TLS alone. Through ob_pam_post
# (scripts/ob-sign-lib.sh) and ob-verify-response they get the checks the PAM
# and NSS modules have. This suite drives each of them against a portal that
# signs (tests/mock_portal_signed.py, signing with tests/jws-sign-fixture,
# never with the code under test) and bends one thing at a time.
#
# The rotation half matters most: the heartbeat answer carries the portal's
# current JWKS, and replacing the trust anchor with whatever came over TLS
# would undo the whole mechanism. So every way of getting a key set in without
# a signature from a key already trusted is tried here, and must leave
# sso-jwks.json alone.

# The checks pass "$([ condition ]; echo $?)": the status of the condition
# is the point.
# shellcheck disable=SC2319

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MOCK="$ROOT_DIR/tests/mock_portal_signed.py"
HB="$ROOT_DIR/scripts/ob-heartbeat"
BID="$ROOT_DIR/scripts/ob-bastion-id"
MON="$ROOT_DIR/scripts/ob-session-monitor"
WORK="$(mktemp -d)"
PORT=${OB_TEST_PORT_BASE:-18960}
MOCK_PID=""
trap '[ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
# check LABEL CONDITION-RESULT [DETAIL]
check() {
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ "$2" = "0" ]; then pass "$1"; else fail "$1" "${3:-}"; fi
}

for cmd in jq curl python3 flock; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "SKIP: $cmd is required"; exit 0; }
done

BUILD_DIR="${OB_BUILD_DIR:-$ROOT_DIR/build}"
VR="$BUILD_DIR/ob-verify-response"
FX="$BUILD_DIR/tests/jws-sign-fixture"
for f in "$VR" "$FX" "$BUILD_DIR/ob-sign-request"; do
    if [ ! -x "$f" ]; then
        echo "SKIP: $f not built (cmake --build build)"
        exit 0
    fi
done

# The scripts find the helpers on PATH, as installed. logger is replaced so the
# test can read what would have gone to syslog.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/logger" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$WORK/syslog"
EOF
chmod +x "$WORK/bin/logger"
PATH="$WORK/bin:$BUILD_DIR:$PATH"
export PATH
export OB_SIGN_LIB="$ROOT_DIR/scripts/ob-sign-lib.sh"
unset OB_VERIFY_RESPONSE OB_SIGN_REQUEST

CLIENT_ID="ob-test-client"
ISS="http://127.0.0.1:$PORT"

# ── Keys ──────────────────────────────────────────────────────────────────────
# k1 is provisioned, k2 is the next key, "rogue" claims k1's kid with another
# key, k9 is unknown, weak is an RSA-1024 key the verifier must skip.
"$FX" keygen P-256 "$WORK/k1.pem"
"$FX" keygen RSA "$WORK/k2.pem"
"$FX" keygen P-256 "$WORK/rogue.pem"
"$FX" keygen ED25519 "$WORK/k9.pem"
"$FX" keygen RSA1024 "$WORK/weak.pem"
JWK1=$("$FX" jwk "$WORK/k1.pem" k1)
JWK2=$("$FX" jwk "$WORK/k2.pem" k2)
JWKWEAK=$("$FX" jwk "$WORK/weak.pem" weak)
JWKS_K1=$(jq -cn --argjson a "$JWK1" '{keys: [$a]}')
JWKS_K1K2=$(jq -cn --argjson a "$JWK1" --argjson b "$JWK2" '{keys: [$a, $b]}')
JWKS_K2=$(jq -cn --argjson b "$JWK2" '{keys: [$b]}')
JWKS_WEAK=$(jq -cn --argjson w "$JWKWEAK" '{keys: [$w]}')

ETC="$WORK/etc"
mkdir -p "$ETC"
JWKS_FILE="$ETC/sso-jwks.json"

install_jwks() {
    printf '%s\n' "$1" > "$JWKS_FILE"
    chmod 0644 "$JWKS_FILE"
}
kids_of() { jq -r '[.keys[].kid] | join(",")' "${1:-$JWKS_FILE}" 2>/dev/null; }

# ── Portal ────────────────────────────────────────────────────────────────────
CTL="$WORK/control.json"
LOG="$WORK/portal.log"
: > "$LOG"
echo '{"kind":"plain"}' > "$CTL"
python3 "$MOCK" "$PORT" "$CTL" "$LOG" "$FX" & MOCK_PID=$!
for _ in $(seq 1 50); do
    (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
    sleep 0.1
done
if ! (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    echo "FAIL: the mock portal did not start on port $PORT"
    exit 1
fi

# portal answers: plain [JQ-ARGS...] | signed KEY KID [JQ-FILTER]
portal_plain() { jq -n "{kind: \"plain\"} ${1:+| $1}" > "$CTL"; }
portal_signed() {
    local key="$1" kid="$2" extra="${3:-}"
    jq -n --arg key "$WORK/$key.pem" --arg kid "$kid" --arg iss "$ISS" \
        --arg aud "$CLIENT_ID" \
        "{kind: \"signed\", key: \$key, kid: \$kid, iss: \$iss, aud: \$aud,
          alg: (if \$kid == \"k2\" then \"RS256\" elif \$kid == \"k9\" then \"EdDSA\" else \"ES256\" end)}
         ${extra:+| $extra}" > "$CTL"
}
requests() { wc -l < "$LOG" | tr -d ' '; }
last_request() { tail -1 "$LOG"; }

# write_conf MODE [EXTRA-LINE...]
CONF="$WORK/ob.conf"
write_conf() {
    local mode="$1"; shift
    {
        printf 'portal_url = http://127.0.0.1:%s/\n' "$PORT"
        printf 'server_group = bastion\n'
        printf 'verify_ssl = false\n'
        printf 'report_sessions = false\n'
        printf 'client_id = %s\n' "$CLIENT_ID"
        printf 'sso_jwks_file = %s   # trust anchor\n' "$JWKS_FILE"
        [ "$mode" = "-" ] || printf 'response_signing = %s\n' "$mode"
        local l
        for l in "$@"; do printf '%s\n' "$l"; done
    } > "$CONF"
    chmod 600 "$CONF"
}

TOKEN="$WORK/token"
# run_hb: one ob-heartbeat run. Sets RC, OUT; the token file is reset first.
run_hb() {
    echo '{"access_token":"old","refresh_token":"rt-1","expires_at":0}' > "$TOKEN"
    chmod 600 "$TOKEN"
    : > "$WORK/syslog"
    OUT=$(bash "$HB" -c "$CONF" -t "$TOKEN" 2>&1); RC=$?
    OUT="$OUT $(cat "$WORK/syslog")"
}
token_now() { jq -r .access_token "$TOKEN" 2>/dev/null; }
refreshed() { [ "$RC" = "0" ] && [ "$(token_now)" = "fresh-access-token" ]; }
refused()   { [ "$RC" != "0" ] && [ "$(token_now)" = "old" ]; }
said() { printf '%s' "$OUT" | grep -qF -- "$1"; }

# ══ 1. ob-verify-response itself ═════════════════════════════════════════════
echo "=== ob-verify-response ==="

install_jwks "$JWKS_K1K2"
out=$("$VR" check-jwks "$JWKS_FILE"); rc=$?
check "check-jwks counts the usable keys" \
    "$([ "$rc" = 0 ] && printf '%s' "$out" | grep -qx 'keys=2'; echo $?)" "$out"

# No fingerprint of its own: the JWKS fingerprint is the SHA-256 of
# `jq -S -c .`, computed where jq runs. What check-jwks lists is one RFC 7638
# thumbprint per key, sorted, so the same key material reformatted, reordered
# or with other members lists the same lines.
check "check-jwks prints no fingerprint= line (that one is jq -S -c . | sha256sum)" \
    "$(! printf '%s' "$out" | grep -q '^fingerprint='; echo $?)" "$out"
keys=$(printf '%s\n' "$out" | grep '^key=')
check "check-jwks lists one key= line per usable key, with its kid" \
    "$([ "$(printf '%s\n' "$keys" | wc -l)" = 2 ] && printf '%s\n' "$keys" | grep -q ' k1$' \
        && printf '%s\n' "$keys" | grep -q ' k2$'; echo $?)" "$out"
jq -S '.keys |= reverse | .keys[] += {use: "sig"}' "$JWKS_FILE" > "$WORK/reformatted.json"
keys2=$("$VR" check-jwks "$WORK/reformatted.json" | grep '^key=')
check "the key= lines ignore formatting, key order and extra members" \
    "$([ -n "$keys" ] && [ "$keys" = "$keys2" ]; echo $?)" "$keys vs $keys2"
if command -v openssl >/dev/null 2>&1; then
    thumbs=$(jq -c '.keys[] | if .kty == "RSA" then {e, kty, n} else {crv, kty, x, y} end' "$JWKS_FILE" \
        | while IFS= read -r m; do
            printf '%s' "$m" | openssl dgst -sha256 -binary | base64 -w0 | tr '+/' '-_' | tr -d '='
            echo
        done | LC_ALL=C sort)
    check "each key= is the RFC 7638 thumbprint, sorted" \
        "$([ "$(printf '%s\n' "$keys" | sed 's/^key=//; s/ .*//')" = "$thumbs" ]; echo $?)" \
        "$keys vs $thumbs"
fi

for bad in '{"keys":[]}' "$JWKS_WEAK" '"garbage"' '{"keys":[{"kty":"oct","kid":"h","k":"c2VjcmV0"}]}'; do
    printf '%s' "$bad" | "$VR" check-jwks - >/dev/null 2>&1; rc=$?
    check "check-jwks refuses a set with no usable key: ${bad:0:40}" "$([ "$rc" = 1 ]; echo $?)" "rc=$rc"
done

cp "$JWKS_FILE" "$WORK/gw.json"; chmod 0664 "$WORK/gw.json"
"$VR" check-jwks --anchor --quiet "$WORK/gw.json" >/dev/null 2>&1; rc=$?
check "check-jwks --anchor refuses a group-writable file" "$([ "$rc" = 1 ]; echo $?)" "rc=$rc"
ln -s "$JWKS_FILE" "$WORK/link.json"
"$VR" check-jwks --anchor --quiet "$WORK/link.json" >/dev/null 2>&1; rc=$?
check "check-jwks --anchor refuses a symlink" "$([ "$rc" = 1 ]; echo $?)" "rc=$rc"

n=$("$VR" nonce)
check "nonce has the X-Nonce format" \
    "$([[ "$n" =~ ^[0-9]{13}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; echo $?)" "$n"

# verify, exit statuses and the jwks claim.
body='{"refresh_token":"rt-1"}'
mk_token() { # KEY KID AUD-or-empty [JWKS-JSON]
    local now; now=$(date +%s)
    jq -cn --arg iss "$ISS" --arg aud "$3" --arg n "$n" \
        --arg sha "$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)" \
        --argjson now "$now" --argjson jwks "${4:-null}" '
        {iss: $iss, iat: $now, exp: ($now + 60), endpoint: "heartbeat",
         req_nonce: $n, req_sha256: $sha, http_status: 200, resp: {ok: true}}
        + (if $aud == "" then {} else {aud: $aud} end)
        + (if $jwks == null then {} else {jwks: $jwks} end)' \
        | "$FX" sign "$WORK/$1.pem" ES256 "$2"
}
verify() { # TOKEN [EXTRA-ARGS...]
    local t="$1"; shift
    printf '%s' "$t" | "$VR" verify --jwks "$JWKS_FILE" --issuer "$ISS" \
        --audience "$CLIENT_ID" --endpoint heartbeat --nonce "$n" \
        --http-status 200 --body-file <(printf '%s' "$body") "$@"
}

rm -f "$WORK/claim"
out=$(verify "$(mk_token k1 k1 "$CLIENT_ID" "$JWKS_K2")" --jwks-out "$WORK/claim" 2>&1); rc=$?
check "verify: a good answer exits 0 and prints resp" \
    "$([ "$rc" = 0 ] && [ "$out" = '{"ok":true}' ]; echo $?)" "rc=$rc $out"
check "verify: the jwks claim of a good answer is written" \
    "$([ "$(kids_of "$WORK/claim")" = k2 ]; echo $?)" "$(cat "$WORK/claim" 2>&1)"

rm -f "$WORK/claim"
out=$(verify "$(mk_token k1 k1 "" "$JWKS_K2")" --jwks-out "$WORK/claim" 2>&1); rc=$?
check "verify: an answer without aud exits 4" "$([ "$rc" = 4 ]; echo $?)" "rc=$rc $out"
check "verify: the jwks claim of an answer without aud is not written" \
    "$([ ! -e "$WORK/claim" ]; echo $?)"

out=$(verify "$(mk_token rogue k1 "$CLIENT_ID")" 2>&1); rc=$?
check "verify: a forged answer exits 1, nothing on stdout" \
    "$([ "$rc" = 1 ] && ! printf '%s' "$out" | grep -q '"ok"'; echo $?)" "rc=$rc $out"
out=$(verify "$(mk_token k1 k1 "$CLIENT_ID")" --http-status 500 2>&1); rc=$?
check "verify: a status other than the signed one exits 1" "$([ "$rc" = 1 ]; echo $?)" "rc=$rc"
out=$(printf '%s' "$(mk_token k1 k1 "$CLIENT_ID")" | "$VR" verify --jwks "$WORK/none.json" \
    --issuer "$ISS" --endpoint heartbeat --nonce "$n" --http-status 200 \
    --body-file /dev/null 2>&1); rc=$?
check "verify: no JWKS exits 3" "$([ "$rc" = 3 ]; echo $?)" "rc=$rc $out"
"$VR" verify --jwks "$JWKS_FILE" --issuer "$ISS" >/dev/null 2>&1; rc=$?
check "verify: a missing option exits 2" "$([ "$rc" = 2 ]; echo $?)" "rc=$rc"

# ══ 2. ob-heartbeat, response_signing ════════════════════════════════════════
echo "=== ob-heartbeat: response_signing ==="
install_jwks "$JWKS_K1"

write_conf off; portal_plain; run_hb
asked() { last_request | jq -e '.accept | contains("ob-pam-response+jwt")' >/dev/null; }
check "off: a plain answer is used, nothing asked" \
    "$(refreshed && ! asked; echo $?)" "rc=$RC $OUT"

write_conf required; portal_plain; run_hb
check "required: an unsigned answer is refused" \
    "$(refused && said "unsigned answer to /pam/heartbeat"; echo $?)" "rc=$RC $OUT"

write_conf requried; portal_plain; run_hb
check "a mistyped mode is read as required" "$(refused; echo $?)" "rc=$RC $OUT"

write_conf prefer; portal_plain; run_hb
check "prefer: an unsigned answer is accepted, with a warning" \
    "$(refreshed && said "accepted (response_signing = prefer)"; echo $?)" "rc=$RC $OUT"
check "prefer: a signed answer is asked for, with one X-Nonce" \
    "$(last_request | jq -e '.accept == "application/ob-pam-response+jwt" and (.nonces | length) == 1' >/dev/null; echo $?)" \
    "$(last_request)"

write_conf required; portal_signed k1 k1; run_hb
check "required: a signed answer is verified and used" "$(refreshed; echo $?)" "rc=$RC $OUT"

# One nonce for both signatures: the HMAC's X-Nonce is what the answer echoes.
write_conf required 'request_signing_secret = s3cr#t key'; portal_signed k1 k1; run_hb
check "with request signing, one X-Nonce serves both and the answer verifies" \
    "$(refreshed && last_request | jq -e '(.nonces | length) == 1 and (.signature | startswith("sha256="))' >/dev/null; echo $?)" \
    "rc=$RC $OUT $(last_request)"

write_conf prefer; portal_signed rogue k1; run_hb
check "prefer: a forged answer (other key, trusted kid) is refused" \
    "$(refused && said "bad signature"; echo $?)" "rc=$RC $OUT"

write_conf required; portal_signed k9 k9; run_hb
check "required: an unknown kid is refused, and nothing is fetched" \
    "$(refused && said "unknown signing key"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.nonce = "1-replayed-for-another-request"'; run_hb
check "an answer bound to another nonce is refused" \
    "$(refused && said "req_nonce"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1; run_hb
portal_plain '.kind = "replay"'; run_hb
# Bound to the previous request: its nonce, and its body too when the uptime
# in it has moved on since.
check "a byte-for-byte replay of the previous answer is refused" \
    "$(refused && { said "req_nonce" || said "req_sha256"; }; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.signed_body = "{}"'; run_hb
check "an answer bound to another body is refused" \
    "$(refused && said "req_sha256"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.aud = "another-client"'; run_hb
check "an answer for another client is refused" "$(refused && said "(aud)"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.endpoint = "userinfo"'; run_hb
check "an answer for another endpoint is refused" "$(refused && said "endpoint"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.iss = "https://elsewhere.example"'; run_hb
check "an answer from another issuer is refused" "$(refused && said "issuer"; echo $?)" "rc=$RC $OUT"

write_conf required 'sso_issuer = https://elsewhere.example'; run_hb
check "sso_issuer replaces the portal URL as the expected iss" "$(refreshed; echo $?)" "rc=$RC $OUT"
write_conf required

portal_signed k1 k1 '.signed_status = 401'; run_hb
check "a status other than the signed one is refused" "$(refused && said "but signed for 401"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.exp_offset = -120'; run_hb
check "an expired answer is refused" "$(refused && said "expired"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.aud = null'; run_hb
check "a granting answer without aud is refused" "$(refused && said "no aud"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.status = 401 | .resp = {error: "invalid_token"}'; run_hb
check "a signed 401 is a verified refusal, named as such" \
    "$(refused && said "invalid or expired refresh_token"; echo $?)" "rc=$RC $OUT"

portal_signed k1 k1 '.status = 401 | .resp = {error: "invalid_token"} | .aud = null'; run_hb
check "a signed 401 without aud is accepted as a refusal" \
    "$(refused && said "invalid or expired refresh_token"; echo $?)" "rc=$RC $OUT"

write_conf off; portal_signed k1 k1; run_hb
check "off: a signed answer nobody asked for is refused" \
    "$(refused && said "not asked for"; echo $?)" "rc=$RC $OUT"

rm -f "$JWKS_FILE"
write_conf required; portal_plain; before=$(requests); run_hb
check "required without a JWKS: nothing is sent" \
    "$(refused && [ "$(requests)" = "$before" ] && said "no usable JWKS"; echo $?)" "rc=$RC $OUT"
write_conf prefer; run_hb
check "prefer without a JWKS: a plain answer is asked for, with a warning" \
    "$(refreshed && ! asked && said "no usable JWKS"; echo $?)" "rc=$RC $OUT"
install_jwks "$JWKS_K1"
chmod 0664 "$JWKS_FILE"
write_conf required; before=$(requests); run_hb
check "required with a group-writable JWKS: nothing is sent" \
    "$(refused && [ "$(requests)" = "$before" ]; echo $?)" "rc=$RC $OUT"
install_jwks "$JWKS_K1"

# ══ 3. ob-heartbeat, JWKS rotation ═══════════════════════════════════════════
echo "=== ob-heartbeat: JWKS rotation ==="
write_conf required

portal_signed k1 k1 ".jwks = $JWKS_K1K2"; run_hb
perms=$(stat -c '%a %u' "$JWKS_FILE")
check "a key set signed by a trusted key is installed" \
    "$(refreshed && [ "$(kids_of)" = "k1,k2" ]; echo $?)" "rc=$RC kids=$(kids_of) $OUT"
check "the new JWKS is 0644, owned by the runner, and no temporary file is left" \
    "$([ "$perms" = "644 $(id -u)" ] && [ -z "$(find "$ETC" -name '.sso-jwks.*')" ]; echo $?)" \
    "$perms $(ls -A "$ETC")"
check "the rotation is logged with the old and new kids" \
    "$(said "kids [k1] -> [k1,k2]"; echo $?)" "$OUT"
fp_old=$(printf '%s' "$JWKS_K1" | jq -S -c . | sha256sum | cut -d' ' -f1)
fp_new=$(printf '%s' "$JWKS_K1K2" | jq -S -c . | sha256sum | cut -d' ' -f1)
check "the rotation logs the old and new fingerprints, as jq -S -c . | sha256sum gives them" \
    "$(said "$fp_old -> $fp_new"; echo $?)" "want $fp_old -> $fp_new: $OUT"
check "the new JWKS is written in canonical form: its sha256sum is the fingerprint" \
    "$([ "$(sha256sum < "$JWKS_FILE" | cut -d' ' -f1)" = "$fp_new" ]; echo $?)" "$(cat "$JWKS_FILE")"
"$VR" check-jwks --anchor --quiet "$JWKS_FILE" >/dev/null 2>&1
check "the installed file passes the modules' own trust-anchor checks" "$?"

portal_signed k2 k2 ".jwks = $JWKS_K2"; run_hb
check "the chain continues: an answer signed by the new key verifies and rotates again" \
    "$(refreshed && [ "$(kids_of)" = "k2" ]; echo $?)" "rc=$RC kids=$(kids_of) $OUT"

portal_signed k1 k1 ".jwks = $JWKS_K1"; run_hb
check "a retired key can no longer sign, nor bring itself back" \
    "$(refused && [ "$(kids_of)" = "k2" ]; echo $?)" "rc=$RC kids=$(kids_of) $OUT"

ino=$(stat -c %i "$JWKS_FILE")
portal_signed k2 k2 ".jwks = $(jq -c '.keys[0] += {use: "sig"} | .keys[0] |= del(.use)' "$JWKS_FILE")"; run_hb
check "the same key set, serialised differently, is not rewritten" \
    "$(refreshed && [ "$(stat -c %i "$JWKS_FILE")" = "$ino" ]; echo $?)" "rc=$RC $OUT"

# Every way in that is not "signed by a trusted key, for this client".
install_jwks "$JWKS_K1"
expect_kept() {
    local label="$1" want_rc="$2"
    if [ "$(kids_of)" != "k1" ]; then
        check "$label" 1 "sso-jwks.json now holds [$(kids_of)]"
    elif [ "$want_rc" = "ok" ]; then
        check "$label" "$(refreshed; echo $?)" "rc=$RC $OUT"
    else
        check "$label" "$(refused; echo $?)" "rc=$RC $OUT"
    fi
}

write_conf prefer
portal_plain ".resp = {status: \"ok\", access_token: \"fresh-access-token\", expires_in: 3600, jwks: $JWKS_K2} | .jwks = $JWKS_K2"
run_hb
expect_kept "an unsigned answer carrying a JWKS rotates nothing (prefer)" ok

portal_signed rogue k1 ".jwks = $JWKS_K2"; run_hb
expect_kept "a forged answer carrying a JWKS rotates nothing" refused

portal_signed k1 k1 ".jwks = $JWKS_K2 | .aud = null"; run_hb
expect_kept "an answer without aud carrying a JWKS rotates nothing" refused

portal_signed k1 k1 ".jwks = $JWKS_K2 | .aud = \"another-client\""; run_hb
expect_kept "an answer for another client carrying a JWKS rotates nothing" refused

portal_signed k1 k1 ".jwks = $JWKS_K2 | .status = 403 | .resp = {error: \"forbidden\"}"; run_hb
expect_kept "a signed refusal carrying a JWKS rotates nothing" refused

write_conf required
portal_signed k1 k1 '.jwks = {keys: []}'; run_hb
expect_kept "an empty key set is not installed (and the heartbeat still succeeds)" ok
check "an empty key set is reported" "$(said "no usable signature key"; echo $?)" "$OUT"

portal_signed k1 k1 ".jwks = $JWKS_WEAK"; run_hb
expect_kept "a key set with only unusable keys (RSA-1024) is not installed" ok

portal_signed k1 k1 '.jwks = "garbage"'; run_hb
expect_kept "a jwks claim that is not an object is ignored" ok

write_conf off; portal_plain ".jwks = $JWKS_K2"; run_hb
expect_kept "response_signing = off never rotates" ok

# Somewhere the unit cannot write: the heartbeat fails loudly, the old file
# stays. (root ignores the mode bits, so not checked as root.)
if [ "$(id -u)" != "0" ]; then
    write_conf required; portal_signed k1 k1 ".jwks = $JWKS_K1K2"
    chmod 0555 "$ETC"; run_hb; chmod 0755 "$ETC"
    check "a JWKS that cannot be installed fails the run and keeps the old one" \
        "$([ "$RC" != 0 ] && [ "$(kids_of)" = "k1" ] && said "Cannot create a file in"; echo $?)" \
        "rc=$RC kids=$(kids_of) $OUT"
fi

# One run at a time: a run that cannot get the lock sends nothing.
write_conf required; portal_signed k1 k1
flock "$WORK" sleep 5 & holder=$!
sleep 0.3
before=$(requests)
OB_HEARTBEAT_LOCK_WAIT=1 run_hb
wait "$holder" 2>/dev/null
check "a run waits for the lock, then gives up without calling the portal" \
    "$(refused && [ "$(requests)" = "$before" ] && said "Another ob-heartbeat"; echo $?)" "rc=$RC $OUT"

# ══ 4. ob-session-monitor ════════════════════════════════════════════════════
echo "=== ob-session-monitor: /pam/userinfo ==="
install_jwks "$JWKS_K1"

# check_user_valid out of the shipped script, as tests/test_ob_session_monitor.sh
# does; the real library behind it.
monitor_verdict() {
    {
        echo 'set -uo pipefail'
        echo ". '$ROOT_DIR/scripts/ob-sign-lib.sh'"
        echo "PORTAL_URL='http://127.0.0.1:$PORT'"
        echo "CONFIG_FILE='$CONF'"
        echo 'SERVER_TOKEN=""'
        echo 'log_warn() { echo "WARN: $*" >&2; }'
        echo 'log_crit() { echo "CRIT: $*" >&2; }'
        echo 'log_debug() { :; }'
        awk '/^check_user_valid\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$MON"
        echo 'check_user_valid alice; echo "VERDICT=$?"'
    } > "$WORK/monitor.sh"
    OUT=$(bash "$WORK/monitor.sh" 2>&1)
    VERDICT=$(printf '%s' "$OUT" | sed -n 's/^VERDICT=//p' | tail -1)
}
# expect_verdict WANT LABEL [GREP]
expect_verdict() {
    monitor_verdict
    check "$2" "$([ "$VERDICT" = "$1" ] && { [ -z "${3:-}" ] || printf '%s' "$OUT" | grep -qF -- "$3"; }; echo $?)" \
        "verdict=$VERDICT $OUT"
}

write_conf required
portal_signed k1 k1
expect_verdict 0 "required: a signed found:true is valid (0)"
portal_signed k1 k1 '.resp = {found: false}'
expect_verdict 1 "required: a signed found:false is revoked (1)"
portal_plain '.resp = {found: false}'
expect_verdict 2 "required: an unsigned found:false is unknown (2), nobody is terminated" "unsigned answer"
portal_signed rogue k1 '.resp = {found: false}'
expect_verdict 2 "a forged found:false is unknown (2)" "bad signature"
portal_signed k1 k1 '.resp = {found: false} | .aud = null'
expect_verdict 2 "a found:false without aud is unknown (2)" "no aud"
portal_signed k1 k1 '.resp = {found: false} | .endpoint = "heartbeat"'
expect_verdict 2 "a found:false for another endpoint is unknown (2)" "endpoint"
write_conf prefer
portal_plain '.resp = {found: false}'
expect_verdict 1 "prefer: an unsigned found:false is still a verdict (1), with a warning" \
    "accepted (response_signing = prefer)"

# ══ 5. ob-bastion-id ═════════════════════════════════════════════════════════
echo "=== ob-bastion-id: /pam/whoami ==="
echo '{"access_token":"dummy-token"}' > "$WORK/bid-token"
run_bid() { OUT=$(bash "$BID" --quiet -c "$CONF" -t "$WORK/bid-token" 2>&1); RC=$?; }

write_conf required; portal_signed k1 k1; run_bid
check "required: a signed whoami prints the bastion_id" \
    "$([ "$RC" = 0 ] && [ "$OUT" = "9f86d081" ]; echo $?)" "rc=$RC $OUT"
portal_plain; run_bid
check "required: an unsigned whoami is refused (exit 2)" "$([ "$RC" = 2 ]; echo $?)" "rc=$RC $OUT"
portal_signed rogue k1 '.resp = {bastion_id: "attacker-bastion"}'; run_bid
check "a forged whoami is refused, its id never printed" \
    "$([ "$RC" = 2 ] && ! printf '%s' "$OUT" | grep -q attacker-bastion; echo $?)" "rc=$RC $OUT"
write_conf prefer; portal_plain; run_bid
check "prefer: an unsigned whoami is used, with a warning" \
    "$([ "$RC" = 0 ] && printf '%s' "$OUT" | grep -q "^9f86d081$" && printf '%s' "$OUT" | grep -q "WARN"; echo $?)" "rc=$RC $OUT"

# ══ 6. Without ob-sign-lib.sh ═══════════════════════════════════════════════
# A broken install (the library missing) can check nothing. Under
# response_signing = off nothing was going to be checked: the call goes out
# unsigned, as before #339, so the bastion keeps its token. Anything else --
# prefer, required, a typo, an unreadable configuration -- sends nothing.
echo "=== without ob-sign-lib.sh: off calls unsigned, anything else fails closed ==="
mkdir -p "$WORK/nolib"
cp "$HB" "$WORK/nolib/ob-heartbeat"
cp "$BID" "$WORK/nolib/ob-bastion-id"
install_jwks "$JWKS_K1"
run_hb_nolib() {
    echo '{"access_token":"old","refresh_token":"rt-1","expires_at":0}' > "$TOKEN"
    chmod 600 "$TOKEN"
    : > "$WORK/syslog"
    OUT=$(OB_SIGN_LIB="$WORK/nolib/none.sh" bash "$WORK/nolib/ob-heartbeat" -c "$CONF" -t "$TOKEN" 2>&1); RC=$?
    OUT="$OUT $(cat "$WORK/syslog")"
}
# nolib_hb LABEL ok|refused CONF-ARGS...
nolib_hb() {
    local label="$1" want="$2" before
    shift 2
    write_conf "$@"; portal_plain; before=$(requests); run_hb_nolib
    if [ "$want" = ok ]; then
        check "heartbeat, $label: sent unsigned, answer used" \
            "$(refreshed && [ "$(requests)" -gt "$before" ] && ! asked \
                && [ -z "$(last_request | jq -r .signature)" ] \
                && last_request | jq -e '.body | contains("rt-1")' >/dev/null; echo $?)" \
            "rc=$RC $OUT $(last_request)"
    else
        check "heartbeat, $label: nothing sent, the run fails" \
            "$(refused && [ "$(requests)" = "$before" ] && said "ob-sign-lib.sh not found"; echo $?)" \
            "rc=$RC $OUT"
    fi
}
nolib_hb "response_signing = off" ok off 'request_signing_secret = s3cr3t'
nolib_hb "no response_signing" ok -
nolib_hb "a quoted off with a comment" ok "'off'   # quoted"
nolib_hb "off last (last one wins)" ok required 'response_signing = off'
nolib_hb "prefer" refused prefer
nolib_hb "required" refused required
nolib_hb "an unknown value" refused requried
nolib_hb "required last (last one wins)" refused off 'response_signing = required'
nolib_hb "Off (case matters, as in the library)" refused Off

# ob-session-monitor: the library-loading block of the shipped script, then
# check_user_valid, from a directory without the library.
monitor_nolib() {
    {
        echo 'set -uo pipefail'
        echo "OB_SIGN_LIB='$WORK/nolib/none.sh'"
        awk '/^_OB_SIGN_LIB=/{f=1} /^MARKER_DIR=/{exit} f' "$MON"
        echo "PORTAL_URL='http://127.0.0.1:$PORT'"
        echo "CONFIG_FILE='$1'"
        echo 'SERVER_TOKEN=""'
        echo 'log_warn() { echo "WARN: $*" >&2; }'
        echo 'log_crit() { echo "CRIT: $*" >&2; }'
        echo 'log_debug() { :; }'
        awk '/^check_user_valid\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$MON"
        echo 'check_user_valid alice; echo "VERDICT=$?"'
    } > "$WORK/nolib/monitor.sh"
    OUT=$(bash "$WORK/nolib/monitor.sh" 2>&1)
    VERDICT=$(printf '%s' "$OUT" | sed -n 's/^VERDICT=//p' | tail -1)
}
write_conf off; portal_plain '.resp = {found: false}'; before=$(requests); monitor_nolib "$CONF"
check "session-monitor, off: sent unsigned, found:false is a verdict (1)" \
    "$([ "$VERDICT" = 1 ] && [ "$(requests)" -gt "$before" ]; echo $?)" "verdict=$VERDICT $OUT"
write_conf required; before=$(requests); monitor_nolib "$CONF"
check "session-monitor, required: nothing sent, the status is unknown (2)" \
    "$([ "$VERDICT" = 2 ] && [ "$(requests)" = "$before" ] \
        && printf '%s' "$OUT" | grep -q "ob-sign-lib.sh not found"; echo $?)" "verdict=$VERDICT $OUT"
if [ "$(id -u)" != "0" ]; then
    write_conf off; chmod 000 "$CONF"; before=$(requests); monitor_nolib "$CONF"; chmod 600 "$CONF"
    check "session-monitor, unreadable configuration: nothing sent, unknown (2)" \
        "$([ "$VERDICT" = 2 ] && [ "$(requests)" = "$before" ] \
            && printf '%s' "$OUT" | grep -q "(unreadable)"; echo $?)" "verdict=$VERDICT $OUT"
fi

run_bid_nolib() {
    OUT=$(OB_SIGN_LIB="$WORK/nolib/none.sh" bash "$WORK/nolib/ob-bastion-id" --quiet -c "$CONF" -t "$WORK/bid-token" 2>&1); RC=$?
}
write_conf off; portal_plain; before=$(requests); run_bid_nolib
check "ob-bastion-id, off: sent unsigned, the bastion_id is printed" \
    "$([ "$RC" = 0 ] && [ "$OUT" = "9f86d081" ] && [ "$(requests)" -gt "$before" ]; echo $?)" "rc=$RC $OUT"
write_conf prefer; before=$(requests); run_bid_nolib
check "ob-bastion-id, prefer: nothing sent, exit 2" \
    "$([ "$RC" = 2 ] && [ "$(requests)" = "$before" ] \
        && printf '%s' "$OUT" | grep -q "ob-sign-lib.sh not found"; echo $?)" "rc=$RC $OUT"

# The three copies of the fallback are one piece of code; they must not drift.
fallback_of() { awk '/^    \. "\$_OB_SIGN_LIB"$/{f=1; next} f&&/^fi$/{exit} f' "$1"; }
fb_hb=$(fallback_of "$HB")
check "ob-heartbeat, ob-session-monitor and ob-bastion-id carry the same fallback" \
    "$([ -n "$fb_hb" ] && [ "$fb_hb" = "$(fallback_of "$MON")" ] && [ "$fb_hb" = "$(fallback_of "$BID")" ]; echo $?)"

# ══ 7. Inventory ═════════════════════════════════════════════════════════════
# Every shell caller of an endpoint the portal signs goes through ob_pam_post.
# The enrolment and setup probes are diagnostics that grant nothing; they are
# named here so that adding another caller is a decision, not an accident.
echo "=== every shell caller of a signed endpoint checks the answer ==="
bad=""
while IFS= read -r f; do
    case "$f" in
        scripts/ob-enroll) continue ;;   # post-enrolment probe, see the doc
    esac
    grep -q 'ob_pam_post' "$ROOT_DIR/$f" || bad="$bad $f"
done < <(cd "$ROOT_DIR" && grep -lE '"\$\{PORTAL_URL\}/pam/(authorize|verify|userinfo|whoami|heartbeat)"|ob_pam_post|ob_sign_request POST /pam/(authorize|verify|userinfo|whoami|heartbeat)' scripts/ob-* 2>/dev/null)
check "ob-heartbeat, ob-session-monitor, ob-bastion-id use ob_pam_post${bad:+ (not:$bad)}" \
    "$([ -z "$bad" ] && grep -q ob_pam_post "$HB" && grep -q ob_pam_post "$MON" && grep -q ob_pam_post "$BID"; echo $?)"

# The JWKS is state: the default sso_jwks_file is under /var/lib/open-bastion,
# which the unit may write (the rotation renames into jwks/), while /etc stays
# read-only under ProtectSystem=strict.
unit="$ROOT_DIR/systemd/ob-heartbeat.service"
bad=""
grep -qx 'ProtectSystem=strict' "$unit" || bad="$bad not-strict"
grep -qx 'ReadWritePaths=/var/lib/open-bastion' "$unit" || bad="$bad rw:$(grep '^ReadWritePaths=' "$unit")"
grep -q '^ReadWritePaths=.*/etc' "$unit" && bad="$bad etc-writable"
grep -q '^ReadOnlyPaths=' "$unit" && bad="$bad read-only-exceptions"
grep -q '"/var/lib/open-bastion/jwks/sso-jwks.json"' "$ROOT_DIR/include/config.h" || bad="$bad pam-default"
grep -q '"/var/lib/open-bastion/jwks/sso-jwks.json"' "$ROOT_DIR/nss/libnss_openbastion.c" || bad="$bad nss-default"
grep -q 'OB_RS_JWKS:-/var/lib/open-bastion/jwks/sso-jwks.json' "$ROOT_DIR/scripts/ob-sign-lib.sh" || bad="$bad lib-default"
check "ob-heartbeat.service writes /var/lib/open-bastion only, where the JWKS lives by default" \
    "$([ -z "$bad" ]; echo $?)" "$bad"

echo
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
