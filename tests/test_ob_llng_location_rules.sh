#!/bin/bash
#
# Guards the portal locationRules that are the ONLY authorization on two sets of
# routes (#195):
#
#   /device                        — approve or refuse a host enrolment. The
#                                    plugin's own control
#                                    (oidcRPMetaDataOptionsAllowDeviceAuthorization)
#                                    is an activation flag when set to 1, so the
#                                    vhost rule is then the whole control.
#   /ssh/admin, /ssh/certs,        — list every issued certificate and revoke
#   /ssh/revoke                      anyone's. Up to plugin v0.5.2 the ssh-ca
#                                    plugin performs no authorization on them at
#                                    all; from 0.6.0 `sshCaAdminRule` is the
#                                    fail-closed control and the vhost rule is
#                                    defence in depth.
#
# Two ways to get these rules wrong are load-bearing, and both are silent:
#
#   - `^/device$` does NOT fail to fire: the approval form posts to
#     PORTAL_URL/device with user_code and action in the body, so REQUEST_URI is
#     "/device" and an anchored rule matches the decision. What it misses is the
#     page (`/device?user_code=...`) and a crafted POST carrying the same
#     parameters in the query string, both of which go through ungated.
#   - `^/ssh/revoke` also matches `/ssh/revoked`, the PUBLIC KRL. That does not
#     break fleet-wide propagation — backends fetch it with an anonymous curl,
#     and a request with no session never reaches grant() — but it does 403 a
#     KRL fetch made with a session.
#
# So this test checks the shipped configurations carry the rules, and replays
# the regexes against the real route list to prove they separate admin routes
# from user and public ones.
#

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# Configurations that enable the ssh-ca plugin and therefore expose the admin
# routes. The token-only demos have no /ssh routes at all.
SSHCA_CONFIGS=(
    "docker-demo-cert/lmConf-1.json"
    "docker-demo-maxsec/lmConf-1.json"
)

# Every shipped portal configuration: all of them expose /device.
ALL_CONFIGS=(
    "docker-demo-cert/lmConf-1.json"
    "docker-demo-maxsec/lmConf-1.json"
    "docker-demo-token/lmConf-1.json"
    "docker-demo-token-svc/lmConf-1.json"
    "quick-start/lmConf-1.json"
)

# ── Test 1: the shipped configs are valid JSON ──
test_configs_are_valid_json() {
    local bad="" c
    for c in "${ALL_CONFIGS[@]}"; do
        python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$ROOT_DIR/$c" 2>/dev/null \
            || bad="$bad $c"
    done
    if [ -z "$bad" ]; then
        pass "shipped lmConf files are valid JSON"
    else
        fail "shipped lmConf files are valid JSON" "bad:$bad"
    fi
}

# ── Test 2: every portal vhost restricts /device ──
test_device_rule_present() {
    local bad="" c
    for c in "${ALL_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PY' || bad="$bad $c"
import json, sys
conf = json.load(open(sys.argv[1]))
rules = conf.get("locationRules", {})
if not rules:
    sys.exit(1)
for host, host_rules in rules.items():
    if not any(k.startswith("^/device") for k in host_rules):
        sys.exit(1)
sys.exit(0)
PY
    done
    if [ -z "$bad" ]; then
        pass "every shipped portal vhost carries a ^/device rule"
    else
        fail "every shipped portal vhost carries a ^/device rule" "missing:$bad"
    fi
}

# ── Test 3: the /device rule covers the page, not just the decision ──
# `grant()` matches against REQUEST_URI, which carries the query string. The
# approval form posts to PORTAL_URL/device with user_code and action in the
# BODY (device.tpl), so REQUEST_URI is "/device" there and an end-anchored
# `^/device$` does match the decision -- the trap is not that the rule never
# fires. What an anchored rule misses is the page itself
# (/device?user_code=...) and a crafted POST carrying the same parameters in
# the query string: both go through ungated.
#
# Asserted by compiling the rule and running URIs through it, not by
# pattern-matching the rule text. The textual heuristic this replaces had two
# blind spots: it skipped any rule containing "|", so an anchored form hidden
# in an alternation passed, and it rejected a safe `^/device(\?.*)?$` because
# that ends with "$".
test_device_rule_covers_page_and_decision() {
    local bad="" c
    for c in "${ALL_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PYEOF' || bad="$bad $c"
import json, re, sys

MUST_MATCH = [
    "/device",                                     # the decision POST
    "/device?user_code=ABCD-EFGH",                 # the page GET
    "/device?user_code=ABCD-EFGH&action=approve",  # a crafted POST
]

conf = json.load(open(sys.argv[1]))
for host, host_rules in conf.get("locationRules", {}).items():
    for pattern in host_rules:
        if not pattern.startswith("^/device"):
            continue
        rx = re.compile(pattern)
        for uri in MUST_MATCH:
            if not rx.search(uri):
                print(f"{host}: {pattern} fails to match {uri}", file=sys.stderr)
                sys.exit(1)
sys.exit(0)
PYEOF
    done
    if [ -z "$bad" ]; then
        pass "^/device rule matches the page, the decision and a query-string POST"
    else
        fail "^/device rule covers page and decision" "offenders:$bad"
    fi
}

# ── Test 4: ssh-ca configs restrict the admin routes ──
test_ssh_admin_rule_present() {
    local bad="" c
    for c in "${SSHCA_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PY' || bad="$bad $c"
import json, sys
conf = json.load(open(sys.argv[1]))
if not conf.get("sshCaActivation"):
    sys.exit(0)   # plugin off: no /ssh routes to protect
for host_rules in conf.get("locationRules", {}).values():
    if not any(k.startswith("^/ssh") for k in host_rules):
        sys.exit(1)
sys.exit(0)
PY
    done
    if [ -z "$bad" ]; then
        pass "ssh-ca configs carry a ^/ssh admin rule on every vhost"
    else
        fail "ssh-ca configs carry a ^/ssh admin rule" "missing:$bad"
    fi
}

# ── Test 5: the /ssh rule matches the admin routes and NOTHING else ──
# This is the one that matters: /ssh/revoked is the public KRL, and /ssh/sign,
# /ssh/mycerts, /ssh/myrevoke are ordinary user operations.
test_ssh_rule_separates_routes() {
    local bad="" c
    for c in "${SSHCA_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PY' || bad="$bad $c"
import json, re, sys

MUST_MATCH = ["/ssh/admin", "/ssh/certs", "/ssh/certs?search=x",
              "/ssh/revoke", "/ssh/revoke/42"]
MUST_NOT   = ["/ssh/revoked",          # public KRL, downloaded by every backend
              "/ssh/ca",               # public CA key
              "/ssh/sign",             # the user's own certificate request
              "/ssh/mycerts", "/ssh/myrevoke",
              "/ssh",                  # the signing interface
              # Weakening one alternative must not pass because the others
              # hold: `^/ssh/(admin\w*|certs|revoke)(\?|/|$)` would restrict a
              # page served by the `*` leaf and otherwise go green.
              "/ssh/adminfoo", "/ssh/certsx", "/ssh/revoketoo"]

conf = json.load(open(sys.argv[1]))
for host, host_rules in conf.get("locationRules", {}).items():
    for pattern in host_rules:
        if not pattern.startswith("^/ssh"):
            continue
        rx = re.compile(pattern)
        for uri in MUST_MATCH:
            if not rx.search(uri):
                print(f"{host}: {pattern} fails to match {uri}", file=sys.stderr)
                sys.exit(1)
        for uri in MUST_NOT:
            if rx.search(uri):
                print(f"{host}: {pattern} wrongly matches {uri}", file=sys.stderr)
                sys.exit(1)
sys.exit(0)
PY
    done
    if [ -z "$bad" ]; then
        pass "^/ssh rule covers admin routes and spares /ssh/revoked, /ssh/ca, user routes"
    else
        fail "^/ssh rule route separation" "wrong in:$bad"
    fi
}

# ── Test 6: the shipped configs carry the plugin-side admin rule ──
# From plugin 0.6.0 the ssh-ca admin routes are fail-closed on
# `sshCaAdminRule`: unset, /ssh/admin, /ssh/certs and /ssh/revoke answer 403 to
# everyone, including the users the vhost locationRules would let through. A
# demo that ships the vhost rule alone stops demonstrating the admin flow the
# day the portal image moves to 0.6.0, and does so silently.
test_ssh_admin_plugin_rule_present() {
    local bad="" c
    for c in "${SSHCA_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PYEOF' || bad="$bad $c"
import json, sys
conf = json.load(open(sys.argv[1]))
if not conf.get("sshCaActivation"):
    sys.exit(0)   # plugin off: no admin routes to guard
rule = (conf.get("sshCaAdminRule") or "").strip()
sys.exit(0 if rule and rule != "0" else 1)
PYEOF
    done
    if [ -z "$bad" ]; then
        pass "ssh-ca configs set sshCaAdminRule (fail-closed from plugin 0.6.0)"
    else
        fail "ssh-ca configs set sshCaAdminRule" "missing:$bad"
    fi
}

# ── Test 7: the documentation ships the same rules, in every copy ──
# The production deployment is an operator's own portal, which this repository
# does not configure; the guide is the deliverable, so it must not drift. The
# same normative content lives in four places, and checking only one of them
# lets the other three rot -- an `^/device$` example copied into a security
# checklist would have gone green.
test_documented() {
    local ok=1 f
    local guide="$ROOT_DIR/doc/llng-configuration.rst"

    grep -q '\^/device' "$guide" || { ok=0; echo "    (no ^/device rule documented)"; }
    grep -q 'admin|certs|revoke' "$guide" || { ok=0; echo "    (no ^/ssh admin rule documented)"; }
    grep -q '/ssh/revoked' "$guide" || { ok=0; echo "    (the /ssh/revoked trap is not called out)"; }
    grep -q 'sshCaAdminRule' "$guide" || { ok=0; echo "    (sshCaAdminRule is not documented)"; }

    # No copy may show an end-anchored /device rule as a rule. Matched on the
    # quoted JSON key form so the prose explaining WHY it is wrong -- which has
    # to name `^/device$` -- does not trip the check.
    for f in doc/llng-configuration.rst doc/security/01-enrollment.rst \
             doc/security/02-ssh-connection.rst CHANGELOG.md; do
        if grep -qE '"\^/device[^"]*\$"' "$ROOT_DIR/$f"; then
            ok=0; echo "    ($f shows an end-anchored ^/device rule)"
        fi
    done

    # Wherever the ssh admin rule appears, it keeps its (\?|/|$) guard: without
    # it the rule swallows /ssh/revoked, the public KRL. Two spellings reach
    # here: the JSON form `(\?|/|$)` and the Markdown table form
    # `(\?\|/\|$)`, whose pipes are escaped for the cell separator, so the
    # tail of either is matched as a fixed string.
    for f in doc/llng-configuration.rst doc/security/01-enrollment.rst \
             doc/security/02-ssh-connection.rst CHANGELOG.md; do
        if grep -q 'admin|certs|revoke' "$ROOT_DIR/$f" \
           && ! grep -qF -e '|/|$)' -e '\|/\|$)' "$ROOT_DIR/$f"; then
            ok=0; echo "    ($f shows the ssh admin rule without its (\?|/|\$) guard)"
        fi
    done

    if [ "$ok" -eq 1 ]; then
        pass "all four copies document the rules, unanchored and guarded"
    else
        fail "documentation copies agree"
    fi
}

echo "=== LLNG portal locationRules (#195) ==="
run_test test_configs_are_valid_json
run_test test_device_rule_present
run_test test_device_rule_covers_page_and_decision
run_test test_ssh_admin_rule_present
run_test test_ssh_rule_separates_routes
run_test test_ssh_admin_plugin_rule_present
run_test test_documented

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
