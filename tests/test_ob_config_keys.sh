#!/bin/bash
#
# Every key this project writes into openbastion.conf must be recognised by
# src/config.c (#229).
#
# Why: config_load() runs once per PAM process, so a key that ob-bastion-setup
# (every role, ob-backend-setup included) or an ob-builder template emits and the parser does not know
# costs one syslog warning per login on every deployed host. Reporting unknown
# keys is only useful while the report means something -- three to five
# warnings per authentication would bury the single typo the feature exists to
# surface, which is the opposite of the point.
#
# Text-level on purpose: it reads the generators and the shipped example rather
# than linking the parser, so it stays valid for keys handled anywhere in
# parse_line(), including the "consumed elsewhere" branches.
#

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_C="$ROOT_DIR/src/config.c"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }

# Keys written into openbastion.conf, per source. Anything else these scripts
# emit goes to a different file (nss_openbastion.conf, service-accounts.conf)
# and is parsed by different code.
keys_from_printf() {           # generator scripts: printf 'key = ...'
    grep -oE "printf '[a-z_]+ = " "$1" 2>/dev/null | sed "s/printf '//; s/ = $//"
}
keys_from_conf() {             # template: active "key = value" lines
    grep -oE '^[a-z_]+[[:space:]]*=' "$1" 2>/dev/null | sed 's/[[:space:]]*=$//'
}
keys_from_reference() {        # example: "# key = default" option lines
    grep -oE '^# [a-z0-9_]+ =( |$)' "$1" 2>/dev/null | sed 's/^# //; s/ =.*$//'
}
keys_from_heredoc() {          # ob-builder: config emitted inside `cat << MODE`
    # Same shape as a conf file, but embedded in a shell script, so the printf
    # extractor above sees none of it. ob-builder was missed entirely until a
    # reviewer's miscount sent us back to check who writes what.
    grep -oE '^[a-z_]+[[:space:]]*=' "$1" 2>/dev/null | sed 's/[[:space:]]*=$//'
}

check_source() {
    local desc="$1" file="$2" mode="$3" missing="" k
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ ! -f "$file" ]; then
        pass "$desc (absent, skipped)"
        return
    fi
    for k in $("keys_from_$mode" "$file" | sort -u); do
        grep -q "\"$k\"" "$CONFIG_C" || missing="$missing $k"
    done
    if [ -z "$missing" ]; then
        pass "$desc"
    else
        fail "$desc" "src/config.c does not know:$missing"
    fi
}

echo "=== openbastion.conf keys the project writes are all parsed (#229) ==="

check_source "ob-bastion-setup writes only known keys (all roles)"  "$ROOT_DIR/scripts/ob-bastion-setup"  printf
check_source "the shipped example carries only known keys" \
    "$ROOT_DIR/config/openbastion.conf.example" reference
check_source "the ansible template carries only known keys" \
    "$ROOT_DIR/admin-builder/templates/ansible/role/templates/openbastion.conf.j2" conf
check_source "ob-builder's embedded configs carry only known keys" \
    "$ROOT_DIR/admin-builder/ob-builder" heredoc

# The generators' own keys must also survive a round trip through the parser's
# unknown-key branch: assert the five that nothing reads back are listed, so a
# future cleanup removes them from BOTH sides or from neither.
TESTS_RUN=$((TESTS_RUN + 1))
_absent=""
for k in cache_enabled cache_dir cache_ttl create_home default_shell; do
    grep -q "\"$k\"" "$CONFIG_C" || _absent="$_absent $k"
done
if [ -z "$_absent" ]; then
    pass "the write-only cache_*/create_home/default_shell keys stay tolerated"
else
    fail "the write-only keys stay tolerated" "missing from src/config.c:$_absent"
fi

# ── The shipped example is the complete option reference (#310) ──
#
# Every generated openbastion.conf carries config/openbastion.conf.example after
# the host's own settings, so the example must list every key parse_line()
# knows, commented out, with the default config.c really applies.

EXAMPLE="$ROOT_DIR/config/openbastion.conf.example"
CONFIG_H="$ROOT_DIR/include/config.h"
# Distinct options sharing one no-op branch of parse_line(), not aliases.
HEARTBEAT_KEYS="node_role report_sessions max_reported_sessions"
WRITE_ONLY_KEYS="cache_enabled cache_dir cache_ttl create_home default_shell"

# parse_line() branches, one line each: "<canonical> [alias...]".
parse_line_branches() {
    awk '
        /^static int parse_line\(/ { on = 1 }
        on && /^}/ { on = 0 }
        !on || $0 !~ /strcmp\(key, "/ { next }
        {
            line = $0; keys = ""
            while (match(line, /strcmp\(key, "[a-z0-9_]+"/)) {
                k = substr(line, RSTART + 13, RLENGTH - 14)
                keys = keys (keys == "" ? "" : " ") k
                line = substr(line, RSTART + RLENGTH)
            }
            if ($0 ~ /^[[:space:]]*(else[[:space:]]+)?if[[:space:]]*\(/) {
                if (cur != "") print cur
                cur = keys
            } else {
                cur = cur " " keys
            }
        }
        END { if (cur != "") print cur }
    ' "$CONFIG_C"
}

# The value an option line of the example sets: "# key = value".
example_value() {
    sed -n "s/^# $1 =[[:space:]]*\\(.*\\)\$/\\1/p" "$EXAMPLE" | head -1
}
has_option_line() { grep -qE "^# $1 =( |\$)" "$EXAMPLE"; }

declare -A CANON=()
OPTION_KEYS=""
_missing=""; _unmentioned=""; _active=""
while read -r canonical aliases; do
    for k in $canonical $aliases; do
        case " $HEARTBEAT_KEYS $WRITE_ONLY_KEYS " in
            *" $k "*) continue ;;
        esac
        CANON[$k]=$canonical
    done
    case " $WRITE_ONLY_KEYS " in *" $canonical "*) ;; *)
        OPTION_KEYS="$OPTION_KEYS $canonical" ;;
    esac
    for k in $aliases; do
        case " $HEARTBEAT_KEYS " in *" $k "*) OPTION_KEYS="$OPTION_KEYS $k"; continue ;; esac
        grep -qw -- "$k" "$EXAMPLE" || _unmentioned="$_unmentioned $k"
    done
done < <(parse_line_branches)
for k in $OPTION_KEYS; do
    has_option_line "$k" || _missing="$_missing $k"
done

TESTS_RUN=$((TESTS_RUN + 1))
if [ "$(echo "$OPTION_KEYS" | wc -w)" -ge 80 ] && [ -z "$_missing" ]; then
    pass "every option parse_line() knows has a '# key = default' line in the example"
else
    fail "every option has a line in the example" \
        "found $(echo "$OPTION_KEYS" | wc -w) options; missing:$_missing"
fi

TESTS_RUN=$((TESTS_RUN + 1))
_bad=""
for k in $WRITE_ONLY_KEYS; do
    grep -qw -- "$k" "$EXAMPLE" || _bad="$_bad $k(unmentioned)"
    has_option_line "$k" && _bad="$_bad $k(listed-as-option)"
done
if [ -z "$_unmentioned" ] && [ -z "$_bad" ]; then
    pass "aliases and write-only keys are named in the example, not listed as options"
else
    fail "aliases and write-only keys are named in the example" "$_unmentioned$_bad"
fi

# Appended under a host's own settings, an active line would override them.
TESTS_RUN=$((TESTS_RUN + 1))
_active=$(grep -nE '^[[:space:]]*[a-z_]+[[:space:]]*=' "$EXAMPLE" | head -3)
if [ -z "$_active" ]; then
    pass "the example sets nothing: every key is commented out"
else
    fail "the example sets nothing" "$_active"
fi

# Resolve a C default: true/false, a number, a string, or a macro of either.
c_value() {
    local v="$1" def
    v="${v#strdup(}"; v="${v%)}"
    if [[ "$v" =~ ^[A-Z_][A-Z0-9_]*$ ]] && [ "$v" != NULL ]; then
        def=$(sed -n "s/^#define[[:space:]]\\+${v}[[:space:]]\\+\\(.*\\)\$/\\1/p" \
              "$CONFIG_C" "$CONFIG_H" | head -1)
        v="${def%%[[:space:]]/\**}"
    fi
    v="${v%\"}"; v="${v#\"}"
    printf '%s' "$v"
}

# log_level and audit_level are documented by name, stored as a number.
named_level() {
    local key="$1" n="$2" names
    case "$key" in
        log_level)   names=(error warn info debug) ;;
        audit_level) names=(critical auth all) ;;
        *) printf '%s' "$n"; return ;;
    esac
    printf '%s' "${names[$n]:-$n}"
}

check_default() {
    local key="$1" cval="$2" where="$3" want got
    [ "$cval" = NULL ] && return
    want=$(named_level "$key" "$(c_value "$cval")")
    got=$(example_value "$key")
    [ "$got" = "$want" ] || _wrong="$_wrong $key($where=$want, example=${got:-<none>})"
}

TESTS_RUN=$((TESTS_RUN + 1))
_wrong=""; _checked=0
while read -r field value; do
    key="${CANON[$field]:-}"
    [ -n "$key" ] || continue
    check_default "$key" "$value" config_init
    _checked=$((_checked + 1))
done < <(awk '/^void config_init\(/,/^}/' "$CONFIG_C" \
         | sed -n 's/^[[:space:]]*config->\([a-z0-9_]*\) = \([^;]*\);.*/\1 \2/p')
while read -r canonical value; do
    check_default "$canonical" "$value" parse_int
    _checked=$((_checked + 1))
done < <(awk '
    /^static int parse_line\(/ { on = 1 }
    on && /^}/ { on = 0 }
    !on { next }
    match($0, /strcmp\(key, "[a-z0-9_]+"/) && $0 ~ /^[[:space:]]*(else[[:space:]]+)?if/ {
        cur = substr($0, RSTART + 13, RLENGTH - 14)
    }
    match($0, /parse_(int|double)\(value, [^,]+,/) {
        d = substr($0, RSTART, RLENGTH); sub(/^parse_(int|double)\(value, /, "", d); sub(/,$/, "", d)
        print cur, d
    }' "$CONFIG_C")
if [ "$_checked" -ge 60 ] && [ -z "$_wrong" ]; then
    pass "the example's defaults are config.c's ($_checked checked)"
else
    fail "the example's defaults are config.c's ($_checked checked)" "$_wrong"
fi

# ── Every generator appends the reference ──
TESTS_RUN=$((TESTS_RUN + 1))
_bad=""
grep -qF "cat \"\$CONF_REFERENCE\"" "$ROOT_DIR/debian/open-bastion.postinst" \
    || _bad="$_bad postinst"
grep -qx 'CONF_REFERENCE="/etc/open-bastion/openbastion.conf.example"' \
    "$ROOT_DIR/debian/open-bastion.postinst" || _bad="$_bad postinst-path"
grep -qF "cat -- \"\$OB_CONFIG_REFERENCE\"; } >> \"\$OB_CONFIG_FILE\"" \
    "$ROOT_DIR/scripts/ob-desktop-setup" || _bad="$_bad ob-desktop-setup"
grep -q 'ob_conf_reference.content | b64decode' \
    "$ROOT_DIR/admin-builder/templates/ansible/role/templates/openbastion.conf.j2" \
    || _bad="$_bad openbastion.conf.j2"
if [ -z "$_bad" ]; then
    pass "the postinst, ob-desktop-setup and the ansible template append the reference"
else
    fail "every generator appends the reference" "not in:$_bad"
fi

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
