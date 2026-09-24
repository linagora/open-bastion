#!/bin/bash
# test_ob_login_shell.sh
#
# Guards ob-login-shell, the login shell of SSO users on a host that records
# sessions (#293).
#
# sshd runs the ForceCommand through the login shell, as `$SHELL -c
# /usr/sbin/ob-session-recorder`. Debian's bash sources ~/.bashrc for `bash -c`
# whenever SSH_CLIENT is set, and zsh reads ~/.zshenv for every invocation, so
# the user's own files ran before the recorder did. ob-login-shell reads
# nothing of the user's and has one way out: exec the recorder. These tests pin
# what that means:
#
#   - the ForceCommand (the recorder's path, with or without options) is
#     exec'd, in the same process, with SSH_ORIGINAL_COMMAND passed on;
#   - any other command is NEVER run: it becomes SSH_ORIGINAL_COMMAND and the
#     recorder is what runs it -- recorded;
#   - no argument, -l, --login, -i: an interactive session, through the
#     recorder, with no SSH_ORIGINAL_COMMAND inherited from the caller;
#   - any other invocation is refused and nothing runs;
#   - the recorder gets an environment built from scratch: identity from the
#     passwd entry, a fixed PATH, and only a few sshd variables, each
#     validated. BASH_ENV, ENV, SHELLOPTS, BASH_FUNC_*, LD_*, OB_*, a locale
#     named by a path, and the rest never reach it;
#   - the real shell (SHELL, which the recorder starts inside script(1)) is
#     default_shell from a root-owned nss_openbastion.conf, else /bin/bash, and
#     is never the launcher or the recorder themselves.
#
# It drives ob-login-shell-testbuild (tests/CMakeLists.txt): the same source,
# with the recorder and configuration paths taken from OB_TEST_RECORDER and
# OB_TEST_NSS_CONF so a stub recorder can stand in, unprivileged. That the
# user's startup files are not read before the recorder under a real sshd,
# with a real NSS answer, is tests/test_login_shell_e2e.sh.
#
# It fails rather than skips when the binaries are missing: the mutation runner
# must never read "nothing ran" as "the control is covered".

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${OB_BUILD_DIR:-$ROOT_DIR/build}"
BIN="$BUILD/tests/ob-login-shell-testbuild"
STRICT="$BUILD/tests/ob-login-shell-strictuid"

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

echo "=== ob-login-shell: nothing of the user's before the recorder (#293) ==="

for b in "$BIN" "$STRICT"; do
    if [ ! -x "$b" ]; then
        echo "  FAIL: $b is not built; configure and build the tree first"
        exit 1
    fi
done

WORK=$(mktemp -d)
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/markers" "$WORK/home"
REC="$WORK/recorder"
CONF="$WORK/nss_openbastion.conf"
ME=$(id -un)
MYHOME=$(getent passwd "$(id -u)" | cut -d: -f6)

# The stand-in recorder. It records what it was started with, from
# /proc/self/environ rather than `env`: a shell adds variables of its own (PWD,
# SHLVL) and would blur what the launcher passed.
cat > "$REC" <<EOF
#!/bin/sh
cat /proc/\$\$/environ > "$WORK/env0"
: > "$WORK/args0"
for a in "\$@"; do printf '%s\0' "\$a" >> "$WORK/args0"; done
echo "\$\$" > "$WORK/pid"
exit 0
EOF
chmod 755 "$REC"

# run_ls [VAR=value ...] -- [ARG ...]: the launcher, with exactly that
# environment (plus the two test-build paths), stdout/stderr to $WORK/stderr.
run_ls() {
    local envs=() bin="$BIN"
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
    shift
    [ -n "${USE_BIN:-}" ] && bin="$USE_BIN"
    rm -f "$WORK/env0" "$WORK/args0" "$WORK/pid"
    env -i OB_TEST_RECORDER="$REC" OB_TEST_NSS_CONF="$CONF" \
        ${envs[@]+"${envs[@]}"} "$bin" "$@" >"$WORK/stderr" 2>&1
}

recorder_ran() { [ -f "$WORK/env0" ]; }
# The value of $1 in the recorder's environment, or a sentinel when absent.
env_of() {
    local v
    v=$(tr '\0' '\n' < "$WORK/env0" 2>/dev/null | grep -m1 "^$1=") || { printf '<unset>'; return; }
    printf '%s' "${v#*=}"
}
env_names() { tr '\0' '\n' < "$WORK/env0" | sed 's/=.*//' | sort | tr '\n' ' '; }
args_of() { tr '\0' '|' < "$WORK/args0"; }

SSH_ENV=(SSH_CLIENT="192.0.2.10 50000 22" SSH_CONNECTION="192.0.2.10 50000 192.0.2.1 22"
         SSH_TTY=/dev/pts/3 TERM=xterm-256color)

# ── 0. Control: the mechanism the launcher exists to defeat ──────────────────
# Not an assertion on the launcher: it shows the markers used below would have
# caught a shell reading startup files, on this host's own bash and zsh.
test_control_shells_read_startup_files() {
    local seen="" sh
    printf 'touch "%s/markers/bashrc"\n' "$WORK" > "$WORK/home/.bashrc"
    printf 'touch "%s/markers/zshenv"\n' "$WORK" > "$WORK/home/.zshenv"
    env -i HOME="$WORK/home" SSH_CLIENT="192.0.2.10 50000 22" bash -c true 2>/dev/null
    [ -e "$WORK/markers/bashrc" ] && seen="$seen bash:~/.bashrc"
    if sh=$(command -v zsh); then
        env -i HOME="$WORK/home" ZDOTDIR="$WORK/home" "$sh" -c true 2>/dev/null
        [ -e "$WORK/markers/zshenv" ] && seen="$seen zsh:~/.zshenv"
    fi
    rm -f "$WORK/markers/"*
    pass "control: shells here read the user's files for -c:${seen:- (none on this host)}"
}

# ── 1. The ForceCommand: exec the recorder, pass the client's command on ────
test_forcecommand_execs_recorder() {
    local bad="" pid
    env -i OB_TEST_RECORDER="$REC" OB_TEST_NSS_CONF="$CONF" "${SSH_ENV[@]}" \
        SSH_ORIGINAL_COMMAND='uptime; id' USER=ob-impostor LOGNAME=ob-impostor \
        HOME=/tmp/ob-impostor \
        SHELL=/bin/zsh "$BIN" -c "$REC" >"$WORK/stderr" 2>&1 &
    pid=$!
    wait "$pid"
    recorder_ran || { fail "the ForceCommand starts the recorder" "it did not run: $(cat "$WORK/stderr")"; return; }
    [ "$(cat "$WORK/pid")" = "$pid" ]                        || bad="$bad not-exec'd(pid)"
    [ "$(args_of)" = "" ]                                    || bad="$bad args:$(args_of)"
    [ "$(env_of SSH_ORIGINAL_COMMAND)" = 'uptime; id' ]      || bad="$bad orig:$(env_of SSH_ORIGINAL_COMMAND)"
    [ "$(env_of USER)" = "$ME" ]                             || bad="$bad USER:$(env_of USER)"
    [ "$(env_of LOGNAME)" = "$ME" ]                          || bad="$bad LOGNAME"
    [ "$(env_of HOME)" = "$MYHOME" ]                         || bad="$bad HOME:$(env_of HOME)"
    [ "$(env_of SHELL)" = /bin/bash ]                        || bad="$bad SHELL:$(env_of SHELL)"
    [ "$(env_of PATH)" = /usr/local/bin:/usr/bin:/bin:/usr/games ] || bad="$bad PATH:$(env_of PATH)"
    [ "$(env_of SSH_CLIENT)" = "192.0.2.10 50000 22" ]       || bad="$bad SSH_CLIENT"
    [ "$(env_of SSH_CONNECTION)" = "192.0.2.10 50000 192.0.2.1 22" ] || bad="$bad SSH_CONNECTION"
    [ "$(env_of SSH_TTY)" = /dev/pts/3 ]                     || bad="$bad SSH_TTY"
    [ "$(env_of TERM)" = xterm-256color ]                    || bad="$bad TERM"
    if [ -z "$bad" ]; then
        pass "the ForceCommand execs the recorder in the same process, identity from passwd, client command passed on"
    else
        fail "the ForceCommand execs the recorder" "$bad"
    fi
}

# ── 2. ...with its options, when they are plain words ───────────────────────
test_forcecommand_with_options() {
    run_ls "${SSH_ENV[@]}" -- -c "$REC -f script  -c /etc/open-bastion/x.conf"
    if recorder_ran && [ "$(args_of)" = "-f|script|-c|/etc/open-bastion/x.conf|" ]; then
        pass "recorder options on the ForceCommand line reach the recorder as arguments"
    else
        fail "recorder options on the ForceCommand line reach the recorder" "args=$(args_of 2>/dev/null)"
    fi
}

# ── 3. Any other command is recorded, never run ──────────────────────────────
test_other_command_is_recorded_not_run() {
    local bad="" cmd
    for cmd in "touch $WORK/markers/ran" \
               "$REC; touch $WORK/markers/ran" \
               "$REC \$(touch $WORK/markers/ran)" \
               "$REC \`touch $WORK/markers/ran\`" \
               "${REC}x" \
               "$REC 'quoted arg'"; do
        rm -f "$WORK/markers/ran"
        run_ls "${SSH_ENV[@]}" SSH_ORIGINAL_COMMAND=from-env -- -c "$cmd"
        [ -e "$WORK/markers/ran" ]                      && bad="$bad ran:[$cmd]"
        recorder_ran                                    || { bad="$bad no-recorder:[$cmd]"; continue; }
        [ "$(env_of SSH_ORIGINAL_COMMAND)" = "$cmd" ]   || bad="$bad orig:[$(env_of SSH_ORIGINAL_COMMAND)]"
        [ "$(args_of)" = "" ]                           || bad="$bad args:[$(args_of)]"
    done
    if [ -z "$bad" ]; then
        pass "a command that is not the recorder is never run: it is handed to the recorder to run, recorded"
    else
        fail "a command that is not the recorder is handed to the recorder" "$bad"
    fi
}

# ── 4. An interactive login goes through the recorder too ───────────────────
test_interactive_goes_through_recorder() {
    local bad="" form
    for form in "" "-l" "--login" "-i" "-l -i"; do
        # shellcheck disable=SC2086  # the options are meant to split
        run_ls "${SSH_ENV[@]}" SSH_ORIGINAL_COMMAND='left over from the caller' -- $form
        recorder_ran                                       || { bad="$bad no-recorder:[$form]"; continue; }
        [ "$(env_of SSH_ORIGINAL_COMMAND)" = '<unset>' ]   || bad="$bad inherited-command:[$form]"
    done
    # As login(1), su - and sudo -i start it: argv[0] "-ob-login-shell".
    rm -f "$WORK/env0"
    env -i OB_TEST_RECORDER="$REC" OB_TEST_NSS_CONF="$CONF" \
        bash -c 'exec -a -ob-login-shell "$1"' _ "$BIN" >/dev/null 2>&1
    recorder_ran || bad="$bad no-recorder:[argv0=-ob-login-shell]"
    # -l -c CMD: a login shell asked for a command.
    run_ls -- -l -c "echo hi"
    [ "$(env_of SSH_ORIGINAL_COMMAND)" = "echo hi" ] || bad="$bad -l-c"
    if [ -z "$bad" ]; then
        pass "an interactive login (none, -l, --login, -i, argv[0] -ob-login-shell) starts the recorder, with no inherited command"
    else
        fail "an interactive login starts the recorder" "$bad"
    fi
}

# ── 5. Anything else is refused, and nothing runs ───────────────────────────
test_unsupported_invocations_refused() {
    local bad="" rc
    local -a forms=("-x" "-c" "-s" "--rcfile" "--norc" "-c|echo hi|extra" "-c|echo hi|--" "--|-c|x")
    local f
    for f in "${forms[@]}"; do
        IFS='|' read -r -a argv <<< "$f"
        rc=0
        run_ls "${SSH_ENV[@]}" -- "${argv[@]}" || rc=$?
        [ "$rc" -ne 0 ] || bad="$bad exit0:[$f]"
        recorder_ran && bad="$bad ran:[$f]"
    done
    if [ -z "$bad" ]; then
        pass "unsupported invocations (other options, -c with no command or with positional arguments) are refused, nothing runs"
    else
        fail "unsupported invocations are refused" "$bad"
    fi
}

# ── 6. The recorder's environment is built, not inherited ───────────────────
test_environment_is_scrubbed() {
    local uid names extra="" bad="" n
    uid=$(id -u)
    run_ls "${SSH_ENV[@]}" SSH_ORIGINAL_COMMAND=ls \
        BASH_ENV="$WORK/home/.bashenv" ENV="$WORK/home/.env" SHELLOPTS=xtrace \
        BASHOPTS=extglob 'BASH_FUNC_echo%%=() { touch /tmp/x; }' PS4='$(id)' \
        IFS=x CDPATH=/tmp GLOBIGNORE='*' LD_LIBRARY_PATH="$WORK" LD_AUDIT="$WORK/a.so" \
        GCONV_PATH="$WORK" LOCPATH="$WORK" NLSPATH="$WORK/%N" TMPDIR="$WORK" \
        HOSTALIASES="$WORK/h" TZ=":$WORK/tz" MAIL=/tmp/m PYTHONPATH="$WORK" \
        OB_MAX_SESSION=0 OB_RECORD_SOCKET="$WORK/sock" OB_RECORDER_CONFIG="$WORK/c" \
        PATH="$WORK:/usr/bin" SHELL=/bin/zsh \
        LANG=C.UTF-8 LANGUAGE=fr_FR:en LC_ALL="$WORK/locale" LC_CTYPE=../../x \
        LC_TIME=en_GB.UTF-8 LC_BOGUS=x \
        SSH_AUTH_SOCK=/tmp/ssh-XXXXabcd/agent.123 \
        XDG_RUNTIME_DIR="/run/user/$uid" XDG_SESSION_ID=c42 XDG_SESSION_TYPE=tty \
        XDG_SESSION_CLASS=user -- -c "$REC"
    recorder_ran || { fail "the recorder's environment is built from scratch" "the recorder did not run"; return; }
    local allowed=" HOME LANG LANGUAGE LC_TIME LOGNAME PATH SHELL SSH_AUTH_SOCK SSH_CLIENT SSH_CONNECTION SSH_ORIGINAL_COMMAND SSH_TTY TERM USER XDG_RUNTIME_DIR XDG_SESSION_CLASS XDG_SESSION_ID XDG_SESSION_TYPE "
    names=$(env_names)
    for n in $names; do
        case "$allowed" in
            *" $n "*) ;;
            *) extra="$extra $n" ;;
        esac
    done
    [ -z "$extra" ] || bad="$bad leaked:$extra"
    [ "$(env_of LANG)" = C.UTF-8 ]                        || bad="$bad LANG"
    [ "$(env_of LANGUAGE)" = fr_FR:en ]                   || bad="$bad LANGUAGE"
    [ "$(env_of LC_TIME)" = en_GB.UTF-8 ]                 || bad="$bad LC_TIME"
    [ "$(env_of SSH_AUTH_SOCK)" = /tmp/ssh-XXXXabcd/agent.123 ] || bad="$bad SSH_AUTH_SOCK"
    [ "$(env_of XDG_RUNTIME_DIR)" = "/run/user/$uid" ]    || bad="$bad XDG_RUNTIME_DIR"
    if [ -z "$bad" ]; then
        pass "the recorder's environment holds only the allow-listed, validated variables (BASH_ENV, LD_*, OB_*, a locale path... dropped)"
    else
        fail "the recorder's environment is built from scratch" "$bad"
    fi
}

# ── 7. Each kept variable is validated ───────────────────────────────────────
test_kept_variables_are_validated() {
    local bad="" kv name
    for kv in "TERM=../../tmp/x" "TERM=xterm;id" "SSH_TTY=/tmp/tty" "SSH_TTY=/dev/../tmp/x" \
              "SSH_CLIENT=1.2.3.4 5 22;id" "SSH_CONNECTION=\$(id)" "LANG=/tmp/locale" \
              "LC_MESSAGES=../x" "SSH_AUTH_SOCK=relative/sock" "SSH_AUTH_SOCK=/tmp/../x" \
              "XDG_RUNTIME_DIR=/tmp/runtime" "XDG_SESSION_ID=a b"; do
        name=${kv%%=*}
        run_ls "$kv" -- -c "$REC"
        [ "$(env_of "$name")" = '<unset>' ] || bad="$bad [$kv]"
    done
    if [ -z "$bad" ]; then
        pass "a kept variable with a path, a traversal or a metacharacter where it has no business is dropped"
    else
        fail "kept variables are validated" "passed through:$bad"
    fi
}

# ── 8. The real shell: default_shell from a root-owned configuration ────────
shell_with_conf() {  # $1 = content of the configuration, or "" for none
    rm -f "$CONF"
    if [ -n "$1" ]; then printf '%s\n' "$1" > "$CONF"; chmod 644 "$CONF"; fi
    run_ls -- -c "$REC"
    env_of SHELL
}

test_real_shell_selection() {
    local bad="" got
    got=$(shell_with_conf "")
    [ "$got" = /bin/bash ] || bad="$bad no-conf:$got"
    got=$(shell_with_conf "default_shell = /bin/sh")
    [ "$got" = /bin/sh ] || bad="$bad sh:$got"
    got=$(shell_with_conf 'default_shell = "/bin/sh"')
    [ "$got" = /bin/sh ] || bad="$bad quoted:$got"
    got=$(shell_with_conf $'default_shell = /bin/dash\ndefault_shell = /bin/sh')
    [ "$got" = /bin/sh ] || bad="$bad last-wins:$got"
    got=$(shell_with_conf "force_shell = /bin/sh")
    [ "$got" = /bin/bash ] || bad="$bad force_shell-is-not-it:$got"
    if [ -z "$bad" ]; then
        pass "the recorded session's shell is default_shell from nss_openbastion.conf, else /bin/bash"
    else
        fail "the recorded session's shell is default_shell" "$bad"
    fi
}

test_real_shell_config_must_be_trusted() {
    local bad="" got
    printf 'default_shell = /bin/sh\n' > "$CONF"
    chmod 664 "$CONF"
    run_ls -- -c "$REC"
    [ "$(env_of SHELL)" = /bin/bash ] || bad="$bad group-writable:$(env_of SHELL)"
    chmod 646 "$CONF"
    run_ls -- -c "$REC"
    [ "$(env_of SHELL)" = /bin/bash ] || bad="$bad world-writable:$(env_of SHELL)"
    # A symlink is not followed (O_NOFOLLOW), even to a good file.
    printf 'default_shell = /bin/sh\n' > "$WORK/real.conf"
    chmod 644 "$WORK/real.conf"
    rm -f "$CONF"
    ln -s "$WORK/real.conf" "$CONF"
    run_ls -- -c "$REC"
    [ "$(env_of SHELL)" = /bin/bash ] || bad="$bad symlink:$(env_of SHELL)"
    rm -f "$CONF"
    printf 'default_shell = /bin/sh\n' > "$CONF"
    chmod 644 "$CONF"
    # Not root's: refused by the build that keeps the shipped owner check.
    if [ "$(id -u)" != 0 ]; then
        USE_BIN="$STRICT" run_ls -- -c "$REC"
        [ "$(env_of SHELL)" = /bin/bash ] || bad="$bad not-root-owned:$(env_of SHELL)"
        # ...and the same file is taken when its owner is the trusted one.
        run_ls -- -c "$REC"
        [ "$(env_of SHELL)" = /bin/sh ] || bad="$bad trusted-owner-refused:$(env_of SHELL)"
    else
        echo "  --   running as root: the not-root-owned case is exercised unprivileged"
    fi
    if [ -z "$bad" ]; then
        pass "a configuration that is writable by others, a symlink, or not root's is ignored"
    else
        fail "the configuration naming the shell must be root's and writable only by root" "$bad"
    fi
}

test_real_shell_never_loops() {
    local bad="" got
    ln -s "$BIN" "$WORK/launcher-link"
    ln -s "$REC" "$WORK/recorder-link"
    printf '#!/bin/sh\n' > "$WORK/not-exec"
    chmod 644 "$WORK/not-exec"
    for s in "$WORK/launcher-link" "$WORK/recorder-link" "$REC" "$WORK/not-exec" \
             /nonexistent/sh bash "/bin/../bin/sh" "$WORK"; do
        got=$(shell_with_conf "default_shell = $s")
        [ "$got" = /bin/bash ] || bad="$bad [$s]->$got"
    done
    if [ -z "$bad" ]; then
        pass "default_shell is refused (bash instead) when it is the launcher, the recorder, not an executable file, or not a plain absolute path"
    else
        fail "default_shell is refused when unusable" "$bad"
    fi
}

# ── 9. A recorder that cannot start refuses the session ─────────────────────
test_missing_recorder_fails_closed() {
    local rc=0
    rm -f "$WORK/env0"
    env -i OB_TEST_RECORDER="$WORK/no-such-recorder" OB_TEST_NSS_CONF="$CONF" \
        "$BIN" -c "$WORK/no-such-recorder" >"$WORK/stderr" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ] && grep -q 'access refused' "$WORK/stderr"; then
        pass "no recorder: the session is refused (exit $rc), nothing else is started"
    else
        fail "no recorder: the session is refused" "rc=$rc $(cat "$WORK/stderr")"
    fi
}

run_test test_control_shells_read_startup_files
run_test test_forcecommand_execs_recorder
run_test test_forcecommand_with_options
run_test test_other_command_is_recorded_not_run
run_test test_interactive_goes_through_recorder
run_test test_unsupported_invocations_refused
run_test test_environment_is_scrubbed
run_test test_kept_variables_are_validated
run_test test_real_shell_selection
run_test test_real_shell_config_must_be_trusted
run_test test_real_shell_never_loops
run_test test_missing_recorder_fails_closed

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
