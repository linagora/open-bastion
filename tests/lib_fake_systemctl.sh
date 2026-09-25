# shellcheck shell=bash
# lib_fake_systemctl.sh — a systemctl that keeps unit state in a directory.
#
#   fake_systemctl DIR   write DIR/bin/systemctl; put DIR/bin first in PATH to
#                        use it
#
# It understands what the timer code asks of it (daemon-reload, enable,
# disable, start, restart, stop, is-enabled, is-active) and nothing else. State
# is one file per unit and property -- DIR/state/<unit>.enabled and .active --
# so a test can both preset it and check it. Every call is appended to
# DIR/calls, one line each.
#
# Two knobs, as files so they survive the subshells the code under test runs
# in:
#   DIR/fail-enable   `enable` exits 1 and changes nothing
#   DIR/fail-start    `start` / `restart` exit 1 and change nothing

fake_systemctl() {
    local dir="$1"
    mkdir -p "$dir/bin" "$dir/state"
    : > "$dir/calls"
    cat > "$dir/bin/systemctl" <<EOF
#!/bin/bash
dir="$dir"
echo "\$*" >> "\$dir/calls"
verb=""; unit=""
for a in "\$@"; do
    case "\$a" in
        --*) ;;
        *) if [ -z "\$verb" ]; then verb="\$a"; else unit="\$a"; fi ;;
    esac
done
case "\$verb" in
    daemon-reload) exit 0 ;;
    enable)
        [ -e "\$dir/fail-enable" ] && exit 1
        touch "\$dir/state/\$unit.enabled" ;;
    disable) rm -f "\$dir/state/\$unit.enabled" ;;
    start|restart)
        [ -e "\$dir/fail-start" ] && exit 1
        touch "\$dir/state/\$unit.active" ;;
    stop) rm -f "\$dir/state/\$unit.active" ;;
    is-enabled) [ -e "\$dir/state/\$unit.enabled" ] ;;
    is-active)  [ -e "\$dir/state/\$unit.active" ] ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$dir/bin/systemctl"
}
