# shellcheck shell=bash
# lib_setup_script.sh — reach the setup script under the name an admin uses.
#
# scripts/ob-bastion-setup is the only implementation of the three setup
# commands. ob-backend-setup and ob-standalone-setup are symlinks the build
# makes, and the name the script is invoked under chooses the default node
# role (#288). A test of the backend role therefore has to reach the script
# as "ob-backend-setup" -- sourcing ob-bastion-setup would silently test a
# bastion instead.
#
#   load_setup_as NAME   eval the script's definitions as if invoked as NAME,
#                        without running main() and without `set -e`
#   setup_command NAME   print a path that runs the script as NAME
#
# Sourcing this file creates a temporary directory for the command links and
# removes it on EXIT; a test that sets its own EXIT trap must remove
# "$SETUP_LINK_DIR" itself.

SETUP_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../scripts" && pwd)/ob-bastion-setup"

SETUP_LINK_DIR=$(mktemp -d)
trap 'rm -rf "$SETUP_LINK_DIR"' EXIT
ln -s "$SETUP_SCRIPT" "$SETUP_LINK_DIR/ob-bastion-setup"
ln -s "$SETUP_SCRIPT" "$SETUP_LINK_DIR/ob-backend-setup"
ln -s "$SETUP_SCRIPT" "$SETUP_LINK_DIR/ob-standalone-setup"

setup_command() {
    printf '%s/%s' "$SETUP_LINK_DIR" "$1"
}

load_setup_as() {
    local name="$1" content
    local line='PROG_NAME=$(basename "$0")'
    content=$(cat "$SETUP_SCRIPT")
    content="${content%main \"\$@\"}"
    content=$(printf '%s\n' "$content" | sed -E 's/^set -e(uo pipefail)?$//')
    # The substitution is what selects the role. If the line ever changes
    # shape, fail loudly rather than load the script as a bastion.
    if [ "$(grep -cxF "$line" <<<"$content")" != "1" ]; then
        echo "lib_setup_script: '$line' not found exactly once in $SETUP_SCRIPT" >&2
        return 1
    fi
    content="${content/"$line"/PROG_NAME=$name}"
    eval "$content"
}
