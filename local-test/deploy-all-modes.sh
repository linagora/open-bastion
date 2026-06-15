#!/usr/bin/env bash
# Run the Ansible deploy harness once per PAM scenario (all five modes), each on
# a freshly recreated lab (bastion + 2 backends + standalone). Prints a per-mode
# PASS/FAIL scoreboard. NOT run in CI (needs libvirt VMs + the Docker SSO).
#
# Usage:  local-test/deploy-all-modes.sh [scenario ...]
#         OB_GOLDEN=... local-test/deploy-all-modes.sh        # all five modes
#         local-test/deploy-all-modes.sh max-security         # one mode
set -uo pipefail
LT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCENARIOS=("$@")
[ "${#SCENARIOS[@]}" -gt 0 ] || SCENARIOS=(token-only token+unix keys+llng mixed max-security)

declare -A RESULT
overall=0
for scen in "${SCENARIOS[@]}"; do
    log="$LT_DIR/.work/all-modes-$scen.log"
    printf '\n############ scenario=%s ############\n' "$scen"
    # Reuse the build + SSO across runs to save time; the harness still recreates
    # the VMs every run, which is what we want for an isolated per-mode test.
    if OB_SCENARIO="$scen" SKIP_BUILD="${SKIP_BUILD:-0}" "$LT_DIR/deploy-ansible.sh" 2>&1 | tee "$log"; then
        RESULT[$scen]="PASS"
    else
        RESULT[$scen]="FAIL"; overall=1
    fi
    # After the first run the .deb is staged, so skip rebuilding for the rest.
    SKIP_BUILD=1
done

printf '\n================ all-modes scoreboard ================\n'
for scen in "${SCENARIOS[@]}"; do printf '  %-14s %s\n' "$scen" "${RESULT[$scen]}"; done
exit "$overall"
