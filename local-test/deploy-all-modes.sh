#!/usr/bin/env bash
# Run the deploy harness(es) once per PAM scenario (all five modes), each on a
# freshly recreated lab (bastion + 2 backends + standalone). Exercises all three
# target roles (bastion, backend, standalone) every run. Prints a per-mode,
# per-harness PASS/FAIL scoreboard. NOT run in CI (needs libvirt VMs + Docker SSO).
#
# Usage:  local-test/deploy-all-modes.sh [scenario ...]
#         OB_GOLDEN=... local-test/deploy-all-modes.sh           # both harnesses, all 5 modes
#         OB_HARNESS=shell    local-test/deploy-all-modes.sh     # shell harness only
#         OB_HARNESS=ansible  local-test/deploy-all-modes.sh max-security
#
# Env:
#   OB_HARNESS   space-separated subset of {ansible shell}; default "ansible shell"
#   OB_GOLDEN    genericcloud golden image (else auto-detected by lib.sh)
#   SKIP_BUILD   reuse a previously staged .deb (auto-set to 1 after the 1st run)
set -uo pipefail
LT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCENARIOS=("$@")
[ "${#SCENARIOS[@]}" -gt 0 ] || SCENARIOS=(token-only token+unix keys+llng mixed max-security)
read -ra HARNESSES <<< "${OB_HARNESS:-ansible shell}"

declare -A RESULT
overall=0
for harness in "${HARNESSES[@]}"; do
    script="$LT_DIR/deploy-$harness.sh"
    [ -x "$script" ] || { echo "unknown harness: $harness ($script missing)" >&2; exit 2; }
    for scen in "${SCENARIOS[@]}"; do
        log="$LT_DIR/.work/all-modes-$harness-$scen.log"
        printf '\n############ harness=%s scenario=%s ############\n' "$harness" "$scen"
        # Reuse the build + SSO across runs to save time; the harness still
        # recreates the VMs every run, which is what we want for isolation.
        if OB_SCENARIO="$scen" SKIP_BUILD="${SKIP_BUILD:-0}" "$script" 2>&1 | tee "$log"; then
            RESULT["$harness/$scen"]="PASS"
        else
            RESULT["$harness/$scen"]="FAIL"; overall=1
        fi
        # After the first run the .deb is staged, so skip rebuilding for the rest.
        SKIP_BUILD=1
    done
done

printf '\n================ all-modes scoreboard ================\n'
printf '  %-14s' 'scenario'; for h in "${HARNESSES[@]}"; do printf ' %-8s' "$h"; done; printf '\n'
for scen in "${SCENARIOS[@]}"; do
    printf '  %-14s' "$scen"
    for h in "${HARNESSES[@]}"; do printf ' %-8s' "${RESULT[$h/$scen]:-?}"; done
    printf '\n'
done
exit "$overall"
