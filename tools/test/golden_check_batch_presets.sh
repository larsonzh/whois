#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDEN_CHECK="$SCRIPT_DIR/golden_check.sh"

usage() {
  cat <<EOF
Usage: $(basename "$0") <preset> -l <smoke_log> [extra golden_check.sh args]

Presets:
  raw           Header/referral/tail only (no batch action constraints)
  health-first  Requires debug-penalize,start-skip,force-last actions
  plan-a        Requires plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize actions

Example:
  $(basename "$0") health-first -l ./out/artifacts/<ts>/build_out/smoke_test.log
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

preset="$1"
shift

case "$preset" in
  raw)
    preset_args=()
    ;;
  health-first)
    preset_args=("--batch-actions" "debug-penalize,start-skip,force-last")
    ;;
  plan-a)
    preset_args=("--batch-actions" "plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize")
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown preset: $preset" >&2
    usage
    exit 2
    ;;
esac

exec "$GOLDEN_CHECK" "${preset_args[@]}" "$@"
