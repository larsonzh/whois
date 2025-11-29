#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDEN_CHECK="$SCRIPT_DIR/golden_check.sh"

usage() {
  cat <<EOF
Usage: $(basename "$0") <preset> [--selftest-actions list] -l <smoke_log> [extra golden_check.sh args]

Presets:
  raw           Header/referral/tail only (no batch action constraints)
  health-first  Requires debug-penalize,start-skip,force-last actions
  plan-a        Requires plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize actions

Example:
  $(basename "$0") health-first -l ./out/artifacts/<ts>/build_out/smoke_test.log
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

preset="$1"
shift

selftest_actions=""
passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --selftest-actions)
      if [[ $# -lt 2 ]]; then
        echo "--selftest-actions requires a value" >&2
        exit 2
      fi
      selftest_actions="$2"
      shift 2
      ;;
    --selftest-actions=*)
      selftest_actions="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      passthrough_args+=("$1")
      shift
      ;;
  esac
done

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
  *)
    echo "Unknown preset: $preset" >&2
    usage
    exit 2
    ;;
esac

if [[ -n "$selftest_actions" ]]; then
  preset_args+=("--selftest-actions" "$selftest_actions")
fi

exec "$GOLDEN_CHECK" "${preset_args[@]}" "${passthrough_args[@]}"
