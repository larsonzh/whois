#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDEN_CHECK="$SCRIPT_DIR/golden_check.sh"

usage() {
  cat <<EOF
Usage: $(basename "$0") <preset> [--selftest-actions list] [--backoff-actions list] [--pref-labels list] -l <smoke_log> [extra golden_check.sh args]

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
backoff_actions=""
preset_pref_labels=""
preset_backoff_default=""
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
    --backoff-actions)
      if [[ $# -lt 2 ]]; then
        echo "--backoff-actions requires a value" >&2
        exit 2
      fi
      backoff_actions="$2"
      shift 2
      ;;
    --backoff-actions=*)
      backoff_actions="${1#*=}"
      shift
      ;;
    --pref-labels)
      if [[ $# -lt 2 ]]; then
        echo "--pref-labels requires a value" >&2
        exit 2
      fi
      preset_pref_labels="$2"
      shift 2
      ;;
    --pref-labels=*)
      preset_pref_labels="${1#*=}"
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
    preset_backoff_default="skip,force-last"
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
if [[ -n "$backoff_actions" ]]; then
  preset_args+=("--backoff-actions" "$backoff_actions")
elif [[ -n "$preset_backoff_default" ]]; then
  preset_args+=("--backoff-actions" "$preset_backoff_default")
fi
if [[ -n "$preset_pref_labels" ]]; then
  preset_args+=("--pref-labels" "$preset_pref_labels")
fi

exec "$GOLDEN_CHECK" "${preset_args[@]}" "${passthrough_args[@]}"
