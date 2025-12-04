#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: referral_143128_check.sh [--iana-log path] [--arin-log path] [--afrinic-log path]
  Validates that the captured logs for `-h iana|arin|afrinic 143.128.0.0 --debug --retry-metrics --dns-cache-stats`
  resolve to AfriNIC and keep the expected referral chain. Both "Additional" and "Redirected"
  query lines are accepted when verifying each hop.

Default paths:
  --iana-log     out/iana-143.128.0.0
  --arin-log     out/arin-143.128.0.0
  --afrinic-log  out/afrinic-143.128.0.0
EOF
}

IANA_LOG="out/iana-143.128.0.0"
ARIN_LOG="out/arin-143.128.0.0"
AFRINIC_LOG="out/afrinic-143.128.0.0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iana-log) IANA_LOG="$2"; shift 2 ;;
    --arin-log) ARIN_LOG="$2"; shift 2 ;;
    --afrinic-log) AFRINIC_LOG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

require_log() {
  local log_path="$1"
  local label="$2"
  if [[ ! -s "$log_path" ]]; then
    echo "[referral][ERROR] $label log missing or empty: $log_path" >&2
    return 1
  fi
  return 0
}

check_log() {
  local log_path="$1"
  local start_host="$2"
  local extras_str="$3"
  local extras=()
  if [[ -n "$extras_str" ]]; then
    read -ra extras <<<"$extras_str"
  fi
  require_log "$log_path" "$start_host" || return 1

  local escaped_start=${start_host//\./\\.}
  local header_re="^=== Query: 143\\.128\\.0\\.0 via ${escaped_start} @ (unknown|[0-9A-Fa-f:.]+) ===$"
  if ! grep -E "$header_re" "$log_path" >/dev/null; then
    echo "[referral][ERROR] $start_host header missing in $log_path" >&2
    return 1
  fi

  for extra in "${extras[@]}"; do
    local escaped_extra=${extra//\./\\.}
    local add_re="^=== Additional query to ${escaped_extra} ===$"
    local redir_re="^=== Redirected query to ${escaped_extra} ===$"
    if ! grep -E "$add_re" "$log_path" >/dev/null && ! grep -E "$redir_re" "$log_path" >/dev/null; then
      echo "[referral][ERROR] missing 'Additional/Redirected query to $extra' in $log_path" >&2
      return 1
    fi
  done

  local tail_re="^=== Authoritative RIR: whois\\.afrinic\\.net @ (unknown|[0-9A-Fa-f:.]+) ===$"
  if ! grep -E "$tail_re" "$log_path" >/dev/null; then
    echo "[referral][ERROR] AfriNIC authoritative tail missing in $log_path" >&2
    return 1
  fi

  echo "[referral] PASS $start_host -> whois.afrinic.net ($log_path)"
  return 0
}

status=
check_log "$IANA_LOG" "whois.iana.org" "whois.arin.net whois.afrinic.net" || status=1
check_log "$ARIN_LOG" "whois.arin.net" "whois.afrinic.net" || status=1
check_log "$AFRINIC_LOG" "whois.afrinic.net" "" || status=1

exit $status
