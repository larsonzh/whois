#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: referral_143128_check.sh [--ref-dir path] [--cases "query@h1,h2,h3@auth;..."]
       [--iana-log path] [--arin-log path] [--afrinic-log path]

Generalized multi-hop referral check. By default it validates the chain
143.128.0.0 -> whois.iana.org -> whois.arin.net -> whois.afrinic.net using
logs under out/referral_checks/143.128.0.0/<host>.log

Options:
  --ref-dir DIR     Base directory containing per-case subfolders (default: out/referral_checks)
  --cases SPEC      Semicolon-separated cases. Each case: query@host1,host2,...@auth
                    - auth is optional; defaults to last host
                    - example: "143.128.0.0@whois.iana.org,whois.arin.net,whois.afrinic.net@whois.afrinic.net"

Legacy compatibility (single fixed case, older layouts):
  --iana-log PATH   Direct path to iana log
  --arin-log PATH   Direct path to arin log
  --afrinic-log PATH Direct path to afrinic log
EOF
}

REF_DIR="out/referral_checks"
CASES="143.128.0.0@whois.iana.org,whois.arin.net,whois.afrinic.net@whois.afrinic.net"
IANA_LOG="out/iana-143.128.0.0"
ARIN_LOG="out/arin-143.128.0.0"
AFRINIC_LOG="out/afrinic-143.128.0.0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref-dir) REF_DIR="$2"; shift 2 ;;
    --cases) CASES="$2"; shift 2 ;;
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
  local query="$2"
  local start_host="$3"
  local extras_str="$4"
  local auth_host="$5"
  local extras=()
  if [[ -n "$extras_str" ]]; then
    read -ra extras <<<"$extras_str"
  fi
  require_log "$log_path" "$start_host" || return 1

  local escaped_start=${start_host//\./\\.}
  local escaped_query=${query//\./\\.}
  local header_re="^=== Query: ${escaped_query} via ${escaped_start} @ (unknown|[0-9A-Fa-f:.]+) ===$"
  if ! grep -E "$header_re" "$log_path" >/dev/null; then
    echo "[referral][WARN] $start_host header missing in $log_path (non-fatal)" >&2
  fi

  for extra in "${extras[@]}"; do
    local escaped_extra=${extra//\./\\.}
    local add_re="^=== Additional query to ${escaped_extra} ===$"
    local redir_re="^=== Redirected query to ${escaped_extra} ===$"
    if ! grep -E "$add_re" "$log_path" >/dev/null && ! grep -E "$redir_re" "$log_path" >/dev/null; then
      echo "[referral][WARN] missing 'Additional/Redirected query to $extra' in $log_path (non-fatal)" >&2
    fi
  done

  local escaped_auth=${auth_host//\./\\.}
  local tail_re="^=== Authoritative RIR: ${escaped_auth} @ (unknown|[0-9A-Fa-f:.]+) ===$"
  if ! grep -E "$tail_re" "$log_path" >/dev/null; then
    echo "[referral][ERROR] Authoritative tail missing (${auth_host}) in $log_path" >&2
    return 1
  fi

  echo "[referral] PASS $start_host -> $auth_host ($log_path)"
  return 0
}

sanitize_label() {
  echo "$1" | tr ' /\\\n\r\t' '_' | sed -E 's/[^A-Za-z0-9._-]+/_/g; s/^_+//; s/_+$//'
}

trim_ws() {
  echo "$1" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//'
}

run_cases() {
  local cases_str="$1"
  local ref_dir="$2"
  local status=0
  IFS=';' read -ra case_arr <<<"$cases_str"
  for case_spec in "${case_arr[@]}"; do
    [[ -z "$case_spec" ]] && continue
    IFS='@' read -ra parts <<<"$case_spec"
    local query="$(trim_ws "${parts[0]:-143.128.0.0}")"
    local hosts_raw="${parts[1]:-whois.iana.org,whois.arin.net,whois.afrinic.net}"
    local auth_host="$(trim_ws "${parts[2]:-}")"
    IFS=',' read -ra hosts <<<"$hosts_raw"
    local cleaned_hosts=()
    for h in "${hosts[@]}"; do
      h_trim=$(trim_ws "$h")
      [[ -z "$h_trim" ]] && continue
      cleaned_hosts+=("$h_trim")
    done
    hosts=("${cleaned_hosts[@]}")
    if [[ -z "$auth_host" ]]; then
      auth_host="${hosts[-1]}"
    fi
    if ((${#hosts[@]}==0)); then
      echo "[referral][ERROR] Empty host list in case '$case_spec'" >&2
      status=1; continue
    fi
    label=$(sanitize_label "$query")
    case_dir="$ref_dir/$label"
    for idx in "${!hosts[@]}"; do
      start_host="${hosts[$idx]}"
      extras=("${hosts[@]:$((idx+1))}")
      extras_join="${extras[*]}"
      log_path="$case_dir/$(sanitize_label "$start_host").log"
      if ! check_log "$log_path" "$query" "$start_host" "$extras_join" "$auth_host"; then
        status=1
      fi
    done
  done
  return $status
}

if [[ -n "$CASES" ]]; then
  run_cases "$CASES" "$REF_DIR" || exit 1
  exit 0
fi

# Legacy mode (fixed 143.128.0.0 chain)
status=
check_log "$IANA_LOG" "143.128.0.0" "whois.iana.org" "whois.arin.net whois.afrinic.net" "whois.afrinic.net" || status=1
check_log "$ARIN_LOG" "143.128.0.0" "whois.arin.net" "whois.afrinic.net" "whois.afrinic.net" || status=1
check_log "$AFRINIC_LOG" "143.128.0.0" "whois.afrinic.net" "" "whois.afrinic.net" || status=1

exit $status
