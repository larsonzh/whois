#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: golden_check_selftest.sh -l <smoke_log> [--expect action=force-suspicious,query=8.8.8.8] \
  [--require-error <regex>] [--require-line <regex>] [--require-tag <component> <regex>]

Options:
  -l, --log PATH              Path to smoke_test.log (default: ./out/build_out/smoke_test.log)
  --expect SPEC               Expect a [SELFTEST] entry. SPEC supports:
                               - action=<name> (required)
                               - query=<value> (optional)
                               - match=<regex> (optional extra matcher)
                              Example: --expect action=force-private,query=10.0.0.8
          Repeat --expect for multiple actions (e.g., force-suspicious + force-private).
  --require-error REGEX       Require an Error line matching REGEX (can be repeated)
  --require-line REGEX        Require a complete output line matching REGEX (can be repeated)
  --require-tag COMPONENT REGEX
                              Require a tagged line like [COMPONENT] ... matching REGEX
  -h, --help                  Show this help

Exit code 0 indicates all expectations satisfied.
EOF
}

LOG="./out/build_out/smoke_test.log"
EXPECTS=()
ERROR_REGEXES=()
LINE_REGEXES=()
TAG_EXPECTS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--log)
      LOG="$2"; shift 2 ;;
    --expect)
      EXPECTS+=("$2"); shift 2 ;;
    --require-error)
      ERROR_REGEXES+=("$2"); shift 2 ;;
    --require-line)
      LINE_REGEXES+=("$2"); shift 2 ;;
    --require-tag)
      if [[ $# -lt 3 ]]; then
        echo "[golden-selftest][ERROR] --require-tag needs COMPONENT and REGEX" >&2
        exit 2
      fi
      TAG_EXPECTS+=("$2|||$3"); shift 3 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -s "$LOG" ]]; then
  echo "[golden-selftest][ERROR] smoke log missing or empty: $LOG" >&2
  exit 1
fi

status=0
log_match_success() {
  echo "[golden-selftest][INFO] $1"
}
log_match_error() {
  echo "[golden-selftest][ERROR] $1" >&2
  status=1
}

for spec in "${EXPECTS[@]}"; do
  [[ -z "$spec" ]] && continue
  action=""
  query=""
  extra=""
  IFS=',' read -ra kv <<<"$spec"
  for pair in "${kv[@]}"; do
    trimmed="${pair//[[:space:]]/}"
    [[ -z "$trimmed" ]] && continue
    case "$trimmed" in
      action=*) action="${trimmed#action=}" ;;
      query=*) query="${trimmed#query=}" ;;
      match=*) extra="${trimmed#match=}" ;;
      *) log_match_error "Unknown expect token '$trimmed'" ;;
    esac
  done
  if [[ -z "$action" ]]; then
    log_match_error "--expect missing action=... in '$spec'"
    continue
  fi
  pattern="\\[SELFTEST\\][^\\n]*action=${action//\//\\/}"
  if [[ -n "$query" ]]; then
    pattern+="[^\\n]*query=${query//\//\\/}"
  fi
  if [[ -n "$extra" ]]; then
    pattern+="[^\\n]*${extra}"
  fi
  if grep -E "$pattern" "$LOG" >/dev/null; then
    log_match_success "found action=$action${query:+ query=$query}"
  else
    query_suffix=""
    if [[ -n "$query" ]]; then
      query_suffix=" for query '$query'"
    fi
    log_match_error "missing [SELFTEST] action '$action'$query_suffix"
  fi
done

for re in "${ERROR_REGEXES[@]}"; do
  [[ -z "$re" ]] && continue
  if grep -E "$re" "$LOG" >/dev/null; then
    log_match_success "error pattern matched: $re"
  else
    log_match_error "missing error pattern: $re"
  fi
done

for re in "${LINE_REGEXES[@]}"; do
  [[ -z "$re" ]] && continue
  if sed 's/\r$//' "$LOG" | grep -E "^(${re})$" >/dev/null; then
    log_match_success "output line matched: $re"
  else
    log_match_error "missing output line: $re"
  fi
done

for tag_spec in "${TAG_EXPECTS[@]}"; do
  [[ -z "$tag_spec" ]] && continue
  IFS='|||' read -r component regex <<<"$tag_spec"
  if [[ -z "$component" || -z "$regex" ]]; then
    log_match_error "invalid --require-tag spec: $tag_spec"
    continue
  fi
  component_clean="${component//[[:space:]]/}"
  tag_pattern="\\[${component_clean}\\].*${regex}"
  if grep -E "$tag_pattern" "$LOG" >/dev/null; then
    log_match_success "tag [$component_clean] matched regex: $regex"
  else
    log_match_error "missing [$component_clean] regex: $regex"
  fi
done

if [[ "$status" -eq 0 ]]; then
  echo "[golden-selftest] PASS"
else
  echo "[golden-selftest] FAIL"
fi

exit "$status"
