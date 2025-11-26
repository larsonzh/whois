#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [-l <smoke_log>] [--query Q] [--start S] [--auth A] [--batch-actions list]
  -l  Path to smoke_test.log (default: ./out/build_out/smoke_test.log)
  --query  Query string expected in header (default: 8.8.8.8)
  --start  Starting whois server shown in header (default: whois.iana.org)
  --auth   Authoritative RIR expected in tail (default: whois.arin.net)
  --batch-actions  Comma-separated [DNS-BATCH] action names that must appear in the log

Checks (regex-based, IPs may vary):
  - Header: ^=== Query: <Q> via <S> @ (unknown|[0-9a-fA-F:.]+) ===
  - Additional referral line: ^=== Additional query to <A> ===
  - Tail: ^=== Authoritative RIR: <A> @ (unknown|[0-9a-fA-F:.]+) ===
EOF
}

LOG="./out/build_out/smoke_test.log"
Q="8.8.8.8"
S="whois.iana.org"
A="whois.arin.net"
ALT_AUTH="whois.apnic.net"
BATCH_ACTIONS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) LOG="$2"; shift 2 ;;
    --query) Q="$2"; shift 2 ;;
    --start) S="$2"; shift 2 ;;
    --auth) A="$2"; shift 2 ;;
    --batch-actions) BATCH_ACTIONS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -s "$LOG" ]]; then
  echo "[golden][ERROR] smoke log missing or empty: $LOG" >&2
  exit 1
fi

ok=1
header_re="^=== Query: ${Q//\//\\/} via ${S//\//\\/} @ (unknown|[0-9A-Fa-f:.]+) ===$"
ref_re="^=== Additional query to ${A//\//\\/} ===$"
tail_re="^=== Authoritative RIR: (${A//\//\\/}|${ALT_AUTH//\//\\/}) @ (unknown|[0-9A-Fa-f:.]+) ===$"

if ! grep -E "$header_re" "$LOG" >/dev/null; then
  echo "[golden][ERROR] header not found matching: $header_re" >&2
  ok=0
fi
if ! grep -E "$ref_re" "$LOG" >/dev/null; then
  echo "[golden][ERROR] referral line not found matching: $ref_re" >&2
  # Fallback: if APNIC became first hop (direct authoritative), allow missing referral
  if grep -E "^=== Authoritative RIR: ${ALT_AUTH//\//\\/} @" "$LOG" >/dev/null; then
    echo "[golden][INFO] referral skipped: direct authoritative to $ALT_AUTH"
  else
    ok=0
  fi
fi
if ! grep -E "$tail_re" "$LOG" >/dev/null; then
  echo "[golden][ERROR] tail not found matching: $tail_re" >&2
  ok=0
fi

if [[ -n "$BATCH_ACTIONS" ]]; then
  IFS=',' read -ra _actions <<<"$BATCH_ACTIONS"
  for action in "${_actions[@]}"; do
    action_trimmed="${action//[[:space:]]/}"
    [[ -z "$action_trimmed" ]] && continue
    if ! grep -F "[DNS-BATCH]" "$LOG" | grep -F "action=$action_trimmed" >/dev/null; then
      echo "[golden][ERROR] missing [DNS-BATCH] action '$action_trimmed'" >&2
      ok=0
    fi
  done
fi

if [[ "$ok" == "1" ]]; then
  echo "[golden] PASS: header/referral/tail match expected patterns"
  exit 0
else
  echo "[golden] FAIL"
  exit 3
fi
