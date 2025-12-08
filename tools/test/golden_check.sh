#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [-l <smoke_log>] [--query Q] [--start S] [--auth A] [--batch-actions list] [--backoff-actions list] [--selftest-actions list]
  --pref-labels  Comma-separated preference labels that must appear (accepts either bare values like v4-then-v6-hop0 or literals like pref=v4-first)
  --auth-unknown-when-capped  Expect tail to be 'Authoritative RIR: unknown @ unknown' (e.g., when -R caps the referral chain)
  --redirect-line <host>      Require a '=== Redirected query to <host> ===' line (useful with capped referrals)
  -l  Path to smoke_test.log (default: ./out/build_out/smoke_test.log)
  --query  Query string expected in header (default: 8.8.8.8)
  --start  Starting whois server shown in header (default: whois.iana.org)
  --auth   Authoritative RIR expected in tail (default: whois.arin.net)
  --batch-actions  Comma-separated [DNS-BATCH] action names that must appear in the log
  --backoff-actions  Comma-separated [DNS-BACKOFF] action names that must appear in the log
  --selftest-actions  Comma-separated \`[SELFTEST] action=<name>\` entries that must appear (e.g., force-suspicious,force-private)

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
BACKOFF_ACTIONS=""
SELFTEST_ACTIONS=""
PREF_LABELS=""
AUTH_UNKNOWN_WHEN_CAPPED=0
REDIRECT_LINE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) LOG="$2"; shift 2 ;;
    --query) Q="$2"; shift 2 ;;
    --start) S="$2"; shift 2 ;;
    --auth) A="$2"; shift 2 ;;
    --batch-actions) BATCH_ACTIONS="$2"; shift 2 ;;
    --backoff-actions) BACKOFF_ACTIONS="$2"; shift 2 ;;
    --selftest-actions) SELFTEST_ACTIONS="$2"; shift 2 ;;
    --pref-labels) PREF_LABELS="$2"; shift 2 ;;
    --auth-unknown-when-capped) AUTH_UNKNOWN_WHEN_CAPPED=1; shift 1 ;;
    --redirect-line) REDIRECT_LINE="$2"; shift 2 ;;
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
  if [[ "$A" == "$S" ]]; then
    echo "[golden][INFO] referral skipped: start host already authoritative"
  elif grep -E "^=== Authoritative RIR: ${ALT_AUTH//\//\/} @" "$LOG" >/dev/null; then
    echo "[golden][INFO] referral skipped: direct authoritative to $ALT_AUTH"
  else
    ok=0
  fi
fi
if [[ "$AUTH_UNKNOWN_WHEN_CAPPED" == "1" ]]; then
  tail_re="^=== Authoritative RIR: unknown @ unknown ===$"
else
  tail_re="^=== Authoritative RIR: (${A//\//\\/}|${ALT_AUTH//\//\\/}) @ (unknown|[0-9A-Fa-f:.]+) ===$"
fi
if ! grep -E "$tail_re" "$LOG" >/dev/null; then
  echo "[golden][ERROR] tail not found matching: $tail_re" >&2
  ok=0
fi

if [[ -n "$REDIRECT_LINE" ]]; then
  redir_re="^=== Redirected query to ${REDIRECT_LINE//\//\\/} ===$"
  if ! grep -E "$redir_re" "$LOG" >/dev/null; then
    echo "[golden][ERROR] redirect line not found matching: $redir_re" >&2
    ok=0
  fi
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

if [[ -n "$BACKOFF_ACTIONS" ]]; then
  IFS=',' read -ra _backoff_actions <<<"$BACKOFF_ACTIONS"
  for action in "${_backoff_actions[@]}"; do
    action_trimmed="${action//[[:space:]]/}"
    [[ -z "$action_trimmed" ]] && continue
    if ! grep -F "[DNS-BACKOFF]" "$LOG" | grep -F "action=$action_trimmed" >/dev/null; then
      echo "[golden][ERROR] missing [DNS-BACKOFF] action '$action_trimmed'" >&2
      ok=0
    fi
  done
fi

if [[ -n "$SELFTEST_ACTIONS" ]]; then
  IFS=',' read -ra _st_actions <<<"$SELFTEST_ACTIONS"
  for action in "${_st_actions[@]}"; do
    action_trimmed="${action//[[:space:]]/}"
    [[ -z "$action_trimmed" ]] && continue
    if ! grep -F "[SELFTEST]" "$LOG" | grep -F "action=$action_trimmed" >/dev/null; then
      echo "[golden][ERROR] missing [SELFTEST] action '$action_trimmed'" >&2
      ok=0
    fi
  done
fi

if [[ -n "$PREF_LABELS" ]]; then
  IFS=',' read -ra _pref_labels <<<"$PREF_LABELS"
  for label in "${_pref_labels[@]}"; do
    label_trimmed="${label//[[:space:]]/}"
    [[ -z "$label_trimmed" ]] && continue
    pref_pattern="$label_trimmed"
    if [[ "$pref_pattern" != pref=* ]]; then
      pref_pattern="pref=$pref_pattern"
    fi
    if ! grep -F "$pref_pattern" "$LOG" >/dev/null; then
      echo "[golden][ERROR] missing preference label '$pref_pattern'" >&2
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
