#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [-l <smoke_log>] [--query Q] [--start S] [--auth A] [--batch-actions list] [--backoff-actions list] [--selftest-actions list]
  --pref-labels  Comma-separated preference labels that must appear (accepts either bare values like v4-then-v6-hop0 or literals like pref=v4-first)
  --dns-family-mode <mode>  Require stderr to contain [DNS-CAND] mode=<mode>
  --dns-start <ipv4|ipv6>   Require the same [DNS-CAND] block to include start=<value>
  --auth-unknown-when-capped  Expect tail to be 'Authoritative RIR: unknown @ unknown' (e.g., when -R caps the referral chain)
  --redirect-line <host>      Require a '=== Redirected query to <host> ===' line (useful with capped referrals)
  --skip-header-tail          Skip header/referral/tail checks (for selftest-only logs)
  --allow-missing-tail        Do not fail if tail is absent (e.g., single-hop capped referral)
  --skip-redirect-line        Skip redirect-line check even if --redirect-line is provided
  --selftest-actions-only     Shorthand for "--skip-header-tail --skip-redirect-line" to only assert [SELFTEST] actions
  --selftest-registry         Convenience: assert registry harness tags (batch-registry-default,set-active,override-pick,override-on-result)
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

require_arg() {
  # Enforce that the current option has a following argument to avoid unbound variable under set -u
  # Usage: require_arg "$@" where "$1" is the option name and "$2" (if present) is the value
  if [[ $# -lt 2 || -z "$2" ]]; then
    echo "[golden][ERROR] option '$1' requires a non-empty argument" >&2
    usage
    exit 2
  fi
}

LOG="./out/build_out/smoke_test.log"
Q="8.8.8.8"
S="whois.iana.org"
A="whois.arin.net"
ALT_AUTH="whois.apnic.net"
BATCH_ACTIONS=""
BACKOFF_ACTIONS=""
SELFTEST_ACTIONS=""
SELFTEST_REGISTRY=0
PREF_LABELS=""
DNS_FAMILY_MODE=""
DNS_START=""
AUTH_UNKNOWN_WHEN_CAPPED=0
REDIRECT_LINE=""
SKIP_HEADER_TAIL=0
ALLOW_MISSING_TAIL=0
SKIP_REDIRECT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; LOG="$2"; shift 2 ;;
    --query)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; Q="$2"; shift 2 ;;
    --start)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; S="$2"; shift 2 ;;
    --auth)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; A="$2"; shift 2 ;;
    --batch-actions)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; BATCH_ACTIONS="$2"; shift 2 ;;
    --backoff-actions)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; BACKOFF_ACTIONS="$2"; shift 2 ;;
    --selftest-actions)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; SELFTEST_ACTIONS="$2"; shift 2 ;;
    --pref-labels)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; PREF_LABELS="$2"; shift 2 ;;
    --dns-family-mode)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; DNS_FAMILY_MODE="$2"; shift 2 ;;
    --dns-start)
      if [[ $# -lt 2 ]]; then require_arg "$1"; fi
      require_arg "$1" "$2"; DNS_START="$2"; shift 2 ;;
    --auth-unknown-when-capped) AUTH_UNKNOWN_WHEN_CAPPED=1; shift 1 ;;
    --redirect-line) REDIRECT_LINE="$2"; shift 2 ;;
    --skip-header-tail) SKIP_HEADER_TAIL=1; shift 1 ;;
    --allow-missing-tail) ALLOW_MISSING_TAIL=1; shift 1 ;;
    --skip-redirect-line) SKIP_REDIRECT=1; shift 1 ;;
    --selftest-actions-only) SKIP_HEADER_TAIL=1; SKIP_REDIRECT=1; shift 1 ;;
    --selftest-registry) SELFTEST_REGISTRY=1; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -s "$LOG" ]]; then
  echo "[golden][ERROR] smoke log missing or empty: $LOG" >&2
  exit 1
fi

if [[ "$SELFTEST_REGISTRY" == "1" ]]; then
  if [[ -z "$SELFTEST_ACTIONS" ]]; then
    SELFTEST_ACTIONS="batch-registry-default,batch-registry-set-active,batch-registry-override-pick,batch-registry-override-on-result"
  else
    SELFTEST_ACTIONS+=" ,batch-registry-default,batch-registry-set-active,batch-registry-override-pick,batch-registry-override-on-result"
  fi
fi

ok=1
header_re="^=== Query: ${Q//\//\\/} via ${S//\//\\/} @ (unknown|[0-9A-Fa-f:.]+) ===$"
ref_re="^=== Additional query to ${A//\//\\/} ===$"
tail_re="^=== Authoritative RIR: (${A//\//\\/}|${ALT_AUTH//\//\\/}) @ (unknown|[0-9A-Fa-f:.]+) ===$"

if [[ "$SKIP_HEADER_TAIL" != "1" ]]; then
  if ! grep -E "$header_re" "$LOG" >/dev/null; then
    echo "[golden][ERROR] header not found matching: $header_re" >&2
    ok=0
    ref_found=0
    redirect_found=0
    ref_found=0
    redirect_found=0
  fi
  if grep -E "$ref_re" "$LOG" >/dev/null; then
    ref_found=1
  else
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
    tail_re="^=== Authoritative RIR: (${A//\//\\}|${ALT_AUTH//\//\\}) @ (unknown|[0-9A-Fa-f:.]+) ===$"
  fi
fi

# Redirect check is independent so tail allowance can see redirect_found
if [[ -n "$REDIRECT_LINE" && "$SKIP_REDIRECT" != "1" ]]; then
  redir_re="^=== Redirected query to ${REDIRECT_LINE//\//\\} ===$"
  if grep -E "$redir_re" "$LOG" >/dev/null; then
    redirect_found=1
  else
    echo "[golden][ERROR] redirect line not found matching: $redir_re" >&2
    ok=0
  fi
fi

if [[ "$SKIP_HEADER_TAIL" != "1" ]]; then
  if ! grep -E "$tail_re" "$LOG" >/dev/null; then
    if [[ "$ALLOW_MISSING_TAIL" == "1" || "$ref_found" == "1" || "$redirect_found" == "1" ]]; then
      echo "[golden][INFO] tail missing but allowed"
    else
      echo "[golden][ERROR] tail not found matching: $tail_re" >&2
      ok=0
    fi
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
    elif grep -F "[SELFTEST]" "$LOG" | grep -F "action=$action_trimmed" | grep -F "FAIL" >/dev/null; then
      echo "[golden][ERROR] [SELFTEST] action '$action_trimmed' reported FAIL" >&2
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

if [[ -n "$DNS_FAMILY_MODE" ]]; then
  if ! grep -F "[DNS-CAND]" "$LOG" | grep -F "mode=$DNS_FAMILY_MODE" >/dev/null; then
    echo "[golden][ERROR] missing [DNS-CAND] mode=$DNS_FAMILY_MODE" >&2
    ok=0
  elif [[ -n "$DNS_START" ]]; then
    if ! grep -F "[DNS-CAND]" "$LOG" | grep -F "mode=$DNS_FAMILY_MODE" | grep -F "start=$DNS_START" >/dev/null; then
      echo "[golden][ERROR] missing start=$DNS_START for mode=$DNS_FAMILY_MODE" >&2
      ok=0
    fi
  fi
fi

if [[ "$ok" == "1" ]]; then
  echo "[golden] PASS"
  exit 0
else
  echo "[golden] FAIL"
  exit 3
fi
