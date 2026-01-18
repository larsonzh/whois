#!/bin/sh
# BusyBox-compatible startup-cost benchmark for whois binaries.
# Measures total wall time for repeated --version invocations.

set -e

usage() {
  echo "Usage: $0 -a <whois-aarch64-path|dir> -o <official-whois-path> [-n iterations]" >&2
  echo "  -n  iterations (default: 1000)" >&2
  echo "  -a  whois-aarch64 binary path (or dir containing whois-aarch64)" >&2
  echo "  -o  official whois binary path" >&2
}

N=1000
WHOIS_A=""
WHOIS_O=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n) N="$2"; shift 2 ;;
    -a) WHOIS_A="$2"; shift 2 ;;
    -o) WHOIS_O="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Error: unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$WHOIS_A" ] || [ -z "$WHOIS_O" ]; then
  usage
  exit 1
fi

if [ -d "$WHOIS_A" ]; then
  if [ -x "$WHOIS_A/whois-aarch64" ]; then
    WHOIS_A="$WHOIS_A/whois-aarch64"
  else
    echo "Error: whois-aarch64 not found in dir: $WHOIS_A" >&2
    exit 1
  fi
fi
if [ ! -x "$WHOIS_A" ]; then
  echo "Error: not executable: $WHOIS_A" >&2
  exit 1
fi
if [ ! -x "$WHOIS_O" ]; then
  echo "Error: not executable: $WHOIS_O" >&2
  exit 1
fi

run_bench() {
  label="$1"
  shift
  start=$(date +%s)
  i=1
  while [ "$i" -le "$N" ]; do
    "$@" >/dev/null 2>&1 || true
    i=$((i + 1))
  done
  end=$(date +%s)
  elapsed=$((end - start))
  avg_ms=$(awk "BEGIN{ if ($N > 0) printf \"%.3f\", ($elapsed * 1000.0) / $N; else print 0 }")
  echo "$label: total_s=$elapsed avg_ms=$avg_ms iterations=$N"
}

run_bench "whois-aarch64 -v" "$WHOIS_A" -v
run_bench "official whois -v" "$WHOIS_O" -v
