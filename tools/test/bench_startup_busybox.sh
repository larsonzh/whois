#!/bin/sh
# BusyBox-compatible startup-cost benchmark for whois binaries.
# Accepts a whois binary path or a directory containing whois-*.
# Measures total wall time for repeated --version invocations.

set -e

usage() {
  echo "Usage: $0 -a <whois-path|dir> -o <official-whois-path> [-n iterations]" >&2
  echo "  -n  iterations (default: 1000)" >&2
  echo "  -a  whois binary path (or dir containing whois-*)" >&2
  echo "  -o  official whois binary path" >&2
  echo "Example: $0 -a /opt/home/lzispro/whois/whois-armv7 -o /usr/bin/whois" >&2
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
  found=""
  for candidate in "$WHOIS_A"/whois-*; do
    if [ -x "$candidate" ]; then
      found="$candidate"
      break
    fi
  done
  if [ -n "$found" ]; then
    WHOIS_A="$found"
  else
    echo "Error: no executable whois-* found in dir: $WHOIS_A" >&2
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

whois_label=${WHOIS_A##*/}
run_bench "$whois_label -v" "$WHOIS_A" -v
run_bench "official whois -v" "$WHOIS_O" -v
