#!/bin/sh
# BusyBox-compatible parallel startup-cost benchmark for whois binaries.
# Accepts a whois binary path or a directory containing whois-*.
# Measures total wall time for N iterations per process across P processes.

set -e

usage() {
  echo "Usage: $0 -a <whois-path|dir> -o <official-whois-path> [-n iterations] [-p processes]" >&2
  echo "  -n  iterations per process (default: 200)" >&2
  echo "  -p  processes in parallel (default: 48)" >&2
  echo "  -a  whois binary path (or dir containing whois-*)" >&2
  echo "  -o  official whois binary path" >&2
  echo "Example: $0 -a /opt/home/lzispro/whois/whois-armv7 -o /usr/bin/whois -n 183 -p 48" >&2
}

N=200
P=48
WHOIS_A=""
WHOIS_O=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n) N="$2"; shift 2 ;;
    -p) P="$2"; shift 2 ;;
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

run_parallel_bench() {
  label="$1"
  shift
  cmd="$1"
  shift

  tmp_dir="/tmp/bench_parallel.$$.$label"
  mkdir -p "$tmp_dir"

  start=$(date +%s)
  i=1
  while [ "$i" -le "$P" ]; do
    (
      wstart=$(date +%s)
      j=1
      while [ "$j" -le "$N" ]; do
        "$cmd" "$@" >/dev/null 2>&1 || true
        j=$((j + 1))
      done
      wend=$(date +%s)
      echo $((wend - wstart)) > "$tmp_dir/w_$i"
    ) &
    i=$((i + 1))
  done

  wait
  end=$(date +%s)
  elapsed=$((end - start))

  avg_proc_s=$(awk 'BEGIN{sum=0;cnt=0} {sum+=$1;cnt+=1} END{ if (cnt>0) printf "%.3f", sum/cnt; else print 0 }' "$tmp_dir"/w_*)

  echo "$label: total_s=$elapsed avg_proc_s=$avg_proc_s iterations=$N processes=$P"
  rm -rf "$tmp_dir"
}

whois_label=${WHOIS_A##*/}
run_parallel_bench "$whois_label -v" "$WHOIS_A" -v
run_parallel_bench "official whois -v" "$WHOIS_O" -v
