#!/usr/bin/env bash
set -euo pipefail

# Remote static cross-compile and optional smoke tests (to run on Ubuntu VM)
# Code comments and messages are English-only per repository policy.

: "${TARGETS:=aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64}"
: "${OUTPUT_DIR:=out/build_out}"
: "${RUN_TESTS:=0}"
# Optional extra args for smoke tests, e.g., -g "Org|Net|Country"
: "${SMOKE_ARGS:=}"
# Smoke test behavior
# Default to real network testing against actual queries; you can override queries via SMOKE_QUERIES
: "${SMOKE_MODE:=net}"       # kept for backward compatibility; default is 'net'
: "${SMOKE_QUERIES:=8.8.8.8}" # space-separated queries, e.g. "8.8.8.8 example.com"

# Resolve repo root from this script path: whois/tools/remote
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"  # repo root
SRC_DIR="$REPO_DIR/src"
SOURCE_FILE="$SRC_DIR/whois_client.c"

mkdir -p "$REPO_DIR/$OUTPUT_DIR"
ARTIFACTS_DIR="$(cd "$REPO_DIR/$OUTPUT_DIR" && pwd)"

log() { echo "[remote_build] $*"; }
warn() { echo "[remote_build][WARN] $*" >&2; }
err() { echo "[remote_build][ERROR] $*" >&2; }

# Resolve compiler path by target, preferring absolute paths under $HOME
find_cc() {
  local target="$1"
  local cand=()
  case "$target" in
    aarch64)
      cand=("$HOME/.local/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc" "aarch64-linux-musl-gcc") ;;
    armv7)
      cand=("$HOME/.local/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc" "arm-linux-musleabihf-gcc" "armv7l-linux-musleabihf-gcc") ;;
    x86_64)
      cand=("$HOME/.local/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc" "x86_64-linux-musl-gcc") ;;
    x86)
      cand=("$HOME/.local/i686-linux-musl-cross/bin/i686-linux-musl-gcc" "i686-linux-musl-gcc") ;;
    mipsel)
      cand=("$HOME/.local/mipsel-linux-musl-cross/bin/mipsel-linux-musl-gcc" "mipsel-linux-musl-gcc") ;;
    mips64el)
      cand=("$HOME/.local/mips64el-linux-musl-cross/bin/mips64el-linux-musl-gcc" "mips64el-linux-musl-gcc") ;;
    loongarch64)
      cand=("$HOME/.local/loongson-gnu-toolchain-8.3-x86_64-loongarch64-linux-gnu-rc1.6/bin/loongarch64-linux-gnu-gcc" "loongarch64-linux-gnu-gcc" "loongarch64-linux-musl-gcc") ;;
    *) echo ""; return 0 ;;
  esac
  local c
  for c in "${cand[@]}"; do
    if [[ "$c" = /* ]]; then
      [[ -x "$c" ]] && { echo "$c"; return 0; }
      continue
    fi
    local resolved
    resolved="$(command -v "$c" 2>/dev/null || true)"
    [[ -n "$resolved" ]] && { echo "$resolved"; return 0; }
  done
  echo ""
}

build_one() {
  local target="$1"
  local out=""
  case "$target" in
    aarch64)
      local cc; cc="$(find_cc aarch64)"; [[ -z "$cc" ]] && { warn "aarch64 toolchain not found"; return 0; }
      out="$ARTIFACTS_DIR/whois-aarch64"
      log "Building aarch64 => $(basename "$out") (CC: $cc)"
      "$cc" -static -O3 -s -o "$out" "$SOURCE_FILE" -Wall -pthread
      ;;
    armv7)
      local cc; cc="$(find_cc armv7)"; [[ -z "$cc" ]] && { warn "armv7 toolchain not found"; return 0; }
      out="$ARTIFACTS_DIR/whois-armv7"
      log "Building armv7 => $(basename "$out") (CC: $cc)"
      "$cc" -static -O3 -s -o "$out" "$SOURCE_FILE" -Wall -pthread
      ;;
    x86_64)
      local cc; cc="$(find_cc x86_64)"; [[ -z "$cc" ]] && { warn "x86_64 toolchain not found"; return 0; }
      out="$ARTIFACTS_DIR/whois-x86_64"
      log "Building x86_64 => $(basename "$out") (CC: $cc)"
      "$cc" -static -O3 -s -o "$out" "$SOURCE_FILE" -Wall -pthread
      ;;
    x86)
      local cc; cc="$(find_cc x86)"; [[ -z "$cc" ]] && { warn "x86 (i686) toolchain not found"; return 0; }
      out="$ARTIFACTS_DIR/whois-x86"
      log "Building x86 => $(basename "$out") (CC: $cc)"
      "$cc" -static -O3 -s -o "$out" "$SOURCE_FILE" -Wall -pthread
      ;;
    mipsel)
      local cc; cc="$(find_cc mipsel)"; [[ -z "$cc" ]] && { warn "mipsel toolchain not found"; return 0; }
      out="$ARTIFACTS_DIR/whois-mipsel"
      log "Building mipsel => $(basename "$out") (CC: $cc)"
      "$cc" -static -O3 -s -o "$out" "$SOURCE_FILE" -Wall -pthread
      ;;
    mips64el)
      local cc; cc="$(find_cc mips64el)"; [[ -z "$cc" ]] && { warn "mips64el toolchain not found"; return 0; }
      out="$ARTIFACTS_DIR/whois-mips64el"
      log "Building mips64el => $(basename "$out") (CC: $cc)"
      "$cc" -static -O3 -s -o "$out" "$SOURCE_FILE" -Wall -pthread
      ;;
    loongarch64)
      local cc; cc="$(find_cc loongarch64)"; [[ -z "$cc" ]] && { warn "loongarch64 toolchain not found"; return 0; }
      out="$ARTIFACTS_DIR/whois-loongarch64"
      log "Building loongarch64 => $(basename "$out") (CC: $cc)"
      "$cc" -O3 -s -o "$out" "$SOURCE_FILE" -Wall -pthread -static-libgcc -static-libstdc++
      ;;
    *) warn "Unknown target: $target"; return 0;;
  esac
}

bin_name_for_target() {
  case "$1" in
    aarch64) echo "whois-aarch64" ;;
    armv7) echo "whois-armv7" ;;
    x86_64) echo "whois-x86_64" ;;
    x86) echo "whois-x86" ;;
    mipsel) echo "whois-mipsel" ;;
    mips64el) echo "whois-mips64el" ;;
    loongarch64) echo "whois-loongarch64" ;;
    *) echo "" ;;
  esac
}

smoke_test() {
  local bin="$1"
  [[ -x "$bin" ]] || { warn "Smoke test skipped: $bin not executable"; return 0; }
  local name="$(basename "$bin")"
  local qemu_prefix=""
  case "$name" in
    whois-aarch64) qemu_prefix="qemu-aarch64-static" ;;
    whois-armv7) qemu_prefix="qemu-arm-static" ;;
    whois-x86_64) qemu_prefix="qemu-x86_64-static" ;;
    whois-x86) qemu_prefix="qemu-i386-static" ;;
    whois-mipsel) qemu_prefix="qemu-mipsel-static" ;;
    whois-mips64el) qemu_prefix="qemu-mips64el-static" ;;
    whois-loongarch64) return 0 ;;
    *) return 0 ;;
  esac

  # Iterate all queries and test against real network (no private IP substitution)
  for q in $SMOKE_QUERIES; do
    log "Smoke test: $name -- $q"
    local cmd
    if [[ -n "$SMOKE_ARGS" ]]; then
      # Heuristic: treat the first token as option (e.g., -g) and the rest as value, quote the value to protect pipes
      local opt rest safe_args
      opt="${SMOKE_ARGS%% *}"
      rest="${SMOKE_ARGS#*$opt}"
      rest="${rest# }"
      if [[ -n "$rest" ]]; then
        safe_args="$opt '$rest'"
      else
        safe_args="$opt"
      fi
      cmd="$qemu_prefix \"$bin\" $safe_args $q"
    else
      cmd="$qemu_prefix \"$bin\" $q"
    fi
    if command -v timeout >/dev/null 2>&1; then
      bash -lc "timeout 8 $cmd" || warn "Smoke test non-zero exit: $name (q=$q)"
    else
      bash -lc "$cmd" || warn "Smoke test non-zero exit: $name (q=$q)"
    fi
  done
}

if [[ ! -f "$SOURCE_FILE" ]]; then
  err "Source not found: $SOURCE_FILE"
  exit 1
fi

log "Repo dir: $REPO_DIR"
log "Artifacts: $ARTIFACTS_DIR"
log "Targets: $TARGETS"
log "PATH: $PATH"
log "Smoke mode: $SMOKE_MODE"
log "Smoke queries: $SMOKE_QUERIES"
[[ -n "$SMOKE_ARGS" ]] && log "Smoke extra args: $SMOKE_ARGS"

# Optional: quick port-43 connectivity pre-check (log-only, non-blocking)
precheck_43() {
  local host="$1"
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w3 "$host" 43 >/dev/null 2>&1; then
      log "Port 43 pre-check: $host OK"
    else
      warn "Port 43 pre-check: $host FAIL"
    fi
  else
    if command -v timeout >/dev/null 2>&1; then
      if timeout 3 bash -lc ": >/dev/tcp/$host/43" >/dev/null 2>&1; then
        log "Port 43 pre-check: $host OK"
      else
        warn "Port 43 pre-check: $host FAIL"
      fi
    else
      # Fallback try without timeout; still log-only
      if bash -lc ": >/dev/tcp/$host/43" >/dev/null 2>&1; then
        log "Port 43 pre-check: $host OK"
      else
        warn "Port 43 pre-check: $host FAIL"
      fi
    fi
  fi
}

if [[ "$RUN_TESTS" == "1" && "$SMOKE_MODE" == "net" ]]; then
  log "Running port-43 connectivity pre-checks (log-only)"
  precheck_43 whois.iana.org || true
  precheck_43 whois.apnic.net || true
fi

file_report="$ARTIFACTS_DIR/file_report.txt"
smoke_log="$ARTIFACTS_DIR/smoke_test.log"
: > "$file_report"
: > "$smoke_log"

for t in $TARGETS; do
  build_one "$t"
  # Optional UPX per built target
  case "$t" in
    aarch64)
      if command -v upx >/dev/null 2>&1; then
        log "UPX compress whois-aarch64"
        [[ -f "$ARTIFACTS_DIR/whois-aarch64" ]] && upx --best --lzma "$ARTIFACTS_DIR/whois-aarch64" || true
      fi
      ;;
    x86_64)
      if command -v upx >/dev/null 2>&1; then
        log "UPX compress whois-x86_64"
        [[ -f "$ARTIFACTS_DIR/whois-x86_64" ]] && upx --best --lzma "$ARTIFACTS_DIR/whois-x86_64" || true
      fi
      ;;
  esac

  # file(1) report for the built target only
  bn="$(bin_name_for_target "$t")"
  if [[ -n "$bn" && -f "$ARTIFACTS_DIR/$bn" ]]; then
    file "$ARTIFACTS_DIR/$bn" | tee -a "$file_report" >/dev/null || true
  fi

  # single-binary smoke test for the built target
  if [[ "$RUN_TESTS" == "1" && -n "$bn" && -x "$ARTIFACTS_DIR/$bn" ]]; then
    echo "[remote_build] QEMU smoke: $bn ..."
    smoke_test "$ARTIFACTS_DIR/$bn" >> "$smoke_log" 2>&1 || true
  fi
done

log "Done. Artifacts in: $ARTIFACTS_DIR"
