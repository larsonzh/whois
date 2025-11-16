#!/usr/bin/env bash
set -euo pipefail

# Remote static cross-compile and optional smoke tests (to run on Ubuntu VM)
# Code comments and messages are English-only per repository policy.

: "${TARGETS:=aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64}"
: "${OUTPUT_DIR:=out/build_out}"
: "${RUN_TESTS:=0}"
: "${RB_QUIET:=0}"
# Optional extra args for smoke tests, e.g., -g "Org|Net|Country"
: "${SMOKE_ARGS:=}"
# Optional per-arch CFLAGS_EXTRA override coming from the launcher
: "${RB_CFLAGS_EXTRA:=}"
# Smoke test behavior
# Default to real network testing against actual queries; you can override queries via SMOKE_QUERIES
: "${SMOKE_MODE:=net}"       # kept for backward compatibility; default is 'net'
: "${SMOKE_QUERIES:=8.8.8.8}" # space-separated queries, e.g. "8.8.8.8 example.com"

# Safe quoting for -g patterns with '|' (prevent accidental shell pipelines).
# We avoid brittle regex replacements; instead we tokenise once.
if [[ -n "$SMOKE_ARGS" ]]; then
  # Only attempt if contains '-g ' and a pipe symbol.
  if [[ "$SMOKE_ARGS" == *"-g "* && "$SMOKE_ARGS" == *"|"* ]]; then
    # Skip if user already quoted after -g.
    if [[ "$SMOKE_ARGS" != *"-g '"* && "$SMOKE_ARGS" != *"-g \""* ]]; then
      # Split into array respecting existing whitespace.
      # shellcheck disable=SC2206
      _sa=($SMOKE_ARGS)
      _out=""
      i=0
      while [[ $i -lt ${#_sa[@]} ]]; do
        if [[ "${_sa[$i]}" == "-g" && $((i+1)) -lt ${#_sa[@]} ]]; then
          pat="${_sa[$((i+1))]}"
          # If pattern contains '|' and no internal spaces, quote it.
          if [[ "$pat" == *"|"* && "$pat" != *" "* ]]; then
            _out+=" -g '$pat'"
          else
            _out+=" -g $pat"
          fi
          i=$((i+2))
          continue
        fi
        _out+=" ${_sa[$i]}"
        i=$((i+1))
      done
      SMOKE_ARGS="${_out# }"
    fi
  fi
fi

# Resolve repo root from this script path: whois/tools/remote
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"  # repo root
SRC_DIR="$REPO_DIR/src"
SOURCE_FILE="$SRC_DIR/whois_client.c" # legacy; Makefile will consume all sources

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
  # Resolve effective CFLAGS_EXTRA: prefer RB_CFLAGS_EXTRA, then env CFLAGS_EXTRA, else default
  local CFE
  if [[ -n "$RB_CFLAGS_EXTRA" ]]; then
    CFE="$RB_CFLAGS_EXTRA"
  elif [[ -n "${CFLAGS_EXTRA:-}" ]]; then
    CFE="$CFLAGS_EXTRA"
  else
    CFE="-O3 -s"
  fi
  local out=""
  case "$target" in
    aarch64)
      local cc; cc="$(find_cc aarch64)"; [[ -z "$cc" ]] && { warn "aarch64 toolchain not found"; return 0; }
  local LFE=""  # static link uses empty extra LDFLAGS by default
  out="$ARTIFACTS_DIR/whois-aarch64"
  log "Building aarch64 => $(basename "$out")"
  if [[ "$RB_QUIET" == "1" ]]; then
    log "Make overrides (arch=aarch64): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log" || true
  else
    log "Make overrides (arch=aarch64): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static )
  fi
  cp -f "$REPO_DIR/whois-client.static" "$out" || warn "Static output missing for aarch64"
      ;;
    armv7)
      local cc; cc="$(find_cc armv7)"; [[ -z "$cc" ]] && { warn "armv7 toolchain not found"; return 0; }
  local LFE=""  # static link uses empty extra LDFLAGS by default
  out="$ARTIFACTS_DIR/whois-armv7"
  log "Building armv7 => $(basename "$out")"
  if [[ "$RB_QUIET" == "1" ]]; then
    log "Make overrides (arch=armv7): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log" || true
  else
    log "Make overrides (arch=armv7): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static )
  fi
  cp -f "$REPO_DIR/whois-client.static" "$out" || warn "Static output missing for armv7"
      ;;
    x86_64)
      local cc; cc="$(find_cc x86_64)"; [[ -z "$cc" ]] && { warn "x86_64 toolchain not found"; return 0; }
  local LFE=""  # static link uses empty extra LDFLAGS by default
  out="$ARTIFACTS_DIR/whois-x86_64"
  log "Building x86_64 => $(basename "$out")"
  if [[ "$RB_QUIET" == "1" ]]; then
    log "Make overrides (arch=x86_64): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log" || true
  else
    log "Make overrides (arch=x86_64): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static )
  fi
  cp -f "$REPO_DIR/whois-client.static" "$out" || warn "Static output missing for x86_64"
      ;;
    x86)
      local cc; cc="$(find_cc x86)"; [[ -z "$cc" ]] && { warn "x86 (i686) toolchain not found"; return 0; }
  local LFE=""  # static link uses empty extra LDFLAGS by default
  out="$ARTIFACTS_DIR/whois-x86"
  log "Building x86 => $(basename "$out")"
  if [[ "$RB_QUIET" == "1" ]]; then
    log "Make overrides (arch=x86): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log" || true
  else
    log "Make overrides (arch=x86): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static )
  fi
  cp -f "$REPO_DIR/whois-client.static" "$out" || warn "Static output missing for x86"
      ;;
    mipsel)
      local cc; cc="$(find_cc mipsel)"; [[ -z "$cc" ]] && { warn "mipsel toolchain not found"; return 0; }
  local LFE=""  # static link uses empty extra LDFLAGS by default
  out="$ARTIFACTS_DIR/whois-mipsel"
  log "Building mipsel => $(basename "$out")"
  if [[ "$RB_QUIET" == "1" ]]; then
    log "Make overrides (arch=mipsel): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log" || true
  else
    log "Make overrides (arch=mipsel): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static )
  fi
  cp -f "$REPO_DIR/whois-client.static" "$out" || warn "Static output missing for mipsel"
      ;;
    mips64el)
      local cc; cc="$(find_cc mips64el)"; [[ -z "$cc" ]] && { warn "mips64el toolchain not found"; return 0; }
  local LFE=""  # static link uses empty extra LDFLAGS by default
  out="$ARTIFACTS_DIR/whois-mips64el"
  log "Building mips64el => $(basename "$out")"
  if [[ "$RB_QUIET" == "1" ]]; then
    log "Make overrides (arch=mips64el): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log" || true
  else
    log "Make overrides (arch=mips64el): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static )
  fi
  cp -f "$REPO_DIR/whois-client.static" "$out" || warn "Static output missing for mips64el"
      ;;
    loongarch64)
      local cc; cc="$(find_cc loongarch64)"; [[ -z "$cc" ]] && { warn "loongarch64 toolchain not found"; return 0; }
  local LFE="-static-libgcc -static-libstdc++"  # dynamic build with extra libs statically linked
  out="$ARTIFACTS_DIR/whois-loongarch64"
  log "Building loongarch64 => $(basename "$out")"
  if [[ "$RB_QUIET" == "1" ]]; then
    log "Make overrides (arch=loongarch64): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make all ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log" || true
  else
    log "Make overrides (arch=loongarch64): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
    ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make all )
  fi
  cp -f "$REPO_DIR/whois-client" "$out" || warn "Output missing for loongarch64"
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
    whois-x86_64)
      # Prefer native execution on x86_64 hosts to speed up smoke
      host_arch="$(uname -m 2>/dev/null || echo unknown)"
      if [[ "$host_arch" != "x86_64" && "$host_arch" != "amd64" ]]; then
        qemu_prefix="qemu-x86_64-static"
      else
        qemu_prefix=""
      fi
      ;;
    whois-x86) qemu_prefix="qemu-i386-static" ;;
    whois-mipsel) qemu_prefix="qemu-mipsel-static" ;;
    whois-mips64el) qemu_prefix="qemu-mips64el-static" ;;
    whois-loongarch64) return 0 ;;
    *) return 0 ;;
  esac

  # Explicitly log the runner selected (QEMU prefix or native)
  if [[ -n "$qemu_prefix" ]]; then
    log "Smoke runner for $name: $qemu_prefix"
  else
    log "Smoke runner for $name: native"
  fi

  # Iterate all queries and test against real network (no private IP substitution)
  for q in $SMOKE_QUERIES; do
    log "Smoke test: $name -- $q"
    local cmd_base
    if [[ -n "$qemu_prefix" ]]; then
      cmd_base="$qemu_prefix \"$bin\""
    else
      cmd_base="\"$bin\""
    fi
    local cmd
    if [[ -n "$SMOKE_ARGS" ]]; then
      # Pass through SMOKE_ARGS as-is so that embedded quotes are respected by bash -lc
      cmd="$cmd_base $SMOKE_ARGS \"$q\""
    else
      cmd="$cmd_base \"$q\""
    fi
    # Avoid timeout when retry metrics enabled so atexit flush prints [RETRY-METRICS]
    if command -v timeout >/dev/null 2>&1 && [[ "${WHOIS_RETRY_METRICS:-}" != "1" ]]; then
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
[[ -n "$RB_CFLAGS_EXTRA" ]] && log "CFLAGS extra override: $RB_CFLAGS_EXTRA"
log "Quiet mode: $RB_QUIET"

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
      else
        log "UPX not found; skip compress whois-aarch64"
      fi
      ;;
    x86_64)
      if command -v upx >/dev/null 2>&1; then
        log "UPX compress whois-x86_64"
        [[ -f "$ARTIFACTS_DIR/whois-x86_64" ]] && upx --best --lzma "$ARTIFACTS_DIR/whois-x86_64" || true
      else
        log "UPX not found; skip compress whois-x86_64"
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

# Build summary (quiet or verbose both produce report)
report_file="$ARTIFACTS_DIR/build_report.txt"
: > "$report_file"

# Detect hash tool (prefer sha256)
HASH_CMD=""; HASH_NAME=""
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD="sha256sum"; HASH_NAME="sha256"
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD="shasum -a 256"; HASH_NAME="sha256"
elif command -v sha1sum >/dev/null 2>&1; then
  HASH_CMD="sha1sum"; HASH_NAME="sha1"
fi

# Optional: always produce SHA256SUMS-static.txt when possible
if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "$ARTIFACTS_DIR" && ls whois-* >/dev/null 2>&1 && sha256sum whois-* > SHA256SUMS-static.txt || true
  )
fi

summary_parts=()
for t in $TARGETS; do
  bn="$(bin_name_for_target "$t")"
  if [[ -n "$bn" && -f "$ARTIFACTS_DIR/$bn" ]]; then
    sz="$(stat -c %s "$ARTIFACTS_DIR/$bn" 2>/dev/null || echo 0)"
    hashval="NA"
    if [[ -n "$HASH_CMD" ]]; then
      # shellcheck disable=SC2086
      hashval="$(cd "$ARTIFACTS_DIR" && $HASH_CMD "$bn" 2>/dev/null | awk '{print $1}')"
    fi
    echo "${t},binary=${bn},size=${sz},${HASH_NAME:-hash}=${hashval}" >> "$report_file"
    summary_parts+=("${t}(size=${sz},${HASH_NAME:-hash}=${hashval})")
  else
    echo "${t},binary=missing" >> "$report_file"
    summary_parts+=("${t}(missing)")
  fi
done
if [[ -s "$ARTIFACTS_DIR/build_errors.log" ]]; then
  warn "Build errors/warnings captured in build_errors.log"
fi

# One-line summary for quick glance
if ((${#summary_parts[@]} > 0)); then
  log "Build summary (per arch):"
  for entry in "${summary_parts[@]}"; do
    log "$entry"
  done
fi
