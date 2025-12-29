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
# Optional stdin file for batch smoke tests (repo-relative or absolute)
: "${SMOKE_STDIN_FILE:=}"
# Optional libgnurx search paths for MinGW static link (per-arch overrides)
: "${GNURX_WIN64_LIBDIR:=$HOME/libgnurx-x86_64-deb/usr/x86_64-w64-mingw32/lib}"
: "${GNURX_WIN32_LIBDIR:=$HOME/libgnurx-i686-deb/usr/i686-w64-mingw32/lib}"
# Optional per-arch CFLAGS_EXTRA override coming from the launcher
: "${RB_CFLAGS_EXTRA:=}"
# Smoke test behavior
# Default to real network testing against actual queries; you can override queries via SMOKE_QUERIES
: "${SMOKE_MODE:=net}"       # kept for backward compatibility; default is 'net'
: "${SMOKE_QUERIES:=8.8.8.8}" # space-separated queries, e.g. "8.8.8.8 example.com"
: "${SMOKE_QUERIES_PROVIDED:=0}"
: "${WINE64_BIN:=}"   # optional override for wine64 binary
: "${WINE32_BIN:=}"   # optional override for wine (32-bit)

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
WINDOWS_MODE_FILE="$ARTIFACTS_DIR/windows_build_modes.txt"

if [[ -n "$SMOKE_STDIN_FILE" && "$SMOKE_STDIN_FILE" != /* ]]; then
  SMOKE_STDIN_FILE="$REPO_DIR/$SMOKE_STDIN_FILE"
fi

log() { echo "[remote_build] $*"; }
warn() { echo "[remote_build][WARN] $*" >&2; }
err() { echo "[remote_build][ERROR] $*" >&2; }

# Reset Windows build mode markers for this run
: > "$WINDOWS_MODE_FILE"

resolve_wine_bin() {
  local kind="$1" # 32 or 64
  local override
  if [[ "$kind" == "64" ]]; then
    override="$WINE64_BIN"
  else
    override="$WINE32_BIN"
  fi
  if [[ -n "$override" ]]; then
    command -v "$override" >/dev/null 2>&1 && { echo "$override"; return 0; }
    warn "wine override '$override' not found; falling back to auto-detect"
  fi
  if [[ "$kind" == "64" ]]; then
    for cand in /usr/lib/wine/wine64 wine64 wine; do
      command -v "$cand" >/dev/null 2>&1 && { echo "$cand"; return 0; }
    done
  else
    for cand in /usr/lib/wine/wine wine; do
      command -v "$cand" >/dev/null 2>&1 && { echo "$cand"; return 0; }
    done
  fi
  echo ""
}

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
    win64)
      cand=("$HOME/.local/x86_64-w64-mingw32/bin/x86_64-w64-mingw32-gcc" "x86_64-w64-mingw32-gcc") ;;
    win32)
      cand=("$HOME/.local/i686-w64-mingw32/bin/i686-w64-mingw32-gcc" "i686-w64-mingw32-gcc") ;;
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
    win64)
      local cc; cc="$(find_cc win64)"; [[ -z "$cc" ]] && { warn "win64 toolchain not found"; return 0; }
  local gnurx_dir="$GNURX_WIN64_LIBDIR"
  [[ ! -d "$gnurx_dir" ]] && warn "win64: libgnurx dir missing: $gnurx_dir (will still try link)"
  local LFE_FULL="-static -static-libgcc -static-libstdc++ -L$gnurx_dir -Wl,-Bstatic -lgnurx -lwinpthread -Wl,-Bdynamic -lws2_32"
  local LFE_FALLBACK="-static-libgcc -static-libstdc++ -L$gnurx_dir -Wl,-Bstatic -lgnurx -lwinpthread -Wl,-Bdynamic -lws2_32"
  local LFE_DLL="-static-libgcc -static-libstdc++ -lws2_32 -lwinpthread -lregex"
  out="$ARTIFACTS_DIR/whois-win64.exe"
  log "Building win64 => $(basename "$out")"
  local success=0
  local success_mode="failed"
  for LFE in "$LFE_FULL" "$LFE_FALLBACK" "$LFE_DLL"; do
    local mode_label="full-static"
    [[ "$LFE" == "$LFE_FALLBACK" ]] && mode_label="fallback-libgcc"
    [[ "$LFE" == "$LFE_DLL" ]] && mode_label="dll-gnurx"
    if [[ "$RB_QUIET" == "1" ]]; then
      log "Make overrides (arch=win64 mode=$mode_label): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
      if ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log"; then
        success=1; success_mode="$mode_label"; break
      else
        warn "win64 build attempt ($mode_label) failed; see build_errors.log"
      fi
    else
      log "Make overrides (arch=win64 mode=$mode_label): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
      if ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ); then
        success=1; success_mode="$mode_label"; break
      else
        warn "win64 build attempt ($mode_label) failed"
      fi
    fi
  done
  if (( success == 0 )); then
    warn "Static output missing for win64 (all attempts failed)"
    echo "win64 mode=failed" >> "$WINDOWS_MODE_FILE"
    return 0
  fi
  local src=""
  for cand in "$REPO_DIR/whois-client.exe" "$REPO_DIR/whois-client.static" "$REPO_DIR/whois-client"; do
    if [[ -f "$cand" ]]; then src="$cand"; break; fi
  done
  if [[ -z "$src" ]]; then
    warn "Static output missing for win64"
    echo "win64 mode=missing" >> "$WINDOWS_MODE_FILE"
    return 0
  fi
  cp -f "$src" "$out" || warn "Copy failed for win64 -> $out"
  echo "win64 mode=$success_mode" >> "$WINDOWS_MODE_FILE"
      ;;
    win32)
      local cc; cc="$(find_cc win32)"; [[ -z "$cc" ]] && { warn "win32 toolchain not found"; return 0; }
  local gnurx_dir="$GNURX_WIN32_LIBDIR"
  [[ ! -d "$gnurx_dir" ]] && warn "win32: libgnurx dir missing: $gnurx_dir (will still try link)"
  local LFE_FULL="-static -static-libgcc -static-libstdc++ -L$gnurx_dir -Wl,-Bstatic -lgnurx -lwinpthread -Wl,-Bdynamic -lws2_32"
  local LFE_FALLBACK="-static-libgcc -static-libstdc++ -L$gnurx_dir -Wl,-Bstatic -lgnurx -lwinpthread -Wl,-Bdynamic -lws2_32"
  local LFE_DLL="-static-libgcc -static-libstdc++ -lws2_32 -lwinpthread -lregex"
  out="$ARTIFACTS_DIR/whois-win32.exe"
  log "Building win32 => $(basename "$out")"
  local success=0
  local success_mode="failed"
  for LFE in "$LFE_FULL" "$LFE_FALLBACK" "$LFE_DLL"; do
    local mode_label="full-static"
    [[ "$LFE" == "$LFE_FALLBACK" ]] && mode_label="fallback-libgcc"
    [[ "$LFE" == "$LFE_DLL" ]] && mode_label="dll-gnurx"
    if [[ "$RB_QUIET" == "1" ]]; then
      log "Make overrides (arch=win32 mode=$mode_label): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE' (quiet)"
      if ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ) >/dev/null 2>>"$ARTIFACTS_DIR/build_errors.log"; then
        success=1; success_mode="$mode_label"; break
      else
        warn "win32 build attempt ($mode_label) failed; see build_errors.log"
      fi
    else
      log "Make overrides (arch=win32 mode=$mode_label): CC=$cc CFLAGS_EXTRA='$CFE' LDFLAGS_EXTRA='$LFE'"
      if ( cd "$REPO_DIR" && make clean >/dev/null 2>&1 || true; CC="$cc" CFLAGS_EXTRA="$CFE" LDFLAGS_EXTRA="$LFE" make static ); then
        success=1; success_mode="$mode_label"; break
      else
        warn "win32 build attempt ($mode_label) failed"
      fi
    fi
  done
  if (( success == 0 )); then
    warn "Static output missing for win32 (all attempts failed)"
    echo "win32 mode=failed" >> "$WINDOWS_MODE_FILE"
    return 0
  fi
  local src=""
  for cand in "$REPO_DIR/whois-client.exe" "$REPO_DIR/whois-client.static" "$REPO_DIR/whois-client"; do
    if [[ -f "$cand" ]]; then src="$cand"; break; fi
  done
  if [[ -z "$src" ]]; then
    warn "Static output missing for win32"
    echo "win32 mode=missing" >> "$WINDOWS_MODE_FILE"
    return 0
  fi
  cp -f "$src" "$out" || warn "Copy failed for win32 -> $out"
  echo "win32 mode=$success_mode" >> "$WINDOWS_MODE_FILE"
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
    win64) echo "whois-win64.exe" ;;
    win32) echo "whois-win32.exe" ;;
    *) echo "" ;;
  esac
}

run_smoke_command() {
  local cmd="$1"
  local label="$2"
  local noglob_prefix="set -o noglob;"
  if command -v timeout >/dev/null 2>&1; then
    if [[ "$cmd" == *"--retry-metrics"* ]]; then
      local t=${SMOKE_TIMEOUT_ON_METRICS_SECS:-45}
      if timeout --help 2>/dev/null | grep -q -- "--signal"; then
        bash -lc "$noglob_prefix timeout --signal=INT --kill-after=5s ${t}s $cmd" || warn "Smoke test non-zero exit: $label"
      else
        bash -lc "$noglob_prefix timeout -s INT -k 5s ${t}s $cmd" || warn "Smoke test non-zero exit: $label"
      fi
    else
      local t=${SMOKE_TIMEOUT_DEFAULT_SECS:-8}
      bash -lc "$noglob_prefix timeout ${t}s $cmd" || warn "Smoke test non-zero exit: $label"
    fi
  else
    bash -lc "$noglob_prefix $cmd" || warn "Smoke test non-zero exit: $label"
  fi
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
    whois-win64.exe|whois-win32.exe)
      log "Smoke skipped for $name (use wine in launcher pipeline)"
      return 0 ;;
    *) return 0 ;;
  esac

  # Explicitly log the runner selected (QEMU prefix or native)
  if [[ -n "$qemu_prefix" ]]; then
    log "Smoke runner for $name: $qemu_prefix"
  else
    log "Smoke runner for $name: native"
  fi

  local cmd_base
  if [[ -n "$qemu_prefix" ]]; then
    cmd_base="$qemu_prefix \"$bin\""
  else
    cmd_base="\"$bin\""
  fi

  if [[ -n "$SMOKE_STDIN_FILE" ]]; then
    if [[ ! -f "$SMOKE_STDIN_FILE" ]]; then
      warn "SMOKE_STDIN_FILE not found: $SMOKE_STDIN_FILE"
      return 1
    fi
    local effective_args="$SMOKE_ARGS"
    if [[ "$effective_args" != *"-B"* && "$effective_args" != *"--batch"* ]]; then
      warn "SMOKE_STDIN_FILE set but -B/--batch missing in SMOKE_ARGS; auto-appending -B"
      effective_args="${effective_args:+$effective_args }-B"
    fi
    local cmd="$cmd_base"
    if [[ -n "$effective_args" ]]; then
      cmd="$cmd $effective_args"
    fi
    log "Smoke test: $name -- stdin@$SMOKE_STDIN_FILE"
    local pipeline_cmd="cat \"$SMOKE_STDIN_FILE\" | $cmd"
    run_smoke_command "$pipeline_cmd" "$name (stdin)"
    return 0
  fi

  # Iterate all queries and test against real network (no private IP substitution)
  for q in $SMOKE_QUERIES; do
    log "Smoke test: $name -- $q"
    local cmd="$cmd_base"
    if [[ -n "$SMOKE_ARGS" ]]; then
      cmd="$cmd $SMOKE_ARGS \"$q\""
    else
      cmd="$cmd \"$q\""
    fi
    run_smoke_command "$cmd" "$name (q=$q)"
  done
}

wine_smoke() {
  local bin="$1"
  local log_name="$2"
  local wine_bin="$3"
  [[ -x "$bin" ]] || { warn "Wine smoke skipped: $bin not executable"; return 0; }
  if [[ -z "$wine_bin" ]]; then
    warn "Wine smoke skipped for $log_name: wine binary not found"
    return 0
  fi
  # Use env so WINEDEBUG applies to wine even when wrapped by timeout.
  local cmd_base="env WINEDEBUG=-all $wine_bin \"$bin\""

  if [[ -n "$SMOKE_STDIN_FILE" ]]; then
    if [[ ! -f "$SMOKE_STDIN_FILE" ]]; then
      warn "Wine smoke stdin file not found: $SMOKE_STDIN_FILE"
      return 1
    fi
    local effective_args="$SMOKE_ARGS"
    if [[ "$effective_args" != *"-B"* && "$effective_args" != *"--batch"* ]]; then
      warn "Wine smoke stdin set but -B/--batch missing in SMOKE_ARGS; auto-appending -B"
      effective_args="${effective_args:+$effective_args }-B"
    fi
    local cmd="$cmd_base"
    if [[ -n "$effective_args" ]]; then
      cmd="$cmd $effective_args"
    fi
    log "Wine smoke: $log_name -- stdin@$SMOKE_STDIN_FILE"
    local pipeline_cmd="cat \"$SMOKE_STDIN_FILE\" | $cmd"
    run_smoke_command "$pipeline_cmd" "$log_name (stdin)"
    return 0
  fi

  for q in $SMOKE_QUERIES; do
    log "Wine smoke: $log_name -- $q"
    local cmd="$cmd_base"
    if [[ -n "$SMOKE_ARGS" ]]; then
      cmd="$cmd $SMOKE_ARGS \"$q\""
    else
      cmd="$cmd \"$q\""
    fi
    run_smoke_command "$cmd" "$log_name (q=$q)"
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
[[ -n "$SMOKE_STDIN_FILE" ]] && log "Smoke stdin file: $SMOKE_STDIN_FILE"
[[ -n "$RB_CFLAGS_EXTRA" ]] && log "CFLAGS extra override: $RB_CFLAGS_EXTRA"
log "GNURX win64 libdir: ${GNURX_WIN64_LIBDIR:-<unset>}"
log "GNURX win32 libdir: ${GNURX_WIN32_LIBDIR:-<unset>}"
log "Quiet mode: $RB_QUIET"

if [[ -n "$SMOKE_STDIN_FILE" && "$SMOKE_QUERIES_PROVIDED" == "1" && -n "$SMOKE_QUERIES" ]]; then
  warn "SMOKE_STDIN_FILE set; SMOKE_QUERIES entries will be ignored for batch smoke runs"
fi

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
: "${smoke_log_win64:=$ARTIFACTS_DIR/smoke_test_win64.log}"
: "${smoke_log_win32:=$ARTIFACTS_DIR/smoke_test_win32.log}"
: > "$file_report"
: > "$smoke_log"
WIN_SMOKE_BINS=()

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

  # Collect Windows binaries for wine smoke (run later)
  if [[ "$bn" == "whois-win64.exe" || "$bn" == "whois-win32.exe" ]]; then
    WIN_SMOKE_BINS+=("$ARTIFACTS_DIR/$bn")
  fi

  # single-binary smoke test for the built target
  if [[ "$RUN_TESTS" == "1" && -n "$bn" && -x "$ARTIFACTS_DIR/$bn" ]]; then
    echo "[remote_build] QEMU smoke: $bn ..."
    smoke_test "$ARTIFACTS_DIR/$bn" >> "$smoke_log" 2>&1 || true
  fi
done

# Windows wine smoke tests (run after build loop to avoid repeated setup)
if [[ "$RUN_TESTS" == "1" && ${#WIN_SMOKE_BINS[@]} -gt 0 ]]; then
  wine64_resolved="$(resolve_wine_bin 64)"
  wine32_resolved="$(resolve_wine_bin 32)"
  [[ -n "$wine64_resolved" ]] && log "Wine64 runner: $wine64_resolved" || warn "wine64 not found; win64 smoke skipped"
  [[ -n "$wine32_resolved" ]] && log "Wine runner (32): $wine32_resolved" || warn "wine (32) not found; win32 smoke skipped"

  # Clear per-arch wine smoke logs
  : > "$smoke_log_win64"
  : > "$smoke_log_win32"

  for wb in "${WIN_SMOKE_BINS[@]}"; do
    bn="$(basename "$wb")"
    case "$bn" in
      whois-win64.exe)
        [[ -z "$wine64_resolved" ]] && continue
        echo "[remote_build] Wine smoke: $bn ..." | tee -a "$smoke_log_win64" >/dev/null
        wine_smoke "$wb" "$bn" "$wine64_resolved" >> "$smoke_log_win64" 2>&1 || true
        ;;
      whois-win32.exe)
        [[ -z "$wine32_resolved" ]] && continue
        echo "[remote_build] Wine smoke: $bn ..." | tee -a "$smoke_log_win32" >/dev/null
        wine_smoke "$wb" "$bn" "$wine32_resolved" >> "$smoke_log_win32" 2>&1 || true
        ;;
    esac
  done
fi

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
