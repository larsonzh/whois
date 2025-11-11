#!/usr/bin/env bash
set -euo pipefail

# Local launcher for remote static cross-compile and optional QEMU smoke tests.
# English-only in code/comments; user-facing Chinese doc provided separately.

SSH_HOST=${SSH_HOST:-"10.0.0.199"}
SSH_USER=${SSH_USER:-"larson"}
SSH_PORT=${SSH_PORT:-22}
SSH_KEY=${SSH_KEY:-""}
REMOTE_DIR=${REMOTE_DIR:-""}   # default: $HOME/whois_remote
TARGETS=${TARGETS:-"aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64"}
RUN_TESTS=${RUN_TESTS:-0}
OUTPUT_DIR=${OUTPUT_DIR:-"out/build_out"}
FETCH_TO=${FETCH_TO:-"out/artifacts"}
SYNC_TO=${SYNC_TO:-""}         # optional: copy whois-* to one or more local folders; supports multi-target via ';' or ',' separators
PRUNE_TARGET=${PRUNE_TARGET:-0} # if 1 and SYNC_TO set: remove non-whois-* before copying
SMOKE_MODE=${SMOKE_MODE:-"net"} # default to real network tests
SMOKE_QUERIES=${SMOKE_QUERIES:-"8.8.8.8"} # space-separated queries; passed through to remote
# Additional args for smoke tests (e.g., -g "Org|Net|Country")
SMOKE_ARGS=${SMOKE_ARGS:-""}
# Optional override for per-arch make CFLAGS_EXTRA (e.g., "-O3 -s" or "-O2 -g")
RB_CFLAGS_EXTRA=${RB_CFLAGS_EXTRA:-""}
UPLOAD_TO_GH=${UPLOAD_TO_GH:-0}  # 1 to upload fetched assets to GitHub Release
RELEASE_TAG=${RELEASE_TAG:-""}  # tag name to upload to (e.g. v3.1.4)
# Optional: enable grep/seclog self-test hooks (compile-time + runtime)
GREP_TEST=${GREP_TEST:-0}
SECLOG_TEST=${SECLOG_TEST:-0}

print_help() {
  cat <<EOF
Usage: $(basename "$0") [options] [keyfile]

Options:
  -H <host>          SSH host (default: $SSH_HOST)
  -u <user>          SSH user (default: $SSH_USER)
  -p <port>          SSH port (default: $SSH_PORT)
  -k <key>           SSH private key path (optional)
  -R <remote_dir>    Remote base dir (default: use remote \$HOME/whois_remote)
  -t <targets>       Space-separated targets (default: "$TARGETS")
  -r <0|1>           Run smoke tests (default: $RUN_TESTS)
  -o <output_dir>    Remote output dir (default: $OUTPUT_DIR)
  -f <fetch_to>      Local artifacts base dir (default: $FETCH_TO)
  -s <sync_to>       Copy fetched whois-* to this local directory (optional)
  -P <0|1>           If 1 with -s, prune target (delete non whois-*) before copy (default: $PRUNE_TARGET)
  -a <smoke_args>    Extra args for remote smoke tests (e.g., -g "Org|Net|Country")
  -E <cflags_extra>  Override per-arch CFLAGS_EXTRA passed to make (e.g., "-O3 -s")
  -X <0|1>           Enable GREP self-test (adds -DWHOIS_GREP_TEST and sets WHOIS_GREP_TEST=1)
  -Z <0|1>           Enable SECLOG self-test (adds -DWHOIS_SECLOG_TEST and sets WHOIS_SECLOG_TEST=1)
  -h                 Show help

Notes:
  - Run with NO options to build all targets with defaults.
  - A single positional [keyfile] is accepted as a shortcut for -k.
EOF
}

GOLDEN=${GOLDEN:-0}
QUIET=${QUIET:-0}
# Preserve raw original argv for debug (quoted as received by bash after expansion)
ORIG_ARGS="$*"
while getopts ":H:u:p:k:R:t:r:o:f:s:P:m:q:a:E:U:T:G:X:Z:Y:h" opt; do
  case $opt in
    H) SSH_HOST="$OPTARG" ;;
    u) SSH_USER="$OPTARG" ;;
    p) SSH_PORT="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    R) REMOTE_DIR="$OPTARG" ;;
    t) TARGETS="$OPTARG" ;;
    r) RUN_TESTS="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    f) FETCH_TO="$OPTARG" ;;
    s) SYNC_TO="$OPTARG" ;;
    P) PRUNE_TARGET="$OPTARG" ;;
  m) SMOKE_MODE="$OPTARG" ;;
  q) SMOKE_QUERIES="$OPTARG" ;;
  a) SMOKE_ARGS="$OPTARG" ;;
  E) RB_CFLAGS_EXTRA="$OPTARG" ;;
  U) UPLOAD_TO_GH="$OPTARG" ;;
  T) RELEASE_TAG="$OPTARG" ;;
  G) GOLDEN="$OPTARG" ;;
  X) GREP_TEST="$OPTARG" ;;
  Z) SECLOG_TEST="$OPTARG" ;;
  Y) QUIET="$OPTARG" ;;
    h) print_help; exit 0 ;;
    :) echo "Option -$OPTARG requires an argument" >&2; exit 2 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; print_help; exit 2 ;;
  esac
done
shift $((OPTIND-1))
if (( $# >= 1 )) && [[ -z "$SSH_KEY" ]]; then
  [[ -f "$1" ]] && SSH_KEY="$1"
fi

log() { echo "[remote_build] $*"; }
warn() { echo "[remote_build][WARN] $*" >&2; }
err() { echo "[remote_build][ERROR] $*" >&2; }

# Resolve local repo root: script under whois/tools/remote
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_NAME="$(basename "$REPO_ROOT")"
log "Repo root: $REPO_ROOT"
log "Raw args: $ORIG_ARGS"

# Build sync target list (allow multi-target via ';' or ',' or whitespace)
SYNC_TARGETS=()
if [[ -z "$SYNC_TO" ]]; then
  DEFAULT_LOCAL_SYNC="$REPO_ROOT/release/lzispro/whois"
  SYNC_TARGETS+=("$DEFAULT_LOCAL_SYNC")
  # By default, prune the target folder to avoid accumulating unrelated files
  PRUNE_TARGET=1
  log "No -s/SYNC_TO provided; default to: ${SYNC_TARGETS[*]} (PRUNE_TARGET=$PRUNE_TARGET)"
else
  # Normalize separators to whitespace, then split
  SYNC_TO_NORM="${SYNC_TO//;/ }"
  SYNC_TO_NORM="${SYNC_TO_NORM//,/ }"
  # shellcheck disable=SC2206
  SYNC_TARGETS=( $SYNC_TO_NORM )
  log "Custom sync targets (-s): ${SYNC_TARGETS[*]} (PRUNE_TARGET=$PRUNE_TARGET)"
fi

# Windows path normalization: convert 'C:\foo\bar' -> '/c/foo/bar' for Git Bash compatibility
if (( ${#SYNC_TARGETS[@]} )); then
  NORMALIZED=()
  for raw in "${SYNC_TARGETS[@]}"; do
    # Trim possible trailing slash/backslash artifacts
    raw_trimmed="${raw%\\}"; raw_trimmed="${raw_trimmed%/}";
    if [[ "$raw_trimmed" =~ ^[A-Za-z]:\\ ]]; then
      drive_letter=${raw_trimmed:0:1}
      rest=${raw_trimmed:2}
      rest=${rest//\\/\/}
      lower_drive=$(echo "$drive_letter" | tr '[:upper:]' '[:lower:]')
      posix_path="/${lower_drive}/${rest}"
      NORMALIZED+=("$posix_path")
    else
      NORMALIZED+=("$raw_trimmed")
    fi
  done
  SYNC_TARGETS=("${NORMALIZED[@]}")
  log "Normalized sync targets: ${SYNC_TARGETS[*]}"
fi

SSH_BASE=(ssh -p "$SSH_PORT" -o ConnectTimeout=8)
SCP_BASE=(scp -P "$SSH_PORT" -o ConnectTimeout=8)
if [[ -n "$SSH_KEY" ]]; then
  SSH_BASE+=(-i "$SSH_KEY")
  SCP_BASE+=(-i "$SSH_KEY")
fi
SSH_BASE+=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR)
SCP_BASE+=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR)
REMOTE_HOST="${SSH_USER}@${SSH_HOST}"

run_remote_lc() {
  local payload="$1"
  # Escape single quotes for safe wrapping in single quotes: ' -> '\''
  local esc
  esc=${payload//\'/\'"\'"\'}
  "${SSH_BASE[@]}" "$REMOTE_HOST" "bash -lc '$esc'"
}

log "Check SSH connectivity/auth"
if ! "${SSH_BASE[@]}" "$REMOTE_HOST" bash -lc "echo ok" >/dev/null 2>&1; then
  rc=$?
  if [[ $rc -eq 255 ]]; then
    err "SSH connect failed (timeout/refused). host=$SSH_HOST port=$SSH_PORT. Check VM IP/port, firewall/NAT, and network reachability."
  else
    err "SSH authentication failed (rc=$rc). Use -k /d/xxx/id_rsa or ssh-agent; ensure public key is in remote authorized_keys."
  fi
  exit 1
fi

# Determine remote $HOME via helper to avoid array expansion warnings in some editors
REMOTE_HOME="$(run_remote_lc 'cd ~ && pwd' | tr -d '\r\n')"
[[ -z "$REMOTE_HOME" ]] && REMOTE_HOME="/home/$SSH_USER"
REMOTE_BASE="$REMOTE_HOME/whois_remote"
[[ -n "$REMOTE_DIR" ]] && REMOTE_BASE="$REMOTE_DIR"

log "Create remote work dir: $REMOTE_BASE/src"
run_remote_lc "mkdir -p $REMOTE_BASE/src"

log "Upload repository (exclude .git and out/artifacts)"
LOCAL_PARENT_DIR="$(cd "$REPO_ROOT/.." && pwd)"
EXCLUDES=("--exclude=$REPO_NAME/.git" "--exclude=$REPO_NAME/out/artifacts" "--exclude=$REPO_NAME/dist")

# Write VERSION.txt for remote builds (no .git on remote), then remove locally after packaging
VERSION_STR="$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo "dev-$(date +%Y%m%d)")"
echo "$VERSION_STR" > "$REPO_ROOT/VERSION.txt"
log "Version: $VERSION_STR (written to VERSION.txt)"

tar -C "$LOCAL_PARENT_DIR" -cf - "${EXCLUDES[@]}" "$REPO_NAME" | \
  run_remote_lc "mkdir -p $REMOTE_BASE/src && tar -C $REMOTE_BASE/src -xf -"

# Clean local VERSION.txt (only used for packaging)
rm -f "$REPO_ROOT/VERSION.txt"

REMOTE_REPO_DIR="$REMOTE_BASE/src/$REPO_NAME"

log "Remote build and optional tests"
# Escape single quotes in SMOKE_ARGS for safe embedding inside single quotes in heredoc command
SMOKE_ARGS_ESC="$SMOKE_ARGS"
SMOKE_ARGS_ESC=${SMOKE_ARGS_ESC//\'/\'"\'"\'}
RB_CFLAGS_EXTRA_ESC="$RB_CFLAGS_EXTRA"
RB_CFLAGS_EXTRA_ESC=${RB_CFLAGS_EXTRA_ESC//\'/\'"'"\'}
# If grep/seclog self-test enabled, append compile-time defines
if [[ "$GREP_TEST" == "1" ]]; then
  RB_CFLAGS_EXTRA_ESC="$RB_CFLAGS_EXTRA_ESC -DWHOIS_GREP_TEST"
fi
if [[ "$SECLOG_TEST" == "1" ]]; then
  RB_CFLAGS_EXTRA_ESC="$RB_CFLAGS_EXTRA_ESC -DWHOIS_SECLOG_TEST"
fi
"${SSH_BASE[@]}" "$REMOTE_HOST" bash -l -s <<EOF
set -e
cd "$REMOTE_REPO_DIR"
chmod +x tools/remote/remote_build.sh
echo "[remote_build] Build environment (base, intentionally clean to avoid host pollution):"
echo "[remote_build]   CC=
	\${CC:-\"\"}"
echo "[remote_build]   CFLAGS=
	\${CFLAGS:-\"\"}"
echo "[remote_build]   CFLAGS_EXTRA=
	\${CFLAGS_EXTRA:-\"\"}"
echo "[remote_build]   LDFLAGS=
  \${LDFLAGS:-\"\"}"
echo "[remote_build]   LDFLAGS_EXTRA=
  \${LDFLAGS_EXTRA:-\"\"} (effective value is set per-arch in remote_build.sh)"
echo "[remote_build]   Note: actual per-arch make overrides (CC, CFLAGS_EXTRA) will be printed as 'Make overrides (arch=...)' below"
echo "[remote_build]   TARGETS='$TARGETS' RUN_TESTS=$RUN_TESTS OUTPUT_DIR='$OUTPUT_DIR' SMOKE_MODE='$SMOKE_MODE' SMOKE_QUERIES='$SMOKE_QUERIES' SMOKE_ARGS='$SMOKE_ARGS_ESC'"
echo "[remote_build]   RB_CFLAGS_EXTRA='$RB_CFLAGS_EXTRA_ESC' (per-arch make override)"
echo "[remote_build]   QUIET=$QUIET"
echo "[remote_build]   RAW_SMOKE_ARGS_ORIG='$SMOKE_ARGS'"
# Export grep/seclog self-test env if requested so it runs at program start
if [[ "$GREP_TEST" == "1" ]]; then
  export WHOIS_GREP_TEST=1
  echo "[remote_build]   WHOIS_GREP_TEST=1 (enabled)"
fi
if [[ "$SECLOG_TEST" == "1" ]]; then
  export WHOIS_SECLOG_TEST=1
  echo "[remote_build]   WHOIS_SECLOG_TEST=1 (enabled)"
fi
TARGETS='$TARGETS' RUN_TESTS=$RUN_TESTS OUTPUT_DIR='$OUTPUT_DIR' SMOKE_MODE='$SMOKE_MODE' SMOKE_QUERIES='$SMOKE_QUERIES' SMOKE_ARGS='$SMOKE_ARGS_ESC' RB_CFLAGS_EXTRA='$RB_CFLAGS_EXTRA_ESC' RB_QUIET='$QUIET' ./tools/remote/remote_build.sh
EOF

# Fetch artifacts back
stamp="$(date +%Y%m%d-%H%M%S)"
LOCAL_ARTIFACTS_DIR="$REPO_ROOT/$FETCH_TO/$stamp"
mkdir -p "$LOCAL_ARTIFACTS_DIR"
REMOTE_ARTIFACTS="$REMOTE_REPO_DIR/$OUTPUT_DIR/"
log "Fetch artifacts -> $LOCAL_ARTIFACTS_DIR"
"${SCP_BASE[@]}" -r "$REMOTE_HOST:$REMOTE_ARTIFACTS" "$LOCAL_ARTIFACTS_DIR/"

# Sync fetched static binaries to local folder(s)
for tgt in "${SYNC_TARGETS[@]}"; do
  [[ -z "$tgt" ]] && continue
  mkdir -p "$tgt" || true
  if [[ "$PRUNE_TARGET" == "1" ]]; then
    # Remove everything except whois-* in target
    find "$tgt" -maxdepth 1 -type f ! -name 'whois-*' -exec rm -f {} + || true
  fi
  log "Sync whois-* to: $tgt"
  cp -f "$LOCAL_ARTIFACTS_DIR/build_out"/whois-* "$tgt/" 2>/dev/null || warn "No whois-* found to sync for $tgt"
done

# Remote cleanup
log "Remote cleanup: rm -rf $REMOTE_BASE"
run_remote_lc "rm -rf $REMOTE_BASE"

log "Done. Artifacts saved to: $LOCAL_ARTIFACTS_DIR"

# Local re-summary from fetched build_report.txt (independent of remote verbosity)
LOCAL_REPORT="$LOCAL_ARTIFACTS_DIR/build_out/build_report.txt"
if [[ -s "$LOCAL_REPORT" ]]; then
  echo "[remote_build] Local build summary (per arch):"
  while IFS= read -r line; do
    # line format: arch,binary=...,size=...,sha256=...
    # Just echo with same prefix for consistency
    echo "[remote_build] $line"
  done < "$LOCAL_REPORT"
  if [[ -s "$LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt" ]]; then
    echo "[remote_build] SHA256 list: $LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt"
  fi
  if [[ -s "$LOCAL_ARTIFACTS_DIR/build_out/build_errors.log" ]]; then
    echo "[remote_build][WARN] build_errors.log has content (quiet captured warnings/errors)"
  fi
  # Consistency verification: compare sha256 in build_report.txt with SHA256SUMS-static.txt
  if [[ -s "$LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt" ]]; then
    declare -A sha_map
    while read -r h name; do
      [[ -n "$name" ]] && sha_map["$name"]="$h"
    done < "$LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt"
    mismatch=0; missing=0
    while IFS= read -r line; do
      # Example line: aarch64,binary=whois-aarch64,size=89788,sha256=abc123...
      bin_field="$(echo "$line" | tr ',' '\n' | grep '^binary=' || true)"
      hash_field="$(echo "$line" | tr ',' '\n' | grep '^sha256=' || true)"
      bin_name="${bin_field#binary=}"
      hash_val="${hash_field#sha256=}"
      if [[ -z "$bin_name" || -z "$hash_val" ]]; then
        missing=1
        continue
      fi
      expected="${sha_map[$bin_name]:-}";
      if [[ -z "$expected" ]]; then
        echo "[remote_build][WARN] No expected hash for $bin_name in SHA256SUMS-static.txt"
        missing=1
        continue
      fi
      if [[ "$expected" != "$hash_val" ]]; then
        echo "[remote_build][ERROR] Hash mismatch for $bin_name: report=$hash_val sums=$expected"
        mismatch=1
      fi
    done < "$LOCAL_REPORT"
    if [[ "$mismatch" == "0" && "$missing" == "0" ]]; then
      echo "[remote_build] Local hash verify: PASS"
    elif [[ "$mismatch" == "0" ]]; then
      echo "[remote_build][WARN] Local hash verify: PASS (some entries missing)"
    else
      echo "[remote_build][ERROR] Local hash verify: FAIL"
      # Do not exit 1 automatically; allow caller to decide. Uncomment to enforce.
      # exit 1
    fi
  else
    echo "[remote_build][WARN] SHA256SUMS-static.txt absent; skip hash consistency verification"
  fi
else
  echo "[remote_build][WARN] local build_report.txt missing or empty: $LOCAL_REPORT"
fi

if [[ "$RUN_TESTS" == "1" ]]; then
  if [[ -s "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" ]]; then
    echo "[remote_build] Smoke test tail (last 60 lines):"
    # Prefer a segment containing the first header marker to quickly verify the output contract
    # Fallback to tail if grep fails
    if grep -n "^=== Query: " "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" >/dev/null 2>&1; then
      start=$(grep -n "^=== Query: " "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" | head -n1 | cut -d: -f1)
      sed -n "$((start>5?start-5:1)),$((start+55))p" "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" || tail -n 60 "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log"
    else
      tail -n 60 "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" || true
    fi
    # Additionally, surface any GREP/SECLOG self-test lines explicitly
    if grep -n "\[GREPTEST\]" "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" >/dev/null 2>&1; then
      echo "[remote_build] GREP self-test lines:" 
      grep "\[GREPTEST\]" "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" | tail -n 10 || true
    fi
    if grep -n "\[SECLOGTEST\]" "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" >/dev/null 2>&1; then
      echo "[remote_build] SECLOG self-test lines:" 
      grep "\[SECLOGTEST\]" "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" | tail -n 10 || true
    fi
  else
    echo "[remote_build][WARN] smoke_test.log is missing or empty"
  fi

  # Optional golden verification on fetched smoke log
  if [[ "$GOLDEN" == "1" ]]; then
    if [[ -x "$REPO_ROOT/tools/test/golden_check.sh" ]]; then
      echo "[remote_build] Running golden check ..."
      first_query="$(echo "$SMOKE_QUERIES" | awk '{print $1}')"
      if [[ -z "$first_query" ]]; then
        first_query="8.8.8.8"
        echo "[remote_build][WARN] SMOKE_QUERIES empty; fallback first_query=$first_query"
      fi
      echo "[remote_build] Golden expected query: $first_query"
      if "$REPO_ROOT/tools/test/golden_check.sh" -l "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" --query "$first_query"; then
        echo "[remote_build] Golden check: PASS"
      else
        echo "[remote_build][ERROR] Golden check: FAIL"
        exit 1
      fi
    else
      echo "[remote_build][WARN] golden_check.sh not executable or missing; skip"
    fi
  fi
fi

# Optional: upload fetched artifacts to GitHub Release
if [[ "$UPLOAD_TO_GH" == "1" ]]; then
  if [[ -z "$RELEASE_TAG" ]]; then
    warn "UPLOAD_TO_GH=1 but RELEASE_TAG is empty; skip upload"
  else
    # Detect owner/repo from git remote
    ORIGIN_URL="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
    if [[ "$ORIGIN_URL" =~ github.com[:/](.+)/([^/]+)(\.git)?$ ]]; then
      OWNER="${BASH_REMATCH[1]}"; REPO="${BASH_REMATCH[2]}"; REPO="${REPO%.git}"
      uploader="$REPO_ROOT/tools/release/upload_assets.sh"
      if [[ -x "$uploader" ]]; then
        # Build checksums for static binaries
        if command -v sha256sum >/dev/null 2>&1; then
          (cd "$LOCAL_ARTIFACTS_DIR/build_out" && sha256sum whois-* > SHA256SUMS-static.txt) || true
        fi
        FILES=("$LOCAL_ARTIFACTS_DIR/build_out"/whois-*)
        if [[ -f "$LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt" ]]; then
          FILES+=("$LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt")
        fi
        GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
        if [[ -z "$GH_TOKEN" ]]; then
          warn "GH_TOKEN/GITHUB_TOKEN not set; skip upload"
        else
          "$uploader" "$OWNER" "$REPO" "$RELEASE_TAG" "${FILES[@]}" || warn "Upload failed"
        fi
      else
        warn "Uploader script not found or not executable: $uploader"
      fi
    else
      warn "Cannot parse origin remote to detect owner/repo; skip upload (origin=$ORIGIN_URL)"
    fi
  fi
fi
