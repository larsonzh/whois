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
SYNC_TO=${SYNC_TO:-""}         # optional: copy whois-* to a local folder (e.g., lzispro/.../whois)
PRUNE_TARGET=${PRUNE_TARGET:-0} # if 1 and SYNC_TO set: remove non-whois-* before copying
SMOKE_MODE=${SMOKE_MODE:-"net"} # default to real network tests
SMOKE_QUERIES=${SMOKE_QUERIES:-"8.8.8.8"} # space-separated queries; passed through to remote
# Additional args for smoke tests (e.g., -g "Org|Net|Country")
SMOKE_ARGS=${SMOKE_ARGS:-""}
# Optional override for per-arch make CFLAGS_EXTRA (e.g., "-O3 -s" or "-O2 -g")
RB_CFLAGS_EXTRA=${RB_CFLAGS_EXTRA:-""}
UPLOAD_TO_GH=${UPLOAD_TO_GH:-0}  # 1 to upload fetched assets to GitHub Release
RELEASE_TAG=${RELEASE_TAG:-""}  # tag name to upload to (e.g. v3.1.4)

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
  -h                 Show help

Notes:
  - Run with NO options to build all targets with defaults.
  - A single positional [keyfile] is accepted as a shortcut for -k.
EOF
}

GOLDEN=${GOLDEN:-0}
while getopts ":H:u:p:k:R:t:r:o:f:s:P:m:q:a:E:U:T:G:h" opt; do
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

tar -C "$LOCAL_PARENT_DIR" -cf - "${EXCLUDES[@]}" "$REPO_NAME" | \
  run_remote_lc "mkdir -p $REMOTE_BASE/src && tar -C $REMOTE_BASE/src -xf -"

REMOTE_REPO_DIR="$REMOTE_BASE/src/$REPO_NAME"

log "Remote build and optional tests"
# Escape single quotes in SMOKE_ARGS for safe embedding inside single quotes in heredoc command
SMOKE_ARGS_ESC="$SMOKE_ARGS"
SMOKE_ARGS_ESC=${SMOKE_ARGS_ESC//\'/\'"\'"\'}
RB_CFLAGS_EXTRA_ESC="$RB_CFLAGS_EXTRA"
RB_CFLAGS_EXTRA_ESC=${RB_CFLAGS_EXTRA_ESC//\'/\'"'"\'}
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
TARGETS='$TARGETS' RUN_TESTS=$RUN_TESTS OUTPUT_DIR='$OUTPUT_DIR' SMOKE_MODE='$SMOKE_MODE' SMOKE_QUERIES='$SMOKE_QUERIES' SMOKE_ARGS='$SMOKE_ARGS_ESC' RB_CFLAGS_EXTRA='$RB_CFLAGS_EXTRA_ESC' ./tools/remote/remote_build.sh
EOF

# Fetch artifacts back
stamp="$(date +%Y%m%d-%H%M%S)"
LOCAL_ARTIFACTS_DIR="$REPO_ROOT/$FETCH_TO/$stamp"
mkdir -p "$LOCAL_ARTIFACTS_DIR"
REMOTE_ARTIFACTS="$REMOTE_REPO_DIR/$OUTPUT_DIR/"
log "Fetch artifacts -> $LOCAL_ARTIFACTS_DIR"
"${SCP_BASE[@]}" -r "$REMOTE_HOST:$REMOTE_ARTIFACTS" "$LOCAL_ARTIFACTS_DIR/"

# Optional sync to external folder
if [[ -n "$SYNC_TO" ]]; then
  mkdir -p "$SYNC_TO"
  if [[ "$PRUNE_TARGET" == "1" ]]; then
    # Remove everything except whois-* in target
    find "$SYNC_TO" -maxdepth 1 -type f ! -name 'whois-*' -exec rm -f {} + || true
  fi
  log "Sync whois-* to: $SYNC_TO"
  cp -f "$LOCAL_ARTIFACTS_DIR/build_out"/whois-* "$SYNC_TO/" 2>/dev/null || warn "No whois-* found to sync"
fi

# Remote cleanup
log "Remote cleanup: rm -rf $REMOTE_BASE"
run_remote_lc "rm -rf $REMOTE_BASE"

log "Done. Artifacts saved to: $LOCAL_ARTIFACTS_DIR"

if [[ "$RUN_TESTS" == "1" ]]; then
  if [[ -s "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" ]]; then
    echo "[remote_build] Smoke test tail (last 60 lines):"
    # 优先展示包含头部行/尾行的片段，便于快速验证输出契约
    # 若 grep 失败则回退到 tail
    if grep -n "^=== Query: " "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" >/dev/null 2>&1; then
      start=$(grep -n "^=== Query: " "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" | head -n1 | cut -d: -f1)
      sed -n "$((start>5?start-5:1)),$((start+55))p" "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" || tail -n 60 "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log"
    else
      tail -n 60 "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" || true
    fi
  else
    echo "[remote_build][WARN] smoke_test.log is missing or empty"
  fi

  # Optional golden verification on fetched smoke log
  if [[ "$GOLDEN" == "1" ]]; then
    if [[ -x "$REPO_ROOT/tools/test/golden_check.sh" ]]; then
      echo "[remote_build] Running golden check ..."
      if "$REPO_ROOT/tools/test/golden_check.sh" -l "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log"; then
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
