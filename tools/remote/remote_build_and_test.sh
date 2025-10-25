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
  -h                 Show help

Notes:
  - Run with NO options to build all targets with defaults.
  - A single positional [keyfile] is accepted as a shortcut for -k.
EOF
}

while getopts ":H:u:p:k:R:t:r:o:f:s:P:m:q:h" opt; do
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

SSH_BASE=(ssh -p "$SSH_PORT")
SCP_BASE=(scp -P "$SSH_PORT")
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

log "Check SSH auth"
if ! "${SSH_BASE[@]}" "$REMOTE_HOST" bash -lc "echo ok" >/dev/null 2>&1; then
  err "SSH authentication failed. Use -k /d/xxx/id_rsa or ssh-agent."
  exit 1
fi

REMOTE_HOME="$(${SSH_BASE[@]} "$REMOTE_HOST" bash -lc "cd ~ && pwd" | tr -d '\r\n')"
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
"${SSH_BASE[@]}" "$REMOTE_HOST" bash -l -s <<EOF
set -e
cd "$REMOTE_REPO_DIR"
chmod +x tools/remote/remote_build.sh
TARGETS='$TARGETS' RUN_TESTS=$RUN_TESTS OUTPUT_DIR='$OUTPUT_DIR' SMOKE_MODE='$SMOKE_MODE' SMOKE_QUERIES='$SMOKE_QUERIES' ./tools/remote/remote_build.sh
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
    echo "[remote_build] Smoke test tail (last 40 lines):"
    tail -n 40 "$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log" || true
  else
    echo "[remote_build][WARN] smoke_test.log is missing or empty"
  fi
fi
