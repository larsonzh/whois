#!/usr/bin/env bash
set -eo pipefail

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
SMOKE_QUERIES_SET=0
# Additional args for smoke tests (e.g., -g "Org|Net|Country")
SMOKE_ARGS=${SMOKE_ARGS:-""}
# Optional stdin file piped into smoke runner (e.g., for -B batch tests)
SMOKE_STDIN_FILE=${SMOKE_STDIN_FILE:-""}
# Allowlisted WHOIS_* environment forwarding for deterministic tests
WHOIS_BATCH_DEBUG_PENALIZE_VALUE=${WHOIS_BATCH_DEBUG_PENALIZE:-""}
# Optional override for per-arch make CFLAGS_EXTRA (e.g., "-O3 -s" or "-O2 -g")
RB_CFLAGS_EXTRA=${RB_CFLAGS_EXTRA:-""}
UPLOAD_TO_GH=${UPLOAD_TO_GH:-0}  # 1 to upload fetched assets to GitHub Release
RELEASE_TAG=${RELEASE_TAG:-""}  # tag name to upload to (e.g. v3.1.4)
# Optional: enable grep/seclog self-test hooks (compile-time + runtime)
GREP_TEST=${GREP_TEST:-0}
SECLOG_TEST=${SECLOG_TEST:-0}
REFERRAL_CHECK=${REFERRAL_CHECK:-1}
REFERRAL_CASES=${REFERRAL_CASES:-"143.128.0.0@whois.iana.org,whois.arin.net,whois.afrinic.net@whois.afrinic.net"}

log() { echo "[remote_build] $*"; }
warn() { echo "[remote_build][WARN] $*" >&2; }
err() { echo "[remote_build][ERROR] $*" >&2; }

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
  -F <stdin_file>    Repo-relative file piped to smoke tests' stdin (batch mode helper)
  -E <cflags_extra>  Override per-arch CFLAGS_EXTRA passed to make (e.g., "-O3 -s")
  -M <pacing_expect> Assert sleep pacing from smoke log when -r 1 and --retry-metrics present: 'zero' or 'nonzero'
  -L <0|1>           Run referral_143128_check suite after smoke tests (default: $REFERRAL_CHECK)
  -J <cases>         Override referral check cases (default: $REFERRAL_CASES)
  -X <0|1>           Enable GREP self-test (adds -DWHOIS_GREP_TEST and sets WHOIS_GREP_TEST=1)
  -Z <0|1>           Enable SECLOG self-test (adds -DWHOIS_SECLOG_TEST and sets WHOIS_SECLOG_TEST=1)
  -h                 Show help

Notes:
  - Run with NO options to build all targets with defaults.
  - A single positional [keyfile] is accepted as a shortcut for -k.
EOF
}

GOLDEN=${GOLDEN:-0}
PACING_EXPECT=${PACING_EXPECT:-""}
QUIET=${QUIET:-0}
# Preserve raw original argv for debug (quoted as received by bash after expansion)
ORIG_ARGS="$*"
while getopts ":H:u:p:k:R:t:r:o:f:s:P:m:q:a:F:E:M:L:J:U:T:G:X:Z:Y:h" opt; do
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
    q) SMOKE_QUERIES="$OPTARG"; SMOKE_QUERIES_SET=1 ;;
    a) SMOKE_ARGS="$OPTARG" ;;
    F) SMOKE_STDIN_FILE="$OPTARG" ;;
    E) RB_CFLAGS_EXTRA="$OPTARG" ;;
    M) PACING_EXPECT="$OPTARG" ;;
    L) REFERRAL_CHECK="$OPTARG" ;;
    J) REFERRAL_CASES="$OPTARG" ;;
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

# Base SSH/SCP command arrays (filled before any remote call)
SSH_BASE=(ssh -p "$SSH_PORT")
SCP_BASE=(scp -P "$SSH_PORT")
if [[ -n "$SSH_KEY" ]]; then
  SSH_BASE+=(-i "$SSH_KEY")
  SCP_BASE+=(-i "$SSH_KEY")
fi
if [[ "$QUIET" == "1" ]]; then
  SSH_BASE+=(-q)
  SCP_BASE+=(-q)
fi
if [[ "$DEBUG_SSH" == "1" ]]; then
  SSH_BASE+=(-vvv)
  SCP_BASE+=(-vvv)
  log "SSH debug verbosity enabled (-vvv)"
fi
SSH_BASE+=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR)
SCP_BASE+=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR)
REMOTE_HOST="${SSH_USER}@${SSH_HOST}"

# Parse sync targets (allow separators ';' or ',')
SYNC_TARGETS=()
if [[ -n "$SYNC_TO" ]]; then
  old_ifs="$IFS"
  IFS=';, '
  read -ra SYNC_TARGETS <<<"$SYNC_TO"
  IFS="$old_ifs"
fi

# Resolve local repo root: script under whois/tools/remote
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_NAME="$(basename "$REPO_ROOT")"
log "Repo root: $REPO_ROOT"
log "Raw args: $ORIG_ARGS"

run_remote_lc() {
  local payload="${1-}"
  # Escape single quotes for safe wrapping in single quotes: ' -> '\''
  local esc
  esc=${payload//\'/\'"\'"\'}
  "${SSH_BASE[@]}" "$REMOTE_HOST" "bash -lc '$esc'"
}

log "Check SSH connectivity/auth"
if ! "${SSH_BASE[@]}" "$REMOTE_HOST" bash -lc "echo ok" >/dev/null 2>&1; then
  rc=$?
  if [[ $rc -eq 255 ]]; then
    err "SSH connect failed (timeout/refused). host=$SSH_HOST port=$SSH_PORT. Check: public reachability (GitHub runners cannot reach private RFC1918 addresses), firewall/NAT, port.$([[ "$DEBUG_SSH" == "1" ]] && echo ' (debug enabled)')"
  else
    err "SSH authentication failed (rc=$rc). Ensure private key matches remote authorized_keys (no passphrase unless agent) and correct user ($SSH_USER). Set WHOIS_DEBUG_SSH=1 for verbose trace."
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
## Version derivation logic:
# 1. If WHOIS_FORCE_VERSION is set, use it directly.
# 2. If HEAD matches an exact tag and working tree is clean, use the tag verbatim (vX.Y.Z).
# 3. Else fall back to `git describe --tags --long --always` and append -dirty only if there are local changes.
# Diagnostics:
#   - Set WHOIS_DEBUG_VERSION=1 to print detailed cleanliness info and paths.
#   - Set WHOIS_DIRTY_IGNORE_REGEX to ignore tracked changes that match this regex (optional, advanced).
#   - Untracked files are ignored by default for cleanliness check.

force_version="${WHOIS_FORCE_VERSION:-}"
debug_version="${WHOIS_DEBUG_VERSION:-0}"
ignore_regex="${WHOIS_DIRTY_IGNORE_REGEX:-}"
# Toggle strict versioning: when set to 1, append -dirty if tracked changes exist; default 0 (no -dirty)
strict_version="${WHOIS_STRICT_VERSION:-0}"
# Provide a sensible default to ignore synced static binaries under repo (tracked release folder)
if [[ -z "$ignore_regex" ]]; then
  ignore_regex='^release/lzispro/whois/whois-'
fi

# Refresh index metadata to avoid false positives due to stale stat info
git -C "$REPO_ROOT" update-index -q --refresh || true

# Compute cleanliness considering only tracked changes (ignore untracked by default)
is_clean=1
changed_list=$(git -C "$REPO_ROOT" status --porcelain=v1 -uno || true)
if [[ -n "$changed_list" ]]; then
  if [[ -n "$ignore_regex" ]]; then
    # Filter out lines whose path matches ignore_regex (format: XY <path>)
    filtered=$(echo "$changed_list" | sed -E 's/^.. //' | grep -Ev "$ignore_regex" || true)
  else
    filtered=$(echo "$changed_list" | sed -E 's/^.. //' )
  fi
  if [[ -n "$filtered" ]]; then
    is_clean=0
  fi
fi

# Resolve exact tag on HEAD if present
head_tag="$(git -C "$REPO_ROOT" describe --exact-match --tags 2>/dev/null || true)"

# Select version string (simplified by default: no -dirty suffix)
if [[ -n "$force_version" ]]; then
  VERSION_STR="$force_version"
elif [[ -n "$head_tag" ]]; then
  # In simplified mode, use tag verbatim even if working tree has changes
  VERSION_STR="$head_tag"
else
  base_describe="$(git -C "$REPO_ROOT" describe --tags --long --always 2>/dev/null || echo "dev-$(date +%Y%m%d)")"
  if [[ "$strict_version" == "1" && $is_clean -eq 0 ]]; then
    VERSION_STR="${base_describe}-dirty"
  else
    VERSION_STR="$base_describe"
  fi
fi

# Debug dump if requested
if [[ "$debug_version" == "1" ]]; then
  echo "[remote_build][DEBUG] git rev-parse HEAD: $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo N/A)"
  echo "[remote_build][DEBUG] head_tag: ${head_tag:-<none>}"
  echo "[remote_build][DEBUG] is_clean=$is_clean (untracked ignored) strict=$strict_version"
  if [[ -n "$changed_list" ]]; then
    echo "[remote_build][DEBUG] status --porcelain (tracked only):"
    echo "$changed_list" | sed -E 's/^/  /'
    if [[ -n "$ignore_regex" ]]; then
      echo "[remote_build][DEBUG] after ignore-regex filter ($ignore_regex):"
      echo "${filtered:-<empty>}" | sed -E 's/^/  /'
    fi
  fi
fi

echo "$VERSION_STR" > "$REPO_ROOT/VERSION.txt"
log "Version: $VERSION_STR (written to VERSION.txt; clean=$is_clean tag=$head_tag force=${force_version:-none})"

tar -C "$LOCAL_PARENT_DIR" -cf - "${EXCLUDES[@]}" "$REPO_NAME" | \
  run_remote_lc "mkdir -p $REMOTE_BASE/src && tar -C $REMOTE_BASE/src -xf -"

# Clean local VERSION.txt (only used for packaging; tolerate transient Windows locks)
if ! rm -f "$REPO_ROOT/VERSION.txt" 2>/dev/null; then
  warn "VERSION.txt cleanup skipped (file busy); remove manually if it persists"
fi

REMOTE_REPO_DIR="$REMOTE_BASE/src/$REPO_NAME"

log "Remote build and optional tests"
# Escape single quotes in SMOKE_ARGS for safe embedding inside single quotes in heredoc command
SMOKE_ARGS_ESC="$SMOKE_ARGS"
SMOKE_ARGS_ESC=${SMOKE_ARGS_ESC//\'/\'"\'"\'}
# Escape stdin file path if provided
SMOKE_STDIN_FILE_ESC="$SMOKE_STDIN_FILE"
SMOKE_STDIN_FILE_ESC=${SMOKE_STDIN_FILE_ESC//\'/\'"'"'\'}
WHOIS_BATCH_DEBUG_PENALIZE_ESC="$WHOIS_BATCH_DEBUG_PENALIZE_VALUE"
WHOIS_BATCH_DEBUG_PENALIZE_ESC=${WHOIS_BATCH_DEBUG_PENALIZE_ESC//\'/\'"'"'\'}
# Treat VS Code task placeholder 'NONE' as empty extra args
if [[ "$SMOKE_ARGS_ESC" == "NONE" || "$SMOKE_ARGS_ESC" == "none" ]]; then
  SMOKE_ARGS_ESC=""
fi
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
echo "[remote_build] Using CLI flags for pacing/metrics/selftests (only allowlisted WHOIS_* env such as WHOIS_BATCH_DEBUG_PENALIZE are forwarded for deterministic tests)."
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
echo "[remote_build]   TARGETS='$TARGETS' RUN_TESTS=$RUN_TESTS OUTPUT_DIR='$OUTPUT_DIR' SMOKE_MODE='$SMOKE_MODE' SMOKE_QUERIES='$SMOKE_QUERIES' SMOKE_ARGS='${SMOKE_ARGS_ESC:-<empty>}'"
echo "[remote_build]   SMOKE_STDIN_FILE='${SMOKE_STDIN_FILE_ESC:-<empty>}'"
echo "[remote_build]   RB_CFLAGS_EXTRA='$RB_CFLAGS_EXTRA_ESC' (per-arch make override)"
echo "[remote_build]   QUIET=$QUIET"
echo "[remote_build]   RAW_SMOKE_ARGS_ORIG='$SMOKE_ARGS'"
if [[ -n "$WHOIS_BATCH_DEBUG_PENALIZE_VALUE" ]]; then
  echo "[remote_build]   Forward env WHOIS_BATCH_DEBUG_PENALIZE (len=${#WHOIS_BATCH_DEBUG_PENALIZE_VALUE})"
fi
# Export grep/seclog self-test env if requested so it runs at program start
# (Deprecated) GREP/SECLOG env forwarding removed; enable via CLI: --selftest-grep / --selftest-seclog
WHOIS_BATCH_DEBUG_PENALIZE='${WHOIS_BATCH_DEBUG_PENALIZE_ESC}' TARGETS='$TARGETS' RUN_TESTS=$RUN_TESTS OUTPUT_DIR='$OUTPUT_DIR' SMOKE_MODE='$SMOKE_MODE' SMOKE_QUERIES='$SMOKE_QUERIES' SMOKE_ARGS='$SMOKE_ARGS_ESC' SMOKE_STDIN_FILE='${SMOKE_STDIN_FILE_ESC}' RB_CFLAGS_EXTRA='$RB_CFLAGS_EXTRA_ESC' RB_QUIET='$QUIET' SMOKE_QUERIES_PROVIDED='$SMOKE_QUERIES_SET' ./tools/remote/remote_build.sh
EOF

# Capture referral logs on remote host before fetching so local checker can run afterwards.
if [[ "$RUN_TESTS" == "1" && "$REFERRAL_CHECK" == "1" ]]; then
  EFFECTIVE_REFERRAL_CASES="$REFERRAL_CASES"
  if [[ -z "$EFFECTIVE_REFERRAL_CASES" || "$EFFECTIVE_REFERRAL_CASES" == "NONE" ]]; then
    EFFECTIVE_REFERRAL_CASES="143.128.0.0@whois.iana.org,whois.arin.net,whois.afrinic.net@whois.afrinic.net"
  fi
  log "Capture referral logs on remote host (cases: $EFFECTIVE_REFERRAL_CASES)"
  REF_SCRIPT=$(cat <<EOF
set -eo pipefail
cd "$REMOTE_REPO_DIR"
BIN="$OUTPUT_DIR/whois-x86_64"
REF_DIR="$OUTPUT_DIR/referral_checks"
DEBUG_LOG="\$REF_DIR/referral_debug.log"
DEFAULT_HOSTS=("whois.iana.org" "whois.arin.net" "whois.afrinic.net")
if [[ ! -x "\$BIN" ]]; then
  echo "[remote_build][ERROR] referral check skipped: missing \$BIN" >&2
  exit 11
fi
mkdir -p "\$REF_DIR"
IFS=';' read -ra CASE_ARR <<<"$EFFECTIVE_REFERRAL_CASES"
for case_spec in "\${CASE_ARR[@]}"; do
  [[ -z "\$case_spec" ]] && continue
  IFS='@' read -ra PARTS <<<"\$case_spec"
  query="\${PARTS[0]:-143.128.0.0}"
  hosts_raw="\${PARTS[1]:-whois.iana.org,whois.arin.net,whois.afrinic.net}"
  auth_host="\${PARTS[2]:-}"
  echo "case_spec=\$case_spec query_raw=\$query hosts_raw=\$hosts_raw auth_raw=\${PARTS[2]:-}" >>"\$DEBUG_LOG"
  HOSTS=()
  : "\${hosts_raw:=}"
  IFS=',' read -ra HOSTS <<<"\$hosts_raw"
  query=$(echo "\$query" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')
  if [[ -z "\$query" || "\$query" == "_query_" || "\$query" == "query" ]]; then
    query="143.128.0.0"
  fi
  CLEAN_HOSTS=()
  for raw_h in "\${HOSTS[@]}"; do
    trimmed=$(echo "\$raw_h" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')
    [[ -z "\$trimmed" ]] && continue
    CLEAN_HOSTS+=("\$trimmed")
  done
  HOSTS=("\${CLEAN_HOSTS[@]}")
  placeholder_host=0
  for h in "\${HOSTS[@]}"; do
    if [[ "\$h" == "host" || "\$h" == "_host_" ]]; then
      placeholder_host=1
      break
    fi
  done
  echo "hosts_clean=\${HOSTS[*]} placeholder_host=\$placeholder_host" >>"\$DEBUG_LOG"
  if (( \${#HOSTS[@]}==1 )) && (( placeholder_host==1 )); then
    HOSTS=("\${DEFAULT_HOSTS[@]}")
  fi
  if (( \${#HOSTS[@]}==0 )) || (( placeholder_host==1 && \${#HOSTS[@]}<=2 )); then
    echo "[remote_build][WARN] referral case has placeholder/empty hosts; falling back to default chain" >&2
    HOSTS=("\${DEFAULT_HOSTS[@]}")
    query="143.128.0.0"
    auth_host="whois.afrinic.net"
  fi
  if [[ -z "\$auth_host" ]]; then
    auth_host="\${HOSTS[-1]}"
  fi
  echo "hosts_final=\${HOSTS[*]} auth_host=\$auth_host" >>"\$DEBUG_LOG"
  label=$(echo "\$query" | tr ' /\\\n\r\t' '_' | sed -E 's/[^A-Za-z0-9._-]+/_/g; s/^_+//; s/_+$//')
  if [[ "\$label" == "query" || "\$label" == "_query_" ]]; then
    echo "label placeholder detected; fallback applied" >>"\$DEBUG_LOG"
    query="143.128.0.0"
    HOSTS=("\${DEFAULT_HOSTS[@]}")
    auth_host="whois.afrinic.net"
    label="143.128.0.0"
  fi
  case_dir="\$REF_DIR/\$label"
  mkdir -p "\$case_dir"
  echo "[remote_build] Referral parsed: query=\$query hosts=\${HOSTS[*]} auth=\$auth_host label=\$label" >>"\$DEBUG_LOG"
  for host in "\${HOSTS[@]}"; do
    # Domain names are already filename-safe; only swap path separators/newlines/tabs for underscores.
    safe_host="\${host//\//_}"
    safe_host="\${safe_host//$'\r'/}"
    safe_host="\${safe_host//$'\n'/}"
    safe_host="\${safe_host//$'\t'/}"
    outfile="\$case_dir/\${safe_host}.log"
    echo "capture host=\$host safe=\$safe_host outfile=\$outfile" >>"\$DEBUG_LOG"
    echo "Referral capture: query=\$query host=\$host safe=\$safe_host -> \$outfile" >>"\$DEBUG_LOG"
    if ! "\$BIN" -h "\$host" "\$query" --debug --retry-metrics --dns-cache-stats >"\$outfile" 2>&1; then
      echo "[remote_build][ERROR] referral capture failed for \$host (query=\$query)" >&2
      exit 12
    fi
  done
done
echo "Referral dir listing (depth 1):" >>"\$DEBUG_LOG"
ls -l "\$REF_DIR" >>"\$DEBUG_LOG" 2>/dev/null || true
echo "Referral files (depth 2):" >>"\$DEBUG_LOG"
find "\$REF_DIR" -maxdepth 2 -type f -print >>"\$DEBUG_LOG" 2>/dev/null || true
EOF
 )
  if ! run_remote_lc "$REF_SCRIPT"; then
    err "referral capture failed"
    exit 1
  fi
fi

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
    # Remove everything except whois-* and SHA256SUMS-static.txt in target
    find "$tgt" -maxdepth 1 -type f ! -name 'whois-*' ! -name 'SHA256SUMS-static.txt' -exec rm -f {} + || true
  fi
  log "Sync whois-* and SHA256SUMS-static.txt to: $tgt"
  cp -f "$LOCAL_ARTIFACTS_DIR/build_out"/whois-* "$tgt/" 2>/dev/null || warn "No whois-* found to sync for $tgt"
  if [[ -s "$LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt" ]]; then
    cp -f "$LOCAL_ARTIFACTS_DIR/build_out/SHA256SUMS-static.txt" "$tgt/" 2>/dev/null || warn "Failed to copy SHA256SUMS-static.txt to $tgt"
  else
    warn "SHA256SUMS-static.txt missing under $LOCAL_ARTIFACTS_DIR/build_out; skipped"
  fi
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
    echo "[remote_build][WARN] Build warnings/errors detected. See $LOCAL_ARTIFACTS_DIR/build_out/build_errors.log"
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

SMOKE_LOG="$LOCAL_ARTIFACTS_DIR/build_out/smoke_test.log"

if [[ "$RUN_TESTS" == "1" ]]; then
  if [[ -s "$SMOKE_LOG" ]]; then
    smoke_lines=$(wc -l < "$SMOKE_LOG" 2>/dev/null || echo 0)
    smoke_lines="${smoke_lines//[[:space:]]/}"
    echo "[remote_build] Smoke tests completed ($smoke_lines lines). See $SMOKE_LOG"

    # DNS cache stats summary: when --dns-cache-stats is present in SMOKE_ARGS,
    # print the total number of [DNS-CACHE-SUM] lines observed across all arch runs.
    if [[ " $SMOKE_ARGS " == *" --dns-cache-stats "* ]]; then
      dns_cache_sum_count=$(grep -c "\[DNS-CACHE-SUM\]" "$SMOKE_LOG" 2>/dev/null || echo 0)
      echo "[remote_build] DNS-CACHE-SUM lines: $dns_cache_sum_count (details: $SMOKE_LOG)"
      if [[ "$dns_cache_sum_count" -eq 0 ]]; then
        echo "[remote_build][WARN] No [DNS-CACHE-SUM] lines found even though --dns-cache-stats was enabled" >&2
      fi
    fi

    # Optional DNS diagnostics counters when debug metrics requested.
    if [[ " $SMOKE_ARGS " == *" --debug "* || " $SMOKE_ARGS " == *" --retry-metrics "* || " $SMOKE_ARGS " == *" --dns-debug "* ]]; then
      for tag in DNS-CAND DNS-FALLBACK DNS-CACHE; do
        tag_count=$(grep -c "\[$tag\]" "$SMOKE_LOG" 2>/dev/null || echo 0)
        tag_count="${tag_count//[[:space:]]/}"
        if [[ "$tag_count" =~ ^[1-9][0-9]*$ ]]; then
          echo "[remote_build] $tag lines: $tag_count (details: $SMOKE_LOG)"
        fi
      done
    fi
  else
    echo "[remote_build][WARN] smoke_test.log is missing or empty"
  fi

  # Optional pacing assertion: requires --retry-metrics in SMOKE_ARGS
  if [[ -n "$PACING_EXPECT" ]]; then
    if [[ "$SMOKE_ARGS" != *"--retry-metrics"* ]]; then
      echo "[remote_build][WARN] -M specified but --retry-metrics not present; skip pacing assertion"
    else
      log_file="$SMOKE_LOG"
      if [[ -s "$log_file" ]]; then
        mapfile -t sleeps < <(grep -ho "sleep_ms=[0-9]\+" "$log_file" | sed -E 's/.*=([0-9]+)/\1/')
        if (( ${#sleeps[@]} == 0 )); then
          echo "[remote_build][WARN] No sleep_ms extracted from metrics; skip pacing assertion"
        else
          nonzero=0; zero=0
          for v in "${sleeps[@]}"; do
            if [[ "$v" == "0" ]]; then zero=$((zero+1)); else nonzero=$((nonzero+1)); fi
          done
          if [[ "$PACING_EXPECT" == "zero" ]]; then
            if (( nonzero == 0 )); then
              echo "[remote_build] Pacing assertion (zero): PASS"
            else
              echo "[remote_build][ERROR] Pacing assertion (zero) failed: found $nonzero non-zero sleeps"
              exit 1
            fi
          elif [[ "$PACING_EXPECT" == "nonzero" ]]; then
            if (( nonzero > 0 )); then
              echo "[remote_build] Pacing assertion (nonzero): PASS"
            else
              echo "[remote_build][ERROR] Pacing assertion (nonzero) failed: all sleeps are zero ($zero)"
              exit 1
            fi
          else
            echo "[remote_build][WARN] Unknown -M value '$PACING_EXPECT' (use 'zero' or 'nonzero'); skip"
          fi
        fi
      fi
    fi
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
      GOLDEN_REPORT="$LOCAL_ARTIFACTS_DIR/build_out/golden_report.txt"
      ts="$(date +%Y-%m-%dT%H:%M:%S%z)"
      {
        echo "# Golden Check Report"
        echo "timestamp=$ts"
        echo "smoke_log=$SMOKE_LOG"
        echo "query=$first_query"
        echo
      } > "$GOLDEN_REPORT"
      echo "[remote_build] Golden expected query: $first_query"
      if "$REPO_ROOT/tools/test/golden_check.sh" -l "$SMOKE_LOG" --query "$first_query" | tee -a "$GOLDEN_REPORT"; then
        echo "[remote_build] Golden check: PASS (report: $GOLDEN_REPORT)"
      else
        echo "[remote_build][ERROR] Golden check: FAIL (report: $GOLDEN_REPORT)"
        exit 1
      fi
    else
      echo "[remote_build][WARN] golden_check.sh not executable or missing; skip"
    fi
  fi

  if [[ "$REFERRAL_CHECK" == "1" ]]; then
    REF_DIR="$LOCAL_ARTIFACTS_DIR/build_out/referral_checks"
    if [[ -x "$REPO_ROOT/tools/test/referral_143128_check.sh" ]]; then
        if "$REPO_ROOT/tools/test/referral_143128_check.sh" --ref-dir "$REF_DIR" --cases "$EFFECTIVE_REFERRAL_CASES"; then
        echo "[remote_build] referral check: PASS"
      else
        echo "[remote_build][ERROR] referral check failed"
        exit 1
      fi
    else
      echo "[remote_build][WARN] referral_143128_check.sh missing; skip referral check"
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
