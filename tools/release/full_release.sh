#!/usr/bin/env bash
set -euo pipefail

# One-click release pipeline for whois
# 1) Remote cross-compile + (optional) smoke test + sync 7 static binaries to lzispro
# 2) Commit & push updated static binaries in lzispro
# 3) Commit & push updated RELEASE_NOTES.md in whois (optional if changed)
# 4) Create and push annotated tag to trigger GitHub Release (auto-attaches CI x86_64 + 7 static)
#
# Usage:
#   tools/release/full_release.sh [--tag vX.Y.Z] [--queries "8.8.8.8 1.1.1.1"] [--no-smoke]
#                                 [--lzispro-path /d/xxx/lzispro] [--strict-warn 0|1] [--dry-run]
#
# Defaults:
# - If --tag is omitted, auto bump the latest vX.Y.Z tag's patch number (vA.B.(C+1))
# - Smoke tests enabled by default (-r 1)
# - queries default to "8.8.8.8"
# - lzispro-path auto-detected as a sibling directory named 'lzispro'

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"   # whois repo root
cd "$ROOT_DIR"

# Tip: Versioning policy (>=3.2.6)
echo "[full_release] tip: simplified versioning active (no -dirty). For strict mode set WHOIS_STRICT_VERSION=1 or use VS Code task: Remote: Build (Strict Version)."

TAG=""
QUERIES="8.8.8.8"
RUN_SMOKE=1
LZISPRO_PATH=""
DRY_RUN=0
STRICT_WARN=1   # treat warnings as failure for step1 by default

die() { echo "[full_release][ERROR] $*" >&2; exit 2; }
log() { echo "[full_release] $*"; }

# Auto-detect sibling lzispro if not provided
auto_detect_lzispro() {
  local parent; parent="$(cd "$ROOT_DIR/.." && pwd)"
  if [[ -d "$parent/lzispro/.git" ]]; then
    LZISPRO_PATH="$(cd "$parent/lzispro" && pwd)"
  fi
}

next_tag() {
  local last; last="$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | sort -V | tail -n1)"
  if [[ -z "$last" ]]; then
    echo "v0.1.0"
    return
  fi
  local ver="${last#v}"; IFS='.' read -r MAJ MIN PAT <<<"$ver"
  PAT=$((PAT+1))
  echo "v${MAJ}.${MIN}.${PAT}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="${2:-}"; shift 2 ;;
    --queries) QUERIES="${2:-}"; shift 2 ;;
    --no-smoke) RUN_SMOKE=0; shift ;;
    --lzispro-path) LZISPRO_PATH="${2:-}"; shift 2 ;;
    --strict-warn) STRICT_WARN="${2:-1}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '1,60p' "$0" | sed -n '1,30p'; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ -z "$LZISPRO_PATH" ]] && auto_detect_lzispro
[[ -z "$LZISPRO_PATH" ]] && die "Cannot locate lzispro. Use --lzispro-path /d/xxx/lzispro"
[[ -d "$LZISPRO_PATH/.git" ]] || die "lzispro not a git repo: $LZISPRO_PATH"

SYNC_TO="$LZISPRO_PATH/release/lzispro/whois"
log "whois root: $ROOT_DIR"
log "lzispro path: $LZISPRO_PATH"
log "sync target: $SYNC_TO"

if [[ -z "$TAG" ]]; then TAG="$(next_tag)"; fi
log "target tag: $TAG"

if git rev-parse -q --verify "$TAG" >/dev/null 2>&1; then
  die "Tag already exists: $TAG"
fi

# Step 1: remote build + smoke + sync (best effort)
if (( RUN_SMOKE==0 )) && [[ -n "$QUERIES" ]]; then
  log "RUN_SMOKE=0: smoke tests disabled; --queries '$QUERIES' will be ignored."
fi
CMD1=("$ROOT_DIR/tools/remote/remote_build_and_test.sh" -q "$QUERIES" -r "$RUN_SMOKE" -s "$SYNC_TO" -P 1)
log "STEP1: ${CMD1[*]}"
if (( DRY_RUN==0 )); then
  stamp="$(date +%Y%m%d-%H%M%S)"
  LOG_DIR="$ROOT_DIR/out/release_flow/$stamp"; mkdir -p "$LOG_DIR"
  LOG1="$LOG_DIR/step1_remote.log"
  set +e
  "${CMD1[@]}" 2>&1 | tee "$LOG1"
  rc1=${PIPESTATUS[0]}
  set -e
  if (( rc1 != 0 )); then
    die "Step1 failed with exit code $rc1. See $LOG1"
  fi
  if (( STRICT_WARN==1 )); then
    if grep -Eiq "(\[WARN\]|\[ERROR\]|(^|[[:space:]])warning:)" "$LOG1"; then
      die "Warnings detected in step1 (STRICT_WARN=1). See $LOG1"
    fi
  fi
fi

# Copy latest synced static binaries back into whois repository (non-timestamped folder)
# so whois can keep a latest-artifact directory for CI to pick up.
LOCAL_WHOIS_ARTIFACTS="$ROOT_DIR/release/lzispro/whois"
log "Copying synced static binaries into whois local artifacts: $LOCAL_WHOIS_ARTIFACTS"
if (( DRY_RUN==0 )); then
  mkdir -p "$LOCAL_WHOIS_ARTIFACTS"
  # sync files from lzispro sync target to whois local artifacts (preserve names)
  # Use rsync if available, fallback to cp -a
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$SYNC_TO/" "$LOCAL_WHOIS_ARTIFACTS/" || true
  else
    # copy files individually
    rm -f "$LOCAL_WHOIS_ARTIFACTS"/* || true
    cp -a "$SYNC_TO"/* "$LOCAL_WHOIS_ARTIFACTS/" 2>/dev/null || true
  fi
fi

# Step 2: commit & push static bins in lzispro (已禁用自动提交/推送，避免误上传)
# log "STEP2: commit & push static bins in lzispro"
# if (( DRY_RUN==0 )); then
#   git -C "$LZISPRO_PATH" add release/lzispro/whois/whois-*
#   if ! git -C "$LZISPRO_PATH" diff --cached --quiet; then
#     git -C "$LZISPRO_PATH" commit -m "chore(whois): update 7 static binaries"
#     git -C "$LZISPRO_PATH" push origin master
#   else
#     log "No static binary changes to commit in lzispro."
#   fi
# fi

# Commit latest artifacts into whois repo so CI can use them (only if changed)
log "STEP2.1: commit latest artifacts into whois repo if changed"
if (( DRY_RUN==0 )); then
  # Ensure we add only the expected static binaries (7) to avoid noise
  git add -A "$LOCAL_WHOIS_ARTIFACTS" || true
  if ! git diff --cached --quiet; then
    git commit -m "chore(release): update latest static binaries"
    git push origin master
  else
    log "No whois-artifact changes to commit."
  fi
fi

# Step 3: commit updated RELEASE_NOTES.md in whois if changed
log "STEP3: commit whois RELEASE_NOTES.md if changed"
if (( DRY_RUN==0 )); then
  git add RELEASE_NOTES.md || true
  if ! git diff --cached --quiet; then
    git commit -m "docs(release): refresh notes"
    git push origin master
  else
    log "No release notes changes to commit."
  fi
fi

# Step 4: create & push tag to trigger GH release
log "STEP4: tag & push $TAG"
if (( DRY_RUN==0 )); then
  git tag -a "$TAG" -m "Release $TAG"
  git push origin "$TAG"
fi

log "Done. Monitor GitHub Actions for the release job of $TAG."
