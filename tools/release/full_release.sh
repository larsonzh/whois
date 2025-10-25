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
#                                 [--lzispro-path /d/xxx/lzispro] [--dry-run]
#
# Defaults:
# - If --tag is omitted, auto bump the latest vX.Y.Z tag's patch number (vA.B.(C+1))
# - Smoke tests enabled by default (-r 1)
# - queries default to "8.8.8.8"
# - lzispro-path auto-detected as a sibling directory named 'lzispro'

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"   # whois repo root
cd "$ROOT_DIR"

TAG=""
QUERIES="8.8.8.8"
RUN_SMOKE=1
LZISPRO_PATH=""
DRY_RUN=0

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
CMD1=("$ROOT_DIR/tools/remote/remote_build_and_test.sh" -q "$QUERIES" -r "$RUN_SMOKE" -s "$SYNC_TO" -P 1)
log "STEP1: ${CMD1[*]}"
if (( DRY_RUN==0 )); then
  "${CMD1[@]}"
fi

# Step 2: commit & push static bins in lzispro
log "STEP2: commit & push static bins in lzispro"
if (( DRY_RUN==0 )); then
  git -C "$LZISPRO_PATH" add release/lzispro/whois/whois-*
  if ! git -C "$LZISPRO_PATH" diff --cached --quiet; then
    git -C "$LZISPRO_PATH" commit -m "chore(whois): update 7 static binaries"
    git -C "$LZISPRO_PATH" push origin master
  else
    log "No static binary changes to commit."
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
