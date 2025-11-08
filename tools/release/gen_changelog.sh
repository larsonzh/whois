#!/usr/bin/env bash
set -euo pipefail

# gen_changelog.sh - Generate Markdown changelog from last tag to HEAD.
# Usage: tools/release/gen_changelog.sh [prev_tag] [new_tag]

prev_tag=${1:-}
new_tag=${2:-}

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "[changelog] Not a git repository" >&2
  exit 1
fi

if [[ -z "$prev_tag" ]]; then
  prev_tag=$(git describe --tags --abbrev=0 2>/dev/null || true)
fi
if [[ -z "$prev_tag" ]]; then
  echo "[changelog] No previous tag; listing commits from initial" >&2
  range="--reverse $(git rev-list --max-parents=0 HEAD)..HEAD"
else
  range="$prev_tag..HEAD"
fi

if [[ -z "$new_tag" ]]; then
  new_tag=$(git describe --tags --always --dirty 2>/dev/null || echo "(unreleased)")
fi

echo "## Changelog: $prev_tag → $new_tag"
echo
git log --no-merges --pretty='- %s (%h) [%an]' $range || true

echo
echo "Generated on $(date -u +%F)"
