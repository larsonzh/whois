#!/usr/bin/env bash
set -euo pipefail
# Upload files to an existing GitHub Release by tag.
# Usage:
#   GH_TOKEN=... ./tools/release/upload_assets.sh <owner> <repo> <tag> <file> [more files...]
#
# Notes:
# - Requires curl. Tries to avoid jq dependency by using grep/sed.
# - If an asset with the same name exists, it will be deleted then re-uploaded.

if [[ $# -lt 4 ]]; then
  echo "Usage: GH_TOKEN=... $0 <owner> <repo> <tag> <file>..." >&2
  exit 2
fi

OWNER="$1"; shift
REPO="$1"; shift
TAG="$1"; shift

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -z "$TOKEN" ]]; then
  echo "GH_TOKEN/GITHUB_TOKEN is required" >&2
  exit 2
fi

api() {
  local method="$1"; shift
  local url="$1"; shift
  curl -sS -X "$method" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "$url" "$@"
}

# Get release info by tag
REL_JSON="$(api GET "https://api.github.com/repos/$OWNER/$REPO/releases/tags/$TAG")"
if echo "$REL_JSON" | grep -q 'Not Found'; then
  echo "Release for tag '$TAG' not found in $OWNER/$REPO" >&2
  exit 1
fi

UPLOAD_URL_BASE="$(echo "$REL_JSON" | grep -o '"upload_url"[^\n]*' | sed -E 's/.*"upload_url"\s*:\s*"([^"]+)".*/\1/' | sed 's/{?name,label}//')"
ASSETS_URL="$(echo "$REL_JSON" | grep -o '"assets_url"[^\n]*' | sed -E 's/.*"assets_url"\s*:\s*"([^"]+)".*/\1/')"

# List existing assets and map name->id
EXISTING="$(api GET "$ASSETS_URL")"
asset_id_by_name() {
  local name="$1"
  # crude extraction of id by name
  echo "$EXISTING" | awk -v n="$name" '
    $0 ~ /"id":/ { id=$2 }
    $0 ~ /"name":/ { gsub(/[",]/, ""); nm=$2; if(nm==n){ print id; exit } }
  '
}

for f in "$@"; do
  if [[ ! -f "$f" ]]; then
    echo "Skip missing: $f" >&2
    continue
  fi
  base="$(basename "$f")"
  # delete existing asset with same name
  aid="$(asset_id_by_name "$base" || true)"
  if [[ -n "${aid:-}" ]]; then
    api DELETE "https://api.github.com/repos/$OWNER/$REPO/releases/assets/$aid" >/dev/null || true
  fi
  # upload
  echo "Uploading $base ..."
  curl -sS -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @"$f" \
    "$UPLOAD_URL_BASE?name=$base" >/dev/null
  echo "Uploaded: $base"
done

echo "Done"
