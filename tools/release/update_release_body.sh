#!/usr/bin/env bash
set -euo pipefail

# Update the body (and optionally the name) of an existing GitHub Release by tag.
# Requires: curl, jq
# Usage:
#   GH_TOKEN=... tools/release/update_release_body.sh <owner> <repo> <tag> <body.md> [release-name]

if [[ $# -lt 4 ]]; then
  echo "Usage: GH_TOKEN=... $0 <owner> <repo> <tag> <body.md> [release-name]" >&2
  exit 2
fi

OWNER="$1"; shift
REPO="$1"; shift
TAG="$1"; shift
BODY_FILE="$1"; shift
NAME="${1:-}"

if [[ ! -f "$BODY_FILE" ]]; then
  echo "Body file not found: $BODY_FILE" >&2
  exit 2
fi

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

# Get release by tag
REL_JSON="$(api GET "https://api.github.com/repos/$OWNER/$REPO/releases/tags/$TAG")"
if echo "$REL_JSON" | grep -q 'Not Found'; then
  echo "Release for tag '$TAG' not found in $OWNER/$REPO" >&2
  exit 1
fi
REL_ID="$(echo "$REL_JSON" | jq -r '.id')"
if [[ -z "$REL_ID" || "$REL_ID" == "null" ]]; then
  echo "Failed to parse release id" >&2
  exit 1
fi

BODY_JSON="$(jq -Rs . < "$BODY_FILE")"
if [[ -n "$NAME" ]]; then
  NAME_JSON="$(jq -Rn --arg n "$NAME" '$n')"
  DATA="{\"body\": $BODY_JSON, \"name\": $NAME_JSON}"
else
  DATA="{\"body\": $BODY_JSON}"
fi

api PATCH "https://api.github.com/repos/$OWNER/$REPO/releases/$REL_ID" \
  -H 'Content-Type: application/json' \
  --data "$DATA" >/dev/null

echo "Updated release $TAG in $OWNER/$REPO"
