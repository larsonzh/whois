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

# Get release by tag; if missing, auto-create draft release
REL_JSON="$(api GET "https://api.github.com/repos/$OWNER/$REPO/releases/tags/$TAG" || true)"
if echo "$REL_JSON" | grep -q 'Not Found'; then
  echo "[info] Release for tag '$TAG' not found in $OWNER/$REPO. Attempting to create it ..." >&2
  # Build create payload (tag_name & name optional); default name falls back to tag
  if [[ -n "$NAME" ]]; then
    CREATE_DATA="$(jq -n --arg tag "$TAG" --arg name "$NAME" '{tag_name:$tag, name:$name, draft:false, prerelease:false}')"
  else
    CREATE_DATA="$(jq -n --arg tag "$TAG" '{tag_name:$tag, name:$tag, draft:false, prerelease:false}')"
  fi
  CREATE_TMP="$(mktemp 2>/dev/null || echo "/tmp/gh_release_create_$$.json")"
  printf '%s' "$CREATE_DATA" >"$CREATE_TMP"
  CREATE_RESP="$(api POST "https://api.github.com/repos/$OWNER/$REPO/releases" -H 'Content-Type: application/json; charset=utf-8' --data-binary @"$CREATE_TMP")"
  if echo "$CREATE_RESP" | grep -q 'Not Found'; then
    echo "[ERROR] Failed to create release (Not Found). Response:" >&2
    echo "$CREATE_RESP" >&2
    exit 1
  fi
  REL_JSON="$CREATE_RESP"
fi
REL_ID="$(echo "$REL_JSON" | jq -r '.id')"
if [[ -z "$REL_ID" || "$REL_ID" == "null" ]]; then
  echo "Failed to parse release id after create/fetch" >&2
  exit 1
fi

# Build JSON payload robustly via jq, reading body from file to avoid arg-length/escaping issues
if [[ -n "$NAME" ]]; then
  DATA="$(jq -n --rawfile body "$BODY_FILE" --arg name "$NAME" '{body: $body, name: $name}')"
else
  DATA="$(jq -n --rawfile body "$BODY_FILE" '{body: $body}')"
fi

# Write JSON payload to a temp file and send as binary to avoid quoting/CRLF issues on Windows
TMP_JSON="$(mktemp 2>/dev/null || echo "/tmp/gh_release_$$.json")"
printf '%s' "$DATA" >"$TMP_JSON"

# Sanity check JSON
if ! jq -e . <"$TMP_JSON" >/dev/null 2>&1; then
  echo "[ERROR] Generated JSON is invalid (jq parse failed). File: $TMP_JSON" >&2
  sed -n '1,50p' "$TMP_JSON" >&2
  exit 1
fi

# Perform PATCH with strict failure on non-2xx and echo response on error for diagnostics
HTTP_CODE=0
RESP="$(
  api PATCH "https://api.github.com/repos/$OWNER/$REPO/releases/$REL_ID" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data-binary @"$TMP_JSON" \
    -w "\n%{http_code}" 2>/dev/null
)"
HTTP_CODE="$(printf "%s" "$RESP" | tail -n1)"
BODY_OUT="$(printf "%s" "$RESP" | sed '$d')"
if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
  echo "[ERROR] PATCH failed (HTTP $HTTP_CODE). Response:" >&2
  echo "$BODY_OUT" >&2
  exit 1
fi

# Verify by re-fetching the release
NEW_JSON="$(api GET "https://api.github.com/repos/$OWNER/$REPO/releases/$REL_ID")"
NEW_NAME="$(echo "$NEW_JSON" | jq -r '.name')"
echo "Updated release $TAG in $OWNER/$REPO (name: $NEW_NAME)"
