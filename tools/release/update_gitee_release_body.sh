#!/usr/bin/env bash
set -euo pipefail

# Update the body (and optionally the name) of an existing Gitee Release by tag.
# Requires: curl, jq
# Usage:
#   GITEE_TOKEN=... tools/release/update_gitee_release_body.sh <owner> <repo> <tag> <body.md> [release-name]
# API docs: https://gitee.com/api/v5/swagger

if [[ $# -lt 4 ]]; then
  echo "Usage: GITEE_TOKEN=... $0 <owner> <repo> <tag> <body.md> [release-name]" >&2
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

TOKEN="${GITEE_TOKEN:-}"
if [[ -z "$TOKEN" ]]; then
  echo "GITEE_TOKEN is required" >&2
  exit 2
fi

API_ROOT="https://gitee.com/api/v5"

api() {
  local method="$1"; shift
  local url="$1"; shift
  curl -sS -X "$method" \
    -H "Accept: application/json" \
    "$url" "$@"
}

# Get release by tag
REL_JSON="$(api GET "$API_ROOT/repos/$OWNER/$REPO/releases/tags/$TAG?access_token=$TOKEN")"
if echo "$REL_JSON" | grep -q 'message'; then
  echo "[ERROR] Failed to get release by tag: $TAG" >&2
  echo "$REL_JSON" >&2
  exit 1
fi
REL_ID="$(echo "$REL_JSON" | jq -r '.id')"
if [[ -z "$REL_ID" || "$REL_ID" == "null" ]]; then
  echo "[ERROR] Failed to parse release id" >&2
  echo "$REL_JSON" >&2
  exit 1
fi

EFF_NAME="$NAME"
if [[ -z "$EFF_NAME" ]]; then EFF_NAME="$TAG"; fi

# Try JSON PATCH first (more reliable for name), fallback to form-encoded
tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir" 2>/dev/null || true; }
trap cleanup EXIT

payload_json="$tmpdir/payload.json"
jq -n --arg tag "$TAG" --arg name "$EFF_NAME" --rawfile body "$BODY_FILE" '{tag_name:$tag,name:$name,body:$body}' > "$payload_json"

RESP="$(
  curl -sS -X PATCH \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    --data-binary @"$payload_json" \
    "$API_ROOT/repos/$OWNER/$REPO/releases/$REL_ID?access_token=$TOKEN" \
    -w "\n%{http_code}"
)" || true
HTTP_CODE="$(printf "%s" "$RESP" | tail -n1)"
BODY_OUT="$(printf "%s" "$RESP" | sed '$d')"

if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
  # Fallback: form-encoded
  RESP="$(
    curl -sS -X PATCH \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
      --data-urlencode "tag_name=$TAG" \
      --data-urlencode "name=$EFF_NAME" \
      --data-urlencode "body@${BODY_FILE}" \
      "$API_ROOT/repos/$OWNER/$REPO/releases/$REL_ID?access_token=$TOKEN" \
      -w "\n%{http_code}"
  )"
  HTTP_CODE="$(printf "%s" "$RESP" | tail -n1)"
  BODY_OUT="$(printf "%s" "$RESP" | sed '$d')"
  if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
    echo "[ERROR] PATCH failed (HTTP $HTTP_CODE). Response:" >&2
    echo "$BODY_OUT" >&2
    exit 1
  fi
fi

# Verify by re-fetching
NEW_JSON="$(api GET "$API_ROOT/repos/$OWNER/$REPO/releases/$REL_ID?access_token=$TOKEN")"
NEW_NAME="$(echo "$NEW_JSON" | jq -r '.name')"
# Always inject a visible title into body so Gitee UI shows the desired name, regardless of API name behavior
combined="$tmpdir/combined_body.md"
{ printf "# %s\n\n" "$EFF_NAME"; cat "$BODY_FILE"; } > "$combined"
# URL-encode body via jq to avoid curl @file issues on Windows/Git Bash
BODY_ENC="$(jq -rRs @uri < "$combined")"
curl -sS -X PATCH \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data "body=$BODY_ENC" \
  "$API_ROOT/repos/$OWNER/$REPO/releases/$REL_ID?access_token=$TOKEN" >/dev/null
echo "Updated Gitee release $TAG in $OWNER/$REPO (api name: $NEW_NAME, title injected in body: $EFF_NAME)"
