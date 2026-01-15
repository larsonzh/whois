#!/usr/bin/env bash
set -euo pipefail

# Update the body (and optionally the name) of an existing Gitee Release by tag.
# Note: If the body contains static binary links, ensure they include
#       whois-win64.exe / whois-win32.exe and run the link conversion scripts as needed.
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

# Get release by tag; if missing (error message), attempt to create it
REL_JSON="$(api GET "$API_ROOT/repos/$OWNER/$REPO/releases/tags/$TAG?access_token=$TOKEN" || true)"
if echo "$REL_JSON" | grep -q 'message'; then
  echo "[info] Release for tag '$TAG' not found on Gitee. Attempting to create..." >&2
  EFF_NAME_CREATE="$NAME"; [[ -z "$EFF_NAME_CREATE" ]] && EFF_NAME_CREATE="$TAG"
  # Use form-encoded creation (per Gitee API behavior)
  CREATE_RESP="$(
    curl -sS -X POST \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
      --data-urlencode "tag_name=$TAG" \
      --data-urlencode "name=$EFF_NAME_CREATE" \
      --data-urlencode "body=Initial placeholder." \
      "$API_ROOT/repos/$OWNER/$REPO/releases?access_token=$TOKEN"
  )" || true
  if echo "$CREATE_RESP" | grep -q 'message'; then
    echo "[ERROR] Failed to create Gitee release for tag '$TAG'. Response:" >&2
    echo "$CREATE_RESP" >&2
    exit 1
  fi
  # After creation, re-fetch by tag; Gitee may have eventual consistency
  sleep 1
  REL_JSON="$(api GET "$API_ROOT/repos/$OWNER/$REPO/releases/tags/$TAG?access_token=$TOKEN" || true)"
fi
REL_ID="$(echo "$REL_JSON" | jq -r '.id')"
if [[ -z "$REL_ID" || "$REL_ID" == "null" ]]; then
  # Fallback: list releases and match by tag_name
  LIST_JSON="$(api GET "$API_ROOT/repos/$OWNER/$REPO/releases?access_token=$TOKEN&per_page=100" || true)"
  REL_ID="$(echo "$LIST_JSON" | jq -r ".[] | select(.tag_name == \"$TAG\") | .id" | head -n1)"
fi
if [[ -z "$REL_ID" || "$REL_ID" == "null" ]]; then
  echo "[WARN] Failed to locate Gitee release id for tag '$TAG'." >&2
  echo "[DEBUG] GET by tag response (truncated):" >&2
  echo "$REL_JSON" | sed -n '1,120p' >&2
  echo "[DEBUG] List releases response (truncated):" >&2
  echo "$LIST_JSON" | sed -n '1,120p' >&2
  echo "[WARN] Skipping Gitee release update (non-fatal)." >&2
  exit 0
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
