#!/usr/bin/env bash
set -euo pipefail

# normalize_eol.sh - Convert CRLF to LF for repo text files.
# Usage: ./tools/dev/normalize_eol.sh [--dry-run]

DRY=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY=1
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

echo "[normalize] repo root: $root"

# File globs considered text (extend as needed)
globs=("*.c" "*.h" "*.sh" "*.ps1" "*.md" "*.txt" "Makefile" "*.yml" "*.yaml" "*.json")

count=0
for g in "${globs[@]}"; do
  while IFS= read -r -d '' f; do
    # Skip binary-like large files >2MB to avoid accidental damage
    if [[ $(stat -c %s "$f") -gt 2000000 ]]; then
      echo "[normalize][skip] large file: $f"; continue;
    fi
    if file "$f" | grep -qi 'CRLF'; then
      echo "[normalize] CRLF -> LF: $f"
      if [[ $DRY -eq 0 ]]; then
        # Use sed to replace CRLF; ensure final newline
        tmp="$f.tmp.__normalize__"
        sed -e 's/
$//' "$f" > "$tmp"
        mv "$tmp" "$f"
      fi
      ((count++))
    fi
  done < <(find . -type f -name "$g" -print0 2>/dev/null)
done

echo "[normalize] processed $count files (dry-run=$DRY)"

exit 0
