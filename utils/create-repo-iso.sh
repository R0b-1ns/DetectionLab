#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT_PATH="${1:-$REPO_ROOT/Detectionlab.iso}"
LABEL="${2:-DETECTIONLAB}"

EXCLUDES=(
  "docs/*"
  "utils/*"
)

if command -v xorriso >/dev/null 2>&1; then
  xorriso -as mkisofs -r -J -o "$OUTPUT_PATH" -V "$LABEL" \
    -m "${EXCLUDES[0]}" -m "${EXCLUDES[1]}" \
    "$REPO_ROOT"
elif command -v genisoimage >/dev/null 2>&1; then
  genisoimage -r -J -o "$OUTPUT_PATH" -V "$LABEL" \
    -m "${EXCLUDES[0]}" -m "${EXCLUDES[1]}" \
    "$REPO_ROOT"
elif command -v mkisofs >/dev/null 2>&1; then
  mkisofs -r -J -o "$OUTPUT_PATH" -V "$LABEL" \
    -m "${EXCLUDES[0]}" -m "${EXCLUDES[1]}" \
    "$REPO_ROOT"
else
  echo "[ERROR] Missing ISO tool (xorriso, genisoimage, or mkisofs)." >&2
  exit 1
fi

echo "[OK] ISO created at $OUTPUT_PATH"
