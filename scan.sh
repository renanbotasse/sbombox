#!/usr/bin/env bash
# sBOMBox — simple SBOM + vulnerability scan wrapper.
#
# Usage:
#   ./scan.sh                          # current directory
#   ./scan.sh "/path/to/your-project"  # specific project
#   ./scan.sh --with-nvd .             # include NVD enrichment (slower)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load local secrets if present (never commit .env)
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/.env"
  set +a
fi

WITH_NVD=0
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--with-nvd" ]]; then
    WITH_NVD=1
  else
    ARGS+=("$arg")
  fi
done

TARGET="${ARGS[0]:-.}"
OUT="$TARGET/sbom-report"

EXTRA=()
if [[ "$WITH_NVD" -eq 1 ]] || [[ -n "${NVD_API_KEY:-}" ]]; then
  echo "NVD: enabled${NVD_API_KEY:+ (API key detected)}"
else
  EXTRA+=(--no-nvd)
  echo "NVD: disabled (fast mode). Pass --with-nvd or export NVD_API_KEY to enable."
fi

PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m sbombox "$TARGET" -o "$OUT" "${EXTRA[@]}"
echo ""
echo "Report: $OUT/sbom-report.md"
echo "SBOM:   $OUT/sbom.cdx.json"
