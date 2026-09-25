#!/usr/bin/env bash
# SBOMBox — simple SBOM + vulnerability scan wrapper.
#
# Usage:
#   ./scan.sh                          # current directory
#   ./scan.sh "/path/to/your-project"  # specific project
#   ./scan.sh --with-nvd .             # include NVD enrichment (slower)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER="$SCRIPT_DIR/scripts/sbom_scan.py"

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
  # Without an API key NVD waits ~6s per CVE — skip by default for speed.
  EXTRA+=(--no-nvd)
  echo "NVD: disabled (fast mode). Pass --with-nvd or export NVD_API_KEY to enable."
fi

python3 "$SCANNER" "$TARGET" -o "$OUT" "${EXTRA[@]}"
echo ""
echo "Report: $OUT/vuln-report.md"
echo "SBOM:   $OUT/sbom.cdx.json"
