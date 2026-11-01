#!/usr/bin/env bash
# 05_final_assessment.sh - Generate final rooting assessment report for CPH1859
set -euo pipefail

ROOTKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "============================================================"
echo "  CPH1859 Final Root & Vulnerability Assessment Generator"
echo "============================================================"

echo ""
echo "[1/3] Generating base root assessment report..."
python3 "$ROOTKIT_DIR/scripts/gen_report.py"

echo ""
echo "[2/3] Appending CVE-2026-43499 (GhostLock) addendum..."
python3 "$ROOTKIT_DIR/scripts/append_addendum.py"

echo ""
echo "[3/3] Generating standalone CVE-2026-43499 feasibility study..."
python3 "$ROOTKIT_DIR/scripts/gen_cve_report.py"

echo ""
echo "============================================================"
echo "Reports generated successfully:"
echo "  - $ROOTKIT_DIR/FINAL_ROOT_ASSESSMENT.md"
echo "  - $ROOTKIT_DIR/CVE_2026_43499_FEASIBILITY.md"
echo "============================================================"
