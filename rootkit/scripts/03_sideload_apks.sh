#!/usr/bin/env bash
# 03_sideload_apks.sh - Sideload root-related APKs to CPH1859 via ADB
# Installs Magisk Manager (root manager, NOT root itself).
# NOTE: On a stock locked-bootloader device, installing the APK does NOT grant root.
# It is a prerequisite only — root requires a patched boot image with magiskd.
set -euo pipefail

ROOTKIT_DIR="/home/ameya/Realme1/CPH1859/rootkit"
MAGISK_APK="$ROOTKIT_DIR/magisk/Magisk-v31.1.apk"
LOG="$ROOTKIT_DIR/scripts/sideload.log"

echo "============================================================"
echo "  CPH1859 APK Sideload (Magisk Manager v31.1)"
echo "  $(date)"
echo "============================================================"

if [ ! -f "$MAGISK_APK" ]; then
    echo "ERROR: Magisk APK not found at $MAGISK_APK"
    exit 1
fi

echo ""
echo "[1/3] Verifying device is online via ADB..."
adb get-state 2>&1 | tee -a "$LOG"

echo ""
echo "[2/3] Installing Magisk Manager APK..."
adb install -r "$MAGISK_APK" 2>&1 | tee -a "$LOG"

echo ""
echo "[3/3] Confirming installation..."
adb shell pm list packages | grep -i magisk 2>&1 | tee -a "$LOG" || echo "  (Magisk package not found — install may have failed)"

echo ""
echo "============================================================"
echo "  IMPORTANT: Magisk Manager is now installed (if success above),"
echo "  but it does NOT provide root by itself. Root requires the"
echo "  Magisk daemon (magiskd) running as root, which requires a"
echo "  patched boot image — impossible with locked bootloader + DAA."
echo "============================================================"
