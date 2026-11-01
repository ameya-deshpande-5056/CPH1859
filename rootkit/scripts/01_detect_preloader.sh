#!/usr/bin/env bash
# 01_detect_preloader.sh - Detect Realme 1 (CPH1859) in MediaTek preloader/BROM mode
# Non-destructive detection only. No writes to device.
set -euo pipefail

ROOTKIT_DIR="/home/ameya/Realme1/CPH1859/rootkit"
MTKCLIENT="/home/ameya/mtkclient/mtk.py"
LOG="$ROOTKIT_DIR/scripts/detect.log"

echo "============================================================"
echo "  CPH1859 Preloader/BROM Detection"
echo "  $(date)"
echo "============================================================"

echo ""
echo "[1/3] Checking host USB device enumeration (normal ADB mode)..."
adb devices -l 2>&1 | tee -a "$LOG"

echo ""
echo "[2/3] Scanning lsusb for MediaTek / OPPO VIDs..."
lsusb 2>&1 | grep -iE '22d9|0e8d|mediatek|oppo|realme' | tee -a "$LOG" || echo "  (no MediaTek/OPPO USB device seen in current mode)"

echo ""
echo "[3/3] Checking mtkclient readiness..."
if [ -f "$MTKCLIENT" ]; then
    echo "  mtkclient found: $MTKCLIENT"
    python3 "$MTKCLIENT" --help >/dev/null 2>&1 && echo "  mtkclient imports OK" || echo "  mtkclient import issue"
else
    echo "  ERROR: mtkclient not found at $MTKCLIENT"
    exit 1
fi

echo ""
echo "============================================================"
echo "  NEXT STEP (manual): Reboot device into preloader mode"
echo "============================================================"
echo ""
echo "To enter MediaTek preloader mode on CPH1859 (MT6771):"
echo "  1. Power OFF the device completely."
echo "  2. Press and hold VOLUME DOWN + POWER (or VOLUME UP) together."
echo "  3. While holding, connect the USB cable to the PC."
echo "  4. Keep holding until the PC detects a new USB device, then release."
echo "  5. The device screen may stay black (expected in preloader)."
echo ""
echo "Then re-run this script to confirm detection, or run:"
echo "  lsusb | grep 22d9"
echo "  python3 /home/ameya/mtkclient/mtk.py printgpt"
echo ""
echo "NOTE: Prior research shows this MT6771 build enforces DAA signature"
echo "      verification on DA upload, but plain partition READ operations"
echo "      may still be possible in preloader mode without DA."
echo ""
