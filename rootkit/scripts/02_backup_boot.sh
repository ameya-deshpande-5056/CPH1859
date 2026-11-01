#!/usr/bin/env bash
# 02_backup_boot.sh - Back up CPH1859 boot partition via mtkclient (preloader mode)
# NON-DESTRUCTIVE: reads only. Writes backup file to host.
# Usage: ./02_backup_boot.sh   (device must be in preloader mode)
set -euo pipefail

ROOTKIT_DIR="/home/ameya/Realme1/CPH1859/rootkit"
BACKUP_DIR="$ROOTKIT_DIR/backup"
MTKCLIENT="/home/ameya/mtkclient/mtk.py"
BOOT_PART="boot"
BOOT_IMG="$BACKUP_DIR/boot_cph1859_$(date +%Y%m%d_%H%M%S).img"
LOG="$ROOTKIT_DIR/scripts/backup.log"

mkdir -p "$BACKUP_DIR"

echo "============================================================"
echo "  CPH1859 Boot Partition Backup (preloader read-only)"
echo "  $(date)"
echo "============================================================"

echo ""
echo "[1/4] Verifying device is detectable in preloader/BROM mode..."
if ! lsusb 2>&1 | grep -q '22d9'; then
    echo "  ERROR: No MediaTek device (VID 22d9) detected via lsusb."
    echo "  Put device in preloader mode first (see 01_detect_preloader.sh)."
    exit 1
fi
lsusb 2>&1 | grep -iE '22d9|0e8d|mediatek' | tee -a "$LOG"

echo ""
echo "[2/4] Printing GPT table (confirm partition map readable)..."
python3 "$MTKCLIENT" printgpt 2>&1 | tee -a "$LOG" || true

echo ""
echo "[3/4] Reading boot partition to backup image..."
echo "  Output: $BOOT_IMG"
python3 "$MTKCLIENT" r "$BOOT_PART" "$BOOT_IMG" 2>&1 | tee -a "$LOG"

echo ""
echo "[4/4] Verifying backup file..."
if [ -f "$BOOT_IMG" ]; then
    SIZE=$(stat -c%s "$BOOT_IMG" 2>/dev/null || echo 0)
    echo "  Backup created: $BOOT_IMG ($SIZE bytes)"
    echo "  First bytes (magic check):"
    xxd -l 64 "$BOOT_IMG" 2>/dev/null || od -A x -t x1z -v -N 64 "$BOOT_IMG"
    # Android boot image magic: "ANDROID!"
    if head -c 8 "$BOOT_IMG" 2>/dev/null | grep -q 'ANDROID'; then
        echo "  VALID: boot image magic 'ANDROID!' detected."
    else
        echo "  WARN: 'ANDROID!' magic not found at offset 0 — may be empty/wrong partition."
    fi
else
    echo "  ERROR: backup file was not created."
    exit 1
fi

echo ""
echo "============================================================"
echo "  Backup complete. File: $BOOT_IMG"
echo "  Keep this file safe — it is your restore point."
echo "============================================================"
