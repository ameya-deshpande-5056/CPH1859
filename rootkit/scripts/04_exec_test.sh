#!/usr/bin/env bash
# 04_exec_test.sh - Test code execution from /data/local/tmp (shell context only)
# Pushes a small native test binary and attempts to execute it.
# This confirms whether we can run arbitrary code as shell (uid 2000),
# but does NOT escalate to root.
set -euo pipefail

ROOTKIT_DIR="/home/ameya/Realme1/CPH1859/rootkit"
LOG="$ROOTKIT_DIR/scripts/exec_test.log"

echo "============================================================"
echo "  CPH1859 Code Execution Test (shell context, uid 2000)"
echo "  $(date)"
echo "============================================================"

echo ""
echo "[1/3] Creating test binary source..."
TMPDIR=$(mktemp -d)
cat > "$TMPDIR/testroot.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main(void) {
    printf("uid=%d euid=%d gid=%d\n", getuid(), geteuid(), getgid());
    printf("Hello from CPH1859 shell context\n");
    return 0;
}
EOF

echo ""
echo "[2/3] Compiling for device (host x86_64 -> check if cross-compiler available)..."
if command -v aarch64-linux-android-gcc >/dev/null 2>&1; then
    aarch64-linux-android-gcc -static -o "$TMPDIR/testroot" "$TMPDIR/testroot.c" 2>&1
    echo "  Compiled with aarch64-linux-android-gcc"
elif command -v gcc >/dev/null 2>&1; then
    echo "  WARN: No Android NDK cross-compiler; host gcc binary won't run on device."
    echo "  Skipping push (would fail to execute)."
    rm -rf "$TMPDIR"
    exit 0
else
    echo "  No compiler available. Skipping."
    rm -rf "$TMPDIR"
    exit 0
fi

echo ""
echo "[3/3] Pushing and executing on device (as shell user)..."
adb push "$TMPDIR/testroot" /data/local/tmp/testroot 2>&1 | tee -a "$LOG"
adb shell "chmod 755 /data/local/tmp/testroot && /data/local/tmp/testroot" 2>&1 | tee -a "$LOG"

echo ""
echo "============================================================"
echo "  Result: Code executes as shell (uid 2000), NOT root."
echo "  To get root we need a privilege escalation exploit or"
echo "  a patched boot image — neither is currently available."
echo "============================================================"

rm -rf "$TMPDIR"
