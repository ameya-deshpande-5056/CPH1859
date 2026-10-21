"""Host environment diagnostic collector."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Any, Dict

from ..command_runner import SafeCommandRunner


def collect_host_environment(runner: SafeCommandRunner) -> dict[str, Any]:
    """Collects information about the host operating system, platform tools, and Python runtime."""
    data: dict[str, Any] = {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "tools": {},
        "udev_rules": {},
    }

    # Verify tool binaries
    tools = ["adb", "fastboot", "lsusb", "udevadm"]
    for tool in tools:
        path = shutil.which(tool)
        version_str = "unknown"
        if path:
            if tool in ("adb", "fastboot"):
                res = runner.run([tool, "--version"])
                if res.exit_code == 0:
                    version_str = res.stdout.strip().split("\n")[0]
            elif tool == "lsusb":
                version_str = "installed"
            elif tool == "udevadm":
                res = runner.run(["udevadm", "--version"])
                if res.exit_code == 0:
                    version_str = res.stdout.strip()
        data["tools"][tool] = {
            "found": path is not None,
            "path": path,
            "version": version_str,
        }

    # Check for common Android / MTK udev rules
    udev_paths = [
        "/etc/udev/rules.d/51-android.rules",
        "/etc/udev/rules.d/99-mtk.rules",
        "/lib/udev/rules.d/51-android.rules",
    ]
    for up in udev_paths:
        data["udev_rules"][up] = os.path.exists(up)

    return data

