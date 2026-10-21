"""Android system and boot properties collector."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from ..command_runner import SafeCommandRunner

PROP_REGEX = re.compile(r"^\[(.*?)\]:\s*\[(.*?)\]$")

CRITICAL_PROPERTIES = [
    "ro.product.model",
    "ro.product.name",
    "ro.product.device",
    "ro.product.brand",
    "ro.product.manufacturer",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.display.id",
    "ro.build.fingerprint",
    "ro.build.date",
    "ro.build.date.utc",
    "ro.build.type",
    "ro.boot.hardware",
    "ro.boot.bootloader",
    "ro.bootloader",
    "ro.bootmode",
    "ro.boot.mode",
    "ro.boot.flash.locked",
    "ro.oem_unlock_supported",
    "sys.oem_unlock_allowed",
    "ro.boot.verifiedbootstate",
    "ro.boot.veritymode",
    "ro.boot.vbmeta.device_state",
    "ro.boot.serialno",
    "ro.serialno",
    "ro.board.platform",
    "ro.mediatek.version.release",
    "ro.mediatek.platform",
    "ro.crypto.state",
    "ro.crypto.type",
]


def collect_android_properties(runner: SafeCommandRunner) -> tuple[dict[str, Any], set[str]]:
    """Executes `adb shell getprop`, extracts properties, and finds any serial numbers."""
    res = runner.run(["adb", "shell", "getprop"])
    discovered_serials: set[str] = set()
    all_props: dict[str, str] = {}
    critical_props: dict[str, str] = {}

    if res.exit_code == 0:
        for line in res.stdout.splitlines():
            line = line.strip()
            match = PROP_REGEX.match(line)
            if match:
                k, v = match.group(1), match.group(2)
                all_props[k] = v
                if "serial" in k.lower() and v and len(v) >= 4 and v.lower() not in {"unknown", "none", "null"}:
                    discovered_serials.add(v)

        for prop_name in CRITICAL_PROPERTIES:
            critical_props[prop_name] = all_props.get(prop_name, "NOT_FOUND")

    # Analyze unlock & security posture
    security_posture = {
        "flash_locked": critical_props.get("ro.boot.flash.locked", "unknown"),
        "oem_unlock_supported": critical_props.get("ro.oem_unlock_supported", "unknown"),
        "oem_unlock_allowed": critical_props.get("sys.oem_unlock_allowed", "unknown"),
        "verified_boot_state": critical_props.get("ro.boot.verifiedbootstate", "unknown"),
        "verity_mode": critical_props.get("ro.boot.veritymode", "unknown"),
        "platform": critical_props.get("ro.board.platform", critical_props.get("ro.boot.hardware", "unknown")),
        "build_id": critical_props.get("ro.build.display.id", "unknown"),
    }

    data: dict[str, Any] = {
        "execution": {
            "start_time": res.start_time,
            "duration_seconds": res.duration_seconds,
            "exit_code": res.exit_code,
            "error": res.stderr,
        },
        "critical_properties": critical_props,
        "security_posture": security_posture,
        "total_properties_count": len(all_props),
    }

    return data, discovered_serials
