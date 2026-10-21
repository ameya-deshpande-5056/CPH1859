"""USB subsystem scanner and MediaTek / OPPO device identifier collector."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..command_runner import SafeCommandRunner

LSUSB_REGEX = re.compile(r"^Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s+(.*)$")

KNOWN_DEVICE_PROFILES = {
    ("22d9", "2769"): "OPPO / Realme Android Normal Mode (CPH1859)",
    ("22d9", "2765"): "OPPO / Realme Fastboot Mode",
    ("22d9", "2764"): "OPPO / Realme Recovery Mode",
    ("0e8d", "0003"): "MediaTek BootROM (BROM) Mode",
    ("0e8d", "2000"): "MediaTek Preloader USB VCOM Port",
    ("0e8d", "2001"): "MediaTek DA USB VCOM Port",
    ("18d1", "4ee0"): "Google / AOSP ADB Mode",
    ("18d1", "4ee7"): "Google / AOSP Fastboot Mode",
    ("18d1", "d00d"): "Google / AOSP Fastboot / Bootloader Mode",
}


def collect_usb_devices(runner: SafeCommandRunner) -> dict[str, Any]:
    """Runs `lsusb` and analyzes connected devices against known MediaTek/OPPO IDs."""
    res = runner.run(["lsusb"])
    devices: list[dict[str, str]] = []
    matched_profiles: list[dict[str, str]] = []

    if res.exit_code == 0:
        for line in res.stdout.splitlines():
            line = line.strip()
            match = LSUSB_REGEX.match(line)
            if match:
                bus, dev, vid, pid, desc = (
                    match.group(1),
                    match.group(2),
                    match.group(3).lower(),
                    match.group(4).lower(),
                    match.group(5),
                )
                device_info = {
                    "bus": bus,
                    "device": dev,
                    "vendor_id": vid,
                    "product_id": pid,
                    "description": desc,
                }
                devices.append(device_info)

                key = (vid, pid)
                if key in KNOWN_DEVICE_PROFILES:
                    matched_profiles.append({
                        "vendor_id": vid,
                        "product_id": pid,
                        "description": desc,
                        "profile_name": KNOWN_DEVICE_PROFILES[key],
                    })

    data: dict[str, Any] = {
        "execution": {
            "start_time": res.start_time,
            "duration_seconds": res.duration_seconds,
            "exit_code": res.exit_code,
            "error": res.stderr,
        },
        "total_usb_devices": len(devices),
        "devices": devices,
        "matched_special_devices": matched_profiles,
        "is_mtk_brom_detected": any(p["vendor_id"] == "0e8d" and p["product_id"] == "0003" for p in matched_profiles),
        "is_mtk_preloader_detected": any(p["vendor_id"] == "0e8d" and p["product_id"] == "2000" for p in matched_profiles),
        "is_oppo_normal_detected": any(p["vendor_id"] == "22d9" and p["product_id"] == "2769" for p in matched_profiles),
        "is_fastboot_usb_detected": any(
            p["profile_name"].endswith("Fastboot Mode") or p["profile_name"].endswith("Bootloader Mode")
            for p in matched_profiles
        ),
    }

    return data
