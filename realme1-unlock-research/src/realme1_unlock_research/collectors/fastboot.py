"""Fastboot connectivity and device state collector."""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from ..command_runner import SafeCommandRunner


def collect_fastboot_devices(runner: SafeCommandRunner) -> tuple[dict[str, Any], set[str]]:
    """Runs `fastboot devices` safely to determine if any device is currently in Fastboot mode.

    Returns structured results and any discovered serial numbers for redaction.
    """
    res = runner.run(["fastboot", "devices"], timeout_seconds=5.0)
    discovered_serials: set[str] = set()
    devices: list[dict[str, str]] = []

    if res.exit_code == 0:
        lines = res.stdout.strip().splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]
                discovered_serials.add(serial)
                devices.append({
                    "raw_serial": serial,
                    "status": status,
                })

    data: dict[str, Any] = {
        "execution": {
            "start_time": res.start_time,
            "duration_seconds": res.duration_seconds,
            "exit_code": res.exit_code,
            "error": res.stderr,
        },
        "devices_count": len(devices),
        "devices": devices,
        "is_fastboot_active": len(devices) > 0,
    }

    return data, discovered_serials

