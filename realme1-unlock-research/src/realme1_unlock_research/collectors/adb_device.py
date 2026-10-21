"""ADB device detection and enumeration collector."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from ..command_runner import SafeCommandRunner


def collect_adb_devices(runner: SafeCommandRunner) -> tuple[dict[str, Any], set[str]]:
    """Runs `adb devices -l` and parses connected devices.

    Returns structured results and a set of discovered raw serial numbers for redaction.
    """
    res = runner.run(["adb", "devices", "-l"])
    discovered_serials: set[str] = set()
    devices: list[dict[str, str]] = []

    if res.exit_code == 0:
        lines = res.stdout.strip().splitlines()
        # First line is typically "List of devices attached"
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) >= 2:
                raw_serial = parts[0]
                status = parts[1]
                details: dict[str, str] = {
                    "raw_serial": raw_serial,
                    "status": status,
                    "product": "",
                    "model": "",
                    "device": "",
                    "transport_id": "",
                }
                discovered_serials.add(raw_serial)

                for item in parts[2:]:
                    if ":" in item:
                        k, v = item.split(":", 1)
                        if k in details:
                            details[k] = v

                devices.append(details)

    data: dict[str, Any] = {
        "execution": {
            "start_time": res.start_time,
            "duration_seconds": res.duration_seconds,
            "exit_code": res.exit_code,
            "raw_output": res.stdout,
            "error": res.stderr,
        },
        "devices_count": len(devices),
        "devices": devices,
    }

    return data, discovered_serials
