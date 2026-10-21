"""USB event monitor for capturing hardware attach/detach events."""

from __future__ import annotations

import datetime
import re
import subprocess
import time
from typing import Any, Dict, List

from ..command_runner import SafeCommandRunner

UDEV_ACTION_REGEX = re.compile(r"^(add|remove|change|bind|unbind)\s+(.+?)\s+\(usb\)$", re.IGNORECASE)


def monitor_usb_events(runner: SafeCommandRunner, duration_seconds: float = 5.0) -> dict[str, Any]:
    """Monitors USB subsystem events for a fixed duration.

    Uses `udevadm monitor --subsystem-match=usb --property` or periodic sampling.
    """
    tz = datetime.datetime.now().astimezone().tzinfo
    start_time = datetime.datetime.now(tz).isoformat()
    events: list[dict[str, str]] = []

    # Attempt udevadm monitor
    cmd = ["udevadm", "monitor", "--subsystem-match=usb", "--environment"]
    try:
        runner.validate_safety(cmd)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        time.sleep(duration_seconds)
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()

        # Parse captured udevadm events
        current_event: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current_event:
                    events.append(current_event)
                    current_event = {}
                continue

            if "=" in line:
                k, v = line.split("=", 1)
                current_event[k] = v
            else:
                match = UDEV_ACTION_REGEX.match(line)
                if match:
                    current_event["ACTION"] = match.group(1).upper()
                    current_event["DEVPATH"] = match.group(2)

        if current_event:
            events.append(current_event)

    except Exception as e:
        events.append({"error": f"udevadm monitor failed or unsupported: {e}"})

    end_time = datetime.datetime.now(tz).isoformat()

    return {
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": duration_seconds,
        "events_captured_count": len(events),
        "events": events,
    }

