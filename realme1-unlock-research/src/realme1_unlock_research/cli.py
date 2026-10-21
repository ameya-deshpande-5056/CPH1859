"""Main CLI entry point for the Realme 1 (CPH1859) diagnostic tool."""

from __future__ import annotations

import argparse
import datetime
import os
import sys
from typing import Any, Dict, List

from . import __version__
from .collectors.adb_device import collect_adb_devices
from .collectors.environment import collect_host_environment
from .collectors.fastboot import collect_fastboot_devices
from .collectors.packages import collect_testing_packages
from .collectors.properties import collect_android_properties
from .collectors.usb import collect_usb_devices
from .collectors.usb_monitor import monitor_usb_events
from .command_runner import SafeCommandRunner
from .redactor import SensitiveDataRedactor
from .reporter import DiagnosticReporter, DiagnosticTestResult


def run_diagnostics(
    include_usb_monitor: bool = False,
    monitor_duration: float = 3.0,
    known_serials: list[str] | None = None,
) -> tuple[dict[str, Any], DiagnosticReporter]:
    """Executes the full read-only diagnostic suite."""
    runner = SafeCommandRunner()
    redactor = SensitiveDataRedactor(set(known_serials or []))
    reporter = DiagnosticReporter(redactor)

    tz = datetime.datetime.now().astimezone().tzinfo
    session_start = datetime.datetime.now(tz).isoformat()

    tests: list[dict[str, Any]] = []

    # -------------------------------------------------------------
    # Test 1: Host Environment Verification
    # -------------------------------------------------------------
    env_data = collect_host_environment(runner)
    tools = env_data.get("tools", {})
    adb_ok = tools.get("adb", {}).get("found", False)
    fastboot_ok = tools.get("fastboot", {}).get("found", False)

    env_status = "PASSED" if (adb_ok and fastboot_ok) else "FAILED"
    env_summary = "Host environment verified; ADB and Fastboot are installed." if env_status == "PASSED" else "Missing required platform tools (ADB or Fastboot)."

    tests.append({
        "test_id": "TEST_001_ENV",
        "name": "Host Environment & Platform Tools Check",
        "status": env_status,
        "summary": env_summary,
        "commands_executed": [],
        "details": env_data,
    })

    # -------------------------------------------------------------
    # Test 2: USB Subsystem & Chipset Interface Scan
    # -------------------------------------------------------------
    usb_data = collect_usb_devices(runner)
    usb_status = "PASSED" if usb_data.get("is_oppo_normal_detected") or usb_data.get("matched_special_devices") else "INCONCLUSIVE"
    matched_names = [p["profile_name"] for p in usb_data.get("matched_special_devices", [])]
    usb_summary = f"Detected {len(usb_data.get('devices', []))} USB devices. Matched targets: {', '.join(matched_names) if matched_names else 'None'}."

    tests.append({
        "test_id": "TEST_002_USB",
        "name": "USB Bus & Vendor/Product ID Enumeration",
        "status": usb_status,
        "summary": usb_summary,
        "commands_executed": [
            {
                "command": ["lsusb"],
                "start_time": usb_data["execution"]["start_time"],
                "duration_seconds": usb_data["execution"]["duration_seconds"],
                "exit_code": usb_data["execution"]["exit_code"],
                "stdout": "\n".join([f"Bus {d['bus']} Device {d['device']}: ID {d['vendor_id']}:{d['product_id']} {d['description']}" for d in usb_data.get("devices", [])]),
                "stderr": usb_data["execution"]["error"],
                "is_safe": True,
            }
        ],
        "details": usb_data,
    })

    # -------------------------------------------------------------
    # Test 3: ADB Device Connectivity & State
    # -------------------------------------------------------------
    adb_data, adb_serials = collect_adb_devices(runner)
    for s in adb_serials:
        redactor.add_serial(s)

    adb_status = "FAILED"
    if adb_data.get("devices_count", 0) > 0:
        active_states = [d["status"] for d in adb_data.get("devices", [])]
        if "device" in active_states:
            adb_status = "PASSED"
            adb_summary = f"Target device identified via ADB in authorized 'device' mode."
        else:
            adb_status = "INCONCLUSIVE"
            adb_summary = f"Target device detected but in unauthorized/offline state ({', '.join(active_states)})."
    else:
        adb_summary = "No ADB devices detected. Ensure USB debugging is enabled."

    tests.append({
        "test_id": "TEST_003_ADB",
        "name": "ADB Connectivity & Interface State",
        "status": adb_status,
        "summary": adb_summary,
        "commands_executed": [
            {
                "command": ["adb", "devices", "-l"],
                "start_time": adb_data["execution"]["start_time"],
                "duration_seconds": adb_data["execution"]["duration_seconds"],
                "exit_code": adb_data["execution"]["exit_code"],
                "stdout": adb_data["execution"]["raw_output"],
                "stderr": adb_data["execution"]["error"],
                "is_safe": True,
            }
        ],
        "details": adb_data,
    })

    # -------------------------------------------------------------
    # Test 4: Android Build & Boot Properties Collection
    # -------------------------------------------------------------
    prop_data: dict[str, Any] = {}
    if adb_status == "PASSED":
        prop_data, prop_serials = collect_android_properties(runner)
        for s in prop_serials:
            redactor.add_serial(s)

        crit = prop_data.get("critical_properties", {})
        prop_status = "PASSED" if crit.get("ro.boot.hardware") == "mt6771" else "INCONCLUSIVE"
        prop_summary = f"Collected {prop_data.get('total_properties_count')} properties. Confirmed SoC: {crit.get('ro.boot.hardware')}, Build: {crit.get('ro.build.display.id')}."

        tests.append({
            "test_id": "TEST_004_PROPS",
            "name": "Android Build & Verified Boot Properties",
            "status": prop_status,
            "summary": prop_summary,
            "commands_executed": [
                {
                    "command": ["adb", "shell", "getprop"],
                    "start_time": prop_data["execution"]["start_time"],
                    "duration_seconds": prop_data["execution"]["duration_seconds"],
                    "exit_code": prop_data["execution"]["exit_code"],
                    "stdout": "\n".join([f"[{k}]: [{v}]" for k, v in crit.items()]),
                    "stderr": prop_data["execution"]["error"],
                    "is_safe": True,
                }
            ],
            "details": prop_data,
        })
    else:
        tests.append({
            "test_id": "TEST_004_PROPS",
            "name": "Android Build & Verified Boot Properties",
            "status": "NOT_SUPPORTED",
            "summary": "Skipped: ADB connection is not active.",
            "commands_executed": [],
            "details": {},
        })

    # -------------------------------------------------------------
    # Test 5: Fastboot Mode Connectivity Check
    # -------------------------------------------------------------
    fb_data, fb_serials = collect_fastboot_devices(runner)
    for s in fb_serials:
        redactor.add_serial(s)

    fb_status = "PASSED" if fb_data.get("is_fastboot_active") else "INCONCLUSIVE"
    fb_summary = "Device active in Fastboot mode." if fb_data.get("is_fastboot_active") else "No devices currently in Fastboot mode (expected during normal OS operation)."

    tests.append({
        "test_id": "TEST_005_FASTBOOT",
        "name": "Fastboot Bus Status Check",
        "status": fb_status,
        "summary": fb_summary,
        "commands_executed": [
            {
                "command": ["fastboot", "devices"],
                "start_time": fb_data["execution"]["start_time"],
                "duration_seconds": fb_data["execution"]["duration_seconds"],
                "exit_code": fb_data["execution"]["exit_code"],
                "stdout": "\n".join([f"{d['raw_serial']} {d['status']}" for d in fb_data.get("devices", [])]),
                "stderr": fb_data["execution"]["error"],
                "is_safe": True,
            }
        ],
        "details": fb_data,
    })

    # -------------------------------------------------------------
    # Test 6: In-Depth Test / Unlock Package Audit
    # -------------------------------------------------------------
    if adb_status == "PASSED":
        pkg_data = collect_testing_packages(runner)
        pkg_status = "PASSED"
        dt_installed = pkg_data.get("deeptesting_installed", False)
        pkg_summary = f"Audit complete. DeepTesting application is {'INSTALLED' if dt_installed else 'NOT INSTALLED'}."

        tests.append({
            "test_id": "TEST_006_PACKAGES",
            "name": "Deep Testing & Unlock Package Inspection",
            "status": pkg_status,
            "summary": pkg_summary,
            "commands_executed": [
                {
                    "command": ["adb", "shell", "pm", "list", "packages"],
                    "start_time": pkg_data["execution"]["start_time"],
                    "duration_seconds": pkg_data["execution"]["duration_seconds"],
                    "exit_code": pkg_data["execution"]["exit_code"],
                    "stdout": "\n".join([f"{kw}: {pkgs}" for kw, pkgs in pkg_data.get("matched_packages", {}).items() if pkgs]),
                    "stderr": pkg_data["execution"]["error"],
                    "is_safe": True,
                }
            ],
            "details": pkg_data,
        })
    else:
        tests.append({
            "test_id": "TEST_006_PACKAGES",
            "name": "Deep Testing & Unlock Package Inspection",
            "status": "NOT_SUPPORTED",
            "summary": "Skipped: ADB connection is not active.",
            "commands_executed": [],
            "details": {},
        })

    # -------------------------------------------------------------
    # Test 7: Bootloader Security & Unlock Posture Assessment
    # -------------------------------------------------------------
    security_posture = prop_data.get("security_posture", {})
    if security_posture:
        is_locked = security_posture.get("flash_locked") == "1"
        is_oem_allowed = security_posture.get("oem_unlock_allowed") == "1"
        posture_status = "PASSED"
        posture_summary = f"Bootloader is {'LOCKED' if is_locked else 'UNLOCKED'}. OEM Unlocking toggle is {'ENABLED (allowed)' if is_oem_allowed else 'DISABLED'}."

        tests.append({
            "test_id": "TEST_007_POSTURE",
            "name": "Security & Bootloader Posture Assessment",
            "status": posture_status,
            "summary": posture_summary,
            "commands_executed": [],
            "details": security_posture,
        })

    # -------------------------------------------------------------
    # Test 8: Optional USB Monitor
    # -------------------------------------------------------------
    if include_usb_monitor:
        mon_data = monitor_usb_events(runner, duration_seconds=monitor_duration)
        tests.append({
            "test_id": "TEST_008_USB_MONITOR",
            "name": "USB Subsystem Event Monitoring",
            "status": "PASSED" if mon_data.get("events_captured_count", 0) >= 0 else "FAILED",
            "summary": f"Monitored USB bus for {monitor_duration}s. Captured {mon_data.get('events_captured_count')} event(s).",
            "commands_executed": [
                {
                    "command": ["udevadm", "monitor", "--subsystem-match=usb", "--environment"],
                    "start_time": mon_data["start_time"],
                    "duration_seconds": mon_data["duration_seconds"],
                    "exit_code": 0,
                    "stdout": f"Captured {mon_data.get('events_captured_count')} events",
                    "stderr": "",
                    "is_safe": True,
                }
            ],
            "details": mon_data,
        })

    session_end = datetime.datetime.now(tz).isoformat()

    session_data = {
        "metadata": {
            "tool_name": "realme1-unlock-research",
            "tool_version": __version__,
            "timestamp": session_start,
            "session_end": session_end,
            "host_os": env_data.get("os_name"),
            "host_machine": env_data.get("machine"),
            "safety_policy": "STRICT_READ_ONLY",
        },
        "security_posture": security_posture,
        "tests": tests,
    }

    return session_data, reporter


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="realme1-unlock-research",
        description="Read-only diagnostic CLI tool for Realme 1 (CPH1859) bootloader unlock research.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "both"],
        default="markdown",
        help="Report output format (default: markdown).",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=str,
        help="Optional base path or file path to write diagnostic report.",
    )
    parser.add_argument(
        "--monitor-usb",
        action="store_true",
        help="Enable live USB subsystem event monitoring for a brief duration.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=3.0,
        help="Duration in seconds for USB monitoring (default: 3.0s).",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    session_data, reporter = run_diagnostics(
        include_usb_monitor=args.monitor_usb,
        monitor_duration=args.duration,
    )

    md_output = reporter.format_markdown(session_data)
    json_output = reporter.format_json(session_data)

    if args.out:
        out_base = args.out
        if args.format in ("markdown", "both"):
            md_path = out_base if out_base.endswith(".md") else f"{out_base}.md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_output)
            print(f"[+] Wrote Markdown diagnostic report to: {md_path}")

        if args.format in ("json", "both"):
            json_path = out_base if out_base.endswith(".json") else f"{out_base}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"[+] Wrote JSON diagnostic report to: {json_path}")
    else:
        if args.format == "json":
            print(json_output)
        else:
            print(md_output)

    return 0


if __name__ == "__main__":
    sys.exit(main())

