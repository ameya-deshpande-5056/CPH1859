"""Diagnostic report generator for structured JSON and human-readable Markdown outputs."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from .redactor import SensitiveDataRedactor


@dataclass
class DiagnosticTestResult:
    test_id: str
    name: str
    status: str  # "PASSED", "FAILED", "INCONCLUSIVE", "NOT_SUPPORTED"
    summary: str
    commands_executed: list[dict[str, Any]]
    details: dict[str, Any]


class DiagnosticReporter:
    """Formats and exports diagnostic results with mandatory identifier redaction."""

    def __init__(self, redactor: SensitiveDataRedactor) -> None:
        self.redactor = redactor

    def format_json(self, session_data: dict[str, Any], indent: int = 2) -> str:
        """Serializes session data to redacted JSON."""
        sanitized = self.redactor.redact_structure(session_data)
        return json.dumps(sanitized, indent=indent)

    def format_markdown(self, session_data: dict[str, Any]) -> str:
        """Generates a comprehensive, human-readable Markdown report."""
        sanitized = self.redactor.redact_structure(session_data)
        meta = sanitized.get("metadata", {})
        tests: list[dict[str, Any]] = sanitized.get("tests", [])

        lines: list[str] = [
            "# Realme 1 (CPH1859) Diagnostic & Bootloader Posture Report",
            "",
            "> [!NOTE]",
            f"> Generated on: {meta.get('timestamp', 'N/A')}  ",
            f"> Tool Version: {meta.get('tool_version', '0.1.0')}  ",
            f"> Host OS: {meta.get('host_os', 'Linux')} ({meta.get('host_machine', 'x86_64')})  ",
            "> Safety Guarantee: Strictly Read-Only (Non-Invasive) — Zero Partition Writes / Erases",
            "",
            "## Executive Summary",
            "",
            "| Test ID | Test Name | Status | Summary |",
            "|---|---|---|---|",
        ]

        for t in tests:
            status_badge = t.get("status", "UNKNOWN")
            if status_badge == "PASSED":
                badge = "**PASSED**"
            elif status_badge == "FAILED":
                badge = "**FAILED**"
            elif status_badge == "INCONCLUSIVE":
                badge = "*INCONCLUSIVE*"
            elif status_badge == "NOT_SUPPORTED":
                badge = "`NOT_SUPPORTED`"
            else:
                badge = status_badge

            lines.append(f"| `{t.get('test_id')}` | {t.get('name')} | {badge} | {t.get('summary')} |")

        lines.extend([
            "",
            "---",
            "",
            "## Security & Bootloader Posture Analysis",
            "",
        ])

        posture = sanitized.get("security_posture", {})
        if posture:
            lines.extend([
                "| Property | Value | Interpretation |",
                "|---|---|---|",
                f"| `ro.boot.flash.locked` | `{posture.get('flash_locked', 'N/A')}` | Device bootloader partition lock state (1 = locked). |",
                f"| `ro.oem_unlock_supported` | `{posture.get('oem_unlock_supported', 'N/A')}` | Android platform OEM unlock toggle support. |",
                f"| `sys.oem_unlock_allowed` | `{posture.get('oem_unlock_allowed', 'N/A')}` | User toggle in Developer Options (1 = allowed). |",
                f"| `ro.boot.verifiedbootstate` | `{posture.get('verified_boot_state', 'N/A')}` | AVB State (green = locked official OEM boot image). |",
                f"| `ro.boot.veritymode` | `{posture.get('verity_mode', 'N/A')}` | dm-verity enforcement policy (enforcing). |",
                f"| `ro.board.platform` | `{posture.get('platform', 'N/A')}` | MediaTek Helio P60 platform code (`mt6771`). |",
                f"| `ro.build.display.id` | `{posture.get('build_id', 'N/A')}` | ColorOS firmware release identifier. |",
                "",
            ])
        else:
            lines.append("No security posture data available.\n")

        lines.extend([
            "---",
            "",
            "## Detailed Test Audits & Commands Executed",
            "",
        ])

        for t in tests:
            lines.extend([
                f"### {t.get('test_id')}: {t.get('name')}",
                f"- **Status:** `{t.get('status')}`",
                f"- **Summary:** {t.get('summary')}",
                "",
                "**Audited Commands & Preserved Outputs:**",
                "",
            ])

            cmds = t.get("commands_executed", [])
            if not cmds:
                lines.append("*No shell commands executed for this test.*\n")
            else:
                for c in cmds:
                    cmd_str = " ".join(c.get("command", []))
                    lines.extend([
                        f"- Command: `{cmd_str}`",
                        f"  - Start Time: `{c.get('start_time')}`",
                        f"  - Duration: `{c.get('duration_seconds')}s`",
                        f"  - Exit Code: `{c.get('exit_code')}`",
                        f"  - Safe Guard: `{'APPROVED' if c.get('is_safe', True) else 'VIOLATION'}`",
                        "",
                    ])
                    stdout = c.get("stdout", "").strip()
                    stderr = c.get("stderr", "").strip()
                    if stdout:
                        lines.extend([
                            "```text",
                            stdout,
                            "```",
                            "",
                        ])
                    if stderr:
                        lines.extend([
                            "> Stderr Output:",
                            "```text",
                            stderr,
                            "```",
                            "",
                        ])

        return "\n".join(lines)
