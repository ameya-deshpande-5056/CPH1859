"""Android package manager collector targeting unlock and testing packages."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..command_runner import SafeCommandRunner

TARGET_KEYWORDS = [
    "deeptesting",
    "deep_test",
    "unlock",
    "engineermode",
    "factory",
    "test",
    "mediatek",
    "coloros",
]


def collect_testing_packages(runner: SafeCommandRunner) -> dict[str, Any]:
    """Inspects installed Android packages to verify presence of unlock/diagnostic apps."""
    res = runner.run(["adb", "shell", "pm", "list", "packages"])
    installed_packages: list[str] = []
    matched_packages: dict[str, list[str]] = {kw: [] for kw in TARGET_KEYWORDS}

    if res.exit_code == 0:
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                pkg = line[len("package:"):].strip()
                installed_packages.append(pkg)
                pkg_lower = pkg.lower()
                for kw in TARGET_KEYWORDS:
                    if kw in pkg_lower:
                        matched_packages[kw].append(pkg)

    data: dict[str, Any] = {
        "execution": {
            "start_time": res.start_time,
            "duration_seconds": res.duration_seconds,
            "exit_code": res.exit_code,
            "error": res.stderr,
        },
        "total_packages_count": len(installed_packages),
        "deeptesting_installed": len(matched_packages["deeptesting"]) > 0 or len(matched_packages["deep_test"]) > 0,
        "matched_packages": matched_packages,
    }

    return data
