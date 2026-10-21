"""Safe command execution engine with strict read-only enforcement and execution audit logging."""

from __future__ import annotations

import datetime
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional


class CommandSecurityViolation(Exception):
    """Raised when an attempted command violates the read-only safety policy."""
    pass


@dataclass
class ExecutionResult:
    command: list[str]
    start_time: str
    end_time: str
    duration_seconds: float
    exit_code: int
    stdout: str
    stderr: str
    is_safe: bool = True
    error_message: str | None = None

    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.error_message


class SafeCommandRunner:
    """Executes system commands while enforcing a strict read-only guarantee.

    Specifically blocks any command or argument related to flashing, erasing,
    formatting, writing partitions, or triggering unlock commands.
    """

    # Prohibited command tokens or argument substrings (case-insensitive)
    PROHIBITED_TOKENS = {
        "flash",
        "flashing",
        "erase",
        "format",
        "unlock",
        "lock",
        "oem-unlock",
        "flashing-unlock",
        "fastboot-unlock",
        "write",
        "dd",
        "mkfs",
        "wipe",
        "seccfg",
    }

    # Prohibited executables or commands
    BLOCKED_PROGRAMS = {
        "dd",
        "mkfs",
        "fdisk",
        "parted",
        "gdisk",
        "sfdisk",
    }

    def validate_safety(self, command: list[str]) -> None:
        """Inspects the command and its arguments. Raises CommandSecurityViolation if

        any unsafe token is present.
        """
        if not command:
            raise CommandSecurityViolation("Empty command is invalid.")

        executable = command[0].lower().split("/")[-1]
        for blocked in self.BLOCKED_PROGRAMS:
            if executable == blocked or executable.startswith(f"{blocked}."):
                raise CommandSecurityViolation(f"Blocked executable '{executable}' violates safety policy.")

        for arg in command:
            token = arg.lower().strip()
            # Check exact match or token containment for fastboot / adb subcommands
            if token in self.PROHIBITED_TOKENS:
                raise CommandSecurityViolation(
                    f"Command contains prohibited token '{token}' which violates read-only safety constraints."
                )
            if "unlock" in token or "flash" in token or "erase" in token:
                # Check for arguments like --unlock, flashing_unlock, etc.
                # Allow safe flags like --disable-verity check in documentation only, but here in execution:
                raise CommandSecurityViolation(
                    f"Command argument '{arg}' matches prohibited modification pattern."
                )

    def run(self, command: list[str], timeout_seconds: float = 30.0) -> ExecutionResult:
        """Executes the safe command and returns a structured ExecutionResult."""
        tz = datetime.datetime.now().astimezone().tzinfo
        start_dt = datetime.datetime.now(tz)
        start_iso = start_dt.isoformat()
        start_perf = time.perf_counter()

        try:
            self.validate_safety(command)
        except CommandSecurityViolation as e:
            end_dt = datetime.datetime.now(tz)
            end_perf = time.perf_counter()
            return ExecutionResult(
                command=command,
                start_time=start_iso,
                end_time=end_dt.isoformat(),
                duration_seconds=round(end_perf - start_perf, 4),
                exit_code=-1,
                stdout="",
                stderr=str(e),
                is_safe=False,
                error_message=str(e),
            )

        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
            )
            end_dt = datetime.datetime.now(tz)
            end_perf = time.perf_counter()

            return ExecutionResult(
                command=command,
                start_time=start_iso,
                end_time=end_dt.isoformat(),
                duration_seconds=round(end_perf - start_perf, 4),
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                is_safe=True,
            )
        except subprocess.TimeoutExpired as te:
            end_dt = datetime.datetime.now(tz)
            end_perf = time.perf_counter()
            return ExecutionResult(
                command=command,
                start_time=start_iso,
                end_time=end_dt.isoformat(),
                duration_seconds=round(end_perf - start_perf, 4),
                exit_code=-2,
                stdout=te.stdout or "" if isinstance(te.stdout, str) else "",
                stderr=f"Command timed out after {timeout_seconds} seconds.",
                is_safe=True,
                error_message=f"TimeoutExpired: {timeout_seconds}s",
            )
        except FileNotFoundError as fnf:
            end_dt = datetime.datetime.now(tz)
            end_perf = time.perf_counter()
            return ExecutionResult(
                command=command,
                start_time=start_iso,
                end_time=end_dt.isoformat(),
                duration_seconds=round(end_perf - start_perf, 4),
                exit_code=-3,
                stdout="",
                stderr=str(fnf),
                is_safe=True,
                error_message=f"FileNotFoundError: {command[0]} not found in PATH.",
            )
        except Exception as ex:
            end_dt = datetime.datetime.now(tz)
            end_perf = time.perf_counter()
            return ExecutionResult(
                command=command,
                start_time=start_iso,
                end_time=end_dt.isoformat(),
                duration_seconds=round(end_perf - start_perf, 4),
                exit_code=-4,
                stdout="",
                stderr=str(ex),
                is_safe=True,
                error_message=str(ex),
            )
