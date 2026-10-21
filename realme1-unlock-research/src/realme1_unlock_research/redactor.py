"""Redaction engine for sanitizing sensitive identifiers from diagnostic data."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Union


class SensitiveDataRedactor:
    """Detects and redacts sensitive hardware identifiers such as serial numbers,

    IMEIs, MAC addresses, and specific tokens.
    """

    # Generic patterns
    MAC_REGEX = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b")
    IMEI_REGEX = re.compile(r"\b\d{15}\b")
    IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, explicit_serials: set[str] | None = None) -> None:
        self.exact_serials: set[str] = set()
        if explicit_serials:
            for s in explicit_serials:
                self.add_serial(s)

    def add_serial(self, serial: str) -> None:
        """Register a known device serial number for exact redaction."""
        clean = serial.strip()
        if clean and len(clean) >= 4 and clean.lower() not in {"unknown", "none", "null", "device", "offline"}:
            self.exact_serials.add(clean)

    def redact_text(self, text: str) -> str:
        """Sanitize a raw text string by replacing sensitive identifiers with placeholder tokens."""
        if not text:
            return ""

        redacted = text

        # 1. Redact registered exact serial numbers first
        for serial in self.exact_serials:
            redacted = redacted.replace(serial, "[REDACTED_SERIAL]")

        # 2. Redact MAC addresses
        redacted = self.MAC_REGEX.sub("[REDACTED_MAC]", redacted)

        # 3. Redact IMEI numbers (15 contiguous digits)
        redacted = self.IMEI_REGEX.sub("[REDACTED_IMEI]", redacted)

        return redacted

    def redact_structure(self, obj: Any) -> Any:
        """Recursively redact dictionary, list, or primitive values."""
        if isinstance(obj, str):
            return self.redact_text(obj)
        elif isinstance(obj, dict):
            return {self.redact_text(str(k)): self.redact_structure(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.redact_structure(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self.redact_structure(item) for item in obj)
        elif isinstance(obj, set):
            return {self.redact_structure(item) for item in obj}
        return obj
