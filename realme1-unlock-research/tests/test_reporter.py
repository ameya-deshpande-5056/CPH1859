"""Unit tests for report formatting and serialization."""

import json
import unittest
from realme1_unlock_research.redactor import SensitiveDataRedactor
from realme1_unlock_research.reporter import DiagnosticReporter


class TestReporter(unittest.TestCase):
    def setUp(self):
        self.redactor = SensitiveDataRedactor(explicit_serials={"TESTSERIAL12345"})
        self.reporter = DiagnosticReporter(self.redactor)

    def test_json_formatting_and_redaction(self):
        data = {
            "metadata": {"timestamp": "2026-10-21T10:00:00+05:30"},
            "tests": [
                {
                    "test_id": "TEST_001",
                    "name": "Serial Check",
                    "status": "PASSED",
                    "summary": "Serial TESTSERIAL12345 found",
                    "commands_executed": [],
                    "details": {"serial": "TESTSERIAL12345"},
                }
            ],
        }
        json_str = self.reporter.format_json(data)
        parsed = json.loads(json_str)

        self.assertNotIn("TESTSERIAL12345", json_str)
        self.assertIn("[REDACTED_SERIAL]", json_str)
        self.assertEqual(parsed["tests"][0]["details"]["serial"], "[REDACTED_SERIAL]")

    def test_markdown_formatting(self):
        data = {
            "metadata": {
                "timestamp": "2026-10-21T10:00:00+05:30",
                "tool_version": "0.1.0",
                "host_os": "Linux",
                "host_machine": "x86_64",
            },
            "security_posture": {
                "flash_locked": "1",
                "oem_unlock_supported": "1",
                "oem_unlock_allowed": "1",
                "verified_boot_state": "green",
                "verity_mode": "enforcing",
                "platform": "mt6771",
                "build_id": "CPH1859EX_11_C.50",
            },
            "tests": [
                {
                    "test_id": "TEST_001_ENV",
                    "name": "Host Check",
                    "status": "PASSED",
                    "summary": "Verified environment",
                    "commands_executed": [
                        {
                            "command": ["adb", "--version"],
                            "start_time": "2026-10-21T10:00:00+05:30",
                            "duration_seconds": 0.05,
                            "exit_code": 0,
                            "stdout": "Android Debug Bridge version 1.0.41",
                            "stderr": "",
                            "is_safe": True,
                        }
                    ],
                    "details": {},
                }
            ],
        }
        md_str = self.reporter.format_markdown(data)

        self.assertIn("# Realme 1 (CPH1859) Diagnostic & Bootloader Posture Report", md_str)
        self.assertIn("TEST_001_ENV", md_str)
        self.assertIn("**PASSED**", md_str)
        self.assertIn("Android Debug Bridge version 1.0.41", md_str)


if __name__ == "__main__":
    unittest.main()

