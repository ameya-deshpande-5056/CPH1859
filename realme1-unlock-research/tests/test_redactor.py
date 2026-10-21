"""Unit tests for the sensitive data redactor."""

import unittest
from realme1_unlock_research.redactor import SensitiveDataRedactor


class TestSensitiveDataRedactor(unittest.TestCase):
    def setUp(self):
        self.redactor = SensitiveDataRedactor()

    def test_exact_serial_redaction(self):
        test_serial = "DUMMY_SERIAL_1234567890"
        self.redactor.add_serial(test_serial)

        text = f"Device attached with serial {test_serial} running build C.50"
        redacted = self.redactor.redact_text(text)

        self.assertNotIn(test_serial, redacted)
        self.assertIn("[REDACTED_SERIAL]", redacted)

    def test_imei_redaction(self):
        text = "IMEI detected: 867530901234567 in nvram"
        redacted = self.redactor.redact_text(text)

        self.assertNotIn("867530901234567", redacted)
        self.assertIn("[REDACTED_IMEI]", redacted)

    def test_mac_redaction(self):
        text = "WLAN MAC: 00:1A:2B:3C:4D:5E connected"
        redacted = self.redactor.redact_text(text)

        self.assertNotIn("00:1A:2B:3C:4D:5E", redacted)
        self.assertIn("[REDACTED_MAC]", redacted)

    def test_recursive_structure_redaction(self):
        test_serial = "DUMMY_SERIAL_1234567890"
        self.redactor.add_serial(test_serial)

        data = {
            "device": {
                "serial": test_serial,
                "history": [f"Rebooted {test_serial}", "867530901234567"],
            },
            "status": "active",
        }

        sanitized = self.redactor.redact_structure(data)

        self.assertEqual(sanitized["device"]["serial"], "[REDACTED_SERIAL]")
        self.assertIn("[REDACTED_SERIAL]", sanitized["device"]["history"][0])
        self.assertIn("[REDACTED_IMEI]", sanitized["device"]["history"][1])
        self.assertEqual(sanitized["status"], "active")


if __name__ == "__main__":
    unittest.main()
