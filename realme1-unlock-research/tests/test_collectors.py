"""Unit tests for diagnostic collectors and parser logic."""

import unittest
from realme1_unlock_research.collectors.properties import PROP_REGEX, CRITICAL_PROPERTIES
from realme1_unlock_research.collectors.usb import LSUSB_REGEX, KNOWN_DEVICE_PROFILES


class TestCollectorParsers(unittest.TestCase):
    def test_getprop_parsing(self):
        sample_line = "[ro.boot.flash.locked]: [1]"
        match = PROP_REGEX.match(sample_line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "ro.boot.flash.locked")
        self.assertEqual(match.group(2), "1")

        sample_line2 = "[ro.build.display.id]: [CPH1859EX_11_C.50]"
        match2 = PROP_REGEX.match(sample_line2)
        self.assertIsNotNone(match2)
        self.assertEqual(match2.group(1), "ro.build.display.id")
        self.assertEqual(match2.group(2), "CPH1859EX_11_C.50")

    def test_lsusb_parsing(self):
        sample_line = "Bus 003 Device 008: ID 22d9:2769 OPPO Electronics Corp. CPH1859"
        match = LSUSB_REGEX.match(sample_line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "003")
        self.assertEqual(match.group(2), "008")
        self.assertEqual(match.group(3).lower(), "22d9")
        self.assertEqual(match.group(4).lower(), "2769")
        self.assertIn("OPPO Electronics Corp.", match.group(5))

    def test_known_profile_mapping(self):
        oppo_profile = KNOWN_DEVICE_PROFILES.get(("22d9", "2769"))
        self.assertIsNotNone(oppo_profile)
        self.assertIn("CPH1859", oppo_profile)

        brom_profile = KNOWN_DEVICE_PROFILES.get(("0e8d", "0003"))
        self.assertIsNotNone(brom_profile)
        self.assertIn("BootROM", brom_profile)


if __name__ == "__main__":
    unittest.main()
