#!/usr/bin/env python3
"""
Unit tests for Bootloader Authorization Protocol Analyzer (analyze_authorization_protocol.py)
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
import analyze_authorization_protocol as analyzer


class TestAuthorizationProtocol(unittest.TestCase):
    def setUp(self):
        self.c49_lk = analyzer.DEFAULT_C49_LK
        self.c50_lk = analyzer.DEFAULT_C50_LK
        self.recovery = analyzer.DEFAULT_RECOVERY

    def test_verify_unlock_token_code_identity(self):
        vut_c49 = analyzer.analyze_verify_unlock_token(self.c49_lk)
        vut_c50 = analyzer.analyze_verify_unlock_token(self.c50_lk)
        self.assertEqual(vut_c49["sha256"], vut_c50["sha256"])
        self.assertEqual(vut_c49["sha256"], "c1fa1a7d7cf6627d8beba0dd9614e1949780fdcf4e0f3918f900617295b6a63c")

    def test_verify_unlock_token_checks(self):
        vut = analyzer.analyze_verify_unlock_token(self.c49_lk)
        self.assertTrue(vut["checks"]["read_reserve4_call"])
        self.assertTrue(vut["checks"]["serial_offset_0x100"])
        self.assertTrue(vut["checks"]["leading_zero_fallback"])
        self.assertTrue(vut["checks"]["pubkey_pointer_valid"])
        self.assertTrue(vut["checks"]["pubkey_length_2048"])
        self.assertTrue(vut["checks"]["pss_salt_32"])
        self.assertTrue(vut["checks"]["pss_trailer_0xbc"])
        self.assertTrue(vut["checks"]["strings_intact"])

    def test_fastboot_init_checks(self):
        fb = analyzer.analyze_fastboot_init(self.c49_lk)
        self.assertTrue(fb["checks"]["calls_verify_unlock_token"])
        self.assertTrue(fb["checks"]["calls_mtk_arch_reset_on_fail"])
        self.assertTrue(fb["checks"]["failure_string_verify"])
        self.assertTrue(fb["checks"]["success_string_verify"])
        self.assertTrue(fb["checks"]["has_flashing_unlock"])
        self.assertTrue(fb["checks"]["has_flashing_lock"])
        self.assertTrue(fb["checks"]["lacks_oem_unlock"])

    def test_recovery_ramdisk_checks(self):
        rec = analyzer.analyze_recovery_ramdisk(self.recovery)
        self.assertGreater(rec["recovery_binary_size"], 1000000)
        self.assertTrue(rec["checks"]["lacks_reserve4_reference"])
        self.assertTrue(rec["checks"]["lacks_seccfg_reference"])
        self.assertTrue(rec["checks"]["lacks_fastboot_reference"])
        self.assertTrue(rec["checks"]["lacks_deeptest_reference"])

    def test_negative_truncated_lk_handling(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            tf.write(b"SHORT_DATA_1234")
            tname = tf.name

        try:
            with self.assertRaises(Exception):
                analyzer.analyze_verify_unlock_token(tname)
        finally:
            if os.path.exists(tname):
                os.remove(tname)


if __name__ == "__main__":
    unittest.main()
