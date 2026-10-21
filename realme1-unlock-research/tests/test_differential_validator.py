"""Unit tests for the independent LK differential validator."""

import os
import sys
import unittest

# Add project root and scripts directory to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from validate_lk_differential import (
    DEFAULT_C49_LK,
    DEFAULT_C50_LK,
    DEFAULT_C49_PRELOADER,
    DEFAULT_C50_PRELOADER,
    find_diff_ranges,
    cluster_ranges,
    validate_lk_differential,
)


class TestDifferentialValidator(unittest.TestCase):
    def test_find_diff_ranges_unit(self):
        b1 = b"AAAA1111BBBB2222"
        b2 = b"AAAA9999BBBB3333"
        ranges = find_diff_ranges(b1, b2)
        self.assertEqual(ranges, [(4, 8), (12, 16)])

    def test_cluster_ranges_unit(self):
        ranges = [(10, 20), (24, 30), (100, 110)]
        clusters = cluster_ranges(ranges, max_gap=16)
        self.assertEqual(clusters, [(10, 30), (100, 110)])

    def test_validator_with_missing_file(self):
        res = validate_lk_differential(
            c49_path="/nonexistent/path/lk.img",
            c50_path=DEFAULT_C50_LK,
            c49_p_path=DEFAULT_C49_PRELOADER,
            c50_p_path=DEFAULT_C50_PRELOADER,
        )
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any("missing" in err.lower() for err in res["failures"]))

    @unittest.skipUnless(
        os.path.isfile(DEFAULT_C49_LK)
        and os.path.isfile(DEFAULT_C50_LK)
        and os.path.isfile(DEFAULT_C49_PRELOADER)
        and os.path.isfile(DEFAULT_C50_PRELOADER),
        "Real firmware binaries required for live validation test",
    )
    def test_full_validation_passes(self):
        res = validate_lk_differential(
            c49_path=DEFAULT_C49_LK,
            c50_path=DEFAULT_C50_LK,
            c49_p_path=DEFAULT_C49_PRELOADER,
            c50_p_path=DEFAULT_C50_PRELOADER,
        )
        self.assertEqual(res["status"], "PASS", f"Validation failed with: {res['failures']}")
        self.assertEqual(len(res["failures"]), 0)

        # Detailed assertion checks
        self.assertEqual(res["lk_diff"]["total_differing_bytes"], 315)
        self.assertEqual(len(res["lk_diff"]["clusters_half_open"]), 3)
        self.assertTrue(res["container_validation"]["valid"])
        self.assertTrue(res["payload_digest_validation"]["c49"]["match"])
        self.assertTrue(res["payload_digest_validation"]["c50"]["match"])
        self.assertTrue(res["certificate_validation"]["cert1_self_signed_verified"])
        self.assertTrue(res["certificate_validation"]["cert2_c49_signed_verified"])
        self.assertTrue(res["certificate_validation"]["cert2_c50_signed_verified"])
        self.assertTrue(res["certificate_validation"]["key_c2_matches_between_cert1_and_cert2"])
        self.assertTrue(res["certificate_validation"]["encoded_pss_salt_length_32"])
        self.assertTrue(res["certificate_validation"]["oem_unlock_key_is_distinct"])
        self.assertTrue(res["preloader_validation"]["code_region_identical"])
        self.assertEqual(res["preloader_validation"]["total_differing_bytes"], 569)
        self.assertTrue(res["code_and_strings_validation"]["verify_unlock_token_identical"])
        self.assertTrue(res["code_and_strings_validation"]["fastboot_init_identical"])
        self.assertTrue(res["code_and_strings_validation"]["strings_valid"])


if __name__ == "__main__":
    unittest.main()
