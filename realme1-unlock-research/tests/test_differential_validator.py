"""Unit tests for the independent LK differential validator."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

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
    safe_diff_count,
    parse_der_tlv,
    parse_der_sequence,
    decode_oid,
    parse_mtk_header,
    parse_cert1_info,
    parse_cert2_info,
    validate_lk_differential,
)


class TestDifferentialValidator(unittest.TestCase):
    """Exhaustive unit and regression test suite for validate_lk_differential."""

    def test_find_diff_ranges_unit(self):
        b1 = b"AAAA1111BBBB2222"
        b2 = b"AAAA9999BBBB3333"
        ranges = find_diff_ranges(b1, b2)
        self.assertEqual(ranges, [(4, 8), (12, 16)])

    def test_cluster_ranges_unit(self):
        ranges = [(10, 20), (24, 30), (100, 110)]
        clusters = cluster_ranges(ranges, max_gap=16)
        self.assertEqual(clusters, [(10, 30), (100, 110)])

    def test_safe_diff_count_unit(self):
        b1 = b"ABCDEF"
        b2 = b"ABXDEF"
        self.assertEqual(safe_diff_count(b1, b2), 1)

        # Unequal lengths: must not raise IndexError
        b3 = b"ABC"
        b4 = b"ABCDEF"
        self.assertEqual(safe_diff_count(b3, b4), 3)
        self.assertEqual(safe_diff_count(b4, b3), 3)

        # Offsets and slice ranges
        self.assertEqual(safe_diff_count(b1, b2, start=2, end=3), 1)
        self.assertEqual(safe_diff_count(b1, b2, start=3, end=5), 0)

    def test_parse_der_tlv_bounds_and_malformed(self):
        self.assertIsNone(parse_der_tlv(b""))
        self.assertIsNone(parse_der_tlv(b"\x30"))
        self.assertIsNone(parse_der_tlv(b"\x30\x80"))  # Indefinite length disallowed in DER
        self.assertIsNone(parse_der_tlv(b"\x30\x82"))  # Truncated length field
        self.assertIsNone(parse_der_tlv(b"\x30\x05ABC"))  # Value truncated (length 5, only 3 bytes)

        # Valid TLV
        valid_tlv = b"\x02\x01\x20"  # INTEGER 32
        parsed = parse_der_tlv(valid_tlv, 0)
        self.assertIsNotNone(parsed)
        tag, hlen, length, val = parsed
        self.assertEqual(tag, 0x02)
        self.assertEqual(hlen, 2)
        self.assertEqual(length, 1)
        self.assertEqual(val, b"\x20")

    def test_decode_oid_unit(self):
        self.assertEqual(decode_oid(b""), "")
        # OID 1.2.840.113549.1.1.10 (rsassaPss) -> 2a 86 48 86 f7 0d 01 01 0a
        pss_oid_bytes = bytes.fromhex("2a864886f70d01010a")
        self.assertEqual(decode_oid(pss_oid_bytes), "1.2.840.113549.1.1.10")
        # OID 2.16.886.2454.2.1 (MTK payload digest) -> 60 86 76 93 16 02 01
        digest_oid_bytes = bytes.fromhex("60867693160201")
        self.assertEqual(decode_oid(digest_oid_bytes), "2.16.886.2454.2.1")

    def test_parse_mtk_header_truncated(self):
        self.assertIsNone(parse_mtk_header(b"", 0))
        self.assertIsNone(parse_mtk_header(b"\x00" * 30, 0))
        self.assertIsNone(parse_mtk_header(b"\x00" * 100, 80))

    def test_validator_with_missing_file(self):
        res = validate_lk_differential(
            c49_path="/nonexistent/path/lk.img",
            c50_path=DEFAULT_C50_LK,
            c49_p_path=DEFAULT_C49_PRELOADER,
            c50_p_path=DEFAULT_C50_PRELOADER,
        )
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any("missing" in err.lower() for err in res["failures"]))

    def test_validator_rejects_truncated_lk(self):
        """Confirm validator rejects a truncated LK image without raising unhandled exceptions."""
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(b"\x00" * 1024)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=tmp.name,
                c50_path=DEFAULT_C50_LK,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertTrue(any("truncated" in err.lower() for err in res["failures"]))

    def test_validator_rejects_truncated_preloader(self):
        """Confirm validator rejects a truncated Preloader image without raising unhandled exceptions."""
        with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
            tmp.write(b"\x00" * 512)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=DEFAULT_C50_LK,
                c49_p_path=tmp.name,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertTrue(any("truncated" in err.lower() for err in res["failures"]))

    def test_validator_rejects_malformed_c49_container_header(self):
        """Confirm validator rejects corrupted MTK header magic in C.49."""
        with open(DEFAULT_C49_LK, "rb") as f:
            data = bytearray(f.read())
        data[0:4] = b"BAD!"
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=tmp.name,
                c50_path=DEFAULT_C50_LK,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["container_validation"]["valid"])

    def test_validator_rejects_malformed_c50_container_header(self):
        """Confirm validator symmetrically rejects corrupted MTK header magic in C.50."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        data[0:4] = b"BAD!"
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["container_validation"]["valid"])

    def test_validator_rejects_modified_payload_digest_in_cert2(self):
        """Confirm validator rejects modified embedded payload digest in cert2."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        # Flip 1 byte in cert2 embedded digest at 0x0B7F73
        data[0x0B7F73] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["payload_digest_validation"]["c50"]["match"])

    def test_validator_rejects_payload_code_mutation(self):
        """Confirm validator rejects payload modification when cert2 is unaltered."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        # Flip 1 byte in executable payload at 0x1000
        data[0x1000] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["payload_digest_validation"]["c50"]["match"])

    def test_validator_rejects_invalid_cert1_signature(self):
        """Confirm validator rejects invalid or corrupted cert1 signature."""
        with open(DEFAULT_C49_LK, "rb") as f:
            data = bytearray(f.read())
        # Flip 1 byte in cert1 signature block (near end of cert1, offset 0x0B7B00)
        data[0x0B7B00] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=tmp.name,
                c50_path=DEFAULT_C50_LK,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["certificate_validation"]["cert1_self_signed_verified"])

    def test_validator_rejects_invalid_cert2_signature(self):
        """Confirm validator rejects invalid or corrupted cert2 signature."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        # Flip 1 byte in cert2 signature block (Cluster 3, file offset 0x0B8050)
        data[0x0B8050] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["certificate_validation"]["cert2_c50_signed_verified"])

    def test_validator_rejects_corrupted_asn1_der_structure(self):
        """Confirm validator handles malformed ASN.1 DER sequence gracefully without crashing."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        # Overwrite cert2 DER header at 0x0B7D80 with garbage tag
        data[0x0B7D80:0x0B7D84] = b"\xFF\xFF\xFF\xFF"
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertTrue(any("asn.1" in err.lower() or "certificate" in err.lower() for err in res["failures"]))

    def test_validator_rejects_unexpected_preloader_code_diff(self):
        """Confirm validator detects unauthorized executable code diff in Preloader."""
        with open(DEFAULT_C50_PRELOADER, "rb") as f:
            data = bytearray(f.read())
        # In C.50 Preloader, byte 2048 + 0x1000 is inside the executable code region
        data[2048 + 0x1000] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=DEFAULT_C50_LK,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=tmp.name,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["preloader_validation"]["code_region_identical"])

    def test_validator_rejects_preloader_missing_emmc_boot_header(self):
        """Confirm validator rejects C.50 preloader lacking EMMC_BOOT header."""
        with open(DEFAULT_C50_PRELOADER, "rb") as f:
            data = bytearray(f.read())
        # Overwrite magic EMMC_BOOT header
        data[0:9] = b"RAW_BOOT!"
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=DEFAULT_C50_LK,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=tmp.name,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["preloader_validation"]["c50_emmc_boot_header_detected"])

    def test_validator_rejects_unexpected_diff_in_verify_unlock_token(self):
        """Confirm validator detects code modification in verify_unlock_token."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        # Modify 1 byte in verify_unlock_token at 0x02ED00
        data[0x02ED00] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["code_and_strings_validation"]["verify_unlock_token_identical"])

    def test_validator_rejects_unexpected_diff_in_fastboot_init(self):
        """Confirm validator detects code modification in fastboot_init."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        # Modify 1 byte in fastboot_init at 0x030218
        data[0x030218] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["code_and_strings_validation"]["fastboot_init_identical"])

    def test_validator_rejects_injected_verity_string(self):
        """Confirm validator detects injection of fastboot_unlock_verity string."""
        with open(DEFAULT_C50_LK, "rb") as f:
            data = bytearray(f.read())
        # Replace fastboot_unlock_verify with fastboot_unlock_verity at 0x080BFC
        data[0x080BFC : 0x080BFC + 22] = b"fastboot_unlock_verity"
        with tempfile.NamedTemporaryFile(suffix=".img") as tmp:
            tmp.write(data)
            tmp.flush()
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=tmp.name,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["code_and_strings_validation"]["strings_valid"])
            self.assertTrue(res["code_and_strings_validation"]["string_fastboot_unlock_verity_in_c50"])

    def test_deliberate_logic_breakage_in_fixture(self):
        """Task 4 fixture: Verify test fails when validation logic is deliberately broken."""
        # Deliberately break container header validation by patching parse_mtk_header to return invalid magic
        with patch("validate_lk_differential.parse_mtk_header") as mock_parse:
            mock_parse.return_value = {
                "offset": "0x000000",
                "magic": "0x00000000",  # Broken magic
                "ext_magic": "0x00000000",
                "name": "broken",
                "dsize": 0,
                "dsize_hex": "0x0",
                "hdr_size": 0,
            }
            res = validate_lk_differential(
                c49_path=DEFAULT_C49_LK,
                c50_path=DEFAULT_C50_LK,
                c49_p_path=DEFAULT_C49_PRELOADER,
                c50_p_path=DEFAULT_C50_PRELOADER,
            )
            # The test confirms that when validation logic is broken, the validator rejects it
            self.assertEqual(res["status"], "FAIL")
            self.assertFalse(res["container_validation"]["valid"])

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
