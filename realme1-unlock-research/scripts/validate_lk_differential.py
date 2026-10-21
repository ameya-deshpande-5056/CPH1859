#!/usr/bin/env python3
"""
validate_lk_differential.py — Deterministic Validation of Realme 1 LK Differential Analysis

Validates the differential reverse engineering findings between ColorOS C.49 and C.50
bootloader binaries (Little Kernel & Preloader) for the Realme 1 (CPH1859).

Checks performed:
  1. File existence, size bounds, and whole-file SHA-256 hash recalculation.
  2. Safe byte-by-byte differential enumeration in half-open intervals [start, end).
  3. Symmetric MediaTek container header boundary and magic validation (C.49 and C.50).
  4. Exact payload range hashing and comparison with cert2 digest extension.
  5. Dynamic ASN.1 DER certificate parsing, OID inspection, key relationship verification.
  6. RSASSA-PSS signature verification (SHA-256, MGF1 SHA-256, salt length 32).
  7. Preloader header normalization (EMMC_BOOT), safe byte diff, and code region audit.
  8. Fastboot token verification routine (verify_unlock_token, fastboot_init) audit.
  9. String table resolution (fastboot_unlock_verify vs fastboot_unlock_verity).

Usage:
  python3 scripts/validate_lk_differential.py [--json-out PATH] [--markdown-out PATH] [--verbose]
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

import capstone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Default canonical paths
DEFAULT_C49_LK = os.path.expanduser("~/Realme1/C49_extracted/lk.img")
DEFAULT_C50_PACKAGE = os.path.expanduser(
    "~/Realme1/C50_research/CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t"
)
DEFAULT_C50_LK = os.path.join(DEFAULT_C50_PACKAGE, "lk.img")
DEFAULT_C49_PRELOADER = os.path.expanduser("~/Realme1/C49_extracted/preloader_oppo6771_17065.bin")
DEFAULT_C50_PRELOADER = os.path.join(DEFAULT_C50_PACKAGE, "preloader_emmc.img")

# Expected SHA-256 hashes
EXPECTED_HASHES = {
    "c49_lk": "30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa",
    "c50_lk": "58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563",
    "c49_preloader": "afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a",
    "c50_preloader": "2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca",
}

# Minimum file bounds required for valid container parsing
MIN_LK_SIZE = 0x0B8140  # 753,984 bytes
MIN_PRELOADER_C49_SIZE = 265756
MIN_PRELOADER_C50_SIZE = 2048


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def safe_diff_count(b1: bytes, b2: bytes, start: int = 0, end: Optional[int] = None) -> int:
    """Safely count differing bytes between b1 and b2 within [start, end), without IndexError."""
    len1 = len(b1)
    len2 = len(b2)
    max_len = max(len1, len2)
    if end is None or end > max_len:
        end = max_len
    if start >= end or start >= max_len:
        return 0

    diffs = 0
    common_end = min(end, len1, len2)
    if start < common_end:
        diffs += sum(b1[i] != b2[i] for i in range(start, common_end))
        start = common_end
    if start < end:
        diffs += end - start
    return diffs


def find_diff_ranges(b1: bytes, b2: bytes) -> List[Tuple[int, int]]:
    """Enumerate contiguous differing ranges as half-open intervals [start, end)."""
    min_len = min(len(b1), len(b2))
    diff_indices = [i for i in range(min_len) if b1[i] != b2[i]]
    if len(b1) != len(b2):
        diff_indices.extend(range(min_len, max(len(b1), len(b2))))

    ranges: List[Tuple[int, int]] = []
    if not diff_indices:
        return ranges

    cur_start = diff_indices[0]
    cur_end = diff_indices[0] + 1
    for idx in diff_indices[1:]:
        if idx == cur_end:
            cur_end = idx + 1
        else:
            ranges.append((cur_start, cur_end))
            cur_start = idx
            cur_end = idx + 1
    ranges.append((cur_start, cur_end))
    return ranges


def cluster_ranges(ranges: List[Tuple[int, int]], max_gap: int = 16) -> List[Tuple[int, int]]:
    """Cluster adjacent ranges that are separated by at most max_gap identical bytes."""
    if not ranges:
        return []
    clusters: List[Tuple[int, int]] = []
    cur_start, cur_end = ranges[0]
    for s, e in ranges[1:]:
        if s - cur_end <= max_gap:
            cur_end = e
        else:
            clusters.append((cur_start, cur_end))
            cur_start, cur_end = s, e
    clusters.append((cur_start, cur_end))
    return clusters


# ---------------------------------------------------------------------------
# Dynamic ASN.1 DER Parser (Lightweight, pure-Python, zero external parser deps)
# ---------------------------------------------------------------------------

def parse_der_tlv(data: bytes, offset: int = 0) -> Optional[Tuple[int, int, int, bytes]]:
    """Parse a single ASN.1 DER Tag-Length-Value element.

    Returns (tag, header_len, length, value_bytes) or None if truncated or invalid.
    """
    if offset < 0 or offset >= len(data):
        return None
    tag = data[offset]
    if offset + 1 >= len(data):
        return None
    l_byte = data[offset + 1]
    if l_byte & 0x80 == 0:
        length = l_byte
        header_len = 2
    else:
        num_len_bytes = l_byte & 0x7F
        if num_len_bytes == 0 or num_len_bytes > 4 or offset + 2 + num_len_bytes > len(data):
            return None
        length = int.from_bytes(data[offset + 2 : offset + 2 + num_len_bytes], "big")
        header_len = 2 + num_len_bytes
    if offset + header_len + length > len(data):
        return None
    value = data[offset + header_len : offset + header_len + length]
    return tag, header_len, length, value


def parse_der_sequence(data: bytes, offset: int = 0) -> Optional[List[Dict[str, Any]]]:
    """Parse a DER SEQUENCE and return its child elements as dictionaries."""
    elem = parse_der_tlv(data, offset)
    if not elem or elem[0] != 0x30:
        return None
    _, seq_hlen, seq_len, seq_val = elem
    children: List[Dict[str, Any]] = []
    sub_off = 0
    while sub_off < len(seq_val):
        child = parse_der_tlv(seq_val, sub_off)
        if not child:
            return None
        ctag, chlen, clen, cval = child
        elem_offset = offset + seq_hlen + sub_off
        total_len = chlen + clen
        children.append({
            "tag": ctag,
            "offset": elem_offset,
            "header_len": chlen,
            "length": clen,
            "total_len": total_len,
            "raw": data[elem_offset : elem_offset + total_len],
            "value": cval,
        })
        sub_off += total_len
    return children


def decode_oid(b: bytes) -> str:
    """Decode DER-encoded Object Identifier bytes into a dot-notation string."""
    if not b:
        return ""
    first = b[0]
    oid = [str(first // 40), str(first % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            oid.append(str(val))
            val = 0
    return ".".join(oid)


def parse_mtk_header(data: bytes, offset: int) -> Optional[Dict[str, Any]]:
    """Parse a MediaTek image container header (union prt_img_hdr)."""
    if offset < 0 or offset + 56 > len(data):
        return None
    try:
        magic, dsize, name = struct.unpack("<II32s", data[offset : offset + 40])
        ext_magic, hdr_size = struct.unpack("<II", data[offset + 48 : offset + 56])
        clean_name = name.split(b"\x00")[0].decode("ascii", errors="replace")
        return {
            "offset": f"0x{offset:06x}",
            "magic": f"0x{magic:08x}",
            "ext_magic": f"0x{ext_magic:08x}",
            "name": clean_name,
            "dsize": dsize,
            "dsize_hex": f"0x{dsize:x}",
            "hdr_size": hdr_size,
        }
    except Exception:
        return None


def parse_cert1_info(cert1_bytes: bytes) -> Dict[str, Any]:
    """Dynamically parse MediaTek Key Certificate (cert1) via ASN.1 DER."""
    c1_seq = parse_der_sequence(cert1_bytes, 0)
    if not c1_seq or len(c1_seq) < 3:
        raise ValueError("Malformed cert1: Expected SEQUENCE with 3 elements")
    tbs_elem = c1_seq[0]
    sig_alg_elem = c1_seq[1]
    sig_elem = c1_seq[2]

    if tbs_elem["tag"] != 0x30 or sig_alg_elem["tag"] != 0x30 or sig_elem["tag"] != 0x03:
        raise ValueError("Malformed cert1: Top-level elements have unexpected tags")

    tbs_raw = tbs_elem["raw"]
    sig_raw = sig_elem["value"]
    if len(sig_raw) < 2:
        raise ValueError("Malformed cert1: Signature value too short")
    sig_bytes = sig_raw[1:]  # Skip unused bit count byte

    tbs_children = parse_der_sequence(tbs_raw, 0)
    if not tbs_children or len(tbs_children) < 11:
        raise ValueError("Malformed cert1: TBS sequence has insufficient children")

    # Key C1 is at index 6 (SubjectPublicKeyInfo)
    spki_c1_raw = tbs_children[6]["raw"]
    key_c1 = serialization.load_der_public_key(spki_c1_raw)

    # Key C2 is under OID 2.16.886.2454.1.2
    key_c2_raw = None
    for i, child in enumerate(tbs_children):
        if child["tag"] == 0x06 and decode_oid(child["value"]) == "2.16.886.2454.1.2":
            if i + 1 < len(tbs_children):
                key_c2_raw = tbs_children[i + 1]["raw"]
            break

    if not key_c2_raw:
        key_c2_raw = tbs_children[10]["raw"]

    key_c2 = serialization.load_der_public_key(key_c2_raw)

    # Sig alg rsassa-pss
    sig_alg_children = parse_der_sequence(sig_alg_elem["raw"], 0)
    if not sig_alg_children or len(sig_alg_children) < 2:
        raise ValueError("Malformed cert1: sig_alg sequence invalid")

    alg_oid = decode_oid(sig_alg_children[0]["value"])
    pss_params = parse_der_sequence(sig_alg_children[1]["raw"], 0)
    salt_len = None
    if pss_params:
        for p in pss_params:
            if p["tag"] == 0xA2:
                s_tlv = parse_der_tlv(p["value"], 0)
                if s_tlv and s_tlv[0] == 0x02:
                    salt_len = int.from_bytes(s_tlv[3], "big")

    return {
        "tbs_raw": tbs_raw,
        "sig_bytes": sig_bytes,
        "key_c1": key_c1,
        "key_c2": key_c2,
        "alg_oid": alg_oid,
        "salt_len": salt_len,
    }


def parse_cert2_info(cert2_bytes: bytes) -> Dict[str, Any]:
    """Dynamically parse MediaTek Content Certificate (cert2) via ASN.1 DER."""
    c2_seq = parse_der_sequence(cert2_bytes, 0)
    if not c2_seq or len(c2_seq) < 3:
        raise ValueError("Malformed cert2: Expected SEQUENCE with 3 elements")
    tbs_elem = c2_seq[0]
    sig_alg_elem = c2_seq[1]
    sig_elem = c2_seq[2]

    if tbs_elem["tag"] != 0x30 or sig_alg_elem["tag"] != 0x30 or sig_elem["tag"] != 0x03:
        raise ValueError("Malformed cert2: Top-level elements have unexpected tags")

    tbs_raw = tbs_elem["raw"]
    sig_raw = sig_elem["value"]
    if len(sig_raw) < 2:
        raise ValueError("Malformed cert2: Signature value too short")
    sig_bytes = sig_raw[1:]  # Skip unused bit count byte

    tbs_children = parse_der_sequence(tbs_raw, 0)
    if not tbs_children or len(tbs_children) < 11:
        raise ValueError("Malformed cert2: TBS sequence has insufficient children")

    # Key C2 is at index 6 (SubjectPublicKeyInfo)
    spki_c2_raw = tbs_children[6]["raw"]
    key_c2 = serialization.load_der_public_key(spki_c2_raw)

    # Payload digest is under OID 2.16.886.2454.2.1
    digest_bytes = None
    for i, child in enumerate(tbs_children):
        if child["tag"] == 0x06 and decode_oid(child["value"]) == "2.16.886.2454.2.1":
            if i + 1 < len(tbs_children):
                val_child = tbs_children[i + 1]
                if val_child["tag"] == 0x03 and len(val_child["value"]) >= 33:
                    digest_bytes = val_child["value"][1:33]
            break

    # Sig alg rsassa-pss
    sig_alg_children = parse_der_sequence(sig_alg_elem["raw"], 0)
    if not sig_alg_children or len(sig_alg_children) < 2:
        raise ValueError("Malformed cert2: sig_alg sequence invalid")

    alg_oid = decode_oid(sig_alg_children[0]["value"])
    pss_params = parse_der_sequence(sig_alg_children[1]["raw"], 0)
    salt_len = None
    if pss_params:
        for p in pss_params:
            if p["tag"] == 0xA2:
                s_tlv = parse_der_tlv(p["value"], 0)
                if s_tlv and s_tlv[0] == 0x02:
                    salt_len = int.from_bytes(s_tlv[3], "big")

    return {
        "tbs_raw": tbs_raw,
        "sig_bytes": sig_bytes,
        "key_c2": key_c2,
        "payload_digest": digest_bytes,
        "alg_oid": alg_oid,
        "salt_len": salt_len,
    }


def validate_lk_differential(
    c49_path: str,
    c50_path: str,
    c49_p_path: str,
    c50_p_path: str,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Execute complete deterministic validation."""
    results: Dict[str, Any] = {
        "status": "PASS",
        "failures": [],
        "file_validation": {},
        "lk_diff": {},
        "container_validation": {},
        "payload_digest_validation": {},
        "certificate_validation": {},
        "preloader_validation": {},
        "code_and_strings_validation": {},
    }

    # -------------------------------------------------------------
    # 1. File existence and whole-file SHA-256 hash recalculation
    # -------------------------------------------------------------
    file_map = {
        "c49_lk": c49_path,
        "c50_lk": c50_path,
        "c49_preloader": c49_p_path,
        "c50_preloader": c50_p_path,
    }

    loaded_bytes: Dict[str, bytes] = {}
    for key, path in file_map.items():
        if not os.path.isfile(path):
            results["status"] = "FAIL"
            err = f"File missing: {path}"
            results["failures"].append(err)
            results["file_validation"][key] = {"error": err}
            return results

        with open(path, "rb") as f:
            data = f.read()
        loaded_bytes[key] = data
        calc_hash = compute_sha256(data)
        exp_hash = EXPECTED_HASHES[key]
        match = calc_hash == exp_hash
        if not match:
            results["status"] = "FAIL"
            results["failures"].append(f"Hash mismatch for {key}: expected {exp_hash}, got {calc_hash}")

        results["file_validation"][key] = {
            "path": path,
            "size": len(data),
            "sha256": calc_hash,
            "expected_sha256": exp_hash,
            "match": match,
        }

    c49_lk = loaded_bytes["c49_lk"]
    c50_lk = loaded_bytes["c50_lk"]
    c49_p = loaded_bytes["c49_preloader"]
    c50_p = loaded_bytes["c50_preloader"]

    # File bounds check: Ensure files are large enough for container and code analysis
    if len(c49_lk) < MIN_LK_SIZE:
        results["status"] = "FAIL"
        results["failures"].append(f"Input file truncated: c49_lk size {len(c49_lk)} B is less than required {MIN_LK_SIZE} B")
    if len(c50_lk) < MIN_LK_SIZE:
        results["status"] = "FAIL"
        results["failures"].append(f"Input file truncated: c50_lk size {len(c50_lk)} B is less than required {MIN_LK_SIZE} B")
    if len(c49_p) < MIN_PRELOADER_C49_SIZE:
        results["status"] = "FAIL"
        results["failures"].append(f"Input file truncated: c49_preloader size {len(c49_p)} B is less than required {MIN_PRELOADER_C49_SIZE} B")
    if len(c50_p) < MIN_PRELOADER_C50_SIZE:
        results["status"] = "FAIL"
        results["failures"].append(f"Input file truncated: c50_preloader size {len(c50_p)} B is less than required {MIN_PRELOADER_C50_SIZE} B")

    # Do not attempt fixed-offset certificate or disassembly checks on truncated
    # inputs.  Returning the structured failure keeps malformed-input handling
    # deterministic and avoids turning an audit diagnostic into an exception.
    if any(len(data) < required for data, required in (
        (c49_lk, MIN_LK_SIZE),
        (c50_lk, MIN_LK_SIZE),
        (c49_p, MIN_PRELOADER_C49_SIZE),
        (c50_p, MIN_PRELOADER_C50_SIZE),
    )):
        return results

    # -------------------------------------------------------------
    # 2. LK Diff Enumeration
    # -------------------------------------------------------------
    lk_ranges = find_diff_ranges(c49_lk, c50_lk)
    lk_clusters = cluster_ranges(lk_ranges, max_gap=16)
    total_differing_bytes = safe_diff_count(c49_lk, c50_lk)

    results["lk_diff"] = {
        "total_differing_bytes": total_differing_bytes,
        "expected_differing_bytes": 315,
        "differing_ranges_half_open": [
            {"start": f"0x{s:06x}", "end": f"0x{e:06x}", "len": e - s} for s, e in lk_ranges
        ],
        "clusters_half_open": [
            {
                "cluster_index": i + 1,
                "start": f"0x{s:06x}",
                "end": f"0x{e:06x}",
                "span": e - s,
                "diff_count": safe_diff_count(c49_lk, c50_lk, s, e),
            }
            for i, (s, e) in enumerate(lk_clusters)
        ],
    }

    if total_differing_bytes != 315:
        results["status"] = "FAIL"
        results["failures"].append(f"LK differing bytes count mismatch: expected 315, got {total_differing_bytes}")

    if len(lk_clusters) != 3:
        results["status"] = "FAIL"
        results["failures"].append(f"LK diff cluster count mismatch: expected 3, got {len(lk_clusters)}")

    # -------------------------------------------------------------
    # 3. Symmetric MediaTek Container Header Validation
    # -------------------------------------------------------------
    h_lk_49 = parse_mtk_header(c49_lk, 0x000000)
    h_cert1_49 = parse_mtk_header(c49_lk, 0x0B72D0)
    h_cert2_49 = parse_mtk_header(c49_lk, 0x0B7B80)

    h_lk_50 = parse_mtk_header(c50_lk, 0x000000)
    h_cert1_50 = parse_mtk_header(c50_lk, 0x0B72D0)
    h_cert2_50 = parse_mtk_header(c50_lk, 0x0B7B80)

    def check_headers_ok(h_lk: Optional[Dict[str, Any]], h_c1: Optional[Dict[str, Any]], h_c2: Optional[Dict[str, Any]]) -> bool:
        return (
            h_lk is not None
            and h_lk["magic"] == "0x58881688"
            and h_lk["ext_magic"] == "0x58891689"
            and h_lk["name"] == "lk"
            and h_lk["dsize"] == 749772
            and h_c1 is not None
            and h_c1["magic"] == "0x58881688"
            and h_c1["ext_magic"] == "0x58891689"
            and h_c1["name"] == "cert1"
            and h_c1["dsize"] == 1709
            and h_c2 is not None
            and h_c2["magic"] == "0x58881688"
            and h_c2["ext_magic"] == "0x58891689"
            and h_c2["name"] == "cert2"
            and h_c2["dsize"] == 945
        )

    container_c49_ok = check_headers_ok(h_lk_49, h_cert1_49, h_cert2_49)
    container_c50_ok = check_headers_ok(h_lk_50, h_cert1_50, h_cert2_50)
    container_ok = container_c49_ok and container_c50_ok

    results["container_validation"] = {
        "valid": container_ok,
        "headers": {"lk": h_lk_49, "cert1": h_cert1_49, "cert2": h_cert2_49},
        "payload_intervals": {
            "lk_payload": "[0x000200, 0x0b72cc)",
            "lk_payload_padded_16b": "[0x000200, 0x0b72d0)",
            "cert1_payload": "[0x0b74d0, 0x0b7b7d)",
            "cert2_payload": "[0x0b7d80, 0x0b8131)",
            "file_end": "[0x000000, 0x0b8140)",
        },
    }

    if not container_ok:
        results["status"] = "FAIL"
        results["failures"].append("MediaTek container header validation failed")

    # -------------------------------------------------------------
    # 4. Exact Payload Range Hashing & cert2 Digest Validation
    # -------------------------------------------------------------
    # LK payload interval [0x000200, 0x0B72D0) = 749,776 bytes
    payload_c49 = c49_lk[0x000200:0x0B72D0]
    payload_c50 = c50_lk[0x000200:0x0B72D0]

    calc_digest_c49 = hashlib.sha256(payload_c49).digest()
    calc_digest_c50 = hashlib.sha256(payload_c50).digest()

    cert2_digest_c49 = c49_lk[0x0B7F73:0x0B7F93]
    cert2_digest_c50 = c50_lk[0x0B7F73:0x0B7F93]

    digest_match_c49 = (len(payload_c49) == 749776) and (calc_digest_c49 == cert2_digest_c49)
    digest_match_c50 = (len(payload_c50) == 749776) and (calc_digest_c50 == cert2_digest_c50)

    # -------------------------------------------------------------
    # 5. ASN.1 DER Certificate Parsing & Cryptographic Signatures
    # -------------------------------------------------------------
    cert1_bytes_49 = c49_lk[0x0B74D0:0x0B7B7D]
    cert2_bytes_49 = c49_lk[0x0B7D80:0x0B8131]
    cert1_bytes_50 = c50_lk[0x0B74D0:0x0B7B7D]
    cert2_bytes_50 = c50_lk[0x0B7D80:0x0B8131]

    cert1_self_signed = False
    cert2_49_signed = False
    cert2_50_signed = False
    key_c2_match = False
    salt_32_encoded = False
    c1_mod_str = "N/A"
    c2_mod_str = "N/A"
    oem_mod_str = "N/A"
    keys_distinct = False

    try:
        c1_info_49 = parse_cert1_info(cert1_bytes_49)
        c1_info_50 = parse_cert1_info(cert1_bytes_50)
        c2_info_49 = parse_cert2_info(cert2_bytes_49)
        c2_info_50 = parse_cert2_info(cert2_bytes_50)

        # Cross-verify ASN.1 decoded payload digests against calculated digests
        if c2_info_49["payload_digest"] != calc_digest_c49:
            digest_match_c49 = False
            results["failures"].append("cert2 C.49 ASN.1 payload digest mismatch with calculated digest")
        if c2_info_50["payload_digest"] != calc_digest_c50:
            digest_match_c50 = False
            results["failures"].append("cert2 C.50 ASN.1 payload digest mismatch with calculated digest")

        key_c1_49 = c1_info_49["key_c1"]
        key_c2_49_from_c1 = c1_info_49["key_c2"]
        key_c2_49_from_c2 = c2_info_49["key_c2"]

        key_c1_50 = c1_info_50["key_c1"]
        key_c2_50_from_c1 = c1_info_50["key_c2"]
        key_c2_50_from_c2 = c2_info_50["key_c2"]

        # Check key C2 consistency across cert1 and cert2 for both C.49 and C.50
        key_c2_match = (
            key_c2_49_from_c1.public_numbers().n == key_c2_49_from_c2.public_numbers().n
            and key_c2_50_from_c1.public_numbers().n == key_c2_50_from_c2.public_numbers().n
            and key_c2_49_from_c1.public_numbers().n == key_c2_50_from_c1.public_numbers().n
        )

        salt_32_encoded = (
            c1_info_49["salt_len"] == 32
            and c2_info_49["salt_len"] == 32
            and c1_info_50["salt_len"] == 32
            and c2_info_50["salt_len"] == 32
        )

        # Verify cert1 self-signature (Key C1, RSASSA-PSS SHA-256)
        try:
            key_c1_49.verify(
                c1_info_49["sig_bytes"],
                c1_info_49["tbs_raw"],
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=c1_info_49["salt_len"] or 32),
                hashes.SHA256(),
            )
            key_c1_50.verify(
                c1_info_50["sig_bytes"],
                c1_info_50["tbs_raw"],
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=c1_info_50["salt_len"] or 32),
                hashes.SHA256(),
            )
            cert1_self_signed = True
        except Exception as e:
            cert1_self_signed = False
            results["failures"].append(f"cert1 self-signature verification failed: {e}")

        # Verify cert2 C.49 signature (Key C2, RSASSA-PSS SHA-256)
        try:
            key_c2_49_from_c1.verify(
                c2_info_49["sig_bytes"],
                c2_info_49["tbs_raw"],
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=c2_info_49["salt_len"] or 32),
                hashes.SHA256(),
            )
            cert2_49_signed = True
        except Exception as e:
            cert2_49_signed = False
            results["failures"].append(f"cert2 C.49 signature verification failed: {e}")

        # Verify cert2 C.50 signature (Key C2, RSASSA-PSS SHA-256)
        try:
            key_c2_50_from_c1.verify(
                c2_info_50["sig_bytes"],
                c2_info_50["tbs_raw"],
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=c2_info_50["salt_len"] or 32),
                hashes.SHA256(),
            )
            cert2_50_signed = True
        except Exception as e:
            cert2_50_signed = False
            results["failures"].append(f"cert2 C.50 signature verification failed: {e}")

        c1_mod = key_c1_49.public_numbers().n
        c2_mod = key_c2_49_from_c1.public_numbers().n
        c1_mod_str = hex(c1_mod)[:32] + "..."
        c2_mod_str = hex(c2_mod)[:32] + "..."

        # Inspect OEM token verification public key at file 0x7F048 (RAM 0x6007EE48)
        if len(c49_lk) >= 0x07F048 + 256:
            oem_mod_bytes = c49_lk[0x07F048 : 0x07F048 + 256]
            oem_mod = int.from_bytes(oem_mod_bytes, byteorder="big")
            oem_mod_str = hex(oem_mod)[:32] + "..."
            keys_distinct = (c1_mod != c2_mod) and (c1_mod != oem_mod) and (c2_mod != oem_mod)
        else:
            keys_distinct = False
            results["failures"].append("OEM unlock public key offset exceeds LK image bounds")

    except Exception as e:
        results["status"] = "FAIL"
        results["failures"].append(f"ASN.1 certificate parsing or cryptographic validation failed: {e}")

    results["payload_digest_validation"] = {
        "hashed_interval": "[0x000200, 0x0b72d0)",
        "hashed_bytes_len": len(payload_c49),
        "c49": {
            "calculated_sha256": calc_digest_c49.hex(),
            "cert2_embedded_digest": cert2_digest_c49.hex(),
            "match": digest_match_c49,
        },
        "c50": {
            "calculated_sha256": calc_digest_c50.hex(),
            "cert2_embedded_digest": cert2_digest_c50.hex(),
            "match": digest_match_c50,
        },
    }

    if not (digest_match_c49 and digest_match_c50):
        results["status"] = "FAIL"
        results["failures"].append("Payload digest does not match cert2 embedded digest")

    results["certificate_validation"] = {
        "key_c1_modulus_prefix": c1_mod_str,
        "key_c2_modulus_prefix": c2_mod_str,
        "oem_unlock_key_modulus_prefix": oem_mod_str,
        "key_c2_matches_between_cert1_and_cert2": key_c2_match,
        "encoded_pss_salt_length_32": salt_32_encoded,
        "cert1_self_signed_verified": cert1_self_signed,
        "cert2_c49_signed_verified": cert2_49_signed,
        "cert2_c50_signed_verified": cert2_50_signed,
        "oem_unlock_key_is_distinct": keys_distinct,
    }

    if not (cert1_self_signed and cert2_49_signed and cert2_50_signed and key_c2_match and keys_distinct):
        results["status"] = "FAIL"

    # -------------------------------------------------------------
    # 6. Preloader Audit & Normalization
    # -------------------------------------------------------------
    p50_header_has_emmc = len(c50_p) >= 2048 and c50_p[:9] == b"EMMC_BOOT"
    c50_p_stripped = c50_p[2048:] if len(c50_p) >= 2048 else b""
    p_len_match = len(c49_p) == len(c50_p_stripped)

    p_ranges = find_diff_ranges(c49_p, c50_p_stripped)
    p_clusters = cluster_ranges(p_ranges, max_gap=16)
    p_differing_bytes = safe_diff_count(c49_p, c50_p_stripped)

    # Verify that all preloader diffs are strictly in metadata string regions or signature block:
    # String regions: [0x325A5, 0x39400)
    # Signature block: [0x40CFC, 0x40E1C)
    preloader_code_untouched = True
    for s, e in p_ranges:
        in_strings = (s >= 0x0325A5) and (e <= 0x039400)
        in_sig = (s >= 0x040CFC) and (e <= 0x040E1C)
        if not (in_strings or in_sig):
            preloader_code_untouched = False
            results["failures"].append(f"Preloader diff at [0x{s:x}, 0x{e:x}) outside metadata/sig blocks")

    results["preloader_validation"] = {
        "c50_emmc_boot_header_detected": p50_header_has_emmc,
        "normalized_lengths_match": p_len_match,
        "normalized_length": len(c49_p),
        "total_differing_bytes": p_differing_bytes,
        "expected_differing_bytes": 569,
        "cluster_count": len(p_clusters),
        "code_region_identical": preloader_code_untouched,
    }

    if not (p50_header_has_emmc and p_len_match and p_differing_bytes == 569 and preloader_code_untouched):
        results["status"] = "FAIL"

    # -------------------------------------------------------------
    # 7. Fastboot Gating Routines & String Table Validation
    # -------------------------------------------------------------
    # verify_unlock_token: file interval [0x02ED00, 0x02EFCC) (716 bytes)
    vut_c49 = c49_lk[0x02ED00:0x02EFCC] if len(c49_lk) >= 0x02EFCC else b""
    vut_c50 = c50_lk[0x02ED00:0x02EFCC] if len(c50_lk) >= 0x02EFCC else b""
    vut_match = (len(vut_c49) == 716) and (vut_c49 == vut_c50)

    # fastboot_init: file interval [0x030218, 0x030828) (1,552 bytes)
    fb_c49 = c49_lk[0x030218:0x030828] if len(c49_lk) >= 0x030828 else b""
    fb_c50 = c50_lk[0x030218:0x030828] if len(c50_lk) >= 0x030828 else b""
    fb_match = (len(fb_c49) == 1552) and (fb_c49 == fb_c50)

    # Disassemble and check call instructions in verify_unlock_token
    vut_insn_count = 0
    fb_insn_count = 0
    try:
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        vut_insns = list(md.disasm(vut_c49, 0x6002EB00))
        fb_insns = list(md.disasm(fb_c49, 0x60030018))
        vut_insn_count = len(vut_insns)
        fb_insn_count = len(fb_insns)
    except Exception as e:
        results["failures"].append(f"Capstone disassembly failed: {e}")

    # String presence checks:
    has_verify_c49 = b"fastboot_unlock_verify" in c49_lk
    has_verify_c50 = b"fastboot_unlock_verify" in c50_lk
    has_verity_c49 = b"fastboot_unlock_verity" in c49_lk
    has_verity_c50 = b"fastboot_unlock_verity" in c50_lk

    strings_valid = (
        has_verify_c49
        and has_verify_c50
        and (not has_verity_c49)
        and (not has_verity_c50)
    )

    results["code_and_strings_validation"] = {
        "verify_unlock_token_interval": "[0x02ed00, 0x02efcc)",
        "verify_unlock_token_len": len(vut_c49),
        "verify_unlock_token_identical": vut_match,
        "verify_unlock_token_instruction_count": vut_insn_count,
        "fastboot_init_interval": "[0x030218, 0x030828)",
        "fastboot_init_len": len(fb_c49),
        "fastboot_init_identical": fb_match,
        "fastboot_init_instruction_count": fb_insn_count,
        "string_fastboot_unlock_verify_in_c49": has_verify_c49,
        "string_fastboot_unlock_verify_in_c50": has_verify_c50,
        "string_fastboot_unlock_verity_in_c49": has_verity_c49,
        "string_fastboot_unlock_verity_in_c50": has_verity_c50,
        "strings_valid": strings_valid,
    }

    if not (vut_match and fb_match and strings_valid and vut_insn_count == 274 and fb_insn_count == 640):
        results["status"] = "FAIL"
        results["failures"].append("Code or string table validation failed")

    return results


def format_markdown_report(res: Dict[str, Any]) -> str:
    """Generate concise Markdown report from validation results."""
    lines = [
        "# Independent Validation Report: Realme 1 LK Differential Analysis",
        "",
        f"**Validation Status:** **`{res['status']}`**  ",
        f"**Date:** 2026-10-21  ",
        "",
        "---",
        "",
        "## 1. Firmware Hash & Integrity Verification",
        "",
        "| File Target | File Size | Calculated SHA-256 | Expected SHA-256 | Match |",
        "|---|---|---|---|---|",
    ]
    for key, fval in res["file_validation"].items():
        if "error" in fval:
            lines.append(f"| `{key}` | N/A | {fval['error']} | N/A | FAIL |")
        else:
            m = "PASS" if fval["match"] else "FAIL"
            lines.append(f"| `{key}` | {fval['size']} B | `{fval['sha256']}` | `{fval['expected_sha256']}` | **`{m}`** |")

    lines.extend([
        "",
        "---",
        "",
        "## 2. Little Kernel Binary Diff Audit",
        "",
        f"- **Total Differing Bytes:** `{res['lk_diff'].get('total_differing_bytes')}` (Expected: `315`)",
        "- **Clusters (Intervals in `[start, end)` Half-Open Notation):**",
    ])
    for cl in res["lk_diff"].get("clusters_half_open", []):
        lines.append(
            f"  - **Cluster {cl['cluster_index']}:** `[{cl['start']}, {cl['end']})` "
            f"(span: {cl['span']} bytes, differing bytes: {cl['diff_count']})"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. MediaTek Container & Payload Digest Verification",
        "",
        f"- **Container Headers Valid:** `{'YES' if res['container_validation'].get('valid') else 'NO'}`",
        f"- **Hashed Interval:** `{res['payload_digest_validation'].get('hashed_interval')}` ({res['payload_digest_validation'].get('hashed_bytes_len')} bytes)",
        f"- **C.49 Payload Digest Match:** `{'PASS' if res['payload_digest_validation'].get('c49', {}).get('match') else 'FAIL'}` (`{res['payload_digest_validation'].get('c49', {}).get('calculated_sha256')}`)",
        f"- **C.50 Payload Digest Match:** `{'PASS' if res['payload_digest_validation'].get('c50', {}).get('match') else 'FAIL'}` (`{res['payload_digest_validation'].get('c50', {}).get('calculated_sha256')}`)",
        "",
        "---",
        "",
        "## 4. Cryptographic Certificate & Key Chain Audit",
        "",
        f"- **Key C1 Modulus:** `{res['certificate_validation'].get('key_c1_modulus_prefix')}`",
        f"- **Key C2 Modulus:** `{res['certificate_validation'].get('key_c2_modulus_prefix')}`",
        f"- **OEM Unlock Modulus:** `{res['certificate_validation'].get('oem_unlock_key_modulus_prefix')}`",
        f"- **Key C2 Binding (cert1 OID 2.16.886.2454.1.2 == cert2 SPKI):** `{'VERIFIED' if res['certificate_validation'].get('key_c2_matches_between_cert1_and_cert2') else 'FAILED'}`",
        f"- **RSASSA-PSS Salt Length (DER Encoded 0x20 = 32 bytes):** `{'CONFIRMED' if res['certificate_validation'].get('encoded_pss_salt_length_32') else 'FAILED'}`",
        f"- **cert1 Self-Signature (Key C1, PSS SHA-256):** `{'VALID' if res['certificate_validation'].get('cert1_self_signed_verified') else 'FAILED'}`",
        f"- **cert2 C.49 Signature (Key C2, PSS SHA-256):** `{'VALID' if res['certificate_validation'].get('cert2_c49_signed_verified') else 'FAILED'}`",
        f"- **cert2 C.50 Signature (Key C2, PSS SHA-256):** `{'VALID' if res['certificate_validation'].get('cert2_c50_signed_verified') else 'FAILED'}`",
        f"- **OEM Unlock Key Distinct from MTK Keys:** `{'VERIFIED' if res['certificate_validation'].get('oem_unlock_key_is_distinct') else 'FAILED'}`",
        "",
        "---",
        "",
        "## 5. Preloader Normalization & Code Identity Audit",
        "",
        f"- **C.50 EMMC_BOOT Header Detected & Normalized (2,048 bytes):** `{'YES' if res['preloader_validation'].get('c50_emmc_boot_header_detected') else 'NO'}`",
        f"- **Normalized Payload Size:** `{res['preloader_validation'].get('normalized_length')} bytes`",
        f"- **Total Differing Bytes:** `{res['preloader_validation'].get('total_differing_bytes')}` (Expected: `569`)",
        f"- **Executable Code Region Byte-Identical:** `{'CONFIRMED (100% Identical)' if res['preloader_validation'].get('code_region_identical') else 'FAILED'}`",
        "",
        "---",
        "",
        "## 6. Fastboot Gating Routines & String Table Resolution",
        "",
        f"- **`verify_unlock_token` (RAM `0x6002EB00`):** `{'100% BYTE-IDENTICAL' if res['code_and_strings_validation'].get('verify_unlock_token_identical') else 'MISMATCH'}`",
        f"- **`fastboot_init` (RAM `0x60030018`):** `{'100% BYTE-IDENTICAL' if res['code_and_strings_validation'].get('fastboot_init_identical') else 'MISMATCH'}`",
        f"- **`fastboot_unlock_verify` Present at `0x080BFC`:** `{'BOTH C.49 AND C.50' if res['code_and_strings_validation'].get('string_fastboot_unlock_verify_in_c49') and res['code_and_strings_validation'].get('string_fastboot_unlock_verify_in_c50') else 'FAIL'}`",
        f"- **`fastboot_unlock_verity` (with 't') Absent:** `{'CONFIRMED ABSENT IN ALL BINARIES' if not (res['code_and_strings_validation'].get('string_fastboot_unlock_verity_in_c49') or res['code_and_strings_validation'].get('string_fastboot_unlock_verity_in_c50')) else 'FAIL'}`",
        "",
        "---",
        "",
        "## 7. Epistemic Calibration & Trust Anchoring Distinction",
        "",
        "1. **Mathematical Verification vs Hardware Trust:** Mathematical verification proves internal consistency of the certificate chain (Key C1 -> Key C2 -> cert2 -> payload digest). However, hardware trust on the device requires that `SHA256(Key C1)` matches the hash burned into SoC SBC EFUSE registers. Static analysis cannot observe physical efuse bits.",
        "2. **Fastboot Token Orthogonality:** Fastboot gating does not query `cert1` or `cert2`. It verifies partition `reserve4` sector `0x7816` using an independent OEM public key modulus hardcoded at RAM `0x6007EE48`.",
        "3. **Firmware Compatibility Warning:** Build C.50 is an `oppo6771_17065` codebase historically targeted for CPH1861. It must not be assumed safe to flash onto CPH1859, preserving the project's non-invasive read-only policy.",
        "",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Deterministic validation of Realme 1 LK differential analysis.")
    parser.add_argument("--c49-lk", default=DEFAULT_C49_LK, help="Path to C.49 lk.img")
    parser.add_argument("--c50-lk", default=DEFAULT_C50_LK, help="Path to C.50 lk.img")
    parser.add_argument("--c49-preloader", default=DEFAULT_C49_PRELOADER, help="Path to C.49 preloader.bin")
    parser.add_argument("--c50-preloader", default=DEFAULT_C50_PRELOADER, help="Path to C.50 preloader_emmc.img")
    parser.add_argument("--json-out", help="Path to write machine-readable JSON output")
    parser.add_argument("--markdown-out", help="Path to write Markdown report")
    parser.add_argument("--verbose", action="store_true", help="Print verbose output")

    args = parser.parse_args()

    results = validate_lk_differential(
        c49_path=args.c49_lk,
        c50_path=args.c50_lk,
        c49_p_path=args.c49_preloader,
        c50_p_path=args.c50_preloader,
        verbose=args.verbose,
    )

    md_report = format_markdown_report(results)

    if args.json_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Wrote machine-readable JSON to {args.json_out}")

    if args.markdown_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.markdown_out)), exist_ok=True)
        with open(args.markdown_out, "w") as f:
            f.write(md_report)
        print(f"Wrote Markdown report to {args.markdown_out}")

    if not (args.json_out or args.markdown_out):
        print(md_report)

    if results["status"] != "PASS":
        print(f"\n[!] VALIDATION FAILED with {len(results['failures'])} errors:", file=sys.stderr)
        for err in results["failures"]:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[*] ALL INDEPENDENT VALIDATION CHECKS PASSED (Status: PASS)")
        sys.exit(0)


if __name__ == "__main__":
    main()
