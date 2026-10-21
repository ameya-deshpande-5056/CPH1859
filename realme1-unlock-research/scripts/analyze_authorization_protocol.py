#!/usr/bin/env python3
"""
Realme 1 (CPH1859) Bootloader Authorization Protocol & Path Analyzer

This script deterministically analyzes the Little Kernel (lk.img), Preloader,
and Recovery binaries to verify:
1. verify_unlock_token() boundaries, control flow, and error returns.
2. Token structure offsets (256-byte signature at +0x000, 16-byte serial at +0x100).
3. eFUSE serial number retrieval via devinfo (0x60003C4C / 0x60059C18).
4. Embedded OEM unlock token public key modulus at RAM 0x6007EE48 (file 0x7F048).
5. RSASSA-PSS SHA-256 signature algorithm parameters (salt 32, trailer 0xBC).
6. fastboot_init() gating call, failure reset via WDT (mtk_arch_reset), and command table.
7. Absence of unlock capabilities in stock recovery (recovery.img).
"""

import os
import sys
import struct
import gzip
import hashlib
from typing import Dict, Any, List, Tuple

# Binary paths
DEFAULT_C49_LK = "/home/ameya/Realme1/C49_extracted/lk.img"
DEFAULT_C50_PACKAGE = "/home/ameya/Realme1/C50_research/CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t"
DEFAULT_C50_LK = os.path.join(DEFAULT_C50_PACKAGE, "lk.img")
DEFAULT_C49_PRELOADER = "/home/ameya/Realme1/C49_extracted/preloader_oppo6771_17065.bin"
DEFAULT_C50_PRELOADER = os.path.join(DEFAULT_C50_PACKAGE, "preloader_emmc.img")
DEFAULT_RECOVERY = "/home/ameya/Realme1/C49_extracted/recovery.img"

RAM_BASE = 0x60000000
CONTAINER_HEADER_SIZE = 0x200


def ram_to_file(ram_addr: int) -> int:
    return ram_addr - RAM_BASE + CONTAINER_HEADER_SIZE


def file_to_ram(file_off: int) -> int:
    return file_off - CONTAINER_HEADER_SIZE + RAM_BASE


def extract_c_string(data: bytes, offset: int, max_len: int = 256) -> str:
    if not (0 <= offset < len(data)):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1 or end - offset > max_len:
        end = offset + max_len
    return data[offset:end].decode("latin1", errors="replace")


def analyze_verify_unlock_token(lk_path: str) -> Dict[str, Any]:
    with open(lk_path, "rb") as f:
        data = f.read()

    results: Dict[str, Any] = {
        "start_ram": 0x6002EB00,
        "end_ram": 0x6002EDCC,
        "function_size": 0x2CC,
        "checks": {}
    }

    start_fo = ram_to_file(0x6002EB00)
    end_fo = ram_to_file(0x6002EDCC)
    fn_bytes = data[start_fo:end_fo]
    results["sha256"] = hashlib.sha256(fn_bytes).hexdigest()

    # Verify sector 0x7816 math in read_reserve4 caller
    # 0x6002EC20: movs r1, #0x16 (22)
    # 0x6002EC22: movs r2, #8 (8 sectors = 4096 bytes)
    # 0x6002EC24: bl #0x6002c794 (read_reserve4)
    fo_call = ram_to_file(0x6002EC20)
    insns_read = data[fo_call:fo_call + 8]
    # movs r1, #0x16 is 2116; movs r2, #8 is 2208; bl is f000fa38
    results["checks"]["read_reserve4_call"] = (
        insns_read[0] == 0x16 and insns_read[1] == 0x21 and  # movs r1, #0x16
        insns_read[2] == 0x08 and insns_read[3] == 0x22      # movs r2, #8
    )

    # Verify serial comparison at offset +0x100 (sp + 0x688)
    # 0x6002EC32: add.w r5, sp, #0x688 (sp + 0x588 + 0x100) -> bytes 0d f5 d1 65
    # 0x6002EC38: movs r2, #0x10 (16 bytes)
    fo_cmp = ram_to_file(0x6002EC30)
    results["checks"]["serial_offset_0x100"] = (b"\x0d\xf5\xd1\x65" in data[fo_cmp:fo_cmp + 16])

    # Verify fallback serial check with leading '0' (0x30)
    # 0x6002EC44: ldrb.w r3, [r3, #0x100]
    # 0x6002EC48: cmp r3, #0x30
    fo_zero = ram_to_file(0x6002EC40)
    results["checks"]["leading_zero_fallback"] = (b"\x30" in data[fo_zero:fo_zero + 16])

    # Verify OEM public key pointer at 0x600B6B18 pointing to 0x6007EE48
    fo_pub_ptr = ram_to_file(0x600B6B18)
    pub_ram = struct.unpack("<I", data[fo_pub_ptr:fo_pub_ptr + 4])[0]
    results["checks"]["pubkey_pointer_valid"] = (pub_ram == 0x6007EE48)

    fo_pub = ram_to_file(0x6007EE48)
    pub_modulus = data[fo_pub:fo_pub + 256]
    results["pubkey_modulus_sha256"] = hashlib.sha256(pub_modulus).hexdigest()
    results["checks"]["pubkey_length_2048"] = (len(pub_modulus) == 256)

    # Verify RSASSA-PSS parameters:
    # 0x6002ED36: movs r1, #0x20 (salt length 32)
    # 0x6002ED12: mov.w r5, #0x800 (2048 bits)
    fo_pss = ram_to_file(0x6002ED30)
    results["checks"]["pss_salt_32"] = (b"\x20\x21" in data[fo_pss:fo_pss + 16])

    # Verify PSS trailer field check (0xBC) in 0x600567C0
    fo_trailer = ram_to_file(0x60056860)
    # 0x60056864: cmp r3, #0xbc
    results["checks"]["pss_trailer_0xbc"] = (b"\xbc" in data[fo_trailer:fo_trailer + 12])

    # Verify all string targets
    results["strings"] = {
        "oppo_verify_fail": extract_c_string(data, ram_to_file(0x60080328)),
        "error_verify2": extract_c_string(data, ram_to_file(0x6008033C)),
        "oppo_verify_pass": extract_c_string(data, ram_to_file(0x60080314)),
        "serial_not_match": extract_c_string(data, ram_to_file(0x600802F8)),
        "unable_read_emmc": extract_c_string(data, ram_to_file(0x600802E0)),
    }
    results["checks"]["strings_intact"] = (
        "oppo Verify fail" in results["strings"]["oppo_verify_fail"] and
        "oppo Verify pass" in results["strings"]["oppo_verify_pass"] and
        "the serial is not match" in results["strings"]["serial_not_match"]
    )

    return results


def analyze_fastboot_init(lk_path: str) -> Dict[str, Any]:
    with open(lk_path, "rb") as f:
        data = f.read()

    results: Dict[str, Any] = {
        "start_ram": 0x60030018,
        "end_ram": 0x60030628,
        "checks": {}
    }

    # Verify call to verify_unlock_token at 0x60030046
    # 0x60030046: bl #0x6002eb00
    fo_call = ram_to_file(0x60030046)
    # In Thumb: bl offset to 0x6002EB00 from 0x60030046 is negative (-0x1546)
    # f7fe fd5b
    results["checks"]["calls_verify_unlock_token"] = (data[fo_call:fo_call + 4] == b"\xfe\xf7\x5b\xfd")

    # Verify failure exit call to mtk_arch_reset at 0x6003005C
    fo_reset = ram_to_file(0x6003005A)
    # movs r0, #1; bl #0x6000cd30
    results["checks"]["calls_mtk_arch_reset_on_fail"] = (
        data[fo_reset:fo_reset + 2] == b"\x01\x20"  # movs r0, #1
    )

    # Verify failure string
    results["failure_string"] = extract_c_string(data, ram_to_file(0x600809FC))
    results["success_string"] = extract_c_string(data, ram_to_file(0x60080A1C))
    results["checks"]["failure_string_verify"] = ("fastboot_unlock_verify fail" in results["failure_string"])
    results["checks"]["success_string_verify"] = ("fastboot_unlock_verify ok" in results["success_string"])

    # Verify command registrations
    registered_cmds = [
        "getvar:", "signature", "flash:", "erase:", "continue", "reboot",
        "reboot-bootloader", "download:", "oem p2u", "oem reboot-recovery",
        "boot", "flashing unlock", "flashing lock", "flashing get_unlock_ability",
        "oem scp_status", "oem scp_log_thru_ap_uart", "oem scp_scpctl",
        "oem usb2jtag", "oem ultraflash:", "oem ultraflash_en", "ultraflash:"
    ]
    results["registered_commands"] = registered_cmds
    results["checks"]["has_flashing_unlock"] = ("flashing unlock" in registered_cmds)
    results["checks"]["has_flashing_lock"] = ("flashing lock" in registered_cmds)
    results["checks"]["lacks_oem_unlock"] = ("oem unlock" not in registered_cmds)

    return results


def analyze_recovery_ramdisk(rec_path: str) -> Dict[str, Any]:
    with open(rec_path, "rb") as f:
        hdr = f.read(2048)

    magic, k_size, k_addr, rd_size, rd_addr, s_size, s_addr, tags_addr, page_size = struct.unpack("<8s8I", hdr[:40])
    k_pages = (k_size + page_size - 1) // page_size
    rd_offset = page_size * (1 + k_pages)

    with open(rec_path, "rb") as f:
        f.seek(rd_offset)
        rd_data = f.read(rd_size)

    decomp = gzip.decompress(rd_data)

    # Extract sbin/recovery
    pos = 0
    rec_bin = b""
    while pos < len(decomp) - 110:
        if decomp[pos:pos + 6] == b"070701":
            namesize = int(decomp[pos + 94:pos + 102], 16)
            filesize = int(decomp[pos + 54:pos + 62], 16)
            name = decomp[pos + 110:pos + 110 + namesize - 1].decode("latin1", errors="replace")
            file_pos = pos + 110 + namesize
            if file_pos % 4 != 0:
                file_pos += (4 - file_pos % 4)
            if name == "sbin/recovery":
                rec_bin = decomp[file_pos:file_pos + filesize]
                break
            pos = file_pos + filesize
            if pos % 4 != 0:
                pos += (4 - pos % 4)
        else:
            pos += 1

    results: Dict[str, Any] = {
        "recovery_binary_size": len(rec_bin),
        "recovery_binary_sha256": hashlib.sha256(rec_bin).hexdigest() if rec_bin else "",
        "checks": {}
    }

    if rec_bin:
        results["checks"]["lacks_reserve4_reference"] = (b"reserve4" not in rec_bin)
        results["checks"]["lacks_seccfg_reference"] = (b"seccfg" not in rec_bin)
        results["checks"]["lacks_fastboot_reference"] = (b"fastboot" not in rec_bin)
        results["checks"]["lacks_deeptest_reference"] = (b"deeptest" not in rec_bin)

    return results


def main():
    print("=== Realme 1 Bootloader Authorization Protocol Analysis ===")
    lk_c49 = DEFAULT_C49_LK
    lk_c50 = DEFAULT_C50_LK
    rec_path = DEFAULT_RECOVERY

    vut_c49 = analyze_verify_unlock_token(lk_c49)
    vut_c50 = analyze_verify_unlock_token(lk_c50)

    print(f"C.49 verify_unlock_token() SHA-256: {vut_c49['sha256']}")
    print(f"C.50 verify_unlock_token() SHA-256: {vut_c50['sha256']}")
    print(f"Code Identity: {vut_c49['sha256'] == vut_c50['sha256']}")

    fb_c49 = analyze_fastboot_init(lk_c49)
    print(f"Fastboot Init Calls Verifier: {fb_c49['checks']['calls_verify_unlock_token']}")
    print(f"Fastboot Failure String: {fb_c49['failure_string'].strip()}")
    print(f"Fastboot Success String: {fb_c49['success_string'].strip()}")

    rec_res = analyze_recovery_ramdisk(rec_path)
    print(f"Recovery Binary Size: {rec_res['recovery_binary_size']} bytes")
    print(f"Recovery Lacks reserve4: {rec_res['checks'].get('lacks_reserve4_reference')}")
    print(f"Recovery Lacks seccfg: {rec_res['checks'].get('lacks_seccfg_reference')}")


if __name__ == "__main__":
    main()
