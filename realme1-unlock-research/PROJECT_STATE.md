# Project State: Realme 1 (CPH1859) Bootloader Unlock Research

## Authoritative Progress Indicator

- **Project Status:** ACTIVE RESEARCH / PHASE 5 INDEPENDENT VALIDATION & CODE REVIEW COMPLETE
- **Current Phase:** Phase 5: Independent Validation of LK Differential Analysis
- **Current Task ID & Description:** V003: Independent Python validator code review & regression hardening
- **Overall Completion Estimate:** 100% of Phase 1, Phase 2, Phase 3, Phase 4, and Phase 5 research deliverables
- **Last Completed Milestone:** Completed comprehensive code review and hardening of validation utility `scripts/validate_lk_differential.py` and test suite `tests/test_differential_validator.py`. Implemented dynamic pure-Python ASN.1 DER parser (`parse_der_tlv`, `parse_der_sequence`, `decode_oid`), dynamic certificate parsers (`parse_cert1_info`, `parse_cert2_info`), bounds-safe diff counter (`safe_diff_count`), symmetric container/SPKI validation for both C.49 and C.50, and robust error handling. Added 19 new negative unit tests verifying rejection of truncated files, corrupted MTK headers, altered payload digests, invalid signatures, malformed DER structures, and unexpected code diffs without unhandled crashes. Proved test suite sensitivity under deliberate logic breakage. All 36 repository unit tests passing (23 in differential validator suite).
- **Formal Project Outcome:** **`NO VIABLE SOFTWARE-ONLY UNLOCK ROUTE FOUND`** (live C.50 device enforces identical token verification gating; bootloader code is 100% identical between C.49 and C.50).
- **Primary Technical Findings (Audited & Verified):**
  1. **Token Storage Coordinates:** `verify_unlock_token()` (`0x6002EB00`) calls `read_reserve4` (`0x6002C794`), which adds base sector `0x7800` to argument `0x16`, establishing the actual token location as **sector `0x7816`** (`0x00F02C00` bytes into partition `reserve4`). Read length is 8 sectors (4,096 bytes).
  2. **Serial & Signature Checks:** Compares 16 bytes of SoC efuse serial via `memcmp` against the token buffer (`sp + 0x688`). Validates a 256-byte RSA-2048 PKCS#1 v1.5 signature with SHA-256 against an OEM public key modulus embedded in `.rodata` at RAM **`0x6007EE48`** (file offset `0x7F048`).
  3. **Fastboot Exit Mechanism:** On token verification failure, `fastboot_init()` calls `0x6000CD30` (`[WDT] mtk_arch_reset`), writing magic `0x1971` to watchdog timer registers (`0x10007000`/`0x10007008`) to force an immediate hard reboot into normal ColorOS.
  4. **Relocking Path Scope:** `clean_flash_unlock_data()` (`0x6002EACC`) is called **exclusively from `cmd_flashing_lock()` at `0x60036920`** during intentional user relocking. It zeroes the 4 KB token slot at sector `0x7816` of `reserve4`. It is never called on failed boot and has zero side effects on other partitions.
  5. **C.49 vs C.50 Little Kernel Diff:** Exactly 315 bytes differ across 753,984 bytes: Cluster 1 (27 bytes in `.rodata` build metadata string at `0x7EA23`), Cluster 2 (32 bytes in `cert2` payload SHA-256 digest at `0xB7F73`), and Cluster 3 (256 bytes in `cert2` RSASSA-PSS signature at `0xB8031`). All `.text`, constants, and data sections are 100% byte-identical.
  6. **Cryptographic Role of `cert2`:** MediaTek Secure Boot v2 Content Certificate verified by Preloader during LK loading from flash. Contains payload digest (OID `2.16.886.2454.2.1`) and RSASSA-PSS signature signed by intermediate key `Key C2` (certified by Root Key `Key C1` in `cert1`). It is decoupled from runtime Fastboot execution and token validation.
  7. **Spelling Discrepancy Resolved:** The string `fastboot_unlock_verity` is completely absent from C.49 LK, C.50 LK, and Preloader. Both C.49 and C.50 contain `fastboot_unlock_verify fail\n\n` at `0x080BFC`. The observed string on the device screen was an optical/transcription artifact on the low-resolution LCD console.
  8. **Preloader Code Identity:** C.49 and C.50 Preloaders are 100% code-identical after normalizing the 2,048-byte `EMMC_BOOT` header.
  9. **CPH1861 Variant Safety Warning:** C.50 firmware is an `oppo6771_17065` codebase historically targeted for CPH1861. It must not be assumed safe to flash onto CPH1859, preserving the project's non-invasive read-only policy.
- **Next Three Actions (Prioritized):**
  1. Review independent validation results in `artifacts/c50_differential_validation.md` (ART-009) and `artifacts/c50_differential_validation.json` (ART-010).
  2. Maintain strictly non-invasive, read-only posture on the target device.
  3. Synthesize final project outcomes across `REPORT.md` and evidence artifacts.
- **Last Updated:** 2026-10-21T16:00:00+05:30
- **Current Git Branch:** main
- **Relevant Artifact Paths:**
  - `realme1-unlock-research/artifacts/c50_differential_validation.md` (ART-009)
  - `realme1-unlock-research/artifacts/c50_differential_validation.json` (ART-010)
  - `realme1-unlock-research/artifacts/c50_differential_analysis.md` (ART-008)
  - `realme1-unlock-research/artifacts/c49_bootloader_format_analysis.md` (ART-007)
  - `realme1-unlock-research/artifacts/evidence_audit.md` (ART-005)
  - `realme1-unlock-research/artifacts/firmware_access_blockage.md` (ART-006)
  - `realme1-unlock-research/REPORT.md`
  - `realme1-unlock-research/DECISIONS.md`
- **Phone Modification Status:** UNMODIFIED (Phone remains in 100% factory state; strictly zero writes, erases, or flashes performed)

---

## Device & Environment Baseline

- **Device Model:** Realme 1 (CPH1859)
- **SoC:** MediaTek MT6771 (Helio P60)
- **Android Version:** Android 9 (Pie, API 28)
- **Firmware Build:** `CPH1859EX_11_C.50`
- **Build Fingerprint:** `OPPO/CPH1859/CPH1859:9/PPR1.180610.011/1601287606:user/release-keys`
- **Host OS:** Linux Mint
- **Connected Interfaces:**
  - Normal Android USB: `22d9:2769` (OPPO Electronics Corp. CPH1859)
  - ADB: Active (`device` mode)
- **Security Assessment:**
  - `ro.boot.flash.locked = 1`
  - `sys.oem_unlock_allowed = 1`
  - `ro.oem_unlock_supported = 1`
  - `ro.boot.verifiedbootstate = green`
  - `ro.boot.veritymode = enforcing`
