# Project State: Realme 1 (CPH1859) Bootloader Unlock Research

## Authoritative Progress Indicator

- **Project Status:** READ-ONLY SECURITY AUDIT COMPLETE / EXACT CPH1859 C.50 PROVENANCE OPEN
- **Current Phase:** Comprehensive firmware, userspace, kernel, and boot-chain audit
- **Current Task ID & Description:** AUDIT-001: Produce evidence-calibrated inventory, vulnerability matrix, and phase reports
- **Overall Completion Estimate:** Deliverables complete; exact installed CPH1859 C.50 image provenance and preloader indirect dispatch remain open
- **Last Completed Milestone:** Repaired stale validator paths, hardened truncated-input handling, reproduced all 41 tests and differential PASS, generated a 171-file C.49/C.50 manifest, and produced userspace, kernel, boot-chain, and vulnerability-matrix reports.
- **Formal Project Outcome:** **`NO APPLICABLE AND CONFIRMED ROOT OR SOFTWARE-ONLY BOOTLOADER-STATE VULNERABILITY FOUND`** (C.49 and the CPH1861-targeted C.50 reference enforce identical token gating; exact installed CPH1859 C.50 partition provenance remains open).
- **Primary Technical Findings (Audited & Verified):**
  1. **Token Storage Coordinates:** `verify_unlock_token()` (`0x6002EB00`) calls `read_reserve4` (`0x6002C794`), which adds base sector `0x7800` to argument `0x16`, establishing the actual token location as **sector `0x7816`** (`0x00F02C00` bytes into partition `reserve4`). Read length is 8 sectors (4,096 bytes).
  2. **Serial & Signature Checks:** Compares 16 bytes of SoC eFUSE serial against the token serial field (`sp + 0x688`), with a leading-zero fallback. Hashes the 16-byte token serial field and validates a 256-byte RSA-2048 RSASSA-PSS/SHA-256 signature with MGF1-SHA-256, salt length 32, and trailer `0xBC` against the OEM public modulus at RAM **`0x6007EE48`** (file offset `0x7F048`).
  3. **Fastboot Exit Mechanism:** On token verification failure, `fastboot_init()` calls `0x6000CD30` (`[WDT] mtk_arch_reset`), writing magic `0x1971` to watchdog timer registers (`0x10007000`/`0x10007008`) to force an immediate hard reboot into normal ColorOS.
  4. **Relocking Path Scope:** `clean_flash_unlock_data()` (`0x6002EACC`) is called **exclusively from `cmd_flashing_lock()` at `0x60036920`** during intentional user relocking. It zeroes the 4 KB token slot at sector `0x7816` of `reserve4`. It is never called on failed boot and has zero side effects on other partitions.
  5. **C.49 vs C.50 Little Kernel Diff:** Exactly 315 bytes differ across 753,984 bytes: Cluster 1 (27 bytes in `.rodata` build metadata string at `0x7EA23`), Cluster 2 (32 bytes in `cert2` payload SHA-256 digest at `0xB7F73`), and Cluster 3 (256 bytes in `cert2` RSASSA-PSS signature at `0xB8031`). All `.text`, constants, and data sections are 100% byte-identical.
  6. **Cryptographic Role of `cert2`:** MediaTek Secure Boot v2 Content Certificate verified by Preloader during LK loading from flash. Contains payload digest (OID `2.16.886.2454.2.1`) and RSASSA-PSS signature signed by intermediate key `Key C2` (certified by Root Key `Key C1` in `cert1`). It is decoupled from runtime Fastboot execution and token validation.
  7. **Spelling Discrepancy Resolved:** The string `fastboot_unlock_verity` is completely absent from C.49 LK, C.50 LK, and Preloader. Both C.49 and C.50 contain `fastboot_unlock_verify fail\n\n` at `0x080BFC`. The observed string on the device screen was an optical/transcription artifact on the low-resolution LCD console.
  8. **Preloader Code Identity:** C.49 and C.50 Preloaders are 100% code-identical after normalizing the 2,048-byte `EMMC_BOOT` header.
  9. **CPH1861 Variant Safety Warning:** C.50 firmware is an `oppo6771_17065` codebase historically targeted for CPH1861. It must not be assumed safe to flash onto CPH1859, preserving the project's non-invasive read-only policy.
  10. **Exact PSS input:** At `0x6002ed44`, LK passes a precomputed 32-byte `mHash` from SHA-256 over token bytes `+0x100..+0x10f`; `0x600567C0` performs PSS encoding checks and does not receive raw message bytes.
  11. **Preloader call-graph correction:** `usbdl_*`, `bldr_handshake`, `S-CHIP`/`NS-CHIP`, and BROM offsets are diagnostic/source strings, not proven function entry points. Conservative direct/PC-relative references to them were not found; table/indirect dispatch remains unknown.
  12. **Emergency reset:** Executable watchdog routines at raw `0x2ae34`, `0x2ae44`, and `0x2aef0` have direct internal callers/transfers. The BROM strings do not establish a host-triggerable command path.
  13. **DeepTesting End-to-End Pipeline Proven:** Decompiled APK analysis proves `unlockCode` was fetched from `https://lkf.realmemobile.com`, decoded from 544 hex chars to 272 binary bytes, transferred via `OppoEngineerManager.fastbootUnlock` to HAL daemon `vendor.oppo.engnative.engineer@1.0-service`, and written directly to sector `0x7816` (`0x00F02C00`) of `/dev/block/.../reserve4`. Exit-test zeroing writes a single `0x00` byte. APK v1.0.1 explicitly requires model prefix `RMX` (excluding `CPH1859`). Decommissioning of the backend completely closes the official software authorization route.
- **Next Three Actions (Prioritized):**
  1. Acquire and authenticate exact CPH1859 C.50 LK/preloader images with independent partition provenance.
  2. Use a loader-aware static-analysis tool to resolve preloader table/indirect DA and security dispatch; do not test the reset path on the phone.
  3. Synthesize final comprehensive investigation report integrating Little Kernel, Preloader, DeepTesting APK, and vendor HAL.
- **Last Updated:** 2026-10-21T18:12:00+05:30
- **Current Git Branch:** main
- **Relevant Artifact Paths:**
  - `realme1-unlock-research/artifacts/deeptesting_decompiled_analysis.md` (ART-017)
  - `realme1-unlock-research/artifacts/firmware_inventory.json` / `.md`
  - `realme1-unlock-research/artifacts/android_userspace_audit.md`
  - `realme1-unlock-research/artifacts/kernel_audit.md`
  - `realme1-unlock-research/artifacts/boot_chain_audit.md`
  - `realme1-unlock-research/artifacts/vulnerability_matrix.json` / `.md`
  - `realme1-unlock-research/artifacts/authorization_protocol.md` (ART-012)
  - `realme1-unlock-research/artifacts/alternative_unlock_paths.md` (ART-013)
  - `realme1-unlock-research/artifacts/security_findings.md` (ART-014)
  - `realme1-unlock-research/artifacts/preloader_usb_architecture_and_feasibility.md` (ART-011)
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
