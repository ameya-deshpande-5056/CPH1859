# Project State: Realme 1 (CPH1859) Bootloader Unlock Research

## Authoritative Progress Indicator

- **Project Status:** ACTIVE RESEARCH / PHASE 4 AUDIT & PREREQUISITE MATRIX COMPLETE
- **Current Phase:** Phase 4: C.49 Findings Audit & C.50 Differential Research
- **Current Task ID & Description:** P004: C.49 findings audit & software-only prerequisite matrix
- **Overall Completion Estimate:** 100% of Phase 1, Phase 2, Phase 3, and Phase 4 research deliverables
- **Last Completed Milestone:** Comprehensive technical audit of C.49 Little Kernel findings delivered: verified token sector offset (`0x7816` in `reserve4`), embedded RSA-2048 public key (`0x6007ee48`), hardware WDT reset call (`0x6000cd30`), `clean_flash_unlock_data` restricted relocking scope (`0x60036920`), and software-only route prerequisite classification matrix.
- **Formal Project Outcome:** **`BLOCKED BY MISSING FIRMWARE OR ACCESS`** (for software-only unlock on live C.50 device; C.49 static baseline fully audited).
- **Primary Technical Findings (Audited):**
  1. **Token Storage Coordinates:** `verify_unlock_token()` (`0x6002eb00`) calls `read_reserve4` (`0x6002c794`), which adds base sector `0x7800` to argument `0x16`, establishing the actual token location as **sector `0x7816`** (`0x00f02c00` bytes into partition `reserve4`). Read length is 8 sectors (4,096 bytes).
  2. **Serial & Signature Checks:** Compares 16 bytes of SoC efuse serial via `memcmp` against the token buffer (`sp + 0x688`). Validates a 256-byte RSA-2048 PKCS#1 v1.5 signature with SHA-256 against an OEM public key modulus embedded in `.rodata` at RAM **`0x6007ee48`** (file offset `0x7f048`).
  3. **Fastboot Exit Mechanism:** On token verification failure, `fastboot_init()` calls `0x6000cd30` (`[WDT] mtk_arch_reset`), writing magic `0x1971` to watchdog timer registers (`0x10007000`/`0x10007008`) to force an immediate hard reboot into normal ColorOS.
  4. **Relocking Path Scope:** `clean_flash_unlock_data()` (`0x6002eacc`) is called **exclusively from `cmd_flashing_lock()` at `0x60036920`** during intentional user relocking. It zeroes the 4 KB token slot at sector `0x7816` of `reserve4`. It is never called on failed boot and has zero side effects on other partitions.
  5. **FRP Permission Read:** `get_unlock_permission()` (`0x60036390`) calculates 64-bit offset `partition_size - 4` on `"frp"` and reads 4 bytes. If `0`, `cmd_flashing_unlock()` rejects with `"Unlock operation is not allowed"`.
  6. **Hardware Compatibility:** Built on unified `oppo6771_17065` codebase (`Common_software_project="17065"`), confirmed by connected device properties (`ro.separate.soft = 17066`, `vendor.gsm.project.baseband = OPPO6771_17065`). Findings apply across CPH1859 and sister variants.
  7. **C.50 Firmware Status:** Official Realme download portals have removed Realme 1 packages post-EOL; third-party repositories host C.09/C.18/C.49, but no verified C.50 full package is currently obtainable.
- **Next Three Actions (Prioritized):**
  1. Review audited technical findings in `artifacts/c49_bootloader_format_analysis.md` and prerequisite matrix in `REPORT.md`.
  2. If an authenticated C.50 full package (`.ozip` or dump) becomes available from an official or trusted archive, perform binary diffing against C.49 `lk.img`.
  3. Maintain strictly non-invasive, read-only posture on the target device.
- **Last Updated:** 2026-10-21T12:40:00+05:30
- **Current Git Branch:** main
- **Relevant Artifact Paths:**
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
