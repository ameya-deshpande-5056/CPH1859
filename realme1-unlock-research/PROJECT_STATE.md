# Project State: Realme 1 (CPH1859) Bootloader Unlock Research

## Authoritative Progress Indicator

- **Project Status:** ACTIVE RESEARCH / PHASE 3 STATIC REVERSE ENGINEERING COMPLETE
- **Current Phase:** Phase 3: C.49 Firmware Container Analysis & Static Binary Reverse Engineering
- **Current Task ID & Description:** F003: C.49 Little Kernel container layout & static reverse engineering
- **Overall Completion Estimate:** 100% of Phase 1, Phase 2, and Phase 3 static binary analysis tasks
- **Last Completed Milestone:** Static reverse engineering of C.49 Little Kernel container format, DRAM memory map (`0x60000000`), ARM/Thumb mode transitions, and fastboot verification / unlock logic delivered in `artifacts/c49_bootloader_format_analysis.md`.
- **Formal Project Outcome:** **`BLOCKED BY MISSING FIRMWARE OR ACCESS`** (for software-only unlock on live C.50 device; C.49 static baseline fully characterized).
- **Primary Technical Findings:**
  1. **Container Architecture:** `lk.img` uses 512-byte MediaTek Image Headers (`union prt_img_hdr`, magic `0x58881688`/`0x58891689`) containing a 749,772-byte executable payload (`0x000b70cc`), followed by two 512-byte certificate containers (`cert1` at `0xb72d0` and `cert2` at `0xb7b80`). Total file size: 753,984 bytes.
  2. **Execution Layout & Mode Switch:** 32-bit ARMv7-A Little Endian executing at base DRAM address `0x60000000`. Reset vector at `0x60000000` (file `0x200`) runs in 32-bit ARM mode to disable CP15 caches/MMU, perform self-relocation, initialize mode stacks, and zero BSS, transitioning via `blx #0x6002a944` into Thumb-2 mode for `kmain()`.
  3. **Fastboot Gatekeeper Identified:** `fastboot_init()` at `0x60030018` calls `0x6002eb00` to verify an OEM cryptographic token matching the efuse board serial number. In absence of a valid token, it prints `fastboot_unlock_verify fail\n\n` and immediately reboots via `0x6000cd30`, preventing factory devices from remaining in fastboot.
  4. **Unlock Permission Path:** `flashing get_unlock_ability` (`0x60036518`) and `flashing unlock` (`0x60036648`) query `0x60036390`, which reads the 4-byte flag from `partition_size - 4` of the `"frp"` partition (`unlock_allowed_flag_offset: 0x%llx`).
  5. **Disassembler Toolchain:** Verified local Pyenv Python 3.13 with Capstone 5.0.7 as the lightweight, non-invasive static disassembly suite on Linux Mint.
- **Next Three Actions (Prioritized):**
  1. Review verified container format and disassembly findings in `artifacts/c49_bootloader_format_analysis.md`.
  2. Formulate C.50 firmware acquisition strategy to obtain decrypted C.50 `lk.img` for binary diffing and resolution of `fastboot_unlock_verify` vs `verity`.
  3. Continue maintaining strict non-invasive, read-only posture on the target device.
- **Last Updated:** 2026-10-21T12:22:00+05:30
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
