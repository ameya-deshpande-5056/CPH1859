# Next Agent Handoff: Realme 1 (CPH1859) Bootloader Unlock Research

## Current Objective
Phase 4 technical audit of C.49 findings, C.50 differential assessment, and software-only unlock route classification is **COMPLETE**. All C.49 Little Kernel coordinates have been verified against instruction-level disassembly, and the software-only prerequisite matrix has been established in `REPORT.md` Section 3.

## Current Status
- **Confirmed Results:**
  - Token storage coordinates in `reserve4` audited: `read_reserve4` (`0x6002c794`) adds base sector `0x7800` to argument `0x16`, establishing the actual token location as **sector `0x7816`** (`0x00f02c00` bytes into partition `reserve4`).
  - OEM RSA-2048 public key modulus audited: Embedded in `.rodata` at RAM **`0x6007ee48`** (file offset `0x7f048`), referenced via `.data` pointer `0x600b6b18`.
  - Relocking path audited: `clean_flash_unlock_data()` (`0x6002eacc`) is called **strictly from `cmd_flashing_lock()` at `0x60036920`** during intentional user relocking, zeroing 4 KB at sector `0x7816` of `reserve4`. It is never called on failed boot.
  - Fastboot exit call audited: `0x6000cd30` confirmed as `[WDT] mtk_arch_reset`, writing magic `0x1971` to watchdog timer registers (`0x10007000`/`0x10007008`) to force an immediate hard reboot.
  - Hardware project compatibility audited: Unified `oppo6771_17065` codebase verified to support CPH1859 and sister sub-models (`ro.separate.soft = 17066`, `vendor.gsm.project.baseband = OPPO6771_17065`).
  - Software-only routes evaluated: All 5 potential vectors (OEM authorization, ordinary ADB, Fastboot command access, software vulnerability, and BootROM) are formally blocked by verified access controls.
  - Target device remains unmodified in factory state (`ro.boot.flash.locked = 1`).

## Last Verified Result
- Reverse engineering artifact: `artifacts/c49_bootloader_format_analysis.md` (SHA-256: `c94f1e2697b078b5783a46a511d85a0873742b211ed4921768f487e674da7c83`).
- Evidence audit artifact: `artifacts/evidence_audit.md` (SHA-256: `0a1a65c800be18255f42d26d458af67c2f111308afa4b73f99b29f500faac8ab`).
- Access blockage artifact: `artifacts/firmware_access_blockage.md` (SHA-256: `3f0a3421f2496134535f10ae81c72d0665a5dc1036166e2f5fba90ebe10b39a2`).

## Work Completed
- Tasks `T001` through `S003` (Phase 1), `A001` through `S004` (Phase 2), `F003` (Phase 3), and `P004`/`C001` (Phase 4) are marked **DONE**.
- 7 research artifacts indexed in `artifacts/README.md`.
- Read-only diagnostic CLI tool `realme1-unlock-research` tested with 13/13 passing tests.

## Work in Progress
None. Phase 4 audit and differential research complete.

## Known Failures & Blockers
- **C.50 vs C.49 Binary Diffing:** Blocked by absence of decrypted `lk.img` / `preloader.bin` binaries for C.50. Official download mirrors removed post-EOL.
- **Online Partition Extraction:** Blocked by Android DAC permissions (`root:root`) and SELinux on `/dev/block/mmcblk0p33`.
- **Fastboot Execution:** Blocked by Little Kernel efuse serial token check (`fastboot_unlock_verify fail` / `verity fail`).
- **BootROM Entry:** Blocked by Preloader mediation; requires hardware testpoint grounding if software crash payloads are rejected.

## Open Questions
- Does ColorOS C.50 `lk.img` contain the string `fastboot_unlock_verity` (with a `t`) or `fastboot_unlock_verify` (with an `f`), and did C.50 alter the token verification routine in `0x6002eb00`? (Requires sourcing full C.50 OTA `.ozip` and decrypting offline).

## Next Action
1. Present audited C.49 findings, verified token storage coordinates, and software-only prerequisite matrix to the user.
2. If authenticated C.50 full OTA packages are ever acquired, perform binary diffing against C.49 `lk.img`.

## Acceptance Criteria
- Deliver comprehensive summary directly addressing all points in Phase 2 prompt.
- Point the user to `REPORT.md`, `artifacts/evidence_audit.md`, and `artifacts/firmware_access_blockage.md`.
- Confirm phone remains in unmodified factory state.

## Safety Constraints
- Maintain strict prohibition on unauthorized flashing, partition modification, or hardware tampering.
- Preserve redaction of all device serial numbers.

## Environment Requirements
- Linux Mint host.
- Python 3.13 standard library.
- Android platform tools (`adb`, `fastboot`).
