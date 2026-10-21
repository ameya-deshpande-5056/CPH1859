# Next Agent Handoff: Realme 1 (CPH1859) Bootloader Unlock Research

## Current Objective
Phase 7 reverse engineering of the bootloader authorization mechanism, static inventory of alternative paths across Fastboot/Recovery/Preloader, and systematic security findings audit is **COMPLETE**. The token verifier `verify_unlock_token()` (RAM `0x6002EB00`–`0x6002EDCC`) is mathematically verified to enforce RSASSA-PSS SHA-256 with salt length 32 and trailer byte `0xBC`, verifying the 16-byte SoC eFUSE serial against OEM public key `0x6007EE48`. Fastboot commands are strictly registered post-verification. Stock recovery (`sbin/recovery`) contains zero unlock or partition-writing logic. Research artifacts `artifacts/authorization_protocol.md` (`ART-012`), `artifacts/alternative_unlock_paths.md` (`ART-013`), and `artifacts/security_findings.md` (`ART-014`) are published. Full test suite passes 41/41 unit tests.

## Current Status
- **Confirmed Verification Results:**
  - **Function Identity & Hashes:**
    - `verify_unlock_token()` SHA-256: `c1fa1a7d7cf6627d8beba0dd9614e1949780fdcf4e0f3918f900617295b6a63c` (100% byte-identical between C.49 and C.50).
    - C.49 LK (`753,984 B`): `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa`
    - C.50 LK (`753,984 B`): `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563`
    - C.49 Preloader (`265,756 B`): `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a`
    - C.50 Preloader (`267,804 B`): `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca`
    - Stock Recovery binary (`1,266,160 B`): `a91176bc06a323382fb9d2a6a117b3cb34164b49463994356ea8c82305307525`
  - **Token Storage & Structure:**
    - Storage sector: `reserve4` sector `0x7816` (offset `0x00F02C00`, 4,096 bytes read via `read_reserve4`).
    - Offset `+0x000` (256 bytes): RSASSA-PSS SHA-256 signature signed by OEM private key.
    - Offset `+0x100` (16 bytes): Device serial number in ASCII hex (or leading `'0'` + 15 chars).
  - **Cryptographic Engine Dissection (`0x600567C0`):**
    - Strictly implements RFC 8017 Section 9.1.2 (RSASSA-PSS-VERIFY).
    - Modulus: 2048-bit OEM key at RAM `0x6007EE48` (distinct from eFUSE Root Key `Key C1`).
    - Digest: 32-byte SHA-256 calculated strictly over the 16 bytes of SoC serial.
    - MGF: MGF1 with SHA-256 (`0x600566C4`).
    - Salt: 32 bytes (`0x20`).
    - Trailer field: `0xBC` checked at `0x60056864`.
  - **Fastboot Initialization Gate:**
    - `fastboot_init()` at `0x60030046` calls `verify_unlock_token()`.
    - On failure: prints `"fastboot_unlock_verify fail\n\n"` and calls `[WDT] mtk_arch_reset(1)`, writing `0x1971` to `0x10007000`.
    - Fastboot commands (21 registered handlers) are registered strictly after successful verification.
  - **Alternative Paths Audited:**
    - `fastboot oem unlock`: ABSENT from binary.
    - `flashing unlock`: Gated by `frp` partition flag and interactive LCD prompt; post-fastboot only.
    - Stock recovery: Contains zero unlock logic; partitions `reserve4` and `seccfg` are completely unreferenced.
    - Preloader USB (`0e8d:2000`): Enforces hardware SLA challenge-response (`S-CHIP`); USB crash payloads patched in 2020 builds.
  - **Target Device Status:** Target device remains unmodified in factory state (`ro.boot.flash.locked = 1`, `ro.boot.verifiedbootstate = green`).

## Last Verified Result
- Authorization protocol artifact: `artifacts/authorization_protocol.md` (ART-012, SHA-256: `45f66ce32bda5e8790c85d4c525f649f590050c6f3f7337220dca6a43091f44a`).
- Alternative paths artifact: `artifacts/alternative_unlock_paths.md` (ART-013, SHA-256: `fae3c0d72d3e6adad8931a4ffb183c63329b4e223b47b3e509199fac6100d08a`).
- Security findings artifact: `artifacts/security_findings.md` (ART-014, SHA-256: `8750a5777af745bda247c58f030033e9b1b36d5c4e997d7d05d00caf431c3974`).
- Analysis tool: `scripts/analyze_authorization_protocol.py` (Exit code 0, all checks passed).
- Unit test suite: `tests/test_authorization_protocol.py` (5 tests passing, 41/41 across repository).

## Work Completed
- Tasks `T001` through `S003` (Phase 1), `A001` through `S004` (Phase 2), `F003` (Phase 3), `P004`/`C001`/`D004` (Phase 4), `V002`/`V003` (Phase 5), `R005` (Phase 6), and `P005`/`P006`/`P007` (Phase 7) are marked **DONE**.
- 14 research artifacts indexed in `artifacts/README.md`.
- Test suite with 41/41 passing tests (`PYTHONPATH=src:scripts python3 -m unittest discover -s tests`).

## Known Failures & Blockers
- **Fastboot Execution:** Blocked by Little Kernel efuse serial token check (`fastboot_unlock_verify fail`).
- **BootROM Entry:** Blocked by Preloader mediation; requires hardware testpoint grounding if software crash payloads are rejected.
- **In-Depth Test APK:** Blocked by permanent decommission of Oppo/Realme ColorOS 5/6 authorization servers.

## Open Questions
- None regarding Little Kernel, Recovery, or Preloader binary structures.
- Exact JSON payload structure and client serialization of historical `com.coloros.deeptesting.apk` remains unanalyzed due to missing APK binary.

## Next Action
1. Present comprehensive research synthesis and evidence tables directly to the user.
2. Confirm the target device remains in factory state.

## Safety Constraints
- Maintain strict prohibition on unauthorized flashing, partition modification, or hardware tampering.
- Preserve redaction of all device serial numbers.

## Work in Progress
None. All research requirements are fully met.

## Known Failures & Blockers
- **Fastboot Execution:** Blocked by Little Kernel efuse serial token check (`fastboot_unlock_verify fail`).
- **BootROM Entry:** Blocked by Preloader mediation; requires hardware testpoint grounding if software crash payloads are rejected.
- **In-Depth Test APK:** Blocked by permanent decommission of Oppo/Realme ColorOS 5/6 authorization servers.

## Open Questions
- None regarding Little Kernel or Preloader binary structure or C.49 vs C.50 differences. Every byte difference is fully verified and accounted for.
- DeepTesting client APK token serialization format remains unanalyzed due to missing APK binary.

## Next Action
1. Present comprehensive research synthesis and evidence tables directly to the user.
2. Confirm the target device remains in factory state.

## Safety Constraints
- Maintain strict prohibition on unauthorized flashing, partition modification, or hardware tampering.
- Preserve redaction of all device serial numbers.
- Preserve redaction of all device serial numbers.

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
