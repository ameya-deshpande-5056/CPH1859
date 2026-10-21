# Next Agent Handoff: Realme 1 (CPH1859) Bootloader Unlock Research

## Current Objective
Phase 7 reverse engineering, Phase 8 evidence reconciliation, Phase 9 static path audit, and Phase 10 DeepTesting end-to-end reverse engineering are **COMPLETE**. The token verifier `verify_unlock_token()` (RAM `0x6002EB00`–`0x6002EDCC`) hashes the 16-byte token serial field, passes the resulting 32-byte digest to `0x600567C0`, and the latter performs RSASSA-PSS SHA-256 with salt length 32 and trailer byte `0xBC`. Fastboot commands are strictly registered post-verification. Stock recovery has no direct audited references to the security partitions. In Phase 10, static reverse engineering of the decompiled OEM DeepTesting APK (`com.coloros.deeptesting`), system framework (`services.vdex`), and native HAL (`vendor.oppo.engnative.engineer@1.0-service`) fully resolved the token origin, AES-128-ECB payload encryption, framework routing via `OppoEngineerManager.fastbootUnlock`, native partition persistence to `reserve4` sector `0x7816` (`0x00F02C00`), and Little Kernel handoff. Full test suite passes 41/41 unit tests.

## Current Status
- **Confirmed Verification Results:**
  - **Function Identity & Hashes:**
    - `verify_unlock_token()` SHA-256: `c1fa1a7d7cf6627d8beba0dd9614e1949780fdcf4e0f3918f900617295b6a63c` (100% byte-identical between C.49 and C.50).
    - C.49 LK (`753,984 B`): `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa`
    - C.50 LK (`753,984 B`): `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563`
    - C.49 Preloader (`265,756 B`): `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a`
    - C.50 Preloader (`267,804 B`): `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca`
    - Extracted C.49 `sbin/recovery` (`1,266,160 B`): `05cfcf8ffbb59abcbd642a950989cc4d112d1985ad1a4c9eab642ce4e67bdb34`
  - **Token Storage & Structure:**
    - Storage sector: `reserve4` sector `0x7816` (offset `0x00F02C00`, 4,096 bytes read via `read_reserve4`).
    - Offset `+0x000` (256 bytes): RSASSA-PSS SHA-256 signature signed by OEM private key.
    - Offset `+0x100` (16 bytes): Device serial number in ASCII hex (or leading `'0'` + 15 chars).
  - **Cryptographic Engine Dissection (`0x600567C0`):**
    - Strictly implements RFC 8017 Section 9.1.2 (RSASSA-PSS-VERIFY).
    - Modulus: 2048-bit OEM key at RAM `0x6007EE48` (distinct from eFUSE Root Key `Key C1`).
    - Digest: 32-byte SHA-256 calculated over the 16-byte token serial field; normally this is the eFUSE-derived serial text, with a leading-zero fallback.
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
    - Stock recovery: The accessible `sbin/recovery` has no direct audited references to `reserve4` or `seccfg`; indirect/helper behavior is not proved absent.
    - Preloader USB (`0e8d:2000`): Contains DA/security-policy and emergency BROM-reset paths; exact runtime authentication and crash-payload reachability remain unproven for the physical device.
    - Preloader static correction: `usbdl_*`, `bldr_handshake`, `S-CHIP`/`NS-CHIP`, and BROM offsets are strings. Conservative direct/PC-relative references were not found; executable watchdog routines and direct internal callers are traced, while table/indirect DA dispatch remains unknown.
  - **Target Device Status:** Target device remains unmodified in factory state (`ro.boot.flash.locked = 1`, `ro.boot.verifiedbootstate = green`).

## Last Verified Result
- Authorization protocol artifact: `artifacts/authorization_protocol.md` (ART-012, SHA-256: `45f66ce32bda5e8790c85d4c525f649f590050c6f3f7337220dca6a43091f44a`).
- Alternative paths artifact: `artifacts/alternative_unlock_paths.md` (ART-013, SHA-256: `fae3c0d72d3e6adad8931a4ffb183c63329b4e223b47b3e509199fac6100d08a`).
- Security findings artifact: `artifacts/security_findings.md` (ART-014, SHA-256: `8750a5777af745bda247c58f030033e9b1b36d5c4e997d7d05d00caf431c3974`).
- Analysis tool: `scripts/analyze_authorization_protocol.py` (Exit code 0, all checks passed).
- Unit test suite: `tests/test_authorization_protocol.py` (5 tests passing, 41/41 across repository).

## Work Completed
- Tasks `T001` through `S003` (Phase 1), `A001` through `S004` (Phase 2), `F003` (Phase 3), `P004`/`C001`/`D004` (Phase 4), `V002`/`V003` (Phase 5), `R005` (Phase 6), `P005`/`P006`/`P007` (Phase 7), `P008` (Phase 8), and `P009` (Phase 9) are marked **DONE**.
- 14 research artifacts indexed in `artifacts/README.md`.
- Test suite with 41/41 passing tests (`PYTHONPATH=src:scripts python3 -m unittest discover -s tests`).

## Known Failures & Blockers
- **Fastboot Execution:** Blocked by Little Kernel efuse serial token check (`fastboot_unlock_verify fail`).
- **BootROM Entry:** No software-only route was demonstrated; preloader mediation and exact crash-payload reachability remain unresolved on the physical device.
- **In-Depth Test APK:** Blocked by permanent decommission of Oppo/Realme ColorOS 5/6 authorization servers.

## Open Questions
- None regarding the LK/PSS sequence. The exact preloader DA/security call graph, table/indirect targets, fuse/configuration branches, and host-triggerability of the emergency BROM reset remain unresolved.
- Exact JSON payload structure and client serialization of historical `com.coloros.deeptesting.apk` remains unanalyzed due to missing APK binary.

## Next Action
1. Present the calibrated synthesis and evidence links to the user.
2. If further read-only work is desired, obtain model-authenticated CPH1859 C.50 images or the historical DeepTesting APK, then use loader-aware static analysis; do not flash or probe the phone.

## Safety Constraints
- Maintain strict prohibition on unauthorized flashing, partition modification, or hardware tampering.
- Preserve redaction of all device serial numbers.

## Work in Progress
Phase 9 static audit is complete. Further progress requires exact-image provenance or loader-aware analysis of unresolved indirect preloader dispatch; no live reset/USB testing is authorized.

## Known Failures & Blockers
- **Fastboot Execution:** Blocked by Little Kernel efuse serial token check (`fastboot_unlock_verify fail`).
- **BootROM Entry:** No software-only route was demonstrated; preloader mediation and exact crash-payload reachability remain unresolved on the physical device.
- **In-Depth Test APK:** Blocked by permanent decommission of Oppo/Realme ColorOS 5/6 authorization servers.

## Open Questions
- LK/PSS structure and the direct watchdog edges are resolved. The preloader DA/security table and indirect-call graph, fuse/configuration branches, and host-triggerability of the emergency reset remain open.
- DeepTesting client APK token serialization format remains unanalyzed due to missing APK binary.

## Next Action
1. Present the calibrated synthesis and evidence links to the user.
2. If further read-only work is desired, obtain model-authenticated CPH1859 C.50 images or the historical DeepTesting APK; do not flash or probe the phone.

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
