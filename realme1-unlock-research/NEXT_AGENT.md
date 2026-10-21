# Next Agent Handoff: Realme 1 (CPH1859) Bootloader Unlock Research

## Current Objective
Phase 5 independent validation and Python validator code review of C.49/C.50 Little Kernel (`lk.img`) and Preloader differential analysis is **COMPLETE**. All container structures, dynamic ASN.1 DER certificates (`cert1`/`cert2`), exact payload hash intervals (`[0x000200, 0x0B72D0)`), cryptographic signature parameters (RSASSA-PSS salt length 32), Preloader code identity, and string resolutions have been deterministically verified via `scripts/validate_lk_differential.py` and unit-tested in `tests/test_differential_validator.py` (36/36 tests passing across test suite, 23 in differential validator suite).

## Current Status
- **Confirmed Validation Results:**
  - **Whole-File Hashes Recalculated & Verified:**
    - C.49 LK (`753,984 B`): `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa`
    - C.50 LK (`753,984 B`): `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563`
    - C.49 Preloader (`265,756 B`): `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a`
    - C.50 Preloader (`267,804 B`): `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca`
  - **Full LK Binary Diff in Half-Open Interval Notation:**
    - Cluster 1: `[0x07EA23, 0x07EA48)` (span 37 bytes, 27 diffs in `.rodata` build metadata string).
    - Cluster 2: `[0x0B7F73, 0x0B7F93)` (span 32 bytes, 32 diffs in `cert2` payload SHA-256 digest).
    - Cluster 3: `[0x0B8031, 0x0B8131)` (span 256 bytes, 256 diffs in `cert2` RSASSA-PSS signature).
    - Total differing bytes: Exactly 315 across the entire 753,984-byte binary.
  - **Exact Payload Range Hashed:**
    - MediaTek container Header 1 declares `dsize = 0x000B70CC` (749,772 bytes).
    - With 16-byte alignment padding up to Header 2, the exact hashed interval is `[0x000200, 0x0B72D0)` (749,776 bytes).
    - SHA-256 of this range matches the embedded 32-byte digest in `cert2` (OID `2.16.886.2454.2.1`) for both C.49 and C.50.
  - **ASN.1 DER Certificate Chain & Cryptographic Verification:**
    - `cert1` (`[0x0B74D0, 0x0B7B7D)`, 1,709 bytes): Contains Root Key `Key C1` (offset 181) and certifies Intermediate Key `Key C2` (offset 496, OID `2.16.886.2454.1.2`). Mathematically verified self-signed by `Key C1` using RSASSA-PSS SHA-256 (MGF1 SHA-256, salt 32).
    - `cert2` (`[0x0B7D80, 0x0B8131)`, 945 bytes): Contains `Key C2` as SubjectPublicKeyInfo. Mathematically verified signed by `Key C2` using RSASSA-PSS SHA-256 (MGF1 SHA-256, salt 32).
    - The hardcoded OEM unlock token verification public key at RAM `0x6007EE48` (file `0x7F048`) is completely distinct from `Key C1` and `Key C2`.
  - **Preloader Normalization & Code Identity:**
    - C.50 Preloader begins with 2,048-byte `EMMC_BOOT` header (`[0x000, 0x800)`). Stripping this normalizes the payload to 265,756 bytes, matching C.49.
    - All 569 differing bytes reside strictly in `__FILE__` metadata paths (`[0x0325A5, 0x039400)`) and the trailing signature block (`[0x040CFC, 0x040E1C)`).
    - Preloader executable code (`0x00000` to `0x325A4`) is 100% byte-identical.
  - **Fastboot Gating Routines & String Resolution:**
    - `verify_unlock_token()` (RAM `0x6002EB00`–`0x6002EDCC`, 716 bytes) and `fastboot_init()` (RAM `0x60030018`–`0x60030628`, 1,552 bytes) are 100% byte-identical.
    - The string `fastboot_unlock_verify` exists in both images at `0x080BFC`. The string `fastboot_unlock_verity` is completely absent from all binaries.
  - **CPH1861 Variant Caution:** C.50 firmware is an `oppo6771_17065` codebase historically targeted for CPH1861. It must not be assumed safe to flash onto CPH1859, preserving the project's non-invasive read-only policy.
  - **Software-Only Feasibility Conclusion:** **`NO VIABLE SOFTWARE-ONLY UNLOCK ROUTE FOUND`**. C.50 introduces zero code changes; token verification remains identical to C.49, strictly enforcing efuse serial match and valid RSA-2048 signature.
  - **Target Device Status:** Target device remains unmodified in factory state (`ro.boot.flash.locked = 1`, `ro.boot.verifiedbootstate = green`).

## Last Verified Result
- Validation report: `artifacts/c50_differential_validation.md` (ART-009, SHA-256: `080e6998d57695cf232aae0e6169c109b2b8f9c4f1933f5df2d5cabfb209a6c7`).
- Machine-readable data: `artifacts/c50_differential_validation.json` (ART-010, SHA-256: `767cca25eccdff98002985e53d1755948716a883fdb1796c7cc7651c31ea9685`).
- Validation tool: `scripts/validate_lk_differential.py` (Exit code 0, all checks passed).
- Differential analysis artifact: `artifacts/c50_differential_analysis.md` (ART-008, SHA-256: `31f2b2b3382e8abb49c8fafd72a7ebead5dae4b59c5b68f2568bbb486b1b48f2`).

## Work Completed
- Tasks `T001` through `S003` (Phase 1), `A001` through `S004` (Phase 2), `F003` (Phase 3), `P004`/`C001`/`D004` (Phase 4), and `V002`/`V003` (Phase 5) are marked **DONE**.
- 10 research artifacts indexed in `artifacts/README.md`.
- Test suite with 36/36 passing tests (`PYTHONPATH=src:scripts python3 -m unittest discover -s tests`).

## Work in Progress
None. All Phase 5 validation requirements are fully met.

## Known Failures & Blockers
- **Fastboot Execution:** Blocked by Little Kernel efuse serial token check (`fastboot_unlock_verify fail`).
- **BootROM Entry:** Blocked by Preloader mediation; requires hardware testpoint grounding if software crash payloads are rejected.
- **In-Depth Test APK:** Blocked by permanent decommission of Oppo/Realme ColorOS 5/6 authorization servers.

## Open Questions
- None regarding Little Kernel binary structure or C.49 vs C.50 differences. Every byte difference is fully verified and accounted for.

## Next Action
1. Present independent validation outcomes, deterministic script usage, and epistemic boundaries to the user.
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
