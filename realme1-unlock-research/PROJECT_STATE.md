# Project State: Realme 1 (CPH1859) Bootloader Unlock Research

## Authoritative Progress Indicator

- **Project Status:** READ-ONLY SECURITY AUDIT COMPLETE / ANDROID ROOT ASSESSMENT COMPLETE / EXACT CPH1859 C.50 PROVENANCE OPEN / C.50/LK DIFFERENTIAL ANALYSIS COMPLETE
- **Current Phase:** Android root candidate assessment and evidence report
- **Current Task ID & Description:** AUDIT-002: Produce ranked Android root candidate shortlist, evidence reports, and read-only experiment plan
- **Overall Completion Estimate:** Android root assessment deliverables complete; exact installed CPH1859 C.50 image provenance and kernel config/source remain open; C.49 vs C.50 LK differential: 315 bytes in 3 certificate clusters only, all other code/data 100% identical
- **Current Phase Sub-phase:** E-001/E-002/E-003 open investigations / Kernel .config extracted from live device
- **Overall Completion Estimate:** Android root assessment deliverables complete; kernel .config extracted from live CPH1859 device via /proc/config.gz - major evidence gap closed; exact installed CPH1859 C.50 image provenance open but config now available; C.49 vs C.50 LK differential confirmed: 315 bytes in 3 certificate clusters only, all .text/data/code 100% byte-identical; live device ADB audit performed, engineer HIDL service confirmed, ATCI service documented as disabled in user build; kernel config reveals Oppo-specific security features relevant to root candidate assessment
- **Last Completed Milestone:** Updated vulnerability matrix with Android root candidates (U-001 through U-005, K-001 through K-004); produced ranked shortlist, individual evidence reports, and safe read-only experiment plan; extracted and analyzed C.49 kernel and vendor filesystems; C.49 vs C.50 LK differential analysis (ART-008): 315 bytes differ across 753,984 bytes concentrated in 3 certificate clusters only; token verification 100% identical across builds; live device ADB audit: 187 services enumerated, engineer HIDL service confirmed, ATCI service documented as disabled in user build; kernel .config extracted from live device and analyzed for Oppo security features
- **Formal Project Outcome:** **`NO CONFIRMED ANDROID ROOT PATH FOUND`** — No vulnerability confirmed to provide Android userspace or kernel root on CPH1859 C.50. Strongest candidates: K-001/K-002 (kernel LPE, UNKNOWN/PLAUSIBLE — evidence gap), U-001 (Engineer HIDL service, PLAUSIBLE — no untrusted_app path proven), U-002 (ATCI diagnostic service, STRONGLY SUPPORTED surface but disabled in user build). Bootloader-state modification remains a separate downstream question.
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
  1. Acquire model-authenticated CPH1859 C.50 OTA; extract boot.img; perform kernel CVE backport analysis (E-001)
  2. Enumerate exported Binder/HIDL services on live device via read-only ADB (E-002)
  3. Statically analyze Engineer HIDL service binary for caller-check vulnerabilities (E-003)
- **Last Updated:** 2026-10-21T18:12:00+05:30
- **Current Git Branch:** main
- **Relevant Artifact Paths:**
  - `realme1-unlock-research/artifacts/deeptesting_decompiled_analysis.md` (ART-017)
  - `realme1-unlock-research/artifacts/firmware_inventory.json` / `.md`
  - `realme1-unlock-research/artifacts/android_userspace_audit.md`
  - `realme1-unlock-research/artifacts/kernel_audit.md`
  - `realme1-unlock-research/artifacts/boot_chain_audit.md`
  - `realme1-unlock-research/artifacts/vulnerability_matrix.json` / `.md` **(UPDATED: Android root candidates U-001–U-005, K-001–K-004)**
  - `realme1-unlock-research/artifacts/root_candidate_shortlist.md` **(NEW: ranked Android root candidates)**
  - `realme1-unlock-research/artifacts/evidence_report_K-001_kernel_lpe.md` **(NEW: kernel LPE evidence)**
  - `realme1-unlock-research/artifacts/evidence_report_U-001_engineer_hidl.md` **(NEW: Engineer HIDL evidence)**
  - `realme1-unlock-research/artifacts/evidence_report_U-002_atci.md` **(NEW: ATCI diagnostic service evidence)**
  - `realme1-unlock-research/artifacts/safe_readonly_experiments.md` **(NEW: read-only experiment plan)**
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
