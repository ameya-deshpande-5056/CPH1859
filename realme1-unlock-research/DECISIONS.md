# Decisions Record: Realme 1 (CPH1859) Bootloader Unlock Research

## Architectural & Research Decisions

### DEC-001: Strict Adherence to Non-Invasive Software-Only Constraints
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** Hardware disassembly and testpoint shorting are commonly suggested in repair forums for MediaTek Helio P60 unbricking and BootROM forcing.
- **Decision:** All research, testing, and diagnostic tools must strictly operate over standard USB (ADB, Fastboot, standard USB device enumeration). Hardware testpoints, motherboard modification, battery disconnection, and paid servicing boxes (e.g. Chimera, UnlockTool) are explicitly rejected.
- **Reason:** The user's research objective specifically mandates software-only investigation without physical alteration or commercial service boxes.
- **Alternatives Rejected:** Hardware testpoint shorting (grounding pin on motherboard), opening back cover, testpoint cables.

---

### DEC-002: Mandatory Identifier Redaction Across All Tools & Artifacts
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** The device serial number and potentially sensitive hardware identifiers (IMEI, MAC, etc.) are exposed via ADB and fastboot.
- **Decision:** Built-in sanitization and redaction engines must run across all diagnostic collectors, loggers, and artifact exporters. The unique serial number will be dynamically detected and replaced with `[REDACTED_SERIAL]`.
- **Reason:** Privacy protection, security best practices, and explicit project mandate prohibiting committing serial numbers to version control or public reports.
- **Alternatives Rejected:** Manual log editing (prone to human error and leaks).

---

### DEC-003: Read-Only Diagnostic Architecture
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** Building diagnostic tools that interface with Android platform tools.
- **Decision:** The diagnostic CLI must never execute commands that modify system state, flash partitions (`fastboot flash`, `dd`, `fastboot flashing unlock`), wipe data, or trigger unverified exploit payloads.
- **Reason:** Zero-risk guarantee against bricking, data loss, or bootloader state corruption.
- **Alternatives Rejected:** Automated exploit execution or brute-forcing fastboot arguments.

---

### DEC-004: Dual-Location State Accessibility
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** The workspace root is `/home/ameya/CPH1859`, while the specified project name is `realme1-unlock-research`.
- **Decision:** Place authoritative files in `realme1-unlock-research/` and create symbolic links at `/home/ameya/CPH1859/` pointing into `realme1-unlock-research/`.
- **Reason:** Ensures any resuming agent or user inspecting either the workspace root or the project subfolder immediately finds all project state files.
- **Alternatives Rejected:** Keeping files solely in one location without symlinks.

---

### DEC-005: Conclusion on Software-Only Unlock Feasibility for CPH1859EX_11_C.50
- **Date:** 2026-10-21
- **Status:** SUPERSEDED BY DEC-006
- **Context:** Initial evaluation based on preliminary diagnostic scan and literature review.
- **Decision:** Initial report declared unlocking impossible.
- **Reason:** Superseded to remove unproven claims of mathematical impossibility.

---

### DEC-006: Epistemic Calibration & Formal Project Outcome Selection
- **Date:** 2026-10-21
- **Status:** APPROVED / CURRENT
- **Context:** Phase 2 evidence audit revealed that claims regarding exact C function names, token storage structures, and preloader crash error codes were inferred from secondary literature rather than locally disassembled binaries. Furthermore, local C.50 firmware images are unavailable on the host, and raw block access is restricted over ADB.
- **Decision:** 
  1. Calibrate all research findings using the 5-tier epistemic taxonomy (`directly observed`, `independently verified`, `source-reported`, `inferred`, `unsubstantiated`).
  2. Adopt the formal outcome: **`BLOCKED BY MISSING FIRMWARE OR ACCESS`** (with secondary finding `NO VIABLE ROUTE FOUND WITH CURRENT EVIDENCE`).
  3. Formally catalog the specific reverse-engineering analyses that remain blocked pending offline firmware acquisition.
- **Reason:** Adheres strictly to scientific integrity; a failed search or absent binary is not proof that no vulnerability exists.
- **Alternatives Rejected:** Declaring software unlock "mathematically impossible" (unsubstantiated certainty); fabricating simulated disassembly of unavailable images (scientific misconduct).

---

### DEC-007: C.49 Little Kernel Container & Static Execution Boundary Calibration
- **Date:** 2026-10-21
- **Status:** APPROVED / CURRENT
- **Context:** Extracted C.49 firmware packages (`lk.img`, `preloader_oppo6771_17065.bin`, `MT6771_Android_scatter.txt`) were provided for static reverse engineering. Initial assumptions regarding load address (`0x200` vs `0x60000000`) and disassembler availability required empirical validation.
- **Decision:**
  1. Formally record the container format of `lk.img` as MediaTek Image Header (`union prt_img_hdr`, magic `0x58881688`/`0x58891689`, 512-byte header, 749,772-byte payload, followed by two 512-byte certificate containers `cert1` and `cert2`).
  2. Confirm base DRAM execution address as `0x60000000` via bootstrap CP15 setup and self-relocation loop disassembly.
  3. Confirm processor architecture as ARMv7-A 32-bit Little Endian, with ARM state reset vector transitioning via `blx #0x6002a944` into Thumb-2 state at `kmain()`.
  4. Standardize on Python 3 + Capstone 5.0.7 (verified locally present in pyenv) as the primary reproducible static disassembly toolchain.
- **Reason:** Grounded in direct static binary disassembly without guessing load addresses or relying on unavailable external tools.
- **Alternatives Rejected:** Assuming load address is `0x200` or raw binary offset (would cause incorrect memory offsets); guessing toolchain requirements without testing local pyenv packages.

---

### DEC-008: C.49 Detailed Findings Audit, Token Storage Coordinates & Failure Path Scope
- **Date:** 2026-10-21
- **Status:** APPROVED / CURRENT
- **Context:** An independent audit of Phase 3 findings was conducted to verify token storage coordinates, cryptographic implementation, hardware project variant relationships, and destructive failure paths.
- **Decision:**
  1. Correct token sector offset: `read_reserve4` (`0x6002c794`) adds base sector `0x7800` to argument `0x16`, establishing the actual token location as **sector `0x7816`** (`0x00f02c00` bytes into partition `reserve4`).
  2. Confirm public key location: The OEM RSA-2048 public key modulus is embedded in `.rodata` at RAM **`0x6007ee48`** (file offset `0x7f048`), pointed to by `.data` address `0x600b6b18`.
  3. Correct `clean_flash_unlock_data` caller scope: `clean_flash_unlock_data` (`0x6002eacc`) is called **strictly from `cmd_flashing_lock()` at `0x60036920`** during intentional user relocking (`fastboot flashing lock`). It is **not** called upon token verification failure.
  4. Confirm fastboot abort mechanism: Token verification failure in `fastboot_init()` calls `0x6000cd30` (`mtk_arch_reset`), writing magic `0x1971` to the MediaTek Watchdog Timer at `0x10007000`/`0x10007008` to force an immediate hard reboot.
  5. Confirm project variant scope: The firmware is built on the unified `oppo6771_17065` codebase (`Common_software_project="17065"`), confirmed by connected device properties (`ro.separate.soft = 17066`, `vendor.gsm.project.baseband = OPPO6771_17065`). Findings apply equally across CPH1859 and sister sub-models.
- **Reason:** Rigorous, instruction-by-instruction verification correcting earlier preliminary drafting hypotheses.
- **Alternatives Rejected:** Assuming relative sector `0x16` was absolute without tracing partition driver offset arithmetic; asserting `clean_flash_unlock_data` was reached on failed boot without tracing all call xrefs.

---

### DEC-009: C.50 Little Kernel Differential Identity, cert2 Dissection, and Verify/Verity Resolution
- **Date:** 2026-10-21
- **Status:** APPROVED / CURRENT
- **Context:** Acquired C.50 static firmware images (`lk.img`, `preloader_emmc.img`) allowed an exhaustive binary diff and reverse engineering evaluation against the C.49 baseline.
- **Decision:**
  1. Confirm Little Kernel code identity: Across all 753,984 bytes, exactly 315 bytes differ in 3 isolated non-executable clusters (Cluster 1: 27-byte build timestamp string in `.rodata`; Cluster 2: 32-byte payload SHA-256 digest in `cert2`; Cluster 3: 256-byte RSASSA-PSS signature in `cert2`). All executable code (`.text`), constants, and data sections are 100% byte-identical.
  2. Confirm token verifier and Fastboot initialization identity: `verify_unlock_token()` (RAM `0x6002EB00` – `0x6002EDCC`, 716 bytes) and `fastboot_init()` (RAM `0x60030018` – `0x60030628`, 1,552 bytes), their basic blocks, literal pools, branches, and all 44 call targets are 100% byte-identical.
  3. Classify `cert2` structure: Formally document `cert2` (file offset `0x0B7B80` – `0x0B8131`) as an ASN.1 DER MediaTek Secure Boot v2 Content Certificate verified by the Preloader, containing the LK payload SHA-256 digest under MediaTek vendor OID `2.16.886.2454.2.1` and an RSASSA-PSS SHA-256 signature signed by intermediate key `Key C2` (certified by Root Key `Key C1` in `cert1`). Decouple `cert2` from fastboot token verification.
  4. Conclusively resolve the `verify` vs `verity` discrepancy: Both C.49 and C.50 Little Kernel contain `fastboot_unlock_verify fail\n\n` at `0x080BFC` and `the serial is not match\n` at `0x0804F8`. Neither binary contains `fastboot_unlock_verity`. The on-screen text was an optical/transcription artifact on the low-resolution LCD console.
- **Reason:** Supported by complete binary diffing, Capstone instruction-level tracing, OpenSSL ASN.1 DER parsing, and Python `cryptography` cryptographic verification.
- **Alternatives Rejected:** Hypothesizing that C.50 altered token verification logic or introduced new bootloader security checks; assuming `cert2` participates in fastboot token gating without tracing cross-references.
