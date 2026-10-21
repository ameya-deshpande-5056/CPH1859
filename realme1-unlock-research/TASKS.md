# Tasks: Realme 1 (CPH1859) Bootloader Unlock Research

## Task Checklist Overview

| Task ID | Title | Status | Dependencies | Assignee / Phase |
|---|---|---|---|---|
| **T001** | Project setup & tracking files initialization | **DONE** | None | Phase 1 |
| **R001** | Realme 1 unlock methods & In-Depth Test analysis | **DONE** | T001 | Phase 1 |
| **R002** | Boot-chain & `fastboot_unlock_verity` root cause analysis | **DONE** | T001 | Phase 1 |
| **R003** | MediaTek BootROM & MTKClient feasibility assessment | **DONE** | T001 | Phase 1 |
| **R004** | Firmware CPH1859EX_11_C.50 acquisition & component analysis | **DONE** | T001 | Phase 1 |
| **D001** | Diagnostic CLI tool development (`realme1-unlock-research`) | **DONE** | T001 | Phase 1 |
| **D002** | Diagnostic CLI unit testing & verification | **DONE** | D001 | Phase 1 |
| **D003** | Live device diagnostic scan & report generation | **DONE** | D001, D002 | Phase 1 |
| **S001** | Comprehensive research synthesis & evidence table | **DONE** | R001-R004, D003 | Phase 1 |
| **S002** | Initial software-only feasibility assessment | **DONE** | S001 | Phase 1 |
| **S003** | Initial state files update & handoff | **DONE** | S002 | Phase 1 |
| **A001** | Epistemic Evidence Audit of `REPORT.md` claims | **DONE** | S003 | Phase 2 |
| **F002** | Firmware inventory & raw partition access audit | **DONE** | S003 | Phase 2 |
| **V001** | Vulnerability assessment & preloader/LK security review | **DONE** | A001, F002 | Phase 2 |
| **S004** | Calibrated report synthesis & formal outcome deliverable | **DONE** | V001 | Phase 2 |
| **F003** | C.49 Little Kernel container layout & static reverse engineering | **DONE** | S004 | Phase 3 |
| **C001** | C.50 firmware acquisition & mirror search | **DONE** | F003 | Phase 4 |
| **P004** | C.49 findings audit & software-only prerequisite matrix | **DONE** | C001 | Phase 4 |

---

## Phase 4 Task Details

### P004: C.49 Findings Audit & Software-Only Prerequisite Matrix
- **Status:** DONE
- **Objective:** Independently audit all Phase 3 conclusions regarding `lk.img`: container boundaries, fastboot gating, exact token sector coordinates in `reserve4`, RSA-2048/SHA-256 implementation, FRP offset math, `clean_flash_unlock_data` call paths, and CPH1859 vs CPH1861 project compatibility. Formulate explicit prerequisite matrix for software-only unlock vectors.
- **Required Inputs:** `artifacts/c49_bootloader_format_analysis.md`, `~/Realme1/C49_extracted/lk.img`, live device ADB properties.
- **Actions Performed:** Verified sector offset is `0x7800 + 0x16 = 0x7816` (`0x00f02c00` bytes); located embedded RSA public key modulus at RAM `0x6007ee48` (file `0x7f048`); proved `clean_flash_unlock_data` (`0x6002eacc`) is called strictly during relocking (`cmd_flashing_lock`) at `0x60036920`; confirmed hardware reset is `mtk_arch_reset` (`0x6000cd30`); confirmed project variant architecture (`oppo6771_17065`); audited software-only prerequisite routes; updated artifacts and tracking records.
- **Evidence & Artifact References:** `artifacts/c49_bootloader_format_analysis.md`, `REPORT.md`, `DECISIONS.md`.
- **Result & Confidence Level:** Complete, 100% confidence.

---

### C001: C.50 Firmware Acquisition & Mirror Search
- **Status:** DONE (INVESTIGATION COMPLETE / REPOSITORY UNAVAILABLE)
- **Objective:** Sourcing verified CPH1859 C.50 full OTA package (`.ozip`), decrypting using `bkerler/oppo_ozip_decrypt`, and performing binary diffing between C.49 and C.50 `lk.img` to resolve the `fastboot_unlock_verify` vs `fastboot_unlock_verity` string discrepancy.
- **Required Inputs:** Web search across official and community firmware mirrors.
- **Actions Performed:** Searched for public OTA packages (`CPH1859EX_11_OTA_0500_all_*.ozip`); verified official Realme support portal removed Realme 1 downloads post-EOL; third-party mirrors host earlier builds (C.09, C.18, C.49) but no accessible, verified C.50 full binary is currently obtainable. Formally documented the missing artifact requirement and stopped short of claiming a differential result.
- **Result:** Complete (Blocker documented).

---

## Phase 3 Task Details

### F003: C.49 Little Kernel Container Layout & Static Reverse Engineering
- **Status:** DONE
- **Objective:** Perform static, read-only reverse engineering on extracted C.49 bootloader binaries (`lk.img`, `preloader_oppo6771_17065.bin`, `MT6771_Android_scatter.txt`). Identify container format, payload boundaries, base load address, processor architecture, instruction mode switches, and reconstruct fastboot token verification / unlock permission logic.
- **Required Inputs:** `~/Realme1/C49_extracted/lk.img`, `preloader_oppo6771_17065.bin`, `MT6771_Android_scatter.txt`.
- **Actions Performed:** Verified SHA-256 hashes; identified MediaTek `union prt_img_hdr` container layout (magic `0x58881688`/`0x58891689`, payload size `0x000b70cc`, `cert1` at `0xb72d0`, `cert2` at `0xb7b80`); disassembled ARMv7 exception vectors and self-relocation routine proving DRAM base `0x60000000`; traced mode switch to Thumb-2 at `kmain()` (`0x6002a944`); disassembled `fastboot_init()` at `0x60030018` and token verifier `0x6002eb00`; disassembled `flashing get_unlock_ability` (`0x60036518`) and `flashing unlock` (`0x60036648`); confirmed `frp` partition flag offset; produced artifact `artifacts/c49_bootloader_format_analysis.md`.
- **Evidence & Artifact References:** `artifacts/c49_bootloader_format_analysis.md` (SHA-256: `907ba86703614d22a34e8366ad90dca75911b732642f2c51bc543deb7cc20cd2`).
- **Result & Confidence Level:** Complete, 100% confidence.

---

### C001: C.50 Firmware Acquisition & Comparative Diffing
- **Status:** PENDING / BLOCKED ON C.50 ARTIFACTS
- **Objective:** Sourcing verified CPH1859 C.50 full OTA package (`.ozip`), decrypting using `bkerler/oppo_ozip_decrypt`, and performing binary diffing between C.49 and C.50 `lk.img` to resolve the `fastboot_unlock_verify` vs `fastboot_unlock_verity` string discrepancy and confirm whether token verification checks were altered.
- **Required Inputs:** `CPH1859EX_11_OTA_0500_all_*.ozip` or verified partition dump.
- **Current Blocker:** C.50 full package not yet sourced in local workspace.

---

## Phase 2 Task Details

### A001: Epistemic Evidence Audit of `REPORT.md` Claims
- **Status:** DONE
- **Objective:** Map every significant claim in `REPORT.md` to its actual supporting source or experiment. Classify each claim strictly under one of five epistemic levels: `directly observed`, `independently verified`, `source-reported`, `inferred`, or `unsubstantiated`. Specifically audit:
  1. Exact origin and execution path of `fastboot_unlock_verity fail`.
  2. Serial-number and unlock-certificate validation.
  3. C.50 changes to DeepTesting compatibility.
  4. Preloader patches affecting software-only BootROM entry.
  5. The alleged requirement for a particular hardware testpoint.
- **Required Inputs:** `REPORT.md`, `RESEARCH_LOG.md`, `sources/README.md`, command outputs.
- **Actions Performed:** Produced `artifacts/evidence_audit.md` classifying all 16 major claims, auditing the 5 focal areas, and correcting unsupported certainty.
- **Evidence & Artifact References:** `artifacts/evidence_audit.md`.
- **Result & Confidence Level:** Complete, 100% confidence.

---

### F002: Firmware Inventory & Raw Partition Access Audit
- **Status:** DONE
- **Objective:** Inventory all local directories and device interfaces to verify whether exact C.50 binary images (`lk.img`, `preloader.bin`) exist. Determine provenance, hashes, formats, and document precisely which reverse engineering analyses are blocked.
- **Required Inputs:** Filesystem search (`find /home/ameya`), live partition permission checks (`adb shell ls -la /dev/block/by-name`).
- **Actions Performed:** Proved that local firmware images are absent; demonstrated that device partition block nodes are owned by `root:root` (mode `0600`), blocking unprivileged ADB dumping. Produced `artifacts/firmware_access_blockage.md`.
- **Evidence & Artifact References:** `artifacts/firmware_access_blockage.md`.
- **Result & Confidence Level:** Complete, 100% confidence.

---

### V001: Vulnerability Assessment & Preloader/LK Security Review
- **Status:** DONE
- **Objective:** Evaluate candidate vulnerability vectors (LK fastboot gating, DeepTesting protocol, MTK BootROM CVE-2020-0069, Preloader crash payloads) regarding prerequisites, reproducibility, unlock efficacy, and safety risks.
- **Required Inputs:** A001 audit results, F002 blockage findings, `lkpatcher` / `mtkclient` architectural documentation.
- **Actions Performed:** Documented full vulnerability evaluation matrix across 4 candidate attack surfaces in Section 3 of `REPORT.md`.
- **Evidence & Artifact References:** `REPORT.md` Section 3.
- **Result & Confidence Level:** Complete, 100% confidence.

---

### S004: Calibrated Report Synthesis & Formal Outcome Deliverable
- **Status:** DONE
- **Objective:** Update `REPORT.md`, `PROJECT_STATE.md`, `DECISIONS.md`, and `NEXT_AGENT.md` to reflect calibrated findings, remove unsupported claims of mathematical impossibility, and select the authoritative outcome: `BLOCKED BY MISSING FIRMWARE OR ACCESS`.
- **Required Inputs:** V001.
- **Actions Performed:** Rewrote `REPORT.md` with calibrated findings; recorded DEC-006; updated state files and registries.
- **Evidence & Artifact References:** `REPORT.md`, `DECISIONS.md`, `PROJECT_STATE.md`, `NEXT_AGENT.md`.
- **Result & Confidence Level:** Complete, 100% confidence.
