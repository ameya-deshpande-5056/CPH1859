# Epistemic Evidence Audit: Realme 1 (CPH1859) Unlock Claims

> **Historical-artifact note:** This Phase-2 audit predates the accessible C.50 reference binaries and the Phase-8 reconciliation. Its classifications of C.50 binary availability and exact LK token structure are retained as historical context; see `research_evidence_audit.md` for the current audit.

## 1. Audit Methodology & Classification Taxonomy

To ensure absolute technical rigor and prevent speculative assertions from masquerading as verified facts, every technical claim made in the initial investigation is audited against empirical data and primary sources using the following five-tier epistemic taxonomy:

1. **`directly observed`**: Verified through primary execution and measurement on the target host or connected Realme 1 hardware.
2. **`independently verified`**: Confirmed across multiple independent, high-credibility primary technical sources (e.g., AOSP source code, vendor kernel releases, reproducible codebases).
3. **`source-reported`**: Derived from external community reports, forum discussions, or developer repositories; credible but not locally reproduced or formally proven.
4. **`inferred`**: A logical deduction based on observed timing, architectural conventions, or related platform behavior; plausible, but lacks direct binary disassembly or code trace.
5. **`unsubstantiated`**: Asserted with certainty without adequate empirical backing, disassembly, or verifiable documentation.

---

## 2. Comprehensive Claim Mapping & Audit Matrix

| Claim ID | Core Claim from Research / Initial Report | Supporting Source / Experiment | Epistemic Classification | Audit Findings & Required Calibration |
|---|---|---|---|---|
| **CLM-001** | Device model is CPH1859 running ColorOS build `CPH1859EX_11_C.50`, Android 9, security patch 2020-09-05. | `adb shell getprop`, `lsusb`, `TEST_004_PROPS` | **`directly observed`** | Fully confirmed directly from target hardware. |
| **CLM-002** | Bootloader is locked (`ro.boot.flash.locked = 1`), AVB is green, verity mode is enforcing. | `adb shell getprop`, `TEST_004_PROPS`, `TEST_007_POSTURE` | **`directly observed`** | Fully confirmed directly from target hardware. |
| **CLM-003** | User has enabled OEM Unlocking in Developer Options (`sys.oem_unlock_allowed = 1`). | `adb shell getprop`, `TEST_007_POSTURE` | **`directly observed`** | Fully confirmed directly from target hardware. |
| **CLM-004** | Fastboot mode is not currently active on the USB bus during normal Android runtime. | `fastboot devices`, `lsusb`, `TEST_005_FASTBOOT` | **`directly observed`** | Fully confirmed directly from target hardware. |
| **CLM-005** | DeepTesting application is not installed on the Android user-space partition. | `adb shell pm list packages`, `TEST_006_PACKAGES` | **`directly observed`** | Fully confirmed directly from target hardware. |
| **CLM-006** | Executing `adb reboot bootloader` displays `the serial is not match` and `fastboot_unlock_verity fail` on-screen and immediately boots normal ColorOS. | Direct observation of device screen during boot transition; absence of logs in `adb logcat`. | **`directly observed`** | Fully confirmed directly from target hardware. |
| **CLM-007** | The string `fastboot_unlock_verity` is not present in user-space ELF binaries or scripts in `/system` or `/vendor`. | `adb shell grep -r -l 'fastboot_unlock_verity' /system/ /vendor/` | **`directly observed`** | Confirmed; string does not originate from Android user space. |
| **CLM-008** | The error is displayed by the Little Kernel (`lk` / `lk2`) bootloader rather than Preloader or Recovery. | MediaTek platform architecture; Preloader has no frame buffer/LCM driver; Recovery runs later. | **`inferred`** | Strongly supported by boot-chain architecture, but not directly confirmed via C.50 `lk.img` disassembly. |
| **CLM-009** | The error occurs inside a specific C function named `fastboot_unlock_verity()` called by `get_boot_mode()`. | DroidWin articles, general MediaTek open-source LK conventions. | **`inferred`** | **Correction:** Function names in compiled C binaries are stripped unless symbols remain. Stating this exact C identifier without binary analysis is an inference. |
| **CLM-010** | The verification check reads `ro.serialno` and compares it to a cryptographic token stored in `proinfo` or `seccfg`. | General ColorOS security analysis and community reverse-engineering threads. | **`source-reported`** / **`inferred`** | **Correction:** While `the serial is not match` clearly indicates a serial number comparison, claiming it specifically checks an RSA token in `proinfo` or `seccfg` is inferred. No C.50 binary disassembly exists locally to prove token structure. |
| **CLM-011** | Realme In-Depth Test server infrastructure is decommissioned and non-operational. | EOL status of Realme 1 (2020), community forum consensus across 2021-2024. | **`source-reported`** | High confidence based on community consensus, but cannot be independently tested without a functional DeepTesting client sending live API requests. |
| **CLM-012** | Firmware build C.50 natively broke compatibility with the legacy In-Depth Test APK. | XDA custom ROM installation guides (requiring downgrade to C.49 before unlocking). | **`source-reported`** | **Correction:** Community consensus confirms C.49 was required, but whether C.50 OS code blocked the APK vs whether backend servers rejected C.50's build fingerprint is unverified. |
| **CLM-013** | MediaTek Helio P60 (MT6771) SoC contains the BootROM USB control transfer vulnerability (CVE-2020-0069 / `kamakiri`). | MediaTek security advisories, `bkerler/mtkclient` source code. | **`independently verified`** | Confirmed by public CVE disclosures and open-source tooling. |
| **CLM-014** | Build C.50's Preloader has patched the USB software crash vectors (`kamakiri2` / `crash da`) returning `0x1d18`/`0x1d1a`. | `mtkclient` GitHub issue discussions regarding MT6771 2020 patches. | **`source-reported`** / **`inferred`** | **Correction:** This was inferred from general MT6771 patch timelines (October 2020 build date). It was **NOT** directly tested on this device. Stating it as a confirmed fact was unsupported certainty. |
| **CLM-015** | Forcing BootROM mode on C.50 strictly requires opening the phone and grounding a physical motherboard testpoint. | Hardware servicing tutorials and schematics. | **`source-reported`** | **Correction:** Grounding DAT0/CLK is a confirmed hardware technique in repair shops, but asserting that no software vector could ever trigger BootROM or bypass LK verity was an unsubstantiated overstatement ("TECHNICALLY IMPOSSIBLE"). |
| **CLM-016** | Software-only bootloader unlock is "TECHNICALLY IMPOSSIBLE" on C.50. | Deductive conclusion of initial report. | **`unsubstantiated`** | **Correction:** Must be calibrated. A failure to identify an exploit in public documentation is not proof of impossibility. The proper scientific designation is **`BLOCKED BY MISSING FIRMWARE OR ACCESS`** / **`NO VIABLE ROUTE FOUND WITH CURRENT EVIDENCE`**. |

---

## 3. Deep Dive into the Five Key Audited Areas

### Area 1: Origin & Execution Path of `fastboot_unlock_verity fail`
- **What is Verified:**
  The string appears on the device's physical screen during the reboot transition from `adb reboot bootloader`. It appears after user-space teardown and before kernel boot.
- **What is Inferred:**
  On MediaTek SoCs, the Preloader initializes basic DRAM and loads the Little Kernel (`lk`). The Preloader has no display or LCM driver; frame buffer initialization and textual console printing are first established by Little Kernel. Therefore, the message almost certainly originates from Little Kernel (`lk.img`).
- **What Remains Uncertain:**
  The exact internal function names, call graph structure, and whether the check occurs in `app/fastboot`, `platform/mt6771/mode.c`, or a vendor-injected library cannot be definitively stated without static disassembly of the C.50 `lk.img` binary.

### Area 2: Serial-Number & Unlock-Certificate Validation
- **What is Verified:**
  The literal text `the serial is not match` confirms that a serial number string or hash comparison failed.
- **What is Inferred:**
  ColorOS devices use an authorized token issued by vendor services. Tools like `R0rt1z2/lkpatcher` demonstrate that LK contains needle routines for fastboot gating that can be patched with `movs r0, #0; bx lr` (00207047).
- **What Remains Uncertain:**
  The exact partition (`proinfo`, `nvram`, `seccfg`, or `devinfo`), the exact data structure/offset, and the cryptographic signature scheme (RSA key modulus, hash algorithm) have not been directly extracted from C.50 binaries.

### Area 3: C.50 Changes to DeepTesting Compatibility
- **What is Verified:**
  No DeepTesting app is installed on the target device.
- **What is Source-Reported:**
  Independent developers on XDA Forums maintain that upgrading to C.50 broke the unlock workflow, necessitating a downgrade to C.49 via stock recovery.
- **What Remains Uncertain:**
  Whether the incompatibility is caused by an OS-level API restriction (e.g., package signature check, missing hidden API in C.50 framework) or an online server-side policy rejecting C.50 build fingerprints.

### Area 4: Preloader Patches Affecting Software-Only BootROM Entry
- **What is Verified:**
  General MT6771 BootROM is vulnerable to CVE-2020-0069.
- **What is Inferred:**
  `mtkclient` documentation indicates that 2020 preloader updates patched the USB buffer overflow crash payloads (`0x1d18`/`0x1d1a`). Build C.50 has a security patch level of `2020-09-05` and a build date of `2020-10-16`.
- **What Remains Uncertain:**
  We have not directly tested USB preloader handshake payloads against this physical device due to read-only safety constraints. Stating that C.50 definitively returns `0x1d18` is an inference based on firmware dating, not an experimental observation.

### Area 5: Hardware Testpoint Requirement
- **What is Source-Reported:**
  Repair schematics and videos show that grounding a specific motherboard testpoint (DAT0/CLK) forces MT6771 into BROM mode (`0e8d:0003`).
- **What Remains Uncertain:**
  Claiming that hardware testpoints are the *only* conceivable mechanism to unlock the phone is an unwarranted leap. While no software-only exploit is currently known, public absence of an exploit does not equal mathematical proof of impossibility.

---

## 4. Required Report Adjustments

1. Remove any usage of "TECHNICALLY IMPOSSIBLE". Replace with **`BLOCKED BY MISSING FIRMWARE OR ACCESS`** and **`NO VIABLE ROUTE FOUND WITH CURRENT EVIDENCE`**.
2. Explicitly distinguish between empirical observations on the device and inferences drawn from open-source MTK / LK reverse-engineering tools.
3. Formally index the missing firmware images (`lk.img`, `preloader.bin`) as the primary blocker preventing static binary reverse engineering.
