# Evidence-Driven Research & Firmware Reverse Engineering Report: Realme 1 (CPH1859 C.50)

## Executive Summary & Formal Project Outcome

**Research Objective:** Investigate whether the Realme 1 (CPH1859), running ColorOS based on Android 9, firmware build `CPH1859EX_11_C.50`, can have its bootloader unlocked through a software-only method without opening the device, shorting motherboard testpoints, or using proprietary servicing tools.

**Formal Outcome:** **`NO VIABLE SOFTWARE-ONLY UNLOCK ROUTE FOUND IN THE ANALYZED EVIDENCE`**
*(The phone is CPH1859 C.50, while the available C.50 LK/preloader references are documented as CPH1861-targeted; exact installed-image provenance is not established.)*

In strict accordance with empirical research standards, this report updates and calibrates all previous claims. Unsupported certainty (such as declaring bootloader unlock "mathematically or technically impossible") has been removed. Instead, the evidence demonstrates that:
1. Static reverse engineering of the supplied reference images found the C.50 Little Kernel and normalized Preloader executable regions **byte-identical** to C.49, with LK differences limited to 27 build-metadata bytes plus certificate digest/signature bytes. This is not proof about the exact installed CPH1859 partitions.
2. The observed error `the serial is not match / fastboot_unlock_verify fail` is directly supported by C.49 disassembly at `0x6002EB00` / `0x60030018`. The C.50 reference has the identical gate. It compares the token serial field with the eFUSE-derived serial and verifies an RSA-2048 RSASSA-PSS signature against an embedded OEM public key, then reboots via watchdog on failure.
3. The official vendor-supported unlock pathway (In-Depth Test APK) is **source-reported** to be decommissioned on vendor servers and incompatible with build C.50.
4. MediaTek BootROM exploitation ([CVE-2020-0069](https://github.com/bkerler/mtkclient)) is source-supported for the chipset, but no exact-device software-only entry was demonstrated. Preloader mediation, secure-state policy, and emergency reset paths remain partly unresolved statically.

The target phone remains in a **100% unmodified factory state** (`ro.boot.flash.locked = 1`, `ro.boot.verifiedbootstate = green`).

---

## 1. Evidence Audit & Epistemic Calibration

All claims in this research have been subjected to an evidence audit using a five-tier epistemic taxonomy:
- **`directly observed`**: Verified via primary execution on the host or connected device.
- **`independently verified`**: Confirmed across multiple primary open-source codebases or vendor advisories.
- **`source-reported`**: Derived from credible community forums or developer threads; not reproduced locally.
- **`inferred`**: Logical deduction from platform conventions and timing; lacks direct binary disassembly.
- **`unsubstantiated`**: Assertions made without empirical backing (now corrected).

### Evidence Audit Matrix

| Claim ID | Technical Claim | Epistemic Status | Supporting Evidence / Audit Finding |
|---|---|---|---|
| **CLM-001** | Device is CPH1859, Android 9 (API 28), build `CPH1859EX_11_C.50`, patch date 2020-09-05. | **`directly observed`** | Verified via `adb shell getprop` (`TEST_004_PROPS`). |
| **CLM-002** | Bootloader is locked (`flash.locked = 1`), AVB is `green`, verity mode is `enforcing`. | **`directly observed`** | Verified via `adb shell getprop` (`TEST_004_PROPS`, `TEST_007_POSTURE`). |
| **CLM-003** | OEM Unlocking toggle is enabled in Developer Options (`sys.oem_unlock_allowed = 1`). | **`directly observed`** | Verified via `adb shell getprop` (`TEST_007_POSTURE`). |
| **CLM-004** | Fastboot mode is not currently active on the USB bus during normal OS operation. | **`directly observed`** | Verified via `fastboot devices` (`TEST_005_FASTBOOT`). |
| **CLM-005** | DeepTesting application is not installed on the Android user-space partition. | **`directly observed`** | Verified via `adb shell pm list packages` (`TEST_006_PACKAGES`). |
| **CLM-006** | `adb reboot bootloader` displays `the serial is not match` and `fastboot_unlock_verify fail` on-screen and immediately boots normal ColorOS. | **`directly observed`** | Observed during live reboot transition; verified via binary disassembly at `0x6002EB00`/`0x60030018`. |
| **CLM-007** | The string `fastboot_unlock_verity` (with a 't') is absent from user-space ELF binaries and LK/Preloader firmware. | **`directly observed`** | Verified via recursive `grep` over ADB shell and binary search in C.49/C.50 `lk.img`. |
| **CLM-008** | The error string is displayed by the Little Kernel (`lk` / `lk2`) bootloader stage during `fastboot_init()`. | **`directly observed`** | Disassembled at RAM `0x60030050` (file offset `0x030250`), printing string from `0x600809FC`. |
| **CLM-009** | The check occurs in `fastboot_init()` calling token verifier `verify_unlock_token()` at RAM `0x6002EB00`. | **`directly observed`** | Directly disassembled and verified byte-identical between C.49 and C.50 Little Kernel. |
| **CLM-010** | The verification routine reads 4 KB from sector `0x7816` of `reserve4`, checking 16-byte efuse serial and RSA-2048 signature against public key at `0x6007EE48`. | **`directly observed`** | Directly disassembled in `verify_unlock_token()` (`0x6002EB00`) and `read_reserve4()` (`0x6002C794`). |
| **CLM-011** | Realme In-Depth Test server infrastructure for ColorOS 5.x/6.x is permanently decommissioned. | **`source-reported`** | Community consensus across XDA and Realme forums; Realme 1 reached EOL in 2020. |
| **CLM-012** | Build C.50 natively broke compatibility with the legacy In-Depth Test application. | **`source-reported`** | Documented on XDA Forums; developers mandated downgrading to C.49 before unlocking. |
| **CLM-013** | MediaTek MT6771 (Helio P60) BootROM contains the USB control transfer exploit ([CVE-2020-0069](https://github.com/bkerler/mtkclient)). | **`independently verified`** | Confirmed by MediaTek security advisory 2020-03 and `bkerler/mtkclient`. |
| **CLM-014** | Build C.50 Preloader patches USB crash payloads (`0x1d18`/`0x1d1a` RX errors). | **`source-reported`** / **`inferred`** | Inferred from MT6771 patch history and 2020 firmware date; not directly executed on device. |
| **CLM-015** | Forcing BootROM mode on C.50 requires opening the device and grounding the DAT0/CLK testpoint. | **`source-reported`** | Documented repair technique; claiming it is the *only* conceivable method was unsupported certainty. |

---

## 2. Firmware Inventory & Access Blockage Analysis

### Local File Inventory
A search was conducted across the workspace and host filesystems:
- Target files: `*.ozip`, `*.ofp`, `*.bin`, `*.img`, `*CPH1859*`.
- Result: No exact, model-authenticated CPH1859 C.50 package was found in the project directory.
- Found files: C.49 references in `/home/ameya/Realme1/C49_extracted/` and C.50 reference LK/preloader images in `/home/ameya/Realme1/C50_research/c50_static/`; project provenance identifies the C.50 references as CPH1861-targeted.

### Live Device Partition Node Probing
Partition block nodes were examined on the connected Realme 1 over ADB:
```text
/dev/block/by-name/lk           -> /dev/block/mmcblk0p33 (mode: brw------- root:root)
/dev/block/by-name/lk2          -> /dev/block/mmcblk0p34 (mode: brw------- root:root)
/dev/block/by-name/preloader_a  -> /dev/block/mmcblk0boot0 (mode: brw-rw---- root:system)
/dev/block/by-name/seccfg       -> /dev/block/mmcblk0p17 (mode: brw------- root:root)
/dev/block/by-name/proinfo      -> /dev/block/mmcblk0p20 (mode: brw------- root:root)
```

**Empirical Read Check:**
```bash
adb shell "head -c 16 /dev/block/by-name/lk"
# Result: head: /dev/block/by-name/lk: Permission denied
```

### Exact-device provenance limitation & reference analysis
The installed CPH1859 C.50 partition nodes remain inaccessible to unprivileged ADB, but reference C.50 LK/preloader images are available and reproducibly analyzed:
1. **C.49 Baseline Fully Characterized & Audited:** Extracted C.49 binaries (`lk.img`, `preloader_oppo6771_17065.bin`) were analyzed and audited in `artifacts/c49_bootloader_format_analysis.md` (ART-007). The container layout was proven to be MediaTek `union prt_img_hdr` (512-byte header, 749,772-byte payload, followed by two 512-byte certificate containers `cert1` and `cert2`), running at base DRAM address `0x60000000` with ARMv7/Thumb-2 state switching.
2. **Fastboot Gatekeeper & Hardware WDT Reset:** In C.49 LK, `fastboot_init()` at `0x60030018` calls `0x6002eb00`, which reads the efuse board serial and validates an OEM RSA-2048/SHA-256 token read from sector `0x7816` (`0x00f02c00` bytes) of partition `reserve4`. On failure, it outputs `fastboot_unlock_verify fail\n\n` and calls `0x6000cd30` (`mtk_arch_reset`), writing magic `0x1971` to the hardware watchdog timer (`0x10007000`/`0x10007008`) to force an immediate reboot to normal ColorOS.
3. **Relocking Path & `clean_flash_unlock_data` Scope:** `clean_flash_unlock_data` (`0x6002eacc`) is called strictly during relocking (`cmd_flashing_lock` at `0x60036920`), zeroing the 4 KB token slot at sector `0x7816` of `reserve4`. It is never called on failed boot.
4. **Unlock Logic & FRP Flag Offset Traced:** Handlers for `flashing get_unlock_ability` (`0x60036518`) and `flashing unlock` (`0x60036648`) query `0x60036390`, which reads the 4-byte flag from `partition_size - 4` of the `"frp"` partition.
5. **Reference differential result:** The supplied C.50 reference LK differs from C.49 in exactly 315 bytes; the token verifier and Fastboot initializer are byte-identical. The supplied normalized C.50 reference preloader differs in 569 bytes confined by the validator to metadata/signature regions. This resolves the reference-image string question, but does not prove that the installed CPH1859 image is identical.

---

## 3. Vulnerability & Attack Surface Assessment (Software-Only Routes & Prerequisites)

Five potential routes were systematically evaluated against explicit prerequisites and verified device evidence:

### Prerequisite Classification Matrix

| Route Category | Proposed Route | Explicit Prerequisite | Verified Device Evidence | Status & Unknowns / Blockers |
|---|---|---|---|---|
| **Supported OEM Authorization** | In-Depth Test (DeepTesting) Client-Server Handshake | Live backend signing server issuing RSA-2048 token matching hardware serial; client APK compatibility on C.50 | Token verifier `0x6002eb00` verifies RSA-2048/SHA-256 token at sector `0x7816` of `reserve4`; device properties show `ro.oem_unlock_supported = 1` | **BLOCKED:** Servers permanently offline post-2020 EOL; private key undisclosed; C.50 community-reported incompatible with legacy APK |
| **Ordinary Android / ADB Access** | Partition Write via ADB shell | Elevated local privilege (root) or permissive block node permissions to write to `reserve4`, `lk`, or `frp` | Block nodes `/dev/block/by-name/{lk,reserve4,frp}` are strictly mode `0600 root:root`; ADB runs as UID 2000 (`shell`); SELinux `Enforcing` | **BLOCKED:** Unprivileged ADB cannot read or write raw partitions (`Permission denied`); zero verified LPE exploits on Android 9 Sept 2020 patch |
| **Fastboot Command Access** | Standard Fastboot Protocol (`flashing unlock`) | Device remains in Fastboot mode over USB, accepting command packets | `fastboot_init()` calls `verify_unlock_token()`, fails due to absent/invalid token in the analyzed path, prints `fastboot_unlock_verify fail`, and triggers hardware watchdog reset | **BLOCKED in analyzed images:** command registration is reached only after successful verification |
| **Demonstrated Software Vulnerability** | In-Memory Patch / Memory Corruption in LK | Working unauthenticated software exploit bypassing memory protections in ColorOS kernel or Little Kernel | Static analysis confirms patching `0x6002eb00` to return `0` (`movs r0, #0; bx lr`) would bypass check | **BLOCKED:** Modifying LK on flash is rejected by preloader AVB; no remote/local software-only memory exploit demonstrated on C.50 |
| **BootROM / Preloader-Level Access** | MediaTek BootROM USB Control Transfer Exploit (CVE-2020-0069) | USB device connection in true BootROM mode (`0e8d:0003`) without preloader mediation | SoC is MT6771; reference preloader contains USB/DA security and emergency BROM-reset paths | **NOT DEMONSTRATED:** exact-device crash-payload behavior and host reachability of the reset path remain unknown |

### Candidate 1: Little Kernel Fastboot Verification Bypass
- **Target Binary:** `lk.img` / `lk2.img` (ColorOS build C.50).
- **Vulnerability Mechanics:** The bootloader contains a conditional gate that prevents Fastboot initialization when a serial mismatch occurs. Open-source patch engines ([`R0rt1z2/lkpatcher`](https://github.com/R0rt1z2/lkpatcher)) show that modifying the verification function to return Thumb-2 `00207047` (`movs r0, #0; bx lr`) bypasses this check.
- **Prerequisites & Access:** Modifying `lk.img` requires write access to `/dev/block/mmcblk0p33`. On a locked bootloader, flashing modified partitions is rejected by Android Verified Boot (AVB) in the preloader.
- **Reproducibility:** The failure is recorded on the phone; the reference LK reproduces the gate. Bypassing it via a software write was not demonstrated and would require prohibited partition modification.
- **Unlock Efficacy:** High (would allow standard `fastboot flashing unlock`).
- **Safety Risk:** Critical brick risk if patched LK fails signature verification during preloader handoff.

### Candidate 2: In-Depth Test (DeepTesting) Client-Server Protocol
- **Target Binary:** `com.coloros.deeptesting` / `com.coloros.sau`.
- **Vulnerability Mechanics:** Exploiting or mocking the client-server handshake to issue an authorized unlock token locally.
- **Prerequisites & Access:** Server endpoint availability or reversing the cryptographic signing private key.
- **Reproducibility on C.50:** Blocked. Servers are offline, and C.50 is source-reported to reject the legacy client.
- **Unlock Efficacy:** High (official OEM unlock path).
- **Safety Risk:** Zero brick risk (wipes user data via standard factory reset).

### Candidate 3: MediaTek BootROM USB Control Transfer Overflow (CVE-2020-0069)
- **Target Binary:** MediaTek MT6771 On-Chip BootROM (Silicon ROM).
- **Vulnerability Mechanics:** Buffer overflow during USB control transfers in BootROM mode (`0e8d:0003`) allows code execution to disable SLA/DAA authentication and patch the `seccfg` partition directly.
- **Prerequisites & Access:** Device must be connected in BootROM mode, NOT Preloader mode (`0e8d:2000`).
- **Reproducibility:** The chipset-level vulnerability is source-supported; forcing BootROM mode over software on this device was not demonstrated.
- **Unlock Efficacy:** High (direct `seccfg unlock` via `mtkclient`).
- **Safety Risk:** Low-to-medium; risk of metadata corruption if partition tables mismatch.

### Candidate 4: Preloader USB Handshake Crash Vector (`kamakiri2` / `crash da`)
- **Target Binary:** `preloader_cph1859.bin`.
- **Vulnerability Mechanics:** Sending malformed DA packets to the Preloader COM port to trigger an unhandled exception/watchdog reset into BootROM mode.
- **Prerequisites & Access:** Connecting over USB in Preloader mode.
- **Reproducibility:** Source-reported for some 2020 MT6771 firmwares; not live-tested on this target.
- **Unlock Efficacy:** Moderate (stepping stone to Candidate 3).
- **Safety Risk:** Preloader hang if payload causes unexpected state.

---

## 4. Synthesis & Recommendations

### Summary of Technical Blockers
1. **No Software Route to Fastboot:** Little Kernel enforces a hardware serial check and aborts to ColorOS upon failure.
2. **No demonstrated software route to BootROM:** The preloader contains USB/DA security and emergency BROM-reset paths, but exact reachability and crash-payload behavior on the target were not live-tested.
3. **No Local Privilege Escalation:** Production Android 9 with the September 2020 patch level enforces strict DAC and SELinux separation on raw block devices.
4. **Exact-image uncertainty:** The CPH1861-targeted C.50 references are not a substitute for a model-authenticated CPH1859 C.50 package.

### Recommended Next Steps for the User
- **To Maintain the Software-Only Constraint:** Conclude the investigation at this boundary. Do not flash random partition images or execute unverified exploit payloads that risk bricking the device.
- **To reduce the remaining uncertainty:** Acquire a model-authenticated copy of the `CPH1859EX_11_C.50.ozip` package, decrypt it with `bkerler/oppo_ozip_decrypt`, and compare its `lk`, preloader, and recovery images against the current references.
- **If Hardware Constraints are Relaxed in the Future:** The device casing can be opened to ground the DAT0/CLK testpoint, forcing true BootROM mode for `mtkclient` flashing.
