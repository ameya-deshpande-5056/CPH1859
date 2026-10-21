# Sources Index: Realme 1 (CPH1859) Bootloader Unlock Research

This file maintains an index of primary and secondary sources, technical documentation, community threads, and source code repositories referenced during this investigation.

## External Sources Index

| Source ID | Title / Resource | Author / Publisher | Type | Direct URL | Access Date | Claims & Relevance |
|---|---|---|---|---|---|---|
| **SRC-001** | *Realme 1 Bootloader Unlock & In-Depth Test Guide* | Realme Community / Official | Primary Vendor | https://c.realme.com/in/post-details/1154673752672768000 | 2026-10-21 | Documents the official bootloader unlock process using DeepTesting APK and fastboot flashing unlock command. |
| **SRC-002** | *How to Fix Fastboot Unlock Verity Fail / The Serial is Not Match* | DroidWin (Manu J) | Secondary Analysis | https://droidwin.com/fix-the-serial-is-not-match-fastboot-unlock-verify-fail/ | 2026-10-21 | Explains that the error originates from LK verifying token signatures against serial numbers during fastboot entry. |
| **SRC-003** | *MTKClient: Vulnerability & BROM Exploitation Tool* | B. Kerler (bkerler) | Open Source Codebase | https://github.com/bkerler/mtkclient | 2026-10-21 | MediaTek BootROM exploit suite supporting MT6771; details preloader crash mechanisms and SLA/DAA bypass constraints. |
| **SRC-004** | *Helio P60 (MT6771) BootROM Exploit and Preloader Handshake* | XDA Forums Contributors | Technical Community | https://xdaforums.com/t/guide-mtk-bkerler-mtkclient-for-helio-p60-p70.4357731/ | 2026-10-21 | Discusses MT6771 BROM communication, DA timeout workarounds, and necessity of hardware testpoints on patched preloaders. |
| **SRC-005** | *Realme 1 CPH1859 ROMs & Firmware Versions (C.49 vs C.50)* | XDA Forums / Developers | Technical Community | https://xdaforums.com/t/rom-realme-1-cph1859-lineageos-17-1.4150619/ | 2026-10-21 | Confirms that C.50 broke unlock/modding compatibility, and community established C.49 as the maximum supported base. |
| **SRC-006** | *Android Verified Boot (AVB) Architecture & Little Kernel (LK)* | Android Open Source Project (AOSP) | Primary Specification | https://source.android.com/docs/security/features/verifiedboot/avb | 2026-10-21 | Details verified boot state flow, `green`/`orange`/`yellow`/`red` flags, and security configuration (`seccfg`). |
| **SRC-007** | *MediaTek Kamakiri Exploit & Preloader Crashing Analysis* | XYZ / Freesmartphone Security | Research Publication | https://github.com/xyzz/kamakiri | 2026-10-21 | Analysis of BootROM USB control transfer vulnerability (CVE-2020-0069 / kamakiri) and subsequent vendor patching. |
| **SRC-008** | *LKPatcher: MediaTek Little Kernel Security Policy Patcher* | R0rt1z2 | Open Source Tool | https://github.com/R0rt1z2/lkpatcher | 2026-10-21 | Documents binary patterns (`needles`) and Thumb-2 opcodes (`00207047`) used to bypass LK fastboot entry locks and dm-verity checks. |
| **SRC-009** | *CPH1859 Android Device Tree* | kardebayan | Open Source Codebase | https://github.com/kardebayan/android_device_oppo_CPH1859 | 2026-10-21 | Minimal AOSP device tree for Realme 1 CPH1859; confirms partition configuration and platform properties. |
| **SRC-010** | *Realme 1 & Realme U1 Android Pie Kernel Source* | realme-kernel-opensource | Primary Vendor Codebase | https://github.com/realme-kernel-opensource/realme1_realmeU1_AndroidP-kernel-source | 2026-10-21 | Official GPL kernel source for CPH1859; confirms MT6771 driver tree and partition block layouts. |

---

## Citation Standards
- **Primary:** Manufacturer documentation, official source trees, vendor security bulletins.
- **Secondary:** Independent reverse engineering writeups, verified security research publications.
- **Community:** Forum discussions and developer threads (clearly designated as unverified until replicated).
