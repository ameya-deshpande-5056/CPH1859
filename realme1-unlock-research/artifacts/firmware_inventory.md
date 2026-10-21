# Firmware Inventory: Realme 1 (CPH1859 / diamond)

## Overview
This document records the firmware packages, OTA structures, and cryptographic decryption parameters identified for the Realme 1 (CPH1859 / MT6771).

## Build Catalog & Unlock Viability

| Version / Build Identifier | Release Date | Android / ColorOS | Bootloader Unlock Viability | Notes & Community Verification |
|---|---|---|---|---|
| **CPH1859EX_11_A.20 - A.31** | 2018 | Android 8.1 / ColorOS 5.2 | High (Historical) | Original Oreo base builds. Supported early In-Depth Test versions. |
| **CPH1859EX_11_C.46 - C.48** | 2019-2020 | Android 9 / ColorOS 6.0 | High (Historical) | Stable base for Pie DeepTesting APK. Primary target for TWRP/LineageOS 17.1 installations. |
| **CPH1859EX_11_C.49** | Mid 2020 | Android 9 / ColorOS 6.0 | Moderate (Historical) | Last build universally acknowledged on XDA as compatible with In-Depth Test unlocking. |
| **CPH1859EX_11_C.50** (Target) | 2020-10-16 | Android 9 / ColorOS 6.0 | **BLOCKED (Software-Only)** | Security patch level `2020-09-05`. Patched preloader prevents software BROM entry; DeepTesting app deprecated/unsupported; fastboot checks enforce signed serial token. |

---

## Package Architecture & Formats

1. **Format:** Distributed primarily as encrypted `.ozip` archives.
2. **Decryption Method:** AES-128-CBC via `oppo_ozip_decrypt` (B. Kerler).
3. **Internal Partitions:**
   - `preloader_cph1859.bin`: MediaTek secondary bootloader running in eMMC boot partition.
   - `lk.img` / `lk2.img`: Little Kernel bootloader containing the fastboot engine and `fastboot_unlock_verity` routine.
   - `boot.img`: Linux kernel + ramdisk.
   - `recovery.img`: Stock ColorOS recovery (checks Oppo RSA signatures on `.ozip` before applying).
   - `system.new.dat.br`: Android system image (brotli-compressed sparse data).
   - `vendor.new.dat.br`: MediaTek HALs and proprietary vendor drivers.
   - `vbmeta.img`: Android Verified Boot metadata and partition hash trees.
