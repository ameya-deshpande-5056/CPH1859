# Comprehensive Read-Only Security Audit: Realme 1 CPH1859 / MT6771

**Audit date:** 2026-10-21
**Target:** Realme 1 CPH1859, Android 9, reported installed build `CPH1859EX_11_C.50`
**Safety status:** No flashing, erasing, partition writes, live exploit payloads, or bootloader-state changes were performed. The phone remains factory-locked and unmodified.

## Executive assessment

No vulnerability was confirmed to provide Android root, persistent root, or a software-only bootloader-state change.

The strongest reproducible result is a cryptographic Fastboot authorization gate in both analyzed LK references. `verify_unlock_token()` is byte-identical in C.49 and the available C.50 reference; it requires an eFUSE-bound serial and OEM RSA-2048 RSASSA-PSS/SHA-256 signature stored in `reserve4` sector `0x7816`. Failure causes a watchdog reboot before Fastboot commands are exposed.

The C.50 files are not exact-device CPH1859 evidence: the OTA metadata and updater script explicitly identify/enforce CPH1861. Their differential similarity to C.49 is strong evidence about the shared `oppo6771_17065` codebase, but not proof about the installed CPH1859 partitions.

## Components actually available

| Component | Available evidence | Audit boundary |
|---|---|---|
| C.49 preloader/LK | Full binaries; C.49 extraction has CPH1859 project provenance | Direct static analysis |
| C.50 preloader/LK | Full CPH1861-targeted OTA reference | Reference comparison only |
| C.49 boot/recovery/system/vendor/ODM and auxiliary images | Full extracted images, including sparse filesystems | Direct static/static filesystem audit |
| C.50 boot and auxiliary images | Full reference images; system/vendor are compressed block-update payloads | CPH1861 reference only |
| C.50 Android filesystem | Not fully extracted or exact-device | Cannot establish exact C.50 userspace policy/package state |
| Exact installed CPH1859 C.50 LK/preloader/boot/vendor/system | Missing/inaccessible to unprivileged ADB | Key unresolved limitation |
| Kernel source/config | Missing | CVE applicability cannot be proven from version alone |
| Physical BootROM/preloader runtime trace | Not collected by design | Host-triggerability remains unresolved |

The complete 171-file manifest, sizes, types, SHA-256 values, partition metadata and missing-component list is in [artifacts/firmware_inventory.json](artifacts/firmware_inventory.json) and [artifacts/firmware_inventory.md](artifacts/firmware_inventory.md).

## Confirmed boot-chain facts

- C.49 LK SHA-256: `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa`.
- C.50 reference LK SHA-256: `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563`.
- `verify_unlock_token()` spans RAM `0x6002EB00`–`0x6002EDCC`; its function hash is identical in both references.
- The token read resolves to partition `reserve4`, sector `0x7816`, byte offset `0x00F02C00`; the 4 KB buffer contains a 256-byte signature and 16-byte serial field at `+0x100`.
- The verifier uses RSA-2048 RSASSA-PSS/SHA-256 with MGF1-SHA-256, 32-byte salt and trailer `0xBC`, against an embedded OEM public key at RAM `0x6007EE48` / file `0x7F048`.
- `fastboot_init()` calls the verifier, prints `fastboot_unlock_verify fail`, and resets on failure. `flashing unlock` is registered only after successful initialization; `fastboot oem unlock` is absent.
- The C.49/C.50 LK diff is exactly 315 bytes, confined to build metadata and cert2 digest/signature clusters. The normalized preloader diff is 569 bytes, with executable code identical under the validator's defined code region.
- MediaTek certificate and payload-digest checks pass mathematically. Physical eFUSE trust-root equality is not observable from these files.

See [artifacts/boot_chain_audit.md](artifacts/boot_chain_audit.md) and [artifacts/c50_differential_validation.md](artifacts/c50_differential_validation.md).

## Android userspace assessment

The directly inspectable C.49 system/vendor images contain many privileged apps and vendor services. The Oppo Engineer HIDL daemon runs as `system` and its CIL policy grants the `engineer_hidl` domain broad access to the generic Oppo reserve block-device class and engineering files. `system_server` and `engineermode_app` are shown as clients; an untrusted-app path was not found. ATCI/meta/factory/debug services exist but are disabled or engineering-gated in the observed user build.

This is a high-value attack surface, not a confirmed vulnerability. The live posture recorded SELinux enforcing, restrictive raw block-device permissions, and `Permission denied` for unprivileged LK access. The exact CPH1859 C.50 userspace remains unavailable.

See [artifacts/android_userspace_audit.md](artifacts/android_userspace_audit.md).

## Kernel assessment

Both available boot references report Linux `4.4.146+` on MT6771. The image exposes extensive MTK-specific driver and diagnostic surfaces. The Android September 2020 bulletin lists CVE-2019-19769, CVE-2020-0404, and CVE-2020-0407 as kernel candidates at the relevant patch level. The evidence does not establish the exact vendor backport state or an unprivileged trigger. C.49's observed ext4 fstab makes the F2FS candidate inapplicable to that default path; exact C.50 remains unknown.

The kernel result is therefore `UNKNOWN`/`PLAUSIBLE` leads, not confirmed root access.

See [artifacts/kernel_audit.md](artifacts/kernel_audit.md).

## Vulnerability and route classification

The detailed matrix is in [artifacts/vulnerability_matrix.json](artifacts/vulnerability_matrix.json) and [artifacts/vulnerability_matrix.md](artifacts/vulnerability_matrix.md).

| Route/finding | Status | Root impact |
|---|---|---|
| LK OEM token gate | Confirmed in both references; exact CPH1859 C.50 applicability unknown | Blocks Fastboot without token; not root |
| DeepTesting token pipeline | Confirmed historically; backend/token issuance unavailable | Supported bootloader-state route, not a vulnerability |
| Engineer HIDL/raw reserve surface | Plausible attack surface | No untrusted caller bypass proven |
| Android 9 kernel CVE candidates | Unknown applicability | No confirmed Android LPE |
| MT6771 BootROM/Kamakiri lead | Plausible chipset-level lead | Requires exact BootROM mode; no live trigger |
| Preloader indirect DA/BROM dispatch | Unknown | No demonstrated bootloader-state change |
| Stock recovery route | Strong negative evidence in C.49 | No direct unlock/root path found |

## Direct answers

1. **Components available:** Full C.49 boot/recovery/system/vendor and auxiliary images; C.50 CPH1861-targeted LK/preloader/boot/auxiliary images plus compressed system/vendor OTA payloads. Exact CPH1859 C.50 boot-chain/userspace provenance is missing.
2. **Confirmed findings affecting this firmware:** The OEM token gate, its serial/signature rules, watchdog failure behavior, and the reference-image certificate/differential facts. These are controls, not exploitable vulnerabilities.
3. **Chipset/version-only leads:** Android kernel CVEs, MT6771 BootROM/Kamakiri, and unresolved preloader DA/security dispatch.
4. **Plausible Android-root path:** None demonstrated. A kernel or vendor-service bug could theoretically provide an LPE, but no exact applicable bug was identified.
5. **Separate persistent-root path:** None demonstrated. Persistent root would additionally require a bootable/persistent modification path through the locked boot chain or a durable userspace compromise.
6. **Bootloader-state change:** The supported token route is architecturally established but unavailable; the BootROM/preloader route is plausible only as an unresolved, model-dependent lead. No state change was attempted.
7. **Highest-value unresolved question:** Does an authenticated CPH1859 C.50 preloader/boot/userspace differ materially from the CPH1861 reference in indirect DA/USB security dispatch or kernel backports?
8. **Evidence needed:** Model-authenticated CPH1859 C.50 OTA/images, exact `lk`/preloader/boot/vendor/system hashes, extracted C.50 sepolicy and service binaries, kernel config/source provenance, and loader-aware static analysis. No live exploit testing is required to answer the provenance/differential questions.

## Reproducibility

The validator path was repaired from the obsolete `C50_research/c50_static` location to the actual OTA extraction, and truncated-input handling was hardened. Results:

```text
PYTHONPATH=src:scripts python3 -m unittest discover -s tests   # 41 tests: OK
PYTHONPATH=src:scripts python3 scripts/validate_lk_differential.py \
  --json-out artifacts/c50_differential_validation.json \
  --markdown-out artifacts/c50_differential_validation.md     # PASS
PYTHONPATH=src:scripts python3 scripts/generate_firmware_inventory.py # 171 files
```

No phone write, flash, erase, payload execution, or bootloader-state modification occurred.
