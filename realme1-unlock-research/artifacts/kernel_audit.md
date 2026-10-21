# Kernel Security Audit

## Identified kernel

The C.49 `boot.img` (`1a82355e63ca593f28224d4180e070acec562b6d45b76f565c84399a56e1b208`) and C.50 CPH1861 reference `boot.img` (`44d9b48d5c49cde8b9df5eb9d67b8feefe4adf381bfb56cc9455e4bae23f98c`) contain a gzip-compressed ARM64 kernel reporting:

`Linux version 4.4.146+`, Android clang 6.0.2, MT6771 vendor tree.

The C.49 kernel build path is `kernel-4.4`, dated 2020-05-09. The C.50 reference kernel is dated 2020-10-16 and uses the same reported 4.4.146+ lineage. A kernel `.config` and source tree were not available, so configuration-dependent conclusions are limited.

## Driver and interface inventory

Static strings and vendor init/policy identify MT6771-specific interfaces for modem/CCCI, NVRAM, camera/VPU, GPU/Mali, ION, MDP/VCodec, CMDQ/M4U, sensors, fingerprint, TEE/Trustonic, USB, debugfs/proc logging, and Engineer/ATCI/meta modes. The vendor init policy includes several broad diagnostic permissions, including world/system-readable or writable device/debug interfaces in the image configuration. These are attack surfaces, not proof of an exploitable defect.

The fstab uses ext4 for system, vendor, ODM, userdata, persist, protect, nvdata, and nvcfg. This reduces the relevance of F2FS-only candidates to the observed C.49 configuration, but does not rule out an F2FS code path in a different partition or exact C.50 build.

## Public vulnerability cross-reference

The official Android September 2020 bulletin lists these upstream kernel candidates at the `2020-09-05` patch level:

| Candidate | Component/type in bulletin | Applicability to this evidence | Confidence |
|---|---|---|---|
| CVE-2019-19769 | upstream kernel, storage subsystem, EoP | Kernel lineage overlaps, but exact backport and reachable storage path were not verified | `UNKNOWN` |
| CVE-2020-0404 | upstream kernel, USB driver, EoP | MT6771 USB is present, but exact vulnerable function and fix state were not recovered | `UNKNOWN` |
| CVE-2020-0407 | upstream kernel, F2FS | Observed C.49 fstab uses ext4; exact C.50 filesystem/config is unavailable | `DISPROVEN` for the observed C.49 default path; `UNKNOWN` for exact C.50 |
| CVE-2020-0069 / Kamakiri reports | MediaTek BootROM lead in existing research | This is below the Linux kernel and requires exact BootROM mode/SoC behavior; no exact-device trigger was demonstrated | `PLAUSIBLE` chipset-level lead only |

Source: [Android Security Bulletin—September 2020](https://source.android.com/docs/security/bulletin/2020-09-01). The bulletin is evidence that the candidates existed at the relevant patch level; it is not evidence that the exact vendor implementation is vulnerable.

## Findings

### K-001 — Old vendor kernel lineage

**Classification:** exposure/lead, not a vulnerability claim; `STRONGLY SUPPORTED`.

The 4.4.146+ vendor kernel is substantially older than current Android kernels and contains extensive proprietary drivers. This increases the candidate set, but version overlap alone cannot establish exploitability. No source-level vulnerable function, missing backport, or unprivileged trigger was proven.

### K-002 — Broad MTK diagnostic driver surface

**Classification:** attack surface; `PLAUSIBLE`.

The image exposes MTK-specific debugfs/proc/sysfs and device-driver interfaces, including GPU, ION, camera/VPU, CMDQ/M4U, modem, sensor, and logging paths. Some permissions are granted to system/radio/diagnostic domains. No reproducible ioctl bug or untrusted-app access chain was established.

### K-003 — Kernel CVE candidates

**Classification:** unresolved applicability; `UNKNOWN`.

For each candidate above, the necessary next step is exact-image function-level comparison against the fixing commit/backport and policy-guided reachability analysis. Live triggering is outside this read-only audit and was not performed.

## Kernel conclusion

The evidence establishes a 4.4.146+ MT6771 vendor kernel and several high-value driver surfaces, but it does not confirm an unprivileged kernel LPE. The highest-value kernel artifact is the exact CPH1859 C.50 `boot.img` plus extracted kernel configuration and symbol/source provenance. Until then, CVE claims remain leads rather than findings affecting this phone.
