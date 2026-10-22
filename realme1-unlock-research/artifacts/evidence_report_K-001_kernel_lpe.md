# Evidence Report: K-001 / K-002 — Kernel Local Privilege Escalation

**Candidate ID:** K-001 (evidence gap) / K-002 (attack surface)
**Rank:** 1 (highest potential impact)
**Confidence:** UNKNOWN / PLAUSIBLE

---

## 1. Candidate Summary

**Component:** Linux kernel 4.4.146+ MT6771 vendor kernel (boot.img)
**Sub-components:** MTK GPU/ION/CMDQ/camera/modem/debug drivers
**Vulnerability class:** Memory corruption / permission bypass in kernel driver → kernel code execution → Android root
**Expected impact:** Full Android root (kernel code execution at EL1)
**Persistence:** Not persistent by itself (memory-only); requires combination with persistent write primitive

---

## 2. Evidence Tied to CPH1859 C.50

### 2.1 Kernel Version Evidence (Directly Observed)

From C.49 `boot.img` (SHA-256: `1a82355e63ca593f28224d4180e070acec562b6d45b76f565c84399a56e1b208`):
- Android boot image, page size 2048, kernel at 0x40080000
- Kernel size: 9,771,616 bytes (gzip-compressed)
- Kernel cmdline: `bootopt=64S3,32N2,64N2 buildvariant=user veritykeyid=id:1d4555949ff04fc79ff51daa7b3cbab222f2622a`
- Strings confirm: `Linux version 4.4.146+`, `Android clang 6.0.2`, `MT6771 vendor tree`
- Build path: `kernel-4.4`, dated 2020-05-09

From C.50 CPH1861-reference `boot.img` (SHA-256: `44d9b48d5c49cde8b9df5eb9d67b8feefe4adf381bfb56cc9455e4bae23f98c`):
- Same 4.4.146+ lineage
- Build date: 2020-10-16

From live device (directly observed via `adb shell getprop`):
- `ro.build.version.security_patch`: `2020-09-05` (diagnostic report)
- `ro.board.platform`: `mt6771`
- `ro.mediatek.platform`: `MT6771`

**Inconsistency noted:** The diagnostic report records security patch `2020-09-05`, while the userspace audit states C.49 system image identifies security patch `2020-05-05`. This discrepancy is unresolved — the exact installed C.50 kernel patch level cannot be confirmed without the exact C.50 boot.img.

### 2.2 Driver Surface Evidence (Directly Observed)

Static strings and vendor init/policy identify MT6771-specific interfaces:
- Modem/CCCI, NVRAM, camera/VPU, GPU/Mali, ION, MDP/VCodec, CMDQ/M4U
- Sensors, fingerprint, TEE/Trustonic, USB, debugfs/proc logging
- Engineer/ATCI/meta modes

Vendor init policy includes broad diagnostic permissions including world/system-readable or writable device/debug interfaces in the image configuration.

**These are attack surfaces, not proof of an exploitable defect.**

### 2.3 CVE Cross-Reference

| CVE | Component | Bulletin | Applicability |
|---|---|---|---|
| CVE-2019-19769 | Upstream kernel storage subsystem EoP | Android Sept 2020 | Kernel lineage overlaps, but exact backport and reachable storage path not verified → UNKNOWN |
| CVE-2020-0404 | Upstream kernel USB driver EoP | Android Sept 2020 | MT6771 USB present, but exact vulnerable function and fix state not recovered → UNKNOWN |
| CVE-2020-0407 | Upstream kernel F2FS | Android Sept 2020 | Observed C.49 fstab uses ext4 → DISPROVEN for C.49 default path; UNKNOWN for exact C.50 |

Source: [Android Security Bulletin—September 2020](https://source.android.com/docs/security/bulletin/2020-09-01)

---

## 3. Why This Is NOT a Confirmed Vulnerability

- **No kernel `.config` available** — cannot verify which features/drivers are compiled in
- **No kernel source tree available** — cannot perform function-level comparison against fixing commits
- **No symbol information** — cannot identify vulnerable functions in the vendor kernel binary
- **Exact installed CPH1859 C.50 boot.img is unavailable** — only C.50 CPH1861 reference exists
- **Version overlap is not proof of vulnerability** — vendor backports may have fixed or may not apply
- **No unprivileged trigger path was proven** — static strings are attack surface, not exploitability

---

## 4. Safe Read-Only Next Steps

1. **Obtain model-authenticated CPH1859 C.50 boot.img** (do not flash)
2. **Extract kernel** from boot.img (gzip-decompress at offset 0)
3. **Compare vulnerable functions** against fixing commits from Android kernel source
4. **Check vendor backport status** for CVE-2019-19769 and CVE-2020-0404
5. **Static analysis only** — no live triggering or exploit payloads

---

## 5. Source Locations

- C.49 boot.img: `/home/ameya/Realme1/C49_extracted/boot.img`
- C.50 reference boot.img: `/home/ameya/Realme1/C50_research/CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t/boot.img`
- Extracted kernel: `/tmp/C49_kernel.bin` (9,771,616 bytes, gzip-compressed)
- Kernel audit: `/home/ameya/Realme1/CPH1859/realme1-unlock-research/artifacts/kernel_audit.md`
- Vulnerability matrix entry: K-001, K-002, K-004 in `vulnerability_matrix.json`

---

## 6. Conclusion for K-001/K-002

A kernel vulnerability in the 4.4.146+ MT6771 vendor kernel would directly yield Android root. The kernel version overlaps September 2020 Android security bulletin candidates, but exact backport/mitigation status cannot be established without the kernel `.config` and source. **This is an evidence gap, not a confirmed finding.** The highest-value missing evidence is the exact CPH1859 C.50 kernel image with configuration and source provenance.