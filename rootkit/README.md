# Realme 1 (CPH1859) Rooting Assessment & CVE Feasibility Suite

This directory contains diagnostic assessment scripts, reproducible report generators, and vulnerability feasibility analyses for exploring software-only rooting vectors on the **OPPO Realme 1 (CPH1859)** running firmware **`CPH1859EX_11_C.50`**.

---

## Target System Profile

- **Device:** OPPO Realme 1 (CPH1859)
- **SoC:** MediaTek MT6771 (Helio P60)
- **OS Version:** Android 9 (Pie, API Level 28)
- **Firmware Build:** `CPH1859EX_11_C.50`
- **Kernel Version:** Linux `4.4.146+` (aarch64, PREEMPT)
- **Security Posture:** Locked bootloader (`ro.boot.flash.locked=1`), SELinux Enforcing, Production User Build (`ro.debuggable=0`, `ro.secure=1`)

---

## Key Deliverables & Reports

| Document | Description |
| :--- | :--- |
| **[`FINAL_ROOT_ASSESSMENT.md`](FINAL_ROOT_ASSESSMENT.md)** | Consolidated audit report evaluating non-destructive software root paths (ADB root, BROM/Preloader entry, APK sideloading, local binary execution) and verifying the factory state. |
| **[`CVE_2026_43499_FEASIBILITY.md`](CVE_2026_43499_FEASIBILITY.md)** | Technical feasibility analysis of CVE-2026-43499 ("GhostLock", futex priority-inheritance UAF) on the device's unpatched `4.4.146+` kernel, evaluating barriers such as ARMv8 PAN/PXN, MediaTek BSP struct offsets, and lack of symbol resolution. |

---

## Script Inventory

| Script | Purpose |
| :--- | :--- |
| `00_preloader_entry_guide.sh` | Interactive guide for entering MediaTek Preloader / BootROM mode via hardware key combinations. |
| `01_detect_preloader.sh` | Host USB scan and `mtkclient` environment readiness check. |
| `02_backup_boot.sh` | Read-only partition backup procedure for safeguarding kernel and recovery partitions. |
| `03_sideload_apks.sh` | Script verifying APK sideloading capabilities and manager installation constraints. |
| `04_exec_test.sh` | Host-to-device execution test verifying `adb shell` execution boundaries (`uid=2000`). |
| `05_final_assessment.sh` | End-to-end wrapper running the Python report generators to regenerate assessment markdown files. |
| `gen_report.py` | Generates the core `FINAL_ROOT_ASSESSMENT.md` report. |
| `append_addendum.py` | Appends the CVE-2026-43499 feasibility summary addendum to the final report. |
| `gen_cve_report.py` | Generates the standalone `CVE_2026_43499_FEASIBILITY.md` report. |

---

## Safety & Non-Destructive Policy

All procedures and tests documented in this suite adhere strictly to non-destructive principles:
- **No unauthorized partition writes:** Flash, erase, and direct block-device writes (`dd`) are strictly prohibited.
- **Factory state preservation:** Device remains 100% factory state.
- **No untested exploit execution:** Exploit binaries are not executed on live hardware to avoid kernel panics or bootloops.


## Additional deliverables
- `GHOSTLOCK_OFFSETS.md` — recovered struct/symbol offsets for the GhostLock port.
- `cph1859_symbols.json` — machine-readable KASLR-aware symbol offset table.