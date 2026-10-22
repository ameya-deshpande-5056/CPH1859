# Ranked Shortlist: Android Root Candidates — Realme 1 (CPH1859, ColorOS C.50, Android 9)

**Scope:** Android userspace or kernel root only. Bootloader-state modification is treated as a separate downstream question.

**Ranking criteria:** Evidential strength (confirmed → strongly supported → plausible → unknown), target applicability to CPH1859 C.50, feasibility under read-only constraints, and potential impact (root). Not ranked by how dramatic the exploit would be.

---

## Rank 1 — K-001 / K-002: Kernel Local Privilege Escalation (UNKNOWN / PLAUSIBLE)

**Candidate:** Linux kernel 4.4.146+ MT6771 vendor kernel vulnerability → root

**Component:** Kernel (boot.img), MTK GPU/ION/CMDQ/camera/modem/debug drivers

**Class:** Memory corruption / permission bypass in kernel driver

**Confidence:** UNKNOWN (K-001 evidence gap) / PLAUSIBLE (K-002 attack surface)

| Field | Assessment |
|---|---|
| Applicability | Kernel version overlaps September 2020 Android bulletin candidates (CVE-2019-19769 storage EoP, CVE-2020-0404 USB driver EoP). Live device patch level: 2020-09-05 (inconsistent with C.49 image 2020-05-05 — see inconsistency log). Exact C.50 kernel not available. |
| Initial access | Untrusted Android app via ioctl, sysfs, debugfs, or binder interface exposed by MTK vendor drivers. |
| Security boundary | Kernel/user privilege boundary (CPU EL0 vs EL1). |
| Expected impact | Kernel code execution = full Android root. Persistence depends on surviving reboot (re-exploitation needed unless combined with persistent write primitive). |
| Persistence | Not persistent by itself (memory-only exploit); would need combination with a write primitive to /data or boot partition. |
| Missing evidence | Kernel `.config`, source tree, symbol information, exact backport/mitigation status, function-level comparison against fixing commits. |
| Next experiment | Obtain model-authenticated CPH1859 C.50 boot.img, extract kernel, compare vulnerable functions against fixing commits statically (no live triggering). |


## Rank 2 — U-001: Engineer HIDL Service Privilege Escalation (PLAUSIBLE)

**Candidate:** vendor.oppo.engnative.engineer@1.0-service HIDL interface

**Component:** `vendor/bin/hw/vendor.oppo.engnative.engineer@1.0-service` (C.49 vendor image)

**Class:** Insufficient caller authorization / improper input validation in privileged HIDL service

**Confidence:** PLAUSIBLE (surface confirmed, bypass not proven)

| Field | Assessment |
|---|---|
| Applicability | Service confirmed in C.49 vendor image. Runs as user system, group system, class main (starts at boot). SELinux domain `engineer_hidl` has `oppo_block_device` read/write and can SET `engineer_adb_state_vendor_prop`/`engineer_vendor_prop`. Accessible by `system_server`, `engineermode_app`, `oppo_hal_engineer_client`. No `untrusted_app` allow rule found. |
| Initial access | App that can influence `system_server` or `engineermode_app` to call HIDL methods with attacker-controlled arguments; or direct HIDL caller-check bypass. |
| Security boundary | HIDL caller-identity check; SELinux `hwservice_manager (find)` restriction; `oppo_block_device` MAC label. |
| Expected impact | Write to oppo_block_device partitions (reserve4, potentially others); set ADB engineer properties (`vendor.oppo.engineer.adb.flag/state`) potentially enabling ADB root. Not direct root without secondary privilege escalation. |
| Persistence | Property changes persist until reboot; block device writes are persistent. |
| Missing evidence | Exact C.50 vendor image for comparison; HIDL method-level caller-check analysis; analysis of `vendor.oppo.engnative.engineer@1.0-service` binary for unsafe command execution/path handling/deserialization. |

## Rank 3 — U-002: ATCI/Diagnostic Service Root Access (STRONGLY SUPPORTED surface, PLAUSIBLE exploit)

**Candidate:** atci_service / atcid diagnostic daemon

**Component:** `vendor/bin/atci_service`, `vendor/bin/atcid`

**Class:** Privileged service reachability / activation bypass

**Confidence:** STRONGLY SUPPORTED (surface exists), not a confirmed exploit

| Field | Assessment |
|---|---|
| Applicability | `atci_service` runs as user root but is disabled (conditional on `ro.build.type=eng` or `persist.vendor.service.atci.autostart=1`). `atcid` runs as user system. Live device is user build (disabled). |
| Initial access | Setting `persist.vendor.service.atci.autostart=1` (requires property write access); exploiting a vulnerability in atcid; or engineering build activation. |
| Security boundary | SELinux `hal_atci`/`hal_atci_client`/`hal_atci_server` domains; disabled init entries; user build property `ro.build.type=user`. |
| Expected impact | If `atci_service` (root) could be activated and reached: direct root. `atcid` (system): system-level access. |
| Persistence | Service restart on boot if autostart enabled; property changes persist. |
| Missing evidence | Whether `persist.vendor.service.atci.autostart` is writable from untrusted contexts; atcid/atci_service binary vulnerability analysis. |
| Next experiment | Statically analyze atcid and atci_service binaries for command injection or unsafe parsing; check property_contexts for `persist.vendor.service.atci.autostart` write rules. |

## Rank 4 — U-005: Diagnostic/Factory Binary Pivot (PLAUSIBLE)

**Candidate:** engineer_vendor_shell.sh, factory, OppoKeybox, TBaseDeviceBinding

**Component:** Vendor binaries in `/vendor/bin/`

**Class:** Command injection / unsafe path handling in privileged binary

**Confidence:** PLAUSIBLE

| Field | Assessment |
|---|---|
| Applicability | `engineer_vendor_shell.sh` creates operator lock/simlock config files with `chown radio system`. `factory` (824,544 bytes) and `OppoKeybox` (3,193,584 bytes) are large privileged binaries with unknown attack surface. |
| Initial access | Binder/HIDL service or exported component invoking these binaries with attacker-controlled input. |
| Security boundary | SELinux domains; file permissions; caller checks in invoking service. |
| Expected impact | File creation/chown with elevated privileges as pivot; not direct root. |
| Persistence | File system changes are persistent. |
| Missing evidence | Reachability from untrusted context; binary vulnerability analysis. |
| Next experiment | Extract exact C.50 vendor image, statically analyze factory/OppoKeybox binaries, enumerate invoking services. |


## Not Ranked as Android-Root Candidates (Bootloader-State Only)

- **B-001 (LK OEM token gate):** Bootloader-state control, not Android root. Blocks Fastboot without OEM token.
- **B-002 (MediaTek signed container):** Boot-chain integrity, not root.
- **K-003 (BootROM Kamakiri/CVE-2020-0069):** Bootloader-state lead, requires hardware testpoint for BootROM entry (out of software-only scope).
- **R-001 (Stock recovery):** No direct unlock/root path found.
- **D-001 (DeepTesting):** Backend decommissioned, APK model guard excludes CPH1859.
- **U-003:** Confirmed negative control — blocks direct partition access from ADB shell.
- **U-004:** DeepTesting not installed; no current token issuance.

---

## Summary Ranking by Evidential Strength and Feasibility

| Rank | ID | Candidate | Confidence | Root Impact | Primary Blocker |
|---|---|---|---|---|---|
| 1 | K-001/K-002 | Kernel LPE (4.4.146+ MT6771) | UNKNOWN/PLAUSIBLE | Direct root | Missing kernel config/source; exact C.50 boot.img unavailable |
| 2 | U-001 | Engineer HIDL service | PLAUSIBLE | Indirect (block device/ADB props) | No `untrusted_app` → `engineer_hidl` path proven; HIDL method analysis pending |
| 3 | U-002 | ATCI diagnostic service | STRONGLY SUPPORTED surface | Direct root if `atci_service` reachable | Disabled in user build; activation requires property write |
| 4 | U-005 | Diagnostic/factory binary | PLAUSIBLE | Indirect pivot | Reachability from untrusted context unproven |

**Overall conclusion:** No Android root path is confirmed. The most promising lead requiring investigation is **K-001/K-002** (kernel LPE), followed by **U-001** (Engineer HIDL service) as a userspace pivot surface.
| Next experiment | Extract exact C.50 vendor image, statically enumerate all IEngineer HIDL methods and caller-check branches, disassemble the native daemon binary. |
