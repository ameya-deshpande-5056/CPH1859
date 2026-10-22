# Phase 10: Root Surface Audit — Realme 1 CPH1859

## Scope

This phase reassesses the three priority areas requested for the live CPH1859 / Android 9 / MT6771 device:

1. The security meaning of `CONFIG_OPPO_ROOT_CHECK=y` in the live kernel configuration;
2. Method-level authorization and reachability of Engineer HIDL / Oppo engineering interfaces;
3. Whether historical Android kernel CVEs actually apply to the device kernel, drivers, and backports.

The working premise remains strict read-only investigation. No live exploit, flashing, partition writes, or modification of the device was performed.

## Evidence boundary

The strongest live evidence in this workspace is:

- The live-device ADB audit recorded in the project logs and reports;
- The C.49 vendor-image audit for Engineer HIDL / ATCI / vendor policy;
- The C.49 vs C.50 Little Kernel differential analysis; and
- The live-device kernel config references recorded in the project logs.

There is no exact CPH1859 C.50 kernel source tree or symbolized vendor tree in the workspace, and no exact CPH1859 C.50 `vmlinux` or kernel module symbol archive was recovered. That fact materially limits any claim about the implementation of vendor-specific config options.

---

## 1) `CONFIG_OPPO_ROOT_CHECK`

### What the live evidence says

The project log records that the live CPH1859 kernel config contains:

- `CONFIG_OPPO_ROOT_CHECK=y`
- `CONFIG_OPPO_KEVENT_UPLOAD=y`
- `CONFIG_OPPO_EXECVE_BLOCK=y`
- `CONFIG_OPPO_EXECVE_REPORT=y`

These are vendor-specific config names, not upstream Linux options. The log also records that the kernel is a vendor `4.4.146+` MT6771 build and that the exact kernel source tree and module symbols are not available in the workspace.

### Most likely meaning

The most likely interpretation is that `CONFIG_OPPO_ROOT_CHECK` is part of a vendor anti-root / root-usage detection and reporting subsystem, not a direct exploit primitive. This is a reasonable inference from the naming pattern and from the co-presence of other Oppo-specific root-reporting toggles (`OPPO_EXECVE_BLOCK`, `OPPO_EXECVE_REPORT`, `OPPO_KEVENT_UPLOAD`).

It is not a credible conclusion that the symbol itself is a UID 0 escalation or a direct user-to-kernel bypass mechanism. The project has no recovered source, no symbol table, and no disassembly showing a privileged operation exposed to unprivileged callers.

### Evidence supporting that interpretation

1. The config name is vendor-specific and not an upstream Linux root check.
2. It appears alongside other Oppo-specific security/telemetry options in the same kernel config snapshot.
3. The project’s previous research identified a broad vendor diagnostic and system-security surface in the image, but no untrusted app route to the relevant kernel code.
4. No actual source file, Kconfig entry, or symbol definition for `OPPO_ROOT_CHECK` exists in the workspace for this device.

### What it does not establish

- It does not establish a root-detection bypass.
- It does not establish a user-controlled root escalation path.
- It does not establish that the feature is a kernel vulnerability.
- It does not prove the symbol is even reachable from Android userspace.

### Conclusion for `CONFIG_OPPO_ROOT_CHECK`

`CONFIG_OPPO_ROOT_CHECK=y` is best treated as a configuration lead for a vendor root-detection / anti-root mitigation feature, not as evidence of an exploitable path to UID 0. The available evidence supports the interpretation that it is a security policy option, not a direct privilege-escalation primitive.

### Missing artifact needed to resolve uncertainty

The single most important missing artifact is the exact CPH1859 C.50 kernel source, symbolized `vmlinux`, or module `Module.symvers` from the installed build, plus the vendor Kconfig fragments or `scripts/config` metadata that define the option. Without these, the implementation cannot be recovered with confidence.

---

## 2) Engineer HIDL / Oppo engineering interfaces

### Inventory and implementation evidence

The C.49 vendor image analysis found the following relevant service and policy objects:

- `vendor/oppo/engnative/engineer@1.0-service`
- `vendor.oppo.engnative.engineer@1.0::IEngineer/default`
- `android.engineer.OppoEngineerManager` reflection references in the decompiled DeepTesting APK
- `engineer_hidl` SELinux domain
- `oppo_block_device` class
- `engineermode_app`, `system_server`, and `oppo_hal_engineer_client` as authorized callers in the SELinux service context files

The DeepTesting APK decompilation showed the historical call chain:

- `Class.forName("android.engineer.OppoEngineerManager")`
- `getMethod("fastbootUnlock", byte[].class, Integer.TYPE)`
- IPC to `vendor.oppo.engnative.engineer@1.0::IEngineer.saveEngineerData()`

The native service was then historically used to write the unlock token to the `reserve4` block device at sector `0x7816`, offset `0x00F02C00`, matching the LK token slot.

### Method-level authorization audit

| Field | Required information |
|---|---|
| Interface / method | `android.engineer.OppoEngineerManager.fastbootUnlock(byte[], int)`; `vendor.oppo.engnative.engineer@1.0::IEngineer.saveEngineerData()` (method name recovered from decompiled APK and service path; exact method list not fully recovered from stripped vendor binary) |
| Implementation evidence | Decompiled DeepTesting APK; vendor service registration; earlier LK token-slot matching to `reserve4` writes; service SELinux policy |
| Caller restrictions | SELinux `hwservice_manager find` access limited to `system_server`, `engineermode_app`, and `oppo_hal_engineer_client`; no `untrusted_app` allow rule was found |
| Privileged operation | Historical value-writing to `reserve4` / bootloader token area; property writes to engineering ADB properties |
| Untrusted reachability | Proven to be absent in the examined policy and service path; no direct `untrusted_app` → `engineer_hidl` path established |
| Root relevance | Indirect lead; potentially useful pivot if HIDL caller checks or privileged client compromise exists, but not direct root by itself |
| Confidence | Medium |

### Notably relevant ATCI surface

The C.49 vendor init scripts define:

- `service atci_service /vendor/bin/atci_service`
  - runs as `user root`
  - disabled by default
  - starts only on `ro.build.type=eng` or `persist.vendor.service.atci.autostart=1`
- `service atcid-daemon-u /vendor/bin/atcid`
  - runs as `user system`
  - disabled by default
  - starts on the same property condition

This is a real privileged surface, but it is still gated by build type and property activation. The live device is observed as a user build (`ro.build.type=user`), so the service is not active in the live posture.

### Method-level table summary

| Interface / method | Implementation evidence | Caller restrictions | Privileged operation | Untrusted reachability | Root relevance | Confidence |
|---|---|---|---|---|---|---|
| `android.engineer.OppoEngineerManager.fastbootUnlock` | Decompiled DeepTesting APK + service registration | `system_server` / `engineermode_app` / `oppo_hal_engineer_client`; no `untrusted_app` rule | Writes unlock token to `reserve4` | Disproven within examined paths for direct untrusted app use | Indirect lead | Medium |
| `vendor.oppo.engnative.engineer@1.0::IEngineer.saveEngineerData` | Historical APK call target + service path | Same as above | Writes engineer data to block device | Same as above | Indirect lead | Medium |
| `atci_service` | C.49 vendor init + service config | `root`, but disabled; requires `eng` or property | Root-level diagnostic service if enabled | Not active in live user build; property gate remains | Potential root if activation path exists | Medium |
| `atcid` | C.49 vendor init + service config | `system`, disabled by default | System-level diagnostic control | Not active in live user build | Indirect lead only | Medium |

### Conclusion for HIDL / ATCI

The service surfaces are real, privileged, and relevant, but the examined evidence does not establish an untrusted-app path to those methods or a direct bypass of the caller restrictions. The path is therefore not a confirmed Android-root vector from the current Android userspace. It remains a plausible pivot surface only if a separate service, system app, or binder mismatch can be exploited.

---

## 3) Historical kernel CVE applicability

### Candidate mapping and validation

The earlier phase notes raised `CVE-2020-0404` and `CVE-2020-0407` as possible leads. These must be treated as candidates only, not assumptions.

#### `CVE-2020-0404`

- Official issue type: upstream Linux kernel local privilege escalation in a USB driver path.
- Affected component: USB subsystem / kernel driver path, not a generic “MediaTek vendor feature”.
- Device applicability: the live configuration includes `CONFIG_USB_MU3D_DRV=y`, which makes the USB driver present in the kernel config, but the actual vulnerable code path and whether the exact vendor backport is present cannot be proven without kernel source or symbolized binary.
- Assessment: relevant as a possible candidate, but unproven on this device.

#### `CVE-2020-0407`

- Official issue type: upstream kernel issue in F2FS.
- Affected component: F2FS, not ext4.
- Device applicability: the observed C.49 default filesystem uses ext4, which is not the affected path. Exact C.50 partition layout and default fs remain unknown. This makes the candidate not credible for the observed C.49 default device posture.
- Assessment: not a valid current lead for the installed default path without a different filesystem configuration being established.

### Why the mapping must not be overstate

The live device kernel version is `4.4.146+`, and the vendor tree is MT6771. That overlaps with the Android September 2020 security bulletin range, but version overlap alone is not proof of vulnerability. Missing vendor-specific backports, patches, and driver provenance matter. The project also lacks the exact CPH1859 C.50 kernel source and the exact modules / symbol tables for the installed build, so any statement about patch status remains an uncertainty, not a fact.

### Additional candidate review

The project already concluded that the kernel-level candidate set remains high-value but unresolved. There is no evidence in the available artifacts that the issue is reachable from an unprivileged Android app under the live configuration. The presence of a driver in the config is not the same as a reachable or exploitable bug.

### Conclusion for CVE applicability

The historical CVEs are not enough to establish a kernel-root path on the installed CPH1859. `CVE-2020-0404` remains a plausible vendor-kernel candidate because the USB driver exists in the config, but it is unresolved and not proven. `CVE-2020-0407` is not supported for the observed ext4 default configuration and should not be treated as a live lead for the device as currently evidenced.

---

## 4) Final conclusion

### Established

- `CONFIG_OPPO_ROOT_CHECK` is not recoverable from the workspace as a source-backed implementation, but it is best interpreted as a vendor root-detection / anti-root configuration feature rather than a direct UID 0 primitive.
- The Engineer HIDL service is a real privileged surface, but the examined evidence does not show an untrusted app path to it.
- ATCI services are real and privileged, but the live user build is not enabling them.
- Historical kernel CVEs remain unresolved leads; the evidence does not establish that any of them applies to the live device.

### Ruled out

- No direct untrusted-app path to `engineer_hidl` was established.
- No live kernel exploit path was established.
- No confirmed Android-root path was identified from the available evidence.

### Strongest remaining root candidates

1. Kernel-level local privilege escalation in a vendor MT6771 driver path;
2. Engineer HIDL caller-auth bypass or privileged client compromise;
3. ATCI service activation if an activation or property-write path is available.

### Evidence-backed conclusion

No confirmed Android-root path identified from the available evidence.

### Highest-value next artifact

The single highest-value missing artifact is the exact CPH1859 C.50 kernel image plus the exact vendor kernel source or symbolized `vmlinux`/`Module.symvers` from the installed build, coupled with the exact user-space HIDL service binary and SELinux policy from the same build. Without that, the remaining candidate paths remain hypotheses rather than substantiated vulnerabilities.
