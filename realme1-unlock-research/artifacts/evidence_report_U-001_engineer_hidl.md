# Evidence Report: U-001 — Engineer HIDL Service Privilege Escalation

**Candidate ID:** U-001
**Rank:** 2
**Confidence:** PLAUSIBLE

**Component:** `vendor.oppo.engnative.engineer@1.0-service` HIDL interface
**Binary:** `vendor/bin/hw/vendor.oppo.engnative.engineer@1.0-service` (C.49 vendor image)
**Class:** Insufficient caller authorization / improper input validation in privileged HIDL service
**Expected impact:** Write to oppo_block_device partitions; set ADB engineer properties → potential ADB root pivot

## 2. Evidence Tied to CPH1859 C.50 (from C.49 vendor reference)

### 2.1 Service Configuration (Directly Observed)

File: `vendor/etc/init/vendor.oppo.engnative.engineer@1.0-service.rc`

```
service oppo.engineer-1-0 /vendor/bin/hw/vendor.oppo.engnative.engineer@1.0-service
    class main
    user system
    group system
    interface vendor.oppo.engnative.engineer@1.0::IEngineer default
```

- Runs as `user system`, `group system`
- Class: `main` (starts at boot)
- Registers HIDL interface: `vendor.oppo.engnative.engineer@1.0::IEngineer/default`
- Binary size: 691,680 bytes

### 2.2 SELinux Policy (Directly Observed from vendor_sepolicy.cil)

**Block device access:**
- Lines 11281-11287: `engineer_hidl` allowed read/write on `oppo_block_device` (dir/file/lnk_file/blk_file)

**Property access:**
- Lines 11327-11328: `engineer_hidl` can SET `engineer_vendor_prop`
- Lines 11357-11358: `engineer_hidl` can SET `engineer_adb_state_vendor_prop`

**HIDL service access (authorized callers via hwservice_manager find):**
- Line 11430: `engineermode_app_28_0` → `oppo_hal_engineer_hwservice`
- Line 11597: `oppo_hal_engineer_client` → `oppo_hal_engineer_hwservice`
- Line 11630: `system_server_28_0` → `oppo_hal_engineer_hwservice`

**No `untrusted_app` allow rule found** for `oppo_hal_engineer_hwservice`.

### 2.3 Live Device Posture (Directly Observed)

- `ro.build.type`: `user`
- SELinux: `Enforcing`
- `ro.boot.flash.locked`: `1`


## 3. Attack Path Analysis

### Path A: Untrusted App → System Server → Engineer HIDL
An untrusted app would need to compromise or influence `system_server` (which has `hwservice_manager find` access) to call `IEngineer` methods with attacker-controlled arguments. No direct `untrusted_app` → `engineer_hidl` SELinux path exists.

### Path B: EngineerMode App → Engineer HIDL
`engineermode_app_28_0` has `hwservice_manager find` access. If an untrusted app can influence the EngineerMode app, it could potentially reach the HIDL service.

### Path C: Direct HIDL Caller-Check Bypass
If `IEngineer` HIDL methods lack proper caller identity checks, a caller that can reach the service might bypass authorization. Requires static analysis of HIDL method implementations.

## 4. Why This Is NOT a Confirmed Vulnerability

- No direct `untrusted_app` → `engineer_hidl` SELinux path proven
- HIDL method implementations not statically analyzed — caller-check branches unknown
- `vendor.oppo.engnative.engineer@1.0-service` binary not disassembled
- Exact C.50 vendor image unavailable — C.49 findings may not apply to installed C.50
- Service runs as `system`, not `root` — requires secondary privilege escalation for full root

## 5. Safe Read-Only Next Steps

1. Extract exact C.50 vendor image (obtain model-authenticated CPH1859 C.50 OTA)
2. Statically enumerate all IEngineer HIDL methods from the service binary
3. Analyze caller-check branches in each HIDL method implementation
4. Disassemble `vendor.oppo.engnative.engineer@1.0-service` for unsafe command execution/path handling
5. Compare C.49 vs C.50 for differences in caller authorization logic
6. No live invocation of the service on the phone

## 6. Source Locations

- Init script: `vendor/etc/init/vendor.oppo.engnative.engineer@1.0-service.rc` (C.49 vendor image)
- Service binary: `vendor/bin/hw/vendor.oppo.engnative.engineer@1.0-service` (C.49 vendor image)
- SELinux policy: `vendor/etc/selinux/vendor_sepolicy.cil` (C.49 vendor image)
- HWS service contexts: `vendor/etc/selinux/vendor_hwservice_contexts` (C.49 vendor image)
- Vendor image SHA-256: `cd5123491d641226583fb017ccc993a9be1c11e44cd49823bce6e3308c169bc5`
- Userspace audit: `artifacts/android_userspace_audit.md`
- Vulnerability matrix entry: U-001 in `vulnerability_matrix.json`

## 7. Conclusion for U-001

The Oppo Engineer HIDL service runs as `system`, has `oppo_block_device` read/write (including `reserve4`), and can set ADB-engineer properties. Reachable by `system_server` and `engineermode_app`. No direct `untrusted_app` → `engineer_hidl` path proven. Plausible pivot surface requiring HIDL method analysis. Not direct root without secondary escalation.
**Persistence:** Property changes persist until reboot; block device writes are persistent
