# Evidence Report: U-002 — ATCI/Diagnostic Service Root Access

**Candidate ID:** U-002
**Rank:** 3
**Confidence:** STRONGLY SUPPORTED (surface), not a confirmed exploit

**Component:** `vendor/bin/atci_service`, `vendor/bin/atcid`
**Class:** Privileged service reachability / activation bypass
**Expected impact:** Direct root if `atci_service` (root) reachable; system-level access via `atcid`
**Persistence:** Service restart on boot if autostart enabled; property changes persist

## 1. Evidence (Directly Observed from C.49 vendor image)

### atci_service — `vendor/etc/init/atci_service.rc`
```
service atci_service /vendor/bin/atci_service
    class core
    socket atci-service stream 660 radio system
    user root
    disabled
    group radio system

on property:ro.build.type=eng
start atci_service

on property:persist.vendor.service.atci.autostart=1
start atci_service
```
- Runs as `user root`
- **Disabled** by default
- Starts only if `ro.build.type=eng` OR `persist.vendor.service.atci.autostart=1`

### atcid — `vendor/etc/init/atcid.rc`
```
service atcid-daemon-u /vendor/bin/atcid
    interface vendor.mediatek.hardware.atci@1.0::IAtcid default
    class hal
    class main
    socket adb_atci_socket stream 660 radio system
    user system wifi
    group radio system media bluetooth wifi
    disabled
    oneshot

on property:persist.vendor.service.atci.autostart=1
start atcid-daemon-u
```
- Runs as `user system`
- Disabled, oneshot
- Starts on `persist.vendor.service.atci.autostart=1`

### audiocmdservice_atci — `vendor/etc/init/audiocmdservice_atci.rc`
```
service audio-daemon /vendor/bin/audiocmdservice_atci
    class main
    socket atci-audio stream 666 system system
    user system
    group system audio
    disabled
    oneshot
```
- Runs as `user system`
- Disabled, oneshot

### SELinux (vendor_sepolicy.cil)
- Line 7671: `(allow hal_atci_server hal_atci_hwservice (hwservice_manager (add find)))`
- Line 7673: `(neverallow base_typeattr_303_28_0 hal_atci_hwservice (hwservice_manager (add)))`
- Lines 8085-8090: `hal_atci_client` ↔ `hal_atci_server` binder/fd access
- `hal_atci_client` includes: `radio_28_0`, `system_app_28_0`, `atci_service_sys_28_0`, `atci_service`
- **No `untrusted_app` in `hal_atci_client`**

### Live Device Posture
- `ro.build.type`: `user` (not eng) — atci_service disabled

## 2. Attack Path Analysis

### Path A: Enable atci_service via property
Set `persist.vendor.service.atci.autostart=1` → triggers atci_service (root) to start. Requires property write access to `persist.vendor.service.atci_prop`. No `untrusted_app` write rule found for this property.

### Path B: Exploit atcid vulnerability
If `atcid` (system) has a vulnerability (command injection, unsafe parsing), an attacker reaching it via `adb_atci_socket` could gain system-level access. `atcid` is disabled by default in user builds.

### Path C: ATCI socket access
`atci_service` creates socket `atci-service` with mode 660, group `radio system`. Untrusted apps are not in `radio` or `system` groups.

## 3. Why This Is NOT a Confirmed Vulnerability

- `atci_service` disabled in user build (requires `ro.build.type=eng` or property set)
- No `untrusted_app` → `hal_atci_hwservice` SELinux path
- `atcid` and `audiocmdservice_atci` are disabled by default
- No binary vulnerability analysis performed on atcid/atci_service
- Exact C.50 vendor image unavailable

## 4. Safe Read-Only Next Steps

1. Check property_contexts for `persist.vendor.service.atci.autostart` write rules
2. Statically analyze atcid and atci_service binaries for command injection/unsafe parsing
3. Extract exact C.50 vendor image, compare ATCI service configuration
4. No live testing on device

## 5. Source Locations

- `vendor/etc/init/atci_service.rc` (C.49 vendor image)
- `vendor/etc/init/atcid.rc` (C.49 vendor image)
- `vendor/etc/init/audiocmdservice_atci.rc` (C.49 vendor image)
- `vendor/etc/selinux/vendor_sepolicy.cil` (C.49 vendor image)
- Vendor image SHA-256: `cd5123491d641226583fb017ccc993a9be1c11e44cd49823bce6e3308c169bc5`