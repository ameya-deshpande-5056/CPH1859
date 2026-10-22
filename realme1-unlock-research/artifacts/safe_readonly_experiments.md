# Safe, Read-Only Experiments to Discriminate Between Competing Root Hypotheses

**All experiments are non-invasive and read-only.** No flashing, partition writes, exploit payloads, or bootloader-state changes.

---

## Experiment E-001: Acquire and Analyze Exact CPH1859 C.50 boot.img

**Objective:** Resolve the K-001/K-002 kernel LPE evidence gap.

**Procedure (offline/static only):**
1. Obtain model-authenticated CPH1859 C.50 OTA package (`.ozip` or `.ofp`)
2. Decrypt using `oppo_ozip_decrypt` (available in workspace)
3. Extract `boot.img` from OTA payload
4. Decompress gzip kernel; extract version strings, build date, config
5. Compare kernel functions against Android Sept 2020 bulletin fixing commits (CVE-2019-19769, CVE-2020-0404)
6. Check vendor backports and mitigation status

**Discriminates:** Whether kernel CVE candidates apply to exact installed CPH1859 C.50 kernel
**Risk:** None — offline static analysis
**Required:** Model-authenticated CPH1859 C.50 OTA package

## Experiment E-002: Enumerate Exported Binder/HIDL Services on Live Device

**Objective:** Determine which privileged services are reachable from untrusted_app.

**Procedure (read-only ADB commands):**
1. `adb shell service list` — enumerate all registered system services
2. `adb shell dumpsys` — inspect service state and permissions
3. `adb shell pm list packages -s` — list system/privileged packages
4. `adb shell dumpsys activity services` — inspect running services
5. `adb shell getprop` — verify SELinux mode, build type, security patch
6. `adb shell ls -la /dev/block/by-name/` — confirm partition node permissions

**Discriminates:** Whether any privileged service is exposed to untrusted apps
**Risk:** None — read-only enumeration
**Required:** Live device connected via ADB

## Experiment E-003: Static Analysis of C.49 Engineer HIDL Service Binary

**Objective:** Analyze `vendor.oppo.engnative.engineer@1.0-service` for caller-check vulnerabilities.

**Procedure (offline/static only):**
1. Extract binary from C.49 vendor image
2. Use `readelf`, `objdump`, `strings` to inspect symbols and imported functions
3. Look for `system()`, `exec()`, `popen()`, `sprintf()`, `strcpy()` patterns
4. Look for HIDL method dispatch and caller identity checks (`getCallingUid()`, `getCallingPid()`)
5. Document all HIDL method names and implementations

**Discriminates:** Whether Engineer HIDL service has unsafe method implementations
**Risk:** None — offline binary analysis

## Experiment E-004: Static Analysis of C.49 atcid and atci_service Binaries

**Objective:** Analyze ATCI diagnostic daemons for command injection or unsafe parsing.

**Procedure (offline/static only):**
1. Extract binaries: `vendor/bin/atcid`, `vendor/bin/atci_service`
2. Inspect symbols and string references
3. Look for socket command handling, buffer operations, format string vulnerabilities
4. Document all command handlers and input validation

**Discriminates:** Whether ATCI daemons have exploitable input handling
**Risk:** None — offline binary analysis
**Required:** C.49 vendor image (already available)

## Experiment E-005: Kernel Driver Function-Level Comparison

**Objective:** Compare MTK driver functions against known vulnerability fixing commits.

**Procedure (offline/static only):**
1. Extract kernel from C.49 boot.img (decompressed to `/tmp/C49_kernel.bin`)
2. Identify MTK driver functions (CMDQ, ION, GPU, camera, USB)
3. Compare against Android kernel fixing commits
4. Check for missing backports or incomplete fixes

**Discriminates:** Whether specific kernel drivers contain unpatched vulnerabilities
**Risk:** None — offline static analysis
**Required:** C.49 boot.img (already available)

## Experiment E-006: Verify SELinux Enforcing Mode and Property Write Restrictions

**Objective:** Confirm whether untrusted_app can write to engineer/ATCI properties.

**Procedure (read-only ADB commands):**
1. `adb shell getenforce` — confirm SELinux mode
2. `adb shell getprop ro.build.type` — confirm user build
3. `adb shell dumpsys policy` — inspect SELinux policy
4. `adb shell ls -la /vendor/etc/selinux/` — confirm policy files present

**Discriminates:** Whether property-based activation of diagnostic services is feasible
**Risk:** None — read-only queries only
**Required:** Live device connected via ADB

## Experiment E-007: Extract and Compare C.49 vs C.50 Vendor Image (if C.50 obtained)

**Objective:** Determine whether C.50 changes security-relevant userspace components.

**Procedure (offline/static only):**
1. Decrypt CPH1859 C.50 OTA and extract vendor image
2. Compare vendor_sepolicy.cil between C.49 and C.50
3. Compare init scripts and service configurations
4. Compare privileged binary versions/hashes

**Discriminates:** Whether C.50 introduces or removes userspace attack surfaces
**Risk:** None — offline comparison only
**Required:** Model-authenticated CPH1859 C.50 OTA package

---

## Experiment Priority Ranking

| Priority | Experiment | Target Candidate | Value |
|---|---|---|---|
| 1 | E-001 | K-001/K-002 | Resolves highest-impact kernel LPE evidence gap |
| 2 | E-002 | U-001/U-002 | Determines live service reachability from untrusted apps |
| 3 | E-003 | U-001 | Analyzes Engineer HIDL service for caller-check bypass |
| 4 | E-004 | U-002 | Analyzes ATCI daemons for command injection |
| 5 | E-005 | K-001/K-002 | Kernel driver function-level CVE comparison |
| 6 | E-006 | U-001/U-002 | Verifies SELinux and property write restrictions |
| 7 | E-007 | All userspace | C.49 vs C.50 vendor comparison (requires C.50 OTA) |

**Required:** C.49 vendor image (already available)
