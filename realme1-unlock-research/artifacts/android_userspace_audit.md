# Android Userspace Security Audit

## Scope and confidence boundary

The directly inspectable Android userspace is the C.49 CPH1859 reference filesystem in `C49_extracted/system.img` and `vendor.img`:

- system image SHA-256: `3c28df6690940df4a60431a6a3bcb756e3c4936acda9678f99406584e48b5f03`
- vendor image SHA-256: `cd5123491d641226583fb017ccc993a9be1c11e44cd49823bce6e3308c169bc5`
- system properties identify Android 9/API 28, security patch `2020-05-05`, board `oppo6771_17065`.

The C.50 package contains compressed `system.new.dat.br` and `vendor.new.dat.br` payloads, but its OTA metadata and updater script explicitly identify and enforce `CPH1861`. It is therefore not treated as the installed CPH1859 C.50 userspace. No exact-device CPH1859 C.50 filesystem was available.

## Observed inventory

The C.49 system image contains 70+ `system/priv-app` directories, including `EngineerMode`, `OppoBootReg`, `Settings`, `SystemUI`, `TeeService`, and Google/telephony providers. The vendor image contains MediaTek HIDL services, Trustonic TEE/keymaster services, Oppo Engineer/Messager/EngSensor services, ATCI/meta/factory tools, modem/RIL components, and diagnostic collectors.

Relevant init and policy evidence:

- `vendor/etc/init/vendor.oppo.engnative.engineer@1.0-service.rc` starts `vendor.oppo.engnative.engineer@1.0-service` as `user system`, `group system`, and registers `vendor.oppo.engnative.engineer@1.0::IEngineer/default`.
- `vendor/etc/init/atci_service.rc` defines a root `atci_service`, but it is disabled and only starts for `ro.build.type=eng` or an engineering property.
- `system/init.oppo.debug.rc` defines several root diagnostic services, but they are disabled/oneshot and have dedicated SELinux domains.
- The C.49 `vendor_sepolicy.cil` labels the Engineer HIDL service as `oppo_hal_engineer_hwservice` and permits `system_server_28_0` and `engineermode_app_28_0` to find/call it. The untrusted-app domain is not shown as a client.
- The `engineer_hidl` domain has read/write access to the generic `oppo_block_device` class and several persistent/engineering files. This is powerful by design; the static evidence does not show a path from an untrusted app to that domain.
- The vendor fstab mounts system, vendor, ODM, userdata, persist, protect, nvdata, and nvcfg as ext4. The bootloader-critical nodes (`lk`, `lk2`, `seccfg`, `preloader`) are exposed as emmc/block-device paths but are not ordinary untrusted-app interfaces.

## Findings

### U-001 — Privileged Engineer HIDL raw-storage surface

**Classification:** attack surface; `PLAUSIBLE` as a review lead, not a confirmed vulnerability.

**Evidence:** C.49 vendor image above; service path and `vendor_sepolicy.cil` rules for `engineer_hidl`, `oppo_block_device`, `system_server`, and `engineermode_app`. Prior decompilation also shows the Engineer service/HAL is the historical recipient of the OEM unlock token and writes `reserve4`.

**Security impact:** If an untrusted or ordinary platform application could reach a method lacking caller authorization, the service might become a storage-integrity or bootloader-state pivot. The observed policy instead limits the HIDL service to privileged callers, and the analyzed path writes only the authorized token coordinate, not `lk` or `seccfg`.

**Mitigation / non-applicability evidence:** Dedicated HIDL service label, system/EngineerMode client domains, SELinux enforcing on the live device, and raw block nodes inaccessible to shell. No unauthenticated Binder/HIDL method or type-confusion/overflow was proven.

**Next step:** Obtain the exact CPH1859 C.50 Engineer service and framework binaries, enumerate every HIDL method and caller-check branch statically, and compare C.49/C.50. Do not invoke the service on the phone.

### U-002 — Engineering and diagnostic commands

**Classification:** privileged diagnostic surface; `STRONGLY SUPPORTED`, not a root exploit.

**Evidence:** `atci_service`, `atcid`, `meta_tst`, `factory`, `engineer_vendor_shell.sh`, logging/trace services, debugfs/proc/sysfs labels, and root diagnostic init entries are present in the C.49 image. Several are disabled or require engineering build/property conditions.

**Security impact:** A separate authorization defect could expose modem, debug, or storage operations. Static presence alone does not establish reachability from an unprivileged Android process.

**Mitigation / non-applicability evidence:** User build properties, disabled init entries, dedicated SELinux domains, and no observed untrusted-app allow rule to the Engineer HIDL service.

**Next step:** Statically extract the exact CPH1859 C.50 manifests, service contexts, and method implementations; compare exported Binder/HIDL names against `untrusted_app` and `platform_app` policy.

### U-003 — Raw partition access from ordinary Android shell

**Classification:** negative control; `STRONGLY SUPPORTED` for the observed C.49 policy/live posture.

**Evidence:** Live diagnostic records show ADB UID `shell`, SELinux `Enforcing`, bootloader-critical nodes owned by `root:root` with restrictive modes, and read attempts against `lk` returned `Permission denied`. C.49 policy labels `lk`, `seccfg`, `preloader`, `frp`, and reserve classes separately.

**Security impact:** No direct ADB path to write the unlock token, LK, or `seccfg` was demonstrated.

**Limitation:** This is not proof that every C.50 CPH1859 service/policy branch is identical because the exact C.50 userspace is missing.

### U-004 — DeepTesting authorization client

**Classification:** supported authorization mechanism, not a vulnerability; `CONFIRMED` historically for the analyzed client/HAL pipeline.

**Evidence:** Decompiled client, framework IPC, vendor Engineer HAL, and LK analysis show a server-issued token is transferred to `reserve4` sector `0x7816` (`0x00F02C00`). The LK independently checks the eFUSE-derived serial and OEM RSA-PSS signature.

**Security impact:** Possession of the client or network response is insufficient without a valid OEM signature. The historical server route is reported decommissioned; no signing-key recovery or local token forgery was found.

**Next step:** Preserve the decompiled APK/HAL evidence and, if acquired, analyze the original APK/network certificate pinning offline. Do not mock the service or write a token.

## Userspace conclusion

The available evidence supports a hardened privileged-service architecture with several diagnostic interfaces and a powerful Engineer HAL, but it does not confirm an Android local privilege escalation, an untrusted-app Binder/HIDL bypass, or a persistent-root path. Exact CPH1859 C.50 system/vendor images are the highest-value missing userspace evidence.
