# Phase 12 Kernel Provenance and LPE Evidence-Gap Closure

## Executive conclusion

No exact CPH1859 C.50 kernel image or matching vendor source tree was recovered in the workspace or in the available local caches. The strongest current conclusion is therefore:

- No confirmed Android-root path identified from the available evidence.
- No exact CPH1859 kernel-source match was established.
- The kernel LPE evidence gap remains open because the exact installed boot image, vendor kernel patch state, and source provenance are still missing.

This is not a claim that kernel root is impossible on this device. It is a claim that the available evidence does not support a device-specific exploit conclusion, and the exact installed kernel provenance is still the decisive missing fact.

## 1) Evidence reviewed from Phase 11

The unresolved Phase 11 conclusions that depend on missing provenance were:

- `CONFIG_OPPO_ROOT_CHECK` remains a symbol-only lead; no implementation or source-backed behavior was recovered.
- `CVE-2020-0404` remains an unresolved kernel candidate because the vendor USB driver and exact backport state are not proven for the installed image.
- `CVE-2020-0407` is not supported for the observed default filesystem posture, but exact C.50 fs layout remains unverified.
- The high-confidence negative conclusion is valid only within the exact evidence boundary: no confirmed unprivileged path to UID 0 was established.

These unresolved claims all require the exact installed kernel or vendor source tree. The available workspace contains only the following kernel-related artifacts:

1. C.49 extracted `boot.img` for the device-family CPH1859 extraction.
2. C.49 extracted `lk.img` and `preloader_oppo6771_17065.bin` from the same source set.
3. C.50 reference `boot.img` and `lk.img` from the CPH1861 OTA package `CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t`.
4. Live-device config evidence extracted from the running CPH1859 via `/proc/config.gz`.

No exact installed CPH1859 C.50 `boot.img`, `vendor_boot.img`, kernel source archive, or symbolized kernel binary was found.

## 2) Artifacts actually present in the workspace

### 2.1 C.49 extracted device-family artifacts

| Artifact | Path | Size | SHA-256 | Provenance |
| --- | --- | ---: | --- | --- |
| C.49 boot image | `/home/ameya/Realme1/C49_extracted/boot.img` | 9,780,048 bytes | `1a82355e63ca593f28224d4180e070acec562b6d45b76f565c84399a56e1b208` | Directly extracted C.49 artifact from the known CPH1859 extraction set |
| C.49 LK image | `/home/ameya/Realme1/C49_extracted/lk.img` | 753,984 bytes | `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa` | Directly extracted C.49 LK |
| C.49 recovery image | `/home/ameya/Realme1/C49_extracted/recovery.img` | 30,483,280 bytes | `05cfcf8ffbb59abcbd642a950989cc4d112d1985ad1a4c9eab642ce4e67bdb34` | Directly extracted recovery image |
| C.49 preloader | `/home/ameya/Realme1/C49_extracted/preloader_oppo6771_17065.bin` | 265,756 bytes | `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a` | Direct preloader binary from same extraction set |
| Project config metadata | `/home/ameya/Realme1/C49_extracted/Projectconfig.xml` | 778 bytes | `7ae7f1d5ddc3d0b4d381d5f0cba6496d7a0ecde36f6a3a1b3b11e3d0f7dc52a` | Model family metadata only |

### 2.2 C.50 OTA reference artifacts (not exact CPH1859)

| Artifact | Path | Size | SHA-256 | Provenance |
| --- | --- | ---: | --- | --- |
| C.50 boot image | `/home/ameya/Realme1/C50_research/CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t/boot.img` | 9,786,192 bytes | `44d9b48d5c49cde8b9df5eb9d67b8feefe4adf381bfb56cc9455e4bae23f98c5` | CPH1861 OTA reference; not proof of CPH1859 installation |
| C.50 LK image | `/home/ameya/Realme1/C50_research/CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t/lk.img` | 753,984 bytes | `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563` | OTA reference image; same code family but different model target |
| C.50 preloader | `/home/ameya/Realme1/C50_research/CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t/preloader_emmc.img` | 267,804 bytes | `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca` | Reference build image, not exact installed image |
| OTA metadata | `/home/ameya/Realme1/C50_research/CPH1861EX_11_OTA_0500_all_fLuS0Ipoe93t/compatibility.zip` | 7,231 bytes | `c61e5e96e5d1dcdb0bd921bf9d2fdb49861cfb166f7575c0e0df058a8d1310a8` | Confirms CPH1861 target packaging |

### 2.3 Live-device evidence

| Artifact | Source | Observed value | Evidence class |
| --- | --- | --- | --- |
| Device fingerprint | ADB / build props | `OPPO/CPH1859/CPH1859:9/PPR1.180610.011/1601287606:user/release-keys` | Directly observed |
| Kernel version | live kernel strings and config | `Linux version 4.4.146+`, MT6771, Android clang 6.0.2 | Directly observed |
| Security patch level | build props | `ro.build.version.security_patch` recorded in project notes as a device/config fact; exact image provenance still incomplete | Directly observed but incomplete |
| Runtime config | `/proc/config.gz` | includes `CONFIG_OPPO_ROOT_CHECK=y`, `CONFIG_OPPO_KEVENT_UPLOAD=y`, `CONFIG_OPPO_EXECVE_BLOCK=y`, `CONFIG_OPPO_EXECVE_REPORT=y` | Directly observed |
| Boot state | readable properties | `ro.boot.flash.locked = 1`, `ro.boot.verifiedbootstate = green`, `ro.boot.veritymode = enforcing` | Directly observed |

## 3) Provenance and lineage estimate

### Directly observed kernel metadata

- C.49 extracted `boot.img` contains a gzip-compressed Linux 4.4.146+ kernel for the MT6771 platform.
- The C.49 kernel image reports Android clang 6.0.2 and was dated 2020-05-09.
- The C.50 OTA reference `boot.img` also reports Linux 4.4.146+, Android clang 6.0.2, and MT6771, with a 2020-10-16 date in the reference package metadata.
- The live CPH1859 device reports the same `4.4.146+` family and the same SoC family.

### Evidence from the running CPH1859

- The device is a Realme 1 (CPH1859) on Android 9.
- The live kernel config extracted from `/proc/config.gz` shows the vendor-specific Oppo root/config instrumentation, but not the exact implementation of the relevant code path.
- The running device is boot-locked and verified boot is green with enforcing dm-verity.

### Evidence from C.49

- The C.49 extracted artifacts are a credible model-family reference for this device lineage.
- Exact code identity is strong for the LK token path across C.49 and C.50: the `verify_unlock_token()` and `fastboot_init()` code are 100% identical aside from certificate cluster differences.
- This supports that the LK-level security gate and token flow are not materially different between the C.49 and C.50 references.

### Evidence from CPH1861 C.50

- The C.50 OTA reference is not a proven match to exact installed CPH1859 C.50 firmware.
- Its naming and package metadata target `CPH1861`, and the project has explicitly treated it as a related reference only.
- It is useful for platform-level similarity analysis, not for exact installed-kernel provenance.

### Inferences and unknowns

- Inference: the observed device and the available C.49 and C.50 references are in the same MediaTek MT6771 4.4.146+ family.
- Inference: the live kernel is likely in the same vendor code lineage, but exact patch commit, vendor backports, and live image provenance are unproven.
- Unknown: exact build ID, exact `boot.img` hash of the live CPH1859 C.50 installation, exact vendor tree, exact mainline backport status, exact kernel `.config` for the exact installed vendor image.

## 4) Public-source and patch-history review

The only public authoritative kernel-source entry recovered in the general research chain is the Android common kernel repository, which is a generic AOSP/common kernel tree. It is not a vendor branch for CPH1859 and does not prove a device-specific vendor patch set.

| Repository / source | URL / maintainer | Target scope | Relevance | Assessment |
| --- | --- | --- | --- | --- |
| Android common kernel tree | `https://android.googlesource.com/kernel/common` | Generic AOSP/common kernel, not vendor-specific | Useful for understanding common-kernel backport conventions and branch/tag structure | Not a credible exact match for CPH1859 |
| Android Security Bulletin Sep 2020 | `https://source.android.com/docs/security/bulletin/2020-09-01` | Upstream bulletin, not device source | Validates the existence of candidate kernel issues at the bulletin patch level | Credible for bulletin applicability, not device provenance |
| MediaTek vendor tree or device tree | Not recovered in workspace | Vendor-specific | Needed for exact MT6771 backport state | Missing and decisive |

Important distinction:

- A repository exists and a chipset name matches does not prove the running CPH1859 vendor kernel is based on that source.
- A generic upstream kernel bulletin CVE does not prove a device-specific vendor backport or live exploit path.

## 5) Re-evaluation of the leading LPE candidates

### Candidate 1: `CVE-2020-0404` (USB driver EoP)

1. Vulnerable function or code path: upstream USB-driver EoP; specific vulnerable function is not recovered in the exact vendor tree.
2. Present in affected component: likely present in the MT6771 USB stack, based on config compatibility.
3. Present in a matching source or binary: not proven in the exact CPH1859 source or binary.
4. Fix/backport identifiable: Not recoverable without the exact vendor kernel source or symbolized image.
5. Unprivileged app reachability: not proven.
6. Plausible impact: direct kernel compromise if the exact bug is present and reachable.
7. Missing evidence: exact vendor USB driver source, exact built binary, exact patch backport status, reachable call path.

Conclusion: unresolved candidate only; not evidence of an actual device exploit.

### Candidate 2: `CONFIG_OPPO_ROOT_CHECK`

1. Vulnerable function or code path: not recovered.
2. Present in affected component: yes, as a live config symbol.
3. Present in matching source or binary: no exact implementation found.
4. Fix or backport: not applicable; it is not proven to be a vulnerability.
5. Unprivileged app reachability: unknown; no proof of a call path exists.
6. Plausible impact: anti-root or root-detection instrumentation, not a direct privilege-escalation primitive.
7. Missing evidence: exact `CONFIG_OPPO_ROOT_CHECK` implementation in the vendor source or symbolized kernel.

Conclusion: unresolved config artifact, not an exploit primitive.

### Candidate 3: Broad MTK driver surfaces

1. Vulnerable function or code path: possible but not identified.
2. Present in affected component: yes, broad driver surface exists.
3. Present in matching source or binary: no exact vendor source recovered.
4. Fix/backport identifiable: not without exact vendor tree.
5. Unprivileged app reachability: no proven path.
6. Plausible impact: if a specific bug matches the exact build and interface, privilege escalation could exist.
7. Missing evidence: exact driver source, exact kernel build and patch status, direct path to the driver entry.

Conclusion: potential attack surface only; no actionable device-specific claim.

## 6) Root-detection configuration reassessment

`CONFIG_OPPO_ROOT_CHECK=y` remains only a configuration signal. It does not qualify as a root primitive or as a confirmed kernel exploit without the actual implementation and behavior. The evidence to date is consistent with a vendor root-detection / anti-root mitigation configuration, not a direct UID 0 bypass.

The project therefore retains the disciplined interpretation:

- `CONFIG_OPPO_ROOT_CHECK` is a lead for vendor root-detection behavior.
- It is not evidence of a vulnerability.
- It is not a confirmed privilege-escalation primitive.

## 7) Final conclusion: exact match vs. evidence-based conclusion

### What is supported by the evidence

- The live device is a CPH1859 running Android 9 with MT6771.
- The kernel family is Linux 4.4.146+ and the vendor codebase is broadly in the MT6771 family.
- The C.49 extracted kernels and the C.50 reference OTA both share the same 4.4.146+ vendor-family layout.
- No exact installed CPH1859 C.50 kernel image was recovered.
- No exact vendor source tree or symbolized binary for the running device was recovered.
- No actionable, device-specific LPE path is proven.

### What is not supported by the evidence

- A claim that the exact installed CPH1859 kernel is the same as the CPH1861 reference build.
- A claim that a generic kernel CVE applies to the exact installed device without exact source or backport evidence.
- A claim that `CONFIG_OPPO_ROOT_CHECK` or a broad vendor driver surface is a confirmed root primitive.

### The defensible distinction

- No confirmed root path: supported by the direct evidence.
- Root paths ruled out: not supported by the evidence, because the exact kernel image and vendor source are missing.

The phase therefore ends with the strongest evidence-based statement:

No confirmed Android-root path identified from the available evidence; the exact CPH1859 C.50 kernel provenance remains the decisive missing fact required to elevate any remaining kernel candidate from a plausible lead to a proven exploit.
