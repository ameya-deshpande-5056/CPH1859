# Phase 13 — CVE-2022-20110 Targeted Kernel LPE Analysis

Date: 2026-10-23 (Asia/Kolkata)

## Decision

**Verdict: unresolved due to missing exact-target evidence.** CVE-2022-20110 is a credible, high-priority candidate for the MT6771/Android 9 platform, and the live device demonstrably has the ION subsystem enabled. The available source leads also contain the MediaTek ION V1/custom ioctl surface. However, no examined source tree is an authenticated match for the installed CPH1859 C.50 kernel, the exact vulnerable implementation described by the advisory research is not present in the examined `ion_sys_cache_sync` code, and no public commit tying MediaTek patch `ALPS06399915` to either source lead was found. Confidence in this verdict: **high**.

This is a decision about whether the candidate is established for this device. It is not a claim that every possible CPH1859 C.50 kernel build is safe.

## Advisory summary

The authoritative MediaTek Product Security Bulletin for May 2022 lists CVE-2022-20110 as:

- title: “Time-of-check time-of-use (TOCTOU) race condition in ion”;
- severity: High; vulnerability type: local elevation of privilege;
- weakness: CWE-367;
- description: a race-dependent use-after-free in ION, with no additional execution privilege or user interaction required;
- affected chipsets: includes MT6771;
- affected software: Android 9.0, 10.0, 11.0, and 12.0;
- vendor identifiers: patch `ALPS06399915`, issue `ALPS06399901`.

Sources:

- [MediaTek Product Security Bulletin — May 2022](https://www.mediatek.com/product-security-bulletin/May-2022), published 2022-05-03.
- [Android Security Bulletin — June 2022](https://source.android.com/docs/security/bulletin/2022-06-01): the Android bulletin explains that MediaTek component details and severity are supplied directly by MediaTek; it does not provide the CVE’s vendor patch diff.
- [CVE-2022-20110 record](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-20110), assigned to MediaTek and published 2022-05-03.

The public advisory does not identify a source function, a source commit, a required ION heap, or a permission/SELinux condition. Those must be established from the vendor implementation.

## Target environment observations

Direct ADB observations from the connected device:

| Observation | Result |
| --- | --- |
| Identity | `CPH1859`, `mt6771`, Android 9, build fingerprint `OPPO/CPH1859/CPH1859:9/PPR1.180610.011/1601287606:user/release-keys` |
| Kernel | `Linux 4.4.146+ #2 SMP PREEMPT Fri Oct 16 23:57:58 CST 2020 aarch64` |
| Compiler string | Android clang 6.0.2, LLVM revision `34361f...` |
| Security patch | `2020-09-05` |
| Runtime config | `CONFIG_ION=y`, `CONFIG_MTK_ION=y`, `CONFIG_DMA_SHARED_BUFFER=y` |
| ION optimization | `CONFIG_MTK_ION_CACHE_OPTIMIZATION` is not set; `CONFIG_MTK_CACHE_FLUSH_RANGE_PARALLEL` is not set |
| Device node | `/dev/ion`: character device, mode `0666`, owner `system:graphics`, SELinux type `ion_device` |
| Sysfs | `/sys/class/misc/ion` exists and points to the virtual ION device |
| Shell reachability | shell UID 2000, domain `u:r:shell:s0`; read/write access check reports `rw`, but opening `/dev/ion` is denied under enforcing SELinux |
| Device state | bootloader remains locked/verified; no device writes or exploit tests were performed |

The node mode alone is not an access-control result. The enforcing SELinux denial means that ordinary shell access to the ION file descriptor was not demonstrated. No APK was installed and no app-domain probe was performed.

## Repository provenance

### GitLab lead

Repository: [eldraco/android_kernel_oppo_mt6771](https://gitlab.com/eldraco/android_kernel_oppo_mt6771)

The repository describes itself as Pie kernel source for Realme 1 CPH1859/CPH1861 and advertises a newer 4.4.205 state. The examined branch/ref was:

- branch: `android-9.0`
- commit: `0050c1d2eaed995c476e61abd017bc0559cfee5d`
- commit date: 2020-07-27
- commit title: “merged official kernel src into linux 4.4.146 kernel tag”
- Makefile version at that commit: Linux `4.4.146`
- branch history for `drivers/staging/android/ion/mtk/ion_drv.c`: the API returned only this import commit; no later CVE patch commit was present in the examined branch history.

Examined file hashes at that commit:

| Path | SHA-256 |
| --- | --- |
| `Makefile` | `9d88e650000ab88c5c3cf9a984c839875dab2b49e72739a4075bc03c4776cd85` |
| `drivers/staging/android/ion/ion.c` | `d29500e53a3f220361d6ff83d7adcda8470c90006e17f8be0a9bc332fe5f7887` |
| `drivers/staging/android/ion/ion.h` | `185d951f40c88b61ab6f30280c07064c2d75a34d4a4265bb4591ce01975f9748` |
| `drivers/staging/android/ion/Kconfig` | `c6a01eb882d81e3e67435e1cb7626377df8e899fef49399804c36ea1457cd89` |
| `drivers/staging/android/ion/mtk/ion_drv.c` | `1139ed636ab38b4682c3836242a96adcbb25ecf35741a53f5833ead2e4c6290b` |
| `drivers/staging/android/ion/mtk/ion_drv.h` | `79b99288265d8e600f4b9758598e035ce0ae7c436e0701067496bec5564978af` |

This is a credible device-family/platform source lead, not proof of the installed CPH1859 C.50 source. Its commit predates the live build by roughly three months and the repository’s own advertised current version is not the examined commit.

### GitHub lead

Repository: [realme-mt6771-devs/android_kernel_realme_mt6771](https://github.com/realme-mt6771-devs/android_kernel_realme_mt6771)

The examined ref was:

- branch: `android-13.0`
- commit: `cea131ed320016c369ea5926c1d7a55dd94efc6b`
- commit date: 2023-06-12
- commit title: “videox: Completely bypass gamma subsystem to fix flickering issues”
- Makefile version at that commit: Linux `4.4.167`

The branch has a `CPH1859_defconfig`, but its Android 13-era history and 4.4.167 Makefile make it a related development tree, not an exact CPH1859 C.50 match. The relevant MTK ION files are byte-identical to the GitLab lead for the files below, while the core `ion.c` differs.

Examined file hashes at that commit:

| Path | SHA-256 |
| --- | --- |
| `Makefile` | `41a670af9b72239ce5cb6ed230ca2908039b411a5751529cc6abcebfe792526f` |
| `arch/arm64/configs/CPH1859_defconfig` | `1bac0d37ba5206c323056c4864f098bf7a055dbdbaa30368a88c8195a34cab71` |
| `drivers/staging/android/ion/ion.c` | `61cda6f30552cb2b8a35a4b112a8a9e4df899ea8bc76b1eb85c281e8b1a8a381` |
| `drivers/staging/android/ion/ion.h` | `185d951f40c88b61ab6f30280c07064c2d75a34d4a4265bb4591ce01975f9748` |
| `drivers/staging/android/ion/mtk/ion_drv.c` | `1139ed636ab38b4682c3836242a96adcbb25ecf35741a53f5833ead2e4c6290b` |
| `drivers/staging/android/ion/mtk/ion_drv.h` | `79b99288265d8e600f4b9758598e035ce0ae7c436e0701067496bec5564978af` |

## Vulnerable code and fix analysis

### What the candidate source establishes

Both leads contain the legacy MediaTek ION V1 custom interface:

- `drivers/staging/android/ion/mtk/ion_drv.h` defines `ION_CMD_SYSTEM`, `ION_SYS_CACHE_SYNC`, and the cache-sync parameter structures.
- `drivers/staging/android/ion/mtk/ion_drv.c:200` defines `ion_sys_cache_sync()`.
- `ion_sys_ioctl()` at approximately line 528 dispatches user-supplied custom data to `ION_SYS_CACHE_SYNC`.
- `_ion_ioctl()` at approximately line 595 dispatches `ION_CMD_SYSTEM`.
- `ion_custom_ioctl()` at approximately line 618 passes the user path (`from_kernel = 0`) into that dispatcher.
- `ion_drv_probe()` at approximately line 803 creates the ION device with `ion_device_create(ion_custom_ioctl)`.
- The core `drivers/staging/android/ion/ion.c` registers the ordinary `ION_IOC_CUSTOM` entry point.

This is enough to establish a credible ION attack surface in a related MT6771 source lineage. It is not enough to establish the CVE.

### Comparison with the CVE description

The public technical description of CVE-2022-20110 in the [ExplosION presentation](https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Wu-ExplosION-The-Hidden-Mines.pdf) describes a vendor ION V1 `ion_sys_cache_sync()` variant that reads `buffer->kmap_cnt`/`buffer->vaddr` without the buffer lock, races with another mapping/unmapping operation, and later uses an unmapped address.

The examined `ion_drv.c` is materially different at that point:

- the normal range path obtains a referenced handle with `ion_drv_get_handle()`;
- it locks `client->lock`;
- it uses `buffer->sg_table` and maps individual pages through the cache-map helper;
- the examined function has no direct `buffer->kmap_cnt` or `buffer->vaddr` access;
- the `ION_CACHE_*_USE_VA` path calls the exported `ion_unmap_kernel()` helper rather than directly manipulating those internal counters.

The core `ion.c` does contain `buffer->kmap_cnt` and `buffer->vaddr`, but `ion_map_kernel()` and `ion_unmap_kernel()` protect those operations with `buffer->lock` (approximately lines 743–784 in the examined GitLab file). This source comparison therefore does **not** show the published vulnerable pseudocode in either named lead.

### Fix references examined

MediaTek publicly identifies the fix only as `ALPS06399915` / `ALPS06399901`; no public source diff or vendor commit was found in the two named repositories.

For comparison, Android Common Kernel commit [`504e1d6ee65d5b5a053253ae62f46035d774353c`](https://android.googlesource.com/kernel/common/+/504e1d6ee65d5b5a053253ae62f46035d774353c) (“ion: Fix use after free during ION_IOC_ALLOC”, 2022-01-25) changes `ION_IOC_ALLOC` reference handling in `ion-ioctl.c`, `ion.c`, and `ion.h`. Android Common commit [`0d752f78b20dbe4eeb9bc76f118889f1898948ca`](https://android.googlesource.com/kernel/common/+/0d752f78b20dbe4eeb9bc76f118889f1898948ca) backports a reference-counting check in `ion_buffer.c`. These are adjacent ION UAF fixes, not evidence that either is the CVE-2022-20110 fix. They were recorded to prevent conflating a public ION fix with MediaTek’s separate vendor patch identifier.

## Reachability and impact

| Question | Assessment | Evidence boundary |
| --- | --- | --- |
| Is ION present in a credible source candidate? | Yes | Both named trees contain legacy ION V1 and MTK custom ioctl files. |
| Is ION enabled on the target? | Yes | Live `/proc/config.gz`: `CONFIG_ION=y`, `CONFIG_MTK_ION=y`; `/dev/ion` and sysfs node exist. |
| Does the examined source contain the published CVE variant? | Not shown | The direct unlocked `buffer->kmap_cnt`/`buffer->vaddr` access from the published description is absent from the examined `ion_sys_cache_sync()`. |
| Is the path reachable from ordinary shell? | Not observed; direct open denied | `/dev/ion` mode is `0666`, but shell UID 2000 in `u:r:shell:s0` receives an SELinux denial under enforcing policy. |
| Is an untrusted-app path established? | No | No app was installed or probed; no policy rule proving `untrusted_app` access was found in this phase. |
| Is a UID 0 impact path established? | No | The advisory says local EoP in the abstract; no target-specific vulnerable function, trigger, memory-corruption control, or post-corruption privilege transition was demonstrated. |

The custom ioctl source has no obvious credential check inside `ion_custom_ioctl()`, so a domain that can open `/dev/ion` could be relevant. That is a conditional source inference, not evidence that an ordinary app can reach it on this device. SELinux, the exact target binary, and the exact vendor patch state remain decisive.

## What prevents an exact match

1. The live device exposes only the generic `4.4.146+` release string and runtime configuration; it does not expose the exact boot image hash or vendor commit.
2. The GitLab source is a 2020 import into a 4.4.146 tree, not an authenticated CPH1859 C.50 build tree.
3. The GitHub source is a 2023 Android 13-era 4.4.167 development tree, despite having a CPH1859 defconfig.
4. The available C.50 firmware artifact in the workspace targets CPH1861, not CPH1859.
5. MediaTek’s public `ALPS06399915` identifier has no public diff in the examined source histories.
6. A source tree can contain code that is not selected or can differ from the built kernel; the live config narrows this for ION but does not prove byte identity.

## Minimum safe additional evidence

No exploit or crash-inducing test is authorized by this phase. The minimum evidence needed before any controlled, isolated validation would be:

1. a model-authenticated CPH1859 C.50 `boot.img` or a trusted kernel source/build artifact;
2. extraction of the exact kernel `.config`, ION symbols/strings, and `drivers/staging/android/ion/mtk/ion_drv.c` equivalent;
3. a code-level comparison to the vendor’s `ALPS06399915` patch or a verified backport;
4. an offline SELinux policy proof that an explicitly authorized test domain can open `/dev/ion`;
5. only then, a disposable isolated test plan with crash recovery and no production-device execution.

## Final assessment

CVE-2022-20110 is **not contradicted as a platform candidate**: MT6771, Android 9, enabled ION, and related MTK ION source all align with the advisory’s broad applicability. It is also **not supported as a device-specific vulnerability** because the examined code does not reproduce the described vulnerable variant, the exact CPH1859 C.50 kernel is unavailable, and shell/app reachability plus backport status are not established.

Accordingly, the required device decision is **unresolved due to missing evidence**, with **high confidence**. The candidate warrants offline provenance and patch verification, but it does not warrant exploit execution on the phone or a claim of a plausible UID 0 path.
