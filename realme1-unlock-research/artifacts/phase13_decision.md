# Phase 13 Decision — CVE-2022-20110

## Go/no-go

**No-go for exploit execution or phone validation.**

**Go for one offline evidence step:** obtain a model-authenticated CPH1859 C.50 kernel artifact and compare its ION implementation and patch state against MediaTek `ALPS06399915` / `ALPS06399901`.

## Decision

**Unresolved due to missing exact-target evidence.**

The candidate is technically relevant: MediaTek lists CVE-2022-20110 for MT6771 and Android 9, the live kernel has ION enabled, `/dev/ion` exists, and both named MT6771 source leads contain the MediaTek ION V1/custom ioctl surface. But the examined `ion_sys_cache_sync()` implementation does not reproduce the published vulnerable variant’s direct unlocked `buffer->kmap_cnt`/`buffer->vaddr` access. The exact CPH1859 C.50 kernel and the public vendor fix diff are missing, so applicability cannot be promoted to supported or contradicted for the installed build.

## Reachability and impact

- ION is compiled in and present on the target.
- The device node is mode `0666` but labeled `ion_device`; shell UID 2000 in enforcing `u:r:shell:s0` was denied when opening it.
- Untrusted-app access was not observed or tested.
- No target-specific vulnerable primitive, exploit trigger, kernel control, or path to Android UID 0 was established.

## Remaining blocker

The decisive blocker is exact CPH1859 C.50 kernel provenance: boot image hash, exact ION code, and whether MediaTek’s `ALPS06399915` fix was backported. The CPH1861 C.50 OTA reference and public development trees cannot answer that question.

## Single highest-value next action

Acquire a model-authenticated CPH1859 C.50 `boot.img` (or trusted vendor kernel source), extract the kernel/config, and perform an offline function-level comparison of `ion_sys_cache_sync`, `ion_map_kernel`, `ion_unmap_kernel`, and the vendor patch identifier. Do not flash it, install an exploit, or run a crash test on the phone.

## Test status

The repository regression suite is a separate software-integrity check. It does not establish vulnerability or exploitability; its result is recorded in the final handoff after execution.
