# Phase 10 Candidate Matrix

## Candidate vulnerability summary

| Candidate | Required preconditions | Evidence of device applicability | Evidence of unprivileged reachability | Potential privilege gained | Patch / backport status | Confidence | Next non-destructive validation step |
|---|---|---|---|---|---|---|---|
| `CONFIG_OPPO_ROOT_CHECK` | Exact kernel source or symbolized binary needed; vendor-specific root-detection implementation | Live kernel config includes `CONFIG_OPPO_ROOT_CHECK=y` alongside other Oppo security options | None established; no unprivileged caller path recovered | Unknown; likely detection/report only, not direct escalation | Unknown; no implementation recovered | Low | Recover the exact Kconfig and source for this option from the installed boot image / vendor tree |
| `engineer_hidl` / `vendor.oppo.engnative.engineer@1.0-service` | Caller auth bypass, or compromise of a privileged client such as `system_server` or `engineermode_app` | Service and policy confirmed in C.49 vendor image; block-device access to `oppo_block_device` and properties | Not established; no direct `untrusted_app` allow rule found | Indirect block-device writes / engineering property writes; possibly pivot to root if a second bug exists | Unclear; service methods not fully recovered from stripped binary | Medium | Recover the exact vendor binary and enumerate the full HIDL method list with caller checks |
| `atci_service` / `atcid` | Property activation (`persist.vendor.service.atci.autostart=1`), engineering build, or binary bug | Configured and disabled in user build; `atci_service` runs as root, `atcid` runs as system | Not established in the live user build; no untrusted_app path found | Direct root if `atci_service` becomes reachable; system-only if `atcid` exploited | Not proven; activation is gated and disabled | Medium | Validate property_contexts and perform static analysis of the service binaries for unsafe parsing or command execution |
| `CVE-2020-0404` | Exact vulnerable function in vendor tree; reachable USB driver path under the installed config | `CONFIG_USB_MU3D_DRV=y` present, but exact code path and backport state not recovered | Not established | Kernel code execution / root if exploitable and reachable | Unknown; exact vendor patch state not recovered | Low | Compare the MT6771 USB driver source or binary against the upstream fix commit, then validate reachability |
| `CVE-2020-0407` | F2FS path or alternate filesystem config | Observed default user data path is ext4; no evidence of F2FS path in current build | Not established; not credible for the observed build | Kernel code exec if reachable | Not applicable to the observed default path | Low | Confirm exact filesystem config for the installed build; otherwise treat as not applicable |

## Summary conclusion

No candidate in the available evidence has a defensible, unprivileged, end-to-end path to UID 0 on the live CPH1859. The strongest remaining lead is a kernel-level bug in a vendor MT6771 driver path, but it remains unproven without exact kernel symbols and source from the installed build.

The next highest-value non-destructive action is to recover the exact CPH1859 C.50 kernel image and vendor symbol metadata, then verify whether `OPPO_ROOT_CHECK` and any matching root-detection code are merely defensive instrumentation or a real privilege boundary.
