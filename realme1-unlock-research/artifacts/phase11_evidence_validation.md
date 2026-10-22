# Phase 11 Evidence Validation

## Executive result

No confirmed Android-root path identified from the available evidence.

This phase independently revalidated the Phase 10 conclusions against the actual artifact set, the live-device config notes, and the authoritative Android Security Bulletin entries for the relevant kernel CVEs. The result is not a claim that no vulnerability exists; it is an evidence-based conclusion that no specific, device-relevant, user-to-UID-0 escalation path is confirmed in the available material.

## Scope reviewed

- `PROJECT_STATE.md`
- `NEXT_AGENT.md`
- `TASKS.md`
- `artifacts/phase10_root_surface_audit.md`
- `artifacts/phase10_candidate_matrix.md`
- `artifacts/phase10_evidence.json`
- `artifacts/kernel_audit.md`
- `artifacts/vulnerability_matrix.md`
- `artifacts/root_candidate_shortlist.md`
- Android Security Bulletin, September 2020
- NIST CVE pages for CVE-2020-0404 and CVE-2020-0407

## Classification matrix

| Finding | Classification | Rationale |
| --- | --- | --- |
| `CONFIG_OPPO_ROOT_CHECK` is a real kernel config symbol | Unresolved | The workspace contains no recovered implementation or vendor source proving what the symbol does. It is not evidence of an actual exploit path by itself. |
| Engineer HIDL / `vendor.oppo.engnative.engineer@1.0-service` is a privileged surface | Supported but gated | The service is real and privileged, and the DeepTesting evidence shows a direct write path to `reserve4`. However, there is no audited untrusted-app caller path in the available evidence. |
| ATCI service is privileged and starts only under engineering/property conditions | Supported and disabled in user build | The live device evidence indicates the service is not active in the user build. This reduces its practical exploitability for the installed configuration. |
| `CVE-2020-0404` is relevant to a USB driver EoP bug class | Unresolved candidate | The Android bulletin lists it as a kernel EoP issue, and the vendor USB driver is plausible in the MT6771 config. But exact vendor patch status and exploitability remain unresolved without exact kernel source or patch backport evidence. |
| `CVE-2020-0407` is applicable to the observed CPH1859 device | Contradicted / not supported | The Android bulletin names it as an F2FS issue. The device evidence and the installed filesystem posture do not support treating it as the active path for this device. |
| The kernel config and build-lineage facts are direct evidence | Directly supported | The extracted config and build metadata show the relevant vendor lineage, driver family, and device posture. This establishes the boundary conditions for the review. |
| The final conclusion “No confirmed Android-root path identified from the available evidence” | Directly supported | The evidence base does not establish a concrete kernel or Android userspace reachability chain from an untrusted app to UID 0. |

## Key reasoned conclusions

1. The strongest evidence in the workspace supports a disciplined negative conclusion: there is no confirmed Android-root or kernel EoP path from the local Android userspace to UID 0.
2. The missing evidence that would move a candidate from “unresolved” to “confirmed” is the exact installed CPH1859 C.50 kernel image and vendor source/symbol data, not a speculative exploit hypothesis.
3. The investigation deliberately distinguishes between a device feature that is privileged and a vulnerability that is exploitable from the installed build. The available evidence supports the first; it does not support the second.

## Final classification

The Phase 10 conclusions remain the strongest supportable result:

- Directly supported: the device is factory-locked, boot verification is enforced, and the effective fastboot gate is a validated LK token path.
- Supported but gated: the Engineer HIDL and ATCI surfaces exist and are privileged.
- Unresolved: the actual kernel local privilege escalation path, if any exists in the installed vendor kernel, remains unproven.
- Contradicted / not supported: the ext4/F2FS CVE mapping in the current device posture does not establish a concrete exploit path.

The audit therefore ends with: no confirmed Android-root path identified from the available evidence.
