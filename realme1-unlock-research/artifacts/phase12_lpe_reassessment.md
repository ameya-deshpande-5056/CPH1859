# Phase 12 LPE Reassessment

## Goal

Reassess the leading LPE candidates using the strongest available kernel provenance without assuming that a related-kernel artifact proves the installed CPH1859 image.

## Current evidence boundary

The available evidence supports the following statement:

- The live device is a CPH1859 using a Linux 4.4.146+ MT6771 kernel family.
- The C.49 extracted kernel and the CPH1861 OTA reference share the same vendor-family lineage.
- The exact installed CPH1859 C.50 kernel image and exact vendor patch set remain unverified.
- No actionable privilege-escalation candidate has been proven for the live device.

This means the project can confidently say: there is no confirmed root path from the available evidence. It cannot say: all kernel-root paths are ruled out.

## Candidate reassessment

### 1) `CVE-2020-0404` (USB driver EoP)

- Status: unresolved candidate
- Why still relevant: kernel config and driver family plausibly match the MT6771 platform; the bulletin shows this was a real upstream issue class.
- Why not actionable: no exact vendor USB driver code, no exact built binary for the live CPH1859 image, no verified backport state, and no unprivileged reachability proof.
- Evidence still missing: exact installed kernel source, vendor patch backport status, exact driver function mapping, attacker reachability path.

### 2) `CONFIG_OPPO_ROOT_CHECK`

- Status: configuration artifact, not a proven exploit primitive
- Why it remains a lead: it is real in the live config and sits with other Oppo security symbols.
- Why it does not prove root: the implementation is absent; no source or symbolized binary was recovered; no direct UID 0 path is established.
- Evidence still missing: exact source implementation and behavior in the installed kernel.

### 3) Broad MTK driver and diagnostic surfaces

- Status: plausible attack surface, not proven vulnerability
- Why they remain candidates: MT6771 has many vendor-specific debug/driver surfaces, and the kernel config shows broad support.
- Why they remain non-actionable: without the exact vendor binary or source, no concrete vulnerable function can be tied to the live image.
- Evidence still missing: exact built driver source, patch-level backport check, module metadata, and reachability proof.

## Root-detection and exploitability distinction

This project draws a strict boundary between:

- A privileged or diagnostic service that exists in the image;
- A device-specific vulnerability that is proven to affect the live build and reachable from an unprivileged caller.

The first category is observed in the live CPH1859 and the C.49/C.50 references. The second category is not established.

## Final judgment

The Phase 12 review does not materially change the final evidence position reached in Phase 11:

- No confirmed Android-root path identified from the available evidence.
- Management of kernel LPE candidates remains conservative because the exact installed CPH1859 C.50 kernel source, image, and vendor patch state are missing.
- The decisive next step is model-authenticated exact-image provenance acquisition, not exploitation or speculative CVE assignment.

The project therefore keeps the following distinction explicit:

- No confirmed root path: supported.
- Root paths ruled out: not supported without exact installed-kernel provenance and source-backport confirmation.
