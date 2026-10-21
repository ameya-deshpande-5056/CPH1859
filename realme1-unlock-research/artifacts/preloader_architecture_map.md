# Preloader Architecture Map: Realme 1 MT6771

**Date:** 2026-10-21  
**Analyzed references:**

- C.49 `preloader_oppo6771_17065.bin`, 265,756 bytes, SHA-256 `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a`
- C.50 `preloader_emmc.img` reference, 267,804 bytes, SHA-256 `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca`

The C.50 file is a CPH1861-targeted reference according to project provenance. It must not be treated as the exact installed CPH1859 preloader.

## Audit correction: string anchors are not function addresses

The earlier map used offsets such as `0x32924`, `0x32a0a`, `0x371f4`, and `0x3917e` as if they identified executable routines. They are offsets of diagnostic/source strings. Disassembling those offsets produces data, not callable code. A fresh Capstone scan of the executable region (`0x100..0x325a4`) found zero conservative direct literal-pointer or `ldr`+`add pc` references to the named `usbdl_*`, `bldr_handshake`, `S-CHIP`/`NS-CHIP`, `cert chain`, `BR cmd`, `trigger BROM`, `Force brom`, `lock_state`, and `sbc_en` strings. This does not rule out table-based or indirect use, but it means those strings cannot be used as a resolved DA call graph.

The reproducible command is `python3 scripts/validate_remaining_paths.py`. It also records direct watchdog transfer sites. No binary or device state is modified.

## 1. Entry and image structure

The C.49 GFH/header analysis identifies an eMMC preloader image with SRAM load address `0x00200f10`, code entry `0x00201000`, and ARMv7-A code that later switches into Thumb-2. The C.50 reference has a 2048-byte `EMMC_BOOT` prefix; removing that prefix yields the same 265,756-byte comparison length.

These are static image facts. They do not establish the physical fuse configuration or the exact reset reason on the phone.

## 2. Mapped subsystems and evidence anchors

| Subsystem | Evidence anchor in C.49 | What is established | Classification |
|---|---|---|---|
| Core boot flow | GFH and `platform/mt6771/src/core/main.c` strings | Preloader initializes platform/storage, decides whether to continue boot or enter USB/meta handling, and loads later stages | Confirmed at architecture/string level; exact stripped function boundaries are incomplete |
| USB handshake | String `bldr_handshake` at `0x34d0a` and nearby source/debug text | The image contains handshake-related build text | String presence confirmed; executable caller/callee and host branch unresolved |
| DA reception | `%s usbdl_send_da...` at `0x3293b` | The image contains DA-receive diagnostic text | String presence confirmed; receive function not identified by this string |
| DA verification | `usbdl_vfy_da:disabled` at `0x32924` | The build contains a diagnostic/configuration string saying one named verification stage is disabled | Confirmed string only; complete runtime policy is not proven |
| DA execution | `%s usbdl_jump_da: %x` at `0x32a0a` | The image contains DA-jump diagnostic text | String presence confirmed; execution target and preceding checks unresolved |
| Secure-boot state | `S-CHIP`/`NS-CHIP` at `0x3a0ca`/`0x3a0d7`; `sbc_en` at `0x3a36d` | The image contains secure/non-secure and policy text | Confirmed strings; executable branches, fuse values, and physical state remain unknown |
| Partition/certificate checks | `cert chain vfy` at `0x3688d` | Preloader contains image-container/certificate validation logic for later stages | Strongly supported; exact indirect key-call graph remains incomplete |
| `seccfg`/lock state | `seccfg` references around `0x38cbf–0x38e17`; `lock_state` around `0x38fa4` | Preloader contains security-configuration and lock-state handling | Confirmed at reference-code/string level; no unauthenticated write path demonstrated |
| META/factory modes | `METAMETA`, `ADVEMETA`, and fast-meta strings | Alternate factory/diagnostic mode selection exists | Confirmed as an interface; unlock impact unknown |
| Emergency BootROM reset | Strings at `0x371f4`/`0x3917e`; executable WDT routines at raw `0x2ae34`, `0x2ae44`, `0x2aef0` | Watchdog reset primitives and internal callers exist; BROM meaning is suggested only by data text | Reset primitives confirmed; BROM selection, host reachability, and preconditions unknown |

The C.50 reference has the corresponding anchors shifted by its 2048-byte prefix (for example `usbdl_vfy_da:disabled` at `0x33124` and `bldr_handshake` at `0x3550a`). After normalization, the validator finds 569 differing bytes, all within identified metadata/signature regions, and no differences in the compared code region.

## 3. USB state model

```text
platform initialization
        |
        v
named DA/security strings (data only)
        |   no resolved direct references
        v
unresolved table/indirect dispatch
        |---------------- policy decision unknown ---------------->
        v
DA receive/verification/jump semantics unknown
```

This diagram is a static evidence model, not a recovered control-flow graph. It is not a claim that any displayed transition is reachable from an arbitrary USB packet, nor that a successful DA operation is unauthenticated.

## 4. Authentication and raw-storage assessment

The reference preloaders contain all of the following relevant evidence:

- secure-chip state and `sbc_en` policy references;
- DA-related receive/verify/jump diagnostic text;
- certificate-chain validation strings for later images;
- `seccfg` and lock-state handling;
- a `BR cmd is disabled` diagnostic string;
- emergency reset-to-BROM strings.

The string `usbdl_vfy_da:disabled` is counterevidence to a simple claim that every DA is checked by one ordinary software signature routine. It does not prove that the whole download path is unauthenticated: hardware SLA/secure-boot policy, indirect calls, and subsequent DA checks may still constrain execution. Because the named strings have no conservative direct code references in the pinned executable scan, the available static evidence supports only “security-related DA code/text is present”; the complete runtime command policy is **unknown**.

No direct evidence was found in the audited artifacts of a host-reachable, unauthenticated raw write primitive that changes `seccfg`, `reserve4`, or LK. The presence of storage routines or service strings alone is insufficient to classify such a primitive as exploitable.

## 4A. Resolved watchdog-reset edges and emergency-path limits

The actual instruction-level edges that can be named without relying on strings are:

| Routine | Instruction evidence | Direct callers/transfers | Input/dependency |
|---|---|---|---|
| Raw `0x2ae34` / RAM `0x22bd44` | `movw r2,#0x1971`; `str r2,[r3]`, with literal `0x10007008`; return through `0x22bd40` | `0x1f76`, `0x15f58`, `0x16466`, `0x23618`, `0x2361c`, `0x2b436`, `0x2b8ac` | No host input is visible at this edge; caller context differs and is not fully named. |
| Raw `0x2ae44` / RAM `0x22bd54` | `movw r2,#0x1971`; writes watchdog state at `0x10007000` and continues configuring reset state | Tail transfer from raw `0x27c32` | Preserves the wrapper's `r0`; origin is unresolved. |
| Raw `0x2aef0` / RAM `0x22be00` | Logs, writes `0x1971` to `0x10007000`, selects configuration based on `r0`, writes `0x1209` to `0x10007014`, and does not return normally | Raw `0x23698` and `0x236c2` | One caller derives mode from `0x22bdc4`'s return value; the other supplies zero. |

These are internal reset dependencies, not proof of a USB command. `BLX` register calls and table dispatch remain unresolved. In particular, the BROM-related strings do not establish a host-triggerable path. The strongest safe classification is **internal recovery/reset path present; host trigger unknown**.

## 5. Differential result and scope

The normalized comparison is reproducible:

- 569 differing bytes between C.49 preloader and the C.50 reference payload;
- differences are confined by the validator to metadata-string ranges and the trailing signature block;
- the compared executable region is byte-identical.

This is strong evidence that the supplied C.50 reference did not change the preloader code paths examined in C.49. It is not direct evidence about an unacquired CPH1859 C.50 preloader.

## 6. Assessment

| Question | Assessment |
|---|---|
| Is preloader USB/DA-related content present? | Confirmed by strings/source inventory; executable call graph unresolved. |
| Is a complete unauthenticated raw-write path demonstrated? | No. Unknown/unsupported by current evidence. |
| Is the emergency BROM-reset path host-triggerable without its internal preconditions? | Unknown. Reset primitives are confirmed, but the BROM string is data and no host edge is proven. |
| Is software-only unlocking demonstrated through preloader? | No. |
| Highest-value next step | Acquire the exact CPH1859 C.50 preloader with provenance and use a loader-aware disassembler to resolve table/indirect DA and security dispatch; do not test the reset path on the phone. |

