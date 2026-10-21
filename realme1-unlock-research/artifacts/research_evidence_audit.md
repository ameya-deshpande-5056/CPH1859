# Research Evidence Audit: Realme 1 CPH1859 Unlock Study

**Date:** 2026-10-21  
**Scope:** Read-only audit of the supplied binaries, scripts, artifacts, and recorded device observations. This revision adds an instruction-level LK/PSS argument trace, a conservative preloader call-site scan, and a correction separating string-table offsets from executable entry points.

## Bottom line

The strongest reproducible result is a locked Fastboot entry gate in the supplied C.49 LK and C.50 reference LK. `fastboot_init()` calls `verify_unlock_token()` before registering commands; failure prints `fastboot_unlock_verify fail` and calls the watchdog reset path. The verifier reads 4096 bytes from `reserve4`, compares the token's serial field with the eFUSE-derived board serial, and verifies a 256-byte RSA-2048 RSASSA-PSS signature.

No software-only unlock path is demonstrated. This is a bounded conclusion, not a proof that no undiscovered vulnerability exists.

## Binary provenance and reproducibility

| Artifact | Size | SHA-256 | Scope status |
|---|---:|---|---|
| C.49 LK | 753,984 | `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa` | Reference image; directly analyzed |
| C.50 LK reference | 753,984 | `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563` | CPH1861-targeted reference provenance; not proven to be the installed CPH1859 LK |
| C.49 preloader | 265,756 | `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a` | Reference image; directly analyzed |
| C.50 preloader reference | 267,804 | `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca` | CPH1861-targeted reference provenance; normalized comparison only |
| C.49 recovery | 1,266,160 (`sbin/recovery`) | `05cfcf8ffbb59abcbd642a950989cc4d112d1985ad1a4c9eab642ce4e67bdb34` | The recorded `a91176...` recovery hash is stale and does not match the accessible extracted binary |

The hashes above were recalculated from the accessible files. The repository's differential validator and 41-test suite pass, but those tests validate encoded assumptions; they do not establish that the C.50 reference image is the phone's exact installed image.

## Authorization protocol: confirmed facts

### Entry gate

In both LK images, the following bytes disassemble identically:

```text
0x60030046: bl       #0x6002eb00
0x6003004a: cmp      r0, #0
0x6003004c: beq.w    #0x600303e6
0x60030050: ldr.w    r0, [pc, #0x424]
0x60030056: bl       #0x60038b7c
0x6003005a: movs     r0, #1
0x6003005c: bl       #0x6000cd30
```

The command-registration sequence begins after the success branch. The failure path therefore prevents ordinary Fastboot command registration in the analyzed images.

### Token input and validation

- `verify_unlock_token()` is the file interval `[0x02ed00, 0x02efcc)` and RAM interval `0x6002eb00–0x6002edcc`; its SHA-256 is `c1fa1a7d7cf6627d8beba0dd9614e1949780fdcf4e0f3918f900617295b6a63c` in both LK images.
- The call at `0x6002ec20` passes sector `0x16` and count `8` to `read_reserve4()` at `0x6002c794`.
- `read_reserve4()` adds `0x7800`, then shifts by 9, yielding sector `0x7816` and byte offset `0x00f02c00` within `reserve4`.
- The verifier uses token bytes `+0x000..+0x0ff` as the 256-byte signature and `+0x100..+0x10f` as the 16-byte serial field. The remaining bytes in the 4096-byte read are not shown as inputs to this verifier.
- It compares 16 bytes of the token serial with the eFUSE-derived board-serial string. A fallback accepts token byte `+0x100 == '0'` and compares token bytes `+0x101..+0x10f` with 15 bytes of the board string.
- The verifier copies the 16-byte token serial field into its hash input buffer before calling the SHA-256 routine at `0x60058250`. Thus the exact authenticated message is the token serial field, normally the same 16-byte text as the eFUSE-derived value; the leading-zero fallback is an alternate 16-byte encoding, not a hash of a separate model or timestamp.
- The RSA public modulus is 256 bytes at RAM `0x6007ee48` (file offset `0x7f048`), referenced through the pointer at `0x600b6b18`; exponent handling is `65537` in the surrounding RSA setup.
- The call at `0x6002ed44` reaches `0x600567c0` with digest length `0x20`, encoded-message length `0x100`, salt length `0x20`, and modulus size `0x800` bits.

The verifier at `0x600567c0` checks the PSS trailer `0xbc`, unmasks the DB with MGF1-SHA-256, checks the `0x00...01` delimiter and 32-byte salt, recomputes `H' = SHA-256( eight zero bytes || mHash || salt )`, and compares the result. This directly supports RSASSA-PSS/SHA-256 with MGF1-SHA-256 and salt length 32. The old C.49 artifact sentence calling this PKCS#1 v1.5 is incorrect and is superseded by this audit.

#### Exact caller-versus-verifier data flow

The argument roles are now separated explicitly:

| Site | Register/stack state | Role |
|---|---|---|
| `0x6002ecfc–0x6002ed04` | `r0` = copy of token bytes `+0x100..+0x10f`, `r1` = `0x10`, `r2` = digest output | Caller invokes SHA-256 at `0x60058250` over the 16-byte token serial field. |
| `0x6002ed08–0x6002ed30` | RSA setup reverses/copies the 256-byte signature and invokes modular exponentiation at `0x60056598` | Caller obtains the RSA-decrypted encoded message `EM`; this is not the PSS verifier. |
| `0x6002ed34–0x6002ed44` | `r0` = 32-byte digest (`mHash`), `r1` = `0x20`, `r2` = `EM`, `r3` = `0x100`; stack args = salt length `0x20`, modulus size `0x800` bits, status pointer | Caller invokes `0x600567c0`. The first argument is already a SHA-256 digest, not raw message bytes. |
| `0x600567c0` | Reads `EM`, checks trailer `0xbc`, unmasks DB, parses salt, and recomputes PSS `H'` | Internal RSASSA-PSS verification implementation. It does not hash the original token serial itself. |

Therefore the precise authenticated message is the 16 bytes at token-buffer offset `+0x100`, including whichever leading-zero encoding passed the serial comparison. The eFUSE-derived serial is a comparison source and normally equals that field; it is not separately concatenated into the signed message. The 256-byte signature, the unused remainder of the 4096-byte read, model strings, and FRP state are not inputs to this PSS hash call.

The internal sequence is: RSA public operation -> `EM` length `0x100` -> trailer check -> `maskedDB` length `0xdf` -> MGF1-SHA-256 using the 32-byte `H` -> leftmost-bit masking -> zero-padding and `0x01` delimiter check -> 32-byte salt extraction -> SHA-256 over `08 00` bytes followed by `mHash` and salt -> constant-length comparison with `H`. This is the PSS encoded-message check, distinct from the outer caller's token-field SHA-256 and RSA setup.

### Failure paths

| Condition | Evidence at LK | Result |
|---|---|---|
| Board-serial retrieval/format failure | `0x6002eb5c–0x6002ec14` | Nonzero return and error log |
| `reserve4` read failure | `0x6002ec24–0x6002ec2c` | Nonzero return and error log |
| Serial mismatch | `0x6002ec40–0x6002ec5c`, branch `0x6002ed9e` | `-1`, then Fastboot watchdog path |
| SHA-256/RSA/PSS failure | `0x6002ed04–0x6002ed70` | Nonzero error, then watchdog path |
| Verification status not equal to 1 | `0x6002ed70–0x6002ed86` | Nonzero error, then watchdog path |
| All checks pass | `0x6002ed70–0x6002ed86` | Zero return; command registration continues |

### Later unlock logic

`cmd_flashing_unlock()` at `0x60036648` calls the FRP-reading helper `0x60036390` only after Fastboot is running, then requires user confirmation before updating `seccfg` and erasing user data/keystore. `clean_flash_unlock_data()` at `0x6002eacc` is called from `cmd_flashing_lock()` at `0x60036920`, not from the failed entry path.

The LK directly demonstrates a persistent FRP flag read at `frp` partition offset `size - 4`. It does not, by itself, prove that this byte value is read from or dynamically synchronized with Android's `sys.oem_unlock_allowed` property. Those are related observations, not the same demonstrated input.

## Trust model classification

| Mechanism | What the evidence proves | What it does not prove |
|---|---|---|
| BootROM/SBC | Preloader images contain Secure Boot/container-validation code, cert-chain strings, and S-CHIP/NS-CHIP paths; LK `cert1`/`cert2` form a mathematically valid C1→C2→payload certificate relation | The physical device's burned fuse hash and enabled bits cannot be read from these files |
| Preloader DA/SLA | The images contain DA/security strings and executable indirect-dispatch code; the two normalized reference preloaders have identical executable bytes | The named strings have no conservative direct code-reference found in the pinned C.49 executable scan, so they do not identify callable function addresses or prove a complete handshake→DA call chain. No live protocol test was performed |
| LK unlock token | The exact token gate and independent embedded OEM public key are directly disassembled | The owner or location of the corresponding private key is not established |
| AVB/Secure Boot | Container certificate signatures and payload digest checks are mathematically valid in the supplied reference images | Mathematical validity alone does not prove the physical fuse root accepts those keys |
| Android/FRP state | Live properties and LK's later FRP partition read are separately observed | The property-to-partition synchronization mechanism is not shown by LK analysis |

The OEM unlock public key is distinct from the MediaTek C1/C2 certificate keys. Static absence of a private key in firmware does not establish that it was exclusively held by a discontinued server or any particular vendor service.

## Alternative-path coverage

- LK Fastboot command table: 21 registrations examined; no `oem unlock` entry; all registrations occur after the token gate.
- `flashing unlock`/`flashing lock`: entry checks, interactive confirmation, `seccfg`, erase, and token-clear call path examined.
- Recovery: extracted `sbin/recovery` searched and structurally inspected. Absence of `reserve4`, `seccfg`, `frp`, and `fastboot` literals is evidence against those direct paths, not a proof about every indirect helper or recovery script.
- Preloader: GFH/header, reset/entry, source/debug strings, executable watchdog-reset routines, direct reset call sites, and conservative string-reference scans examined. The named `bldr_handshake`/`usbdl_*`/`S-CHIP`/`NS-CHIP`/BROM strings are data anchors, not proven function entry points; full semantic reconstruction of the USB/DA dispatch and every indirect target was not completed.

## Findings and uncertainty

No confirmed exploitable defect was found. The LK gate, serial binding, PSS checks, Fastboot ordering, FRP ordering, and the reference-image differential are confirmed. The preloader binary proves watchdog reset routines and security-related data, but does not, from these string anchors alone, prove DA authentication policy, host-triggerability of the BROM path, or a software crash route. Preloader crash resistance on the physical CPH1859 and the historical DeepTesting backend/client behavior remain hypotheses or source-reported claims unless tested with exact CPH1859 artifacts, which the safety scope excludes.

## Phase 9 reproducible preloader audit

`scripts/validate_remaining_paths.py` was run against the pinned C.49 files. It reports the expected C.49 hashes, the exact string offsets, zero conservative direct/PC-relative references from the executable scan to each named DA/security/BROM string, and these actual direct Thumb transfers (raw file offsets):

| Target routine inferred from instructions | Raw file body | Direct transfer sites | What is safe to conclude |
|---|---:|---|---|
| watchdog-key routine; writes `0x1971` to the literal address `0x10007008` | `0x2ae34` | `0x1f76`, `0x15f58`, `0x16466`, `0x23618`, `0x2361c`, `0x2b436`, `0x2b8ac` | A generic watchdog reset primitive is called from several internal paths. |
| watchdog/BROM-or-reset routine; writes `0x1971` to `0x10007000` and changes watchdog configuration | `0x2ae44` | tail transfer `0x27c32` | The path is directly reached by one tail call; its original argument is not host-attributable from this edge alone. |
| reset-mode wrapper; writes `0x1971` to `0x10007000`, selects a mode from `r0`, writes watchdog configuration and `0x1209` | `0x2aef0` | `0x23698`, `0x236c2` | The mode is supplied by internal callers: one depends on `0x22bdc4`'s return value, the other explicitly supplies zero. |

The strings `trigger BROM` (raw `0x371f4`) and `Force brom` (raw `0x3917e`) disassemble as data, not code. Their presence cannot establish that either reset routine is a host command handler. The unresolved edges include table-based dispatch, `BLX` register calls, the USB handshake/DA receive path, fuse/configuration-dependent branches, and the origin of the reset wrapper's mode values. This is why the emergency path remains **internal-recovery supported but host-triggerability unknown**.

The single highest-value next read-only step is to acquire and authenticate the exact CPH1859 C.50 `lk`, preloader, and recovery images (or a signed package whose model and partition provenance are independently established), then rerun the same differential and preloader call-site audit. The historical DeepTesting APK is the next best step for reconstructing token serialization, but it cannot by itself demonstrate a bypass.

