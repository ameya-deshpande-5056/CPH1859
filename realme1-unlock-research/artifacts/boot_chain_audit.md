# Early-Boot and MediaTek Security Audit

## Available images

| Component | Reference | SHA-256 | Applicability |
|---|---|---|---|
| C.49 preloader | `preloader_oppo6771_17065.bin`, 265,756 B | `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a` | C.49 reference, project provenance CPH1859 |
| C.50 preloader | `preloader_emmc.img`, 267,804 B | `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca` | CPH1861-targeted OTA reference |
| C.49 LK | `lk.img`, 753,984 B | `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa` | C.49 reference |
| C.50 LK | `lk.img`, 753,984 B | `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563` | CPH1861-targeted OTA reference |

The C.50 OTA updater script contains explicit `CPH1861` checks and writes LK/preloader/other boot-chain components. That proves package scope and makes it unsafe to call the package an exact CPH1859 image.

## LK authorization gate — directly observed in both references

- `verify_unlock_token()` at RAM `0x6002EB00` / file `0x02ED00` is byte-identical in C.49 and C.50; function SHA-256 is `c1fa1a7d7cf6627d8beba0dd9614e1949780fdcf4e0f3918f900617295b6a63c`.
- It reads eight sectors from `reserve4` using relative sector `0x16`; the traced partition helper makes the absolute partition sector `0x7816`, byte offset `0x00F02C00`, 4,096 bytes.
- The token contains a 256-byte RSASSA-PSS/SHA-256 signature and 16-byte serial field at `+0x100`. The verifier compares the serial with eFUSE-derived data and uses an embedded 2048-bit OEM modulus at RAM `0x6007EE48` / file `0x7F048`.
- `fastboot_init()` at RAM `0x60030018` calls the verifier at `0x60030046`. On failure it prints `fastboot_unlock_verify fail` and calls the watchdog reset path at `0x6000CD30`; command registration follows only on success.
- `fastboot oem unlock` is absent. `flashing unlock` exists only after the gate and additionally consults the FRP unlock-ability flag.

This is a security control, not a vulnerability. It blocks ordinary Fastboot entry without a valid OEM token. A modified LK would require defeating the MediaTek signed-image chain or obtaining a privileged write path; neither was demonstrated or attempted.

## C.49/C.50 differential validation

The deterministic validator passes all checks:

- LK: exactly 315 differing bytes, limited to build metadata plus cert2 digest/signature clusters.
- LK executable authorization routines and embedded OEM token key are identical.
- Preloader: after stripping the 2,048-byte `EMMC_BOOT` header, code is identical; 569 differences are confined to metadata/signature ranges.
- cert1/cert2 DER parsing, payload digests, Key C1 → Key C2 relationship, and RSASSA-PSS signatures validate mathematically.

Mathematical validation does not prove that the device's physical eFUSE root key equals the extracted certificate root, nor does it prove the installed CPH1859 C.50 partitions equal the CPH1861 reference.

## Preloader and BootROM

The preloader contains strings and code associated with DA/security policy, USB download, watchdog/reset, and BROM selection. Static analysis directly identified executable watchdog routines and internal callers. It did not resolve every table/indirect dispatch or prove that a host can reach an emergency BROM reset from the normal preloader USB interface. Strings such as `usbdl_*`, `bldr_handshake`, `S-CHIP`, and `NS-CHIP` are not by themselves function-entry or exploit evidence.

The MT6771 BootROM exploit/Kamakiri route remains a chipset-level lead. It requires true BootROM USB mode and exact target behavior; a normal preloader USB connection is not equivalent. No live crash payload, authentication bypass, memory write, or partition write was attempted.

## Boot-chain findings

### B-001 — OEM token gate

`CONFIRMED` for both analyzed reference LK images; exact installed CPH1859 C.50 applicability is `UNKNOWN` until the exact image is authenticated. Impact is Fastboot availability/bootloader authorization, not Android root by itself.

### B-002 — MediaTek container signing

`STRONGLY SUPPORTED` for the reference images. The cert chain authenticates the LK payload under MediaTek's image-loading trust relationship. This is separate from the runtime OEM unlock-token key and does not itself grant or deny Android root.

### B-003 — Preloader DA/BROM dispatch

`UNKNOWN` for exploitability. The exact indirect call graph, fuse configuration, host-triggerability, and installed preloader are unresolved. The safe next step is loader-aware static analysis of an authenticated CPH1859 C.50 preloader, not live probing.

### B-004 — Bootloader-state versus Android-root distinction

`CONFIRMED` architectural distinction. A BootROM/DA path that can write `seccfg` or LK is a bootloader-state/integrity route; it is not evidence of a persistent Android root unless a modified boot chain can be installed and booted. Conversely, an Android LPE would not necessarily unlock the bootloader.

## Boot-chain conclusion

No supported or technically demonstrated software-only path to either Android root or persistent root was found. The official token pipeline is cryptographically gated; the LK/preloader reference comparison found no C.50 bypass; and the BootROM/preloader lead remains untested and model/provenance-dependent.
