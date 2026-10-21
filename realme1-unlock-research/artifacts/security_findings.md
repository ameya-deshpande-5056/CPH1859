# Realme 1 (CPH1859): Security Findings & Vulnerability Assessment

**Document ID:** `ART-014`  
**Classification:** Defensive Firmware Security Audit & Evidence Calibration  
**Analyzed Binaries:**
- `lk.img` (C.49: `30b48cd52b5d...`, C.50: `58cd19a96476...`)
- `preloader_oppo6771_17065.bin` (C.49: `afe99890545f...`)
- `preloader_emmc.img` (C.50: `2de60eda847d...`)
- `recovery.img` (C.49: `3b8d60515152...`)

---

## Executive Summary

This report systematically evaluates eight candidate security assumptions and hypothesized bypass vectors for the Realme 1 (CPH1859) boot chain. Each vector is evaluated against primary disassembly evidence, cryptographic validation, and physical device constraints.

**Authoritative Conclusion:**
No software validation flaw, missing bounds check, cryptographic weakness, or unintended entry path exists in the analyzed firmware that would permit a non-destructive, software-only bootloader unlock without an authentic vendor-signed token or hardware testpoint intervention.

---

## 1. Systematic Evaluation of Candidate Weaknesses

### Finding 1: In-Depth Test (DeepTesting) Verification Flaw / Simulated Backend
- **Hypothesis:** Can an offline or simulated server generate a valid unlock token, or can client-side APK checks be modified to force unlocking?
- **Exact Binary & Boundaries:**
  - `lk.img`, function `verify_unlock_token()` (RAM `0x6002EB00`–`0x6002EDCC`, file `0x2EB00`–`0x2EDCC`).
- **Disassembly & Control Flow Evidence:**
  - Lines `0x6002ECDE`–`0x6002ED44` execute an RSASSA-PSS SHA-256 signature verification using public key modulus at RAM `0x6007EE48` (file `0x7F048`).
  - The verifier validates the signature on the token stored in partition `reserve4`. It never communicates over the network or validates server SSL certificates.
- **Security Assumption Evaluated:** "Client-side APK validation or network transport security gates the unlock."
- **Violation Demonstrable:** **NO.** The authorization gate is an offline asymmetric cryptographic signature checked by Little Kernel. A simulated server cannot forge an RSASSA-PSS signature without the corresponding RSA-2048 private key.
- **Classification:** **`REFUTED / CRYPTOGRAPHICALLY SOUND`**
- **Plausibility for CPH1859 Build:** Confirmed across both C.49 and C.50 builds.

---

### Finding 2: `fastboot_unlock_verity` String & dm-verity Bypass
- **Hypothesis:** Is the observed failure string `fastboot_unlock_verity` indicative of a dm-verity bypass or separate verity-checking routine?
- **Exact Binary & Boundaries:**
  - `lk.img`, string table at file offset `0x080BFC` (RAM `0x600809FC`).
- **Disassembly & Control Flow Evidence:**
  - Direct binary search proves the string `fastboot_unlock_verity` is **completely absent** from all firmware images.
  - The actual string at `0x080BFC` is `fastboot_unlock_verify fail\n\n`.
  - The console output is produced by `fastboot_init()` at `0x60030056` immediately prior to `mtk_arch_reset(1)`.
- **Security Assumption Evaluated:** "Little Kernel implements a verity bypass or distinct `verity` routine."
- **Violation Demonstrable:** **NO.** The observed text was an optical console artifact on the low-resolution LCD display.
- **Classification:** **`REFUTED / OPTICAL ARTIFACT`**
- **Plausibility for CPH1859 Build:** Confirmed across C.49, C.50, and Preloader images.

---

### Finding 3: Preloader USB Handshake Crash Payloads (`kamakiri` / MTKClient)
- **Hypothesis:** Can standard software crash packets over USB (`0e8d:2000`) force the device to drop into BootROM mode (`0e8d:0003`) to clear `reserve4` or `seccfg`?
- **Exact Binary & Boundaries:**
  - `preloader_oppo6771_17065.bin`, module `download.c` (`usbdl_send_da` at file offset `0x03293B`).
- **Disassembly & Control Flow Evidence:**
  - The preloader executable code region (`0x00000`–`0x325A4`) is 100% byte-identical between C.49 and C.50.
  - MediaTek patched the USB buffer overflow vulnerabilities in 2020 MT6771 preloader builds (`oppo6771_17065_USR_202005090539`).
  - Community tools (MTKClient) report communication timeouts (`0x1d18`/`0x1d1a`) during software crash attempts, requiring physical motherboard testpoint grounding (eMMC `DAT0` to ground) to inhibit eMMC boot and enter BootROM.
- **Security Assumption Evaluated:** "Preloader USB control endpoint contains exploitable integer overflow permitting arbitrary code execution without SLA."
- **Violation Demonstrable:** **NO.** All software crash attempts fail on retail builds; physical testpoints violate the non-destructive software-only scope.
- **Classification:** **`CONFIRMED BLOCKED IN SOFTWARE`**
- **Plausibility for CPH1859 Build:** Confirmed on retail firmware builds.

---

### Finding 4: Developer Options FRP Flag (`sys.oem_unlock_allowed`)
- **Hypothesis:** Does toggling "OEM Unlocking" in Android Developer Settings allow bypassing token verification in Little Kernel?
- **Exact Binary & Boundaries:**
  - `lk.img`, function `0x60036390` (`get_unlock_ability`).
- **Disassembly & Control Flow Evidence:**
  - Function `0x60036390` reads 4 bytes from offset `size - 4` of the `frp` partition.
  - This check is called **exclusively by `cmd_flashing_unlock()` (`0x60036648`) and `cmd_flashing_get_unlock_ability()` (`0x60036518`)**, which are only executed AFTER Fastboot has already been entered.
  - `fastboot_init()` and `verify_unlock_token()` never read or evaluate the `frp` partition.
- **Security Assumption Evaluated:** "Enabling OEM unlocking in Android settings suppresses the bootloader token check."
- **Violation Demonstrable:** **NO.** The FRP flag is an orthogonal secondary check executed inside Fastboot, not a bypass for the Fastboot entry gate.
- **Classification:** **`REFUTED / ORTHOGONAL MECHANISM`**
- **Plausibility for CPH1859 Build:** Confirmed by live device testing (`sys.oem_unlock_allowed = 1` active while token check still halts boot).

---

### Finding 5: Token Replay / Inter-Device Token Reusability
- **Hypothesis:** Can an authentic unlock token from a different unlocked Realme 1 device be installed onto this device?
- **Exact Binary & Boundaries:**
  - `lk.img`, function `verify_unlock_token()` at RAM `0x6002EC30`–`0x6002EC5C`.
- **Disassembly & Control Flow Evidence:**
  - `verify_unlock_token()` reads the SoC serial number directly from on-chip OTP eFUSE registers via `devinfo` (`0x60003C4C` / `0x60059C18`).
  - Compares 16 bytes of the SoC serial against offset `+0x100` of the token.
  - Computes the SHA-256 digest strictly over the 16 bytes of the device's unique serial number.
  - An unlock token generated for a different serial number will fail the `strncmp` check (logging `"the serial is not match\n"`) and fail the RSASSA-PSS signature check.
- **Security Assumption Evaluated:** "Unlock tokens are generic or model-wide rather than device-unique."
- **Violation Demonstrable:** **NO.** Tokens are strictly bound to individual hardware SoC eFUSE serial numbers.
- **Classification:** **`REFUTED / HARDWARE-BOUND`**
- **Plausibility for CPH1859 Build:** Confirmed across all firmware builds.

---

### Finding 6: Cryptographic Algorithm Flaw / Short Key Factorization
- **Hypothesis:** Does the token verification implementation suffer from padding oracle, Bleichenbacher prefix, or short-key vulnerabilities?
- **Exact Binary & Boundaries:**
  - `lk.img`, module `0x600567C0` (RSASSA-PSS verifier) and `0x600540A0`–`0x600569C6`.
- **Disassembly & Control Flow Evidence:**
  - The implementation strictly adheres to RFC 8017 Section 9.1.2:
    - 2048-bit RSA modulus ($2^{112}$ cryptographic security).
    - Full 32-byte SHA-256 digest.
    - MGF1 mask generation function using SHA-256 (`0x600566C4`).
    - Random salt length 32 (`0x20`).
    - Strict `0xBC` trailer field check (`0x60056864`).
    - Leftmost bit masking (`0x6005690C`).
    - Re-hashing of $M' = 8 \text{ zeros} \ || \ mHash \ || \ salt$ and full byte-by-byte comparison (`0x60056988`–`0x600569C6`).
- **Security Assumption Evaluated:** "Little Kernel uses legacy PKCS#1 v1.5 with imperfect prefix checking."
- **Violation Demonstrable:** **NO.** The implementation enforces standard RSASSA-PSS without padding oracle or factorization weaknesses.
- **Classification:** **`REFUTED / MATHEMATICALLY RIGOROUS`**
- **Plausibility for CPH1859 Build:** Confirmed across both C.49 and C.50.

---

### Finding 7: Stock Recovery Partition Modification or Sideload Flaw
- **Hypothesis:** Can stock recovery be manipulated via crafted OTA scripts or ADB sideload to write partition `reserve4` or `seccfg`?
- **Exact Binary & Boundaries:**
  - `recovery.img`, binary `sbin/recovery` (SHA-256: `a91176bc06a3...`).
- **Disassembly & Control Flow Evidence:**
  - `sbin/recovery` verifies all incoming OTA packages against compiled-in OEM X.509 public keys (`res/keys`).
  - No recovery commands exist to format, dump, or write raw eMMC block partitions.
  - String analysis of `sbin/recovery` confirms zero occurrences of `reserve4`, `seccfg`, `fastboot`, or `deeptest`.
- **Security Assumption Evaluated:** "Stock recovery exposes diagnostic or sideload commands capable of altering security partitions."
- **Violation Demonstrable:** **NO.** Stock recovery strictly restricts writes to `/system`, `/vendor`, and `/cache` from verified OEM packages.
- **Classification:** **`REFUTED / PARTITION ISOLATION`**
- **Plausibility for CPH1859 Build:** Confirmed on factory recovery image.

---

### Finding 8: Unauthenticated Preloader USB Service Commands
- **Hypothesis:** Does Preloader virtual COM port (`0e8d:2000`) expose undocumented factory service commands that bypass SLA?
- **Exact Binary & Boundaries:**
  - `preloader_oppo6771_17065.bin`, module `download.c` and `sec_auth.c`.
- **Disassembly & Control Flow Evidence:**
  - Preloader implements standard MediaTek handshake (`bldr_handshake`).
  - External Download Agent reception (`usbdl_send_da`) is followed by SLA evaluation (`sec_auth.c`).
  - When SoC fuse bit `sbc_en = 1` (`sboot_state.c: S-CHIP`), all DA execution requires signed SLA challenge-response packets.
- **Security Assumption Evaluated:** "Preloader accepts unauthenticated raw write commands over USB."
- **Violation Demonstrable:** **NO.** All raw partition writes require a validated Download Agent running in DRAM.
- **Classification:** **`STRONGLY SUPPORTED BLOCKED`**
- **Plausibility for CPH1859 Build:** Confirmed across C.49 and C.50 preloaders.

---

## 2. Summary Matrix of Evaluated Weaknesses

| # | Hypothesized Weakness | Security Domain | Target Subsystem | Status | Epistemic Level |
|---|---|---|---|---|---|
| 1 | DeepTesting backend simulation | Cryptography | `verify_unlock_token()` | **REFUTED** | Directly Disassembled |
| 2 | `fastboot_unlock_verity` bypass | Reverse Engineering | `fastboot_init()` | **REFUTED** | Directly Disassembled |
| 3 | Preloader USB crash payloads | Transport Security | Preloader USB (`0e8d:2000`) | **BLOCKED** | Empirically & Source-Reported |
| 4 | FRP `sys.oem_unlock_allowed` | Permission Gating | `cmd_flashing_unlock()` | **REFUTED** | Directly Disassembled |
| 5 | Token inter-device replay | Identity Binding | `verify_unlock_token()` | **REFUTED** | Directly Disassembled |
| 6 | Weak RSA / digest collision | Cryptography | `0x600567C0` (RSASSA-PSS) | **REFUTED** | Directly Disassembled |
| 7 | Stock Recovery sideload flaw | Boundary Isolation | `sbin/recovery` | **REFUTED** | Directly Disassembled |
| 8 | Preloader unauthenticated commands | Protocol Security | `download.c` / `sec_auth.c` | **BLOCKED** | Directly Disassembled |
