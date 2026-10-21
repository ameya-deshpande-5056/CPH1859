# Independent Validation Report: Realme 1 LK Differential Analysis

**Validation Status:** **`PASS`**  
**Date:** 2026-10-21  

---

## 1. Firmware Hash & Integrity Verification

| File Target | File Size | Calculated SHA-256 | Expected SHA-256 | Match |
|---|---|---|---|---|
| `c49_lk` | 753984 B | `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa` | `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa` | **`PASS`** |
| `c50_lk` | 753984 B | `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563` | `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563` | **`PASS`** |
| `c49_preloader` | 265756 B | `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a` | `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a` | **`PASS`** |
| `c50_preloader` | 267804 B | `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca` | `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca` | **`PASS`** |

---

## 2. Little Kernel Binary Diff Audit

- **Total Differing Bytes:** `315` (Expected: `315`)
- **Clusters (Intervals in `[start, end)` Half-Open Notation):**
  - **Cluster 1:** `[0x07ea23, 0x07ea48)` (span: 37 bytes, differing bytes: 27)
  - **Cluster 2:** `[0x0b7f73, 0x0b7f93)` (span: 32 bytes, differing bytes: 32)
  - **Cluster 3:** `[0x0b8031, 0x0b8131)` (span: 256 bytes, differing bytes: 256)

---

## 3. MediaTek Container & Payload Digest Verification

- **Container Headers Valid:** `YES`
- **Hashed Interval:** `[0x000200, 0x0b72d0)` (749776 bytes)
- **C.49 Payload Digest Match:** `PASS` (`af82a35e0983891ae21efd1d0736ac18dc9197757c2185a2e94b0705721bb322`)
- **C.50 Payload Digest Match:** `PASS` (`fd95c268116d9bd8700234702921ca65b5322f05edb9e55e8112711fd9a470c1`)

---

## 4. Cryptographic Certificate & Key Chain Audit

- **Key C1 Modulus:** `0xb282df487491ff750d2b14b80d26b7...`
- **Key C2 Modulus:** `0xab3efe31c7a1c89b4b3e4e26aa47f3...`
- **OEM Unlock Modulus:** `0xc2e1e94834f13bcbc0fb9bea87be96...`
- **Key C2 Binding (cert1 OID 2.16.886.2454.1.2 == cert2 SPKI):** `VERIFIED`
- **RSASSA-PSS Salt Length (DER Encoded 0x20 = 32 bytes):** `CONFIRMED`
- **cert1 Self-Signature (Key C1, PSS SHA-256):** `VALID`
- **cert2 C.49 Signature (Key C2, PSS SHA-256):** `VALID`
- **cert2 C.50 Signature (Key C2, PSS SHA-256):** `VALID`
- **OEM Unlock Key Distinct from MTK Keys:** `VERIFIED`

---

## 5. Preloader Normalization & Code Identity Audit

- **C.50 EMMC_BOOT Header Detected & Normalized (2,048 bytes):** `YES`
- **Normalized Payload Size:** `265756 bytes`
- **Total Differing Bytes:** `569` (Expected: `569`)
- **Executable Code Region Byte-Identical:** `CONFIRMED (100% Identical)`

---

## 6. Fastboot Gating Routines & String Table Resolution

- **`verify_unlock_token` (RAM `0x6002EB00`):** `100% BYTE-IDENTICAL`
- **`fastboot_init` (RAM `0x60030018`):** `100% BYTE-IDENTICAL`
- **`fastboot_unlock_verify` Present at `0x080BFC`:** `BOTH C.49 AND C.50`
- **`fastboot_unlock_verity` (with 't') Absent:** `CONFIRMED ABSENT IN ALL BINARIES`

---

## 7. Epistemic Calibration & Trust Anchoring Distinction

1. **Mathematical Verification vs Hardware Trust:** Mathematical verification proves internal consistency of the certificate chain (Key C1 -> Key C2 -> cert2 -> payload digest). However, hardware trust on the device requires that `SHA256(Key C1)` matches the hash burned into SoC SBC EFUSE registers. Static analysis cannot observe physical efuse bits.
2. **Fastboot Token Orthogonality:** Fastboot gating does not query `cert1` or `cert2`. It verifies partition `reserve4` sector `0x7816` using an independent OEM public key modulus hardcoded at RAM `0x6007EE48`.
3. **Firmware Compatibility Warning:** Build C.50 is an `oppo6771_17065` codebase historically targeted for CPH1861. It must not be assumed safe to flash onto CPH1859, preserving the project's non-invasive read-only policy.
