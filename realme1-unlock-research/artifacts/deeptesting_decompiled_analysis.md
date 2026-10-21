# DeepTesting APK Decompiled Architecture & End-to-End Bootloader Authorization Analysis

**Document ID:** `ART-017`  
**Classification:** Application Reverse Engineering, Framework Tracing & End-to-End Protocol Analysis  
**Analyzed Targets:**
- Decompiled DeepTesting APK: `/home/ameya/Realme1/DeepTesting_realme-release_signed.apk_Decompiler.com`
  - Package: `com.coloros.deeptesting` (versionCode `11`, versionName `1.0.1`, compileSdkVersion `28`, targetSdkVersion `27`)
  - Shared UID: `android.uid.system` (`android:sharedUserId="android.uid.system"`)
- System Framework Odex/Vdex: `system/framework/boot-framework.vdex` & `system/framework/oat/arm64/services.vdex` (Android 9 / ColorOS C.49)
- Vendor Engineer HAL Binary: `/vendor/bin/hw/vendor.oppo.engnative.engineer@1.0-service` (ELF 64-bit aarch64)
- Little Kernel Firmware: `lk.img` (C.49 SHA-256 `30b48cd5...`, C.50 SHA-256 `58cd19a9...`)
- Community Procedural Document: `/home/ameya/Realme1/BOOTLOADER_FIX_V1.0.docx`

---

## Executive Summary

Static reverse engineering of the decompiled OEM `DeepTesting` application (`com.coloros.deeptesting`), combined with disassembly of the ColorOS system framework (`services.vdex`), the native hardware abstraction layer (`vendor.oppo.engnative.engineer@1.0-service`), and the Little Kernel (`lk.img`), resolves the complete end-to-end bootloader authorization pipeline of the Realme 1 (CPH1859, MediaTek MT6771):

1. **Authorization Origin:** The DeepTesting application collected hardware and build identifiers (`ro.vold.serialno`, IMEI, `ro.product.name`, `ro.build.version.ota`) and submitted them via an encrypted HTTP POST request to the vendor backend `https://lkf.realmemobile.com/realme/v1/applyLkUnlock`.
2. **Cryptographic Envelope:** Request payloads and responses were encrypted with AES-128-ECB (PKCS5Padding). The 16-byte AES key was dynamically derived from a 15-character pseudorandom suffix whose first digit indexed a static 10-entry seed table in `AesEncryptUtils`.
3. **Unlock Token Artifact:** Upon approval (`checkApproveResult`), the vendor server returned a hexadecimal string (`unlockCode`). When decoded, this formed a 272-byte binary payload comprising a 256-byte RSASSA-PSS signature at `+0x000` and a 16-byte ASCII hardware serial number at `+0x100`.
4. **Token Persistence Pipeline:** The application transferred the token into persistent storage via reflection:
   `OppoEngineerManager.fastbootUnlock(byte[] bArr, int len)` $\rightarrow$ IPC to `com.android.server.engineer.OppoEngineerService` $\rightarrow$ HIDL call `IEngineer.saveEngineerData()` $\rightarrow$ Native daemon `vendor.oppo.engnative.engineer@1.0-service`.
5. **Physical Storage Target:** The native daemon directly opened the raw block partition `/dev/block/platform/bootdevice/by-name/reserve4` and wrote the 272-byte token to offset `0x00F02C00` (sector `0x7816`).
6. **Bootloader Consumption:** Upon executing `reboot bootloader`, the device entered Little Kernel (`lk.img`). In `fastboot_init`, `verify_unlock_token()` read 4,096 bytes from `reserve4` sector `0x7816` via `read_reserve4()`, compared the embedded serial to MT6771 eFUSE registers (`devinfo_get_data`), and verified the RSASSA-PSS SHA-256 signature against the embedded OEM RSA-2048 public key at `0x6007EE48`.
7. **Service Decommissioning Impact:** Because `verify_unlock_token()` mathematically enforces 2048-bit RSASSA-PSS and guards the Fastboot USB enumeration interface, the shutdown of `lkf.realmemobile.com` creates an unbypassable software deadlock. Fastboot commands cannot be executed over USB without a valid token.
8. **Hardware Testpoint Rationale:** The community requirement to short hardware testpoints (`BOOTLOADER_FIX_V1.0.docx`) is mathematically and architecturally validated: testpoint grounding forces MT6771 BootROM USB download mode before the preloader and Little Kernel execute, permitting `mtkclient` to bypass SLA and write a patched Little Kernel that omits `verify_unlock_token()`.

---

## 1. Application Architecture & Permissions

### 1.1 Manifest & Privilege Boundary
Inspection of `resources/AndroidManifest.xml` confirms the highest possible platform privileges:
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:sharedUserId="android.uid.system"
    android:versionCode="11"
    android:versionName="1.0.1"
    package="com.coloros.deeptesting">
    
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    ...
```
Because the application defines `android:sharedUserId="android.uid.system"`, it runs within the Android system process (`system_server` context / UID 1000). It can only be installed if signed by the vendor's private platform release key.

### 1.2 Activity & Service Structure
The application comprises three primary activities and a background communication service:
- `com.coloros.deeptesting.activity.MainActivity`: Manages overall application state, queries local lock status, and checks approval state.
- `com.coloros.deeptesting.activity.ApplyActivity`: Displays disclaimer and submits the initial unlock application to the vendor backend.
- `com.coloros.deeptesting.activity.StatusActivity`: Displays query results and provides the "Start the in-depth test" button to write the token and reboot.
- `com.coloros.deeptesting.service.RequestService`: Background service handling asynchronous network calls via `NetonClient`.

---

## 2. Client-Server Protocol & Payload Encryption

### 2.1 Backend Endpoints
In `RequestService.java`, requests are dispatched based on internal integer message flags:

| Flag | Endpoint URL | Purpose |
|---|---|---|
| `1000` | `https://lkf.realmemobile.com/realme/v1/applyLkUnlock` | Initial unlock application submission |
| `1001` | `https://lkf.realmemobile.com/realme/v1/checkApproveResult` | Polling for approval status and token delivery |
| `1002` | `https://lkf.realmemobile.com/realme/v1/updateLockStatus` | Notifying server that unlock sequence has begun |
| `1003` | `https://lkf.realmemobile.com/realme/v1/acquireClientStatus` | Querying client eligibility |
| `1004` | `https://lkf.realmemobile.com/realme/v1/closeApply` | Canceling application / exiting test |
| `1005` | `https://lkf.realmemobile.com/realme/v1/acquireApplyStatus` | Querying existing application status |

### 2.2 Request Data Model (`com.coloros.deeptesting.service.b`)
When submitting a request, the client serializes the following fields to JSON:
```java
public final class b {
    @com.a.a.a.b(a = "pcb")
    private String a;           // SystemProperties.get("ro.vold.serialno")
    @com.a.a.a.b(a = "imei")
    private String b;           // ColorOSTelephonyManager.colorGetImei(0)
    @com.a.a.a.b(a = "model")
    private String c;           // SystemProperties.get("ro.product.name") [fallback: ro.product.model]
    @com.a.a.a.b(a = "otaVersion")
    private String d;           // SystemProperties.get("ro.build.version.ota")
    @com.a.a.a.b(a = "clientStatus")
    private int e = 0;
    @com.a.a.a.b(a = "adbDvice")
    private String f;           // SystemProperties.get("ro.rom.featrue") [vendor property typo preserved]
}
```

### 2.3 Cryptographic Envelope (`com.coloros.deeptesting.a.a` / `AesEncryptUtils`)
The JSON request is encrypted with AES-128-ECB before transmission. The key derivation is completely self-contained in `AesEncryptUtils.java`:

1. **Random Suffix Generation:** A 15-character string `str2` is generated:
   - First character: Random integer from 0 to 9 (`b.nextInt(10)`).
   - Remaining 14 characters: Pseudorandom alphanumeric characters.
2. **Key Derivation (`c(str)`):**
   ```java
   private static final String[] a = {
       "oppo1997", "baed2017", "java7865", "231uiedn", "09e32ji6",
       "0oiu3jdy", "0pej387l", "2dkliuyt", "20odiuye", "87j3id7w"
   };
   
   private static String c(String str) {
       String strSubstring = str.substring(0, 1);
       int index = TextUtils.isEmpty(strSubstring) ? 0 : Integer.parseInt(strSubstring);
       return a[index] + str.substring(4, 12);
   }
   ```
   The prefix (8 bytes) is selected from static table `a`. Characters 4 through 11 (8 bytes) of the suffix form the second half, yielding an exact 16-byte ASCII AES key.
3. **Payload Structure:** The ciphertext and the unencrypted 15-character random suffix are concatenated: `ciphertext + suffix`.
4. **Decryption:** The server encrypts its response in the same format. The client extracts the last 15 characters, reconstructs the identical AES key via `c()`, and decrypts the preceding ciphertext using AES/ECB/PKCS5Padding.

---

## 3. Token Delivery & Lower-Level Partition Persistence

### 3.1 Approval Response Parsing (`com.coloros.deeptesting.service.c` & `d`)
When `checkApproveResult` (`1001`) returns status code `0`, the decrypted response contains:
```json
{
  "resultCode": 0,
  "msg": "success",
  "data": {
    "unlockCode": "4A1F...[544 hex characters]...",
    "lkLockStatus": 1
  }
}
```
The `unlockCode` field is a 544-character hexadecimal string representing 272 raw binary bytes.

### 3.2 Token Hex Decoding & Handoff (`com.coloros.deeptesting.a.h`)
In `h.java` (lines 214–235), `a(String str)` parses the hex string into raw bytes and passes it to the system framework via reflection:
```java
public static boolean a(String str) {
    byte[] bArr = new byte[str.length() / 2];
    for (int i = 0; i < bArr.length; i++) {
        bArr[i] = (byte) Integer.parseInt(str.substring(i * 2, (i * 2) + 2), 16);
    }
    return ((Boolean) Class.forName("android.engineer.OppoEngineerManager")
        .getMethod("fastbootUnlock", byte[].class, Integer.TYPE)
        .invoke(null, bArr, Integer.valueOf(bArr.length))).booleanValue();
}
```

### 3.3 System Framework Routing (`OppoEngineerService`)
Inspection of `system/framework/oat/arm64/services.vdex` reveals that `OppoEngineerManager.fastbootUnlock` sends an IPC call to `com.android.server.engineer.OppoEngineerService`. The service converts the token write into a HIDL call:
`vendor.oppo.engnative.engineer@1.0::IEngineer.saveEngineerData(offset, length, data)`.

### 3.4 Hardware Abstraction Layer Disassembly (`vendor.oppo.engnative.engineer@1.0-service`)
Disassembly of the 64-bit ELF binary `/vendor/bin/hw/vendor.oppo.engnative.engineer@1.0-service` pinpoints the exact low-level persistence routine:

1. **Virtual Function `0x9C60` (`saveEngineerData`):**
   - Receives buffer pointer `x25` and requested size `w20`.
   - Validates size bounds: `add w8, w20, w21; cmp w8, #0x3ff; b.hi #0x9cb4` (enforces max size < 1024 bytes).
   - Computes base address:
     ```arm64
     0x9e28: mov  w8, #0x800
     0x9e2c: adrp x0, #0xe000
     0x9e30: movk w8, #0xf0, lsl #16   ; w8 = 0x00F00800
     0x9e34: add  x0, x0, #0x3d0       ; x0 -> "/dev/block/platform/bootdevice/by-name/reserve4"
     0x9e38: add  w1, w8, w21          ; w1 = 0x00F00800 + offset (0x2400) = 0x00F02C00
     0x9e3c: mov  x2, x22              ; x2 -> data buffer
     0x9e40: mov  w3, w20              ; w3 -> byte count (272)
     0x9e44: bl   #0x5258              ; call raw block write function
     ```
2. **Raw Block Write Routine (`0x5258`):**
   - Calls `open("/dev/block/platform/bootdevice/by-name/reserve4", O_WRONLY)`.
   - Calls `lseek(fd, 0x00F02C00, SEEK_SET)`.
   - Calls `write(fd, buffer, 272)`.
   - Calls `close(fd)`.

Physical block calculation:
$$\text{Sector} = \frac{0x00F02C00}{512} = \frac{15740416}{512} = 30742 = \mathbf{0x7816}$$
This proves conclusively that `OppoEngineerManager.fastbootUnlock` writes the token directly to **sector `0x7816` of `reserve4`**.

---

## 4. Bootloader Gating & Cryptographic Verification Reconciliation

### 4.1 OEM Unlock Flag & Bootloader Reboot
Immediately following the token write in `StatusActivity.java` (handled in `g.java:25-33`):
```java
// 1. Enable OEM unlock in persistent_data_block (FRP partition)
((PersistentDataBlockManager) this.a.getSystemService("persistent_data_block")).setOemUnlockEnabled(true);

// 2. Issue shell command to reboot into bootloader
com.coloros.deeptesting.a.h.c(); // Executes Runtime.getRuntime().exec("reboot bootloader")
```

### 4.2 Little Kernel Verification Protocol (`lk.img` / ART-012)
Upon rebooting into Little Kernel:
1. `fastboot_init()` begins at `0x60030018`.
2. Before enumerating the Fastboot USB interface or registering commands, it invokes `verify_unlock_token()` at `0x6002EB00`.
3. `verify_unlock_token()` reads 8 sectors (4,096 bytes) starting at offset `0x16` via `read_reserve4()`.
4. `read_reserve4()` internally adds base sector `0x7800`:
   $$0x7800 + 0x16 = \mathbf{0x7816}$$
   matching byte-for-byte the persistence address programmed by `vendor.oppo.engnative.engineer@1.0-service`!
5. **Token Verification Steps:**
   - **Serial Check:** Compares the 16 ASCII characters at token offset `+0x100` against the hardware serial number extracted from MT6771 eFUSE via `devinfo_get_data()`. If they do not match, it logs `"the serial is not match\n\n"` and aborts.
   - **Signature Verification:** Computes SHA-256 over the 16-byte hardware serial number. It passes the 256-byte signature at `+0x000` to the RSA verifier at `0x600567C0`.
   - **Algorithm:** Verified against the OEM RSA-2048 public key modulus at `0x6007EE48` using **RSASSA-PSS SHA-256** (MGF1-SHA256, salt length 32, trailer field `0xBC`).
6. **Execution Branches:**
   - **Valid Token:** Logs `"fastboot_unlock_verify ok\n\n"`, initializes USB, and registers Fastboot command handlers (`flashing unlock`, `flashing lock`).
   - **Invalid / Missing Token:** Logs `"fastboot_unlock_verify fail\n\n"`. Immediately programs the MT6771 Watchdog Timer register (`0x10007000 = 0x1971`) via `mtk_arch_reset(1)`, forcing a hardware reboot.

### 4.3 Test Exit / Invalidation Mechanism
When the user cancels an application or chooses "Apply to exit in-depth test" in `MainActivity.java`:
- It calls `h.b()`:
  ```java
  public static boolean b() {
      return ((Boolean) Class.forName("android.engineer.OppoEngineerManager")
          .getMethod("fastbootUnlock", byte[].class, Integer.TYPE)
          .invoke(null, new byte[]{0}, 1)).booleanValue();
  }
  ```
- This writes a single `0x00` byte to sector `0x7816`.
- On subsequent boots, `verify_unlock_token()` encounters an invalid signature byte, fails verification, and instantly triggers a watchdog reboot, effectively relocking the Fastboot interface.

---

## 5. Architectural Findings & Unbypassable Constraints

### 5.1 Hardcoded Model Prefix Guard in Decompiled APK
In `StatusActivity.java` (line 26), `i.java` (line 18), and `g.java` (line 22), the decompiled APK enforces an explicit device model filter:
```java
if (!com.coloros.deeptesting.a.h.c(this) || !com.coloros.deeptesting.a.h.a().startsWith("RMX")) {
    finish();
}
```
- `h.c(this)` checks `context.getPackageManager().hasSystemFeature("oppo.version.exp")` (requires Export/Global ColorOS ROM).
- `h.a()` evaluates `ro.product.name` (fallback `ro.product.model`).
- On the Realme 1 (CPH1859 / CPH1861), the product name is `CPH1859`, **not** `RMX...` (the `RMX` naming scheme was introduced with the Realme 2 Pro / Realme 3).
- **Consequence:** This specific version of the DeepTesting APK (v1.0.1) immediately exits on a factory Realme 1 without presenting the unlock interface.

### 5.2 Decommissioning Deadlock
Even if the APK's model filter were patched:
1. The application requires an active server response from `https://lkf.realmemobile.com/realme/v1/checkApproveResult`.
2. The server must provide a 256-byte RSASSA-PSS signature generated by the vendor's private 2048-bit RSA key corresponding to public modulus `0x6007EE48`.
3. Because RSA-2048 cannot be broken offline and the server backend has been decommissioned, no valid token can be synthesized.
4. Because Little Kernel aborts and reboots via hardware watchdog before enumerating USB Fastboot if the token in `reserve4` is invalid, standard Fastboot commands cannot be reached.

### 5.3 Physical Testpoint Necessity Explained
The community guide `/home/ameya/Realme1/BOOTLOADER_FIX_V1.0.docx` details the only reproducible unlock path:
- Grounding hardware testpoints behind the motherboard RF shield while connecting USB.
- **Architectural Reason:** Grounding forces the MT6771 BootROM into emergency USB download mode (`0e8d:0003`) before the on-chip preloader or Little Kernel executes.
- This bypasses `verify_unlock_token()` entirely, allowing `mtkclient` to exploit the BootROM USB stack (kamakiri / SLA bypass), flash an unlocked `seccfg` partition, and flash a modified Little Kernel image (`lk1`/`lk2`) that patches out the `verify_unlock_token()` gate.

---

## 6. End-to-End Traceability Matrix

| Stage | Responsible Component | Implementation Evidence | File Offset / Address |
|---|---|---|---|
| User Request | `com.coloros.deeptesting.activity.ApplyActivity` | `ApplyActivity.java:21` | Source lines 20–25 |
| Server Query | `com.coloros.deeptesting.service.RequestService` | `RequestService.java:55` | `https://lkf.realmemobile.com` |
| Envelope Encryption | `com.coloros.deeptesting.a.a` | `AesEncryptUtils.java:31` | AES/ECB/PKCS5Padding |
| Token Delivery | `com.coloros.deeptesting.service.c/d` | `d.java:8` | `unlockCode` hex string |
| Hex Conversion | `com.coloros.deeptesting.a.h` | `h.java:220` | `bArr = new byte[str.length() / 2]` |
| IPC Dispatch | `android.engineer.OppoEngineerManager` | `h.java:229` / `boot-framework.vdex` | Method `fastbootUnlock(byte[], int)` |
| HAL Invocation | `com.android.server.engineer.OppoEngineerService` | `services.vdex` | `IEngineer.saveEngineerData()` |
| Native Partition Write | `vendor.oppo.engnative.engineer@1.0-service` | `0x9C60` $\rightarrow$ `0x5258` | Writes 272 bytes to `/dev/block/.../reserve4` |
| Target Coordinate | eMMC Storage Partition `reserve4` | `0x9E38` in native daemon | `0x00F02C00` (Sector `0x7816`) |
| FRP State Change | `android.service.persistentdata.PersistentDataBlockManager` | `g.java:27` | `setOemUnlockEnabled(true)` |
| System Reboot | Android Runtime Shell | `h.java:131` | `exec("reboot bootloader")` |
| Boot Verification Gate | Little Kernel (`lk.img`) | `fastboot_init()` | `0x60030046: bl #0x6002eb00` |
| Storage Reading | Little Kernel (`lk.img`) | `verify_unlock_token()` | `0x6002EC24: bl #0x6002c794` (sector `0x7816`) |
| Hardware Binding | Little Kernel (`lk.img`) | `verify_unlock_token()` | `0x6002EBC6: bl #0x60003c4c` (`devinfo_get_data`) |
| Cryptographic Verification | Little Kernel (`lk.img`) | `0x600567C0` | RSASSA-PSS SHA-256 against OEM key `0x6007EE48` |
| Watchdog Reboot (on failure) | Little Kernel (`lk.img`) | `fastboot_init()` | `0x6003005C: bl #0x6000cd30` (`mtk_arch_reset(1)`) |
| USB Enumeration (on success) | Little Kernel (`lk.img`) | `fastboot_init()` | `0x60030060`: registers `flashing unlock` |
