# Realme 1 (CPH1859) Diagnostic & Bootloader Posture Report

> [!NOTE]
> Generated on: 2026-10-21T10:22:25.469766+05:30  
> Tool Version: 0.1.0  
> Host OS: Linux (x86_64)  
> Safety Guarantee: Strictly Read-Only (Non-Invasive) — Zero Partition Writes / Erases

## Executive Summary

| Test ID | Test Name | Status | Summary |
|---|---|---|---|
| `TEST_001_ENV` | Host Environment & Platform Tools Check | **PASSED** | Host environment verified; ADB and Fastboot are installed. |
| `TEST_002_USB` | USB Bus & Vendor/Product ID Enumeration | **PASSED** | Detected 8 USB devices. Matched targets: OPPO / Realme Android Normal Mode (CPH1859). |
| `TEST_003_ADB` | ADB Connectivity & Interface State | **PASSED** | Target device identified via ADB in authorized 'device' mode. |
| `TEST_004_PROPS` | Android Build & Verified Boot Properties | **PASSED** | Collected 867 properties. Confirmed SoC: mt6771, Build: CPH1859EX_11_C.50. |
| `TEST_005_FASTBOOT` | Fastboot Bus Status Check | *INCONCLUSIVE* | No devices currently in Fastboot mode (expected during normal OS operation). |
| `TEST_006_PACKAGES` | Deep Testing & Unlock Package Inspection | **PASSED** | Audit complete. DeepTesting application is NOT INSTALLED. |
| `TEST_007_POSTURE` | Security & Bootloader Posture Assessment | **PASSED** | Bootloader is LOCKED. OEM Unlocking toggle is ENABLED (allowed). |

---

## Security & Bootloader Posture Analysis

| Property | Value | Interpretation |
|---|---|---|
| `ro.boot.flash.locked` | `1` | Device bootloader partition lock state (1 = locked). |
| `ro.oem_unlock_supported` | `1` | Android platform OEM unlock toggle support. |
| `sys.oem_unlock_allowed` | `1` | User toggle in Developer Options (1 = allowed). |
| `ro.boot.verifiedbootstate` | `green` | AVB State (green = locked official OEM boot image). |
| `ro.boot.veritymode` | `enforcing` | dm-verity enforcement policy (enforcing). |
| `ro.board.platform` | `mt6771` | MediaTek Helio P60 platform code (`mt6771`). |
| `ro.build.display.id` | `CPH1859EX_11_C.50` | ColorOS firmware release identifier. |

---

## Detailed Test Audits & Commands Executed

### TEST_001_ENV: Host Environment & Platform Tools Check
- **Status:** `PASSED`
- **Summary:** Host environment verified; ADB and Fastboot are installed.

**Audited Commands & Preserved Outputs:**

*No shell commands executed for this test.*

### TEST_002_USB: USB Bus & Vendor/Product ID Enumeration
- **Status:** `PASSED`
- **Summary:** Detected 8 USB devices. Matched targets: OPPO / Realme Android Normal Mode (CPH1859).

**Audited Commands & Preserved Outputs:**

- Command: `lsusb`
  - Start Time: `2026-10-21T10:22:25.488593+05:30`
  - Duration: `0.0062s`
  - Exit Code: `0`
  - Safe Guard: `APPROVED`

```text
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 001 Device 002: ID 04f2:b760 Chicony Electronics Co., Ltd HP Wide Vision HD Camera
Bus 001 Device 003: ID 0bda:b85c Realtek Semiconductor Corp. Bluetooth Radio
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 003 Device 002: ID 04f3:0c00 Elan Microelectronics Corp. ELAN:ARM-M4
Bus 003 Device 008: ID 22d9:2769 OPPO Electronics Corp. CPH1859
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
```

### TEST_003_ADB: ADB Connectivity & Interface State
- **Status:** `PASSED`
- **Summary:** Target device identified via ADB in authorized 'device' mode.

**Audited Commands & Preserved Outputs:**

- Command: `adb devices -l`
  - Start Time: `2026-10-21T10:22:25.494951+05:30`
  - Duration: `0.0028s`
  - Exit Code: `0`
  - Safe Guard: `APPROVED`

```text
List of devices attached
[REDACTED_SERIAL]       device 3-2 product:CPH1859 model:CPH1859 device:CPH1859 transport_id:2
```

### TEST_004_PROPS: Android Build & Verified Boot Properties
- **Status:** `PASSED`
- **Summary:** Collected 867 properties. Confirmed SoC: mt6771, Build: CPH1859EX_11_C.50.

**Audited Commands & Preserved Outputs:**

- Command: `adb shell getprop`
  - Start Time: `2026-10-21T10:22:25.497802+05:30`
  - Duration: `0.0433s`
  - Exit Code: `0`
  - Safe Guard: `APPROVED`

```text
[ro.product.model]: [CPH1859]
[ro.product.name]: [CPH1859]
[ro.product.device]: [CPH1859]
[ro.product.brand]: [OPPO]
[ro.product.manufacturer]: [OPPO]
[ro.build.version.release]: [9]
[ro.build.version.sdk]: [28]
[ro.build.version.security_patch]: [2020-09-05]
[ro.build.display.id]: [CPH1859EX_11_C.50]
[ro.build.fingerprint]: [OPPO/CPH1859/CPH1859:9/PPR1.180610.011/1601287606:user/release-keys]
[ro.build.date]: [Fri Oct 16 23:28:18 CST 2020]
[ro.build.date.utc]: [1602862098]
[ro.build.type]: [user]
[ro.boot.hardware]: [mt6771]
[ro.boot.bootloader]: [NOT_FOUND]
[ro.bootloader]: [unknown]
[ro.bootmode]: [normal]
[ro.boot.mode]: [normal]
[ro.boot.flash.locked]: [1]
[ro.oem_unlock_supported]: [1]
[sys.oem_unlock_allowed]: [1]
[ro.boot.verifiedbootstate]: [green]
[ro.boot.veritymode]: [enforcing]
[ro.boot.vbmeta.device_state]: [NOT_FOUND]
[ro.boot.serialno]: [[REDACTED_SERIAL]]
[ro.serialno]: [[REDACTED_SERIAL]]
[ro.board.platform]: [mt6771]
[ro.mediatek.version.release]: [CPH1859_11_C.50_201016]
[ro.mediatek.platform]: [MT6771]
[ro.crypto.state]: [encrypted]
[ro.crypto.type]: [block]
```

### TEST_005_FASTBOOT: Fastboot Bus Status Check
- **Status:** `INCONCLUSIVE`
- **Summary:** No devices currently in Fastboot mode (expected during normal OS operation).

**Audited Commands & Preserved Outputs:**

- Command: `fastboot devices`
  - Start Time: `2026-10-21T10:22:25.542221+05:30`
  - Duration: `0.2868s`
  - Exit Code: `0`
  - Safe Guard: `APPROVED`

### TEST_006_PACKAGES: Deep Testing & Unlock Package Inspection
- **Status:** `PASSED`
- **Summary:** Audit complete. DeepTesting application is NOT INSTALLED.

**Audited Commands & Preserved Outputs:**

- Command: `adb shell pm list packages`
  - Start Time: `2026-10-21T10:22:25.829155+05:30`
  - Duration: `0.1002s`
  - Exit Code: `0`
  - Safe Guard: `APPROVED`

```text
mediatek: ['com.mediatek.gba', 'com.mediatek.ims', 'com.mediatek.location.lppe.main', 'com.mediatek.providers.drm', 'com.mediatek', 'com.mediatek.nlpservice', 'com.mediatek.location.mtknlp']
coloros: ['com.coloros.backuprestore', 'com.coloros.phonenoareainquire', 'com.coloros.wirelesssettings', 'com.coloros.gamespace', 'com.coloros.simsettings', 'com.coloros.healthcheck', 'com.coloros.weather.service', 'com.coloros.providers.downloads.ui', 'com.coloros.athena', 'com.coloros.blacklistapp', 'com.coloros.blacklist', 'com.coloros.wifibackuprestore', 'com.coloros.oshare', 'com.coloros.gesture', 'com.coloros.bootreg', 'com.coloros.screenrecorder', 'com.coloros.oppoguardelf', 'com.coloros.assistantscreen', 'com.coloros.activation', 'com.coloros.notificationmanager', 'com.coloros.smartdrive', 'com.coloros.translate.engine', 'com.coloros.compass', 'com.coloros.backuprestore.remoteservice', 'com.coloros.recents', 'com.coloros.wallpapers', 'com.coloros.mcs', 'com.coloros.sau', 'com.coloros.encryption', 'com.coloros.weather', 'com.coloros.usbselection', 'com.coloros.colorfilestand', 'com.coloros.pictorial', 'com.coloros.widget.smallweather', 'com.coloros.flashlight', 'com.coloros.sceneservice', 'com.coloros.alarmclock', 'com.coloros.phonemanager', 'com.coloros.securepay', 'com.coloros.sauhelper', 'com.coloros.safecenter', 'com.coloros.exserviceui', 'com.coloros.screenshot', 'com.coloros.cloud', 'com.coloros.video', 'com.coloros.filemanager', 'com.coloros.oppomultiapp', 'com.coloros.ocrscanner', 'com.coloros.soundrecorder', 'com.coloros.ocrservice', 'com.coloros.providers.fileinfo', 'com.coloros.floatassistant', 'com.coloros.childrenspace', 'com.coloros.gallery3d', 'com.coloros.appmanager', 'com.coloros.securitypermission']
```

### TEST_007_POSTURE: Security & Bootloader Posture Assessment
- **Status:** `PASSED`
- **Summary:** Bootloader is LOCKED. OEM Unlocking toggle is ENABLED (allowed).

**Audited Commands & Preserved Outputs:**

*No shell commands executed for this test.*
