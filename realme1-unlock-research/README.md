# Realme 1 (CPH1859) Diagnostic & Unlock Research Tool

A lightweight, strictly read-only Python 3 CLI tool designed for Linux Mint to inspect device state, Android system properties, verified boot posture, and USB interfaces of the Realme 1 (CPH1859, MediaTek MT6771 / Helio P60) running ColorOS.

## Safety Policy & Guarantees

> [!IMPORTANT]
> **Strict Read-Only Enforcement:**
> - Never executes flash (`fastboot flash`, `flashing`), erase (`fastboot erase`), format, partition-write (`dd`), or unlock commands.
> - An internal security engine inspects all attempted subprocess executions and raises `CommandSecurityViolation` if any dangerous keyword or argument is supplied.
> - Zero hardware disassembly or testpoint shorting required.

## Key Features

1. **ADB Device Identification:** Enumerates attached Android devices and checks connection states.
2. **Build & Boot Properties Extraction:** Queries `getprop` and analyzes `ro.boot.*`, `ro.build.*`, verified boot state (`green`/`orange`), verity mode (`enforcing`), and OEM unlock permissions (`sys.oem_unlock_allowed`, `ro.oem_unlock_supported`).
3. **Fastboot Bus Interrogation:** Safely checks `fastboot devices` visibility.
4. **USB Subsystem & MediaTek Profiler:** Scans `lsusb` for vendor/product IDs (`22d9:2769` normal Oppo, `0e8d:0003` MTK BootROM, `0e8d:2000` MTK Preloader, `18d1:4ee7` fastboot).
5. **In-Depth Test Package Audit:** Inspects package manager for DeepTesting or OEM test packages.
6. **Automatic Identifier Redaction:** Automatically registers device serial numbers and applies regex filters across all reports to redact serials (`[REDACTED_SERIAL]`), IMEIs (`[REDACTED_IMEI]`), and MACs (`[REDACTED_MAC]`).
7. **Report Exporters:** Generates comprehensive, audit-logged reports in Markdown and structured JSON.

## Setup Instructions

### Prerequisites
- Host OS: Linux Mint (or any standard Linux distribution).
- Python: Version 3.9+ (Python 3.13 recommended).
- Platform Tools: `adb` and `fastboot` installed (`sudo apt install android-tools-adb android-tools-fastboot`).

### Installation

No external third-party dependencies are required (built entirely on Python's standard library).

You can run directly using Python or install in editable mode:

```bash
cd realme1-unlock-research
pip install -e .
```

Or run directly without installation:

```bash
PYTHONPATH=src python3 -m realme1_unlock_research.cli --help
```

## Usage Examples

### 1. Generate Markdown Diagnostic Report to Stdout
```bash
python3 -m realme1_unlock_research.cli
```

### 2. Export Both Markdown and JSON Reports to Disk
```bash
python3 -m realme1_unlock_research.cli --format both --out artifacts/diagnostic_report
```

### 3. Run with Live USB Subsystem Monitoring
```bash
python3 -m realme1_unlock_research.cli --monitor-usb --duration 5.0
```

## Diagnostic Test Taxonomy

Every test executed by the tool is labeled with one of the following statuses:
- **`PASSED`**: The test executed successfully and expected diagnostic criteria were confirmed.
- **`FAILED`**: The test executed but encountered a failure condition or missing required tool.
- **`INCONCLUSIVE`**: The state could not be definitively asserted (e.g., fastboot not connected while running normal Android).
- **`NOT_SUPPORTED`**: The test could not be performed due to prerequisite unavailability (e.g. ADB offline).

## Limitations

- The tool does NOT modify bootloader state, generate cryptographic tokens, or bypass manufacturer verification.
- Offline device detection relies on USB bus enumeration (`lsusb`).
