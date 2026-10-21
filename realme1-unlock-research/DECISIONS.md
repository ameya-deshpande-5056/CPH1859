# Decisions Record: Realme 1 (CPH1859) Bootloader Unlock Research

## Architectural & Research Decisions

### DEC-001: Strict Adherence to Non-Invasive Software-Only Constraints
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** Hardware disassembly and testpoint shorting are commonly suggested in repair forums for MediaTek Helio P60 unbricking and BootROM forcing.
- **Decision:** All research, testing, and diagnostic tools must strictly operate over standard USB (ADB, Fastboot, standard USB device enumeration). Hardware testpoints, motherboard modification, battery disconnection, and paid servicing boxes (e.g. Chimera, UnlockTool) are explicitly rejected.
- **Reason:** The user's research objective specifically mandates software-only investigation without physical alteration or commercial service boxes.
- **Alternatives Rejected:** Hardware testpoint shorting (grounding pin on motherboard), opening back cover, testpoint cables.

---

### DEC-002: Mandatory Identifier Redaction Across All Tools & Artifacts
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** The device serial number and potentially sensitive hardware identifiers (IMEI, MAC, etc.) are exposed via ADB and fastboot.
- **Decision:** Built-in sanitization and redaction engines must run across all diagnostic collectors, loggers, and artifact exporters. The unique serial number will be dynamically detected and replaced with `[REDACTED_SERIAL]`.
- **Reason:** Privacy protection, security best practices, and explicit project mandate prohibiting committing serial numbers to version control or public reports.
- **Alternatives Rejected:** Manual log editing (prone to human error and leaks).

---

### DEC-003: Read-Only Diagnostic Architecture
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** Building diagnostic tools that interface with Android platform tools.
- **Decision:** The diagnostic CLI must never execute commands that modify system state, flash partitions (`fastboot flash`, `dd`, `fastboot flashing unlock`), wipe data, or trigger unverified exploit payloads.
- **Reason:** Zero-risk guarantee against bricking, data loss, or bootloader state corruption.
- **Alternatives Rejected:** Automated exploit execution or brute-forcing fastboot arguments.

---

### DEC-004: Dual-Location State Accessibility
- **Date:** 2026-10-21
- **Status:** APPROVED
- **Context:** The workspace root is `/home/ameya/CPH1859`, while the specified project name is `realme1-unlock-research`.
- **Decision:** Place authoritative files in `realme1-unlock-research/` and create symbolic links at `/home/ameya/CPH1859/` pointing into `realme1-unlock-research/`.
- **Reason:** Ensures any resuming agent or user inspecting either the workspace root or the project subfolder immediately finds all project state files.
- **Alternatives Rejected:** Keeping files solely in one location without symlinks.

---

### DEC-005: Conclusion on Software-Only Unlock Feasibility for CPH1859EX_11_C.50
- **Date:** 2026-10-21
- **Status:** SUPERSEDED BY DEC-006
- **Context:** Initial evaluation based on preliminary diagnostic scan and literature review.
- **Decision:** Initial report declared unlocking impossible.
- **Reason:** Superseded to remove unproven claims of mathematical impossibility.

---

### DEC-006: Epistemic Calibration & Formal Project Outcome Selection
- **Date:** 2026-10-21
- **Status:** APPROVED / CURRENT
- **Context:** Phase 2 evidence audit revealed that claims regarding exact C function names, token storage structures, and preloader crash error codes were inferred from secondary literature rather than locally disassembled binaries. Furthermore, local C.50 firmware images are unavailable on the host, and raw block access is restricted over ADB.
- **Decision:** 
  1. Calibrate all research findings using the 5-tier epistemic taxonomy (`directly observed`, `independently verified`, `source-reported`, `inferred`, `unsubstantiated`).
  2. Adopt the formal outcome: **`BLOCKED BY MISSING FIRMWARE OR ACCESS`** (with secondary finding `NO VIABLE ROUTE FOUND WITH CURRENT EVIDENCE`).
  3. Formally catalog the specific reverse-engineering analyses that remain blocked pending offline firmware acquisition.
- **Reason:** Adheres strictly to scientific integrity; a failed search or absent binary is not proof that no vulnerability exists.
- **Alternatives Rejected:** Declaring software unlock "mathematically impossible" (unsubstantiated certainty); fabricating simulated disassembly of unavailable images (scientific misconduct).
