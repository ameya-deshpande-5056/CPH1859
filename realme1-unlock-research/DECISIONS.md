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
- **Status:** APPROVED / FORMAL CONCLUSION
- **Context:** Feasibility evaluation based on live diagnostics and empirical findings from tasks R001-R004.
- **Decision:** Conclude that a software-only bootloader unlock is not possible on build `CPH1859EX_11_C.50`. Discontinue ungrounded software exploit attempts.
- **Reason:** 
  1. LK actively enforces cryptographic serial token verification for Fastboot entry, resulting in `the serial is not match / fastboot_unlock_verity fail`.
  2. The official DeepTesting authorization backend has been permanently decommissioned.
  3. MediaTek preloader on C.50 patches USB crash vectors, preventing software-triggered BROM mode.
  4. Entering BROM requires hardware testpoint grounding, which is excluded by the project constraints.
- **Alternatives Rejected:** Recommending hardware disassembly (violates user constraints); fabricating speculative software bypasses (violates technical integrity).
