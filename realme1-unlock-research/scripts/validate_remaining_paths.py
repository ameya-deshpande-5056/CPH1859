#!/usr/bin/env python3
"""Read-only checks for the remaining LK/preloader audit.

This intentionally does not emulate USB, talk to a device, or modify any
firmware.  It records only reproducible offsets, hashes, direct Thumb call
sites, and conservative string-reference checks.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from capstone.arm import (
    ARM_INS_ADD,
    ARM_INS_B,
    ARM_INS_BL,
    ARM_INS_BLX,
    ARM_INS_LDR,
    ARM_INS_LDRB,
    ARM_INS_LDRH,
    ARM_INS_LDRSB,
    ARM_INS_LDRSH,
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
    ARM_REG_PC,
)


ROOT = Path("/home/ameya/Realme1")
C49_PRELOADER = ROOT / "C49_extracted/preloader_oppo6771_17065.bin"
C49_LK = ROOT / "C49_extracted/lk.img"

PRELOADER_BASE = 0x00200F10
PRELOADER_CODE_END = 0x325A4

STRINGS = {
    "usbdl_vfy_da": "usbdl_vfy_da:disabled",
    "usbdl_send_da": "%s usbdl_send_da: clean invalid da",
    "usbdl_jump_da": "%s usbdl_jump_da: %x",
    "bldr_handshake": "bldr_handshake",
    "s_chip": "[%s] S-CHIP",
    "ns_chip": "[%s] NS-CHIP",
    "cert_chain": "[%s] cert chain vfy fail...",
    "br_disabled": "[%s] BR cmd is disabled",
    "trigger_brom": "Preloader going reset and trigger BROM usb auto detectiton!!",
    "force_brom": "[%s] Force brom download recovery success",
    "lock_state": "[SEC_POLICY] lock_state = 0x%x",
    "sbc_en": "sbc_en = %d",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def string_offsets(data: bytes) -> dict[str, int]:
    result: dict[str, int] = {}
    for name, value in STRINGS.items():
        result[name] = data.find(value.encode("ascii"))
    return result


def direct_transfers(data: bytes, base: int, target: int, end: int) -> list[int]:
    """Return raw file offsets of direct B/BL/BLX sites to target."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    sites: list[int] = []
    for off in range(0x100, end, 2):
        ins = next(md.disasm(data[off : off + 8], base + off, count=1), None)
        if not ins or ins.id not in (ARM_INS_B, ARM_INS_BL, ARM_INS_BLX):
            continue
        if not ins.operands or ins.operands[0].type != ARM_OP_IMM:
            continue
        if (ins.operands[0].imm & ~1) == target:
            sites.append(off)
    return sites


def direct_pointer_occurrences(data: bytes, address: int) -> list[int]:
    needle = address.to_bytes(4, "little")
    result: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return result
        result.append(offset)
        start = offset + 1


def conservative_pc_string_refs(data: bytes, base: int, end: int) -> dict[str, int]:
    """Count direct literal-pointer and ldr+add-pc string references.

    This is deliberately conservative.  A zero count does not rule out an
    address formed through a table, arithmetic, or an indirect call.
    """
    offsets = string_offsets(data)
    targets = {base + off: name for name, off in offsets.items() if off >= 0}
    counts = {name: 0 for name in offsets}
    for address in targets:
        counts[targets[address]] += len(direct_pointer_occurrences(data, address))

    load_ids = {
        ARM_INS_LDR,
        ARM_INS_LDRB,
        ARM_INS_LDRH,
        ARM_INS_LDRSB,
        ARM_INS_LDRSH,
    }
    for mode, step in ((CS_MODE_THUMB, 2), (CS_MODE_ARM, 4)):
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True
        instructions = {}
        for off in range(0x100, end, step):
            ins = next(md.disasm(data[off : off + 8], base + off, count=1), None)
            if ins and ins.size in (2, 4):
                instructions[off] = ins

        for off, ins in instructions.items():
            if ins.id not in load_ids or len(ins.operands) < 2:
                continue
            dst, memory = ins.operands[0], ins.operands[1]
            if dst.type != ARM_OP_REG or memory.type != ARM_OP_MEM:
                continue
            if memory.mem.base != ARM_REG_PC:
                continue
            pc = ((ins.address + 4) & ~3) if mode == CS_MODE_THUMB else ins.address + 8
            literal = pc + memory.mem.disp
            if not (base <= literal <= base + len(data) - 4):
                continue
            value = int.from_bytes(data[literal - base : literal - base + 4], "little")
            if value in targets:
                counts[targets[value]] += 1
            for delta in range(ins.size, 20, step):
                following = instructions.get(off + delta)
                if not following or following.id != ARM_INS_ADD:
                    continue
                ops = following.operands
                if len(ops) < 3 or not all(op.type == ARM_OP_REG for op in ops[:3]):
                    continue
                if not (ops[0].reg == dst.reg and ops[1].reg == dst.reg and ops[2].reg == ARM_REG_PC):
                    continue
                following_pc = following.address + 4 if mode == CS_MODE_THUMB else following.address + 8
                effective = (value + following_pc) & 0xFFFFFFFF
                if effective in targets:
                    counts[targets[effective]] += 1
    return counts


def main() -> None:
    preloader = C49_PRELOADER.read_bytes()
    lk = C49_LK.read_bytes()
    reset_targets = {
        "wdt_key_10007008": PRELOADER_BASE + 0x2AE34,
        "wdt_brom_or_reset": PRELOADER_BASE + 0x2AE44,
        "reset_mode_wrapper": PRELOADER_BASE + 0x2AEF0,
    }
    calls = {
        name: direct_transfers(preloader, PRELOADER_BASE, target, PRELOADER_CODE_END)
        for name, target in reset_targets.items()
    }
    report = {
        "lk_sha256": sha256(C49_LK),
        "preloader_sha256": sha256(C49_PRELOADER),
        "preloader_string_offsets": {k: hex(v) for k, v in string_offsets(preloader).items()},
        "preloader_string_reference_scan": conservative_pc_string_refs(
            preloader, PRELOADER_BASE, PRELOADER_CODE_END
        ),
        "direct_thumb_reset_call_sites": {
            name: [hex(site) for site in sites] for name, sites in calls.items()
        },
        "notes": [
            "String offsets are data anchors, not function entry points.",
            "The string-reference scan does not resolve table-based or indirect dispatch.",
            "No device I/O or firmware write is performed.",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
