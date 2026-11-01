#!/usr/bin/env python3
"""Disassemble kallsyms_lookup_name to find references to kallsyms data structures."""
from capstone import *
from capstone.arm64 import *

KERNEL_PATH = "/home/ameya/Realme1/CPH1859/rootkit/work/kernel_cph1859_c50.decompressed"

# kallsyms_lookup_name at file offset 0x11d4407
KS_LOOKUP_OFF = 0x11d4407

def main():
    with open(KERNEL_PATH, 'rb') as f:
        data = f.read()

    # We need to know the VA of kallsyms_lookup_name to interpret PC-relative refs
    # Let's try to find it in the addresses table
    # From our earlier scan, kallsyms_addresses is at 0x00eafb90 with 28464 entries
    # But we don't know the VA mapping yet
    
    # Let's just disassemble the raw code and look for ADRP instructions
    # ADRP: 0x90000000 | (immhi << 5) | (immlo << 29) | (rd << 0)
    # But without knowing the VA, we can't compute the target
    
    # Alternative: just print the disassembly and look for patterns
    
    # Read ~512 bytes of code starting at kallsyms_lookup_name
    code_off = KS_LOOKUP_OFF
    code = data[code_off:code_off + 512]
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    
    print(f"Disassembling kallsyms_lookup_name at file offset 0x{KS_LOOKUP_OFF:08x}")
    print(f"Code size: {len(code)} bytes\n")
    
    for insn in md.disasm(code, 0):  # Use 0 as base since we don't know VA
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        # Look for ADRP (loads page address) and LDR/ADD that use its result
        if mnemonic == 'adrp':
            print(f"  0x{insn.address:04x}: {mnemonic} {op_str}  <-- page-relative reference")
        elif mnemonic in ('ldr', 'add', 'sub') and any(x in op_str for x in ['#, ', '#0x']):
            print(f"  0x{insn.address:04x}: {mnemonic} {op_str}")
        elif mnemonic == 'adr':
            print(f"  0x{insn.address:04x}: {mnemonic} {op_str}  <-- PC-relative reference")
        elif mnemonic == 'bl':
            print(f"  0x{insn.address:04x}: {mnemonic} {op_str}  <-- function call")

if __name__ == '__main__':
    main()
