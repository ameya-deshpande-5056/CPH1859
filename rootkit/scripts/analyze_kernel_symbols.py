#!/usr/bin/env python3
"""Analyze CPH1859 C.50 kernel Image for CVE-2026-43499 porting.
Extracts Image header info and searches for kallsyms data to find symbol addresses."""
import struct
import os
import sys

KERNEL_PATH = "/home/ameya/Realme1/CPH1859/rootkit/work/kernel_cph1859_c50.decompressed"

def read_u32(data, off):
    return struct.unpack('<I', data[off:off+4])[0]

def read_u64(data, off):
    return struct.unpack('<Q', data[off:off+8])[0]

def main():
    with open(KERNEL_PATH, 'rb') as f:
        data = f.read()

    print(f"Kernel Image size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

    # Parse ARM64 kernel Image header (first 64 bytes)
    hdr = data[:64]
    code0 = read_u64(hdr, 0x00)   # physical load address
    code1 = read_u64(hdr, 0x08)   # virtual load address
    text_offset = read_u64(hdr, 0x10)  # offset from start to kernel text
    image_size = read_u64(hdr, 0x18)   # effective image size
    flags = read_u64(hdr, 0x20)   # kernel flags
    magic = read_u64(hdr, 0x38)   # ARM64 magic

    print(f"\n--- ARM64 Kernel Image Header ---")
    print(f"  code0 (phys load addr): 0x{code0:016x}")
    print(f"  code1 (virt load addr): 0x{code1:016x}")
    print(f"  text_offset: 0x{text_offset:x} ({text_offset} bytes)")
    print(f"  image_size: 0x{image_size:x} ({image_size} bytes)")
    print(f"  flags: 0x{flags:x}")
    print(f"  magic: 0x{magic:016x} (expected 0x53616402 for ARM64)")

    # The kernel text starts at file offset text_offset
    # Virtual address of kernel text = code1 + (text_offset - 0) if code1 is start of image
    # Actually, for ARM64 Image: kernel is loaded at code1, text starts at code1 + text_offset
    kernel_text_vaddr = code1 + text_offset
    print(f"\n  Kernel text virtual addr: 0x{kernel_text_vaddr:016x}")
    print(f"  Kernel text file offset: 0x{text_offset:x}")

    # Calculate page offset and phys offset
    # For ARM64: PAGE_OFFSET is typically 0xffffff8000000000
    PAGE_OFFSET = 0xffffff8000000000
    phys_offset = code0 - 0x80000000  # rough estimate
    print(f"\n  Estimated PAGE_OFFSET: 0x{PAGE_OFFSET:016x}")

    # Convert file offsets to virtual addresses
    # For a raw Image: vaddr = code1 + (file_offset - text_offset) + text_offset
    # Simplified: vaddr = code1 + (file_offset - header_size)
    # But more accurately: vaddr = KERNEL_TEXT_BASE + (file_offset - text_offset)
    KERNEL_TEXT_BASE = kernel_text_vaddr

    print(f"\n--- Symbol File Offsets → Virtual Addresses ---")
    print(f"  KERNEL_TEXT_BASE = 0x{KERNEL_TEXT_BASE:016x}")
    print(f"  Formula: vaddr = 0x{KERNEL_TEXT_BASE:016x} + (file_offset - 0x{text_offset:x})")

    # Known symbol file offsets from strings search
    symbols = {
        'init_task': 0x11d092c,
        'commit_creds': 0x11d1d2d,
        'prepare_kernel_cred': 0x11d1d62,
        'override_creds': 0x11d1d46,
        'kmalloc_caches': 0x11d625a,
        'generic_file_llseek': 0x11d6a03,
        'noop_llseek': 0x11d6a29,
        '__kernel_write': 0x11d6a96,
        'fput': 0x11d6ae9,
        'fget': 0x11d7835,
        'generic_file_splice_read': 0x11d80f8,
        'kernel_write': 0x11d8126,
        'default_file_splice_read': 0x11d8133,
        'kallsyms_lookup_name': 0x11d4407,
        'kptr_restrict': 0xf9ca84,
        'configfs_read_file': 0xfb6f77,
        'init_uts_ns': 0x11d0912,
        'init_user_ns': 0x11d12a6,
    }

    for name, foff in symbols.items():
        vaddr = KERNEL_TEXT_BASE + (foff - text_offset)
        print(f"  {name:30s} file_off=0x{foff:08x}  vaddr=0x{vaddr:016x}")

    # Try to find kallsyms data structures
    print(f"\n--- Searching for kallsyms data ---")
    # kallsyms_num_syms is typically a u32 near kallsyms_lookup_name
    # Search for the kallsyms_addresses table (array of addresses)
    # Look for a region with many aligned addresses in the kernel range

    # Let's look for kallsyms_names symbol string
    # Search for "kallsyms_names" in the binary
    idx = data.find(b'kallsyms_names')
    if idx >= 0:
        print(f"  Found 'kallsyms_names' string at file offset 0x{idx:x}")
    else:
        print("  'kallsyms_names' string not found")

    idx = data.find(b'kallsyms_addresses')
    if idx >= 0:
        print(f"  Found 'kallsyms_addresses' string at file offset 0x{idx:x}")
    else:
        print("  'kallsyms_addresses' string not found")

    idx = data.find(b'kallsyms_markers')
    if idx >= 0:
        print(f"  Found 'kallsyms_markers' string at file offset 0x{idx:x}")
    else:
        print("  'kallsyms_markers' string not found")

    idx = data.find(b'kallsyms_token_table')
    if idx >= 0:
        print(f"  Found 'kallsyms_token_table' string at file offset 0x{idx:x}")
    else:
        print("  'kallsyms_token_table' string not found")

    idx = data.find(b'kallsyms_num_syms')
    if idx >= 0:
        print(f"  Found 'kallsyms_num_syms' string at file offset 0x{idx:x}")
    else:
        print("  'kallsyms_num_syms' string not found")

    # Check for compressed kallsyms (CONFIG_KALLSYMS=y but names in token table)
    # Look for the kallsyms_data section
    print(f"\n--- Checking for kallsyms compressed format ---")
    # In compressed kallsyms, symbol names are stored as tokens in kallsyms_token_table
    # Individual names like "remove_waiter" won't appear as plain strings
    # We need to parse the token table to reconstruct names

if __name__ == '__main__':
    main()
