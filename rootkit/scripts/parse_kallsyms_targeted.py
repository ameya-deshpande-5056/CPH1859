#!/usr/bin/env python3
"""Targeted kallsyms parser for CPH1859 C.50 kernel Image."""
import struct
import os
import sys

KERNEL_PATH = "/home/ameya/Realme1/CPH1859/rootkit/work/kernel_cph1859_c50.decompressed"

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

def main():
    with open(KERNEL_PATH, 'rb') as f:
        data = f.read()

    size = len(data)
    ADDRS_OFF = 0x00eafb90
    ADDRS_COUNT = 28464

    print(f"kallsyms_addresses at 0x{ADDRS_OFF:08x}, {ADDRS_COUNT} entries")

    addresses = []
    for i in range(ADDRS_COUNT):
        off = ADDRS_OFF + i * 8
        if off + 8 > size:
            break
        addresses.append(read_u64(data, off))

    print(f"Read {len(addresses)} addresses")
    print(f"First: 0x{addresses[0]:016x}, Last: 0x{addresses[-1]:016x}")

    # Search for kallsyms_num_syms near the table
    print("\n=== Searching for kallsyms_num_syms ===")
    num_syms = 28464
    num_syms_hex = struct.pack('<I', num_syms)
    search_start = max(0, ADDRS_OFF - 0x20000)
    search_end = min(size - 4, ADDRS_OFF + ADDRS_COUNT * 8 + 0x20000)
    off = search_start
    count = 0
    while off < search_end and count < 10:
        if data[off:off+4] == num_syms_hex:
            print(f"  Found kallsyms_num_syms=28464 at 0x{off:08x}")
            count += 1
        off += 4

    if count == 0:
        print("  Not found exactly. Checking nearby values...")
        for candidate in [28463, 28465, 28460, 28470]:
            cand_hex = struct.pack('<I', candidate)
            off = search_start
            while off < search_end:
                if data[off:off+4] == cand_hex:
                    print(f"  Found {candidate} at 0x{off:08x}")
                    break
                off += 4

    # Check what comes after addresses table
    print("\n=== Data after addresses table ===")
    after_addrs = ADDRS_OFF + ADDRS_COUNT * 8
    print(f"  Addresses table ends at 0x{after_addrs:08x}")
    for i in range(after_addrs, min(after_addrs + 128, size), 16):
        chunk = data[i:i+16]
        marker_like = sum(1 for b in chunk if b <= 7)
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        if marker_like >= 10:
            print(f"  0x{i:08x}: {hex_str} (marker-like: {marker_like}/16)")

    # Sample addresses
    print("\n=== Sample addresses from table ===")
    for i in [0, 1, 2, 100, 1000, 5000, 10000, 20000, 28463]:
        if i < len(addresses):
            print(f"  [{i:5d}] 0x{addresses[i]:016x}")

if __name__ == '__main__':
    main()
