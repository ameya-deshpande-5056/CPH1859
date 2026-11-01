#!/usr/bin/env python3
"""
Find kallsyms compressed data structures in CPH1859 kernel Image.
We have kallsyms_addresses (28464 entries at 0x00eafb90).
Need to find: kallsyms_markers, kallsyms_names, kallsyms_token_index, kallsyms_token_table.
"""
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

    print("=== Scanning for kallsyms_token_table ===")
    # Token table: region with many short null-terminated strings
    # Look for regions with high null byte density and short strings between them
    best_regions = []
    window = 256
    for start in range(0, size - window, 16):
        chunk = data[start:start+window]
        null_count = chunk.count(b'\x00')
        if null_count < 20:  # Need many nulls for token table
            continue
        # Check string lengths between nulls
        strings = []
        cur = 0
        for b in chunk:
            if b == 0:
                if 1 <= cur <= 32:  # Reasonable token length
                    strings.append(cur)
                cur = 0
            else:
                cur += 1
        if len(strings) >= 15 and sum(1 for s in strings if s <= 16) >= 10:
            # Good candidate: many short strings
            avg_len = sum(strings) / len(strings) if strings else 0
            score = len(strings) + (32 - avg_len)  # Prefer more, shorter strings
            best_regions.append((start, len(strings), avg_len, score))

    best_regions.sort(key=lambda x: -x[3])
    print(f"  Found {len(best_regions)} token-table-like regions")
    for start, n_strings, avg_len, score in best_regions[:10]:
        # Show sample strings
        chunk = data[start:start+window]
        strings = []
        cur = b''
        for b in chunk:
            if b == 0:
                if 1 <= len(cur) <= 32:
                    try:
                        s = cur.decode('ascii')
                        if s.isprintable():
                            strings.append(s)
                    except:
                        pass
                cur = b''
            else:
                cur += bytes([b])
        print(f"  0x{start:08x}: {n_strings} strings, avg_len={avg_len:.1f}, samples={strings[:8]}")

    print("\n=== Scanning for kallsyms_markers ===")
    # Markers: u8 array, values typically 0-7, length = num_syms (28464)
    # Look for a region of 28464 bytes where most values are small
    markers_candidates = []
    for start in range(0, size - 28464, 256):
        chunk = data[start:start+28464]
        small_count = sum(1 for b in chunk if b <= 7)
        if small_count > 28464 * 0.9:  # 90%+ small values
            markers_candidates.append((start, small_count))

    print(f"  Found {len(markers_candidates)} marker-array candidates")
    for start, count in markers_candidates[:10]:
        pct = count / 28464 * 100
        print(f"  0x{start:08x}: {count}/{28464} bytes <= 7 ({pct:.1f}%)")

    print("\n=== Scanning for kallsyms_names ===")
    # Names: u16 array, values are token indices (0 to num_tokens)
    # Token count might be a few hundred to a few thousand
    # Values should be small u16s, terminated by 0 per symbol
    print("  (Skipping - too many false positives without more constraints)")

    print("\n=== Checking region before kallsyms_addresses ===")
    # Maybe kallsyms_num_syms, markers, names are BEFORE the addresses table
    before_addrs = 0x00eafb90
    for i in range(max(0, before_addrs - 0x50000), before_addrs, 256):
        chunk = data[i:i+256]
        small_count = sum(1 for b in chunk if b <= 7)
        if small_count > 200:
            print(f"  0x{i:08x}: {small_count}/256 bytes <= 7 (potential markers)")

    print("\n=== Checking region after kallsyms_addresses ===")
    after_addrs = 0x00eafb90 + 28464 * 8  # 0x00ee7510
    for i in range(after_addrs, min(after_addrs + 0x50000, size), 256):
        chunk = data[i:i+256]
        small_count = sum(1 for b in chunk if b <= 7)
        if small_count > 200:
            print(f"  0x{i:08x}: {small_count}/256 bytes <= 7 (potential markers)")

if __name__ == '__main__':
    main()
