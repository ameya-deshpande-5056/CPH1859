#!/usr/bin/env python3
"""
Parse Linux kernel compressed kallsyms from CPH1859 C.50 kernel Image.
Goal: Extract symbol addresses for CVE-2026-43499 porting.

Missing symbols we need:
  remove_waiter, rt_mutex_start_proxy_lock, rt_mutex_slowlock,
  futex_requeue, ashmem_fops, selinux_state, security_hook_heads,
  anon_pipe_buf_ops

Kernel Image: /home/ameya/Realme1/CPH1859/rootkit/work/kernel_cph1859_c50.decompressed
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
    print(f"Kernel Image size: {size} bytes ({size/1024/1024:.1f} MB)")

    # Kernel VA range for this MT6771 build (from address groups found earlier)
    KVA_START = 0xffffff8008000000
    KVA_END = 0xffffffc000000000

    # -----------------------------------------------------------
    # Step 1: Find kallsyms_num_syms (u32 in reasonable range)
    # -----------------------------------------------------------
    print("\n=== Step 1: Finding kallsyms_num_syms ===")
    num_syms_candidates = []
    for i in range(0, size - 4, 4):
        val = read_u32(data, i)
        if 5000 <= val <= 50000:  # reasonable symbol count
            num_syms_candidates.append((i, val))

    print(f"  Found {len(num_syms_candidates)} candidates for kallsyms_num_syms")
    for off, val in num_syms_candidates[:20]:
        print(f"    offset 0x{off:08x}: {val} symbols")

    # -----------------------------------------------------------
    # Step 2: Find kallsyms_addresses table (array of u64 kernel addresses)
    # -----------------------------------------------------------
    print("\n=== Step 2: Finding kallsyms_addresses table ===")
    # Scan for groups of consecutive u64 kernel addresses
    groups = []
    i = 0
    while i < size - 8:
        val = read_u64(data, i)
        if KVA_START <= val < KVA_END:
            # Start of a potential group
            group_start = i
            group_vals = [val]
            j = i + 8
            while j < size - 8:
                next_val = read_u64(data, j)
                if KVA_START <= next_val < KVA_END and next_val > val:
                    group_vals.append(next_val)
                    val = next_val
                    j += 8
                else:
                    break
            if len(group_vals) >= 100:
                groups.append((group_start, group_vals))
            i = j
        else:
            i += 4

    print(f"  Found {len(groups)} groups of 100+ consecutive kernel addresses")
    for idx, (start, vals) in enumerate(groups):
        print(f"    Group {idx}: file_off 0x{start:08x}, {len(vals)} entries, "
              f"0x{vals[0]:016x} -> 0x{vals[-1]:016x}")

    # -----------------------------------------------------------
    # Step 3: Try to match num_syms with group sizes
    # -----------------------------------------------------------
    print("\n=== Step 3: Matching num_syms with address groups ===")
    for off, num_syms in num_syms_candidates[:50]:
        for gidx, (start, vals) in enumerate(groups):
            if len(vals) == num_syms or len(vals) == num_syms + 1:
                print(f"  MATCH: num_syms={num_syms} at 0x{off:08x} matches group {gidx} "
                      f"with {len(vals)} entries at 0x{start:08x}")

    # -----------------------------------------------------------
    # Step 4: Look for kallsyms data structures near kallsyms_num_syms string
    # The string references we found:
    #   kallsyms_names:       0x17d1504
    #   kallsyms_addresses:   0x17d14f1
    #   kallsyms_markers:     0x17d14c1
    #   kallsyms_token_table: 0x17d154f
    #   kallsyms_num_syms:    0x17d1564
    # These are just string labels. The actual data structures are elsewhere.
    # But they might be clustered together in .data/.bss
    # -----------------------------------------------------------
    print("\n=== Step 4: Examining area near kallsyms string references ===")
    base = 0x17d14c0
    for i in range(base, min(base + 256, size), 8):
        val = read_u64(data, i)
        if KVA_START <= val < KVA_END:
            print(f"  0x{i:08x}: ptr=0x{val:016x} (kernel address)")

    # -----------------------------------------------------------
    # Step 5: Try to parse kallsyms from each large address group
    # -----------------------------------------------------------
    print("\n=== Step 5: Attempting kallsyms parsing on largest groups ===")
    groups.sort(key=lambda g: len(g[1]), reverse=True)
    for gidx, (start, vals) in enumerate(groups[:10]):
        print(f"\n  Group {gidx}: {len(vals)} entries at 0x{start:08x}")
        # Check if first few entries look like symbol addresses
        # (should be in kernel text range, aligned)
        text_start = 0xffffff8008080000  # estimated
        text_end = 0xffffff8009000000
        text_count = sum(1 for v in vals[:100] if text_start <= v < text_end)
        print(f"    First 100 entries in kernel text range: {text_count}/100")

if __name__ == '__main__':
    main()
