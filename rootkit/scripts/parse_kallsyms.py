#!/usr/bin/env python3
"""Parse kallsyms from CPH1859 C.50 kernel Image to extract symbol addresses."""
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

    print(f"Kernel Image size: {len(data)} bytes")

    # Find kallsyms data structure strings
    ksym_names_off = data.find(b'kallsyms_names')
    ksym_addrs_off = data.find(b'kallsyms_addresses')
    ksym_markers_off = data.find(b'kallsyms_markers')
    ksym_token_off = data.find(b'kallsyms_token_table')
    ksym_num_off = data.find(b'kallsyms_num_syms')

    print(f"\n--- kallsyms string references ---")
    print(f"  kallsyms_names:       0x{ksym_names_off:x}")
    print(f"  kallsyms_addresses:   0x{ksym_addrs_off:x}")
    print(f"  kallsyms_markers:     0x{ksym_markers_off:x}")
    print(f"  kallsyms_token_table: 0x{ksym_token_off:x}")
    print(f"  kallsyms_num_syms:    0x{ksym_num_off:x}")

    # The actual data structures are referenced by these symbols
    # We need to find where kallsyms_addresses, kallsyms_names, etc. point to
    # These are symbol addresses, not file offsets

    # Let's try to find kallsyms_num_syms value - it's a u32 somewhere
    # Search near kallsyms_num_syms string for a reasonable number
    print(f"\n--- Searching for kallsyms_num_syms value ---")
    search_start = ksym_num_off
    search_end = min(ksym_num_off + 256, len(data))
    for i in range(search_start, search_end - 4, 4):
        val = read_u32(data, i)
        if 10000 < val < 200000:  # Reasonable number of symbols
            print(f"  Possible num_syms at 0x{i:x}: {val}")

    # Try to parse kallsyms compressed format
    # With CONFIG_KALLSYMS=y, names are stored as tokens
    # kallsyms_token_table contains the token dictionary
    # kallsyms_token_index contains indices into the token table
    # kallsyms_names contains the encoded names
    # kallsyms_addresses contains the addresses
    # kallsyms_markers contains marker bytes

    print(f"\n--- Attempting kallsyms token table parsing ---")
    # The token table starts after the kallsyms_token_table string reference
    # Let's look at data near ksym_token_off
    for i in range(ksym_token_off, min(ksym_token_off + 64, len(data)), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  0x{i:08x}: {hex_str}")

    # Search for the critical symbol names in case they're stored uncompressed somewhere
    print(f"\n--- Direct string search for critical symbols ---")
    critical = [b'remove_waiter', b'rt_mutex_start_proxy_lock', b'rt_mutex_slowlock',
                b'ashmem_fops', b'ashmem_misc_fops', b'selinux_state',
                b'security_hook_heads', b'futex_requeue', b'rt_mutex_adjust_prio_chain']
    for sym in critical:
        idx = data.find(sym)
        if idx >= 0:
            print(f"  FOUND {sym.decode()} at file offset 0x{idx:x}")
        else:
            print(f"  NOT FOUND: {sym.decode()}")

if __name__ == '__main__':
    main()
