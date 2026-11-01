#!/usr/bin/env python3
import struct

with open('/home/ameya/Realme1/CPH1859/rootkit/work/kernel_cph1859_c50.decompressed','rb') as f:
    data = f.read()

base = 0x00da0100
print(f'=== Region 0x{base:08x} - starting after addresses table ===')

u16_vals = struct.unpack_from('<' + 'H' * 128, data, base)
print(f'First 128 token indices:')
for i in range(128):
    print(f'  [{i:3d}]: {u16_vals[i]:5d} 0x{u16_vals[i]:04x}')

print()
print('=== Scanning for token strings ===')
for start in range(base, min(base + 0x5000, len(data)), 256):
    chunk = data[start:start+256]
    if start + 256 > len(data):
        break
    strings = []
    cur = b''
    for b in chunk:
        if b == 0:
            if 1 <= len(cur) <= 32:
                try:
                    s = cur.decode('ascii')
                    if any(c.isalpha() for c in s) and not s.isdigit():
                        strings.append(s)
                except:
                    pass
            cur = b''
        else:
            cur += bytes([b])
    if strings:
        print(f'  0x{start:08x}: {strings[:4]}')
