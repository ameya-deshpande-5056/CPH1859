#!/usr/bin/env python3
"""Decrypt OPPO ozip container (AES-128-ECB on entire file after OPPOENCRYPT! header)."""
import binascii
import os
import sys
from Crypto.Cipher import AES

OZIP_PATH = "/home/ameya/Realme1/CPH1859/CPH1859EX_11_OTA_0500.ozip"
OUT_ZIP = "/home/ameya/Realme1/CPH1859/rootkit/work/CPH1859EX_11_OTA_0500.zip"

# Candidate keys from ozipdecrypt.py - Realme 1 MTK P60 is at index 43
KEYS = [
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E",  # mnkey
    "D6ECCF0AE5ACD4E0E92E522DE7C1381E",  # mkey
    "D6DCCF0AD5ACD4E0292E522DB7C1381E",  # realkey
    "D7DCCE1AD4AFDCE2393E5161CBDC4321",  # testkey
    "D7DBCE2AD4ADDCE1393E5521CBDC4321",  # utilkey
    "D7DBCE1AD4AFDCE1393E5121CBDC4321",  # R11s CPH1719
    "D4D2CD61D4AFDCE13B5E01221BD14D20",  # FindX CPH1871
    "261CC7131D7C1481294E532DB752381E",  # FindX
    "1CA21E12271335AE33AB81B2A7B14622",  # Realme 2 pro
    "D4D2CE11D4AFDCE13B3E0121CBD14D20",  # K1
    "1C4C1EA3A12531AE33AB81B2A7B14622",  # Realme 3 Pro
    "1C4C1EA3A12531AE4A1B21BB31C13C21",  # Reno 10x zoom
    "1C4A11A3A12513AE441B23BB31513121",  # Reno 2 PCKM00
    "1C4A11A3A12589AE441A23BB31517733",  # Realme X2
    "1C4A11A3A22513AE541B53BB31513121",  # Realme 5
    "2442CE821A4F352E33AE81B22BC1462E",  # R17 Pro
    "14C2CD6214CFDC2733AE81B22BC1462C",  # CPH1803 OppoA3s
    "1E38C1B72D522E29E0D4ACD50ACFDCD6",
    "12341EAAC4C123CE193556A1BBCC232D",
    "2143DCCB21513E39E1DCAFD41ACEDBD7",
    "2D23CCBBA1563519CE23C1C4AA1E3412",  # A77 CPH1715 MT6750T
    "172B3E14E46F3CE13E2B5121CBDC4321",  # Realme 1 MTK P60  <-- TARGET
    "ACAA1E12A71431CE4A1B21BBA1C1C6A2",  # Realme U1
    "ACAC1E13A72531AE4A1B22BB31C1CC22",  # Realme 3
    "1C4411A3A12533AE441B21BB31613C11",  # A1k CPH1923
    "1C4416A8A42717AE441523B336513121",  # Reno 3
    "55EEAA33112133AE441B23BB31513121",  # RenoAce
    "ACAC1E13A12531AE4A1B21BB31C13C21",  # Reno, K3
    "ACAC1E13A72431AE4A1B22BBA1C1C6A2",  # A9
    "12CAC11211AAC3AEA2658690122C1E81",  # A1,A83t
    "1CA21E12271435AE331B81BBA7C14612",  # CPH1909 OppoA5s
    "D1DACF24351CE428A9CE32ED87323216",  # Realme1(reserved)
    "A1CC75115CAECB890E4A563CA1AC67C8",  # A73(reserved)
    "2132321EA2CA86621A11241ABA512722",  # Realme3(reserved)
    "22A21E821743E5EE33AE81B227B1462E",  # F3 Plus
]

def find_key(data_after_header):
    """Try each key to decrypt first block and check for ZIP magic."""
    for key_hex in KEYS:
        key = binascii.unhexlify(key_hex)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(data_after_header[:16])
        if decrypted[:4] == b'\x50\x4b\x03\x04':  # ZIP local file header
            print(f"Found correct AES key: {key_hex}")
            return key
        elif decrypted[:4] == b'\x41\x56\x42\x30':  # AVB0
            print(f"Found correct AES key: {key_hex}")
            return key
        elif decrypted[:4] == b'\x41\x4e\x44\x52':  # ANDROID
            print(f"Found correct AES key: {key_hex}")
            return key
    return None

def main():
    os.makedirs(os.path.dirname(OUT_ZIP), exist_ok=True)

    print(f"Reading ozip: {OZIP_PATH}")
    file_size = os.path.getsize(OZIP_PATH)
    print(f"  File size: {file_size} bytes ({file_size / 1024 / 1024:.1f} MB)")

    with open(OZIP_PATH, 'rb') as f:
        header = f.read(12)
        if header != b"OPPOENCRYPT!":
            print(f"ERROR: Not an OPPOENCRYPT! file, header: {header!r}")
            sys.exit(1)
        print("  OPPOENCRYPT! header confirmed")
        data = f.read()

    print(f"  Encrypted data after header: {len(data)} bytes")

    # Try to find the correct key
    key = find_key(data)
    if key is None:
        print("ERROR: No valid AES key found")
        sys.exit(1)

    # Decrypt entire file (AES-128-ECB)
    print("Decrypting entire ozip container (AES-128-ECB)...")
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Process in 16MB chunks (must be 16-byte aligned)
    chunk_size = 16 * 1024 * 1024  # 16MB
    decrypted_chunks = []
    
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + chunk_size]
        # Pad to 16-byte boundary
        remainder = len(chunk) % 16
        if remainder:
            chunk += b'\x00' * (16 - remainder)
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)
        offset += chunk_size

    decrypted = b''.join(decrypted_chunks)
    
    # Trim to original size (remove padding from last block)
    original_size = len(data)
    decrypted = decrypted[:original_size]

    # Verify ZIP magic
    if decrypted[:4] == b'\x50\x4b\x03\x04':
        print("  VALID: Decrypted data starts with ZIP magic PK\x03\x04")
    else:
        print(f"  WARN: Decrypted data starts with: {decrypted[:16]!r}")

    # Write decrypted zip
    with open(OUT_ZIP, 'wb') as f:
        f.write(decrypted)

    print(f"  Written: {OUT_ZIP} ({os.path.getsize(OUT_ZIP)} bytes)")

if __name__ == '__main__':
    main()
