#!/usr/bin/env python3
"""Extract boot.img from encrypted OPPO ozip using the Realme 1 MTK P60 AES key."""
import zipfile
import binascii
import os
import sys
from Crypto.Cipher import AES

OZIP_PATH = "/home/ameya/Realme1/CPH1859/CPH1859EX_11_OTA_0500.ozip"
OUT_DIR = "/home/ameya/Realme1/CPH1859/rootkit/work"
BOOT_IMG_OUT = os.path.join(OUT_DIR, "boot_cph1859_c50.img")

# Realme 1 MTK P60 AES key from ozipdecrypt.py
KEY_HEX = "172B3E14E46F3CE13E2B5121CBDC4321"
KEY = binascii.unhexlify(KEY_HEX)

def decrypt_aes_ecb(data, key):
    """AES-128-ECB decrypt."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print(f"Opening ozip: {OZIP_PATH}")
    with zipfile.ZipFile(OZIP_PATH, 'r') as zo:
        names = zo.namelist()
        print(f"  {len(names)} entries in ozip")

        # Find boot.img
        boot_name = None
        for n in names:
            if n.lower().endswith('boot.img') or n.lower() == 'boot.img':
                boot_name = n
                break

        if boot_name is None:
            print("ERROR: boot.img not found in ozip")
            # Show first 20 entries for debugging
            for n in names[:20]:
                print(f"    {n}")
            sys.exit(1)

        print(f"Found boot.img: {boot_name} ({zo.getinfo(boot_name).file_size} bytes)")

        # Extract boot.img
        info = zo.getinfo(boot_name)
        with zo.open(info) as src:
            data = src.read()

        # Check if encrypted (starts with OPPOENCRYPT!)
        if data[:12] == b"OPPOENCRYPT!":
            print("  boot.img is encrypted (OPPOENCRYPT! magic), decrypting...")
            # OPPOENCRYPT! header is 12 bytes, then encrypted data follows
            # The decryption is AES-128-ECB on 16-byte blocks
            encrypted_data = data[12:]  # Skip the OPPOENCRYPT! header
            # Pad to 16-byte boundary if needed
            remainder = len(encrypted_data) % 16
            if remainder:
                encrypted_data += b'\x00' * (16 - remainder)
            decrypted = decrypt_aes_ecb(encrypted_data, KEY)
            # Remove padding
            # The original size should be info.file_size - 12 (header)
            # But we decrypted the full block-aligned data
            original_size = len(data) - 12
            decrypted = decrypted[:original_size]
        else:
            print("  boot.img is NOT encrypted (no OPPOENCRYPT! header)")
            decrypted = data

        # Write output
        with open(BOOT_IMG_OUT, 'wb') as dst:
            dst.write(decrypted)

    print(f"  Written: {BOOT_IMG_OUT} ({os.path.getsize(BOOT_IMG_OUT)} bytes)")

    # Verify Android boot image magic
    with open(BOOT_IMG_OUT, 'rb') as f:
        magic = f.read(8)
    if magic == b'ANDROID!':
        print("  VALID: Android boot image magic 'ANDROID!' detected")
    else:
        print(f"  WARN: Boot image magic not 'ANDROID!', got: {magic!r}")

if __name__ == '__main__':
    main()
