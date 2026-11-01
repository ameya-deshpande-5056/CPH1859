# CVE-2026-43499 (GhostLock) Feasibility — OPPO Realme 1 (CPH1859)
## Final Analysis After Ozip Decryption and Kallsyms Parsing

## 1. Ozip Decryption — COMPLETE

### 1.1 Decryption Results
- File: CPH1859EX_11_OTA_0500.ozip (2.36 GB)
- AES key: 172B3E14E46F3CE13E2B5121CBDC4321 (Realme 1 MTK P60)
- Tool: bkerler/oppo_ozip_decrypt v1.32
- Decrypted output: CPH1859EX_11_OTA_0500.zip (2.36 GB)

### 1.2 boot.img Extraction
- From decrypted zip: boot.img (9,786,192 bytes = 9.33 MB)
- Magic: ANDROID! (valid Android boot image v1)
- Header: kernel_size=9,778,706, page_size=2048, ramdisk_size=0
- Saved to: /home/ameya/Realme1/CPH1859/rootkit/work/boot.img

### 1.3 Kernel Decompression
- Kernel is gzip-compressed (0x1f8b magic)
- Decompressed size: 26,848,686 bytes (25.6 MB)
- Format: ARM64 Linux kernel Image
- Saved to: /home/ameya/Realme1/CPH1859/rootkit/work/kernel_cph1859_c50.decompressed

### 1.4 Kernel Configuration (from /proc/config.gz on live device)
- CONFIG_KALLSYMS=y (but CONFIG_KALLSYMS_ALL not set)
- CONFIG_FUTEX=y
- CONFIG_RT_MUTEXES=y
- CONFIG_PREEMPT=y
- CONFIG_SMP=y
- CONFIG_CGROUPS=y
- CONFIG_SECCOMP=y
- CONFIG_CC_STACKPROTECTOR_STRONG=y
- All required kernel options for GhostLock are ENABLED

## 2. Symbol Extraction — COMPLETE

### 2.1 Symbols Found via `strings` search
Found 20+ kernel symbols at file offsets in the decompressed kernel Image (see prior revision).

### 2.2 Critical Symbols Recovered for CPH1859 (Linux 4.4.146+)
Recovered via `vmlinux-to-elf` and targeted disassembly (see table above).

### 2.3 Recovered Structure Field Offsets (from disassembly)
Offsets are relative to the containing structure base.

| Structure | Field | Offset | Source function / instruction |
|---|---|---|---|
| `task_struct` | `cred` | `0x748` | `commit_creds`: `ldr x21, [x19, #1864]` (`x19` = current task) |
| `task_struct` | `real_cred` | `0x750` | `commit_creds`: `ldr x8, [x19, #1872]` |
| `task_struct` | `pi_lock` (spinlock) | `0x814` | `remove_waiter`: `add x21, x20, #0x814` (`x20` = current task) |

Additional `task_struct`, `rt_mutex_waiter`, `pipe_inode_info`, `pipe_buffer`, and `cred` field offsets remain to be derived by further disassembly of `task_blocks_on_rt_mutex`, `try_to_take_rt_mutex`, pipe, and ashmem paths.

### 2.4 Memory Layout (CPH1859 MT6771)
- `KIMAGE_TEXT_BASE` (`_text`): `0xffffff8008080000`
- Kernel text file offset: `0x00080000` (ARM64 Image header)
- Effective image size: `0x0200d000` (from Image header)
- `PAGE_OFFSET` (inferred, 48-bit VA): `0xffffff8000000000`
- `PHYS_OFFSET` (inferred from device): `0x40000000` (to be confirmed via `memstart_addr`)
- `memstart_addr`/`module_alloc_base` not yet recovered from this image (no kallsyms entry; requires disassembly of allocator setup).


### 2.1 Symbols Found via `strings` search
Found 20+ kernel symbols at file offsets in the decompressed kernel Image:

| Symbol | File Offset | Virtual Address |
|--------|------------|----------------|
| init_task | 0x11d092c | 0x000000000125092c |
| commit_creds | 0x11d1d2d | 0x0000000001251d2d |
| prepare_kernel_cred | 0x11d1d62 | 0x0000000001251d62 |
| override_creds | 0x11d1d46 | 0x0000000001251d46 |
| kmalloc_caches | 0x11d625a | 0x000000000125625a |
| fget | 0x11d7835 | 0x0000000001257835 |
| fput | 0x11d6ae9 | 0x0000000001256ae9 |
| kernel_write | 0x11d8126 | 0x0000000001258126 |
| generic_file_llseek | 0x11d6a03 | 0x0000000001256a03 |
| noop_llseek | 0x11d6a29 | 0x0000000001256a29 |
| default_file_splice_read | 0x11d8133 | 0x0000000001258133 |
| generic_file_splice_read | 0x11d80f8 | 0x00000000012580f8 |
| kallsyms_lookup_name | 0x11d4407 | 0x0000000001254407 |
| kptr_restrict | 0xf9ca84 | 0x000000000101ca84 |
| configfs_read_file | 0xfb6f77 | 0x0000000001036f77 |
| init_uts_ns | 0x11d0912 | 0x0000000001250912 |
| init_user_ns | 0x11d12a6 | 0x00000000012512a6 |

### 2.2 Critical Symbols Recovered for CPH1859 (Linux 4.4.146+)

Using `vmlinux-to-elf` on `kernel_cph1859_c50.decompressed` (producing `kernel_cph1859.elf`) and cross-referencing function pointers/disassembly for non-text symbols (since `CONFIG_KALLSYMS_ALL` was unset), all genuine symbols for the Realme 1 MT6771 4.4.146+ kernel have been identified and verified:

| Symbol | File Offset | Kernel VA | Type / Detection Method |
|--------|-------------|-----------|-------------------------|
| `rt_mutex_start_proxy_lock` | `0x000965c0` | `0xffffff80081165c0` | Global text symbol (`T`) in ELF |
| `remove_waiter` | `0x00096b88` | `0xffffff8008116b88` | Local text symbol (`t`) in ELF |
| `rt_mutex_slowlock` | `0x00ccd180` | `0xffffff8008d4d180` | Local text symbol (`t`) in ELF |
| `futex_requeue` | `0x000cad5c` | `0xffffff800814ad5c` | Local text symbol (`t`) in ELF |
| `ashmem_fops` | `0x00e5c178` | `0xffffff8008edc178` | `miscdevice` fops table referenced by `ashmem_init` |
| `anon_pipe_buf_ops` | `0x00cfa158` | `0xffffff8008d7a158` | `pipe_buf_operations` struct containing `anon_pipe_buf_release` |
| `selinux_enforcing` | `0x01a85fc8` | `0xffffff8009b05fc8` | Global variable loaded/stored in `sel_{read,write}_enforce` |
| `security_hook_heads` | `0x01820dd8` | `0xffffff80098a0dd8` | LSM hook array referenced by `security_file_open` |

> **Notes on CPH1859 / 4.4 Differences**:
> - `selinux_state` does not exist in Linux 4.4 (introduced in 4.17); the target is `selinux_enforcing` at `0xffffff8009b05fc8`.
> - Because `CONFIG_KALLSYMS_ALL` is disabled, data/rodata symbols (`ashmem_fops`, `anon_pipe_buf_ops`, `selinux_enforcing`, `security_hook_heads`) are omitted from the kallsyms table. They were recovered via instruction disassembly (`adrp`/`ldr`/`str`) of their accessing functions.
> - `sel_write_enforce` in this build includes vendor checks (`is_bootloader_unlocked`, `get_boot_mode`) enforcing `selinux_enforcing = 1` while the bootloader remains locked.

### 2.3 Additional Recovered Helpers

| Symbol | File Offset | Kernel VA | Type |
|--------|-------------|-----------|------|
| `commit_creds` | `0x0004c150` | `0xffffff80080cc150` | `T` |
| `prepare_kernel_cred` | `0x0004c528` | `0xffffff80080cc528` | `T` |
| `override_creds` | `0x0004c46c` | `0xffffff80080cc46c` | `T` |
| `revert_creds` | `0x0004c49c` | `0xffffff80080cc49c` | `T` |
| `kallsyms_lookup_name` | `0x000d6ea0` | `0xffffff8008156ea0` | `T` |
| `futex_lock_pi` | `0x000cbfc0` | `0xffffff800814bfc0` | `t` |
| `futex_wake` | `0x000c8eb4` | `0xffffff8008148eb4` | `t` |
| `rt_mutex_setprio` | `0x000595f0` | `0xffffff80080d95f0` | `T` |
| `task_blocks_on_rt_mutex` | `0x00096830` | `0xffffff8008116830` | `t` |
| `try_to_take_rt_mutex` | `0x0009665c` | `0xffffff800811665c` | `t` |

## 3. Kallsyms Data Structures Located
- kallsyms_names string ref: file offset 0x17d1504
- kallsyms_addresses string ref: file offset 0x17d14f1
- kallsyms_markers string ref: file offset 0x17d14c1
- kallsyms_token_table string ref: file offset 0x17d154f
- kallsyms_num_syms string ref: file offset 0x17d1564 (value: 28464)
- 35 groups of consecutive kernel addresses found (0xffffff80080xxxxx range)
- Largest group: 28464 entries at 0x00eafb90 (kallsyms_addresses table)
- Kernel VA range confirmed: 0xffffff8008000000+

## 4. Feasibility Assessment — UPDATED

| Question | Answer |
|----------|--------|
| Is CVE-2026-43499 present in kernel 4.4.146+? | **YES** — vuln introduced 2011, affects all 4.x, all required CONFIG options enabled |
| Do we have the kernel image? | **YES** — decompressed 25.6 MB ARM64 Image extracted from ozip |
| Can we extract all symbol addresses? | **YES** — full critical symbol set extracted via `kernel_cph1859.elf` and targeted disassembly |
| Is there a working exploit for CPH1859? | **NO** — only PoC for 4.14.180/SM6150/Android 11 exists |
| Can we port it today? | **NO** — blocked by kernel-4.4 struct/layout differences, vendor SELinux lock checks, and exploit adaptation |
| Feasibility | **LOW-MEDIUM** — symbol-access blocker resolved; memory layout, struct offsets, and vendor mitigation adaptation remain |

## 5. What Would Complete the Port

To port GhostLock to CPH1859 kernel 4.4.146+, all of the following would still be required:

1. ✅ **Kernel image** — EXTRACTED from ozip
2. ✅ **Critical GhostLock symbol set** — RECOVERED for CPH1859 (offsets verified against MT6771 4.4.146+ image)
3. ❌ **Kernel 4.4 struct offsets** — task_struct, cred, rt_mutex_waiter, pipe_inode_info (different from 4.14)
4. ❌ **Exact memory layout** — KIMAGE_TEXT_BASE (`0xffffff8008080000`), PAGE_OFFSET for MT6771
5. ❌ **OPPO vendor check bypass** — handle `is_bootloader_unlocked` check inside `sel_{read,write}_enforce`
6. ❌ **Exploit code adaptation** — modify the 4.14 PoC for the MT6771 4.4.146+ kernel
7. ❌ **Build/test cycle** — Android NDK r29, accept kernel-panic risk

## 5. Bottom Line

With the symbol extraction complete via `vmlinux-to-elf` and direct disassembly of non-kallsyms symbols, symbol resolution is no longer a blocker. However, adaptation to kernel 4.4.146+ on MT6771 still requires:

1. Resolving 4.4 kernel structure layout and field offsets (`task_struct`, `rt_mutex_waiter`, `pipe_inode_info`)
2. Accounting for vendor-specific SELinux enforcement checks (`is_bootloader_unlocked` in `selinuxfs.c`)
3. Adaptation of the public 4.14 exploit primitives to this SoC and kernel base
4. Verification on the real device with a controlled unsafe test path

**No exploit code has been built or run.** Device remains in 100% factory state.

## 6. References

- CVE-2026-43499 / GHSA-cqc6-9f34-295v: rtmutex use-after-free in remove_waiter()
- GhostLock-OPPO-PCKM00 PoC: https://github.com/yijiacloud/GhostLock-OPPO-PCKM00
  (targets OPPO PCKM00 / SM6150 / Android 11 / kernel 4.14.180 — NOT CPH1859)
- NebuSec/CyberMeowfia: Original GhostLock research framework
- ozip decryption key: 172B3E14E46F3CE13E2B5121CBDC4321 (Realme 1 MTK P60)
- Decrypted zip: /home/ameya/Realme1/CPH1859/CPH1859EX_11_OTA_0500.zip
- Kernel image: /home/ameya/Realme1/CPH1859/rootkit/work/kernel_cph1859_c50.decompressed
- Boot image: /home/ameya/Realme1/CPH1859/rootkit/work/boot.img

