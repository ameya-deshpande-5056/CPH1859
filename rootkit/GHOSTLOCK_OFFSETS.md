## Pipe offsets (from anon_pipe_buf_release)
- `pipe_inode_info.bufs`: 0x68 (104)
- `pipe_buffer.page`: 0x00
- `pipe_buffer.ops`: 0x20 (inferred from 4.4 `struct pipe_buffer` layout)

## Notes on configfs
- CPH1859 4.4 kernel exposes only `configfs_read_file` (0xffffff8008294060) and `configfs_write_file` (0xffffff8008294190); no `configfs_*_bin_file` symbols. The 4.14 binary-attribute primitive must be reworked for this kernel (e.g. legacy `.read`/`.write` file ops).
## Additional recovered offsets (rt_mutex/task, 2026-11-01)

- `rt_mutex_waiter.tree_entry` (rb_node): 0x00 (24 bytes)
- `rt_mutex_waiter.pi_tree_entry` (rb_node): 0x18 (24 bytes)
- `rt_mutex_waiter.task`: 0x30
- `rt_mutex_waiter.lock`: 0x38
- `rt_mutex_waiter.prio`: 0x40
- `task_struct.prio`: 0x80
- `task_struct.normal_prio`: 0x88
- `task_struct.pi_waiters` (rb_root): 0x820
- `task_struct.pi_blocked_on`: 0x830
- `task_struct.pi_lock`: 0x814 (confirmed)

> Note: rt_mutex_waiter layout above follows the 4.4 `struct rt_mutex_waiter` (rb_node = 24 bytes). Deadline fields are absent in 4.4; adapt exploit's deadline handling accordingly.
# GhostLock (CVE-2026-43499) CPH1859 C.50 Recovered Offsets

## Status
Symbol blocker resolved. Structure-offset recovery in progress.

## Kernel base
- KIMAGE_TEXT_BASE (_text): 0xffffff8008080000
- ARM64 Image text_offset: 0x80000
- Effective image size: 0x0200d000
- PAGE_OFFSET (inferred): 0xffffff8000000000

## Recovered symbol offsets (relative to KIMAGE_TEXT_BASE)
- commit_creds: 0x0004c150
- prepare_kernel_cred: 0x0004c528
- override_creds: 0x0004c46c
- revert_creds: 0x0004c49c
- kallsyms_lookup_name: 0x000d6ea0
- remove_waiter: 0x00096b88
- rt_mutex_start_proxy_lock: 0x000965c0
- rt_mutex_slowlock: 0x00ccd180
- futex_requeue: 0x000cad5c
- futex_lock_pi: 0x000cbfc0
- futex_wake: 0x000c8eb4
- rt_mutex_setprio: 0x000595f0
- task_blocks_on_rt_mutex: 0x00096830
- try_to_take_rt_mutex: 0x0009665c
- ashmem_fops: 0x00e5c178
- anon_pipe_buf_ops: 0x00cfa158
- selinux_enforcing: 0x01a85fc8
- security_hook_heads: 0x01820dd8

## Recovered structure field offsets
- task_struct.cred: 0x748
- task_struct.real_cred: 0x750
- task_struct.pi_lock: 0x814

## TODO
- Full task_struct layout (pid, tgid, comm, tasks, seccomp, atomic_flags, thread_info flags)
- rt_mutex_waiter layout (tree_entry, pi_tree_entry, task, lock, wake_state, ww_ctx)
- pipe_inode_info / pipe_buffer layouts
- cred layout (uid, caps, security)
- memstart_addr / module_alloc_base / PHYS_OFFSET
- Vendor SELinux bypass in sel_write_enforce
- PoC adaptation and build/test

## Implementation artifact

- `rootkit/scripts/extract_cph_symbols.py` — cross-references `kernel_cph1859.elf` via `nm` and writes `rootkit/cph1859_symbols.json` with KASLR-aware relative offsets and symbol types.
