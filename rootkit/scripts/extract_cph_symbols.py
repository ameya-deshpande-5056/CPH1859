#!/usr/bin/env python3
import struct, subprocess, os, json

base = '/home/ameya/Realme1/CPH1859/rootkit'
elf = os.path.join(base, 'work/kernel_cph1859.elf')
kmg = os.path.join(base, 'work/kernel_cph1859_c50.decompressed')
out = os.path.join(base, 'cph1859_symbols.json')

# Check we have a usable cross-nm
nm = ['aarch64-linux-gnu-nm', elf]
try:
    r = subprocess.run(nm, capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and 'aarch64-linux-gnu-nm' not in r.stderr:
        nm = ['nm', elf]
        r = subprocess.run(nm, capture_output=True, text=True, timeout=60)
except Exception as e:
    print('nm error', e)
    r = None

symbols = {}
if r and r.stdout:
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        v, typ, name = parts[0], parts[1], parts[2]
        # Only keep symbols in .text/.kernel and global/local text/data
        symbols[name] = {'type': typ, 'va': int(v, 16)}

# Kernel text base
kbase = 0xffffff8008080000

critical = [
    'commit_creds', 'prepare_kernel_cred', 'override_creds', 'revert_creds',
    'init_task', 'init_cred', 'init_uts_ns', 'init_user_ns', 'init_groups',
    'remove_waiter', 'rt_mutex_start_proxy_lock', 'rt_mutex_slowlock',
    'futex_requeue', 'futex_lock_pi', 'futex_wake', 'rt_mutex_setprio',
    'task_blocks_on_rt_mutex', 'try_to_take_rt_mutex', 'mark_wakeup_next_waiter',
    'ashmem_fops', 'anon_pipe_buf_ops', 'selinux_enforcing', 'security_hook_heads',
    'kallsyms_lookup_name', 'kptr_restrict', 'configfs_read_file', 'configfs_write_file',
]

result = {'kernel_text_base': kbase, 'symbols': {}}
for s in critical:
    if s in symbols:
        result['symbols'][s] = {'relative_off': symbols[s]['va'] - kbase, 'va': symbols[s]['va'], 'type': symbols[s]['type']}
    else:
        result['symbols'][s] = {'status': 'MISSING'}

with open(out, 'w') as f:
    json.dump(result, f, indent=2)

print('Wrote', out)
for s, d in result['symbols'].items():
    if 'status' in d:
        print('MISSING', s)
    else:
        print('{:<32} {:#x} ({} {})'.format(s, d['relative_off'], d['va'], d.get('type', '?')))
