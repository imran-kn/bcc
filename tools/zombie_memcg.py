#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# zombie_memcg Dump info about zombie memcgroups
#           For Linux, uses BCC, eBPF.
#
# USAGE: zombie_memcg [-h] [interval] [count]
#
# Copyright (c) Imran Khan.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Dec-2024   Imran Khan     Created this.


from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import sys

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h> /* For TASK_COMM_LEN */
#include <linux/memcontrol.h> /* For mem_cgroup_from_css */

typedef struct memcg_info {
    u64 online_ts;
    u64 offline_ts;
    u32 pid;
    u8 offline;
    char comm[TASK_COMM_LEN];
    char name[256];
    u64 memcg_ptr;
} memcg_info_t;

BPF_HASH(offline_memcg_info, u64, memcg_info_t);

int mem_cgroup_css_online_probe(struct pt_regs *ctx, struct cgroup_subsys_state *css)
{
    struct kernfs_node *kn;
    struct mem_cgroup *memcg_ptr = (struct mem_cgroup *)PT_REGS_PARM1(ctx);
    memcg_info_t memcg_val = {};
    memcg_val.offline = 0;
    memcg_val.memcg_ptr = (u64)memcg_ptr;
    memcg_val.online_ts = bpf_ktime_get_ns();
    memcg_val.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&memcg_val.comm, sizeof(memcg_val.comm));
    kn = memcg_ptr->css.cgroup->kn;
    bpf_probe_read_kernel_str(&memcg_val.name, sizeof(memcg_val.name), kn->name);
    offline_memcg_info.update(&memcg_val.memcg_ptr, &memcg_val);
    return 0;
}

int mem_cgroup_css_offline_probe(struct pt_regs *ctx, struct cgroup_subsys_state *css)
{
    u64 memcg_ptr = (u64)PT_REGS_PARM1(ctx);
    memcg_info_t *memcg_val_p = offline_memcg_info.lookup(&memcg_ptr);
    if (memcg_val_p == 0) {
        return 0; //data absent
    }
    memcg_val_p->offline = 1;
    memcg_val_p->offline_ts = bpf_ktime_get_ns();
    return 0;
}

int mem_cgroup_free_probe(struct pt_regs *ctx, struct mem_cgroup *memcg)
{
    u64 memcg_ptr = (u64)PT_REGS_PARM1(ctx);
    offline_memcg_info.delete(&memcg_ptr);
    return 0;
}
"""
# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="mem_cgroup_css_online", fn_name="mem_cgroup_css_online_probe")
b.attach_kprobe(event="mem_cgroup_css_offline", fn_name="mem_cgroup_css_offline_probe")
b.attach_kprobe(event="mem_cgroup_free", fn_name="mem_cgroup_free_probe")

print("Dump info about zoombie memcgroups... Hit Ctrl-C to end.")

# output
#exiting = 0 if args.interval else 1
exiting = 0
memcgs = b["offline_memcg_info"]
while (1):
    try:
        sleep(5)
    except KeyboardInterrupt:
        exiting = 1

    print()
    for address, info in memcgs.items():
        try:
            if not info.offline:
                continue
            offlined_since = (BPF.monotonic_time() - info.offline_ts)/1000000000
            print(f'memcg: {address.value:x} name: {info.name} created by pid: {info.pid} comm: {info.comm} offlined {offlined_since} secs ago')
        except KeyboardInterrupt:
            exiting = 1
        
    if exiting:
        exit()
