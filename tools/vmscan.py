#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
# This is just a port of code given in Brendan Gregg's BPF book.
# This porting coverts bpftrace based code given in book to BCC


from __future__ import print_function
from bcc import BPF

src="""
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(shrink_slab_hist);
BPF_HISTOGRAM(direct_reclaim_hist);
BPF_HISTOGRAM(kswapd_hist);
BPF_HISTOGRAM(memcg_reclaim_hist);
BPF_HISTOGRAM(memcg_softlimit_reclaim_hist);
BPF_HISTOGRAM(node_reclaim_hist);

u64 shrink_slab_time = 0;
u64 direct_reclaim_time = 0;
u64 kswapd_time = 0;
u64 memcg_reclaim_time = 0;
u64 memcg_softlimit_reclaim_time = 0;
u64 node_reclaim_time = 0;

TRACEPOINT_PROBE(vmscan, mm_shrink_slab_start) {
    shrink_slab_time =  bpf_ktime_get_ns();
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_shrink_slab_end) {
    u64 dur = 0;
    dur =  bpf_ktime_get_ns() - shrink_slab_time;
    shrink_slab_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_begin) {
    direct_reclaim_time = bpf_ktime_get_ns();
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_end) {
    u64 dur = 0;
    dur = bpf_ktime_get_ns() - direct_reclaim_time;
    direct_reclaim_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_kswapd_sleep) {
    u64 dur = 0;
    dur =  bpf_ktime_get_ns() - kswapd_time;
    kswapd_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_kswapd_wake) {
    kswapd_time = bpf_ktime_get_ns();
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_reclaim_begin) {
    memcg_reclaim_time = bpf_ktime_get_ns();
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_reclaim_end) {
    u64 dur = 0;
    dur = bpf_ktime_get_ns() - memcg_reclaim_time;
    memcg_reclaim_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_softlimit_reclaim_begin) {
    memcg_softlimit_reclaim_time = bpf_ktime_get_ns();
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_softlimit_reclaim_end) {
    u64 dur = 0;
    dur = bpf_ktime_get_ns() - memcg_softlimit_reclaim_time;
    memcg_softlimit_reclaim_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_node_reclaim_begin) {
    node_reclaim_time = bpf_ktime_get_ns();
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_node_reclaim_end) {
    u64 dur = 0;
    dur = bpf_ktime_get_ns() - node_reclaim_time;
    node_reclaim_hist.increment(dur/1000);
    return 0;
}
"""

b = BPF(text=src)
print("Tracing vmcscan event durations ... Hit Ctrl-C to end.")

try:
    sleep(99999999)
except KeyboardInterrupt:
    print()

print("shrink slab histogram ")
b["shrink_slab_hist"].print_hist("microsecs")
print("direct reclaim histogram ")
b["direct_reclaim_hist"].print_hist("microsecs")
print("kswapd histogram ")
b["kswapd_hist"].print_hist("microsecs")
print("memcg reclaim histogram ")
b["memcg_reclaim_hist"].print_hist("microsecs")
print("memcg softlimit reclaim histogram ")
b["memcg_softlimit_reclaim_hist"].print_hist("microsecs")
print("node reclaim histogram ")
b["node_reclaim_hist"].print_hist("microsecs")
