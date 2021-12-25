#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
# This is just a port of code given in Brendan Gregg's BPF book.
# This porting coverts bpftrace based code given in book to BCC


from __future__ import print_function
from bcc import BPF

src="""
#include <uapi/linux/ptrace.h>

BPF_HASH(record);
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
    record.update(100, bpf_ktime_get_ns());
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_shrink_slab_end) {
    u64 dur = 0;
    dur = record.lookup(100)
    dur =  bpf_ktime_get_ns() - dur;
    shrink_slab_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_begin) {
    record.update(200, bpf_ktime_get_ns());
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_end) {
    u64 dur = 0;
    dur = record.lookup(200)
    dur =  bpf_ktime_get_ns() - dur;
    direct_reclaim_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_kswapd_sleep) {
    u64 dur = 0;
    dur = record.lookup(300)
    dur =  bpf_ktime_get_ns() - dur;
    kswapd_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_kswapd_wake) {
    record.update(300, bpf_ktime_get_ns());
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_reclaim_begin) {
    record.update(400, bpf_ktime_get_ns());
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_reclaim_end) {
    u64 dur = 0;
    dur = record.lookup(400)
    dur =  bpf_ktime_get_ns() - dur;
    memcg_reclaim_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_softlimit_reclaim_begin) {
    record.update(500, bpf_ktime_get_ns());
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_softlimit_reclaim_end) {
    u64 dur = 0;
    dur = record.lookup(500)
    dur =  bpf_ktime_get_ns() - dur;
    memcg_softlimit_reclaim_hist.increment(dur/1000);
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_node_reclaim_begin) {
    record.update(600, bpf_ktime_get_ns());
    return 0;
}
TRACEPOINT_PROBE(vmscan, mm_vmscan_node_reclaim_end) {
    u64 dur = 0;
    dur = record.lookup(600)
    dur =  bpf_ktime_get_ns() - dur;
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
