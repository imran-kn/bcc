#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
# This is just a port of code given in Brendan Gregg's BPF book.
# This porting coverts bpftrace based code given in book to BCC


from __future__ import print_function
from bcc import BPF

src="""
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist);
BPF_HASH(record);

TRACEPOINT_PROBE(workqueue, workqueue_queue_work) {
    u64 ts = bpf_ktime_get_ns();
    u64 work = args->work;
    record.update(&work, &ts);
}

TRACEPOINT_PROBE(workqueue, workqueue_execute_start) {
    u64 work = args->work;
    u64 *ts = record.lookup(&work);
    u64 delta = 0;
    delta = bpf_ktime_get_ns() - *ts;
    dist.increment(delta);
    
    record.delete(&work);
}
"""

b = BPF(text=src)
dist = b.get_table("dist")
while 1:
    try:
        sleep(99999999)
    except KeyboardInterrupt:
        exiting = 1

    dist.print_hist("Miliseconds")
    dist.clear()

    
    if exiting:
        exit()
        
