#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
# This is just a port of code given in Brendan Gregg's BPF book.
# This porting coverts bpftrace based code given in book to BCC


from __future__ import print_function
from bcc import BPF
from time import sleep

src="""
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist);
BPF_HASH(record, void*);

TRACEPOINT_PROBE(workqueue, workqueue_queue_work) {
    void *work = NULL;
    u64 ts = bpf_ktime_get_ns();
    if (args != NULL)
        work = args->work;
    record.update(&work, &ts);

    return 0;
}

TRACEPOINT_PROBE(workqueue, workqueue_execute_start) {
    void *work = NULL;
    u64 *ts = NULL;
    u64 delta = 0;
    if (args != NULL) {
        work = args->work;
        ts = record.lookup(&work);
    }
    if (ts != NULL) {
        delta = bpf_ktime_get_ns() - *ts;
        bpf_trace_printk("delta = %ul \\n", delta);
        dist.increment(delta);
    
        record.delete(&work);
    }    
    
    return 0;
}
"""

b = BPF(text=src)
dist = b.get_table("dist")
while 1:
    try:
        sleep(99999999)
    except KeyboardInterrupt:
        exiting = 1

    print("Printing histogram")
    dist.print_linear_hist("Miliseconds")
    dist.clear()

    
    if exiting:
        exit()
        
