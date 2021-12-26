#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
# This is just a port of code given in Brendan Gregg's BPF book.
# This porting coverts bpftrace based code given in book to BCC


from __future__ import print_function
from bcc import BPF
from time import sleep
import re

src = """
#include <uapi/linux/ptrace.h>
#include <linux/workqueue.h>
struct key_t {
	void *func;
};

BPF_HASH(counts, work_func_t);

TRACEPOINT_PROBE(workqueue, workqueue_execute_start) {
    struct work_struct *work = NULL;
    u64 *count = NULL;
    u64 val = 1;
    work_func_t func = NULL;
    struct key_t key = {};
    if (args != NULL) {
        work = args->work;
        if (work != NULL) {
		func = work->func;
		key.func = func;
		count = counts.lookup(&func);
		if (count != NULL) {
			*count = *count + 1;
			counts.update(&func, count);
		} else {
			counts.update(&func, &val);	
		}

		bpf_trace_printk("Hello work %lx \\n", func);
	}
    }
    
    return 0;
}

"""

b = BPF(text=src)
counts = b["counts"]
while 1:
    try:
        sleep(99999999)
    except KeyboardInterrupt:
        exiting = 1

    print("Printing map", len(counts))
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
       func = b.ksym(k)
       print(func, v)
    #for k,v in rec.items():
        #print("work handler: ",k, "count: ", v) 

    counts.clear()

    
    if exiting:
        exit()
        
