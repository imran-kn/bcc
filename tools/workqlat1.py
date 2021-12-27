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
	void *work;
	void *func;
};

BPF_HASH(counts, work_func_t);
BPF_HASH(run_time, struct key_t);
BPF_HASH(wait_time, struct key_t);
BPF_HISTOGRAM(run_hist);

TRACEPOINT_PROBE(workqueue, workqueue_execute_start) {
    struct work_struct *work = NULL;
    u64 *count = NULL;
    u64 *tsp = NULL;
    u64 val = 1;
    work_func_t func = NULL;
    struct key_t key = {};
    u64 time = 0;
    if (args != NULL) {
        work = args->work;
        if (work != NULL) {
		func = work->func;
		key.func = func;
		key.work = work;
		time = bpf_ktime_get_ns();
		run_time.update(&key, &time);
		count = counts.lookup(&func);
		if (count != NULL) {
			*count = *count + 1;
			counts.update(&func, count);
		} else {
			counts.update(&func, &val);	
		}

	}
    }
    
    return 0;
}

TRACEPOINT_PROBE(workqueue, workqueue_execute_end) {
    struct work_struct *work = NULL;
    u64 *tsp = NULL;
    work_func_t func = NULL;
    struct key_t key = {};
    u64 delta = 0;
    if (args != NULL) {
	work = args->work;
	if (work != NULL) {
		func = work->func;
		key.func = func;
		key.work = work;
		tsp = run_time.lookup(&key);
		if (tsp != NULL) {
			delta = bpf_ktime_get_ns() - *tsp;
			bpf_trace_printk("Hello work %lu delta %lu \\n", *tsp, delta);
			run_hist.increment(delta / 1000);
			run_time.delete(&key);
		}
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

    print("Work handler invocation count")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
       func = b.ksym(k)
       print(func.decode("utf-8"), v.value)
    print("Run duration histogram")
    b["run_hist"].print_linear_hist("microsecs")

    
    if exiting:
        exit()
        
