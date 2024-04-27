#!/usr/bin/env python3
from bcc import BPF

program = r"""
#include <linux/sched.h>

struct data_t {
    u64 timestamp;
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int monitor(struct pt_regs *ctx) {
    struct data_t data = {};

    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tgid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

print("Field Headers")
b = BPF(text=program)
syscall = b.get_syscall_fnname("monitor")
b.attach_kprobe(event=syscall, fn_name="monitor")

b.trace_print()