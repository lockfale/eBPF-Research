
#!/usr/bin/python
from bcc import BPF

program = r"""

#struct syscalls_enter_kill_args {
#    long long pad ;
    
#    long syscall_nr ;
#    long pid ;
#    long sig ;
#};

#SEC ("tracepoint/syscalls/sys_enter_kill")
int kill_monitor(struct
    syscalls_enter_kill_args *ctx) {

    if (ctx->sig != 9) return 0;

    char fmt [] = "PID %u is being killed !\n";
    bpf_trace_printk (fmt, sizeof(fmt) , ctx->
      pid , sizeof(ctx -> pid));

    return 0;
}

#char _license [] SEC (" license ") = " GPL ";
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("sys_enter_kill")
b.attach_kprobe(event=syscall, fn_name="kill_monitor")

b.trace_print()