#![no_std]
#![no_main]
use core::ptr;
use memoffset::offset_of;
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut TARGET_PID: PerfMap<u32> = PerfMap::with_max_entries(1024);

#[kprobe("sys_execve")]
pub extern "C" fn sys_execve(ctx: KProbeContext) -> i32 {
    if let Ok(command) = ctx.arg_cstr(1) {
        // Hardcoded target process name for simplicity
        if command.to_bytes() == b"target_process_name" {
            let pid = ctx.pid() as u32;
            unsafe {
                TARGET_PID.insert(&pid, &pid);
            }
        }
    }

    0
}
