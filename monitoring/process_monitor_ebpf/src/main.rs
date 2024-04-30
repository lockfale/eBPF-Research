#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]


use aya_ebpf::{
    macros::{kprobe, map},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    maps::{PerfEventArray, Array},
    programs::ProbeContext,
    cty::c_void,
};

// Example C code for reference
/*
BPF_PERCPU_ARRAY(histogram, u32, MAX_SYSCALLS);

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    // filter by target pid
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != TARGET_PID) {
        return 0;
    }

    // populate histogram
    u32 key = (u32)args->id;
    u32 value = 0, *pval = NULL;
    pval = histogram.lookup_or_try_init(&key, &value);
    if(pval) {
        *pval += 1;
    }

    return 0;
}

*/

#[map]
static mut EVENTS: PerfEventArray<u32> = PerfEventArray::with_max_entries(1024 as u32, 0);

#[map]
static mut TARGET_NAME: Array<u8> = Array::with_max_entries(16, 0);  // Assuming max process name length of 15 + null terminator


#[tracepoint]
pub fn sys_execve(ctx: ProbeContext) -> i32 {
    let pid: u32 = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm: [u8; 16] = [0u8; 16]; // Buffer for the command name
    let task_struct_ptr: u64 = unsafe { bpf_get_current_task() as *const c_void as u64 };  // Assuming you have this helper or equivalent
    let comm_offset: i32 = 0x5c0; // Offset of the comm field in the task struct

    // Read the command name from the current task struct
    unsafe {
        let comm_ptr: *const u8 = (task_struct_ptr as usize + comm_offset as usize) as *const u8;

        if bpf_probe_read_kernel(comm_ptr as *const _).is_err() {
            return 0; // Fail silently if we can't read the command name
        }
    }

    // Get the target process name from the map
    let target_name: u8 = unsafe { TARGET_NAME.get(0).copied().unwrap_or_default() };

    // Convert the command name to a string
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    let target_name_array: [u8; 1] = [target_name];
    let target_name_str: &str = unsafe { core::str::from_utf8_unchecked(&target_name_array) };
    if comm_str == target_name_str {
        // Output the PID to the user space if the names match
        unsafe {
            EVENTS.output(&ctx, &pid, 0);
        }
    }

    0
}

#[panic_handler]
// Remove the panic function to avoid duplicate lang item error
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// #[no_mangle]
// pub extern "C" fn main() -> i32 {
//     // Return 0 to indicate success
//     0
// }

