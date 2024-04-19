use redbpf_probes::prelude::*;
use std::collections::HashMap;
use sysinfo::{ProcessExt, System, SystemExt};

// Define an eBPF map to store the target process name
#[map]
static mut TARGET_PROCESS_NAME: PerfString<256> = PerfString::with_max_len(256);

#[map]
static mut PROCESS_ACTIVITY: HashMap<u32, u64> = HashMap::with_max_entries(10240);

#[tracepoint]
fn sys_enter_execve(ctx: *const TracepointContext) -> i32 {
    let process_name: &str = unsafe { TARGET_PROCESS_NAME.content() };

    if let Some(target_pid) = get_process_pid(process_name) {
        let pid_tgid: u32 = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;
        let tgid = pid_tgid as u32;

        if tgid == target_pid || pid == target_pid {
            let count = unsafe { PROCESS_ACTIVITY.get_mut(&pid).unwrap_or(&mut 0) };
            *count += 1;
        }
    }

    0
}


fn get_process_pid(process_name: &str) -> Option<u32> {
    let mut system = System::new();
    system.refresh_processes();

    for (pid, process) in system.processes() {
        if process.name() == process_name {
            return Some(*pid);
        }
    }

    None
}