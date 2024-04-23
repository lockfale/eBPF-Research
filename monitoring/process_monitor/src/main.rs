use clap::Parser;
use tokio::signal;
use tokio::time::Duration;
use csv::Writer;
use std::fs::File;
use aya::{programs::KProbe, Bpf, include_bytes_aligned};
use log::{info, warn};
use aya_log::BpfLogger;


#[derive(Parser, Debug)]
#[command(name = "Process Monitor", about, version, author)]
struct Args {
    #[arg(short, long)]
    process_name: String,
}

// async fn export_to_csv(mut writer: Writer<File>, data: u32) -> Result<(), csv::Error> {
//     writer.write_record(&[data.to_string()])?;
//     writer.flush()?;
//     Ok(())
// }


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    env_logger::init();
    println!("Monitoring process: {}", args.process_name);

    //  let mut bpf = Bpf::load_file("bpf_program.o")?;
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/ebpf_process/debug/process_monitor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/ebpf_process/release/process_monitor"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {e}")
    }
    // let mut perf_map = PerfBuffer::<u32>::new(bpf.map_mut("EVENTS")?)?;
    let program: &mut KProbe =
        bpf.program_mut("bpf_program")

    let mut writer = Writer::from_writer(File::create("output.csv")?);
    writer.write_record(&["PID"])?;

    perf_map.poll(Duration::from_millis(100), |ctx| {
        let pid = ctx.read();
        if let Ok(pid) = pid {
            if let Err(e) = writer.write_record(&[pid.to_string()]) {
                eprintln!("Failed to write to CSV: {}", e);
            }
        }
    })?;

    signal::ctrl_c().await.expect("Failed to listen for shutdown signal");
    println!("Shutting down the monitor...");

    Ok(())
}

