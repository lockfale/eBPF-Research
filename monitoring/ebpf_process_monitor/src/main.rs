use clap::Parser;
use redbpf::load::Loader;
use std::fs::File;
use std::io::Write;
use csv::Writer;
use tokio::signal;

/// Monitor process activity and export to CSV.
#[derive(Parser, Debug)]
#[command(name = "Process Monitor", author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"), about = "Monitor a process's system calls")]
struct Args {
    /// Name of the process to monitor
    #[arg(long, short)]
    process_name: String,
}

async fn load_and_attach_bpf(program_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut loaded = Loader::load_file(program_file)?;
    for prog in loaded.kprobes_mut() {
        println!("Loading: {}", prog.name());
        prog.attach()?;
    }
    Ok(())
}


async fn monitor_process_to_csv(mut writer: Writer<File>) -> Result<(), Box<dyn std::error::Error>> {
    // Simulated eBPF event loop
    loop {
        // Imagine this is an event from the eBPF program
        let event = ("syscall", "details", 123);
        writer.write_record(&[event.0, event.1, &event.2.to_string()])?;
        writer.flush()?;
        
        if signal::ctrl_c().await.is_ok() {
            break;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("Monitoring process: {}", args.process_name);

    load_and_attach_bpf("path_to_ebpf_program.o").await?;

    let file = File::create("output.csv")?;
    let writer = Writer::from_writer(file);
    monitor_process_to_csv(writer).await?;

    Ok(())
}