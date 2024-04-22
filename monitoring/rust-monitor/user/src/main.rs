use clap::Parser;
use redbpf::load::{Loader, Loaded};
use redbpf::HashMap;
use tokio::signal;
use tokio::time::{self, Duration};

#[derive(Parser, Debug)]
#[clap(author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"), about = "A very simple eBPF process monitor")]
/// A very simple process monitor for eBPF that logs to CSV
struct Arguments {
    #[clap(default_value_t=String::from("openssl"), value_parser = validate_process_name)]
    /// Name of process to monitor
    process_name: String,
    
}

fn validate_process_name(name: &str) -> Result<(), String> {
    if name.trim().len() != name.len() {
        Err(String::from(
            "process name cannot have leading or trailing spaces",
        ))
    } else if name.is_empty() {
            Err(String::from("Process name cannot be empty"))
    } else {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arguments::parse();
    let target_process_name = args.process_name;   

    println!("Monitoring process: {}", target_process_name);

    let mut loaded = Loader::load_file("../../ebpf/target/bpf/probe.elf").expect("Failed to load eBPF program");
   
   
    // Handle BPF events
    tokio::spawn(async move {
        while let Some((map_name, events)) = loaded.events.next().await {
            for event in events {
                // Process each event
                println!("Event from map '{}': {:?}", map_name, event);
            }
        }
    });

    // Assuming there's some shutdown mechanism or signal handling
    tokio::signal::ctrl_c().await.expect("failed to listen for event");
    println!("Shutdown signal received, terminating...");

    Ok(())
}