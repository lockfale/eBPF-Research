use clap::Parser;
use redbpf::load::Loader;

#[derive(Parser, Debug)]
struct Args {
    /// Name of process to monitor
    process_name: String,
}

fn main() {
    let args = Args::parse();
    let matches = App::new("eBPF Process Monitor")
        .arg(
            Parser::with_name("process-name")
                .long("process-name")
                .value_name("NAME")
                .help("The name of the process to monitor")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let process_name = matches.value_of("process-name").unwrap();

    let mut loader = Loader::new().expect("Failed to create loader");
    let mut module = loader.load(b"../../ebpf/target/bpf/program.elf").expect("Failed to load eBPF program");

    let target_process_name_map = module.map_mut("target_process_name").expect("Failed to find target_process_name map");
    target_process_name_map.write_bytes(process_name.as_bytes()).expect("Failed to write process name to map");

    // Write output to CSV file
}