use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "hbse-broker")]
#[command(about = "Hardware Bound Secrets Enclave broker daemon")]
struct Cli {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    #[arg(long, default_value_t = 0.0)]
    idle_timeout_seconds: f64,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = hbse::broker_daemon::serve(cli.vault, cli.socket, cli.idle_timeout_seconds) {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
