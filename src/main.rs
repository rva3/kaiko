use std::{fs, path::PathBuf};

use clap::Parser;
use clap_num::maybe_hex;
use kaiko::{Analyzer, cpu_mode::CpuMode, err::Error};
use tracing::{error, info};

#[derive(Parser)]
struct Cli {
    /// Input file
    #[arg(short, long)]
    input: PathBuf,

    /// String to search for
    #[arg(short, long)]
    s: Option<String>,

    /// Binary base address
    #[arg(short, long, value_parser=maybe_hex::<usize>)]
    base: usize,

    /// Binary entrypoint
    #[arg(short, long, value_parser=maybe_hex::<usize>)]
    offset: Option<usize>,
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    let data = fs::read(cli.input).unwrap();

    info!("start analysis");
    let analyzer =
        Analyzer::try_new(data, cli.base, cli.offset.unwrap_or(0), CpuMode::Arm).unwrap();

    if let Some(s) = cli.s {
        if let Some(mut iter) = analyzer.fns_by_str(&s) {
            while let Some(f) = iter.next() {
                info!("{f}");
            }
            info!("done");
        } else {
            error!("can't find string in the binary");
        }
    }

    Ok(())
}
