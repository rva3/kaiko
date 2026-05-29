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
    #[arg(short, long, value_parser=maybe_hex::<u32>)]
    base: u32,

    /// Binary entrypoint
    #[arg(short, long, value_parser=maybe_hex::<u32>)]
    offset: Option<u32>,
}

fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    let data = fs::read(cli.input).map_err(|e| e.to_string())?;

    info!("start analysis");
    let analyzer = Analyzer::try_new(&data, cli.base, cli.offset.unwrap_or(0), CpuMode::Arm)
        .map_err(|e| e.to_string())?;

    if let Some(s) = cli.s {
        if let Some(fns) = analyzer.fns_by_str(&s) {
            for f in fns {
                info!("{f}");
            }
            info!("done");
        } else {
            error!("can't find string in the binary");
        }
    }

    Ok(())
}
