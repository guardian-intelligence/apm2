#![allow(missing_docs)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use apm2_lab2::run::{run_rfc_control_from_path, run_sweep_from_path};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "apm2-lab2")]
#[command(about = "RFC control-loop laboratory harness")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run one RFC control-loop experiment.
    RunRfcControl {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        seed: u64,
    },
    /// Run multiple seeds and emit an aggregate summary.
    SweepRfcControl {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        seeds: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::RunRfcControl { spec, seed } => {
            let summary = run_rfc_control_from_path(spec, seed).await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        },
        Command::SweepRfcControl { spec, seeds } => {
            let seed_values = parse_csv_u64(&seeds)?;
            let summary = run_sweep_from_path(spec, &seed_values).await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        },
    }

    Ok(())
}

fn parse_csv_u64(input: &str) -> Result<Vec<u64>> {
    let values = input
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u64>()
                .with_context(|| format!("invalid seed '{part}'"))
        })
        .collect::<Result<Vec<_>>>()?;

    if values.is_empty() {
        anyhow::bail!("--seeds must include at least one value");
    }

    Ok(values)
}
