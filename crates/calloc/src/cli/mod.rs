use clap::{Parser, Subcommand};

use crate::Error;

pub mod common;
pub mod pack;
pub mod page;
pub mod stream;

/// `calloc` command-line interface.
#[derive(Debug, Parser)]
#[command(name = "calloc")]
#[command(about = "Convert files into deterministic, paginated context for agents")]
pub struct Cli {
    /// Command to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level CLI commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Build a deterministic pack from ad hoc file-selection flags.
    Pack(pack::PackArgs),
    /// Build and emit one paginated page directly from selected files.
    Stream(stream::StreamArgs),
    /// Page an existing block JSONL stream from stdin.
    Page(page::PageArgs),
}

/// Runs CLI command.
pub fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Commands::Pack(args) => pack::run(&args),
        Commands::Stream(args) => stream::run(&args),
        Commands::Page(args) => page::run(&args),
    }
}
