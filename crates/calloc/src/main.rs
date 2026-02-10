#![allow(missing_docs)]

use calloc::cli::Cli;
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = calloc::cli::run(cli) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
