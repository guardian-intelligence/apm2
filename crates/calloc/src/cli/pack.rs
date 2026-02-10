use std::io::Write;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use serde::Serialize;

use crate::cli::common::SelectionArgs;
use crate::wire::write_pack_blocks_jsonl;
use crate::{Allocator, Error, IndexSnapshot};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EmitFormat {
    #[value(name = "pack-json")]
    PackJson,
    #[value(name = "blocks-jsonl")]
    BlocksJsonl,
}

/// Arguments for `calloc pack`.
#[derive(Debug, Args)]
pub struct PackArgs {
    #[command(flatten)]
    pub selection: SelectionArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = EmitFormat::PackJson)]
    pub emit: EmitFormat,
    /// Output path (defaults to stdout).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct PackOutput {
    ordering_version: &'static str,
    pack_digest: String,
    block_count: usize,
    total_bytes: u64,
    estimated_tokens: u64,
    files: Vec<PackFile>,
    generated_at: String,
}

#[derive(Debug, Serialize)]
struct PackFile {
    path: String,
    digest: String,
    bytes: u64,
    estimated_tokens: u64,
}

/// Runs `calloc pack`.
pub fn run(args: &PackArgs) -> Result<(), Error> {
    let manifest = args.selection.load_manifest()?;
    let snapshot = IndexSnapshot::build(&manifest.index)?;
    let mut allocator = Allocator::new(snapshot, manifest.budget.clone());

    allocator.can_allocate(&manifest)?;
    let (handle, pack, receipt) = allocator.allocate_once(&manifest)?;

    let write_result = match args.emit {
        EmitFormat::PackJson => write_pack_json(args, &pack, &receipt),
        EmitFormat::BlocksJsonl => write_blocks(args, &pack),
    };

    let free_result = allocator.free(&handle);
    match (write_result, free_result) {
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn write_pack_json(
    args: &PackArgs,
    pack: &crate::ContextPack,
    receipt: &crate::AllocationReceipt,
) -> Result<(), Error> {
    let payload = PackOutput {
        ordering_version: receipt.ordering_version,
        pack_digest: hex::encode(pack.digest),
        block_count: pack.block_count(),
        total_bytes: pack.total_bytes,
        estimated_tokens: pack.estimated_tokens,
        files: pack
            .blocks
            .iter()
            .map(|block| PackFile {
                path: block.source_path.to_string_lossy().into_owned(),
                digest: hex::encode(block.digest),
                bytes: u64::try_from(block.len()).unwrap_or(u64::MAX),
                estimated_tokens: block.estimated_tokens,
            })
            .collect(),
        generated_at: receipt.created_at.to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&payload)
        .map_err(|error| Error::Render(format!("json serialization failed: {error}")))?;

    if let Some(path) = &args.output {
        std::fs::write(path, json).map_err(|source| Error::io_at_path(path.clone(), source))?;
    } else {
        println!("{json}");
    }

    Ok(())
}

fn write_blocks(args: &PackArgs, pack: &crate::ContextPack) -> Result<(), Error> {
    if let Some(path) = &args.output {
        let mut file = std::fs::File::create(path)
            .map_err(|source| Error::io_at_path(path.clone(), source))?;
        write_pack_blocks_jsonl(pack, &mut file)?;
        file.flush()?;
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        write_pack_blocks_jsonl(pack, &mut lock)?;
        lock.flush()?;
    }

    Ok(())
}
