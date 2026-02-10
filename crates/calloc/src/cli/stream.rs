use std::io::Write;
use std::path::PathBuf;

use clap::Args;

use crate::cli::common::{PagingArgs, SelectionArgs};
use crate::{Allocator, Error, IndexSnapshot, page_pack};

/// Arguments for `calloc stream`.
#[derive(Debug, Args)]
pub struct StreamArgs {
    #[command(flatten)]
    pub selection: SelectionArgs,
    #[command(flatten)]
    pub paging: PagingArgs,
    /// Optional output file path (defaults to stdout).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Runs `calloc stream`.
pub fn run(args: &StreamArgs) -> Result<(), Error> {
    let manifest = args.selection.load_manifest()?;
    let snapshot = IndexSnapshot::build(&manifest.index)?;
    let mut allocator = Allocator::new(snapshot, manifest.budget.clone());
    let (handle, pack, _receipt) = allocator.allocate_once(&manifest)?;

    let page_result = page_pack(
        &pack,
        args.paging.to_page_spec(),
        args.paging.cursor.as_deref(),
    );

    let free_result = allocator.free(&handle);
    let page = match (page_result, free_result) {
        (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        (Ok(page), Ok(())) => page,
    };

    if let Some(path) = &args.output {
        let mut output = serde_json::to_vec(&page)
            .map_err(|source| Error::Render(format!("json serialization failed: {source}")))?;
        output.push(b'\n');
        std::fs::write(path, output).map_err(|source| Error::io_at_path(path.clone(), source))?;
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        serde_json::to_writer(&mut lock, &page)
            .map_err(|source| Error::Render(format!("json serialization failed: {source}")))?;
        lock.write_all(b"\n")?;
    }

    Ok(())
}
