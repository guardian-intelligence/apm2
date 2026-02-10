use std::io::{BufReader, Write};
use std::path::PathBuf;

use clap::Args;

use crate::Error;
use crate::cli::common::{PagingArgs, ReadLimitArgs};

/// Arguments for `calloc page`.
#[derive(Debug, Args)]
pub struct PageArgs {
    #[command(flatten)]
    pub paging: PagingArgs,
    #[command(flatten)]
    pub read_limits: ReadLimitArgs,
    /// Optional output file path (defaults to stdout).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Runs `calloc page`.
pub fn run(args: &PageArgs) -> Result<(), Error> {
    let paginator = ctxpage::Paginator::new(
        args.paging.to_page_spec().to_budget(),
        ctxpage::TokenizerMode::BytesDiv4,
        args.paging.to_page_spec().strict_cursor,
    )?;

    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let page = paginator.page_from_reader(
        reader,
        args.paging.cursor.as_deref(),
        args.read_limits.to_read_limits(),
        args.read_limits.require_stream_end,
    )?;

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
