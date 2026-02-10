#![allow(missing_docs)]

use std::io::{BufReader, Write};

use clap::{Args, Parser, Subcommand};
use ctxpage::error::ErrorCode;
use ctxpage::{
    Error, InspectReport, PageBudget, Paginator, ReadLimits, TokenizerMode, WIRE_VERSION,
    read_blocks_jsonl_with_limits,
};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "ctxpage")]
#[command(about = "Deterministic pagination for large context streams")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long)]
    json_errors: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit one page for the current cursor.
    Page(PageArgs),
    /// Emit all pages as NDJSON.
    Stream(StreamArgs),
    /// Report stream totals and projected page count.
    Inspect(InspectArgs),
    /// Cursor operations.
    Cursor(CursorArgs),
}

#[derive(Debug, Args)]
struct PageArgs {
    #[command(flatten)]
    budget: BudgetArgs,
    /// Resume cursor from a previous page response.
    #[arg(long)]
    cursor: Option<String>,
}

#[derive(Debug, Args)]
struct StreamArgs {
    #[command(flatten)]
    budget: BudgetArgs,
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[command(flatten)]
    budget: BudgetArgs,
}

#[derive(Debug, Args)]
struct CursorArgs {
    #[command(subcommand)]
    command: CursorCommand,
}

#[derive(Debug, Subcommand)]
enum CursorCommand {
    /// Validate a cursor against the current input stream and budget config.
    Verify(CursorVerifyArgs),
}

#[derive(Debug, Args)]
struct CursorVerifyArgs {
    #[command(flatten)]
    budget: BudgetArgs,
    /// Cursor text to validate.
    #[arg(long)]
    cursor: String,
}

#[derive(Debug, Args, Clone, Copy)]
struct BudgetArgs {
    /// Maximum bytes allowed in a single page.
    #[arg(long)]
    max_bytes: u64,
    /// Optional token estimate cap per page.
    #[arg(long)]
    max_tokens_estimate: Option<u64>,
    /// Maximum number of segments per page.
    #[arg(long, default_value_t = 256)]
    max_segments: u32,
    /// Token estimation strategy.
    #[arg(long, default_value = "bytes_div_4")]
    tokenizer: TokenizerArg,
    /// Allow cursor continuation when budget fingerprint changed.
    #[arg(long)]
    no_strict_cursor: bool,
    /// Maximum total stdin bytes accepted.
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    max_input_bytes: u64,
    /// Maximum size of a single JSONL line.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_line_bytes: usize,
    /// Maximum decoded bytes allowed for one block record.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_decoded_block_bytes: u64,
    /// Require a `stream_end` record at EOF.
    #[arg(long, default_value_t = true)]
    require_stream_end: bool,
}

#[derive(Debug, Clone, Copy)]
struct TokenizerArg(TokenizerMode);

impl std::str::FromStr for TokenizerArg {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(input.parse::<TokenizerMode>()?))
    }
}

impl BudgetArgs {
    fn to_paginator(self) -> Result<Paginator, Error> {
        let budget = PageBudget {
            max_bytes: self.max_bytes,
            max_tokens_estimate: self.max_tokens_estimate,
            max_segments: self.max_segments,
        };
        Paginator::new(budget, self.tokenizer.0, !self.no_strict_cursor)
    }

    const fn to_limits(self) -> ReadLimits {
        ReadLimits {
            max_input_bytes: Some(self.max_input_bytes),
            max_line_bytes: Some(self.max_line_bytes),
            max_decoded_block_bytes: Some(self.max_decoded_block_bytes),
        }
    }
}

#[derive(Debug, Serialize)]
struct CursorVerifyOutput {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    ok: bool,
    next_block_index: u32,
    next_offset: u64,
}

#[derive(Debug, Serialize)]
struct ErrorOutput {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    ok: bool,
    code: &'static str,
    message: String,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(&cli) {
        emit_error(&error, cli.json_errors);
        std::process::exit(2);
    }
}

fn run(cli: &Cli) -> Result<(), Error> {
    match &cli.command {
        Command::Page(args) => run_page(args),
        Command::Stream(args) => run_stream(args),
        Command::Inspect(args) => run_inspect(args),
        Command::Cursor(args) => run_cursor(args),
    }
}

fn run_page(args: &PageArgs) -> Result<(), Error> {
    let paginator = args.budget.to_paginator()?;
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let page = paginator.page_from_reader(
        reader,
        args.cursor.as_deref(),
        args.budget.to_limits(),
        args.budget.require_stream_end,
    )?;
    write_json_line(&page)?;
    Ok(())
}

fn run_stream(args: &StreamArgs) -> Result<(), Error> {
    let paginator = args.budget.to_paginator()?;
    let blocks = read_stdin_blocks(args.budget)?;
    let pages = paginator.stream_pages(&blocks)?;
    for page in pages {
        write_json_line(&page)?;
    }
    Ok(())
}

fn run_inspect(args: &InspectArgs) -> Result<(), Error> {
    let paginator = args.budget.to_paginator()?;
    let blocks = read_stdin_blocks(args.budget)?;
    let pages = paginator.stream_pages(&blocks)?;
    let Some(first) = blocks.first() else {
        return Err(Error::InvalidInputStream {
            message: "no block records found on stdin".to_string(),
        });
    };

    let total_bytes = blocks.iter().fold(0_u64, |sum, block| {
        sum.saturating_add(u64::try_from(block.len()).unwrap_or(u64::MAX))
    });
    let total_tokens_estimate = blocks
        .iter()
        .fold(0_u64, |sum, block| sum.saturating_add(block.token_estimate));

    let report = InspectReport {
        v: WIRE_VERSION,
        kind: "inspect",
        pack_digest: hex::encode(first.pack_digest),
        total_blocks: blocks.len(),
        total_bytes,
        total_tokens_estimate,
        projected_pages: pages.len(),
        budget: paginator.budget().into(),
    };
    write_json_line(&report)?;
    Ok(())
}

fn run_cursor(args: &CursorArgs) -> Result<(), Error> {
    match &args.command {
        CursorCommand::Verify(verify_args) => run_cursor_verify(verify_args),
    }
}

fn run_cursor_verify(args: &CursorVerifyArgs) -> Result<(), Error> {
    let paginator = args.budget.to_paginator()?;
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let cursor = paginator.verify_cursor_from_reader(
        reader,
        &args.cursor,
        args.budget.to_limits(),
        args.budget.require_stream_end,
    )?;
    let output = CursorVerifyOutput {
        v: WIRE_VERSION,
        kind: "cursor_verify",
        ok: true,
        next_block_index: cursor.next_block_index,
        next_offset: cursor.next_offset,
    };
    write_json_line(&output)?;
    Ok(())
}

fn read_stdin_blocks(args: BudgetArgs) -> Result<Vec<ctxpage::Block>, Error> {
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    read_blocks_jsonl_with_limits(reader, args.to_limits(), args.require_stream_end)
}

fn write_json_line<T: Serialize>(value: &T) -> Result<(), Error> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value)?;
    lock.write_all(b"\n")?;
    Ok(())
}

fn emit_error(error: &Error, json_errors: bool) {
    if json_errors {
        let output = ErrorOutput {
            v: WIRE_VERSION,
            kind: "error",
            ok: false,
            code: error.code().as_str(),
            message: error.to_string(),
        };
        let stderr = std::io::stderr();
        let mut lock = stderr.lock();
        let _ = serde_json::to_writer(&mut lock, &output);
        let _ = lock.write_all(b"\n");
        return;
    }
    let code: ErrorCode = error.code();
    eprintln!("error [{}]: {}", code.as_str(), error);
}
