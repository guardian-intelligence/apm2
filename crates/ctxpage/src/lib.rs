//! Deterministic pagination for context block streams.
#![allow(missing_docs)]

pub mod cursor;
pub mod error;
pub mod io;
pub mod model;
pub mod paginator;
pub mod tokenizer;

pub use cursor::{CURSOR_ALGO_V1, CursorV1, decode_cursor, encode_cursor};
pub use error::{Error, ErrorCode};
pub use io::{
    compute_block_chain_curr, read_blocks_jsonl, read_blocks_jsonl_stream,
    read_blocks_jsonl_with_limits, write_blocks_jsonl,
};
pub use model::{
    BLOCK_CHAIN_DOMAIN_V1, Block, InspectReport, Page, PageBudget, PageBudgetReport, PageUsage,
    ReadLimits, Segment, StreamEnd, TruncationReason, WIRE_VERSION, WireEvent, ZERO_CHAIN,
};
pub use paginator::Paginator;
pub use tokenizer::TokenizerMode;
