# ctxpage

Deterministic pagination for large context streams.

`ctxpage` is a standalone CLI and Rust library that slices a block stream into bounded, resumable pages.

It is built as a core primitive for agent systems:
- strict wire format
- deterministic pagination
- verifiable resume cursors
- bounded input and output behavior

## What It Solves

Many model harnesses cannot accept full context in one call.

You need to:
- cap bytes/tokens per request
- continue from an exact point
- validate that resumed context still matches source data

`ctxpage` provides this with a small API surface and explicit invariants.

## Core Guarantees

For identical input stream + budget + cursor:
- page segmentation is deterministic
- cursor generation is deterministic
- resume behavior is deterministic

Integrity guarantees:
- each block validates `block_digest`
- each block validates chain continuity (`chain_prev` -> `chain_curr`)
- terminal `stream_end` validates `total_blocks`, `total_bytes`, and `final_chain`
- cursor resume is bound to pack digest, budget fingerprint (strict mode), and expected chain state

## Install

CLI:

```bash
cargo install ctxpage
```

Library:

```bash
cargo add ctxpage
```

## Wire Protocol (`blocks-jsonl`, v1)

Input is JSONL with two record types.

### `block` record

```json
{
  "v": 1,
  "type": "block",
  "pack_digest": "...64-hex...",
  "block_index": 0,
  "path": "README.md",
  "block_digest": "...64-hex...",
  "byte_len": 1234,
  "token_estimate": 308,
  "content_b64": "...",
  "chain_prev": "...64-hex...",
  "chain_curr": "...64-hex..."
}
```

### `stream_end` record (terminal)

```json
{
  "v": 1,
  "type": "stream_end",
  "pack_digest": "...64-hex...",
  "total_blocks": 42,
  "total_bytes": 104857,
  "final_chain": "...64-hex..."
}
```

Default behavior requires `stream_end` at EOF.

## CLI

Top-level commands:
- `ctxpage page`
- `ctxpage stream`
- `ctxpage inspect`
- `ctxpage cursor verify`

### `ctxpage page`

Emit one page:

```bash
cat blocks.jsonl | ctxpage page --max-bytes 120000
cat blocks.jsonl | ctxpage page --max-bytes 120000 --cursor "$CURSOR"
```

### `ctxpage stream`

Emit all pages as NDJSON:

```bash
cat blocks.jsonl | ctxpage stream --max-bytes 120000
```

### `ctxpage inspect`

Report stream totals and projected page count:

```bash
cat blocks.jsonl | ctxpage inspect --max-bytes 120000
```

### `ctxpage cursor verify`

Validate cursor compatibility with current stream + budget:

```bash
cat blocks.jsonl | ctxpage cursor verify --max-bytes 120000 --cursor "$CURSOR"
```

### Common budget flags

- `--max-bytes <u64>` required
- `--max-tokens-estimate <u64>` optional
- `--max-segments <u32>` default `256`
- `--tokenizer <mode>` default `bytes_div_4`
- `--no-strict-cursor` optional

Tokenizer modes:
- `bytes_div_4`
- `utf8_char_heuristic`
- `fixed_ratio:<N>`

### Input safety flags

- `--max-input-bytes` default `536870912`
- `--max-line-bytes` default `16777216`
- `--max-decoded-block-bytes` default `16777216`
- `--require-stream-end` (enabled by default)

Machine-readable errors:

```bash
ctxpage --json-errors page --max-bytes 120000
```

## Page Output

`ctxpage page` emits one JSON object:

```json
{
  "v": 1,
  "type": "page",
  "pack_digest": "...",
  "page_index": 0,
  "cursor_in": null,
  "cursor_out": "...base64url...",
  "budget": {
    "max_bytes": 120000,
    "max_tokens_estimate": null,
    "max_segments": 256
  },
  "usage": {
    "bytes": 118044,
    "tokens_estimate": 29511,
    "segments": 73
  },
  "segments": [
    {
      "block_index": 0,
      "path": "README.md",
      "block_digest": "...",
      "range_start": 0,
      "range_end_exclusive": 1024,
      "content_b64": "..."
    }
  ],
  "truncated": true,
  "truncation_reason": "max_bytes"
}
```

If `cursor_out` is `null`, you reached end-of-stream.

## Cursor Semantics

Cursor payload (`CursorV1`) includes:
- protocol version
- pack digest
- resume coordinates (`next_block_index`, `next_offset`)
- next page index
- algorithm id (`greedy-v1`)
- budget fingerprint
- expected chain state at resume

Strict mode (default) rejects resume when budget fingerprint changes.

## Compose with `calloc`

```bash
calloc inject --output-format blocks-jsonl \
  | ctxpage page --max-bytes 120000
```

Or delegate directly:

```bash
calloc inject --paginate --max-bytes 120000
```

## Rust API

Parse stream and page in-process:

```rust
use std::io::Cursor;

use ctxpage::{PageBudget, Paginator, TokenizerMode, read_blocks_jsonl_with_limits, ReadLimits};

let blocks = read_blocks_jsonl_with_limits(
    Cursor::new(input_bytes),
    ReadLimits::bounded_default(),
    true,
)?;

let paginator = Paginator::new(
    PageBudget {
        max_bytes: 120_000,
        max_tokens_estimate: None,
        max_segments: 256,
    },
    TokenizerMode::BytesDiv4,
    true,
)?;

let page = paginator.page_from_cursor(&blocks, None)?;
println!("segments={}", page.usage.segments);
# Ok::<(), ctxpage::Error>(())
```

Stream directly from a `BufRead` source without collecting all blocks first:

```rust
use std::io::Cursor;

use ctxpage::{PageBudget, Paginator, ReadLimits, TokenizerMode};

let paginator = Paginator::new(
    PageBudget {
        max_bytes: 120_000,
        max_tokens_estimate: None,
        max_segments: 256,
    },
    TokenizerMode::BytesDiv4,
    true,
)?;

let page = paginator.page_from_reader(
    Cursor::new(input_bytes),
    None,
    ReadLimits::bounded_default(),
    true,
)?;
# Ok::<(), ctxpage::Error>(())
```

## Error Codes

- `INVALID_INPUT_STREAM`
- `INPUT_LIMIT_EXCEEDED`
- `UNSUPPORTED_VERSION`
- `PACK_DIGEST_MISMATCH`
- `CHAIN_MISMATCH`
- `STREAM_END_MISSING`
- `INVALID_CURSOR`
- `CURSOR_BUDGET_MISMATCH`
- `BUDGET_TOO_SMALL`
- `IO`
- `SERIALIZATION`
- `INTERNAL`

## Development

```bash
cargo fmt --all --check
cargo clippy -p ctxpage --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p ctxpage --no-deps --all-features
cargo test -p ctxpage
```

## Benchmarking

```bash
cargo bench -p ctxpage --bench pagination_bench
```

For end-to-end stress scenarios combined with `calloc`:

```bash
./scripts/dev/run_calloc_ctxpage_stress.sh
```

## License

Licensed under either:
- MIT
- Apache-2.0

at your option.
