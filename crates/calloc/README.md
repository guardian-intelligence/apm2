# calloc

Deterministic context packaging and paging for agent bootstrap.

`calloc` is a minimal primitive:
- select files
- build a deterministic context pack
- emit a resumable paginated page

No framework required. No mandatory config files.

## Why

Most agent startups spend time on repeated file reads and unstable ordering.
`calloc` turns that into a deterministic pipeline:

1. **Ad hoc selection** (`--root`, `--include`, `--exclude`, positional paths)
2. **Deterministic pack build** (content-addressed blocks + stable ordering)
3. **Paginated output** (cursor-based resume, byte/token budgets)

## Install

```bash
cargo install calloc
```

## Quickstart

### 1) Build and page in one command

```bash
calloc stream \
  --root . \
  --include AGENTS.md \
  --include README.md \
  --include "crates/calloc/src/**/*.rs" \
  --page-max-bytes 120000
```

Output is one JSON line page with `cursor_out` for resume.

### 2) Resume next page

```bash
calloc stream \
  --root . \
  --include AGENTS.md \
  --include README.md \
  --include "crates/calloc/src/**/*.rs" \
  --page-max-bytes 120000 \
  --cursor "$CURSOR"
```

### 3) Build once, page later

```bash
calloc pack \
  --root . \
  --include AGENTS.md \
  --include README.md \
  --include "crates/calloc/src/**/*.rs" \
  --emit blocks-jsonl > pack.blocks.jsonl

calloc page --page-max-bytes 120000 < pack.blocks.jsonl
```

## CLI

### `calloc stream`

Ad hoc selection + deterministic build + one paginated page.

Key flags:
- `--root <path>` repeatable, default `.`
- `--include <glob>` repeatable
- `--exclude <glob>` repeatable
- positional `PATH` values are converted to include globs automatically
- `--max-file-bytes <u64>` default `524288`
- `--budget-bytes <u64>` optional
- `--budget-tokens-estimate <u64>` optional
- `--page-max-bytes <u64>` required
- `--page-max-tokens-est <u64>` optional
- `--page-max-segments <u32>` default `256`
- `--cursor <base64url>` optional
- `--no-strict-cursor` optional

### `calloc pack`

Build deterministic output without pagination.

Output modes:
- `--emit pack-json` (default): digest + file inventory + size/token stats
- `--emit blocks-jsonl`: full deterministic block stream with terminal `stream_end`

### `calloc page`

Page an existing `blocks-jsonl` stream from stdin.

```bash
cat pack.blocks.jsonl | calloc page --page-max-bytes 120000
```

Useful when build and paging happen in different processes.

## Optional Recipe Files

`calloc` is ad hoc-first. Recipe files are optional.

Use `--recipe <path>` to load an existing manifest (`.toml`) instead of ad hoc flags:

```bash
calloc stream --recipe .calloc.toml --page-max-bytes 120000
```

`--recipe` is mutually exclusive with ad hoc selection flags.

## Wire Contract

`--emit blocks-jsonl` uses line-delimited JSON records:
- `type=block`: path, digest, bytes, token estimate, base64 payload, chain fields
- `type=stream_end`: terminal integrity summary

Paging output (`calloc stream` / `calloc page`) is a JSON line page containing:
- `segments[]` (range + base64 payload)
- `usage` (bytes/tokens/segments)
- `cursor_out` (nullable)

## Determinism Guarantees

Given identical selection spec + identical file bytes:
- selected block set is identical
- block order is identical
- pack digest is identical
- `blocks-jsonl` bytes are identical

## Security and Robustness

- content-addressed block digests (BLAKE3)
- chain validation per block in stream format
- cursor budget fingerprint validation (strict by default)
- bounded parser limits for `calloc page` (`max_input_bytes`, `max_line_bytes`, `max_decoded_block_bytes`)

## Rust API

```rust
use calloc::{PageSpec, SelectionSpec, build_pack, page_pack};

let mut selection = SelectionSpec::default();
selection.includes = vec!["README.md".to_string(), "src/**/*.rs".to_string()];

let pack = build_pack(&selection)?;
let page = page_pack(
    &pack,
    PageSpec {
        max_bytes: 120_000,
        max_tokens_estimate: None,
        max_segments: 256,
        strict_cursor: true,
    },
    None,
)?;

println!("cursor_out={:?}", page.cursor_out);
# Ok::<(), calloc::Error>(())
```

## Development

```bash
cargo fmt --all --check
cargo clippy -p calloc --all-targets --all-features -- -D warnings
cargo test -p calloc
cargo bench -p calloc --bench alloc_bench
```

## License

MIT OR Apache-2.0
