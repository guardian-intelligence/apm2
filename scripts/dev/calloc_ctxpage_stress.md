# calloc + ctxpage Benchmark and Stress Scenarios

This suite has two layers:

1. **Micro-benchmarks (Criterion)** for allocator and paginator hot paths.
2. **Scenario stress runs (CLI integration)** that exercise real end-to-end behavior, including `documents/theory`.

## Criterion Benchmarks

### `calloc`

```bash
cargo bench -p calloc --bench alloc_bench
```

Bench groups:
- `calloc/cold_index_allocate`
- `calloc/hot_allocate`
- `calloc/raw_render`

### `ctxpage`

```bash
cargo bench -p ctxpage --bench pagination_bench
```

Bench groups:
- `ctxpage/parse_stream`
- `ctxpage/page_from_reader`
- `ctxpage/stream_pages`

## Stress Scenario Runner

Script:

```bash
./scripts/dev/run_calloc_ctxpage_stress.sh
```

Artifacts are written to:

- `target/calloc_ctxpage_stress/run-<timestamp>/`

Key outputs:
- `results.tsv` (machine-friendly status + timing)
- `summary.md` (human summary)
- scenario logs (`*.log`)
- generated pack/page/inspect JSON files

## Included Scenarios

### 1) Synthetic Scale Stress

- Generates a large synthetic Rust source tree.
- Runs `calloc pack --emit pack-json` and `calloc pack --emit blocks-jsonl`.
- Runs `ctxpage inspect`, `ctxpage page`, cursor verify/resume across multiple pages.
- Includes one inline pipeline command:
  - `calloc stream --page-max-bytes ...`

### 2) Advanced Real-Repo Scenario (`documents/theory`)

- Builds a purpose-specific manifest rooted in `documents/theory` and related docs.
- Runs repeated `calloc pack` and checks digest stability.
- Runs repeated `calloc pack --emit blocks-jsonl` and checks SHA stability.
- Runs inline and decoupled pagination flows with `ctxpage`.
- Exercises cursor verification and page resume.

## Useful Flags

```bash
./scripts/dev/run_calloc_ctxpage_stress.sh \
  --synthetic-files 5000 \
  --synthetic-bytes 1536 \
  --max-pages 5 \
  --page-budgets 98304,131072,262144
```

Other options:
- `--out-base <dir>`
- `--skip-build`
