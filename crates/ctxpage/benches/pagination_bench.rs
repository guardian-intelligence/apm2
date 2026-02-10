//! Criterion benchmarks for `ctxpage` pagination and cursor verification.
#![allow(missing_docs)]

use std::io::Cursor;
use std::sync::Arc;

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use ctxpage::{
    Block, PageBudget, Paginator, ReadLimits, TokenizerMode, ZERO_CHAIN, compute_block_chain_curr,
    read_blocks_jsonl_with_limits, write_blocks_jsonl,
};

fn make_block_bytes(index: usize, target_len: usize) -> Vec<u8> {
    let token = format!("block-{index:06}-");
    let mut bytes = Vec::new();
    while bytes.len() < target_len {
        bytes.extend_from_slice(token.as_bytes());
    }
    bytes.truncate(target_len);
    bytes
}

fn build_blocks(block_count: usize, block_bytes: usize) -> Vec<Block> {
    let pack_material = format!("ctxpage-bench-pack:{block_count}:{block_bytes}");
    let pack_digest = *blake3::hash(pack_material.as_bytes()).as_bytes();

    let mut blocks = Vec::with_capacity(block_count);
    let mut chain = ZERO_CHAIN;

    for index in 0..block_count {
        let path = format!("src/module_{:03}/file_{index:05}.rs", index % 64);
        let bytes = make_block_bytes(index, block_bytes);
        let block_digest = *blake3::hash(&bytes).as_bytes();
        let block_index = u32::try_from(index).unwrap_or(u32::MAX);

        let mut block = Block {
            pack_digest,
            block_index,
            path,
            block_digest,
            bytes: Arc::from(bytes.into_boxed_slice()),
            token_estimate: u64::try_from(block_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(3)
                / 4,
            chain_prev: chain,
            chain_curr: [0; 32],
        };

        block.chain_curr = compute_block_chain_curr(&block).expect("compute block chain");
        chain = block.chain_curr;
        blocks.push(block);
    }

    blocks
}

fn encode_stream(blocks: &[Block]) -> Vec<u8> {
    let mut output = Vec::new();
    write_blocks_jsonl(&mut output, blocks).expect("encode blocks stream");
    output
}

fn paginator(max_bytes: u64) -> Paginator {
    Paginator::new(
        PageBudget {
            max_bytes,
            max_tokens_estimate: None,
            max_segments: 512,
        },
        TokenizerMode::BytesDiv4,
        true,
    )
    .expect("create paginator")
}

fn bench_parse_stream(c: &mut Criterion) {
    let blocks = build_blocks(2_000, 2_048);
    let stream = encode_stream(&blocks);
    let limits = ReadLimits::bounded_default();

    let mut group = c.benchmark_group("ctxpage/parse_stream");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(
        u64::try_from(stream.len()).unwrap_or(u64::MAX),
    ));

    group.bench_function("read_blocks_jsonl_with_limits", |b| {
        b.iter(|| {
            let parsed = read_blocks_jsonl_with_limits(
                Cursor::new(black_box(stream.as_slice())),
                limits,
                true,
            )
            .expect("parse stream");
            black_box(parsed.len());
        });
    });

    group.finish();
}

fn bench_page_from_reader(c: &mut Criterion) {
    let blocks = build_blocks(2_000, 2_048);
    let stream = encode_stream(&blocks);
    let limits = ReadLimits::bounded_default();
    let paginator = paginator(128 * 1024);

    let mut group = c.benchmark_group("ctxpage/page_from_reader");
    group.sample_size(25);
    group.throughput(Throughput::Bytes(
        u64::try_from(stream.len()).unwrap_or(u64::MAX),
    ));

    group.bench_function("first_page", |b| {
        b.iter(|| {
            let page = paginator
                .page_from_reader(
                    Cursor::new(black_box(stream.as_slice())),
                    None,
                    limits,
                    true,
                )
                .expect("render first page");
            black_box(page.usage.bytes);
        });
    });

    let first_page = paginator
        .page_from_reader(Cursor::new(stream.as_slice()), None, limits, true)
        .expect("prepare first page");
    let cursor = first_page.cursor_out.expect("first page cursor");

    group.bench_function("resume_page", |b| {
        b.iter(|| {
            let page = paginator
                .page_from_reader(
                    Cursor::new(black_box(stream.as_slice())),
                    Some(&cursor),
                    limits,
                    true,
                )
                .expect("render resume page");
            black_box(page.usage.bytes);
        });
    });

    group.bench_function("verify_cursor", |b| {
        b.iter(|| {
            let verified = paginator
                .verify_cursor_from_reader(
                    Cursor::new(black_box(stream.as_slice())),
                    &cursor,
                    limits,
                    true,
                )
                .expect("verify cursor");
            black_box(verified.next_offset);
        });
    });

    group.finish();
}

fn bench_stream_pages(c: &mut Criterion) {
    let blocks = build_blocks(2_000, 2_048);
    let paginator = paginator(128 * 1024);

    let mut group = c.benchmark_group("ctxpage/stream_pages");
    group.sample_size(20);
    group.throughput(Throughput::Elements(
        u64::try_from(blocks.len()).unwrap_or(u64::MAX),
    ));

    group.bench_function("paginate_all", |b| {
        b.iter(|| {
            let pages = paginator
                .stream_pages(black_box(blocks.as_slice()))
                .expect("stream pages");
            black_box(pages.len());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_stream,
    bench_page_from_reader,
    bench_stream_pages,
);
criterion_main!(benches);
