//! Criterion benchmarks for `calloc` allocation and rendering paths.
#![allow(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use calloc::{Allocator, IndexSnapshot, Manifest, RawRenderer};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tempfile::TempDir;

fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn with_cwd<T>(path: &Path, op: impl FnOnce() -> T) -> T {
    let _guard = cwd_lock().lock().expect("cwd lock poisoned");
    let previous = std::env::current_dir().expect("read current dir");
    std::env::set_current_dir(path).expect("set current dir");
    let result = op();
    std::env::set_current_dir(previous).expect("restore current dir");
    result
}

#[derive(Debug)]
struct Fixture {
    _temp_dir: TempDir,
    root: PathBuf,
    manifest_path: PathBuf,
    file_count: usize,
}

fn make_payload(seed: usize, target_len: usize) -> String {
    let token = format!("ctx-{seed:02}-");
    let mut payload = String::new();
    while payload.len() < target_len {
        payload.push_str(&token);
    }
    payload.truncate(target_len);
    payload
}

fn create_fixture(file_count: usize, payload_bytes: usize) -> Fixture {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let root = temp_dir.path().to_path_buf();

    for index in 0..file_count {
        let module = index % 64;
        let dir = root.join("src").join(format!("module_{module:03}"));
        fs::create_dir_all(&dir).expect("create source dir");

        let file_path = dir.join(format!("file_{index:05}.rs"));
        let payload = make_payload(index % 19, payload_bytes);
        let source = format!(
            "// synthetic fixture file {index}\npub fn f_{index}() -> &'static str {{ \"{payload}\" }}\n"
        );
        fs::write(file_path, source).expect("write fixture file");
    }

    let budget_bytes = u64::try_from(file_count)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::try_from(payload_bytes.saturating_add(256)).unwrap_or(u64::MAX))
        .saturating_add(1_048_576);

    let max_file_bytes = u64::try_from(payload_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(8_192);

    let manifest = format!(
        r#"[project]
namespace = "bench"

[index]
roots = ["src"]
exclude = []
max_file_bytes = {max_file_bytes}

[budget]
max_bytes = {budget_bytes}
max_tokens = 500000

[[include]]
glob = "src/**/*.rs"
priority = 100
anchor = true
"#
    );

    let manifest_path = root.join(".calloc.toml");
    fs::write(&manifest_path, manifest).expect("write manifest");

    Fixture {
        _temp_dir: temp_dir,
        root,
        manifest_path,
        file_count,
    }
}

fn bench_cold_index_allocate(c: &mut Criterion) {
    let mut group = c.benchmark_group("calloc/cold_index_allocate");
    group.sample_size(20);

    for &files in &[100_usize, 1_000, 5_000] {
        let fixture = create_fixture(files, 768);
        group.throughput(Throughput::Elements(
            u64::try_from(files).unwrap_or(u64::MAX),
        ));

        group.bench_with_input(
            BenchmarkId::from_parameter(files),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let result = with_cwd(&fixture.root, || {
                        let manifest = Manifest::from_path(&fixture.manifest_path)?;
                        let snapshot = IndexSnapshot::build(&manifest.index)?;
                        let mut allocator = Allocator::new(snapshot, manifest.budget.clone());
                        let (handle, pack, _receipt) = allocator.allocate_once(&manifest)?;
                        black_box(pack.digest());
                        allocator.free(&handle)
                    });
                    result.expect("cold index+allocate benchmark iteration must succeed");
                });
            },
        );
    }

    group.finish();
}

fn bench_hot_allocate(c: &mut Criterion) {
    let fixture = create_fixture(2_500, 1_024);

    with_cwd(&fixture.root, || {
        let manifest = Manifest::from_path(&fixture.manifest_path).expect("load manifest");
        let snapshot = IndexSnapshot::build(&manifest.index).expect("build snapshot");
        let mut allocator = Allocator::new(snapshot, manifest.budget.clone());
        let (warmup_a, _, _) = allocator.allocate(&manifest).expect("warmup allocation a");
        allocator.free(&warmup_a).expect("free warmup allocation a");
        let (warmup_b, _, _) = allocator.allocate(&manifest).expect("warmup allocation b");
        allocator.free(&warmup_b).expect("free warmup allocation b");

        let mut group = c.benchmark_group("calloc/hot_allocate");
        group.sample_size(30);
        group.throughput(Throughput::Elements(
            u64::try_from(fixture.file_count).unwrap_or(u64::MAX),
        ));

        group.bench_function("alloc_free", |b| {
            b.iter(|| {
                let (handle, pack, _receipt) =
                    allocator.allocate(&manifest).expect("allocate pack");
                black_box(pack.total_bytes());
                allocator.free(&handle).expect("free handle");
            });
        });

        group.finish();
    });
}

fn bench_raw_render(c: &mut Criterion) {
    let fixture = create_fixture(1_500, 2_048);

    with_cwd(&fixture.root, || {
        let manifest = Manifest::from_path(&fixture.manifest_path).expect("load manifest");
        let snapshot = IndexSnapshot::build(&manifest.index).expect("build snapshot");
        let mut allocator = Allocator::new(snapshot, manifest.budget.clone());
        let (_handle, pack, _receipt) = allocator.allocate_once(&manifest).expect("allocate pack");
        let renderer = RawRenderer;

        let mut group = c.benchmark_group("calloc/raw_render");
        group.sample_size(30);
        group.throughput(Throughput::Bytes(pack.total_bytes()));

        group.bench_function("render_full_pack", |b| {
            b.iter(|| {
                let output = renderer.render(black_box(&pack)).expect("render pack");
                black_box(output.len());
            });
        });

        group.finish();
    });
}

criterion_group!(
    benches,
    bench_cold_index_allocate,
    bench_hot_allocate,
    bench_raw_render,
);
criterion_main!(benches);
