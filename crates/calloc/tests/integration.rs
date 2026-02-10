#![allow(missing_docs)]

use std::fs;
use std::sync::{Mutex, OnceLock};

use calloc::{Allocator, IndexSnapshot, Manifest, RawRenderer};
use tempfile::tempdir;

fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn end_to_end_pack_and_inject_is_deterministic() {
    let _guard = cwd_lock().lock().expect("cwd lock");
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();

    fs::create_dir_all(root.join("src")).expect("mkdir src");
    fs::write(root.join("src/main.rs"), b"fn main() {}\n").expect("write main");
    fs::write(root.join("AGENTS.md"), b"Agent guide\n").expect("write agents");

    let manifest_text = r#"
[project]
namespace = "integration"

[index]
roots = ["."]
exclude = ["target/**", ".git/**"]
max_file_bytes = 1048576

[budget]
max_bytes = 1048576

[[include]]
glob = "AGENTS.md"
priority = 300
anchor = true

[[include]]
glob = "src/**/*.rs"
priority = 100
anchor = false
"#;

    fs::write(root.join(".calloc.toml"), manifest_text).expect("write manifest");

    let old = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(root).expect("set cwd");

    let manifest = Manifest::from_path(".calloc.toml").expect("load manifest");
    let snapshot = IndexSnapshot::build(&manifest.index).expect("snapshot");

    let mut allocator_1 = Allocator::new(snapshot.clone(), manifest.budget.clone());
    let (_handle_1, pack_1, _receipt_1) = allocator_1.allocate(&manifest).expect("pack 1");

    let mut allocator_2 = Allocator::new(snapshot, manifest.budget.clone());
    let (_handle_2, pack_2, _receipt_2) = allocator_2.allocate(&manifest).expect("pack 2");

    let renderer = RawRenderer;
    let bytes_1 = renderer.render(&pack_1).expect("render 1");
    let bytes_2 = renderer.render(&pack_2).expect("render 2");

    std::env::set_current_dir(old).expect("restore cwd");

    assert_eq!(pack_1.digest, pack_2.digest);
    assert_eq!(bytes_1, bytes_2);
}

#[test]
fn allocation_fails_when_budget_is_exceeded() {
    let _guard = cwd_lock().lock().expect("cwd lock");
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();

    fs::create_dir_all(root.join("src")).expect("mkdir src");
    fs::write(root.join("src/lib.rs"), vec![b'a'; 4096]).expect("write file");

    let manifest_text = r#"
[index]
roots = ["src"]
exclude = []
max_file_bytes = 1048576

[budget]
max_bytes = 64

[[include]]
glob = "src/**/*.rs"
priority = 100
"#;

    fs::write(root.join(".calloc.toml"), manifest_text).expect("write manifest");

    let old = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(root).expect("set cwd");

    let manifest = Manifest::from_path(".calloc.toml").expect("load manifest");
    let snapshot = IndexSnapshot::build(&manifest.index).expect("snapshot");
    let mut allocator = Allocator::new(snapshot, manifest.budget.clone());

    let error = allocator.allocate(&manifest).expect_err("budget must fail");

    std::env::set_current_dir(old).expect("restore cwd");

    assert!(error.to_string().contains("budget exceeded"));
}
