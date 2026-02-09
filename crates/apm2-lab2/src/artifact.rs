use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct RunPaths {
    pub root_dir: PathBuf,
    pub run_dir: PathBuf,
    pub iterations_dir: PathBuf,
    pub events_path: PathBuf,
    pub summary_path: PathBuf,
    pub hypothesis_path: PathBuf,
}

impl RunPaths {
    pub fn new(root_dir: impl AsRef<Path>, run_id: &str) -> Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let run_dir = root_dir.join(run_id);
        let iterations_dir = run_dir.join("iterations");
        let events_path = run_dir.join("events.jsonl");
        let summary_path = run_dir.join("summary.json");
        let hypothesis_path = run_dir.join("hypothesis_eval.json");

        fs::create_dir_all(&iterations_dir)
            .with_context(|| format!("create {}", iterations_dir.display()))?;

        Ok(Self {
            root_dir,
            run_dir,
            iterations_dir,
            events_path,
            summary_path,
            hypothesis_path,
        })
    }
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    Ok(())
}

pub fn write_text(path: impl AsRef<Path>, text: &str) -> Result<()> {
    let path = path.as_ref();
    ensure_parent(path)?;
    fs::write(path, text).with_context(|| format!("write {}", path.display()))
}

pub fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    ensure_parent(path)?;
    let json = serde_json::to_string_pretty(value).context("serialize json")?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))
}

pub fn append_jsonl(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    ensure_parent(path)?;

    let line = serde_json::to_string(value).context("serialize jsonl line")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("append {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("append newline {}", path.display()))?;

    Ok(())
}

pub fn hash_text(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

pub fn hash_json(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("serialize json for hash")?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}
