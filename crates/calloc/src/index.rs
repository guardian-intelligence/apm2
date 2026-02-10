use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::{fs, thread};

use glob::Pattern;

use crate::error::Error;
use crate::manifest::IndexConfig;

const PARALLEL_MIN_FILES: usize = 128;
const MAX_INDEX_WORKERS: usize = 16;

/// Immutable indexed file entry.
#[derive(Debug, Clone)]
pub struct IndexedFile {
    /// Relative path from workspace root.
    pub relative_path: PathBuf,
    /// Canonical, slash-separated relative path.
    pub canonical_path: String,
    /// BLAKE3 digest of file bytes.
    pub digest: [u8; 32],
    /// File contents.
    pub bytes: Arc<[u8]>,
    /// Byte size.
    pub size_bytes: u64,
}

/// In-memory file index used for deterministic allocation.
#[derive(Debug, Clone)]
pub struct IndexSnapshot {
    workspace_root: PathBuf,
    files: BTreeMap<String, IndexedFile>,
    total_bytes: u64,
}

impl IndexSnapshot {
    /// Builds a snapshot from index configuration.
    pub fn build(config: &IndexConfig) -> Result<Self, Error> {
        if config.roots.is_empty() {
            return Err(Error::ManifestValidation(
                "index.roots must not be empty".to_string(),
            ));
        }

        let workspace_root = std::env::current_dir()?;
        let exclude_patterns = compile_patterns(&config.exclude)?;
        let mut collector =
            CandidateCollector::new(&workspace_root, &exclude_patterns, config.max_file_bytes);

        for root in &config.roots {
            let absolute_root = if root.is_absolute() {
                root.clone()
            } else {
                workspace_root.join(root)
            };

            if !absolute_root.exists() {
                continue;
            }

            collector.collect_from_root(&absolute_root)?;
        }

        let indexed = process_candidates(&collector.candidates)?;
        let mut files = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for file in indexed {
            total_bytes = total_bytes.saturating_add(file.size_bytes);
            files.entry(file.canonical_path.clone()).or_insert(file);
        }

        Ok(Self {
            workspace_root,
            files,
            total_bytes,
        })
    }

    /// Returns indexed file count.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Returns total indexed bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns workspace root used for relative path derivation.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Iterates indexed files in canonical path order.
    pub fn files(&self) -> impl Iterator<Item = &IndexedFile> {
        self.files.values()
    }
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<Pattern>, Error> {
    patterns
        .iter()
        .map(|pattern| {
            Pattern::new(pattern).map_err(|source| Error::InvalidGlob {
                pattern: pattern.clone(),
                source,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
struct FileCandidate {
    absolute: PathBuf,
    relative: PathBuf,
    canonical: String,
}

struct CandidateCollector<'a> {
    workspace_root: &'a Path,
    exclude_patterns: &'a [Pattern],
    max_file_bytes: u64,
    candidates: Vec<FileCandidate>,
}

impl<'a> CandidateCollector<'a> {
    const fn new(
        workspace_root: &'a Path,
        exclude_patterns: &'a [Pattern],
        max_file_bytes: u64,
    ) -> Self {
        Self {
            workspace_root,
            exclude_patterns,
            max_file_bytes,
            candidates: Vec::new(),
        }
    }

    fn collect_from_root(&mut self, root: &Path) -> Result<(), Error> {
        self.walk(root)
    }

    fn walk(&mut self, current: &Path) -> Result<(), Error> {
        let metadata = fs::symlink_metadata(current)
            .map_err(|source| Error::io_at_path(current.to_path_buf(), source))?;

        if metadata.file_type().is_symlink() {
            return Ok(());
        }

        if metadata.is_dir() {
            let mut children = fs::read_dir(current)
                .map_err(|source| Error::io_at_path(current.to_path_buf(), source))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| Error::io_at_path(current.to_path_buf(), source))?;
            children.sort_by_key(std::fs::DirEntry::file_name);
            for child in children {
                self.walk(&child.path())?;
            }
            return Ok(());
        }

        if !metadata.is_file() || metadata.len() > self.max_file_bytes {
            return Ok(());
        }

        let relative = match current.strip_prefix(self.workspace_root) {
            Ok(path) => path.to_path_buf(),
            Err(_) => return Ok(()),
        };

        let canonical_path = canonical_relative(&relative);
        if matches_patterns(&canonical_path, self.exclude_patterns) {
            return Ok(());
        }

        self.candidates.push(FileCandidate {
            absolute: current.to_path_buf(),
            relative,
            canonical: canonical_path,
        });
        Ok(())
    }
}

fn process_candidates(candidates: &[FileCandidate]) -> Result<Vec<IndexedFile>, Error> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let worker_count = worker_count_for(candidates.len());
    if worker_count <= 1 {
        return process_candidates_sequential(candidates);
    }

    process_candidates_parallel(candidates, worker_count)
}

fn worker_count_for(file_count: usize) -> usize {
    if file_count < PARALLEL_MIN_FILES {
        return 1;
    }

    let available = thread::available_parallelism().map_or(1, usize::from);
    available.min(file_count).min(MAX_INDEX_WORKERS)
}

fn process_candidates_sequential(candidates: &[FileCandidate]) -> Result<Vec<IndexedFile>, Error> {
    candidates.iter().map(index_candidate).collect()
}

fn process_candidates_parallel(
    candidates: &[FileCandidate],
    worker_count: usize,
) -> Result<Vec<IndexedFile>, Error> {
    let next_index = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel::<(usize, Result<IndexedFile, Error>)>();

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let sender = sender.clone();
            let next_index = &next_index;
            let candidates = &candidates;
            scope.spawn(move || {
                loop {
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    if index >= candidates.len() {
                        break;
                    }
                    let result = index_candidate(&candidates[index]);
                    if sender.send((index, result)).is_err() {
                        break;
                    }
                }
            });
        }
    });

    drop(sender);

    let mut ordered_results = std::iter::repeat_with(|| None)
        .take(candidates.len())
        .collect::<Vec<Option<Result<IndexedFile, Error>>>>();
    for (index, result) in receiver {
        ordered_results[index] = Some(result);
    }

    let mut indexed = Vec::with_capacity(candidates.len());
    for (index, result) in ordered_results.into_iter().enumerate() {
        let Some(result) = result else {
            return Err(Error::ManifestValidation(format!(
                "index worker did not report result for candidate {index}",
            )));
        };
        indexed.push(result?);
    }

    Ok(indexed)
}

fn index_candidate(candidate: &FileCandidate) -> Result<IndexedFile, Error> {
    let raw = fs::read(&candidate.absolute)
        .map_err(|source| Error::io_at_path(candidate.absolute.clone(), source))?;
    let digest = *blake3::hash(&raw).as_bytes();
    let bytes: Arc<[u8]> = Arc::from(raw.into_boxed_slice());
    let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);

    Ok(IndexedFile {
        relative_path: candidate.relative.clone(),
        canonical_path: candidate.canonical.clone(),
        digest,
        bytes,
        size_bytes,
    })
}

fn canonical_relative(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn matches_patterns(path: &str, patterns: &[Pattern]) -> bool {
    patterns.iter().any(|pattern| pattern.matches(path))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    use tempfile::tempdir;

    use super::IndexSnapshot;
    use crate::manifest::IndexConfig;

    fn cwd_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn builds_snapshot_and_respects_exclude() {
        let _guard = cwd_lock().lock().expect("cwd lock");
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();

        fs::create_dir_all(root.join("src")).expect("create src");
        fs::create_dir_all(root.join("target")).expect("create target");
        fs::write(root.join("src/lib.rs"), b"pub fn x() {}\n").expect("write src file");
        fs::write(root.join("target/out.txt"), b"ignore\n").expect("write target file");

        let old = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(root).expect("set cwd");

        let snapshot = IndexSnapshot::build(&IndexConfig {
            roots: vec![PathBuf::from("src"), PathBuf::from("target")],
            exclude: vec!["target/**".to_string()],
            max_file_bytes: 1024,
        })
        .expect("build snapshot");

        std::env::set_current_dir(old).expect("restore cwd");

        assert_eq!(snapshot.file_count(), 1);
        assert!(
            snapshot
                .files()
                .any(|file| file.canonical_path == "src/lib.rs")
        );
    }
}
