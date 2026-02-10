use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use glob::Pattern;

use crate::block::{ContextBlock, estimate_tokens};
use crate::budget::Budget;
use crate::error::Error;
use crate::index::{IndexSnapshot, IndexedFile};
use crate::manifest::{ExcludeRule, IncludeRule, Manifest};
use crate::ordering::{ORDERING_VERSION, OrderingKey, sort_by_key};
use crate::pack::ContextPack;
use crate::stats::AllocatorStats;

/// Handle for a live allocation.
#[derive(Debug, Clone)]
pub struct AllocationHandle {
    /// Allocation identifier.
    pub id: u64,
    /// Digest of allocated pack.
    pub pack_digest: [u8; 32],
    /// Allocation creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Pack block count.
    pub block_count: usize,
    /// Pack byte count.
    pub total_bytes: u64,
}

/// Receipt emitted for allocation operations.
#[derive(Debug, Clone)]
pub struct AllocationReceipt {
    /// Allocation identifier.
    pub allocation_id: u64,
    /// Digest of allocated pack.
    pub pack_digest: [u8; 32],
    /// Number of selected files.
    pub selected_files: usize,
    /// Total selected bytes.
    pub total_bytes: u64,
    /// Aggregate token estimate.
    pub estimated_tokens: u64,
    /// Ordering policy version.
    pub ordering_version: &'static str,
    /// Receipt creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Context allocation engine.
#[derive(Debug)]
pub struct Allocator {
    snapshot: IndexSnapshot,
    budget: Budget,
    allocations: HashMap<u64, AllocationHandle>,
    block_cache: HashMap<[u8; 32], Arc<[u8]>>,
    selection_cache: HashMap<[u8; 32], Arc<SelectionPlan>>,
    manifest_hits: HashMap<[u8; 32], u32>,
    next_id: u64,
}

impl Allocator {
    /// Creates a new allocator.
    #[must_use]
    pub fn new(snapshot: IndexSnapshot, budget: Budget) -> Self {
        Self {
            snapshot,
            budget,
            allocations: HashMap::new(),
            block_cache: HashMap::new(),
            selection_cache: HashMap::new(),
            manifest_hits: HashMap::new(),
            next_id: 0,
        }
    }

    /// Checks whether an allocation can be created without mutating allocator
    /// state.
    pub fn can_allocate(&self, manifest: &Manifest) -> Result<(), Error> {
        let selected = select_files(&self.snapshot, manifest)?;
        let total_bytes = selected
            .iter()
            .fold(0_u64, |sum, item| sum.saturating_add(item.file.size_bytes));
        self.enforce_budget(manifest, total_bytes)?;
        Ok(())
    }

    /// Allocates a deterministic context pack without warming selection caches.
    ///
    /// This is ideal for one-shot CLI calls where warm-cache reuse is unlikely.
    pub fn allocate_once(
        &mut self,
        manifest: &Manifest,
    ) -> Result<(AllocationHandle, ContextPack, AllocationReceipt), Error> {
        let selected = select_files(&self.snapshot, manifest)?;
        let total_bytes = selected
            .iter()
            .fold(0_u64, |sum, item| sum.saturating_add(item.file.size_bytes));
        self.enforce_budget(manifest, total_bytes)?;

        let mut blocks = Vec::with_capacity(selected.len());
        for item in selected {
            let bytes = Arc::clone(&item.file.bytes);
            blocks.push(ContextBlock {
                digest: item.file.digest,
                source_path: item.file.relative_path.clone(),
                estimated_tokens: estimate_tokens(bytes.len()),
                bytes,
            });
        }

        Ok(self.finalize_allocation(ContextPack::new(blocks)))
    }

    /// Allocates a deterministic context pack.
    pub fn allocate(
        &mut self,
        manifest: &Manifest,
    ) -> Result<(AllocationHandle, ContextPack, AllocationReceipt), Error> {
        let manifest_key = selection_cache_key(manifest);
        let promote_to_warm = {
            let hit_count = self.manifest_hits.entry(manifest_key).or_insert(0);
            *hit_count = hit_count.saturating_add(1);
            *hit_count >= 2
        };

        if promote_to_warm {
            let plan = self.selection_plan_for_manifest_with_key(manifest, manifest_key)?;
            self.allocate_from_plan(manifest, &plan)
        } else {
            self.allocate_once(manifest)
        }
    }

    /// Frees a previously allocated handle.
    pub fn free(&mut self, handle: &AllocationHandle) -> Result<(), Error> {
        let Some(stored) = self.allocations.remove(&handle.id) else {
            return Err(Error::UnknownAllocationHandle { id: handle.id });
        };

        if stored.pack_digest != handle.pack_digest {
            return Err(Error::AllocationHandleDigestMismatch { id: handle.id });
        }

        Ok(())
    }

    /// Returns in-memory allocator stats.
    #[must_use]
    pub fn stats(&self) -> AllocatorStats {
        let unique_blocks = self
            .snapshot
            .files()
            .map(|file| file.digest)
            .collect::<HashSet<_>>()
            .len();

        let indexed_files = self.snapshot.file_count();
        #[allow(clippy::cast_precision_loss)]
        let dedup_ratio = if unique_blocks == 0 {
            1.0
        } else {
            indexed_files as f64 / unique_blocks as f64
        };

        AllocatorStats {
            indexed_files,
            indexed_bytes: self.snapshot.total_bytes(),
            unique_blocks,
            dedup_ratio,
            active_allocations: self.allocations.len(),
        }
    }

    fn selection_plan_for_manifest_with_key(
        &mut self,
        manifest: &Manifest,
        manifest_key: [u8; 32],
    ) -> Result<Arc<SelectionPlan>, Error> {
        if let Some(plan) = self.selection_cache.get(&manifest_key) {
            return Ok(Arc::clone(plan));
        }

        let plan = Arc::new(build_selection_plan(&self.snapshot, manifest)?);
        self.selection_cache.insert(manifest_key, Arc::clone(&plan));
        Ok(plan)
    }

    fn allocate_from_plan(
        &mut self,
        manifest: &Manifest,
        plan: &SelectionPlan,
    ) -> Result<(AllocationHandle, ContextPack, AllocationReceipt), Error> {
        self.enforce_budget(manifest, plan.total_bytes)?;

        let mut blocks = Vec::with_capacity(plan.entries.len());
        for item in &plan.entries {
            let bytes = self
                .block_cache
                .entry(item.digest)
                .or_insert_with(|| Arc::clone(&item.bytes))
                .clone();

            blocks.push(ContextBlock {
                digest: item.digest,
                source_path: item.relative_path.clone(),
                estimated_tokens: estimate_tokens(bytes.len()),
                bytes,
            });
        }

        Ok(self.finalize_allocation(ContextPack::new(blocks)))
    }

    fn enforce_budget(&self, manifest: &Manifest, total_bytes: u64) -> Result<(), Error> {
        let max_bytes = self.budget.max_bytes.min(manifest.budget.max_bytes);
        if total_bytes > max_bytes {
            return Err(Error::BudgetExceeded {
                max_bytes,
                actual_bytes: total_bytes,
            });
        }
        Ok(())
    }

    fn finalize_allocation(
        &mut self,
        pack: ContextPack,
    ) -> (AllocationHandle, ContextPack, AllocationReceipt) {
        self.next_id = self.next_id.saturating_add(1);
        let created_at = Utc::now();

        let handle = AllocationHandle {
            id: self.next_id,
            pack_digest: pack.digest,
            created_at,
            block_count: pack.block_count(),
            total_bytes: pack.total_bytes,
        };
        self.allocations.insert(handle.id, handle.clone());

        let receipt = AllocationReceipt {
            allocation_id: handle.id,
            pack_digest: pack.digest,
            selected_files: pack.block_count(),
            total_bytes: pack.total_bytes,
            estimated_tokens: pack.estimated_tokens,
            ordering_version: ORDERING_VERSION,
            created_at,
        };

        (handle, pack, receipt)
    }
}

#[derive(Debug)]
struct SelectedFileRef<'a> {
    key: OrderingKey,
    file: &'a IndexedFile,
}

#[derive(Debug, Clone)]
struct SelectionEntry {
    digest: [u8; 32],
    relative_path: std::path::PathBuf,
    bytes: Arc<[u8]>,
}

#[derive(Debug)]
struct SelectionPlan {
    entries: Vec<SelectionEntry>,
    total_bytes: u64,
}

fn build_selection_plan(
    snapshot: &IndexSnapshot,
    manifest: &Manifest,
) -> Result<SelectionPlan, Error> {
    let selected = select_files(snapshot, manifest)?;
    let mut entries = Vec::with_capacity(selected.len());
    let mut total_bytes = 0_u64;
    for selected_file in selected {
        total_bytes = total_bytes.saturating_add(selected_file.file.size_bytes);
        entries.push(SelectionEntry {
            digest: selected_file.file.digest,
            relative_path: selected_file.file.relative_path.clone(),
            bytes: Arc::clone(&selected_file.file.bytes),
        });
    }

    Ok(SelectionPlan {
        entries,
        total_bytes,
    })
}

fn select_files<'a>(
    snapshot: &'a IndexSnapshot,
    manifest: &Manifest,
) -> Result<Vec<SelectedFileRef<'a>>, Error> {
    let include_patterns = compile_includes(&manifest.include)?;
    let exclude_patterns = compile_excludes(&manifest.exclude)?;

    let mut selected = Vec::new();

    for file in snapshot.files() {
        if matches_any(&file.canonical_path, &exclude_patterns) {
            continue;
        }

        let mut matched = false;
        let mut priority = i32::MIN;
        let mut anchor = false;

        for include in &include_patterns {
            if include.pattern.matches(&file.canonical_path) {
                matched = true;
                priority = priority.max(include.priority);
                anchor |= include.anchor;
            }
        }

        if !matched {
            continue;
        }

        selected.push(SelectedFileRef {
            key: OrderingKey {
                anchor_rank: u8::from(!anchor),
                priority,
                canonical_path: file.canonical_path.clone(),
                digest: file.digest,
            },
            file,
        });
    }

    if selected.is_empty() {
        return Err(Error::NoMatchingFiles);
    }

    sort_by_key(&mut selected, |item| &item.key);
    Ok(selected)
}

#[derive(Debug)]
struct CompiledInclude {
    pattern: Pattern,
    priority: i32,
    anchor: bool,
}

fn compile_includes(rules: &[IncludeRule]) -> Result<Vec<CompiledInclude>, Error> {
    rules
        .iter()
        .map(|rule| {
            let pattern = Pattern::new(&rule.glob).map_err(|source| Error::InvalidGlob {
                pattern: rule.glob.clone(),
                source,
            })?;

            Ok(CompiledInclude {
                pattern,
                priority: rule.priority,
                anchor: rule.anchor,
            })
        })
        .collect()
}

fn compile_excludes(rules: &[ExcludeRule]) -> Result<Vec<Pattern>, Error> {
    rules
        .iter()
        .map(|rule| {
            Pattern::new(&rule.glob).map_err(|source| Error::InvalidGlob {
                pattern: rule.glob.clone(),
                source,
            })
        })
        .collect()
}

fn matches_any(path: &str, patterns: &[Pattern]) -> bool {
    patterns.iter().any(|pattern| pattern.matches(path))
}

fn selection_cache_key(manifest: &Manifest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calloc:selection-cache:v1\n");
    hasher.update(
        &u64::try_from(manifest.include.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for include in &manifest.include {
        hash_len_prefixed(&mut hasher, include.glob.as_bytes());
        hasher.update(&include.priority.to_le_bytes());
        hasher.update(&[u8::from(include.anchor)]);
    }

    hasher.update(
        &u64::try_from(manifest.exclude.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for exclude in &manifest.exclude {
        hash_len_prefixed(&mut hasher, exclude.glob.as_bytes());
    }

    *hasher.finalize().as_bytes()
}

fn hash_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    use tempfile::tempdir;

    use super::Allocator;
    use crate::index::IndexSnapshot;
    use crate::manifest::Manifest;

    fn cwd_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn sample_manifest() -> Manifest {
        Manifest::from_toml(
            r#"
[index]
roots = ["src"]
exclude = []
max_file_bytes = 10240

[budget]
max_bytes = 4096

[[include]]
glob = "src/lib.rs"
priority = 100
anchor = true

[[include]]
glob = "src/**/*.rs"
priority = 10
anchor = false
"#,
        )
        .expect("manifest")
    }

    #[test]
    fn deterministic_allocation_bytes() {
        let _guard = cwd_lock().lock().expect("cwd lock");
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        fs::create_dir_all(root.join("src")).expect("mkdir");
        fs::write(root.join("src/lib.rs"), b"pub fn b() {}\n").expect("write");
        fs::write(root.join("src/a.rs"), b"pub fn a() {}\n").expect("write");

        let old = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(root).expect("set cwd");

        let manifest = sample_manifest();
        let snapshot = IndexSnapshot::build(&manifest.index).expect("snapshot");
        let mut allocator = Allocator::new(snapshot.clone(), manifest.budget.clone());
        let (_h1, pack1, _) = allocator.allocate(&manifest).expect("pack1");

        let mut allocator2 = Allocator::new(snapshot, manifest.budget.clone());
        let (_h2, pack2, _) = allocator2.allocate(&manifest).expect("pack2");

        std::env::set_current_dir(old).expect("restore cwd");

        let files_1: Vec<PathBuf> = pack1.blocks.iter().map(|b| b.source_path.clone()).collect();
        let files_2: Vec<PathBuf> = pack2.blocks.iter().map(|b| b.source_path.clone()).collect();

        assert_eq!(pack1.digest, pack2.digest);
        assert_eq!(files_1, files_2);
    }

    #[test]
    fn budget_enforcement_works() {
        let _guard = cwd_lock().lock().expect("cwd lock");
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        fs::create_dir_all(root.join("src")).expect("mkdir");
        fs::write(root.join("src/lib.rs"), vec![b'a'; 2048]).expect("write");

        let old = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(root).expect("set cwd");

        let mut manifest = sample_manifest();
        manifest.budget.max_bytes = 128;

        let snapshot = IndexSnapshot::build(&manifest.index).expect("snapshot");
        let mut allocator = Allocator::new(snapshot, manifest.budget.clone());
        let err = allocator
            .allocate(&manifest)
            .expect_err("must exceed budget");

        std::env::set_current_dir(old).expect("restore cwd");

        assert!(err.to_string().contains("budget exceeded"));
    }

    #[test]
    fn allocation_reuses_manifest_selection_cache() {
        let _guard = cwd_lock().lock().expect("cwd lock");
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        fs::create_dir_all(root.join("src")).expect("mkdir");
        fs::write(root.join("src/lib.rs"), b"pub fn lib() {}\n").expect("write lib");
        fs::write(root.join("src/main.rs"), b"fn main() {}\n").expect("write main");

        let old = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(root).expect("set cwd");

        let manifest = sample_manifest();
        let snapshot = IndexSnapshot::build(&manifest.index).expect("snapshot");
        let mut allocator = Allocator::new(snapshot, manifest.budget.clone());

        assert_eq!(allocator.selection_cache.len(), 0);

        let (first_handle, _, _) = allocator.allocate(&manifest).expect("first allocation");
        assert_eq!(allocator.selection_cache.len(), 0);
        allocator.free(&first_handle).expect("free first");

        let (second_handle, _, _) = allocator.allocate(&manifest).expect("second allocation");
        assert_eq!(allocator.selection_cache.len(), 1);
        allocator.free(&second_handle).expect("free second");

        std::env::set_current_dir(old).expect("restore cwd");
    }

    #[test]
    fn allocate_once_never_populates_selection_cache() {
        let _guard = cwd_lock().lock().expect("cwd lock");
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        fs::create_dir_all(root.join("src")).expect("mkdir");
        fs::write(root.join("src/lib.rs"), b"pub fn lib() {}\n").expect("write lib");

        let old = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(root).expect("set cwd");

        let manifest = sample_manifest();
        let snapshot = IndexSnapshot::build(&manifest.index).expect("snapshot");
        let mut allocator = Allocator::new(snapshot, manifest.budget.clone());

        let (handle, _, _) = allocator
            .allocate_once(&manifest)
            .expect("first allocation");
        allocator.free(&handle).expect("free first");
        let (handle2, _, _) = allocator
            .allocate_once(&manifest)
            .expect("second allocation");
        allocator.free(&handle2).expect("free second");
        assert_eq!(allocator.selection_cache.len(), 0);

        std::env::set_current_dir(old).expect("restore cwd");
    }
}
