/// Snapshot-level allocator statistics.
#[derive(Debug, Clone, Copy)]
pub struct AllocatorStats {
    /// Number of indexed files.
    pub indexed_files: usize,
    /// Total bytes across indexed files.
    pub indexed_bytes: u64,
    /// Number of unique block digests.
    pub unique_blocks: usize,
    /// Dedup ratio (`indexed_files / unique_blocks`).
    pub dedup_ratio: f64,
    /// Number of active allocations currently tracked.
    pub active_allocations: usize,
}
