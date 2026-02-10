use std::path::PathBuf;
use std::sync::Arc;

/// Content-addressed unit in a context pack.
#[derive(Debug, Clone)]
pub struct ContextBlock {
    /// BLAKE3 digest of `bytes`.
    pub digest: [u8; 32],
    /// Source path relative to workspace root.
    pub source_path: PathBuf,
    /// Immutable bytes for this block.
    pub bytes: Arc<[u8]>,
    /// Approximate token estimate for reporting.
    pub estimated_tokens: u64,
}

impl ContextBlock {
    /// Returns this block byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true when the block has zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Deterministic token estimate for reporting.
#[must_use]
pub fn estimate_tokens(bytes: usize) -> u64 {
    // Conservative fixed-ratio estimate for Phase 0/1 reporting.
    let bytes_u64 = u64::try_from(bytes).unwrap_or(u64::MAX);
    bytes_u64.saturating_add(3) / 4
}
