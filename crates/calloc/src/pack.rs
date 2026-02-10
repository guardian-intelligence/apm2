use crate::block::ContextBlock;

/// Deterministically ordered context pack.
#[derive(Debug, Clone)]
pub struct ContextPack {
    /// Stable digest over ordered blocks.
    pub digest: [u8; 32],
    /// Ordered context blocks.
    pub blocks: Vec<ContextBlock>,
    /// Total byte size across blocks.
    pub total_bytes: u64,
    /// Aggregate token estimate across blocks.
    pub estimated_tokens: u64,
}

impl ContextPack {
    /// Creates a pack and computes deterministic metadata.
    #[must_use]
    pub fn new(blocks: Vec<ContextBlock>) -> Self {
        let total_bytes = blocks.iter().fold(0_u64, |sum, block| {
            sum.saturating_add(u64::try_from(block.len()).unwrap_or(u64::MAX))
        });
        let estimated_tokens = blocks.iter().fold(0_u64, |sum, block| {
            sum.saturating_add(block.estimated_tokens)
        });
        let digest = compute_pack_digest(&blocks);

        Self {
            digest,
            blocks,
            total_bytes,
            estimated_tokens,
        }
    }

    /// Returns pack digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns number of blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns total bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns token estimate.
    #[must_use]
    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }
}

fn compute_pack_digest(blocks: &[ContextBlock]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calloc:context_pack:v1\n");

    for block in blocks {
        hasher.update(&block.digest);
        let path = block.source_path.to_string_lossy();
        let path_bytes = path.as_bytes();
        hasher.update(&(u64::try_from(path_bytes.len()).unwrap_or(u64::MAX)).to_le_bytes());
        hasher.update(path_bytes);
        hasher.update(&(u64::try_from(block.bytes.len()).unwrap_or(u64::MAX)).to_le_bytes());
    }

    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::ContextPack;
    use crate::block::ContextBlock;

    #[test]
    fn pack_digest_is_stable_for_same_order() {
        let block = ContextBlock {
            digest: [7; 32],
            source_path: PathBuf::from("src/lib.rs"),
            bytes: Arc::from(b"pub fn a() {}\n".to_vec().into_boxed_slice()),
            estimated_tokens: 4,
        };

        let a = ContextPack::new(vec![block.clone()]);
        let b = ContextPack::new(vec![block]);

        assert_eq!(a.digest, b.digest);
    }
}
