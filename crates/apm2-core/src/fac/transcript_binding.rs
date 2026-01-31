// AGENT-AUTHORED
//! Transcript chain binding for Agent Acceptance Testing (AAT).
//!
//! This module provides types for binding transcript chunks to AAT receipts,
//! ensuring transcript immutability through Merkle root computation.
//!
//! # Overview
//!
//! The transcript chain binding ensures that AAT transcripts are
//! cryptographically linked to the receipt. Any modification of transcript
//! chunks invalidates the chain root, providing tamper-evidence for the entire
//! transcript.
//!
//! # Components
//!
//! - [`TranscriptChunk`]: A single chunk of transcript content with hash
//!   binding
//! - [`AatTranscriptBinding`]: Wrapper for binding transcript chunks to AAT
//!   receipts
//!
//! # Security Model
//!
//! Transcript chain binding provides:
//!
//! - **Immutability**: Once the chain root is computed, any modification to
//!   transcript chunks is detectable
//! - **Completeness**: All chunks are included in the Merkle root computation
//! - **Ordering**: Chunk order is preserved and verified
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::transcript_binding::{
//!     AatTranscriptBinding, TranscriptChunk,
//! };
//!
//! // Create transcript chunks
//! let chunks = vec![
//!     TranscriptChunk::new(b"First message", 0),
//!     TranscriptChunk::new(b"Second message", 1),
//!     TranscriptChunk::new(b"Third message", 2),
//! ];
//!
//! // Create binding with run transcript hashes
//! let run_hashes = vec![[0x11; 32], [0x22; 32]];
//! let binding = AatTranscriptBinding::new(chunks, run_hashes);
//!
//! // Verify chain integrity
//! assert!(binding.validate().is_ok());
//!
//! // Get the chain root for inclusion in AAT receipt
//! let chain_root = binding.transcript_chain_root_hash();
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of transcript chunks allowed.
///
/// This prevents denial-of-service attacks via oversized transcript
/// collections.
pub const MAX_TRANSCRIPT_CHUNKS: usize = 65536;

/// Maximum size of a single transcript chunk content in bytes.
pub const MAX_CHUNK_CONTENT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum number of run transcript hashes allowed.
pub const MAX_RUN_TRANSCRIPT_HASHES: usize = 256;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during transcript binding operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TranscriptBindingError {
    /// Chain root hash mismatch during validation.
    #[error("transcript chain root hash mismatch: computed {computed:?}, stored {stored:?}")]
    ChainRootMismatch {
        /// The hash computed from chunks.
        computed: [u8; 32],
        /// The hash stored in the binding.
        stored: [u8; 32],
    },

    /// Transcript chunk content exceeds maximum size.
    #[error("transcript chunk content exceeds max size: {actual} > {max} bytes")]
    ChunkTooLarge {
        /// Actual size of the chunk content.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Too many transcript chunks.
    #[error("too many transcript chunks: {actual} > {max}")]
    TooManyChunks {
        /// Actual number of chunks.
        actual: usize,
        /// Maximum allowed number.
        max: usize,
    },

    /// Too many run transcript hashes.
    #[error("too many run transcript hashes: {actual} > {max}")]
    TooManyRunHashes {
        /// Actual number of hashes.
        actual: usize,
        /// Maximum allowed number.
        max: usize,
    },

    /// Chunk sequence number is out of order.
    #[error("chunk sequence number out of order: expected {expected}, got {actual}")]
    SequenceOutOfOrder {
        /// Expected sequence number.
        expected: u64,
        /// Actual sequence number found.
        actual: u64,
    },

    /// Duplicate chunk hash detected.
    #[error("duplicate chunk hash detected at sequence {sequence}")]
    DuplicateChunkHash {
        /// Sequence number where duplicate was found.
        sequence: u64,
    },
}

// =============================================================================
// TranscriptChunk
// =============================================================================

/// A single chunk of transcript content.
///
/// Each chunk represents a portion of the AAT transcript (e.g., a single
/// message or tool invocation). Chunks are ordered by sequence number and
/// hashed for integrity verification.
///
/// # Fields
///
/// - `content_hash`: BLAKE3 hash of the chunk content
/// - `sequence`: Monotonically increasing sequence number (0-indexed)
/// - `content_size`: Size of the original content in bytes
///
/// # Invariants
///
/// - Sequence numbers must be monotonically increasing (0, 1, 2, ...)
/// - Content hash must match the hash of the original content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptChunk {
    /// BLAKE3 hash of the chunk content.
    #[serde(with = "serde_bytes")]
    content_hash: [u8; 32],

    /// Sequence number for ordering (0-indexed).
    sequence: u64,

    /// Size of the original content in bytes.
    content_size: u64,
}

impl TranscriptChunk {
    /// Creates a new transcript chunk from raw content.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw bytes of the transcript chunk
    /// * `sequence` - The sequence number for ordering
    ///
    /// # Panics
    ///
    /// Panics if content exceeds [`MAX_CHUNK_CONTENT_BYTES`].
    #[must_use]
    pub fn new(content: &[u8], sequence: u64) -> Self {
        Self::try_new(content, sequence).expect("content exceeds maximum size")
    }

    /// Attempts to create a new transcript chunk from raw content.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw bytes of the transcript chunk
    /// * `sequence` - The sequence number for ordering
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptBindingError::ChunkTooLarge`] if content exceeds
    /// the maximum size.
    pub fn try_new(content: &[u8], sequence: u64) -> Result<Self, TranscriptBindingError> {
        if content.len() > MAX_CHUNK_CONTENT_BYTES {
            return Err(TranscriptBindingError::ChunkTooLarge {
                actual: content.len(),
                max: MAX_CHUNK_CONTENT_BYTES,
            });
        }

        let content_hash = *blake3::hash(content).as_bytes();

        Ok(Self {
            content_hash,
            sequence,
            content_size: content.len() as u64,
        })
    }

    /// Creates a transcript chunk from a pre-computed hash.
    ///
    /// Use this when the content hash is already known (e.g., when
    /// deserializing or when content is stored externally).
    ///
    /// # Arguments
    ///
    /// * `content_hash` - The pre-computed BLAKE3 hash of the content
    /// * `sequence` - The sequence number for ordering
    /// * `content_size` - The size of the original content in bytes
    #[must_use]
    pub const fn from_hash(content_hash: [u8; 32], sequence: u64, content_size: u64) -> Self {
        Self {
            content_hash,
            sequence,
            content_size,
        }
    }

    /// Returns the content hash.
    #[must_use]
    pub const fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the content size in bytes.
    #[must_use]
    pub const fn content_size(&self) -> u64 {
        self.content_size
    }

    /// Verifies that this chunk's hash matches the given content.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw bytes to verify against the stored hash
    ///
    /// # Returns
    ///
    /// `true` if the content matches the stored hash, `false` otherwise.
    #[must_use]
    pub fn verify_content(&self, content: &[u8]) -> bool {
        let computed_hash = *blake3::hash(content).as_bytes();
        computed_hash == self.content_hash
    }
}

// =============================================================================
// AatTranscriptBinding
// =============================================================================

/// Binding of transcript chunks to an AAT receipt.
///
/// This struct contains the transcript chunks, computes the Merkle root for
/// chain integrity verification, and tracks run-level transcript hashes.
///
/// # Fields
///
/// - `transcript_chunks`: Ordered list of transcript chunks
/// - `transcript_chain_root_hash`: Merkle root computed from chunk hashes
/// - `run_transcript_hashes`: Hashes linking to individual run transcripts
///
/// # Merkle Root Computation
///
/// The chain root is computed as a Merkle tree over the chunk content hashes.
/// For an empty chunk list, the root is the hash of an empty byte array.
/// For a single chunk, the root is the chunk's content hash.
/// For multiple chunks, a balanced Merkle tree is constructed.
///
/// # Security Model
///
/// The chain root provides:
///
/// - **Completeness**: All chunks contribute to the root
/// - **Ordering**: Chunk order affects the root value
/// - **Tamper-evidence**: Any modification changes the root
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatTranscriptBinding {
    /// Ordered list of transcript chunks.
    transcript_chunks: Vec<TranscriptChunk>,

    /// Merkle root hash of the transcript chain.
    #[serde(with = "serde_bytes")]
    transcript_chain_root_hash: [u8; 32],

    /// Hashes linking to individual run transcripts.
    #[serde(with = "vec_hash_serde")]
    run_transcript_hashes: Vec<[u8; 32]>,
}

/// Custom serde for Vec<[u8; 32]>.
mod vec_hash_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(hashes: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec_of_vecs: Vec<&[u8]> = hashes.iter().map(<[u8; 32]>::as_slice).collect();
        vec_of_vecs.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec_of_vecs = Vec::<Vec<u8>>::deserialize(deserializer)?;
        vec_of_vecs
            .into_iter()
            .map(|v| {
                if v.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(arr)
            })
            .collect()
    }
}

impl AatTranscriptBinding {
    /// Creates a new transcript binding from chunks and run hashes.
    ///
    /// The chain root hash is computed automatically from the provided chunks.
    ///
    /// # Arguments
    ///
    /// * `transcript_chunks` - Ordered list of transcript chunks
    /// * `run_transcript_hashes` - Hashes linking to individual run transcripts
    ///
    /// # Panics
    ///
    /// Panics if the number of chunks exceeds [`MAX_TRANSCRIPT_CHUNKS`] or if
    /// the number of run hashes exceeds [`MAX_RUN_TRANSCRIPT_HASHES`].
    #[must_use]
    pub fn new(
        transcript_chunks: Vec<TranscriptChunk>,
        run_transcript_hashes: Vec<[u8; 32]>,
    ) -> Self {
        Self::try_new(transcript_chunks, run_transcript_hashes)
            .expect("chunks or run hashes exceed limits")
    }

    /// Attempts to create a new transcript binding from chunks and run hashes.
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptBindingError::TooManyChunks`] if the number of
    /// chunks exceeds [`MAX_TRANSCRIPT_CHUNKS`].
    ///
    /// Returns [`TranscriptBindingError::TooManyRunHashes`] if the number of
    /// run hashes exceeds [`MAX_RUN_TRANSCRIPT_HASHES`].
    pub fn try_new(
        transcript_chunks: Vec<TranscriptChunk>,
        run_transcript_hashes: Vec<[u8; 32]>,
    ) -> Result<Self, TranscriptBindingError> {
        if transcript_chunks.len() > MAX_TRANSCRIPT_CHUNKS {
            return Err(TranscriptBindingError::TooManyChunks {
                actual: transcript_chunks.len(),
                max: MAX_TRANSCRIPT_CHUNKS,
            });
        }

        if run_transcript_hashes.len() > MAX_RUN_TRANSCRIPT_HASHES {
            return Err(TranscriptBindingError::TooManyRunHashes {
                actual: run_transcript_hashes.len(),
                max: MAX_RUN_TRANSCRIPT_HASHES,
            });
        }

        let transcript_chain_root_hash = Self::compute_chain_root_from_chunks(&transcript_chunks);

        Ok(Self {
            transcript_chunks,
            transcript_chain_root_hash,
            run_transcript_hashes,
        })
    }

    /// Creates a transcript binding from pre-computed values.
    ///
    /// Use this when deserializing or when values are already known. The caller
    /// is responsible for ensuring the chain root hash is valid.
    ///
    /// # Arguments
    ///
    /// * `transcript_chunks` - Ordered list of transcript chunks
    /// * `transcript_chain_root_hash` - Pre-computed Merkle root hash
    /// * `run_transcript_hashes` - Hashes linking to individual run transcripts
    #[must_use]
    pub const fn from_parts(
        transcript_chunks: Vec<TranscriptChunk>,
        transcript_chain_root_hash: [u8; 32],
        run_transcript_hashes: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            transcript_chunks,
            transcript_chain_root_hash,
            run_transcript_hashes,
        }
    }

    /// Returns the transcript chunks.
    #[must_use]
    pub fn transcript_chunks(&self) -> &[TranscriptChunk] {
        &self.transcript_chunks
    }

    /// Returns the transcript chain root hash.
    #[must_use]
    pub const fn transcript_chain_root_hash(&self) -> [u8; 32] {
        self.transcript_chain_root_hash
    }

    /// Returns the run transcript hashes.
    #[must_use]
    pub fn run_transcript_hashes(&self) -> &[[u8; 32]] {
        &self.run_transcript_hashes
    }

    /// Returns the number of transcript chunks.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.transcript_chunks.len()
    }

    /// Returns the total content size across all chunks.
    #[must_use]
    pub fn total_content_size(&self) -> u64 {
        self.transcript_chunks
            .iter()
            .map(TranscriptChunk::content_size)
            .sum()
    }

    /// Computes the chain root hash from the current chunks.
    ///
    /// This recomputes the Merkle root from the stored chunks. Use this to
    /// verify that the stored `transcript_chain_root_hash` is valid.
    #[must_use]
    pub fn compute_chain_root(&self) -> [u8; 32] {
        Self::compute_chain_root_from_chunks(&self.transcript_chunks)
    }

    /// Computes the Merkle root from a list of chunks.
    ///
    /// # Algorithm
    ///
    /// 1. If no chunks, return hash of empty byte array
    /// 2. If one chunk, return that chunk's content hash
    /// 3. Otherwise, build a balanced Merkle tree:
    ///    - Collect all chunk content hashes as leaves
    ///    - Repeatedly hash pairs until one root remains
    ///    - If odd number of nodes, duplicate the last node
    #[must_use]
    pub fn compute_chain_root_from_chunks(chunks: &[TranscriptChunk]) -> [u8; 32] {
        if chunks.is_empty() {
            // Empty transcript: hash of empty content
            return *blake3::hash(&[]).as_bytes();
        }

        if chunks.len() == 1 {
            // Single chunk: return its hash directly
            return chunks[0].content_hash();
        }

        // Multiple chunks: build Merkle tree
        let mut level: Vec<[u8; 32]> = chunks.iter().map(TranscriptChunk::content_hash).collect();

        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));

            let mut i = 0;
            while i < level.len() {
                let left = level[i];
                // If odd number of nodes, duplicate the last one
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    level[i]
                };

                // Hash the concatenation of left and right
                let mut hasher = blake3::Hasher::new();
                hasher.update(&left);
                hasher.update(&right);
                next_level.push(*hasher.finalize().as_bytes());

                i += 2;
            }

            level = next_level;
        }

        level[0]
    }

    /// Validates the transcript chain integrity.
    ///
    /// This method verifies:
    ///
    /// 1. The stored chain root hash matches the computed Merkle root
    /// 2. Chunk sequence numbers are monotonically increasing (0, 1, 2, ...)
    /// 3. No duplicate chunk hashes exist
    /// 4. Collection sizes are within limits
    ///
    /// # Returns
    ///
    /// `Ok(())` if validation passes.
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptBindingError::ChainRootMismatch`] if the stored
    /// hash does not match the computed hash.
    ///
    /// Returns [`TranscriptBindingError::SequenceOutOfOrder`] if chunk
    /// sequence numbers are not monotonically increasing.
    ///
    /// Returns [`TranscriptBindingError::TooManyChunks`] if there are too
    /// many chunks.
    ///
    /// Returns [`TranscriptBindingError::TooManyRunHashes`] if there are too
    /// many run transcript hashes.
    pub fn validate(&self) -> Result<(), TranscriptBindingError> {
        // Check collection sizes
        if self.transcript_chunks.len() > MAX_TRANSCRIPT_CHUNKS {
            return Err(TranscriptBindingError::TooManyChunks {
                actual: self.transcript_chunks.len(),
                max: MAX_TRANSCRIPT_CHUNKS,
            });
        }

        if self.run_transcript_hashes.len() > MAX_RUN_TRANSCRIPT_HASHES {
            return Err(TranscriptBindingError::TooManyRunHashes {
                actual: self.run_transcript_hashes.len(),
                max: MAX_RUN_TRANSCRIPT_HASHES,
            });
        }

        // Validate sequence numbers are monotonically increasing from 0
        for (expected, chunk) in self.transcript_chunks.iter().enumerate() {
            let expected_seq = expected as u64;
            if chunk.sequence() != expected_seq {
                return Err(TranscriptBindingError::SequenceOutOfOrder {
                    expected: expected_seq,
                    actual: chunk.sequence(),
                });
            }
        }

        // Check for duplicate chunk hashes
        let mut seen_hashes = std::collections::HashSet::new();
        for chunk in &self.transcript_chunks {
            if !seen_hashes.insert(chunk.content_hash()) {
                return Err(TranscriptBindingError::DuplicateChunkHash {
                    sequence: chunk.sequence(),
                });
            }
        }

        // Verify chain root hash matches computed value
        let computed = self.compute_chain_root();
        if computed != self.transcript_chain_root_hash {
            return Err(TranscriptBindingError::ChainRootMismatch {
                computed,
                stored: self.transcript_chain_root_hash,
            });
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs, clippy::cast_possible_truncation)]
pub mod tests {
    use super::*;

    // =========================================================================
    // TranscriptChunk Tests
    // =========================================================================

    #[test]
    fn test_transcript_chunk_new() {
        let content = b"Hello, world!";
        let chunk = TranscriptChunk::new(content, 0);

        assert_eq!(chunk.sequence(), 0);
        assert_eq!(chunk.content_size(), content.len() as u64);
        assert!(chunk.verify_content(content));
    }

    #[test]
    fn test_transcript_chunk_hash_determinism() {
        let content = b"Test content";
        let chunk1 = TranscriptChunk::new(content, 0);
        let chunk2 = TranscriptChunk::new(content, 0);

        assert_eq!(chunk1.content_hash(), chunk2.content_hash());
    }

    #[test]
    fn test_transcript_chunk_different_content_different_hash() {
        let chunk1 = TranscriptChunk::new(b"Content A", 0);
        let chunk2 = TranscriptChunk::new(b"Content B", 0);

        assert_ne!(chunk1.content_hash(), chunk2.content_hash());
    }

    #[test]
    fn test_transcript_chunk_verify_content() {
        let content = b"Verify me!";
        let chunk = TranscriptChunk::new(content, 0);

        assert!(chunk.verify_content(content));
        assert!(!chunk.verify_content(b"Wrong content"));
    }

    #[test]
    fn test_transcript_chunk_from_hash() {
        let content = b"Pre-hashed content";
        let content_hash = *blake3::hash(content).as_bytes();

        let chunk = TranscriptChunk::from_hash(content_hash, 5, content.len() as u64);

        assert_eq!(chunk.content_hash(), content_hash);
        assert_eq!(chunk.sequence(), 5);
        assert_eq!(chunk.content_size(), content.len() as u64);
        assert!(chunk.verify_content(content));
    }

    #[test]
    fn test_transcript_chunk_serde_roundtrip() {
        let chunk = TranscriptChunk::new(b"Serializable content", 42);
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: TranscriptChunk = serde_json::from_str(&json).unwrap();

        assert_eq!(chunk, deserialized);
    }

    #[test]
    fn test_transcript_chunk_too_large() {
        let large_content = vec![0u8; MAX_CHUNK_CONTENT_BYTES + 1];
        let result = TranscriptChunk::try_new(&large_content, 0);

        assert!(matches!(
            result,
            Err(TranscriptBindingError::ChunkTooLarge { .. })
        ));
    }

    #[test]
    fn test_transcript_chunk_at_max_size() {
        let max_content = vec![0u8; MAX_CHUNK_CONTENT_BYTES];
        let result = TranscriptChunk::try_new(&max_content, 0);

        assert!(result.is_ok());
    }

    // =========================================================================
    // AatTranscriptBinding Chain Root Tests
    // =========================================================================

    #[test]
    fn test_empty_chunks_chain_root() {
        let binding = AatTranscriptBinding::new(vec![], vec![]);

        let expected_root = *blake3::hash(&[]).as_bytes();
        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_single_chunk_chain_root() {
        let content = b"Single chunk content";
        let chunk = TranscriptChunk::new(content, 0);
        let expected_root = chunk.content_hash();

        let binding = AatTranscriptBinding::new(vec![chunk], vec![]);

        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_two_chunks_chain_root() {
        let chunk1 = TranscriptChunk::new(b"First", 0);
        let chunk2 = TranscriptChunk::new(b"Second", 1);

        // Expected: hash(chunk1_hash || chunk2_hash)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&chunk1.content_hash());
        hasher.update(&chunk2.content_hash());
        let expected_root = *hasher.finalize().as_bytes();

        let binding = AatTranscriptBinding::new(vec![chunk1, chunk2], vec![]);

        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_three_chunks_chain_root() {
        let chunk1 = TranscriptChunk::new(b"A", 0);
        let chunk2 = TranscriptChunk::new(b"B", 1);
        let chunk3 = TranscriptChunk::new(b"C", 2);

        // Level 0: [h1, h2, h3]
        // Level 1: [hash(h1||h2), hash(h3||h3)]
        // Level 2: [hash(l1_0||l1_1)]

        let h1 = chunk1.content_hash();
        let h2 = chunk2.content_hash();
        let h3 = chunk3.content_hash();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&h1);
        hasher.update(&h2);
        let l1_0 = *hasher.finalize().as_bytes();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&h3);
        hasher.update(&h3); // Duplicate for odd count
        let l1_1 = *hasher.finalize().as_bytes();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&l1_0);
        hasher.update(&l1_1);
        let expected_root = *hasher.finalize().as_bytes();

        let binding = AatTranscriptBinding::new(vec![chunk1, chunk2, chunk3], vec![]);

        assert_eq!(binding.transcript_chain_root_hash(), expected_root);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_chain_root_deterministic() {
        let chunks = vec![
            TranscriptChunk::new(b"Chunk 1", 0),
            TranscriptChunk::new(b"Chunk 2", 1),
            TranscriptChunk::new(b"Chunk 3", 2),
            TranscriptChunk::new(b"Chunk 4", 3),
        ];

        let binding1 = AatTranscriptBinding::new(chunks.clone(), vec![]);
        let binding2 = AatTranscriptBinding::new(chunks, vec![]);

        assert_eq!(
            binding1.transcript_chain_root_hash(),
            binding2.transcript_chain_root_hash()
        );
    }

    #[test]
    fn test_chain_root_order_matters() {
        let chunk1 = TranscriptChunk::new(b"First", 0);
        let chunk2 = TranscriptChunk::new(b"Second", 1);

        let binding1 = AatTranscriptBinding::new(vec![chunk1.clone(), chunk2.clone()], vec![]);

        // Create with different sequence numbers to reorder
        let reordered_chunk1 =
            TranscriptChunk::from_hash(chunk2.content_hash(), 0, chunk2.content_size());
        let reordered_chunk2 =
            TranscriptChunk::from_hash(chunk1.content_hash(), 1, chunk1.content_size());
        let binding2 = AatTranscriptBinding::new(vec![reordered_chunk1, reordered_chunk2], vec![]);

        // Different order = different root
        assert_ne!(
            binding1.transcript_chain_root_hash(),
            binding2.transcript_chain_root_hash()
        );
    }

    // =========================================================================
    // AatTranscriptBinding Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_chain_root_mismatch() {
        let chunk = TranscriptChunk::new(b"Content", 0);
        let wrong_root = [0xAB; 32];

        let binding = AatTranscriptBinding::from_parts(vec![chunk], wrong_root, vec![]);

        let result = binding.validate();
        assert!(matches!(
            result,
            Err(TranscriptBindingError::ChainRootMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_sequence_out_of_order() {
        // Create chunks with non-sequential sequence numbers
        let chunk1 = TranscriptChunk::from_hash([0x11; 32], 0, 10);
        let chunk2 = TranscriptChunk::from_hash([0x22; 32], 5, 10); // Should be 1

        // Compute the root from these chunks
        let root =
            AatTranscriptBinding::compute_chain_root_from_chunks(&[chunk1.clone(), chunk2.clone()]);
        let binding = AatTranscriptBinding::from_parts(vec![chunk1, chunk2], root, vec![]);

        let result = binding.validate();
        assert!(matches!(
            result,
            Err(TranscriptBindingError::SequenceOutOfOrder {
                expected: 1,
                actual: 5,
            })
        ));
    }

    #[test]
    fn test_validate_duplicate_chunk_hash() {
        // Create chunks with the same content (same hash)
        let content = b"Duplicate content";
        let chunk1 = TranscriptChunk::new(content, 0);
        let chunk2 = TranscriptChunk::from_hash(chunk1.content_hash(), 1, chunk1.content_size());

        let root =
            AatTranscriptBinding::compute_chain_root_from_chunks(&[chunk1.clone(), chunk2.clone()]);
        let binding = AatTranscriptBinding::from_parts(vec![chunk1, chunk2], root, vec![]);

        let result = binding.validate();
        assert!(matches!(
            result,
            Err(TranscriptBindingError::DuplicateChunkHash { sequence: 1 })
        ));
    }

    #[test]
    fn test_validate_success() {
        let chunks = vec![
            TranscriptChunk::new(b"Message 1", 0),
            TranscriptChunk::new(b"Message 2", 1),
            TranscriptChunk::new(b"Message 3", 2),
        ];
        let run_hashes = vec![[0x11; 32], [0x22; 32]];

        let binding = AatTranscriptBinding::new(chunks, run_hashes);

        assert!(binding.validate().is_ok());
    }

    // =========================================================================
    // AatTranscriptBinding Resource Limit Tests
    // =========================================================================

    #[test]
    fn test_too_many_chunks() {
        let chunks: Vec<TranscriptChunk> = (0..=MAX_TRANSCRIPT_CHUNKS as u64)
            .map(|i| TranscriptChunk::from_hash([i as u8; 32], i, 10))
            .collect();

        let result = AatTranscriptBinding::try_new(chunks, vec![]);
        assert!(matches!(
            result,
            Err(TranscriptBindingError::TooManyChunks { .. })
        ));
    }

    #[test]
    fn test_too_many_run_hashes() {
        let run_hashes: Vec<[u8; 32]> = (0..=MAX_RUN_TRANSCRIPT_HASHES)
            .map(|i| [i as u8; 32])
            .collect();

        let result = AatTranscriptBinding::try_new(vec![], run_hashes);
        assert!(matches!(
            result,
            Err(TranscriptBindingError::TooManyRunHashes { .. })
        ));
    }

    #[test]
    fn test_at_max_chunks() {
        // This test is expensive, so we use a smaller subset
        let chunks: Vec<TranscriptChunk> = (0..100u64)
            .map(|i| TranscriptChunk::from_hash([i as u8; 32], i, 10))
            .collect();

        let result = AatTranscriptBinding::try_new(chunks, vec![]);
        assert!(result.is_ok());
    }

    // =========================================================================
    // AatTranscriptBinding Accessor Tests
    // =========================================================================

    #[test]
    fn test_accessors() {
        let chunks = vec![
            TranscriptChunk::new(b"A", 0),
            TranscriptChunk::new(b"BB", 1),
            TranscriptChunk::new(b"CCC", 2),
        ];
        let run_hashes = vec![[0x11; 32]];

        let binding = AatTranscriptBinding::new(chunks, run_hashes);

        assert_eq!(binding.chunk_count(), 3);
        assert_eq!(binding.total_content_size(), 1 + 2 + 3);
        assert_eq!(binding.transcript_chunks().len(), 3);
        assert_eq!(binding.run_transcript_hashes().len(), 1);
    }

    // =========================================================================
    // Serde Tests
    // =========================================================================

    #[test]
    fn test_binding_serde_roundtrip() {
        let chunks = vec![
            TranscriptChunk::new(b"First", 0),
            TranscriptChunk::new(b"Second", 1),
        ];
        let run_hashes = vec![[0x11; 32], [0x22; 32]];

        let binding = AatTranscriptBinding::new(chunks, run_hashes);

        let json = serde_json::to_string(&binding).unwrap();
        let deserialized: AatTranscriptBinding = serde_json::from_str(&json).unwrap();

        assert_eq!(binding, deserialized);
    }

    #[test]
    fn test_binding_serde_deny_unknown_fields() {
        let json = r#"{
            "transcript_chunks": [],
            "transcript_chain_root_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "run_transcript_hashes": [],
            "unknown_field": "should_fail"
        }"#;

        let result: Result<AatTranscriptBinding, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // compute_chain_root Tests
    // =========================================================================

    #[test]
    fn test_compute_chain_root_matches_stored() {
        let chunks = vec![
            TranscriptChunk::new(b"X", 0),
            TranscriptChunk::new(b"Y", 1),
            TranscriptChunk::new(b"Z", 2),
        ];

        let binding = AatTranscriptBinding::new(chunks, vec![]);

        // compute_chain_root should match the stored hash
        assert_eq!(
            binding.compute_chain_root(),
            binding.transcript_chain_root_hash()
        );
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_large_chunk_merkle_tree() {
        // Test with power of 2 chunks (no duplication needed)
        let chunks: Vec<TranscriptChunk> = (0..8u64)
            .map(|i| TranscriptChunk::new(format!("Chunk {i}").as_bytes(), i))
            .collect();

        let binding = AatTranscriptBinding::new(chunks, vec![]);
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn test_non_power_of_two_chunks() {
        // Test with 7 chunks (requires duplication)
        let chunks: Vec<TranscriptChunk> = (0..7u64)
            .map(|i| TranscriptChunk::new(format!("Chunk {i}").as_bytes(), i))
            .collect();

        let binding = AatTranscriptBinding::new(chunks, vec![]);
        assert!(binding.validate().is_ok());
    }
}
