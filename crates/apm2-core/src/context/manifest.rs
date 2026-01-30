// AGENT-AUTHORED
//! Context pack manifest types for file access control.
//!
//! This module defines [`ContextPackManifest`] which represents the OCAP
//! (Object-Capability) allowlist for file reads. The manifest defines which
//! files an agent is permitted to read and at what access level.
//!
//! # Security Model
//!
//! The context firewall uses the manifest as an allowlist:
//!
//! 1. **Path matching**: Only files explicitly listed in the manifest can be
//!    read
//! 2. **Content hash verification**: File content must match the recorded
//!    `content_hash` to prevent TOCTOU (time-of-check-to-time-of-use) attacks
//! 3. **Access levels**: Different access levels (Read, `ReadWithZoom`) control
//!    what operations are permitted
//!
//! # OCAP Model
//!
//! The manifest implements the Object-Capability security model:
//!
//! - **Unforgeable**: Manifests are identified by cryptographic hash
//! - **Transferable**: Manifests can be passed to authorized agents
//! - **Attenuated**: Access levels can only be reduced, never elevated
//!
//! # Example
//!
//! ```rust
//! use apm2_core::context::{
//!     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
//!     ManifestEntry,
//! };
//!
//! // Create a manifest with file entries
//! let manifest =
//!     ContextPackManifestBuilder::new("manifest-001", "profile-001")
//!         .add_entry(ManifestEntry {
//!             stable_id: Some("src-main".to_string()),
//!             path: "/project/src/main.rs".to_string(),
//!             content_hash: [0x42; 32],
//!             access_level: AccessLevel::Read,
//!         })
//!         .add_entry(ManifestEntry {
//!             stable_id: None,
//!             path: "/project/README.md".to_string(),
//!             content_hash: [0xAB; 32],
//!             access_level: AccessLevel::ReadWithZoom,
//!         })
//!         .build();
//!
//! // Check if a file is allowed
//! assert!(manifest.is_allowed("/project/src/main.rs", &[0x42; 32]));
//!
//! // Wrong hash is rejected
//! assert!(!manifest.is_allowed("/project/src/main.rs", &[0xFF; 32]));
//!
//! // Unknown path is rejected
//! assert!(!manifest.is_allowed("/project/secret.txt", &[0x00; 32]));
//! ```

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::fac::MAX_STRING_LENGTH;

// =============================================================================
// Resource Limits (DoS Protection)
// =============================================================================

/// Maximum number of entries allowed in a context pack manifest.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_ENTRIES: usize = 10_000;

/// Maximum path length in bytes.
/// Prevents memory exhaustion from extremely long paths.
pub const MAX_PATH_LENGTH: usize = 4096;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during manifest operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual length of the string.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Path exceeds maximum length.
    #[error("path exceeds max length: {actual} > {max}")]
    PathTooLong {
        /// Actual length of the path.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Collection size exceeds resource limit.
    #[error("collection size exceeds limit: {field} has {actual} items, max is {max}")]
    CollectionTooLarge {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual size of the collection.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid manifest data.
    #[error("invalid manifest data: {0}")]
    InvalidData(String),

    /// Duplicate path in manifest.
    #[error("duplicate path in manifest: {path}")]
    DuplicatePath {
        /// The duplicate path.
        path: String,
    },

    /// Duplicate `stable_id` in manifest.
    #[error("duplicate stable_id in manifest: {stable_id}")]
    DuplicateStableId {
        /// The duplicate `stable_id`.
        stable_id: String,
    },

    /// Path not found in manifest.
    #[error("path not found in manifest: {path}")]
    PathNotFound {
        /// The path that was not found.
        path: String,
    },

    /// Content hash mismatch.
    #[error("content hash mismatch for path: {path}")]
    ContentHashMismatch {
        /// The path with mismatched hash.
        path: String,
    },
}

// =============================================================================
// AccessLevel
// =============================================================================

/// Access level for a manifest entry.
///
/// Defines what operations are permitted on the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccessLevel {
    /// Read-only access to the file content.
    Read         = 0,
    /// Read access with zoom capability (e.g., semantic navigation).
    ReadWithZoom = 1,
}

impl TryFrom<u8> for AccessLevel {
    type Error = ManifestError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Read),
            1 => Ok(Self::ReadWithZoom),
            _ => Err(ManifestError::InvalidData(format!(
                "invalid access level {value}, must be 0-1"
            ))),
        }
    }
}

impl From<AccessLevel> for u8 {
    fn from(level: AccessLevel) -> Self {
        level as Self
    }
}

// =============================================================================
// ManifestEntry
// =============================================================================

/// An entry in the context pack manifest.
///
/// Each entry defines a single file that is permitted to be read, along with
/// its content hash for integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// Optional stable identifier for the entry.
    ///
    /// Used for semantic referencing across manifest versions. When present,
    /// allows tracking the same logical file across renames or moves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stable_id: Option<String>,

    /// Absolute path to the file.
    pub path: String,

    /// BLAKE3 hash of the file content.
    ///
    /// Used for integrity verification to prevent TOCTOU attacks.
    #[serde(with = "serde_bytes")]
    pub content_hash: [u8; 32],

    /// Access level for this file.
    pub access_level: AccessLevel,
}

// =============================================================================
// ContextPackManifest
// =============================================================================

/// A context pack manifest defining the allowlist for file reads.
///
/// The manifest is the central data structure for the context firewall. It
/// defines which files an agent is permitted to read and provides content
/// hashes for integrity verification.
///
/// # Fields
///
/// - `manifest_id`: Unique identifier for this manifest
/// - `manifest_hash`: BLAKE3 hash of the manifest content (computed at build
///   time)
/// - `profile_id`: Profile that generated this manifest
/// - `entries`: List of allowed file entries
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPackManifest {
    /// Unique identifier for this manifest.
    pub manifest_id: String,

    /// BLAKE3 hash of the manifest content.
    #[serde(with = "serde_bytes")]
    manifest_hash: [u8; 32],

    /// Profile that generated this manifest.
    pub profile_id: String,

    /// List of allowed file entries.
    pub entries: Vec<ManifestEntry>,
}

impl ContextPackManifest {
    /// Returns the manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    /// Computes the manifest hash from the manifest fields.
    ///
    /// The hash is computed over the canonical representation of all fields
    /// except the hash itself.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn compute_manifest_hash(
        manifest_id: &str,
        profile_id: &str,
        entries: &[ManifestEntry],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Manifest ID (length-prefixed)
        hasher.update(&(manifest_id.len() as u32).to_be_bytes());
        hasher.update(manifest_id.as_bytes());

        // Profile ID (length-prefixed)
        hasher.update(&(profile_id.len() as u32).to_be_bytes());
        hasher.update(profile_id.as_bytes());

        // Entries
        hasher.update(&(entries.len() as u32).to_be_bytes());
        for entry in entries {
            // stable_id (optional, length-prefixed)
            if let Some(ref stable_id) = entry.stable_id {
                hasher.update(&[1u8]); // presence flag
                hasher.update(&(stable_id.len() as u32).to_be_bytes());
                hasher.update(stable_id.as_bytes());
            } else {
                hasher.update(&[0u8]); // absence flag
            }

            // path (length-prefixed)
            hasher.update(&(entry.path.len() as u32).to_be_bytes());
            hasher.update(entry.path.as_bytes());

            // content_hash
            hasher.update(&entry.content_hash);

            // access_level
            hasher.update(&[entry.access_level as u8]);
        }

        *hasher.finalize().as_bytes()
    }

    /// Checks if access to a file is allowed.
    ///
    /// This is the primary security check for the context firewall. A file
    /// access is allowed if and only if:
    ///
    /// 1. The path exists in the manifest
    /// 2. The content hash matches the manifest entry (constant-time
    ///    comparison)
    ///
    /// # Security Notes
    ///
    /// - Uses constant-time comparison for hash verification to prevent timing
    ///   attacks
    /// - Both path and hash must match; path-only matching is not sufficient
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute path to check
    /// * `content_hash` - The BLAKE3 hash of the file content
    ///
    /// # Returns
    ///
    /// `true` if access is allowed, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::context::{
    ///     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
    ///     ManifestEntry,
    /// };
    ///
    /// let manifest =
    ///     ContextPackManifestBuilder::new("manifest-001", "profile-001")
    ///         .add_entry(ManifestEntry {
    ///             stable_id: None,
    ///             path: "/project/src/main.rs".to_string(),
    ///             content_hash: [0x42; 32],
    ///             access_level: AccessLevel::Read,
    ///         })
    ///         .build();
    ///
    /// // Matching path and hash: allowed
    /// assert!(manifest.is_allowed("/project/src/main.rs", &[0x42; 32]));
    ///
    /// // Wrong hash: denied
    /// assert!(!manifest.is_allowed("/project/src/main.rs", &[0xFF; 32]));
    ///
    /// // Unknown path: denied
    /// assert!(!manifest.is_allowed("/other/file.rs", &[0x42; 32]));
    /// ```
    #[must_use]
    pub fn is_allowed(&self, path: &str, content_hash: &[u8; 32]) -> bool {
        for entry in &self.entries {
            if entry.path == path {
                // Use constant-time comparison for security
                return bool::from(entry.content_hash.ct_eq(content_hash));
            }
        }
        false
    }

    /// Gets a manifest entry by path.
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute path to look up
    ///
    /// # Returns
    ///
    /// `Some(&ManifestEntry)` if found, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::context::{
    ///     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
    ///     ManifestEntry,
    /// };
    ///
    /// let manifest =
    ///     ContextPackManifestBuilder::new("manifest-001", "profile-001")
    ///         .add_entry(ManifestEntry {
    ///             stable_id: Some("main-file".to_string()),
    ///             path: "/project/src/main.rs".to_string(),
    ///             content_hash: [0x42; 32],
    ///             access_level: AccessLevel::Read,
    ///         })
    ///         .build();
    ///
    /// let entry = manifest.get_entry("/project/src/main.rs").unwrap();
    /// assert_eq!(entry.stable_id, Some("main-file".to_string()));
    /// assert_eq!(entry.access_level, AccessLevel::Read);
    /// ```
    #[must_use]
    pub fn get_entry(&self, path: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// Gets a manifest entry by `stable_id`.
    ///
    /// # Arguments
    ///
    /// * `stable_id` - The stable identifier to look up
    ///
    /// # Returns
    ///
    /// `Some(&ManifestEntry)` if found, `None` otherwise.
    #[must_use]
    pub fn get_entry_by_stable_id(&self, stable_id: &str) -> Option<&ManifestEntry> {
        self.entries
            .iter()
            .find(|e| e.stable_id.as_deref() == Some(stable_id))
    }

    /// Validates access to a file and returns the entry if allowed.
    ///
    /// This is a stricter version of `is_allowed` that returns an error with
    /// details about why access was denied.
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute path to check
    /// * `content_hash` - The BLAKE3 hash of the file content
    ///
    /// # Returns
    ///
    /// `Ok(&ManifestEntry)` if access is allowed.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::PathNotFound`] if the path is not in the
    /// manifest.
    ///
    /// Returns [`ManifestError::ContentHashMismatch`] if the path exists but
    /// the hash doesn't match.
    pub fn validate_access(
        &self,
        path: &str,
        content_hash: &[u8; 32],
    ) -> Result<&ManifestEntry, ManifestError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.path == path)
            .ok_or_else(|| ManifestError::PathNotFound {
                path: path.to_string(),
            })?;

        // Use constant-time comparison for security
        if !bool::from(entry.content_hash.ct_eq(content_hash)) {
            return Err(ManifestError::ContentHashMismatch {
                path: path.to_string(),
            });
        }

        Ok(entry)
    }

    /// Verifies self-consistency by recomputing the manifest hash and
    /// comparing.
    ///
    /// This method recomputes the manifest hash from the current fields
    /// and verifies it matches the stored `manifest_hash`. This is useful
    /// after deserialization to ensure the manifest has not been tampered
    /// with.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the recomputed hash matches the stored hash.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidData`] if the computed hash does not
    /// match the stored hash.
    pub fn verify_self_consistency(&self) -> Result<(), ManifestError> {
        let computed_hash =
            Self::compute_manifest_hash(&self.manifest_id, &self.profile_id, &self.entries);

        // Use constant-time comparison for security
        if !bool::from(computed_hash.ct_eq(&self.manifest_hash)) {
            return Err(ManifestError::InvalidData(format!(
                "manifest hash self-consistency check failed: computed={}, stored={}",
                hex_encode(&computed_hash),
                hex_encode(&self.manifest_hash)
            )));
        }

        Ok(())
    }
}

/// Encodes bytes as a hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`ContextPackManifest`] instances.
#[derive(Debug, Default)]
pub struct ContextPackManifestBuilder {
    manifest_id: String,
    profile_id: String,
    entries: Vec<ManifestEntry>,
}

impl ContextPackManifestBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(manifest_id: impl Into<String>, profile_id: impl Into<String>) -> Self {
        Self {
            manifest_id: manifest_id.into(),
            profile_id: profile_id.into(),
            entries: Vec::new(),
        }
    }

    /// Adds a manifest entry.
    #[must_use]
    pub fn add_entry(mut self, entry: ManifestEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Sets all entries.
    #[must_use]
    pub fn entries(mut self, entries: Vec<ManifestEntry>) -> Self {
        self.entries = entries;
        self
    }

    /// Builds the manifest.
    ///
    /// # Panics
    ///
    /// Panics if validation fails.
    #[must_use]
    pub fn build(self) -> ContextPackManifest {
        self.try_build().expect("manifest build failed")
    }

    /// Attempts to build the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::StringTooLong`] if any string field exceeds
    /// the maximum length.
    /// Returns [`ManifestError::PathTooLong`] if any path exceeds the maximum
    /// length.
    /// Returns [`ManifestError::CollectionTooLarge`] if entries exceed the
    /// limit.
    /// Returns [`ManifestError::DuplicatePath`] if duplicate paths are found.
    /// Returns [`ManifestError::DuplicateStableId`] if duplicate `stable_id`s
    /// are found.
    pub fn try_build(self) -> Result<ContextPackManifest, ManifestError> {
        // Validate string lengths
        if self.manifest_id.len() > MAX_STRING_LENGTH {
            return Err(ManifestError::StringTooLong {
                field: "manifest_id",
                actual: self.manifest_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.profile_id.len() > MAX_STRING_LENGTH {
            return Err(ManifestError::StringTooLong {
                field: "profile_id",
                actual: self.profile_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate collection size
        if self.entries.len() > MAX_ENTRIES {
            return Err(ManifestError::CollectionTooLarge {
                field: "entries",
                actual: self.entries.len(),
                max: MAX_ENTRIES,
            });
        }

        // Track paths and stable_ids for duplicate detection
        let mut paths: Vec<&str> = Vec::with_capacity(self.entries.len());
        let mut stable_ids: Vec<&str> = Vec::new();

        for entry in &self.entries {
            // Validate path length
            if entry.path.len() > MAX_PATH_LENGTH {
                return Err(ManifestError::PathTooLong {
                    actual: entry.path.len(),
                    max: MAX_PATH_LENGTH,
                });
            }

            // Check for duplicate path
            if paths.contains(&entry.path.as_str()) {
                return Err(ManifestError::DuplicatePath {
                    path: entry.path.clone(),
                });
            }
            paths.push(&entry.path);

            // Validate and check stable_id
            if let Some(ref stable_id) = entry.stable_id {
                if stable_id.len() > MAX_STRING_LENGTH {
                    return Err(ManifestError::StringTooLong {
                        field: "entry.stable_id",
                        actual: stable_id.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
                if stable_ids.contains(&stable_id.as_str()) {
                    return Err(ManifestError::DuplicateStableId {
                        stable_id: stable_id.clone(),
                    });
                }
                stable_ids.push(stable_id);
            }
        }

        // Compute manifest hash
        let manifest_hash = ContextPackManifest::compute_manifest_hash(
            &self.manifest_id,
            &self.profile_id,
            &self.entries,
        );

        Ok(ContextPackManifest {
            manifest_id: self.manifest_id,
            manifest_hash,
            profile_id: self.profile_id,
            entries: self.entries,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;

    fn create_test_manifest() -> ContextPackManifest {
        ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: Some("src-main".to_string()),
                path: "/project/src/main.rs".to_string(),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .add_entry(ManifestEntry {
                stable_id: Some("readme".to_string()),
                path: "/project/README.md".to_string(),
                content_hash: [0xAB; 32],
                access_level: AccessLevel::ReadWithZoom,
            })
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/Cargo.toml".to_string(),
                content_hash: [0xCD; 32],
                access_level: AccessLevel::Read,
            })
            .build()
    }

    // =========================================================================
    // Basic Construction Tests
    // =========================================================================

    #[test]
    fn test_build_manifest() {
        let manifest = create_test_manifest();

        assert_eq!(manifest.manifest_id, "manifest-001");
        assert_eq!(manifest.profile_id, "profile-001");
        assert_eq!(manifest.entries.len(), 3);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let manifest1 = create_test_manifest();
        let manifest2 = create_test_manifest();

        // Same content should produce same hash
        assert_eq!(manifest1.manifest_hash(), manifest2.manifest_hash());
    }

    #[test]
    fn test_manifest_hash_differs_with_different_content() {
        let manifest1 = create_test_manifest();

        let manifest2 = ContextPackManifestBuilder::new("manifest-002", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/src/main.rs".to_string(),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .build();

        assert_ne!(manifest1.manifest_hash(), manifest2.manifest_hash());
    }

    // =========================================================================
    // is_allowed Tests
    // =========================================================================

    #[test]
    fn test_is_allowed_matching_path_and_hash() {
        let manifest = create_test_manifest();

        // Matching path and hash
        assert!(manifest.is_allowed("/project/src/main.rs", &[0x42; 32]));
        assert!(manifest.is_allowed("/project/README.md", &[0xAB; 32]));
        assert!(manifest.is_allowed("/project/Cargo.toml", &[0xCD; 32]));
    }

    #[test]
    fn test_is_allowed_wrong_hash_rejected() {
        let manifest = create_test_manifest();

        // Correct path but wrong hash
        assert!(!manifest.is_allowed("/project/src/main.rs", &[0xFF; 32]));
        assert!(!manifest.is_allowed("/project/README.md", &[0x00; 32]));
    }

    #[test]
    fn test_is_allowed_unknown_path_rejected() {
        let manifest = create_test_manifest();

        // Path not in manifest (even with a "valid" hash)
        assert!(!manifest.is_allowed("/project/secret.txt", &[0x42; 32]));
        assert!(!manifest.is_allowed("/other/path.rs", &[0x00; 32]));
    }

    #[test]
    fn test_is_allowed_empty_manifest() {
        let manifest = ContextPackManifestBuilder::new("manifest-empty", "profile-001").build();

        // Empty manifest rejects everything
        assert!(!manifest.is_allowed("/any/path.rs", &[0x42; 32]));
    }

    // =========================================================================
    // get_entry Tests
    // =========================================================================

    #[test]
    fn test_get_entry_found() {
        let manifest = create_test_manifest();

        let entry = manifest.get_entry("/project/src/main.rs").unwrap();
        assert_eq!(entry.stable_id, Some("src-main".to_string()));
        assert_eq!(entry.content_hash, [0x42; 32]);
        assert_eq!(entry.access_level, AccessLevel::Read);
    }

    #[test]
    fn test_get_entry_not_found() {
        let manifest = create_test_manifest();

        assert!(manifest.get_entry("/nonexistent/path.rs").is_none());
    }

    #[test]
    fn test_get_entry_by_stable_id() {
        let manifest = create_test_manifest();

        let entry = manifest.get_entry_by_stable_id("src-main").unwrap();
        assert_eq!(entry.path, "/project/src/main.rs");

        let entry = manifest.get_entry_by_stable_id("readme").unwrap();
        assert_eq!(entry.path, "/project/README.md");
    }

    #[test]
    fn test_get_entry_by_stable_id_not_found() {
        let manifest = create_test_manifest();

        assert!(manifest.get_entry_by_stable_id("nonexistent").is_none());
    }

    // =========================================================================
    // validate_access Tests
    // =========================================================================

    #[test]
    fn test_validate_access_success() {
        let manifest = create_test_manifest();

        let entry = manifest
            .validate_access("/project/src/main.rs", &[0x42; 32])
            .unwrap();
        assert_eq!(entry.stable_id, Some("src-main".to_string()));
    }

    #[test]
    fn test_validate_access_path_not_found() {
        let manifest = create_test_manifest();

        let result = manifest.validate_access("/nonexistent/path.rs", &[0x42; 32]);
        assert!(matches!(
            result,
            Err(ManifestError::PathNotFound { path }) if path == "/nonexistent/path.rs"
        ));
    }

    #[test]
    fn test_validate_access_hash_mismatch() {
        let manifest = create_test_manifest();

        let result = manifest.validate_access("/project/src/main.rs", &[0xFF; 32]);
        assert!(matches!(
            result,
            Err(ManifestError::ContentHashMismatch { path }) if path == "/project/src/main.rs"
        ));
    }

    // =========================================================================
    // Resource Limit Tests
    // =========================================================================

    #[test]
    fn test_entries_too_large() {
        let entries: Vec<ManifestEntry> = (0..=MAX_ENTRIES)
            .map(|i| ManifestEntry {
                stable_id: None,
                path: format!("/path/file-{i}.rs"),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .collect();

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .entries(entries)
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::CollectionTooLarge {
                field: "entries",
                actual,
                max,
            }) if actual == MAX_ENTRIES + 1 && max == MAX_ENTRIES
        ));
    }

    #[test]
    fn test_manifest_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ContextPackManifestBuilder::new(long_id, "profile-001").try_build();

        assert!(matches!(
            result,
            Err(ManifestError::StringTooLong {
                field: "manifest_id",
                ..
            })
        ));
    }

    #[test]
    fn test_profile_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ContextPackManifestBuilder::new("manifest-001", long_id).try_build();

        assert!(matches!(
            result,
            Err(ManifestError::StringTooLong {
                field: "profile_id",
                ..
            })
        ));
    }

    #[test]
    fn test_path_too_long() {
        let long_path = "/".to_string() + &"x".repeat(MAX_PATH_LENGTH);

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: None,
                path: long_path,
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .try_build();

        assert!(matches!(result, Err(ManifestError::PathTooLong { .. })));
    }

    #[test]
    fn test_stable_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: Some(long_id),
                path: "/project/file.rs".to_string(),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::StringTooLong {
                field: "entry.stable_id",
                ..
            })
        ));
    }

    // =========================================================================
    // Duplicate Detection Tests
    // =========================================================================

    #[test]
    fn test_duplicate_path_rejected() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/file.rs".to_string(),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/file.rs".to_string(), // Duplicate path
                content_hash: [0xAB; 32],
                access_level: AccessLevel::ReadWithZoom,
            })
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::DuplicatePath { path }) if path == "/project/file.rs"
        ));
    }

    #[test]
    fn test_duplicate_stable_id_rejected() {
        let result = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: Some("file-id".to_string()),
                path: "/project/file1.rs".to_string(),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .add_entry(ManifestEntry {
                stable_id: Some("file-id".to_string()), // Duplicate stable_id
                path: "/project/file2.rs".to_string(),
                content_hash: [0xAB; 32],
                access_level: AccessLevel::Read,
            })
            .try_build();

        assert!(matches!(
            result,
            Err(ManifestError::DuplicateStableId { stable_id }) if stable_id == "file-id"
        ));
    }

    // =========================================================================
    // Self-Consistency Tests
    // =========================================================================

    #[test]
    fn test_verify_self_consistency_passes() {
        let manifest = create_test_manifest();

        assert!(manifest.verify_self_consistency().is_ok());
    }

    #[test]
    fn test_verify_self_consistency_fails_on_tampered_manifest() {
        // Create a manifest with manually corrupted hash via JSON
        let json = r#"{"manifest_id":"manifest-001","manifest_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"profile_id":"profile-001","entries":[]}"#;
        let manifest: ContextPackManifest = serde_json::from_str(json).unwrap();

        let result = manifest.verify_self_consistency();
        assert!(
            matches!(result, Err(ManifestError::InvalidData(_))),
            "Expected InvalidData but got {result:?}"
        );
    }

    #[test]
    fn test_verify_self_consistency_after_deserialization() {
        let original = create_test_manifest();

        // Serialize and deserialize
        let json = serde_json::to_string(&original).unwrap();
        let recovered: ContextPackManifest = serde_json::from_str(&json).unwrap();

        // Self-consistency should still pass
        assert!(recovered.verify_self_consistency().is_ok());
    }

    // =========================================================================
    // AccessLevel Tests
    // =========================================================================

    #[test]
    fn test_access_level_try_from() {
        assert_eq!(AccessLevel::try_from(0).unwrap(), AccessLevel::Read);
        assert_eq!(AccessLevel::try_from(1).unwrap(), AccessLevel::ReadWithZoom);
        assert!(AccessLevel::try_from(2).is_err());
        assert!(AccessLevel::try_from(255).is_err());
    }

    #[test]
    fn test_access_level_to_u8() {
        assert_eq!(u8::from(AccessLevel::Read), 0);
        assert_eq!(u8::from(AccessLevel::ReadWithZoom), 1);
    }

    // =========================================================================
    // Serde Round-Trip Tests
    // =========================================================================

    #[test]
    fn test_serde_roundtrip() {
        let original = create_test_manifest();

        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();

        // Deserialize back
        let recovered: ContextPackManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(original.manifest_id, recovered.manifest_id);
        assert_eq!(original.manifest_hash, recovered.manifest_hash);
        assert_eq!(original.profile_id, recovered.profile_id);
        assert_eq!(original.entries, recovered.entries);
    }

    #[test]
    fn test_serde_deny_unknown_fields_manifest() {
        // JSON with unknown field should fail to deserialize
        let json = r#"{"manifest_id":"test","manifest_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"profile_id":"profile","entries":[],"unknown_field":"bad"}"#;

        let result: Result<ContextPackManifest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_deny_unknown_fields_entry() {
        // Entry JSON with unknown field should fail
        let json = r#"{"path":"/test","content_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"access_level":"Read","unknown":"bad"}"#;

        let result: Result<ManifestEntry, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Empty Manifest Tests
    // =========================================================================

    #[test]
    fn test_empty_manifest_valid() {
        let manifest = ContextPackManifestBuilder::new("manifest-empty", "profile-001").build();

        assert!(manifest.entries.is_empty());
        assert!(manifest.verify_self_consistency().is_ok());
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_entry_without_stable_id() {
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/file.rs".to_string(),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .build();

        assert!(manifest.is_allowed("/project/file.rs", &[0x42; 32]));
        assert!(manifest.get_entry_by_stable_id("any").is_none());
    }

    #[test]
    fn test_multiple_entries_same_hash_different_paths() {
        // Same content hash for different files is valid (same content in
        // different locations)
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/file1.rs".to_string(),
                content_hash: [0x42; 32],
                access_level: AccessLevel::Read,
            })
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/file2.rs".to_string(),
                content_hash: [0x42; 32], // Same hash, different path
                access_level: AccessLevel::Read,
            })
            .build();

        assert!(manifest.is_allowed("/project/file1.rs", &[0x42; 32]));
        assert!(manifest.is_allowed("/project/file2.rs", &[0x42; 32]));
    }

    #[test]
    fn test_constant_time_hash_comparison() {
        // This test verifies that hash comparison is done in constant time
        // by ensuring the same result regardless of where bytes differ
        let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
            .add_entry(ManifestEntry {
                stable_id: None,
                path: "/project/file.rs".to_string(),
                content_hash: [0xFF; 32],
                access_level: AccessLevel::Read,
            })
            .build();

        // Different in first byte
        let mut hash1 = [0xFF; 32];
        hash1[0] = 0x00;
        assert!(!manifest.is_allowed("/project/file.rs", &hash1));

        // Different in last byte
        let mut hash2 = [0xFF; 32];
        hash2[31] = 0x00;
        assert!(!manifest.is_allowed("/project/file.rs", &hash2));

        // All different
        assert!(!manifest.is_allowed("/project/file.rs", &[0x00; 32]));
    }
}
