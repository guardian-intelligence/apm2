//! Context module for file access control.
//!
//! This module provides types for managing context pack manifests, which define
//! the OCAP (Object-Capability) allowlist for file reads.
//!
//! # Components
//!
//! - [`ContextPackManifest`]: Defines which files are allowed to be read
//! - [`ManifestEntry`]: Individual file entry with path and content hash
//! - [`AccessLevel`]: Read or `ReadWithZoom` access levels
//!
//! # Security Model
//!
//! The context firewall uses manifests as allowlists:
//!
//! 1. Only files explicitly listed can be read
//! 2. Content hashes prevent TOCTOU (time-of-check-to-time-of-use) attacks
//! 3. All reads outside the allowlist are denied
//!
//! # Example
//!
//! ```rust
//! use apm2_core::context::{
//!     AccessLevel, ContextPackManifest, ContextPackManifestBuilder,
//!     ManifestEntry,
//! };
//!
//! let manifest =
//!     ContextPackManifestBuilder::new("manifest-001", "profile-001")
//!         .add_entry(ManifestEntry {
//!             stable_id: Some("main".to_string()),
//!             path: "/project/src/main.rs".to_string(),
//!             content_hash: [0x42; 32],
//!             access_level: AccessLevel::Read,
//!         })
//!         .build();
//!
//! // Check if access is allowed
//! if manifest.is_allowed("/project/src/main.rs", &[0x42; 32]) {
//!     println!("Access granted");
//! }
//! ```

mod manifest;

pub use manifest::{
    AccessLevel, ContextPackManifest, ContextPackManifestBuilder, MAX_ENTRIES, MAX_PATH_LENGTH,
    ManifestEntry, ManifestError,
};
