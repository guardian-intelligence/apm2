//! HSI Contract Manifest V1 types and canonical serialization.
//!
//! This module defines the `HSIContractManifestV1` structure and its
//! deterministic canonical bytes encoding per RFC-0020 section 3.1 and
//! section 1.5. The manifest is a content-addressed artifact stored in CAS
//! and referenced by its BLAKE3 hash.
//!
//! # Canonical Bytes Encoding
//!
//! The manifest uses a deterministic binary encoding:
//! 1. All repeated fields (routes) are sorted lexicographically by `route`
//! 2. String fields use length-prefixed UTF-8 encoding
//! 3. Enum fields use fixed u8 discriminant values
//! 4. Boolean fields use single-byte encoding (0x00/0x01)
//!
//! # Domain Separation (RFC-0020 section 1.5.2)
//!
//! The content hash is computed as:
//! `blake3("apm2:apm2.hsi_contract.v1:1.0.0\n" + canonical_bytes)`
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1: `HSIContractManifestV1`
//! - RFC-0020 section 1.5: `ContentHash` and canonical bytes
//! - RFC-0020 section 1.5.2: Domain separation
//! - `CTR-0001`: `HSIContractManifestV1` contract

use serde::{Deserialize, Serialize};

/// Schema identifier for the HSI contract manifest.
pub const SCHEMA_ID: &str = "apm2.hsi_contract.v1";

/// Schema version for the HSI contract manifest.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Domain separation prefix for content hashing.
///
/// Per RFC-0020 section 1.5.2:
/// `hash("apm2:" + schema_id + ":" + schema_version + "\n" + canonical_bytes)`
pub const DOMAIN_PREFIX: &str = "apm2:apm2.hsi_contract.v1:1.0.0\n";

/// Maximum number of routes in a manifest (denial-of-service bound).
pub const MAX_ROUTES: usize = 1024;

/// Maximum length of a route string.
pub const MAX_ROUTE_LEN: usize = 256;

/// Maximum length of a schema ID string.
pub const MAX_SCHEMA_ID_LEN: usize = 256;

/// Stability classification for an HSI route.
///
/// Per RFC-0020 section 3.1, routes are classified as experimental, stable,
/// or deprecated. Unknown values are invalid (fail-closed enum decoding per
/// section 1.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StabilityClass {
    /// Route is experimental and may change without notice.
    Experimental = 0,
    /// Route is stable and follows semver compatibility rules.
    Stable       = 1,
    /// Route is deprecated and will be removed in a future version.
    Deprecated   = 2,
}

impl StabilityClass {
    /// Returns the canonical byte discriminant.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    /// Parses from a u8 discriminant. Returns `None` for unknown values
    /// (fail-closed per RFC-0020 section 1.2.3).
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Experimental),
            1 => Some(Self::Stable),
            2 => Some(Self::Deprecated),
            _ => None,
        }
    }
}

impl std::fmt::Display for StabilityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Experimental => write!(f, "EXPERIMENTAL"),
            Self::Stable => write!(f, "STABLE"),
            Self::Deprecated => write!(f, "DEPRECATED"),
        }
    }
}

/// Idempotency requirement for a route.
///
/// Per RFC-0020 section 3.1, side-effectful routes MUST declare
/// their idempotency requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IdempotencyRequirement {
    /// Idempotency is not required (read-only or advisory route).
    NotRequired = 0,
    /// Idempotency is required (precondition guards enforced).
    Required    = 1,
    /// Best-effort idempotency (may retry but not guaranteed).
    BestEffort  = 2,
}

impl IdempotencyRequirement {
    /// Returns the canonical byte discriminant.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    /// Parses from a u8 discriminant. Returns `None` for unknown values.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NotRequired),
            1 => Some(Self::Required),
            2 => Some(Self::BestEffort),
            _ => None,
        }
    }
}

impl std::fmt::Display for IdempotencyRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRequired => write!(f, "NOT_REQUIRED"),
            Self::Required => write!(f, "REQUIRED"),
            Self::BestEffort => write!(f, "BEST_EFFORT"),
        }
    }
}

/// Semantics annotation for an HSI route.
///
/// Per RFC-0020 section 3.1, every route MUST have a semantics annotation
/// describing whether it is authoritative vs advisory, its idempotency
/// requirement, and whether receipts are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HsiRouteSemantics {
    /// Whether this route is authoritative (true) or advisory (false).
    ///
    /// Authoritative routes can modify state or produce world effects.
    /// Advisory routes are read-only queries.
    pub authoritative: bool,

    /// Idempotency requirement for this route.
    pub idempotency: IdempotencyRequirement,

    /// Whether a signed receipt is required for this route.
    ///
    /// Per RFC-0020 section 1.3, authoritative routes MUST produce receipts.
    pub receipt_required: bool,
}

impl HsiRouteSemantics {
    /// Returns the canonical bytes for this semantics annotation.
    ///
    /// Format: `[authoritative:u8][idempotency:u8][receipt_required:u8]`
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        vec![
            u8::from(self.authoritative),
            self.idempotency.discriminant(),
            u8::from(self.receipt_required),
        ]
    }
}

/// CLI version metadata for the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CliVersion {
    /// Semantic version string (e.g., "0.9.0").
    pub semver: String,
    /// Build hash for reproducibility (e.g., `blake3:abcdef...`).
    pub build_hash: String,
}

impl CliVersion {
    /// Returns the canonical bytes for this version.
    ///
    /// Format: `[semver_len:u32_le][semver_bytes][build_hash_len:
    /// u32_le][build_hash_bytes]`
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_string(&mut buf, &self.semver);
        encode_string(&mut buf, &self.build_hash);
        buf
    }
}

/// A single route entry in the HSI contract manifest.
///
/// Per RFC-0020 section 3.1, each entry describes a single syscall/route
/// with its schema bindings and semantics annotation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HsiRouteEntry {
    /// Route identifier (e.g., `CTX_MALLOC`).
    pub id: String,
    /// Canonical route path (e.g., `hsi.context.malloc`).
    pub route: String,
    /// Stability classification.
    pub stability: StabilityClass,
    /// Request schema identifier.
    pub request_schema: String,
    /// Response schema identifier.
    pub response_schema: String,
    /// Semantics annotation (authoritative, idempotency, receipt).
    pub semantics: HsiRouteSemantics,
}

impl HsiRouteEntry {
    /// Returns the canonical bytes for this route entry.
    ///
    /// Format:
    /// ```text
    /// [id_len:u32_le][id_bytes]
    /// [route_len:u32_le][route_bytes]
    /// [stability:u8]
    /// [request_schema_len:u32_le][request_schema_bytes]
    /// [response_schema_len:u32_le][response_schema_bytes]
    /// [semantics_bytes (3 bytes)]
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_string(&mut buf, &self.id);
        encode_string(&mut buf, &self.route);
        buf.push(self.stability.discriminant());
        encode_string(&mut buf, &self.request_schema);
        encode_string(&mut buf, &self.response_schema);
        buf.extend_from_slice(&self.semantics.canonical_bytes());
        buf
    }
}

/// The HSI Contract Manifest V1 artifact.
///
/// Per RFC-0020 section 3.1, this is a canonical inventory of all syscalls
/// available through the daemon/CLI dispatch registry, with semantics
/// annotations, schema bindings, and a stable content hash.
///
/// # Determinism
///
/// The manifest is deterministic: identical code + build inputs produce
/// identical canonical bytes and content hash. Routes are sorted
/// lexicographically by `route` field before serialization.
///
/// # Content Hash
///
/// The content hash uses domain-separated BLAKE3:
/// `blake3("apm2:apm2.hsi_contract.v1:1.0.0\n" + canonical_bytes)`
///
/// Text form: `blake3:<64-hex>`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HsiContractManifestV1 {
    /// Schema identifier (always `apm2.hsi_contract.v1`).
    pub schema: String,
    /// Schema version (always "1.0.0").
    pub schema_version: String,
    /// CLI version metadata.
    pub cli_version: CliVersion,
    /// Route entries, sorted lexicographically by `route`.
    pub routes: Vec<HsiRouteEntry>,
}

impl HsiContractManifestV1 {
    /// Returns the canonical bytes for this manifest.
    ///
    /// The encoding is deterministic:
    /// 1. Schema and version are length-prefixed strings
    /// 2. CLI version is encoded via `CliVersion::canonical_bytes`
    /// 3. Route count is encoded as u32 LE
    /// 4. Routes are sorted by `route` field and encoded sequentially
    ///
    /// # Panics
    ///
    /// Panics if routes are not sorted (this is a programming error;
    /// `build_manifest` always sorts routes).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Assert sort invariant
        for i in 1..self.routes.len() {
            assert!(
                self.routes[i - 1].route <= self.routes[i].route,
                "routes must be sorted by route field; found '{}' before '{}'",
                self.routes[i - 1].route,
                self.routes[i].route,
            );
        }

        let mut buf = Vec::new();

        // Schema and version
        encode_string(&mut buf, &self.schema);
        encode_string(&mut buf, &self.schema_version);

        // CLI version
        let cli_bytes = self.cli_version.canonical_bytes();
        buf.extend_from_slice(&cli_bytes);

        // Route count + entries
        let count: u32 = self
            .routes
            .len()
            .try_into()
            .expect("route count exceeds u32");
        buf.extend_from_slice(&count.to_le_bytes());
        for entry in &self.routes {
            let entry_bytes = entry.canonical_bytes();
            buf.extend_from_slice(&entry_bytes);
        }

        buf
    }

    /// Computes the domain-separated content hash (BLAKE3).
    ///
    /// Per RFC-0020 section 1.5.2:
    /// `hash("apm2:apm2.hsi_contract.v1:1.0.0\n" + canonical_bytes)`
    ///
    /// Returns the hash in text form: `blake3:<64-hex>`
    #[must_use]
    pub fn content_hash(&self) -> String {
        let canonical = self.canonical_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_PREFIX.as_bytes());
        hasher.update(&canonical);
        let hash = hasher.finalize();
        format!("blake3:{}", hash.to_hex())
    }

    /// Returns the raw 32-byte BLAKE3 hash (domain-separated).
    #[must_use]
    pub fn content_hash_bytes(&self) -> [u8; 32] {
        let canonical = self.canonical_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_PREFIX.as_bytes());
        hasher.update(&canonical);
        *hasher.finalize().as_bytes()
    }

    /// Validates that the manifest is well-formed.
    ///
    /// Checks:
    /// - Route count within bounds
    /// - Routes are sorted
    /// - Route strings are within length bounds
    /// - All routes have non-empty semantics fields
    ///
    /// Returns a list of validation errors (empty = valid).
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.routes.len() > MAX_ROUTES {
            errors.push(format!(
                "route count {} exceeds maximum {MAX_ROUTES}",
                self.routes.len()
            ));
        }

        for (i, entry) in self.routes.iter().enumerate() {
            if entry.route.len() > MAX_ROUTE_LEN {
                errors.push(format!(
                    "route[{i}] '{}' exceeds max length {MAX_ROUTE_LEN}",
                    entry.route
                ));
            }
            if entry.request_schema.len() > MAX_SCHEMA_ID_LEN {
                errors.push(format!(
                    "route[{i}] request_schema exceeds max length {MAX_SCHEMA_ID_LEN}"
                ));
            }
            if entry.response_schema.len() > MAX_SCHEMA_ID_LEN {
                errors.push(format!(
                    "route[{i}] response_schema exceeds max length {MAX_SCHEMA_ID_LEN}"
                ));
            }
            if entry.route.is_empty() {
                errors.push(format!("route[{i}] has empty route string"));
            }
            if entry.id.is_empty() {
                errors.push(format!("route[{i}] has empty id string"));
            }
        }

        // Check sort order
        for i in 1..self.routes.len() {
            if self.routes[i - 1].route > self.routes[i].route {
                errors.push(format!(
                    "routes not sorted: '{}' appears before '{}'",
                    self.routes[i - 1].route,
                    self.routes[i].route,
                ));
            }
        }

        errors
    }
}

/// Encodes a string as length-prefixed UTF-8 bytes.
///
/// Format: `[len:u32_le][utf8_bytes]`
fn encode_string(buf: &mut Vec<u8>, s: &str) {
    let len: u32 = s.len().try_into().expect("string length exceeds u32");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stability_class_discriminant_roundtrip() {
        for class in [
            StabilityClass::Experimental,
            StabilityClass::Stable,
            StabilityClass::Deprecated,
        ] {
            let d = class.discriminant();
            assert_eq!(StabilityClass::from_u8(d), Some(class));
        }
    }

    #[test]
    fn stability_class_unknown_fails_closed() {
        assert_eq!(StabilityClass::from_u8(3), None);
        assert_eq!(StabilityClass::from_u8(255), None);
    }

    #[test]
    fn idempotency_discriminant_roundtrip() {
        for req in [
            IdempotencyRequirement::NotRequired,
            IdempotencyRequirement::Required,
            IdempotencyRequirement::BestEffort,
        ] {
            let d = req.discriminant();
            assert_eq!(IdempotencyRequirement::from_u8(d), Some(req));
        }
    }

    #[test]
    fn idempotency_unknown_fails_closed() {
        assert_eq!(IdempotencyRequirement::from_u8(3), None);
        assert_eq!(IdempotencyRequirement::from_u8(255), None);
    }

    #[test]
    fn semantics_canonical_bytes_determinism() {
        let sem = HsiRouteSemantics {
            authoritative: true,
            idempotency: IdempotencyRequirement::Required,
            receipt_required: true,
        };
        let b1 = sem.canonical_bytes();
        let b2 = sem.canonical_bytes();
        assert_eq!(b1, b2);
        assert_eq!(b1, vec![0x01, 0x01, 0x01]);
    }

    #[test]
    fn encode_string_determinism() {
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        encode_string(&mut buf1, "hello");
        encode_string(&mut buf2, "hello");
        assert_eq!(buf1, buf2);
        // 4 bytes length (5 as u32 LE) + 5 bytes "hello"
        assert_eq!(buf1.len(), 9);
        assert_eq!(&buf1[0..4], &5u32.to_le_bytes());
        assert_eq!(&buf1[4..9], b"hello");
    }

    #[test]
    fn manifest_canonical_bytes_determinism() {
        let m1 = make_test_manifest();
        let m2 = make_test_manifest();
        assert_eq!(m1.canonical_bytes(), m2.canonical_bytes());
    }

    #[test]
    fn manifest_content_hash_determinism() {
        let m1 = make_test_manifest();
        let m2 = make_test_manifest();
        assert_eq!(m1.content_hash(), m2.content_hash());
        assert!(m1.content_hash().starts_with("blake3:"));
        // Hash is 64 hex chars after "blake3:"
        assert_eq!(m1.content_hash().len(), 7 + 64);
    }

    #[test]
    fn manifest_content_hash_changes_on_semantic_change() {
        let m1 = make_test_manifest();
        let mut m2 = make_test_manifest();
        m2.routes[0].semantics.authoritative = !m2.routes[0].semantics.authoritative;
        assert_ne!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn manifest_validate_sorted() {
        let m = make_test_manifest();
        let errors = m.validate();
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    #[test]
    fn manifest_validate_unsorted() {
        let mut m = make_test_manifest();
        m.routes.reverse();
        let errors = m.validate();
        assert!(
            errors.iter().any(|e| e.contains("not sorted")),
            "expected sort error, got: {errors:?}"
        );
    }

    fn make_test_manifest() -> HsiContractManifestV1 {
        HsiContractManifestV1 {
            schema: SCHEMA_ID.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            cli_version: CliVersion {
                semver: "0.9.0".to_string(),
                build_hash:
                    "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
            },
            routes: vec![
                HsiRouteEntry {
                    id: "TOOL_REQUEST".to_string(),
                    route: "hsi.tool.request".to_string(),
                    stability: StabilityClass::Stable,
                    request_schema: "apm2.tool_request.v1".to_string(),
                    response_schema: "apm2.tool_response.v1".to_string(),
                    semantics: HsiRouteSemantics {
                        authoritative: true,
                        idempotency: IdempotencyRequirement::Required,
                        receipt_required: true,
                    },
                },
                HsiRouteEntry {
                    id: "WORK_CLAIM".to_string(),
                    route: "hsi.work.claim".to_string(),
                    stability: StabilityClass::Stable,
                    request_schema: "apm2.claim_work_request.v1".to_string(),
                    response_schema: "apm2.claim_work_response.v1".to_string(),
                    semantics: HsiRouteSemantics {
                        authoritative: true,
                        idempotency: IdempotencyRequirement::Required,
                        receipt_required: true,
                    },
                },
            ],
        }
    }
}
