//! FAC Job Spec V1: immutable job description with `job_spec_digest` and
//! `actuation` block (RFC-0028 binding).
//!
//! Implements TCK-00512: defines `FacJobSpecV1`, its canonical digest
//! computation, and worker-side validation (digest + `request_id` match).
//!
//! # Design
//!
//! A `FacJobSpecV1` is the immutable envelope describing a unit of work
//! (gates, warm, GC, reset) that flows through the FAC queue. It carries:
//!
//! - `job_spec_digest`: a BLAKE3 commitment over the canonical JSON form of the
//!   spec **with `actuation.channel_context_token` nulled** (so the digest is
//!   stable across token rotations).
//! - `actuation`: the RFC-0028 authorization block binding the spec to a
//!   broker-signed `ChannelContextToken`.
//!
//! # Digest Computation (normative, per RFC-0019 section 5.3.3)
//!
//! 1. Clone the spec.
//! 2. Set `actuation.channel_context_token = None`.
//! 3. Serialize to canonical JSON
//!    (`apm2_core::determinism::canonicalize_json`).
//! 4. Hash as `BLAKE3(schema_id || "\0" || canonical_json_bytes)`.
//! 5. Encode as `"b3-256:<hex>"`.
//!
//! # Worker Validation
//!
//! Workers MUST call [`validate_job_spec`] before executing any job:
//!
//! 1. Recompute the digest and compare to `job_spec_digest` (fail-closed).
//! 2. Verify `actuation.request_id == job_spec_digest` (fail-closed).
//!
//! # Security Invariants
//!
//! - [INV-JS-001] `job_spec_digest` covers ALL fields except the token itself.
//! - [INV-JS-002] Digest comparison is constant-time
//!   (`subtle::ConstantTimeEq`).
//! - [INV-JS-003] Fail-closed: any validation failure results in denial.
//! - [INV-JS-004] `#[serde(deny_unknown_fields)]` on all boundary structs.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::determinism::canonicalize_json;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema identifier for `FacJobSpecV1`.
pub const JOB_SPEC_SCHEMA_ID: &str = "apm2.fac.job_spec.v1";

/// Maximum length for `job_id`.
pub const MAX_JOB_ID_LENGTH: usize = 256;

/// Maximum length for `kind`.
pub const MAX_KIND_LENGTH: usize = 64;

/// Maximum length for `queue_lane`.
pub const MAX_QUEUE_LANE_LENGTH: usize = 64;

/// Maximum length for `lease_id` in the actuation block.
pub const MAX_LEASE_ID_LENGTH: usize = 256;

/// Maximum length for `request_id` in the actuation block.
pub const MAX_REQUEST_ID_LENGTH: usize = 256;

/// Maximum length for `channel_context_token` (base64-encoded).
/// Tokens are base64 of a signed JSON payload; 16 KiB is generous.
pub const MAX_CHANNEL_CONTEXT_TOKEN_LENGTH: usize = 16_384;

/// Maximum length for `decoded_source` hint.
pub const MAX_DECODED_SOURCE_LENGTH: usize = 64;

/// Maximum length for `repo_id` in the source block.
pub const MAX_REPO_ID_LENGTH: usize = 256;

/// Maximum length for `head_sha` in the source block.
pub const MAX_HEAD_SHA_LENGTH: usize = 128;

/// Maximum length for `source.kind`.
pub const MAX_SOURCE_KIND_LENGTH: usize = 64;

/// Maximum serialized size of a `FacJobSpecV1` (bytes).
/// Protects against memory-exhaustion attacks during bounded deserialization.
pub const MAX_JOB_SPEC_SIZE: usize = 65_536;

/// Digest prefix for BLAKE3-256 hashes.
const B3_256_PREFIX: &str = "b3-256:";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from `FacJobSpecV1` construction and validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JobSpecError {
    /// Schema identifier mismatch.
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier.
        actual: String,
    },

    /// A required string field is empty.
    #[error("{field} is empty")]
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },

    /// A string field exceeds its maximum length.
    #[error("{field} length {len} exceeds max {max}")]
    FieldTooLong {
        /// Name of the oversize field.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// The `job_spec_digest` does not match the recomputed digest.
    #[error("job_spec_digest mismatch: declared {declared}, computed {computed}")]
    DigestMismatch {
        /// Declared digest in the spec.
        declared: String,
        /// Recomputed digest.
        computed: String,
    },

    /// `actuation.request_id` does not match `job_spec_digest`.
    #[error("request_id mismatch: request_id={request_id}, job_spec_digest={job_spec_digest}")]
    RequestIdMismatch {
        /// Value of `actuation.request_id`.
        request_id: String,
        /// Value of `job_spec_digest`.
        job_spec_digest: String,
    },

    /// A digest field was not validly formatted as `b3-256:<hex>`.
    #[error("invalid digest for {field}: {value}")]
    InvalidDigest {
        /// Field that contained the invalid digest.
        field: &'static str,
        /// Invalid field value.
        value: String,
    },

    /// Priority value is out of the valid range (0..=100).
    #[error("priority {value} is out of range (0..=100)")]
    PriorityOutOfRange {
        /// Invalid priority value.
        value: u32,
    },

    /// Canonical JSON serialization failed.
    #[error("canonical JSON error: {detail}")]
    CanonicalJson {
        /// Detail about the failure.
        detail: String,
    },

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {detail}")]
    Json {
        /// Detail about the failure.
        detail: String,
    },

    /// Input exceeds maximum allowed size.
    #[error("input size {size} exceeds maximum {max}")]
    InputTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// The `channel_context_token` is missing in default mode.
    #[error("actuation.channel_context_token is required in default mode")]
    MissingChannelContextToken,
}

// ---------------------------------------------------------------------------
// Actuation block
// ---------------------------------------------------------------------------

/// RFC-0028 actuation block binding the job spec to a broker-signed token.
///
/// Workers MUST validate the `channel_context_token` before execution.
/// The `request_id` MUST equal `job_spec_digest` so the token is bound
/// to this specific spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actuation {
    /// Lease ID binding the token to a lane lease. REQUIRED.
    pub lease_id: String,

    /// Request ID binding the token to the job spec. MUST equal
    /// `job_spec_digest` (checked by [`validate_job_spec`]).
    pub request_id: String,

    /// RFC-0028 `ChannelContextToken` (base64-encoded, daemon-signed).
    /// REQUIRED in default mode. Set to `None` when computing
    /// `job_spec_digest`.
    pub channel_context_token: Option<String>,

    /// Optional hint for decoded source classification.
    /// Workers MUST NOT trust this without token verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_source: Option<String>,
}

// ---------------------------------------------------------------------------
// Source block
// ---------------------------------------------------------------------------

/// Source provenance for the job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSource {
    /// Source kind: `"mirror_commit"` or `"patch_injection"`.
    pub kind: String,

    /// Stable logical repository identifier.
    pub repo_id: String,

    /// HEAD commit SHA.
    pub head_sha: String,

    /// Optional patch object for `patch_injection` kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Lane requirements
// ---------------------------------------------------------------------------

/// Lane resource requirements for the job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneRequirements {
    /// Required lane profile hash. `None` if no specific lane is required.
    pub lane_profile_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

/// Execution constraints for the job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobConstraints {
    /// Whether nextest is required.
    #[serde(default)]
    pub require_nextest: bool,

    /// Test execution timeout in seconds.
    #[serde(default)]
    pub test_timeout_seconds: Option<u64>,

    /// Memory ceiling in bytes.
    #[serde(default)]
    pub memory_max_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// FacJobSpecV1
// ---------------------------------------------------------------------------

/// FAC Job Spec V1: the immutable description of a unit of work.
///
/// This struct is serialized to JSON and stored on disk as a queue item.
/// The `job_spec_digest` field binds the spec to a specific content hash
/// and the `actuation` block binds it to an RFC-0028 authorization token.
///
/// # Schema: `apm2.fac.job_spec.v1`
///
/// See RFC-0019 section 5.3.3 for the full schema definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobSpecV1 {
    /// Schema identifier. MUST be `"apm2.fac.job_spec.v1"`.
    pub schema: String,

    /// Unique job identifier.
    pub job_id: String,

    /// Content-addressable digest of the canonical spec form.
    /// Computed with `actuation.channel_context_token = null`.
    pub job_spec_digest: String,

    /// Job kind: `"gates"`, `"warm"`, `"gc"`, `"reset"`, etc.
    pub kind: String,

    /// RFC-0029 queue lane for admission/scheduling.
    pub queue_lane: String,

    /// Priority within the queue lane (0 = highest, 100 = lowest).
    pub priority: u32,

    /// ISO 8601 enqueue timestamp.
    pub enqueue_time: String,

    /// RFC-0028 actuation authorization block.
    pub actuation: Actuation,

    /// Source provenance.
    pub source: JobSource,

    /// Lane resource requirements.
    pub lane_requirements: LaneRequirements,

    /// Execution constraints.
    pub constraints: JobConstraints,
}

impl FacJobSpecV1 {
    /// Computes the `job_spec_digest` for this spec.
    ///
    /// The computation follows RFC-0019 section 5.3.3:
    /// 1. Clone the spec and set `actuation.channel_context_token = None`.
    /// 2. Set `actuation.request_id = ""` to avoid self-reference.
    /// 3. Serialize to JSON.
    /// 4. Canonicalize JSON (sorted keys, no whitespace).
    /// 5. Hash as `BLAKE3(schema_id || "\0" || canonical_json_bytes)`.
    /// 6. Return as `"b3-256:<hex>"`.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or canonicalization fails.
    pub fn compute_digest(&self) -> Result<String, JobSpecError> {
        let mut spec_for_digest = self.clone();
        spec_for_digest.actuation.channel_context_token = None;
        spec_for_digest.actuation.request_id = String::new();
        // Clear mutable identity fields before hashing to avoid circular input.
        spec_for_digest.job_spec_digest = String::new();

        let json = serde_json::to_string(&spec_for_digest).map_err(|e| JobSpecError::Json {
            detail: e.to_string(),
        })?;

        let canonical = canonicalize_json(&json).map_err(|e| JobSpecError::CanonicalJson {
            detail: e.to_string(),
        })?;

        let digest_bytes = compute_digest_bytes(JOB_SPEC_SCHEMA_ID, canonical.as_bytes());
        Ok(format_b3_256_digest(&digest_bytes))
    }

    /// Validates the structural integrity of the spec fields.
    ///
    /// Checks lengths, non-empty required fields, schema match, and
    /// priority range. Does NOT check digest or `request_id` binding
    /// (use [`validate_job_spec`] for full validation).
    ///
    /// # Errors
    ///
    /// Returns the first validation error found.
    pub fn validate_structure(&self) -> Result<(), JobSpecError> {
        // Schema check
        if self.schema != JOB_SPEC_SCHEMA_ID {
            return Err(JobSpecError::SchemaMismatch {
                expected: JOB_SPEC_SCHEMA_ID.to_string(),
                actual: self.schema.clone(),
            });
        }

        // Required non-empty fields
        check_non_empty("job_id", &self.job_id)?;
        check_non_empty("job_spec_digest", &self.job_spec_digest)?;
        check_non_empty("kind", &self.kind)?;
        check_non_empty("queue_lane", &self.queue_lane)?;
        check_non_empty("enqueue_time", &self.enqueue_time)?;
        check_non_empty("actuation.lease_id", &self.actuation.lease_id)?;
        check_non_empty("actuation.request_id", &self.actuation.request_id)?;
        check_non_empty("source.kind", &self.source.kind)?;
        check_non_empty("source.repo_id", &self.source.repo_id)?;
        check_non_empty("source.head_sha", &self.source.head_sha)?;

        // Length bounds
        check_length("job_id", &self.job_id, MAX_JOB_ID_LENGTH)?;
        check_length("kind", &self.kind, MAX_KIND_LENGTH)?;
        check_length("queue_lane", &self.queue_lane, MAX_QUEUE_LANE_LENGTH)?;
        check_length(
            "actuation.lease_id",
            &self.actuation.lease_id,
            MAX_LEASE_ID_LENGTH,
        )?;
        check_length(
            "actuation.request_id",
            &self.actuation.request_id,
            MAX_REQUEST_ID_LENGTH,
        )?;
        if let Some(ref token) = self.actuation.channel_context_token {
            check_length(
                "actuation.channel_context_token",
                token,
                MAX_CHANNEL_CONTEXT_TOKEN_LENGTH,
            )?;
        }
        if let Some(ref ds) = self.actuation.decoded_source {
            check_length("actuation.decoded_source", ds, MAX_DECODED_SOURCE_LENGTH)?;
        }
        check_length("source.kind", &self.source.kind, MAX_SOURCE_KIND_LENGTH)?;
        check_length("source.repo_id", &self.source.repo_id, MAX_REPO_ID_LENGTH)?;
        check_length(
            "source.head_sha",
            &self.source.head_sha,
            MAX_HEAD_SHA_LENGTH,
        )?;

        // Priority range
        if self.priority > 100 {
            return Err(JobSpecError::PriorityOutOfRange {
                value: self.priority,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Full validation (worker-side)
// ---------------------------------------------------------------------------

/// Validates a `FacJobSpecV1` for worker execution.
///
/// Performs structural validation, recomputes the digest, and verifies:
/// 1. `job_spec_digest` matches the recomputed digest (constant-time).
/// 2. `actuation.request_id == job_spec_digest` (constant-time).
///
/// # Errors
///
/// Returns the first validation failure. Workers MUST deny/quarantine the
/// job on any error (fail-closed).
pub fn validate_job_spec(spec: &FacJobSpecV1) -> Result<(), JobSpecError> {
    spec.validate_structure()?;

    if parse_b3_256_digest(&spec.job_spec_digest).is_none() {
        return Err(JobSpecError::InvalidDigest {
            field: "job_spec_digest",
            value: spec.job_spec_digest.clone(),
        });
    }
    if parse_b3_256_digest(&spec.actuation.request_id).is_none() {
        return Err(JobSpecError::InvalidDigest {
            field: "actuation.request_id",
            value: spec.actuation.request_id.clone(),
        });
    }

    // Recompute digest
    let computed_digest = spec.compute_digest()?;

    // Constant-time comparison of declared vs computed digest (INV-JS-002)
    if !constant_time_str_eq(&spec.job_spec_digest, &computed_digest) {
        return Err(JobSpecError::DigestMismatch {
            declared: spec.job_spec_digest.clone(),
            computed: computed_digest,
        });
    }

    // Verify request_id == job_spec_digest (constant-time)
    if !constant_time_str_eq(&spec.actuation.request_id, &spec.job_spec_digest) {
        return Err(JobSpecError::RequestIdMismatch {
            request_id: spec.actuation.request_id.clone(),
            job_spec_digest: spec.job_spec_digest.clone(),
        });
    }

    Ok(())
}

/// Deserializes a `FacJobSpecV1` from JSON bytes with bounded size check.
///
/// Enforces [`MAX_JOB_SPEC_SIZE`] before JSON parsing to prevent
/// memory exhaustion from crafted inputs (RSK-1601).
///
/// # Errors
///
/// Returns an error if the input exceeds the size limit or deserialization
/// fails.
pub fn deserialize_job_spec(bytes: &[u8]) -> Result<FacJobSpecV1, JobSpecError> {
    if bytes.len() > MAX_JOB_SPEC_SIZE {
        return Err(JobSpecError::InputTooLarge {
            size: bytes.len(),
            max: MAX_JOB_SPEC_SIZE,
        });
    }
    serde_json::from_slice(bytes).map_err(|e| JobSpecError::Json {
        detail: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for `FacJobSpecV1` that computes the digest and sets
/// `actuation.request_id` correctly.
pub struct FacJobSpecV1Builder {
    job_id: String,
    kind: String,
    queue_lane: String,
    priority: u32,
    enqueue_time: String,
    lease_id: String,
    channel_context_token: Option<String>,
    decoded_source: Option<String>,
    source: JobSource,
    lane_requirements: LaneRequirements,
    constraints: JobConstraints,
}

impl FacJobSpecV1Builder {
    /// Creates a new builder with required fields.
    #[must_use]
    pub fn new(
        job_id: impl Into<String>,
        kind: impl Into<String>,
        queue_lane: impl Into<String>,
        enqueue_time: impl Into<String>,
        lease_id: impl Into<String>,
        source: JobSource,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            kind: kind.into(),
            queue_lane: queue_lane.into(),
            priority: 50,
            enqueue_time: enqueue_time.into(),
            lease_id: lease_id.into(),
            channel_context_token: None,
            decoded_source: None,
            source,
            lane_requirements: LaneRequirements {
                lane_profile_hash: None,
            },
            constraints: JobConstraints {
                require_nextest: true,
                test_timeout_seconds: None,
                memory_max_bytes: None,
            },
        }
    }

    /// Sets the priority (0 = highest, 100 = lowest).
    #[must_use]
    pub const fn priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the RFC-0028 channel context token (base64).
    #[must_use]
    pub fn channel_context_token(mut self, token: impl Into<String>) -> Self {
        self.channel_context_token = Some(token.into());
        self
    }

    /// Sets the decoded source hint.
    #[must_use]
    pub fn decoded_source(mut self, source: impl Into<String>) -> Self {
        self.decoded_source = Some(source.into());
        self
    }

    /// Sets the lane profile hash requirement.
    #[must_use]
    pub fn lane_profile_hash(mut self, hash: impl Into<String>) -> Self {
        self.lane_requirements.lane_profile_hash = Some(hash.into());
        self
    }

    /// Sets the nextest requirement.
    #[must_use]
    pub const fn require_nextest(mut self, require: bool) -> Self {
        self.constraints.require_nextest = require;
        self
    }

    /// Sets the test timeout in seconds.
    #[must_use]
    pub const fn test_timeout_seconds(mut self, seconds: u64) -> Self {
        self.constraints.test_timeout_seconds = Some(seconds);
        self
    }

    /// Sets the memory ceiling in bytes.
    #[must_use]
    pub const fn memory_max_bytes(mut self, bytes: u64) -> Self {
        self.constraints.memory_max_bytes = Some(bytes);
        self
    }

    /// Builds the `FacJobSpecV1`, computing the digest and setting
    /// `actuation.request_id = job_spec_digest`.
    ///
    /// # Errors
    ///
    /// Returns an error if structural validation or digest computation fails.
    pub fn build(self) -> Result<FacJobSpecV1, JobSpecError> {
        let mut spec = FacJobSpecV1 {
            schema: JOB_SPEC_SCHEMA_ID.to_string(),
            job_id: self.job_id,
            job_spec_digest: String::new(), // placeholder; computed below
            kind: self.kind,
            queue_lane: self.queue_lane,
            priority: self.priority,
            enqueue_time: self.enqueue_time,
            actuation: Actuation {
                lease_id: self.lease_id,
                request_id: String::new(), // placeholder; set to digest below
                channel_context_token: self.channel_context_token,
                decoded_source: self.decoded_source,
            },
            source: self.source,
            lane_requirements: self.lane_requirements,
            constraints: self.constraints,
        };

        // Compute digest (with token nulled and digest/request_id empty)
        let digest = spec.compute_digest()?;

        // Set digest and request_id
        spec.job_spec_digest.clone_from(&digest);
        spec.actuation.request_id = digest;

        // Validate structure
        spec.validate_structure()?;

        Ok(spec)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Computes the raw BLAKE3 digest bytes with domain separation.
///
/// `BLAKE3(schema_id || "\0" || data)`
fn compute_digest_bytes(schema_id: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(schema_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Formats a 32-byte hash as `"b3-256:<hex>"`.
fn format_b3_256_digest(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(B3_256_PREFIX.len() + 64);
    s.push_str(B3_256_PREFIX);
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Parses a `"b3-256:<hex>"` string into raw 32 bytes.
///
/// Returns `None` if the prefix is wrong or the hex is malformed.
pub(crate) fn parse_b3_256_digest(s: &str) -> Option<[u8; 32]> {
    let hex_str = s.strip_prefix(B3_256_PREFIX)?;
    if hex_str.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let hi = hex_char_to_nibble(hex_str.as_bytes().get(i * 2).copied()?)?;
        let lo = hex_char_to_nibble(hex_str.as_bytes().get(i * 2 + 1).copied()?)?;
        *byte = (hi << 4) | lo;
    }
    Some(bytes)
}

pub(crate) const fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Constant-time string comparison using `subtle::ConstantTimeEq`.
///
/// Compares the raw bytes of both strings. Returns `false` if lengths differ
/// (this leaks length, which is acceptable for digest strings of known format).
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

const fn check_non_empty(field: &'static str, value: &str) -> Result<(), JobSpecError> {
    if value.is_empty() {
        return Err(JobSpecError::EmptyField { field });
    }
    Ok(())
}

const fn check_length(field: &'static str, value: &str, max: usize) -> Result<(), JobSpecError> {
    if value.len() > max {
        return Err(JobSpecError::FieldTooLong {
            field,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source() -> JobSource {
        JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: "guardian-intelligence/apm2".to_string(),
            head_sha: "a".repeat(40),
            patch: None,
        }
    }

    fn build_valid_spec() -> FacJobSpecV1 {
        FacJobSpecV1Builder::new(
            "job_20260212T031500Z_001",
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .priority(50)
        .require_nextest(true)
        .test_timeout_seconds(240)
        .memory_max_bytes(25_769_803_776)
        .build()
        .expect("valid spec should build")
    }

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    #[test]
    fn builder_produces_valid_spec() {
        let spec = build_valid_spec();
        assert_eq!(spec.schema, JOB_SPEC_SCHEMA_ID);
        assert!(!spec.job_spec_digest.is_empty());
        assert!(spec.job_spec_digest.starts_with(B3_256_PREFIX));
        assert_eq!(spec.actuation.request_id, spec.job_spec_digest);
        assert_eq!(spec.priority, 50);
    }

    #[test]
    fn builder_with_token_produces_valid_spec() {
        let spec = FacJobSpecV1Builder::new(
            "job_001",
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .channel_context_token("BASE64_TOKEN_DATA")
        .build()
        .expect("should build with token");

        // Token does not affect digest
        assert!(validate_job_spec(&spec).is_ok());
    }

    // -------------------------------------------------------------------
    // Digest computation
    // -------------------------------------------------------------------

    #[test]
    fn digest_is_deterministic() {
        let spec1 = build_valid_spec();
        let spec2 = build_valid_spec();
        assert_eq!(spec1.job_spec_digest, spec2.job_spec_digest);
    }

    #[test]
    fn digest_changes_when_field_changes() {
        let spec1 = build_valid_spec();
        let spec2 = FacJobSpecV1Builder::new(
            "job_20260212T031500Z_001",
            "warm", // different kind
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .priority(50)
        .build()
        .expect("should build");

        assert_ne!(spec1.job_spec_digest, spec2.job_spec_digest);
    }

    #[test]
    fn digest_stable_across_token_rotations() {
        let spec_no_token = FacJobSpecV1Builder::new(
            "job_001",
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .build()
        .expect("should build");

        let spec_with_token = FacJobSpecV1Builder::new(
            "job_001",
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .channel_context_token("DIFFERENT_TOKEN")
        .build()
        .expect("should build");

        assert_eq!(
            spec_no_token.job_spec_digest,
            spec_with_token.job_spec_digest
        );
    }

    // -------------------------------------------------------------------
    // Validation: digest mismatch (tampered spec)
    // -------------------------------------------------------------------

    #[test]
    fn tampered_spec_detected_by_digest_mismatch() {
        let mut spec = build_valid_spec();
        // Tamper with the kind field after digest was computed
        spec.kind = "warm".to_string();

        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "tampered spec must be detected: {result:?}"
        );
    }

    #[test]
    fn tampered_priority_detected() {
        let mut spec = build_valid_spec();
        spec.priority = 10; // change priority post-build
        let result = validate_job_spec(&spec);
        assert!(matches!(result, Err(JobSpecError::DigestMismatch { .. })));
    }

    #[test]
    fn tampered_source_detected() {
        let mut spec = build_valid_spec();
        spec.source.head_sha = "b".repeat(40);
        let result = validate_job_spec(&spec);
        assert!(matches!(result, Err(JobSpecError::DigestMismatch { .. })));
    }

    #[test]
    fn tampered_lease_id_detected() {
        let mut spec = build_valid_spec();
        spec.actuation.lease_id = "ATTACKER-LEASE".to_string();
        let result = validate_job_spec(&spec);
        assert!(matches!(result, Err(JobSpecError::DigestMismatch { .. })));
    }

    // -------------------------------------------------------------------
    // Validation: request_id mismatch
    // -------------------------------------------------------------------

    #[test]
    fn request_id_mismatch_detected() {
        let mut spec = build_valid_spec();
        spec.actuation.request_id =
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        // Digest is still correct (we didn't tamper the content that feeds
        // into the digest), but request_id != digest.
        // Actually the request_id IS part of the digest computation when it
        // is emptied. But validate_job_spec recomputes the digest with
        // request_id = "". Since we set request_id to something else in the
        // live spec, the recomputed digest won't change (it always empties
        // request_id during computation). The check is:
        //   1. recompute => matches job_spec_digest (because we didn't tamper
        //      job_spec_digest or the fields that feed into it)
        //   2. request_id != job_spec_digest => RequestIdMismatch
        //
        // But wait - we changed request_id. The digest computation empties
        // both job_spec_digest and request_id. So the recomputed digest will
        // be the same as the original job_spec_digest. Then the check is:
        //   request_id ("b3-256:000...") != job_spec_digest => mismatch.
        let result = validate_job_spec(&spec);
        assert!(
            matches!(result, Err(JobSpecError::RequestIdMismatch { .. })),
            "request_id mismatch must be detected: {result:?}"
        );
    }

    // -------------------------------------------------------------------
    // Validation: structural checks
    // -------------------------------------------------------------------

    #[test]
    fn rejects_wrong_schema() {
        let mut spec = build_valid_spec();
        spec.schema = "wrong.schema".to_string();
        let result = validate_job_spec(&spec);
        assert!(matches!(result, Err(JobSpecError::SchemaMismatch { .. })));
    }

    #[test]
    fn rejects_empty_job_id() {
        let result = FacJobSpecV1Builder::new(
            "",
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .build();
        assert!(matches!(
            result,
            Err(JobSpecError::EmptyField { field: "job_id" })
        ));
    }

    #[test]
    fn rejects_empty_lease_id() {
        let result = FacJobSpecV1Builder::new(
            "job_001",
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "",
            sample_source(),
        )
        .build();
        assert!(matches!(
            result,
            Err(JobSpecError::EmptyField {
                field: "actuation.lease_id"
            })
        ));
    }

    #[test]
    fn rejects_oversized_job_id() {
        let result = FacJobSpecV1Builder::new(
            "x".repeat(MAX_JOB_ID_LENGTH + 1),
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .build();
        assert!(matches!(
            result,
            Err(JobSpecError::FieldTooLong {
                field: "job_id",
                ..
            })
        ));
    }

    #[test]
    fn rejects_priority_out_of_range() {
        let result = FacJobSpecV1Builder::new(
            "job_001",
            "gates",
            "bulk",
            "2026-02-12T03:15:00Z",
            "L-FAC-LOCAL",
            sample_source(),
        )
        .priority(101)
        .build();
        assert!(matches!(
            result,
            Err(JobSpecError::PriorityOutOfRange { value: 101 })
        ));
    }

    // -------------------------------------------------------------------
    // Bounded deserialization
    // -------------------------------------------------------------------

    #[test]
    fn deserialize_rejects_oversized_input() {
        let oversized = vec![b' '; MAX_JOB_SPEC_SIZE + 1];
        let result = deserialize_job_spec(&oversized);
        assert!(matches!(result, Err(JobSpecError::InputTooLarge { .. })));
    }

    #[test]
    fn deserialize_roundtrip() {
        let spec = build_valid_spec();
        let bytes = serde_json::to_vec(&spec).expect("serialize");
        let deserialized = deserialize_job_spec(&bytes).expect("deserialize");
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn deserialize_rejects_unknown_fields() {
        let spec = build_valid_spec();
        let mut json: serde_json::Value = serde_json::to_value(&spec).expect("to_value");
        json.as_object_mut()
            .unwrap()
            .insert("evil_field".to_string(), serde_json::Value::Bool(true));
        let bytes = serde_json::to_vec(&json).expect("serialize");
        let result = deserialize_job_spec(&bytes);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    // -------------------------------------------------------------------
    // Serde roundtrip preserves digest
    // -------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_preserves_validation() {
        let spec = build_valid_spec();
        let json = serde_json::to_string_pretty(&spec).expect("serialize");
        let deserialized: FacJobSpecV1 = serde_json::from_str(&json).expect("deserialize");
        assert!(validate_job_spec(&deserialized).is_ok());
    }

    // -------------------------------------------------------------------
    // Digest format
    // -------------------------------------------------------------------

    #[test]
    fn digest_has_correct_prefix_and_length() {
        let spec = build_valid_spec();
        assert!(spec.job_spec_digest.starts_with("b3-256:"));
        // b3-256: (7 chars) + 64 hex chars = 71
        assert_eq!(spec.job_spec_digest.len(), 71);
    }

    // -------------------------------------------------------------------
    // parse_b3_256_digest
    // -------------------------------------------------------------------

    #[test]
    fn parse_digest_roundtrip() {
        let hash = [0x42u8; 32];
        let formatted = format_b3_256_digest(&hash);
        let parsed = parse_b3_256_digest(&formatted).expect("should parse");
        assert_eq!(parsed, hash);
    }

    #[test]
    fn parse_digest_rejects_wrong_prefix() {
        assert!(parse_b3_256_digest("sha256:aabb").is_none());
    }

    #[test]
    fn parse_digest_rejects_short_hex() {
        assert!(parse_b3_256_digest("b3-256:aabb").is_none());
    }

    #[test]
    fn parse_digest_rejects_invalid_hex() {
        let bad = format!("b3-256:{}", "zz".repeat(32));
        assert!(parse_b3_256_digest(&bad).is_none());
    }

    // -------------------------------------------------------------------
    // Constant-time comparison
    // -------------------------------------------------------------------

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_str_eq("hello", "hello"));
        assert!(!constant_time_str_eq("hello", "world"));
        assert!(!constant_time_str_eq("hello", "hell"));
        assert!(!constant_time_str_eq("", "a"));
        assert!(constant_time_str_eq("", ""));
    }

    // -------------------------------------------------------------------
    // E2E: build, serialize, deserialize, validate
    // -------------------------------------------------------------------

    #[test]
    fn end_to_end_build_serialize_deserialize_validate() {
        // Build
        let spec = FacJobSpecV1Builder::new(
            "job_e2e_001",
            "gates",
            "bulk",
            "2026-02-12T04:00:00Z",
            "L-FAC-LOCAL-E2E",
            JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: "guardian-intelligence/apm2".to_string(),
                head_sha: "c".repeat(40),
                patch: None,
            },
        )
        .priority(25)
        .channel_context_token("BASE64_E2E_TOKEN")
        .decoded_source("typed_tool_intent")
        .require_nextest(true)
        .test_timeout_seconds(300)
        .memory_max_bytes(8_000_000_000)
        .build()
        .expect("e2e spec should build");

        // Validate fresh build
        assert!(validate_job_spec(&spec).is_ok());

        // Serialize to JSON
        let bytes = serde_json::to_vec_pretty(&spec).expect("serialize");
        assert!(bytes.len() <= MAX_JOB_SPEC_SIZE);

        // Deserialize
        let restored = deserialize_job_spec(&bytes).expect("deserialize");
        assert_eq!(spec, restored);

        // Validate deserialized
        assert!(validate_job_spec(&restored).is_ok());

        // Tamper and verify detection
        let mut tampered = restored;
        tampered.source.repo_id = "evil-org/apm2".to_string();
        let result = validate_job_spec(&tampered);
        assert!(
            matches!(result, Err(JobSpecError::DigestMismatch { .. })),
            "tampered repo_id must be detected"
        );
    }
}
