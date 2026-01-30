//! Gate receipt types for the Forge Admission Cycle.
//!
//! This module defines [`GateReceipt`] which represents a cryptographically
//! signed envelope containing the result of a gate execution. Receipts are
//! versioned for forward compatibility.
//!
//! # Versioning
//!
//! Gate receipts support versioning to enable forward compatibility:
//!
//! - **Receipt Version**: The envelope version (currently v1)
//! - **Payload Kind**: Type of payload ("aat", "quality", "security")
//! - **Payload Schema Version**: Schema version within each payload kind
//!
//! # Enforce Mode
//!
//! Version validation can run in "enforce mode" which rejects unknown versions.
//! This ensures strict validation in production while allowing relaxed
//! validation during development or migration periods.
//!
//! # Security Model
//!
//! Gate receipts are signed using domain-separated Ed25519 signatures with
//! the `GATE_RECEIPT:` prefix. This prevents cross-protocol signature replay.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{GateReceipt, GateReceiptBuilder, PayloadKind};
//!
//! let signer = Signer::generate();
//! let receipt =
//!     GateReceiptBuilder::new("receipt-001", "gate-build", "lease-001")
//!         .changeset_digest([0x42; 32])
//!         .executor_actor_id("executor-001")
//!         .receipt_version(1)
//!         .payload_kind(PayloadKind::Aat)
//!         .payload_schema_version(1)
//!         .payload_hash([0xab; 32])
//!         .evidence_bundle_hash([0xcd; 32])
//!         .build_and_sign(&signer);
//!
//! // Validate the receipt
//! assert!(receipt.validate_signature(&signer.verifying_key()).is_ok());
//! assert!(receipt.validate_version(true).is_ok());
//! ```

use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{GATE_RECEIPT_PREFIX, sign_with_domain, verify_with_domain};
use crate::crypto::{Signature, VerifyingKey};

// =============================================================================
// Supported Versions
// =============================================================================

/// Supported receipt envelope versions.
///
/// Version 1 is the initial version implementing the FAC receipt format.
pub const SUPPORTED_RECEIPT_VERSIONS: &[u32] = &[1];

/// Supported payload kinds.
///
/// - `aat`: Autonomous Agent Team execution receipts
/// - `quality`: Quality gate execution receipts
/// - `security`: Security gate execution receipts
pub const SUPPORTED_PAYLOAD_KINDS: &[&str] = &["aat", "quality", "security"];

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during gate receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptError {
    /// The receipt signature is invalid.
    #[error("invalid receipt signature: {0}")]
    InvalidSignature(String),

    /// The receipt version is not supported.
    #[error("unsupported receipt version: {version} (supported: {supported:?})")]
    UnsupportedVersion {
        /// The unsupported version that was encountered.
        version: u32,
        /// The list of supported versions.
        supported: Vec<u32>,
    },

    /// The payload kind is not supported.
    #[error("unsupported payload kind: {kind} (supported: {supported:?})")]
    UnsupportedPayloadKind {
        /// The unsupported payload kind that was encountered.
        kind: String,
        /// The list of supported payload kinds.
        supported: Vec<String>,
    },

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid receipt data.
    #[error("invalid receipt data: {0}")]
    InvalidData(String),
}

// =============================================================================
// Payload Kind
// =============================================================================

/// The kind of payload contained in the receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PayloadKind {
    /// Autonomous Agent Team execution receipt.
    Aat,
    /// Quality gate execution receipt.
    Quality,
    /// Security gate execution receipt.
    Security,
}

impl PayloadKind {
    /// Returns the string representation for proto encoding.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aat => "aat",
            Self::Quality => "quality",
            Self::Security => "security",
        }
    }

    /// Parses a payload kind from its string representation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "aat" => Some(Self::Aat),
            "quality" => Some(Self::Quality),
            "security" => Some(Self::Security),
            _ => None,
        }
    }

    /// Returns `true` if this payload kind is supported.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        SUPPORTED_PAYLOAD_KINDS.contains(&self.as_str())
    }
}

impl std::fmt::Display for PayloadKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Gate Receipt
// =============================================================================

/// A gate receipt envelope with versioning for forward compatibility.
///
/// The gate receipt is a cryptographically signed envelope containing:
/// - Identity fields (`receipt_id`, `gate_id`, `lease_id`)
/// - Binding fields (`changeset_digest`, `executor_actor_id`)
/// - Version fields (`receipt_version`, `payload_kind`,
///   `payload_schema_version`)
/// - Content fields (`payload_hash`, `evidence_bundle_hash`)
/// - Signature (`receipt_signature`)
///
/// # Fields (11 total)
///
/// 1. `receipt_id`: Unique identifier for this receipt
/// 2. `gate_id`: Gate this receipt is for
/// 3. `lease_id`: Lease authorizing this gate execution
/// 4. `changeset_digest`: Hash binding the receipt to specific changeset
/// 5. `executor_actor_id`: Actor who executed the gate
/// 6. `receipt_version`: Receipt envelope version for forward compatibility
/// 7. `payload_kind`: Type of payload ("aat", "quality", "security")
/// 8. `payload_schema_version`: Schema version of the payload
/// 9. `payload_hash`: Hash of the payload content
/// 10. `evidence_bundle_hash`: Hash of the evidence bundle
/// 11. `receipt_signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// Gate this receipt is for.
    pub gate_id: String,

    /// Lease authorizing this gate execution.
    pub lease_id: String,

    /// Hash binding the receipt to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Actor who executed the gate.
    pub executor_actor_id: String,

    /// Receipt envelope version for forward compatibility.
    pub receipt_version: u32,

    /// Type of payload contained in this receipt.
    pub payload_kind: PayloadKind,

    /// Schema version of the payload.
    pub payload_schema_version: u32,

    /// Hash of the payload content.
    #[serde(with = "serde_bytes")]
    pub payload_hash: [u8; 32],

    /// Hash of the evidence bundle.
    #[serde(with = "serde_bytes")]
    pub evidence_bundle_hash: [u8; 32],

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub receipt_signature: [u8; 64],
}

impl GateReceipt {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature,
    /// encoded in a deterministic order. This ensures that the same logical
    /// receipt always produces the same canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Pre-calculate capacity for efficiency
        let capacity = 64 // receipt_id estimate
            + 32 // gate_id estimate
            + 32 // lease_id estimate
            + 32 // changeset_digest
            + 32 // executor_actor_id estimate
            + 4  // receipt_version
            + 16 // payload_kind estimate
            + 4  // payload_schema_version
            + 32 // payload_hash
            + 32; // evidence_bundle_hash

        let mut bytes = Vec::with_capacity(capacity);

        // Field order is deterministic and matches proto field order
        // 1. receipt_id
        bytes.extend_from_slice(self.receipt_id.as_bytes());
        bytes.push(0); // null separator

        // 2. gate_id
        bytes.extend_from_slice(self.gate_id.as_bytes());
        bytes.push(0);

        // 3. lease_id
        bytes.extend_from_slice(self.lease_id.as_bytes());
        bytes.push(0);

        // 4. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 5. executor_actor_id
        bytes.extend_from_slice(self.executor_actor_id.as_bytes());
        bytes.push(0);

        // 6. receipt_version (big-endian for consistent ordering)
        bytes.extend_from_slice(&self.receipt_version.to_be_bytes());

        // 7. payload_kind
        bytes.extend_from_slice(self.payload_kind.as_str().as_bytes());
        bytes.push(0);

        // 8. payload_schema_version
        bytes.extend_from_slice(&self.payload_schema_version.to_be_bytes());

        // 9. payload_hash
        bytes.extend_from_slice(&self.payload_hash);

        // 10. evidence_bundle_hash
        bytes.extend_from_slice(&self.evidence_bundle_hash);

        bytes
    }

    /// Validates the receipt signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected executor
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(ReceiptError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::InvalidSignature`] if the signature verification
    /// fails.
    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<(), ReceiptError> {
        let signature = Signature::from_bytes(&self.receipt_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(verifying_key, GATE_RECEIPT_PREFIX, &canonical, &signature)
            .map_err(|e| ReceiptError::InvalidSignature(e.to_string()))
    }

    /// Validates the receipt version and payload kind.
    ///
    /// In enforce mode, unknown versions and payload kinds are rejected.
    /// In non-enforce mode, validation always succeeds (useful for migration).
    ///
    /// # Arguments
    ///
    /// * `enforce` - If `true`, reject unknown versions; if `false`, accept all
    ///
    /// # Returns
    ///
    /// `Ok(())` if the version is valid (or enforce is `false`),
    /// `Err(ReceiptError::UnsupportedVersion)` or
    /// `Err(ReceiptError::UnsupportedPayloadKind)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::UnsupportedVersion`] if the receipt version is
    /// not in [`SUPPORTED_RECEIPT_VERSIONS`] and enforce is `true`.
    ///
    /// Returns [`ReceiptError::UnsupportedPayloadKind`] if the payload kind is
    /// not in [`SUPPORTED_PAYLOAD_KINDS`] and enforce is `true`.
    pub fn validate_version(&self, enforce: bool) -> Result<(), ReceiptError> {
        if !enforce {
            return Ok(());
        }

        // Validate receipt version
        if !SUPPORTED_RECEIPT_VERSIONS.contains(&self.receipt_version) {
            return Err(ReceiptError::UnsupportedVersion {
                version: self.receipt_version,
                supported: SUPPORTED_RECEIPT_VERSIONS.to_vec(),
            });
        }

        // Validate payload kind
        if !self.payload_kind.is_supported() {
            return Err(ReceiptError::UnsupportedPayloadKind {
                kind: self.payload_kind.as_str().to_string(),
                supported: SUPPORTED_PAYLOAD_KINDS
                    .iter()
                    .map(|&s| s.to_string())
                    .collect(),
            });
        }

        Ok(())
    }

    /// Returns `true` if the receipt version is supported.
    #[must_use]
    pub fn is_version_supported(&self) -> bool {
        SUPPORTED_RECEIPT_VERSIONS.contains(&self.receipt_version)
    }

    /// Returns `true` if the payload kind is supported.
    #[must_use]
    pub fn is_payload_kind_supported(&self) -> bool {
        self.payload_kind.is_supported()
    }
}

// =============================================================================
// Gate Receipt Builder
// =============================================================================

/// Builder for constructing [`GateReceipt`] instances.
#[derive(Debug, Default)]
pub struct GateReceiptBuilder {
    receipt_id: String,
    gate_id: String,
    lease_id: String,
    changeset_digest: Option<[u8; 32]>,
    executor_actor_id: Option<String>,
    receipt_version: Option<u32>,
    payload_kind: Option<PayloadKind>,
    payload_schema_version: Option<u32>,
    payload_hash: Option<[u8; 32]>,
    evidence_bundle_hash: Option<[u8; 32]>,
}

impl GateReceiptBuilder {
    /// Creates a new builder with required identifiers.
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        gate_id: impl Into<String>,
        lease_id: impl Into<String>,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            gate_id: gate_id.into(),
            lease_id: lease_id.into(),
            ..Default::default()
        }
    }

    /// Sets the changeset digest.
    #[must_use]
    pub const fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the executor actor ID.
    #[must_use]
    pub fn executor_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.executor_actor_id = Some(actor_id.into());
        self
    }

    /// Sets the receipt version.
    #[must_use]
    pub const fn receipt_version(mut self, version: u32) -> Self {
        self.receipt_version = Some(version);
        self
    }

    /// Sets the payload kind.
    #[must_use]
    pub const fn payload_kind(mut self, kind: PayloadKind) -> Self {
        self.payload_kind = Some(kind);
        self
    }

    /// Sets the payload schema version.
    #[must_use]
    pub const fn payload_schema_version(mut self, version: u32) -> Self {
        self.payload_schema_version = Some(version);
        self
    }

    /// Sets the payload hash.
    #[must_use]
    pub const fn payload_hash(mut self, hash: [u8; 32]) -> Self {
        self.payload_hash = Some(hash);
        self
    }

    /// Sets the evidence bundle hash.
    #[must_use]
    pub const fn evidence_bundle_hash(mut self, hash: [u8; 32]) -> Self {
        self.evidence_bundle_hash = Some(hash);
        self
    }

    /// Builds the receipt and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing. Use `try_build_and_sign` for
    /// fallible construction.
    #[must_use]
    pub fn build_and_sign(self, signer: &crate::crypto::Signer) -> GateReceipt {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::MissingField`] if any required field is not set.
    pub fn try_build_and_sign(
        self,
        signer: &crate::crypto::Signer,
    ) -> Result<GateReceipt, ReceiptError> {
        let changeset_digest = self
            .changeset_digest
            .ok_or(ReceiptError::MissingField("changeset_digest"))?;
        let executor_actor_id = self
            .executor_actor_id
            .ok_or(ReceiptError::MissingField("executor_actor_id"))?;
        let receipt_version = self
            .receipt_version
            .ok_or(ReceiptError::MissingField("receipt_version"))?;
        let payload_kind = self
            .payload_kind
            .ok_or(ReceiptError::MissingField("payload_kind"))?;
        let payload_schema_version = self
            .payload_schema_version
            .ok_or(ReceiptError::MissingField("payload_schema_version"))?;
        let payload_hash = self
            .payload_hash
            .ok_or(ReceiptError::MissingField("payload_hash"))?;
        let evidence_bundle_hash = self
            .evidence_bundle_hash
            .ok_or(ReceiptError::MissingField("evidence_bundle_hash"))?;

        // Create receipt with placeholder signature
        let mut receipt = GateReceipt {
            receipt_id: self.receipt_id,
            gate_id: self.gate_id,
            lease_id: self.lease_id,
            changeset_digest,
            executor_actor_id,
            receipt_version,
            payload_kind,
            payload_schema_version,
            payload_hash,
            evidence_bundle_hash,
            receipt_signature: [0u8; 64],
        };

        // Sign the canonical bytes
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, GATE_RECEIPT_PREFIX, &canonical);
        receipt.receipt_signature = signature.to_bytes();

        Ok(receipt)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

/// Proto-generated `GateReceipt` message for wire format.
///
/// This mirrors the structure in `kernel_events.proto`.
#[derive(Clone, PartialEq, Eq, Message)]
#[allow(missing_docs)]
pub struct GateReceiptProto {
    #[prost(string, tag = "1")]
    pub receipt_id: String,

    #[prost(string, tag = "2")]
    pub gate_id: String,

    #[prost(string, tag = "3")]
    pub lease_id: String,

    #[prost(bytes = "vec", tag = "4")]
    pub changeset_digest: Vec<u8>,

    #[prost(string, tag = "5")]
    pub executor_actor_id: String,

    #[prost(uint32, tag = "6")]
    pub receipt_version: u32,

    #[prost(string, tag = "7")]
    pub payload_kind: String,

    #[prost(uint32, tag = "8")]
    pub payload_schema_version: u32,

    #[prost(bytes = "vec", tag = "9")]
    pub payload_hash: Vec<u8>,

    #[prost(bytes = "vec", tag = "10")]
    pub evidence_bundle_hash: Vec<u8>,

    #[prost(bytes = "vec", tag = "11")]
    pub receipt_signature: Vec<u8>,
}

impl TryFrom<GateReceiptProto> for GateReceipt {
    type Error = ReceiptError;

    fn try_from(proto: GateReceiptProto) -> Result<Self, Self::Error> {
        let changeset_digest: [u8; 32] = proto.changeset_digest.try_into().map_err(|_| {
            ReceiptError::InvalidData("changeset_digest must be 32 bytes".to_string())
        })?;

        let payload_hash: [u8; 32] = proto
            .payload_hash
            .try_into()
            .map_err(|_| ReceiptError::InvalidData("payload_hash must be 32 bytes".to_string()))?;

        let evidence_bundle_hash: [u8; 32] =
            proto.evidence_bundle_hash.try_into().map_err(|_| {
                ReceiptError::InvalidData("evidence_bundle_hash must be 32 bytes".to_string())
            })?;

        let receipt_signature: [u8; 64] = proto.receipt_signature.try_into().map_err(|_| {
            ReceiptError::InvalidData("receipt_signature must be 64 bytes".to_string())
        })?;

        let payload_kind = PayloadKind::parse(&proto.payload_kind).ok_or_else(|| {
            ReceiptError::InvalidData(format!("unknown payload kind: {}", proto.payload_kind))
        })?;

        Ok(Self {
            receipt_id: proto.receipt_id,
            gate_id: proto.gate_id,
            lease_id: proto.lease_id,
            changeset_digest,
            executor_actor_id: proto.executor_actor_id,
            receipt_version: proto.receipt_version,
            payload_kind,
            payload_schema_version: proto.payload_schema_version,
            payload_hash,
            evidence_bundle_hash,
            receipt_signature,
        })
    }
}

impl From<GateReceipt> for GateReceiptProto {
    fn from(receipt: GateReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id,
            gate_id: receipt.gate_id,
            lease_id: receipt.lease_id,
            changeset_digest: receipt.changeset_digest.to_vec(),
            executor_actor_id: receipt.executor_actor_id,
            receipt_version: receipt.receipt_version,
            payload_kind: receipt.payload_kind.as_str().to_string(),
            payload_schema_version: receipt.payload_schema_version,
            payload_hash: receipt.payload_hash.to_vec(),
            evidence_bundle_hash: receipt.evidence_bundle_hash.to_vec(),
            receipt_signature: receipt.receipt_signature.to_vec(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn create_test_receipt(signer: &Signer) -> GateReceipt {
        GateReceiptBuilder::new("receipt-001", "gate-build", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind(PayloadKind::Aat)
            .payload_schema_version(1)
            .payload_hash([0xab; 32])
            .evidence_bundle_hash([0xcd; 32])
            .build_and_sign(signer)
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert_eq!(receipt.receipt_id, "receipt-001");
        assert_eq!(receipt.gate_id, "gate-build");
        assert_eq!(receipt.lease_id, "lease-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.executor_actor_id, "executor-001");
        assert_eq!(receipt.receipt_version, 1);
        assert_eq!(receipt.payload_kind, PayloadKind::Aat);
        assert_eq!(receipt.payload_schema_version, 1);
        assert_eq!(receipt.payload_hash, [0xab; 32]);
        assert_eq!(receipt.evidence_bundle_hash, [0xcd; 32]);
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        // Missing changeset_digest
        let result = GateReceiptBuilder::new("receipt-001", "gate-build", "lease-001")
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind(PayloadKind::Aat)
            .payload_schema_version(1)
            .payload_hash([0xab; 32])
            .evidence_bundle_hash([0xcd; 32])
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::MissingField("changeset_digest"))
        ));

        // Missing executor_actor_id
        let result = GateReceiptBuilder::new("receipt-001", "gate-build", "lease-001")
            .changeset_digest([0x42; 32])
            .receipt_version(1)
            .payload_kind(PayloadKind::Aat)
            .payload_schema_version(1)
            .payload_hash([0xab; 32])
            .evidence_bundle_hash([0xcd; 32])
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::MissingField("executor_actor_id"))
        ));

        // Missing receipt_version
        let result = GateReceiptBuilder::new("receipt-001", "gate-build", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .payload_kind(PayloadKind::Aat)
            .payload_schema_version(1)
            .payload_hash([0xab; 32])
            .evidence_bundle_hash([0xcd; 32])
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::MissingField("receipt_version"))
        ));
    }

    // =========================================================================
    // Signature Tests
    // =========================================================================

    #[test]
    fn test_signature_validation() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Valid signature
        assert!(receipt.validate_signature(&signer.verifying_key()).is_ok());

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            receipt
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);

        // Modify content after signing
        receipt.gate_id = "gate-test".to_string();

        // Signature should now be invalid
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let receipt1 = create_test_receipt(&signer);
        let receipt2 = create_test_receipt(&signer);

        // Same content should produce same canonical bytes
        assert_eq!(receipt1.canonical_bytes(), receipt2.canonical_bytes());
    }

    #[test]
    fn test_uses_domain_separator() {
        // Verify that receipt uses GATE_RECEIPT: domain separator
        // by ensuring a signature created with a different prefix fails
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Create a signature with the wrong domain prefix
        let canonical = receipt.canonical_bytes();
        let wrong_signature = super::super::domain_separator::sign_with_domain(
            &signer,
            super::super::domain_separator::GATE_LEASE_ISSUED_PREFIX,
            &canonical,
        );

        // Verification should fail because domains don't match
        let result = super::super::domain_separator::verify_with_domain(
            &signer.verifying_key(),
            super::super::domain_separator::GATE_RECEIPT_PREFIX,
            &canonical,
            &wrong_signature,
        );
        assert!(result.is_err());
    }

    // =========================================================================
    // Version Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_version_known_version_accepted() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Version 1 should be accepted in enforce mode
        assert!(receipt.validate_version(true).is_ok());
    }

    #[test]
    fn test_validate_version_unknown_version_rejected_in_enforce_mode() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.receipt_version = 99; // Unknown version

        // Should be rejected in enforce mode
        let result = receipt.validate_version(true);
        assert!(matches!(
            result,
            Err(ReceiptError::UnsupportedVersion { version: 99, .. })
        ));
    }

    #[test]
    fn test_validate_version_unknown_version_accepted_without_enforce() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.receipt_version = 99; // Unknown version

        // Should be accepted without enforce mode
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_is_version_supported() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert!(receipt.is_version_supported());

        let mut receipt_v99 = receipt;
        receipt_v99.receipt_version = 99;
        assert!(!receipt_v99.is_version_supported());
    }

    #[test]
    fn test_all_supported_versions() {
        let signer = Signer::generate();

        for &version in SUPPORTED_RECEIPT_VERSIONS {
            let receipt = GateReceiptBuilder::new("receipt-001", "gate-build", "lease-001")
                .changeset_digest([0x42; 32])
                .executor_actor_id("executor-001")
                .receipt_version(version)
                .payload_kind(PayloadKind::Aat)
                .payload_schema_version(1)
                .payload_hash([0xab; 32])
                .evidence_bundle_hash([0xcd; 32])
                .build_and_sign(&signer);

            assert!(
                receipt.validate_version(true).is_ok(),
                "Version {version} should be supported"
            );
        }
    }

    // =========================================================================
    // Payload Kind Tests
    // =========================================================================

    #[test]
    fn test_payload_kind_string_conversion() {
        assert_eq!(PayloadKind::Aat.as_str(), "aat");
        assert_eq!(PayloadKind::Quality.as_str(), "quality");
        assert_eq!(PayloadKind::Security.as_str(), "security");

        assert_eq!(PayloadKind::parse("aat"), Some(PayloadKind::Aat));
        assert_eq!(PayloadKind::parse("quality"), Some(PayloadKind::Quality));
        assert_eq!(PayloadKind::parse("security"), Some(PayloadKind::Security));
        assert_eq!(PayloadKind::parse("unknown"), None);
    }

    #[test]
    fn test_all_payload_kinds_supported() {
        let signer = Signer::generate();

        for kind in [
            PayloadKind::Aat,
            PayloadKind::Quality,
            PayloadKind::Security,
        ] {
            let receipt = GateReceiptBuilder::new("receipt-001", "gate-build", "lease-001")
                .changeset_digest([0x42; 32])
                .executor_actor_id("executor-001")
                .receipt_version(1)
                .payload_kind(kind)
                .payload_schema_version(1)
                .payload_hash([0xab; 32])
                .evidence_bundle_hash([0xcd; 32])
                .build_and_sign(&signer);

            assert!(
                receipt.validate_version(true).is_ok(),
                "Payload kind {kind} should be supported"
            );
        }
    }

    #[test]
    fn test_is_payload_kind_supported() {
        assert!(PayloadKind::Aat.is_supported());
        assert!(PayloadKind::Quality.is_supported());
        assert!(PayloadKind::Security.is_supported());
    }

    // =========================================================================
    // Proto Conversion Tests
    // =========================================================================

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_receipt(&signer);

        // Convert to proto
        let proto: GateReceiptProto = original.clone().into();

        // Encode and decode
        let encoded = proto.encode_to_vec();
        let decoded_proto = GateReceiptProto::decode(encoded.as_slice()).unwrap();

        // Convert back to domain type
        let recovered = GateReceipt::try_from(decoded_proto).unwrap();

        // Fields should match
        assert_eq!(original.receipt_id, recovered.receipt_id);
        assert_eq!(original.gate_id, recovered.gate_id);
        assert_eq!(original.lease_id, recovered.lease_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(original.executor_actor_id, recovered.executor_actor_id);
        assert_eq!(original.receipt_version, recovered.receipt_version);
        assert_eq!(original.payload_kind, recovered.payload_kind);
        assert_eq!(
            original.payload_schema_version,
            recovered.payload_schema_version
        );
        assert_eq!(original.payload_hash, recovered.payload_hash);
        assert_eq!(
            original.evidence_bundle_hash,
            recovered.evidence_bundle_hash
        );
        assert_eq!(original.receipt_signature, recovered.receipt_signature);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_proto_invalid_changeset_digest_length() {
        let proto = GateReceiptProto {
            receipt_id: "receipt-001".to_string(),
            gate_id: "gate-build".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0u8; 16], // Wrong length - should be 32
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0u8; 32],
            evidence_bundle_hash: vec![0u8; 32],
            receipt_signature: vec![0u8; 64],
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(result, Err(ReceiptError::InvalidData(_))));
    }

    #[test]
    fn test_proto_invalid_signature_length() {
        let proto = GateReceiptProto {
            receipt_id: "receipt-001".to_string(),
            gate_id: "gate-build".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0u8; 32],
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0u8; 32],
            evidence_bundle_hash: vec![0u8; 32],
            receipt_signature: vec![0u8; 32], // Wrong length - should be 64
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(result, Err(ReceiptError::InvalidData(_))));
    }

    #[test]
    fn test_proto_invalid_payload_kind() {
        let proto = GateReceiptProto {
            receipt_id: "receipt-001".to_string(),
            gate_id: "gate-build".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0u8; 32],
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "invalid_kind".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0u8; 32],
            evidence_bundle_hash: vec![0u8; 32],
            receipt_signature: vec![0u8; 64],
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(result, Err(ReceiptError::InvalidData(_))));
    }
}
