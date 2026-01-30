//! Policy resolution types for the Forge Admission Cycle.
//!
//! This module defines [`PolicyResolvedForChangeSet`] which is the anchor event
//! that locks policy decisions for a changeset. All subsequent lease issuance
//! and receipt validation must reference this anchor.
//!
//! # Security Model
//!
//! `PolicyResolvedForChangeSet` serves as the cryptographic anchor for policy
//! binding:
//!
//! - **Policy Binding**: The `resolved_policy_hash` binds all policy decisions
//!   for a changeset
//! - **Lease Verification**: `verify_lease_match()` ensures lease `policy_hash`
//!   matches resolution
//! - **Anti-Downgrade**: `verify_receipt_match()` detects policy downgrades
//! - **Domain Separation**: Signature uses `POLICY_RESOLVED_FOR_CHANGESET:`
//!   prefix
//!
//! # Ordering Invariant
//!
//! **CRITICAL**: A `PolicyResolvedForChangeSet` event MUST exist before any
//! `GateLeaseIssued` event for the same `work_id`/changeset. This ensures all
//! leases operate under a locked policy configuration.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     GateLease, GateLeaseBuilder, PolicyResolvedForChangeSet,
//!     PolicyResolvedForChangeSetBuilder,
//! };
//!
//! // Create a policy resolution
//! let resolver_signer = Signer::generate();
//! let resolution =
//!     PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
//!         .resolved_risk_tier(1)
//!         .resolved_determinism_class(0)
//!         .resolver_actor_id("resolver-001")
//!         .resolver_version("1.0.0")
//!         .build_and_sign(&resolver_signer);
//!
//! // Create a lease that references the resolution's policy hash
//! let issuer_signer = Signer::generate();
//! let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .issued_at(1704067200000)
//!     .expires_at(1704070800000)
//!     .policy_hash(resolution.resolved_policy_hash())
//!     .issuer_actor_id("issuer-001")
//!     .time_envelope_ref("htf:tick:12345")
//!     .build_and_sign(&issuer_signer);
//!
//! // Verify the lease matches the policy resolution
//! assert!(resolution.verify_lease_match(&lease).is_ok());
//! ```

use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{POLICY_RESOLVED_PREFIX, sign_with_domain, verify_with_domain};
use super::lease::GateLease;
use crate::crypto::{Signature, VerifyingKey};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during policy resolution operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyResolutionError {
    /// The resolution signature is invalid.
    #[error("invalid resolution signature: {0}")]
    InvalidSignature(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid resolution data.
    #[error("invalid resolution data: {0}")]
    InvalidData(String),

    /// Policy hash mismatch between resolution and lease.
    #[error("policy hash mismatch: resolution={resolution_hash}, lease={lease_hash}")]
    PolicyHashMismatch {
        /// Hash from the policy resolution.
        resolution_hash: String,
        /// Hash from the lease.
        lease_hash: String,
    },

    /// Work ID mismatch between resolution and lease.
    #[error("work ID mismatch: resolution={resolution_work_id}, lease={lease_work_id}")]
    WorkIdMismatch {
        /// Work ID from the policy resolution.
        resolution_work_id: String,
        /// Work ID from the lease.
        lease_work_id: String,
    },

    /// Changeset digest mismatch between resolution and lease.
    #[error("changeset digest mismatch")]
    ChangesetDigestMismatch,

    /// Receipt policy hash does not match resolution.
    #[error("receipt policy hash mismatch: expected={expected}, actual={actual}")]
    ReceiptPolicyMismatch {
        /// Expected hash from policy resolution.
        expected: String,
        /// Actual hash from receipt.
        actual: String,
    },
}

// =============================================================================
// PolicyResolvedForChangeSet
// =============================================================================

/// The anchor event that locks policy decisions for a changeset.
///
/// This event cryptographically binds the resolved policy tuple to a specific
/// changeset. All subsequent lease issuance and receipt validation must
/// reference this anchor.
///
/// # Fields (11 total)
///
/// - `work_id`: Work item this policy resolution applies to
/// - `changeset_digest`: Hash binding to specific changeset
/// - `resolved_policy_hash`: Hash of the resolved policy tuple
/// - `resolved_risk_tier`: Resolved risk tier (0-4)
/// - `resolved_determinism_class`: Resolved determinism class (0=non, 1=soft,
///   2=fully)
/// - `resolved_rcp_profile_ids`: Resolved RCP profile IDs
/// - `resolved_rcp_manifest_hashes`: Hashes of resolved RCP manifests
/// - `resolved_verifier_policy_hashes`: Hashes of resolved verifier policies
/// - `resolver_actor_id`: Actor who performed the policy resolution
/// - `resolver_version`: Version of the resolver component
/// - `resolver_signature`: Ed25519 signature with domain separation
///
/// # Security
///
/// The signature uses the `POLICY_RESOLVED_FOR_CHANGESET:` domain prefix to
/// prevent cross-protocol signature replay attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResolvedForChangeSet {
    /// Work item this policy resolution applies to.
    pub work_id: String,

    /// Hash binding to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Hash of the resolved policy tuple.
    ///
    /// Computed from: `risk_tier || determinism_class ||
    /// sorted(rcp_profile_ids) || sorted(rcp_manifest_hashes) ||
    /// sorted(verifier_policy_hashes)`
    #[serde(with = "serde_bytes")]
    resolved_policy_hash: [u8; 32],

    /// Resolved risk tier (0-4).
    pub resolved_risk_tier: u8,

    /// Resolved determinism class (0=non, 1=soft, 2=fully).
    pub resolved_determinism_class: u8,

    /// Resolved RCP profile IDs (sorted for canonical encoding).
    pub resolved_rcp_profile_ids: Vec<String>,

    /// Hashes of resolved RCP manifests (sorted for canonical encoding).
    #[serde(with = "vec_hash_serde")]
    pub resolved_rcp_manifest_hashes: Vec<[u8; 32]>,

    /// Hashes of resolved verifier policies (sorted for canonical encoding).
    #[serde(with = "vec_hash_serde")]
    pub resolved_verifier_policy_hashes: Vec<[u8; 32]>,

    /// Actor who performed the policy resolution.
    pub resolver_actor_id: String,

    /// Version of the resolver component.
    pub resolver_version: String,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub resolver_signature: [u8; 64],
}

/// Custom serde for Vec<[u8; 32]> (serde doesn't support arrays > 32 in Vec).
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

impl PolicyResolvedForChangeSet {
    /// Returns the resolved policy hash.
    #[must_use]
    pub const fn resolved_policy_hash(&self) -> [u8; 32] {
        self.resolved_policy_hash
    }

    /// Computes the policy hash from the resolved fields.
    ///
    /// The hash is computed over:
    /// `risk_tier || determinism_class || sorted(rcp_profile_ids) ||
    ///  sorted(rcp_manifest_hashes) || sorted(verifier_policy_hashes)`
    #[must_use]
    fn compute_policy_hash(
        risk_tier: u8,
        determinism_class: u8,
        rcp_profile_ids: &[String],
        rcp_manifest_hashes: &[[u8; 32]],
        verifier_policy_hashes: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Risk tier and determinism class
        hasher.update(&[risk_tier, determinism_class]);

        // Sorted RCP profile IDs
        let mut sorted_ids = rcp_profile_ids.to_vec();
        sorted_ids.sort();
        for id in &sorted_ids {
            hasher.update(id.as_bytes());
            hasher.update(&[0]); // null separator
        }
        hasher.update(&[0xFF]); // section separator

        // Sorted RCP manifest hashes
        let mut sorted_manifests = rcp_manifest_hashes.to_vec();
        sorted_manifests.sort_unstable();
        for hash in &sorted_manifests {
            hasher.update(hash);
        }
        hasher.update(&[0xFF]); // section separator

        // Sorted verifier policy hashes
        let mut sorted_verifiers = verifier_policy_hashes.to_vec();
        sorted_verifiers.sort_unstable();
        for hash in &sorted_verifiers {
            hasher.update(hash);
        }

        *hasher.finalize().as_bytes()
    }

    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature,
    /// encoded in a deterministic order.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = self.work_id.len()
            + 1
            + 32 // changeset_digest
            + 32 // resolved_policy_hash
            + 2  // risk_tier + determinism_class
            + self.resolved_rcp_profile_ids.iter().map(|s| s.len() + 1).sum::<usize>()
            + self.resolved_rcp_manifest_hashes.len() * 32
            + self.resolved_verifier_policy_hashes.len() * 32
            + self.resolver_actor_id.len()
            + 1
            + self.resolver_version.len()
            + 1;

        let mut bytes = Vec::with_capacity(capacity);

        // 1. work_id
        bytes.extend_from_slice(self.work_id.as_bytes());
        bytes.push(0); // null separator

        // 2. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 3. resolved_policy_hash
        bytes.extend_from_slice(&self.resolved_policy_hash);

        // 4. resolved_risk_tier
        bytes.push(self.resolved_risk_tier);

        // 5. resolved_determinism_class
        bytes.push(self.resolved_determinism_class);

        // 6. resolved_rcp_profile_ids (sorted)
        let mut sorted_ids = self.resolved_rcp_profile_ids.clone();
        sorted_ids.sort();
        for id in &sorted_ids {
            bytes.extend_from_slice(id.as_bytes());
            bytes.push(0);
        }
        bytes.push(0xFF); // section separator

        // 7. resolved_rcp_manifest_hashes (sorted)
        let mut sorted_manifests = self.resolved_rcp_manifest_hashes.clone();
        sorted_manifests.sort_unstable();
        for hash in &sorted_manifests {
            bytes.extend_from_slice(hash);
        }
        bytes.push(0xFF); // section separator

        // 8. resolved_verifier_policy_hashes (sorted)
        let mut sorted_verifiers = self.resolved_verifier_policy_hashes.clone();
        sorted_verifiers.sort_unstable();
        for hash in &sorted_verifiers {
            bytes.extend_from_slice(hash);
        }
        bytes.push(0xFF); // section separator

        // 9. resolver_actor_id
        bytes.extend_from_slice(self.resolver_actor_id.as_bytes());
        bytes.push(0);

        // 10. resolver_version
        bytes.extend_from_slice(self.resolver_version.as_bytes());

        bytes
    }

    /// Validates the resolution signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected resolver
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(PolicyResolutionError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::InvalidSignature`] if signature
    /// verification fails.
    pub fn validate_signature(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), PolicyResolutionError> {
        let signature = Signature::from_bytes(&self.resolver_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(
            verifying_key,
            POLICY_RESOLVED_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| PolicyResolutionError::InvalidSignature(e.to_string()))
    }

    /// Verifies that a lease's `policy_hash` matches this resolution.
    ///
    /// This is the primary mechanism for ensuring that leases operate under
    /// the locked policy configuration established by this resolution.
    ///
    /// # Arguments
    ///
    /// * `lease` - The gate lease to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the lease matches this resolution, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::WorkIdMismatch`] if work IDs don't
    /// match. Returns [`PolicyResolutionError::ChangesetDigestMismatch`] if
    /// changeset digests don't match.
    /// Returns [`PolicyResolutionError::PolicyHashMismatch`] if policy hashes
    /// don't match.
    pub fn verify_lease_match(&self, lease: &GateLease) -> Result<(), PolicyResolutionError> {
        // Check work_id matches
        if self.work_id != lease.work_id {
            return Err(PolicyResolutionError::WorkIdMismatch {
                resolution_work_id: self.work_id.clone(),
                lease_work_id: lease.work_id.clone(),
            });
        }

        // Check changeset_digest matches
        if self.changeset_digest != lease.changeset_digest {
            return Err(PolicyResolutionError::ChangesetDigestMismatch);
        }

        // Check policy_hash matches
        if self.resolved_policy_hash != lease.policy_hash {
            return Err(PolicyResolutionError::PolicyHashMismatch {
                resolution_hash: hex_encode(&self.resolved_policy_hash),
                lease_hash: hex_encode(&lease.policy_hash),
            });
        }

        Ok(())
    }

    /// Verifies that a receipt's policy hash matches this resolution.
    ///
    /// This provides basic anti-downgrade protection by ensuring receipts
    /// reference the locked policy configuration.
    ///
    /// # Arguments
    ///
    /// * `receipt_policy_hash` - The policy hash from a gate receipt
    ///
    /// # Returns
    ///
    /// `Ok(())` if the receipt policy hash matches, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::ReceiptPolicyMismatch`] if hashes don't
    /// match.
    pub fn verify_receipt_match(
        &self,
        receipt_policy_hash: &[u8; 32],
    ) -> Result<(), PolicyResolutionError> {
        if &self.resolved_policy_hash != receipt_policy_hash {
            return Err(PolicyResolutionError::ReceiptPolicyMismatch {
                expected: hex_encode(&self.resolved_policy_hash),
                actual: hex_encode(receipt_policy_hash),
            });
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

/// Builder for constructing [`PolicyResolvedForChangeSet`] instances.
#[derive(Debug, Default)]
pub struct PolicyResolvedForChangeSetBuilder {
    work_id: String,
    changeset_digest: [u8; 32],
    resolved_risk_tier: Option<u8>,
    resolved_determinism_class: Option<u8>,
    resolved_rcp_profile_ids: Vec<String>,
    resolved_rcp_manifest_hashes: Vec<[u8; 32]>,
    resolved_verifier_policy_hashes: Vec<[u8; 32]>,
    resolver_actor_id: Option<String>,
    resolver_version: Option<String>,
}

impl PolicyResolvedForChangeSetBuilder {
    /// Creates a new builder with required `work_id` and `changeset_digest`.
    #[must_use]
    pub fn new(work_id: impl Into<String>, changeset_digest: [u8; 32]) -> Self {
        Self {
            work_id: work_id.into(),
            changeset_digest,
            ..Default::default()
        }
    }

    /// Sets the resolved risk tier (0-4).
    #[must_use]
    pub const fn resolved_risk_tier(mut self, tier: u8) -> Self {
        self.resolved_risk_tier = Some(tier);
        self
    }

    /// Sets the resolved determinism class (0=non, 1=soft, 2=fully).
    #[must_use]
    pub const fn resolved_determinism_class(mut self, class: u8) -> Self {
        self.resolved_determinism_class = Some(class);
        self
    }

    /// Sets the resolved RCP profile IDs.
    #[must_use]
    pub fn resolved_rcp_profile_ids(mut self, ids: Vec<String>) -> Self {
        self.resolved_rcp_profile_ids = ids;
        self
    }

    /// Adds a single RCP profile ID.
    #[must_use]
    pub fn add_rcp_profile_id(mut self, id: impl Into<String>) -> Self {
        self.resolved_rcp_profile_ids.push(id.into());
        self
    }

    /// Sets the resolved RCP manifest hashes.
    #[must_use]
    pub fn resolved_rcp_manifest_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.resolved_rcp_manifest_hashes = hashes;
        self
    }

    /// Adds a single RCP manifest hash.
    #[must_use]
    pub fn add_rcp_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.resolved_rcp_manifest_hashes.push(hash);
        self
    }

    /// Sets the resolved verifier policy hashes.
    #[must_use]
    pub fn resolved_verifier_policy_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.resolved_verifier_policy_hashes = hashes;
        self
    }

    /// Adds a single verifier policy hash.
    #[must_use]
    pub fn add_verifier_policy_hash(mut self, hash: [u8; 32]) -> Self {
        self.resolved_verifier_policy_hashes.push(hash);
        self
    }

    /// Sets the resolver actor ID.
    #[must_use]
    pub fn resolver_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.resolver_actor_id = Some(actor_id.into());
        self
    }

    /// Sets the resolver version.
    #[must_use]
    pub fn resolver_version(mut self, version: impl Into<String>) -> Self {
        self.resolver_version = Some(version.into());
        self
    }

    /// Builds the resolution and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &crate::crypto::Signer) -> PolicyResolvedForChangeSet {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the resolution.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyResolutionError::MissingField`] if any required field is
    /// not set.
    pub fn try_build_and_sign(
        self,
        signer: &crate::crypto::Signer,
    ) -> Result<PolicyResolvedForChangeSet, PolicyResolutionError> {
        let resolved_risk_tier = self
            .resolved_risk_tier
            .ok_or(PolicyResolutionError::MissingField("resolved_risk_tier"))?;
        let resolved_determinism_class =
            self.resolved_determinism_class
                .ok_or(PolicyResolutionError::MissingField(
                    "resolved_determinism_class",
                ))?;
        let resolver_actor_id = self
            .resolver_actor_id
            .ok_or(PolicyResolutionError::MissingField("resolver_actor_id"))?;
        let resolver_version = self
            .resolver_version
            .ok_or(PolicyResolutionError::MissingField("resolver_version"))?;

        // Sort arrays for canonical encoding
        let mut resolved_rcp_profile_ids = self.resolved_rcp_profile_ids;
        resolved_rcp_profile_ids.sort();

        let mut resolved_rcp_manifest_hashes = self.resolved_rcp_manifest_hashes;
        resolved_rcp_manifest_hashes.sort_unstable();

        let mut resolved_verifier_policy_hashes = self.resolved_verifier_policy_hashes;
        resolved_verifier_policy_hashes.sort_unstable();

        // Compute the policy hash
        let resolved_policy_hash = PolicyResolvedForChangeSet::compute_policy_hash(
            resolved_risk_tier,
            resolved_determinism_class,
            &resolved_rcp_profile_ids,
            &resolved_rcp_manifest_hashes,
            &resolved_verifier_policy_hashes,
        );

        // Create resolution with placeholder signature
        let mut resolution = PolicyResolvedForChangeSet {
            work_id: self.work_id,
            changeset_digest: self.changeset_digest,
            resolved_policy_hash,
            resolved_risk_tier,
            resolved_determinism_class,
            resolved_rcp_profile_ids,
            resolved_rcp_manifest_hashes,
            resolved_verifier_policy_hashes,
            resolver_actor_id,
            resolver_version,
            resolver_signature: [0u8; 64],
        };

        // Sign the canonical bytes
        let canonical = resolution.canonical_bytes();
        let signature = sign_with_domain(signer, POLICY_RESOLVED_PREFIX, &canonical);
        resolution.resolver_signature = signature.to_bytes();

        Ok(resolution)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

/// Proto-generated `PolicyResolvedForChangeSet` message for wire format.
#[derive(Clone, PartialEq, Eq, Message)]
#[allow(missing_docs)]
pub struct PolicyResolvedForChangeSetProto {
    #[prost(string, tag = "1")]
    pub work_id: String,

    #[prost(bytes = "vec", tag = "2")]
    pub changeset_digest: Vec<u8>,

    #[prost(bytes = "vec", tag = "3")]
    pub resolved_policy_hash: Vec<u8>,

    #[prost(uint32, tag = "4")]
    pub resolved_risk_tier: u32,

    #[prost(uint32, tag = "5")]
    pub resolved_determinism_class: u32,

    #[prost(string, repeated, tag = "6")]
    pub resolved_rcp_profile_ids: Vec<String>,

    #[prost(bytes = "vec", repeated, tag = "7")]
    pub resolved_rcp_manifest_hashes: Vec<Vec<u8>>,

    #[prost(bytes = "vec", repeated, tag = "8")]
    pub resolved_verifier_policy_hashes: Vec<Vec<u8>>,

    #[prost(string, tag = "9")]
    pub resolver_actor_id: String,

    #[prost(string, tag = "10")]
    pub resolver_version: String,

    #[prost(bytes = "vec", tag = "11")]
    pub resolver_signature: Vec<u8>,
}

impl TryFrom<PolicyResolvedForChangeSetProto> for PolicyResolvedForChangeSet {
    type Error = PolicyResolutionError;

    fn try_from(proto: PolicyResolvedForChangeSetProto) -> Result<Self, Self::Error> {
        let changeset_digest: [u8; 32] = proto.changeset_digest.try_into().map_err(|_| {
            PolicyResolutionError::InvalidData("changeset_digest must be 32 bytes".to_string())
        })?;

        let resolved_policy_hash: [u8; 32] =
            proto.resolved_policy_hash.try_into().map_err(|_| {
                PolicyResolutionError::InvalidData(
                    "resolved_policy_hash must be 32 bytes".to_string(),
                )
            })?;

        let resolver_signature: [u8; 64] = proto.resolver_signature.try_into().map_err(|_| {
            PolicyResolutionError::InvalidData("resolver_signature must be 64 bytes".to_string())
        })?;

        // Validate risk tier (0-4)
        let resolved_risk_tier = u8::try_from(proto.resolved_risk_tier).map_err(|_| {
            PolicyResolutionError::InvalidData("resolved_risk_tier must fit in u8".to_string())
        })?;
        if resolved_risk_tier > 4 {
            return Err(PolicyResolutionError::InvalidData(
                "resolved_risk_tier must be 0-4".to_string(),
            ));
        }

        // Validate determinism class (0-2)
        let resolved_determinism_class =
            u8::try_from(proto.resolved_determinism_class).map_err(|_| {
                PolicyResolutionError::InvalidData(
                    "resolved_determinism_class must fit in u8".to_string(),
                )
            })?;
        if resolved_determinism_class > 2 {
            return Err(PolicyResolutionError::InvalidData(
                "resolved_determinism_class must be 0-2".to_string(),
            ));
        }

        // Convert manifest hashes
        let resolved_rcp_manifest_hashes: Vec<[u8; 32]> = proto
            .resolved_rcp_manifest_hashes
            .into_iter()
            .map(|h| {
                h.try_into().map_err(|_| {
                    PolicyResolutionError::InvalidData(
                        "rcp_manifest_hash must be 32 bytes".to_string(),
                    )
                })
            })
            .collect::<Result<_, _>>()?;

        // Convert verifier hashes
        let resolved_verifier_policy_hashes: Vec<[u8; 32]> = proto
            .resolved_verifier_policy_hashes
            .into_iter()
            .map(|h| {
                h.try_into().map_err(|_| {
                    PolicyResolutionError::InvalidData(
                        "verifier_policy_hash must be 32 bytes".to_string(),
                    )
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            work_id: proto.work_id,
            changeset_digest,
            resolved_policy_hash,
            resolved_risk_tier,
            resolved_determinism_class,
            resolved_rcp_profile_ids: proto.resolved_rcp_profile_ids,
            resolved_rcp_manifest_hashes,
            resolved_verifier_policy_hashes,
            resolver_actor_id: proto.resolver_actor_id,
            resolver_version: proto.resolver_version,
            resolver_signature,
        })
    }
}

impl From<PolicyResolvedForChangeSet> for PolicyResolvedForChangeSetProto {
    fn from(resolution: PolicyResolvedForChangeSet) -> Self {
        Self {
            work_id: resolution.work_id,
            changeset_digest: resolution.changeset_digest.to_vec(),
            resolved_policy_hash: resolution.resolved_policy_hash.to_vec(),
            resolved_risk_tier: u32::from(resolution.resolved_risk_tier),
            resolved_determinism_class: u32::from(resolution.resolved_determinism_class),
            resolved_rcp_profile_ids: resolution.resolved_rcp_profile_ids,
            resolved_rcp_manifest_hashes: resolution
                .resolved_rcp_manifest_hashes
                .into_iter()
                .map(|h| h.to_vec())
                .collect(),
            resolved_verifier_policy_hashes: resolution
                .resolved_verifier_policy_hashes
                .into_iter()
                .map(|h| h.to_vec())
                .collect(),
            resolver_actor_id: resolution.resolver_actor_id,
            resolver_version: resolution.resolver_version,
            resolver_signature: resolution.resolver_signature.to_vec(),
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
    use crate::fac::GateLeaseBuilder;

    fn create_test_resolution(signer: &Signer) -> PolicyResolvedForChangeSet {
        PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .add_rcp_profile_id("rcp-profile-001")
            .add_rcp_manifest_hash([0x11; 32])
            .add_verifier_policy_hash([0x22; 32])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(signer)
    }

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        assert_eq!(resolution.work_id, "work-001");
        assert_eq!(resolution.changeset_digest, [0x42; 32]);
        assert_eq!(resolution.resolved_risk_tier, 1);
        assert_eq!(resolution.resolved_determinism_class, 0);
        assert_eq!(
            resolution.resolved_rcp_profile_ids,
            vec!["rcp-profile-001".to_string()]
        );
        assert_eq!(resolution.resolved_rcp_manifest_hashes, vec![[0x11; 32]]);
        assert_eq!(resolution.resolved_verifier_policy_hashes, vec![[0x22; 32]]);
        assert_eq!(resolution.resolver_actor_id, "resolver-001");
        assert_eq!(resolution.resolver_version, "1.0.0");
    }

    #[test]
    fn test_signature_validation() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Valid signature
        assert!(
            resolution
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            resolution
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut resolution = create_test_resolution(&signer);

        // Modify content after signing
        resolution.work_id = "work-002".to_string();

        // Signature should now be invalid
        assert!(
            resolution
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let resolution1 = create_test_resolution(&signer);
        let resolution2 = create_test_resolution(&signer);

        // Same content should produce same canonical bytes
        assert_eq!(resolution1.canonical_bytes(), resolution2.canonical_bytes());
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let signer = Signer::generate();
        let resolution1 = create_test_resolution(&signer);
        let resolution2 = create_test_resolution(&signer);

        // Same inputs should produce same policy hash
        assert_eq!(
            resolution1.resolved_policy_hash(),
            resolution2.resolved_policy_hash()
        );
    }

    #[test]
    fn test_policy_hash_differs_with_different_inputs() {
        let signer = Signer::generate();

        let resolution1 = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        let resolution2 = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(2) // Different risk tier
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Different risk tier should produce different policy hash
        assert_ne!(
            resolution1.resolved_policy_hash(),
            resolution2.resolved_policy_hash()
        );
    }

    #[test]
    fn test_verify_lease_match_success() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        // Create a matching lease
        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        // Should match
        assert!(resolution.verify_lease_match(&lease).is_ok());
    }

    #[test]
    fn test_verify_lease_match_work_id_mismatch() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-002", "gate-build") // Different work_id
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::WorkIdMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_lease_match_changeset_mismatch() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x99; 32]) // Different changeset
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash(resolution.resolved_policy_hash())
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::ChangesetDigestMismatch)
        ));
    }

    #[test]
    fn test_verify_lease_match_policy_hash_mismatch() {
        let resolver_signer = Signer::generate();
        let resolution = create_test_resolution(&resolver_signer);

        let issuer_signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_704_067_200_000)
            .expires_at(1_704_070_800_000)
            .policy_hash([0xAB; 32]) // Different policy hash
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&issuer_signer);

        let result = resolution.verify_lease_match(&lease);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::PolicyHashMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_receipt_match_success() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Matching receipt policy hash
        assert!(
            resolution
                .verify_receipt_match(&resolution.resolved_policy_hash())
                .is_ok()
        );
    }

    #[test]
    fn test_verify_receipt_match_failure() {
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Non-matching receipt policy hash
        let wrong_hash = [0xAB; 32];
        let result = resolution.verify_receipt_match(&wrong_hash);
        assert!(matches!(
            result,
            Err(PolicyResolutionError::ReceiptPolicyMismatch { .. })
        ));
    }

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_resolution(&signer);

        // Convert to proto
        let proto: PolicyResolvedForChangeSetProto = original.clone().into();

        // Encode and decode
        let encoded = proto.encode_to_vec();
        let decoded_proto = PolicyResolvedForChangeSetProto::decode(encoded.as_slice()).unwrap();

        // Convert back to domain type
        let recovered = PolicyResolvedForChangeSet::try_from(decoded_proto).unwrap();

        // Fields should match
        assert_eq!(original.work_id, recovered.work_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(
            original.resolved_policy_hash,
            recovered.resolved_policy_hash
        );
        assert_eq!(original.resolved_risk_tier, recovered.resolved_risk_tier);
        assert_eq!(
            original.resolved_determinism_class,
            recovered.resolved_determinism_class
        );
        assert_eq!(
            original.resolved_rcp_profile_ids,
            recovered.resolved_rcp_profile_ids
        );
        assert_eq!(
            original.resolved_rcp_manifest_hashes,
            recovered.resolved_rcp_manifest_hashes
        );
        assert_eq!(
            original.resolved_verifier_policy_hashes,
            recovered.resolved_verifier_policy_hashes
        );
        assert_eq!(original.resolver_actor_id, recovered.resolver_actor_id);
        assert_eq!(original.resolver_version, recovered.resolver_version);
        assert_eq!(original.resolver_signature, recovered.resolver_signature);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_proto_risk_tier() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 5, // Invalid: must be 0-4
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(result, Err(PolicyResolutionError::InvalidData(_))));
    }

    #[test]
    fn test_invalid_proto_determinism_class() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 3, // Invalid: must be 0-2
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(result, Err(PolicyResolutionError::InvalidData(_))));
    }

    #[test]
    fn test_invalid_proto_signature_length() {
        let proto = PolicyResolvedForChangeSetProto {
            work_id: "work-001".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 0,
            resolved_determinism_class: 0,
            resolved_rcp_profile_ids: vec![],
            resolved_rcp_manifest_hashes: vec![],
            resolved_verifier_policy_hashes: vec![],
            resolver_actor_id: "resolver-001".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 32], // Wrong length - should be 64
        };

        let result = PolicyResolvedForChangeSet::try_from(proto);
        assert!(matches!(result, Err(PolicyResolutionError::InvalidData(_))));
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        // Missing resolved_risk_tier
        let result = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(PolicyResolutionError::MissingField("resolved_risk_tier"))
        ));
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        // Verify that resolution uses POLICY_RESOLVED_FOR_CHANGESET: domain separator
        // by ensuring a signature created with a different prefix fails
        let signer = Signer::generate();
        let resolution = create_test_resolution(&signer);

        // Create a signature with the wrong domain prefix
        let canonical = resolution.canonical_bytes();
        let wrong_signature = super::super::domain_separator::sign_with_domain(
            &signer,
            super::super::domain_separator::GATE_LEASE_ISSUED_PREFIX,
            &canonical,
        );

        // Verification should fail because domains don't match
        let result = super::super::domain_separator::verify_with_domain(
            &signer.verifying_key(),
            super::super::domain_separator::POLICY_RESOLVED_PREFIX,
            &canonical,
            &wrong_signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sorted_arrays_for_canonical_encoding() {
        let signer = Signer::generate();

        // Create with unsorted arrays
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolved_rcp_profile_ids(vec![
                "z-profile".to_string(),
                "a-profile".to_string(),
                "m-profile".to_string(),
            ])
            .resolved_rcp_manifest_hashes(vec![[0x99; 32], [0x11; 32], [0x55; 32]])
            .resolved_verifier_policy_hashes(vec![[0xCC; 32], [0xAA; 32], [0xBB; 32]])
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        // Arrays should be sorted after build
        assert_eq!(
            resolution.resolved_rcp_profile_ids,
            vec![
                "a-profile".to_string(),
                "m-profile".to_string(),
                "z-profile".to_string()
            ]
        );
        assert_eq!(
            resolution.resolved_rcp_manifest_hashes,
            vec![[0x11; 32], [0x55; 32], [0x99; 32]]
        );
        assert_eq!(
            resolution.resolved_verifier_policy_hashes,
            vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]]
        );
    }

    #[test]
    fn test_empty_arrays() {
        let signer = Signer::generate();

        // Create with empty arrays
        let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(0)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(&signer);

        assert!(resolution.resolved_rcp_profile_ids.is_empty());
        assert!(resolution.resolved_rcp_manifest_hashes.is_empty());
        assert!(resolution.resolved_verifier_policy_hashes.is_empty());

        // Signature should still be valid
        assert!(
            resolution
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }
}
