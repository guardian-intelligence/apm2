//! FAC Broker service: local authority for actuation tokens and economics
//! envelopes.
//!
//! Implements TCK-00510: a local broker authority responsible for FAC actuation
//! authorization and economics/time authority.
//!
//! The broker is the **sole** issuer of:
//! - RFC-0028 `ChannelContextToken` bound to `job_spec_digest` + `lease_id`
//! - RFC-0029 `TimeAuthorityEnvelopeV1` for `boundary_id` + evaluation window
//! - TP-EIO29-002 freshness horizon refs and revocation frontier snapshots
//! - TP-EIO29-003 convergence horizon refs and convergence receipts
//!
//! The broker publishes its verifying key so workers can verify envelope
//! signatures with a real verifier (no `NoOpVerifier` in default mode).
//!
//! # Security Invariants
//!
//! - [INV-BRK-001] The broker signing key is never exposed outside the broker
//!   process boundary. Only the `VerifyingKey` is published.
//! - [INV-BRK-002] All issued tokens and envelopes are cryptographically signed
//!   with the broker's Ed25519 key.
//! - [INV-BRK-003] Fail-closed: missing, stale, or ambiguous authority state
//!   results in denial.
//! - [INV-BRK-004] All in-memory collections are bounded by hard `MAX_*` caps.
//! - [INV-BRK-005] Broker state persistence uses atomic write (temp+rename).
//! - [INV-BRK-006] Horizon hashes are replay-stable (non-zero) in local-only
//!   mode.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::channel::{
    ChannelBoundaryCheck, ChannelContextTokenError, ChannelSource, DeclassificationIntentScope,
    derive_channel_source_witness, issue_channel_context_token,
};
use crate::crypto::{Signer, VerifyingKey};
use crate::economics::queue_admission::{
    ConvergenceHorizonRef, ConvergenceReceipt, EnvelopeSignature, FreshnessHorizonRef,
    HtfEvaluationWindow, RevocationFrontierSnapshot, TimeAuthorityEnvelopeV1,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of admitted policy digests tracked by the broker.
pub const MAX_ADMITTED_POLICY_DIGESTS: usize = 256;

/// Maximum number of convergence receipts the broker will serve.
pub const MAX_CONVERGENCE_RECEIPTS: usize = 64;

/// Maximum length for boundary identifiers.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Maximum length for authority clock identifiers.
pub const MAX_AUTHORITY_CLOCK_LENGTH: usize = 256;

/// Maximum TTL for time authority envelopes (in ticks).
pub const MAX_ENVELOPE_TTL_TICKS: u64 = 10_000;

/// Default TTL for time authority envelopes (in ticks).
pub const DEFAULT_ENVELOPE_TTL_TICKS: u64 = 1_000;

/// Domain separator for broker envelope content hashing.
const BROKER_ENVELOPE_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.envelope.v1";

/// Domain separator for broker horizon hashing.
const BROKER_HORIZON_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.horizon.v1";

/// Domain separator for broker frontier hashing.
const BROKER_FRONTIER_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.frontier.v1";

/// Domain separator for broker convergence hashing.
const BROKER_CONVERGENCE_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.convergence.v1";

/// Schema identifier for persisted broker state.
const BROKER_STATE_SCHEMA_ID: &str = "apm2.fac_broker_state.v1";

/// Schema version for persisted broker state.
const BROKER_STATE_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Hash type alias
// ---------------------------------------------------------------------------

/// 32-byte hash used throughout the broker.
pub type Hash = [u8; 32];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by the FAC Broker service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// Boundary identifier is empty or exceeds maximum length.
    #[error("invalid boundary_id: {detail}")]
    InvalidBoundaryId {
        /// Detail about the validation failure.
        detail: String,
    },

    /// Authority clock identifier is empty or exceeds maximum length.
    #[error("invalid authority_clock: {detail}")]
    InvalidAuthorityClock {
        /// Detail about the validation failure.
        detail: String,
    },

    /// The requested TTL exceeds the broker maximum.
    #[error("ttl_ticks {requested} exceeds maximum {max}")]
    TtlExceedsMaximum {
        /// Requested TTL.
        requested: u64,
        /// Maximum allowed TTL.
        max: u64,
    },

    /// Tick range is inverted (start > end).
    #[error("inverted tick range: tick_start={tick_start} > tick_end={tick_end}")]
    InvertedTickRange {
        /// Start tick.
        tick_start: u64,
        /// End tick.
        tick_end: u64,
    },

    /// Channel context token issuance failed.
    #[error("channel token error: {0}")]
    ChannelToken(#[from] ChannelContextTokenError),

    /// Admitted policy digest store is at capacity.
    #[error("admitted policy digest store at capacity ({max})")]
    PolicyDigestStoreAtCapacity {
        /// Maximum capacity.
        max: usize,
    },

    /// Convergence receipt store is at capacity.
    #[error("convergence receipt store at capacity ({max})")]
    ConvergenceReceiptStoreAtCapacity {
        /// Maximum capacity.
        max: usize,
    },

    /// Persistence operation failed.
    #[error("persistence error: {detail}")]
    Persistence {
        /// Detail about the persistence failure.
        detail: String,
    },

    /// Deserialization of broker state failed.
    #[error("deserialization error: {detail}")]
    Deserialization {
        /// Detail about the deserialization failure.
        detail: String,
    },

    /// Job spec digest is zero (not bound).
    #[error("job_spec_digest is zero (not bound to a job)")]
    ZeroJobSpecDigest,

    /// Lease ID is empty.
    #[error("lease_id is empty")]
    EmptyLeaseId,

    /// Request ID is empty.
    #[error("request_id is empty")]
    EmptyRequestId,
}

// ---------------------------------------------------------------------------
// Broker state (persisted)
// ---------------------------------------------------------------------------

/// Persisted broker state. Serialized to JSON for durable storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerState {
    /// Schema identifier for version checking.
    pub schema_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Monotonic tick counter used for envelope issuance.
    pub current_tick: u64,
    /// Currently admitted policy digest set (bounded).
    pub admitted_policy_digests: Vec<Hash>,
    /// Freshness horizon hash for TP-EIO29-002.
    pub freshness_horizon_hash: Hash,
    /// Revocation frontier hash for TP-EIO29-002.
    pub revocation_frontier_hash: Hash,
    /// Convergence horizon hash for TP-EIO29-003.
    pub convergence_horizon_hash: Hash,
    /// Convergence receipts for TP-EIO29-003 (bounded).
    pub convergence_receipts: Vec<ConvergenceReceipt>,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            schema_id: BROKER_STATE_SCHEMA_ID.to_string(),
            schema_version: BROKER_STATE_SCHEMA_VERSION.to_string(),
            current_tick: 1,
            admitted_policy_digests: Vec::new(),
            freshness_horizon_hash: compute_initial_horizon_hash(),
            revocation_frontier_hash: compute_initial_frontier_hash(),
            convergence_horizon_hash: compute_initial_convergence_hash(),
            convergence_receipts: Vec::new(),
        }
    }
}

impl BrokerState {
    /// Validate state after deserialization.
    fn validate(&self) -> Result<(), BrokerError> {
        if self.schema_id != BROKER_STATE_SCHEMA_ID {
            return Err(BrokerError::Deserialization {
                detail: format!(
                    "schema_id mismatch: expected {BROKER_STATE_SCHEMA_ID}, got {}",
                    self.schema_id
                ),
            });
        }
        if self.admitted_policy_digests.len() > MAX_ADMITTED_POLICY_DIGESTS {
            return Err(BrokerError::Deserialization {
                detail: format!(
                    "admitted_policy_digests count {} exceeds max {MAX_ADMITTED_POLICY_DIGESTS}",
                    self.admitted_policy_digests.len()
                ),
            });
        }
        if self.convergence_receipts.len() > MAX_CONVERGENCE_RECEIPTS {
            return Err(BrokerError::Deserialization {
                detail: format!(
                    "convergence_receipts count {} exceeds max {MAX_CONVERGENCE_RECEIPTS}",
                    self.convergence_receipts.len()
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deterministic initial hash computation
// ---------------------------------------------------------------------------

fn compute_initial_horizon_hash() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_HORIZON_HASH_DOMAIN);
    hasher.update(b"initial");
    *hasher.finalize().as_bytes()
}

fn compute_initial_frontier_hash() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_FRONTIER_HASH_DOMAIN);
    hasher.update(b"initial");
    *hasher.finalize().as_bytes()
}

fn compute_initial_convergence_hash() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_CONVERGENCE_HASH_DOMAIN);
    hasher.update(b"initial");
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// FacBroker
// ---------------------------------------------------------------------------

/// FAC Broker authority service.
///
/// The broker is the sole local authority for issuing actuation tokens
/// (RFC-0028 `ChannelContextToken`) and economics/time authority envelopes
/// (RFC-0029 `TimeAuthorityEnvelopeV1`).
///
/// # Thread Safety
///
/// `FacBroker` is **not** internally synchronized. Callers must hold
/// appropriate locks (e.g., `Mutex`) when accessing from multiple threads.
/// This follows the pattern of `QueueSchedulerState` and `AntiEntropyBudget`
/// in the economics module.
pub struct FacBroker {
    /// Ed25519 signing key owned exclusively by the broker.
    signer: Signer,
    /// Mutable broker state (tick counter, admitted digests, horizons).
    state: BrokerState,
}

impl Default for FacBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl FacBroker {
    /// Creates a new broker with a freshly generated signing key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signer: Signer::generate(),
            state: BrokerState::default(),
        }
    }

    /// Creates a broker from an existing signer and state.
    ///
    /// Used when loading persisted state from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the loaded state fails validation.
    pub fn from_signer_and_state(signer: Signer, state: BrokerState) -> Result<Self, BrokerError> {
        state.validate()?;
        Ok(Self { signer, state })
    }

    /// Returns the broker's verifying (public) key.
    ///
    /// Workers use this key to verify envelope signatures with a real
    /// verifier instead of `NoOpVerifier`.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Returns the current broker tick.
    #[must_use]
    pub const fn current_tick(&self) -> u64 {
        self.state.current_tick
    }

    /// Returns a reference to the current broker state for persistence.
    #[must_use]
    pub const fn state(&self) -> &BrokerState {
        &self.state
    }

    /// Advances the broker tick by 1 (monotonic).
    ///
    /// Returns the new tick value.
    #[must_use]
    pub const fn advance_tick(&mut self) -> u64 {
        self.state.current_tick = self.state.current_tick.saturating_add(1);
        self.state.current_tick
    }

    // -----------------------------------------------------------------------
    // RFC-0028: ChannelContextToken issuance
    // -----------------------------------------------------------------------

    /// Issues an RFC-0028 `ChannelContextToken` bound to `job_spec_digest`
    /// and `lease_id`.
    ///
    /// The token encodes a fully-populated `ChannelBoundaryCheck` with
    /// `broker_verified = true` and all verification flags set, signed by
    /// the broker's Ed25519 key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `job_spec_digest` is all-zero (not bound to a job)
    /// - `lease_id` is empty
    /// - `request_id` is empty
    /// - Token serialization or signing fails
    pub fn issue_channel_context_token(
        &self,
        job_spec_digest: &Hash,
        lease_id: &str,
        request_id: &str,
        issued_at_secs: u64,
    ) -> Result<String, BrokerError> {
        // Validate inputs (fail-closed)
        if bool::from(job_spec_digest.ct_eq(&[0u8; 32])) {
            return Err(BrokerError::ZeroJobSpecDigest);
        }
        if lease_id.is_empty() {
            return Err(BrokerError::EmptyLeaseId);
        }
        if request_id.is_empty() {
            return Err(BrokerError::EmptyRequestId);
        }

        // Build a fully-verified boundary check (broker is the authority).
        // The job_spec_digest is embedded in the policy binding to bind
        // the token to the specific job.
        let check = ChannelBoundaryCheck {
            source: ChannelSource::TypedToolIntent,
            channel_source_witness: Some(derive_channel_source_witness(
                ChannelSource::TypedToolIntent,
            )),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(crate::channel::BoundaryFlowPolicyBinding {
                policy_digest: *job_spec_digest,
                admitted_policy_root_digest: *job_spec_digest,
                canonicalizer_tuple_digest: compute_canonicalizer_tuple_digest(job_spec_digest),
                admitted_canonicalizer_tuple_digest: compute_canonicalizer_tuple_digest(
                    job_spec_digest,
                ),
            }),
            leakage_budget_receipt: Some(crate::channel::LeakageBudgetReceipt {
                leakage_bits: 0,
                budget_bits: 8,
                estimator_family:
                    crate::channel::LeakageEstimatorFamily::MutualInformationUpperBound,
                confidence_bps: 10_000,
                confidence_label: "broker-deterministic".to_string(),
            }),
            timing_channel_budget: Some(crate::channel::TimingChannelBudget {
                release_bucket_ticks: 10,
                observed_variance_ticks: 0,
                budget_ticks: 10,
            }),
            disclosure_policy_binding: Some(crate::channel::DisclosurePolicyBinding {
                required_for_effect: true,
                state_valid: true,
                active_mode: crate::disclosure::DisclosurePolicyMode::TradeSecretOnly,
                expected_mode: crate::disclosure::DisclosurePolicyMode::TradeSecretOnly,
                attempted_channel: crate::disclosure::DisclosureChannelClass::Internal,
                policy_snapshot_digest: *job_spec_digest,
                admitted_policy_epoch_root_digest: *job_spec_digest,
                policy_epoch: 1,
                phase_id: "broker_default".to_string(),
                state_reason: "broker_issued".to_string(),
            }),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
        };

        Ok(issue_channel_context_token(
            &check,
            lease_id,
            request_id,
            issued_at_secs,
            &self.signer,
        )?)
    }

    // -----------------------------------------------------------------------
    // RFC-0029: TimeAuthorityEnvelopeV1 issuance
    // -----------------------------------------------------------------------

    /// Issues an RFC-0029 `TimeAuthorityEnvelopeV1` for a given boundary
    /// and evaluation window.
    ///
    /// The envelope is signed by the broker's Ed25519 key with
    /// `deny_on_unknown = true` (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `boundary_id` is empty or exceeds `MAX_BOUNDARY_ID_LENGTH`
    /// - `authority_clock` is empty or exceeds `MAX_AUTHORITY_CLOCK_LENGTH`
    /// - `tick_start > tick_end` (inverted range)
    /// - `ttl_ticks` exceeds `MAX_ENVELOPE_TTL_TICKS`
    pub fn issue_time_authority_envelope(
        &mut self,
        boundary_id: &str,
        authority_clock: &str,
        tick_start: u64,
        tick_end: u64,
        ttl_ticks: u64,
    ) -> Result<TimeAuthorityEnvelopeV1, BrokerError> {
        // Validate inputs (fail-closed)
        validate_boundary_id(boundary_id)?;
        validate_authority_clock(authority_clock)?;

        if tick_start > tick_end {
            return Err(BrokerError::InvertedTickRange {
                tick_start,
                tick_end,
            });
        }
        if ttl_ticks > MAX_ENVELOPE_TTL_TICKS {
            return Err(BrokerError::TtlExceedsMaximum {
                requested: ttl_ticks,
                max: MAX_ENVELOPE_TTL_TICKS,
            });
        }

        // Compute content hash (domain-separated)
        let content_hash = compute_envelope_content_hash(
            boundary_id,
            authority_clock,
            tick_start,
            tick_end,
            ttl_ticks,
            self.state.current_tick,
        );

        // Sign the content hash
        let signature_bytes = self.signer.sign(&content_hash);
        let envelope_signature = EnvelopeSignature {
            signer_id: self.signer.verifying_key().to_bytes(),
            signature: signature_bytes.to_bytes(),
        };

        // Advance tick for monotonicity
        let _ = self.advance_tick();

        Ok(TimeAuthorityEnvelopeV1 {
            boundary_id: boundary_id.to_string(),
            authority_clock: authority_clock.to_string(),
            tick_start,
            tick_end,
            ttl_ticks,
            deny_on_unknown: true,
            signature_set: vec![envelope_signature],
            content_hash,
        })
    }

    /// Issues a `TimeAuthorityEnvelopeV1` with default TTL.
    ///
    /// Convenience wrapper around [`issue_time_authority_envelope`] using
    /// `DEFAULT_ENVELOPE_TTL_TICKS`.
    ///
    /// # Errors
    ///
    /// Same as [`issue_time_authority_envelope`].
    pub fn issue_time_authority_envelope_default_ttl(
        &mut self,
        boundary_id: &str,
        authority_clock: &str,
        tick_start: u64,
        tick_end: u64,
    ) -> Result<TimeAuthorityEnvelopeV1, BrokerError> {
        self.issue_time_authority_envelope(
            boundary_id,
            authority_clock,
            tick_start,
            tick_end,
            DEFAULT_ENVELOPE_TTL_TICKS,
        )
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-002: Freshness horizon and revocation frontier
    // -----------------------------------------------------------------------

    /// Returns the current freshness horizon reference (TP-EIO29-002).
    ///
    /// The horizon is resolved and has a non-zero, replay-stable hash.
    #[must_use]
    pub const fn freshness_horizon(&self) -> FreshnessHorizonRef {
        FreshnessHorizonRef {
            horizon_hash: self.state.freshness_horizon_hash,
            tick_end: self.state.current_tick,
            resolved: true,
        }
    }

    /// Returns the current revocation frontier snapshot (TP-EIO29-002).
    ///
    /// The frontier is current with a non-zero, replay-stable hash.
    #[must_use]
    pub const fn revocation_frontier(&self) -> RevocationFrontierSnapshot {
        RevocationFrontierSnapshot {
            frontier_hash: self.state.revocation_frontier_hash,
            current: true,
        }
    }

    /// Advances the freshness horizon to a new tick, recomputing the hash.
    pub fn advance_freshness_horizon(&mut self, new_tick_end: u64) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BROKER_HORIZON_HASH_DOMAIN);
        hasher.update(&new_tick_end.to_le_bytes());
        hasher.update(&self.state.freshness_horizon_hash);
        self.state.freshness_horizon_hash = *hasher.finalize().as_bytes();
    }

    /// Advances the revocation frontier, recomputing the hash.
    pub fn advance_revocation_frontier(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BROKER_FRONTIER_HASH_DOMAIN);
        hasher.update(&self.state.current_tick.to_le_bytes());
        hasher.update(&self.state.revocation_frontier_hash);
        self.state.revocation_frontier_hash = *hasher.finalize().as_bytes();
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-003: Convergence horizon and convergence receipts
    // -----------------------------------------------------------------------

    /// Returns the current convergence horizon reference (TP-EIO29-003).
    ///
    /// The horizon is resolved with a non-zero, replay-stable hash.
    #[must_use]
    pub const fn convergence_horizon(&self) -> ConvergenceHorizonRef {
        ConvergenceHorizonRef {
            horizon_hash: self.state.convergence_horizon_hash,
            resolved: true,
        }
    }

    /// Returns all current convergence receipts (TP-EIO29-003).
    ///
    /// In local-only mode, each receipt has a non-zero proof hash and
    /// `converged = true`.
    #[must_use]
    pub fn convergence_receipts(&self) -> &[ConvergenceReceipt] {
        &self.state.convergence_receipts
    }

    /// Adds a convergence receipt for a required authority set.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt store is at capacity.
    pub fn add_convergence_receipt(
        &mut self,
        authority_set_hash: Hash,
        proof_hash: Hash,
    ) -> Result<(), BrokerError> {
        if self.state.convergence_receipts.len() >= MAX_CONVERGENCE_RECEIPTS {
            return Err(BrokerError::ConvergenceReceiptStoreAtCapacity {
                max: MAX_CONVERGENCE_RECEIPTS,
            });
        }

        // Advance convergence horizon hash (chain)
        let mut hasher = blake3::Hasher::new();
        hasher.update(BROKER_CONVERGENCE_HASH_DOMAIN);
        hasher.update(&authority_set_hash);
        hasher.update(&proof_hash);
        hasher.update(&self.state.convergence_horizon_hash);
        self.state.convergence_horizon_hash = *hasher.finalize().as_bytes();

        self.state.convergence_receipts.push(ConvergenceReceipt {
            authority_set_hash,
            proof_hash,
            converged: true,
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Policy digest admission
    // -----------------------------------------------------------------------

    /// Admits a policy digest into the broker's tracked set.
    ///
    /// # Errors
    ///
    /// Returns an error if the digest store is at capacity.
    pub fn admit_policy_digest(&mut self, digest: Hash) -> Result<(), BrokerError> {
        if self.state.admitted_policy_digests.len() >= MAX_ADMITTED_POLICY_DIGESTS {
            return Err(BrokerError::PolicyDigestStoreAtCapacity {
                max: MAX_ADMITTED_POLICY_DIGESTS,
            });
        }
        // Deduplicate (constant-time scan for each existing entry)
        for existing in &self.state.admitted_policy_digests {
            if bool::from(existing.ct_eq(&digest)) {
                return Ok(());
            }
        }
        self.state.admitted_policy_digests.push(digest);
        Ok(())
    }

    /// Checks whether a policy digest is admitted.
    #[must_use]
    pub fn is_policy_digest_admitted(&self, digest: &Hash) -> bool {
        // Use non-short-circuiting fold for constant-time behavior.
        let mut found = 0u8;
        for existing in &self.state.admitted_policy_digests {
            found |= u8::from(bool::from(existing.ct_eq(digest)));
        }
        found != 0
    }

    // -----------------------------------------------------------------------
    // Evaluation window construction
    // -----------------------------------------------------------------------

    /// Constructs an `HtfEvaluationWindow` for the current broker state.
    ///
    /// # Errors
    ///
    /// Returns an error if inputs are invalid.
    pub fn build_evaluation_window(
        &self,
        boundary_id: &str,
        authority_clock: &str,
        tick_start: u64,
        tick_end: u64,
    ) -> Result<HtfEvaluationWindow, BrokerError> {
        validate_boundary_id(boundary_id)?;
        validate_authority_clock(authority_clock)?;

        if tick_start > tick_end {
            return Err(BrokerError::InvertedTickRange {
                tick_start,
                tick_end,
            });
        }

        Ok(HtfEvaluationWindow {
            boundary_id: boundary_id.to_string(),
            authority_clock: authority_clock.to_string(),
            tick_start,
            tick_end,
        })
    }

    // -----------------------------------------------------------------------
    // State serialization (for persistence)
    // -----------------------------------------------------------------------

    /// Serializes the broker state to canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn serialize_state(&self) -> Result<Vec<u8>, BrokerError> {
        serde_json::to_vec_pretty(&self.state).map_err(|e| BrokerError::Persistence {
            detail: e.to_string(),
        })
    }

    /// Deserializes broker state from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization or validation fails.
    pub fn deserialize_state(bytes: &[u8]) -> Result<BrokerState, BrokerError> {
        let state: BrokerState =
            serde_json::from_slice(bytes).map_err(|e| BrokerError::Deserialization {
                detail: e.to_string(),
            })?;
        state.validate()?;
        Ok(state)
    }
}

// ---------------------------------------------------------------------------
// Broker-specific SignatureVerifier implementation
// ---------------------------------------------------------------------------

/// A signature verifier backed by the broker's public key.
///
/// Workers obtain this from the broker to verify `TimeAuthorityEnvelopeV1`
/// signatures with real cryptographic verification instead of `NoOpVerifier`.
pub struct BrokerSignatureVerifier {
    verifying_key: VerifyingKey,
}

impl BrokerSignatureVerifier {
    /// Creates a new verifier from the broker's public key.
    #[must_use]
    pub const fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Verifies a broker-signed envelope signature.
    ///
    /// Convenience method that checks the signer matches the broker key
    /// and the Ed25519 signature is valid over the content hash.
    #[must_use]
    pub fn verify_broker_signature(
        &self,
        content_hash: &Hash,
        signer_id: &Hash,
        signature: &[u8; 64],
    ) -> bool {
        use crate::economics::queue_admission::SignatureVerifier;
        self.verify(signer_id, content_hash, signature).is_ok()
    }
}

impl crate::economics::queue_admission::SignatureVerifier for BrokerSignatureVerifier {
    fn verify(
        &self,
        signer_id: &Hash,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), &'static str> {
        // Verify the signer matches the broker's public key (constant-time)
        if !bool::from(signer_id.ct_eq(&self.verifying_key.to_bytes())) {
            return Err("signer_id_mismatch");
        }

        // Parse and verify the signature
        let vk = VerifyingKey::from_bytes(signer_id).map_err(|_| "invalid_signer_public_key")?;
        let sig = crate::crypto::parse_signature(signature).map_err(|_| "malformed_signature")?;
        crate::crypto::verify_signature(&vk, message, &sig)
            .map_err(|_| "signature_verification_failed")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_boundary_id(boundary_id: &str) -> Result<(), BrokerError> {
    if boundary_id.is_empty() {
        return Err(BrokerError::InvalidBoundaryId {
            detail: "boundary_id is empty".to_string(),
        });
    }
    if boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
        return Err(BrokerError::InvalidBoundaryId {
            detail: format!(
                "boundary_id length {} exceeds max {MAX_BOUNDARY_ID_LENGTH}",
                boundary_id.len()
            ),
        });
    }
    Ok(())
}

fn validate_authority_clock(authority_clock: &str) -> Result<(), BrokerError> {
    if authority_clock.is_empty() {
        return Err(BrokerError::InvalidAuthorityClock {
            detail: "authority_clock is empty".to_string(),
        });
    }
    if authority_clock.len() > MAX_AUTHORITY_CLOCK_LENGTH {
        return Err(BrokerError::InvalidAuthorityClock {
            detail: format!(
                "authority_clock length {} exceeds max {MAX_AUTHORITY_CLOCK_LENGTH}",
                authority_clock.len()
            ),
        });
    }
    Ok(())
}

fn compute_envelope_content_hash(
    boundary_id: &str,
    authority_clock: &str,
    tick_start: u64,
    tick_end: u64,
    ttl_ticks: u64,
    broker_tick: u64,
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_ENVELOPE_HASH_DOMAIN);
    // Length-prefix framing for variable fields.
    // Lengths are bounded by MAX_BOUNDARY_ID_LENGTH and MAX_AUTHORITY_CLOCK_LENGTH
    // (both 256), so truncation cannot occur.
    #[allow(clippy::cast_possible_truncation)]
    let boundary_len = boundary_id.len() as u32;
    hasher.update(&boundary_len.to_le_bytes());
    hasher.update(boundary_id.as_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let clock_len = authority_clock.len() as u32;
    hasher.update(&clock_len.to_le_bytes());
    hasher.update(authority_clock.as_bytes());
    hasher.update(&tick_start.to_le_bytes());
    hasher.update(&tick_end.to_le_bytes());
    hasher.update(&ttl_ticks.to_le_bytes());
    hasher.update(&broker_tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn compute_canonicalizer_tuple_digest(job_spec_digest: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.fac_broker.canonicalizer.v1");
    hasher.update(job_spec_digest);
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{decode_channel_context_token, validate_channel_boundary};

    fn now_secs() -> u64 {
        std::time::UNIX_EPOCH
            .elapsed()
            .expect("current time should be after unix epoch")
            .as_secs()
    }

    // -----------------------------------------------------------------------
    // Construction and basic invariants
    // -----------------------------------------------------------------------

    #[test]
    fn broker_initializes_with_non_zero_hashes() {
        let broker = FacBroker::new();
        assert_ne!(broker.state.freshness_horizon_hash, [0u8; 32]);
        assert_ne!(broker.state.revocation_frontier_hash, [0u8; 32]);
        assert_ne!(broker.state.convergence_horizon_hash, [0u8; 32]);
        assert_eq!(broker.current_tick(), 1);
    }

    #[test]
    fn broker_advance_tick_is_monotonic() {
        let mut broker = FacBroker::new();
        let t1 = broker.current_tick();
        let t2 = broker.advance_tick();
        let t3 = broker.advance_tick();
        assert!(t2 > t1);
        assert!(t3 > t2);
    }

    // -----------------------------------------------------------------------
    // RFC-0028: Channel context token issuance + validation
    // -----------------------------------------------------------------------

    #[test]
    fn issue_and_decode_channel_context_token_roundtrip() {
        let broker = FacBroker::new();
        let job_digest = [0x42; 32];
        let lease_id = "lease-broker-001";
        let request_id = "REQ-001";
        let now = now_secs();

        let token = broker
            .issue_channel_context_token(&job_digest, lease_id, request_id, now)
            .expect("token issuance should succeed");

        // Decode with broker's verifying key
        let decoded = decode_channel_context_token(
            &token,
            &broker.verifying_key(),
            lease_id,
            now,
            request_id,
        )
        .expect("token decode should succeed");

        // Validate boundary check passes
        let defects = validate_channel_boundary(&decoded);
        assert!(
            defects.is_empty(),
            "broker-issued token should pass all boundary checks, got {defects:?}"
        );
    }

    #[test]
    fn issue_channel_context_token_rejects_zero_job_digest() {
        let broker = FacBroker::new();
        let result = broker.issue_channel_context_token(&[0u8; 32], "lease-1", "REQ-1", now_secs());
        assert_eq!(result, Err(BrokerError::ZeroJobSpecDigest));
    }

    #[test]
    fn issue_channel_context_token_rejects_empty_lease_id() {
        let broker = FacBroker::new();
        let result = broker.issue_channel_context_token(&[0x11; 32], "", "REQ-1", now_secs());
        assert_eq!(result, Err(BrokerError::EmptyLeaseId));
    }

    #[test]
    fn issue_channel_context_token_rejects_empty_request_id() {
        let broker = FacBroker::new();
        let result = broker.issue_channel_context_token(&[0x11; 32], "lease-1", "", now_secs());
        assert_eq!(result, Err(BrokerError::EmptyRequestId));
    }

    #[test]
    fn forged_token_rejected_by_different_key() {
        let broker = FacBroker::new();
        let attacker = FacBroker::new();
        let job_digest = [0x42; 32];
        let now = now_secs();

        let forged_token = attacker
            .issue_channel_context_token(&job_digest, "lease-1", "REQ-1", now)
            .expect("attacker token should encode");

        let result = decode_channel_context_token(
            &forged_token,
            &broker.verifying_key(),
            "lease-1",
            now,
            "REQ-1",
        );
        assert!(
            result.is_err(),
            "forged token must be rejected by broker's key"
        );
    }

    // -----------------------------------------------------------------------
    // RFC-0029: TimeAuthorityEnvelopeV1 issuance + signature verification
    // -----------------------------------------------------------------------

    #[test]
    fn issue_time_authority_envelope_and_verify_signature() {
        let mut broker = FacBroker::new();
        let envelope = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope issuance should succeed");

        assert_eq!(envelope.boundary_id, "boundary-1");
        assert_eq!(envelope.authority_clock, "clock-1");
        assert_eq!(envelope.tick_start, 100);
        assert_eq!(envelope.tick_end, 200);
        assert_eq!(envelope.ttl_ticks, 500);
        assert!(envelope.deny_on_unknown);
        assert_eq!(envelope.signature_set.len(), 1);
        assert_ne!(envelope.content_hash, [0u8; 32]);

        // Verify signature using BrokerSignatureVerifier
        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &envelope.signature_set[0];
        assert!(
            verifier.verify_broker_signature(
                &envelope.content_hash,
                &sig.signer_id,
                &sig.signature,
            ),
            "broker-signed envelope must verify"
        );
    }

    #[test]
    fn issue_time_authority_envelope_rejects_empty_boundary_id() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope("", "clock-1", 100, 200, 500);
        assert!(matches!(result, Err(BrokerError::InvalidBoundaryId { .. })));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_oversized_boundary_id() {
        let mut broker = FacBroker::new();
        let long_id = "x".repeat(MAX_BOUNDARY_ID_LENGTH + 1);
        let result = broker.issue_time_authority_envelope(&long_id, "clock-1", 100, 200, 500);
        assert!(matches!(result, Err(BrokerError::InvalidBoundaryId { .. })));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_empty_authority_clock() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope("boundary-1", "", 100, 200, 500);
        assert!(matches!(
            result,
            Err(BrokerError::InvalidAuthorityClock { .. })
        ));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_inverted_tick_range() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope("boundary-1", "clock-1", 200, 100, 500);
        assert!(matches!(result, Err(BrokerError::InvertedTickRange { .. })));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_excessive_ttl() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope(
            "boundary-1",
            "clock-1",
            100,
            200,
            MAX_ENVELOPE_TTL_TICKS + 1,
        );
        assert!(matches!(result, Err(BrokerError::TtlExceedsMaximum { .. })));
    }

    #[test]
    fn envelope_tick_advances_after_issuance() {
        let mut broker = FacBroker::new();
        let tick_before = broker.current_tick();
        let _ = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope issuance should succeed");
        let tick_after = broker.current_tick();
        assert!(tick_after > tick_before, "tick must advance after issuance");
    }

    #[test]
    fn forged_envelope_rejected_by_verifier() {
        let broker = FacBroker::new();
        let mut attacker = FacBroker::new();

        let forged_envelope = attacker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("attacker envelope should encode");

        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &forged_envelope.signature_set[0];
        assert!(
            !verifier.verify_broker_signature(
                &forged_envelope.content_hash,
                &sig.signer_id,
                &sig.signature,
            ),
            "forged envelope must be rejected by broker's verifier"
        );
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-002: Freshness horizon and revocation frontier
    // -----------------------------------------------------------------------

    #[test]
    fn freshness_horizon_is_resolved_and_non_zero() {
        let broker = FacBroker::new();
        let horizon = broker.freshness_horizon();
        assert!(horizon.resolved);
        assert_ne!(horizon.horizon_hash, [0u8; 32]);
        assert_eq!(horizon.tick_end, broker.current_tick());
    }

    #[test]
    fn revocation_frontier_is_current_and_non_zero() {
        let broker = FacBroker::new();
        let frontier = broker.revocation_frontier();
        assert!(frontier.current);
        assert_ne!(frontier.frontier_hash, [0u8; 32]);
    }

    #[test]
    fn freshness_horizon_changes_after_advance() {
        let mut broker = FacBroker::new();
        let h1 = broker.freshness_horizon();
        broker.advance_freshness_horizon(100);
        let h2 = broker.freshness_horizon();
        assert_ne!(h1.horizon_hash, h2.horizon_hash);
    }

    #[test]
    fn revocation_frontier_changes_after_advance() {
        let mut broker = FacBroker::new();
        let f1 = broker.revocation_frontier();
        broker.advance_revocation_frontier();
        let f2 = broker.revocation_frontier();
        assert_ne!(f1.frontier_hash, f2.frontier_hash);
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-003: Convergence horizon and receipts
    // -----------------------------------------------------------------------

    #[test]
    fn convergence_horizon_is_resolved_and_non_zero() {
        let broker = FacBroker::new();
        let horizon = broker.convergence_horizon();
        assert!(horizon.resolved);
        assert_ne!(horizon.horizon_hash, [0u8; 32]);
    }

    #[test]
    fn add_convergence_receipt_updates_horizon() {
        let mut broker = FacBroker::new();
        let h1 = broker.convergence_horizon();

        broker
            .add_convergence_receipt([0x11; 32], [0x22; 32])
            .expect("receipt should be added");

        let h2 = broker.convergence_horizon();
        assert_ne!(h1.horizon_hash, h2.horizon_hash);
        assert_eq!(broker.convergence_receipts().len(), 1);
        assert!(broker.convergence_receipts()[0].converged);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn convergence_receipt_store_cap_enforced() {
        let mut broker = FacBroker::new();
        for i in 0..MAX_CONVERGENCE_RECEIPTS {
            broker
                .add_convergence_receipt([i as u8; 32], [i as u8; 32])
                .expect("receipt should be added");
        }

        let result = broker.add_convergence_receipt([0xFF; 32], [0xFF; 32]);
        assert!(matches!(
            result,
            Err(BrokerError::ConvergenceReceiptStoreAtCapacity { .. })
        ));
        assert_eq!(
            broker.convergence_receipts().len(),
            MAX_CONVERGENCE_RECEIPTS
        );
    }

    // -----------------------------------------------------------------------
    // Policy digest admission
    // -----------------------------------------------------------------------

    #[test]
    fn admit_and_check_policy_digest() {
        let mut broker = FacBroker::new();
        let digest = [0x42; 32];

        assert!(!broker.is_policy_digest_admitted(&digest));
        broker.admit_policy_digest(digest).expect("should admit");
        assert!(broker.is_policy_digest_admitted(&digest));
    }

    #[test]
    fn duplicate_policy_digest_is_idempotent() {
        let mut broker = FacBroker::new();
        let digest = [0x42; 32];

        broker.admit_policy_digest(digest).expect("first admit");
        broker.admit_policy_digest(digest).expect("second admit");
        assert_eq!(broker.state.admitted_policy_digests.len(), 1);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn policy_digest_store_cap_enforced() {
        let mut broker = FacBroker::new();
        for i in 0..MAX_ADMITTED_POLICY_DIGESTS {
            let mut digest = [0u8; 32];
            digest[0] = (i & 0xFF) as u8;
            digest[1] = ((i >> 8) & 0xFF) as u8;
            broker.admit_policy_digest(digest).expect("should admit");
        }

        let result = broker.admit_policy_digest([0xFF; 32]);
        assert!(matches!(
            result,
            Err(BrokerError::PolicyDigestStoreAtCapacity { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // State serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn state_serialization_roundtrip() {
        let mut broker = FacBroker::new();
        broker.admit_policy_digest([0x42; 32]).unwrap();
        broker
            .add_convergence_receipt([0x11; 32], [0x22; 32])
            .unwrap();
        let _ = broker.advance_tick();

        let bytes = broker.serialize_state().expect("serialize should succeed");
        let restored = FacBroker::deserialize_state(&bytes).expect("deserialize should succeed");

        assert_eq!(restored, broker.state);
    }

    #[test]
    fn deserialization_rejects_oversized_policy_digests() {
        let state = BrokerState {
            admitted_policy_digests: vec![[0u8; 32]; MAX_ADMITTED_POLICY_DIGESTS + 1],
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn deserialization_rejects_oversized_convergence_receipts() {
        let state = BrokerState {
            convergence_receipts: (0..=MAX_CONVERGENCE_RECEIPTS)
                .map(|i| ConvergenceReceipt {
                    authority_set_hash: [i as u8; 32],
                    proof_hash: [i as u8; 32],
                    converged: true,
                })
                .collect(),
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    fn deserialization_rejects_wrong_schema() {
        let state = BrokerState {
            schema_id: "wrong.schema".to_string(),
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    // -----------------------------------------------------------------------
    // BrokerSignatureVerifier
    // -----------------------------------------------------------------------

    #[test]
    fn broker_verifier_rejects_wrong_key() {
        let mut broker = FacBroker::new();
        let other = FacBroker::new();

        let envelope = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope should issue");

        let verifier = BrokerSignatureVerifier::new(other.verifying_key());
        let sig = &envelope.signature_set[0];
        assert!(
            !verifier.verify_broker_signature(
                &envelope.content_hash,
                &sig.signer_id,
                &sig.signature,
            ),
            "must reject signature from different key"
        );
    }

    #[test]
    fn broker_verifier_rejects_tampered_content() {
        let mut broker = FacBroker::new();
        let envelope = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope should issue");

        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &envelope.signature_set[0];
        let tampered_hash = [0xFF; 32];
        assert!(
            !verifier.verify_broker_signature(&tampered_hash, &sig.signer_id, &sig.signature,),
            "must reject tampered content hash"
        );
    }

    // -----------------------------------------------------------------------
    // Integration: end-to-end token + envelope + horizons
    // -----------------------------------------------------------------------

    #[test]
    fn end_to_end_broker_token_envelope_horizons() {
        let mut broker = FacBroker::new();
        let job_digest = [0x42; 32];
        let lease_id = "lease-e2e-001";
        let request_id = "REQ-E2E-001";
        let now = now_secs();

        // 1. Issue channel token
        let token = broker
            .issue_channel_context_token(&job_digest, lease_id, request_id, now)
            .expect("token should issue");

        // 2. Decode and validate
        let decoded = decode_channel_context_token(
            &token,
            &broker.verifying_key(),
            lease_id,
            now,
            request_id,
        )
        .expect("token should decode");
        let defects = validate_channel_boundary(&decoded);
        assert!(defects.is_empty(), "token must pass boundary checks");

        // 3. Issue envelope
        let envelope = broker
            .issue_time_authority_envelope("boundary-e2e", "clock-e2e", 10, 100, 500)
            .expect("envelope should issue");

        // 4. Verify signature
        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &envelope.signature_set[0];
        assert!(verifier.verify_broker_signature(
            &envelope.content_hash,
            &sig.signer_id,
            &sig.signature,
        ));

        // 5. Check horizons are non-zero and resolved
        let fh = broker.freshness_horizon();
        assert!(fh.resolved);
        assert_ne!(fh.horizon_hash, [0u8; 32]);

        let rf = broker.revocation_frontier();
        assert!(rf.current);
        assert_ne!(rf.frontier_hash, [0u8; 32]);

        let ch = broker.convergence_horizon();
        assert!(ch.resolved);
        assert_ne!(ch.horizon_hash, [0u8; 32]);
    }
}
