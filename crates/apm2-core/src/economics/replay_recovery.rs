// AGENT-AUTHORED
//! Replay-recovery bounds and idempotency closure for RFC-0029 REQ-0005.
//!
//! Implements:
//! - [`ReplayConvergenceReceiptV1`] and [`RecoveryAdmissibilityReceiptV1`] with
//!   signed temporal bindings (`time_authority_ref`, `window_ref`).
//! - TP-EIO29-004 (`replay_convergence_horizon_satisfied`) enforcement.
//! - TP-EIO29-007 (`replay_idempotency_monotone`) enforcement.
//! - Dedup closure for authoritative effects under retry/restart and
//!   partition/rejoin.
//! - Structured deny defects for unresolved effect identity and stale replay
//!   receipts.
//!
//! # Security Domain
//!
//! `DOMAIN_SECURITY` is in scope. All unknown, missing, stale, or unverifiable
//! replay/recovery states fail closed.
//!
//! # Temporal Model
//!
//! All receipts carry `time_authority_ref` and `window_ref` hashes binding them
//! to HTF evaluation windows. Receipts are Ed25519-signed with domain
//! separation to prevent cross-protocol replay.
//!
//! # Idempotency Closure
//!
//! TP-EIO29-007 enforces that authoritative effects admitted in adjacent
//! windows do not duplicate: revoked effects must be absent from the later
//! window, and no effect identity may appear in both windows unless explicitly
//! re-admitted. Unknown or unresolved effect identity always denies.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::crypto::{Hash, Signer, SignerError, parse_signature, parse_verifying_key};
use crate::fac::{sign_with_domain, verify_with_domain};
use crate::pcac::temporal_arbitration::TemporalPredicateId;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of replay convergence receipts per evaluation.
pub const MAX_REPLAY_RECEIPTS: usize = 256;

/// Maximum number of effect identity digests per idempotency check.
pub const MAX_EFFECT_IDENTITIES: usize = 4_096;

/// Maximum number of revoked effect digests per window.
pub const MAX_REVOKED_EFFECTS: usize = 4_096;

/// Maximum string length for receipt identifiers.
pub const MAX_RECEIPT_ID_LENGTH: usize = 256;

/// Maximum string length for boundary identifiers.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Maximum string length for actor identifiers.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum string length for deny reason codes.
pub const MAX_DENY_REASON_LENGTH: usize = 256;

/// Domain prefix for replay convergence receipt signing.
///
/// Domain separation ensures that a signature for a replay convergence
/// receipt cannot be replayed as another receipt type.
pub const REPLAY_CONVERGENCE_RECEIPT_PREFIX: &[u8] = b"REPLAY_CONVERGENCE_RECEIPT:";

/// Domain prefix for recovery admissibility receipt signing.
pub const RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX: &[u8] = b"RECOVERY_ADMISSIBILITY_RECEIPT:";

const ZERO_HASH: Hash = [0u8; 32];

// ============================================================================
// Deny reason constants (stable strings for replay verification)
// ============================================================================

/// Deny: replay convergence receipt is missing.
pub const DENY_REPLAY_RECEIPT_MISSING: &str = "replay_convergence_receipt_missing";
/// Deny: replay convergence receipt has zero content hash.
pub const DENY_REPLAY_RECEIPT_HASH_ZERO: &str = "replay_convergence_receipt_hash_zero";
/// Deny: replay convergence horizon reference is unresolved.
pub const DENY_REPLAY_HORIZON_UNRESOLVED: &str = "replay_convergence_horizon_unresolved";
/// Deny: backlog remains unresolved after replay horizon end.
pub const DENY_BACKLOG_UNRESOLVED: &str = "replay_backlog_unresolved_after_horizon";
/// Deny: replay receipt signature is invalid.
pub const DENY_REPLAY_RECEIPT_SIGNATURE_INVALID: &str =
    "replay_convergence_receipt_signature_invalid";
/// Deny: replay receipt window reference is zero/missing.
pub const DENY_REPLAY_RECEIPT_WINDOW_ZERO: &str = "replay_convergence_receipt_window_ref_zero";
/// Deny: replay receipt time authority reference is zero/missing.
pub const DENY_REPLAY_RECEIPT_TIME_AUTH_ZERO: &str =
    "replay_convergence_receipt_time_authority_ref_zero";
/// Deny: replay receipt signer key is zero.
pub const DENY_REPLAY_RECEIPT_SIGNER_ZERO: &str = "replay_convergence_receipt_signer_key_zero";
/// Deny: replay receipt ID is empty or oversized.
pub const DENY_REPLAY_RECEIPT_ID_INVALID: &str = "replay_convergence_receipt_id_invalid";
/// Deny: replay receipt boundary mismatch.
pub const DENY_REPLAY_RECEIPT_BOUNDARY_MISMATCH: &str =
    "replay_convergence_receipt_boundary_mismatch";
/// Deny: recovery admissibility receipt is missing.
pub const DENY_RECOVERY_RECEIPT_MISSING: &str = "recovery_admissibility_receipt_missing";
/// Deny: recovery admissibility receipt hash is zero.
pub const DENY_RECOVERY_RECEIPT_HASH_ZERO: &str = "recovery_admissibility_receipt_hash_zero";
/// Deny: recovery admissibility receipt signature is invalid.
pub const DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID: &str =
    "recovery_admissibility_receipt_signature_invalid";
/// Deny: recovery admissibility receipt window reference is zero.
pub const DENY_RECOVERY_RECEIPT_WINDOW_ZERO: &str =
    "recovery_admissibility_receipt_window_ref_zero";
/// Deny: recovery admissibility receipt time authority reference is zero.
pub const DENY_RECOVERY_RECEIPT_TIME_AUTH_ZERO: &str =
    "recovery_admissibility_receipt_time_authority_ref_zero";
/// Deny: recovery admissibility receipt signer key is zero.
pub const DENY_RECOVERY_RECEIPT_SIGNER_ZERO: &str =
    "recovery_admissibility_receipt_signer_key_zero";
/// Deny: recovery admissibility receipt ID is invalid.
pub const DENY_RECOVERY_RECEIPT_ID_INVALID: &str = "recovery_admissibility_receipt_id_invalid";
/// Deny: adjacent windows are not actually adjacent.
pub const DENY_WINDOWS_NOT_ADJACENT: &str = "idempotency_windows_not_adjacent";
/// Deny: revoked effect found in later window.
pub const DENY_REVOKED_EFFECT_IN_LATER_WINDOW: &str = "idempotency_revoked_effect_in_later_window";
/// Deny: duplicate authoritative effect across windows.
pub const DENY_DUPLICATE_AUTHORITATIVE_EFFECT: &str = "idempotency_duplicate_authoritative_effect";
/// Deny: unresolved effect identity.
pub const DENY_UNRESOLVED_EFFECT_IDENTITY: &str = "idempotency_unresolved_effect_identity";
/// Deny: effect identity digest is zero.
pub const DENY_EFFECT_IDENTITY_ZERO: &str = "idempotency_effect_identity_zero";
/// Deny: replay receipt exceeds maximum count.
pub const DENY_REPLAY_RECEIPTS_EXCEEDED: &str = "replay_convergence_receipts_exceeded";
/// Deny: effect set exceeds maximum count.
pub const DENY_EFFECT_SET_EXCEEDED: &str = "idempotency_effect_set_exceeded";
/// Deny: revoked set exceeds maximum count.
pub const DENY_REVOKED_SET_EXCEEDED: &str = "idempotency_revoked_set_exceeded";
/// Deny: stale replay receipt (window does not match evaluation context).
pub const DENY_STALE_REPLAY_RECEIPT: &str = "replay_convergence_receipt_stale";
/// Deny: unknown temporal state.
pub const DENY_UNKNOWN_TEMPORAL_STATE: &str = "replay_recovery_unknown_temporal_state";

// ============================================================================
// Error types
// ============================================================================

/// Errors from replay-recovery receipt operations.
#[derive(Debug, Error)]
pub enum ReplayRecoveryError {
    /// Receipt field validation failed.
    #[error("receipt validation: {reason}")]
    ValidationFailed {
        /// Human-readable description.
        reason: String,
    },
    /// Signature creation or verification failed.
    #[error("signature error: {detail}")]
    SignatureError {
        /// Details of the signature failure.
        detail: String,
    },
    /// A required field is missing or empty.
    #[error("required field missing: {field}")]
    RequiredFieldMissing {
        /// Name of the missing field.
        field: String,
    },
    /// A field value exceeds its maximum allowed length.
    #[error("field '{field}' exceeds maximum length ({actual} > {max})")]
    FieldTooLong {
        /// Name of the violating field.
        field: String,
        /// Actual length observed.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A hash field is zero.
    #[error("field '{field}' must not be zero")]
    ZeroHash {
        /// Name of the violating field.
        field: String,
    },
    /// Collection exceeds capacity.
    #[error("collection '{collection}' exceeds capacity ({count} > {max})")]
    CollectionExceeded {
        /// Collection name.
        collection: String,
        /// Current count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// ============================================================================
// ReplayConvergenceReceiptV1
// ============================================================================

/// Durable, signed receipt proving bounded idempotent convergence of a replay
/// within an HTF window.
///
/// Implements `ReplayConvergenceReceiptV1` from RFC-0029 REQ-0005.
/// Each receipt is domain-separated and Ed25519-signed, binding a replay
/// convergence outcome to a specific time authority and evaluation window.
///
/// # Fields
///
/// - `receipt_id`: unique identifier for this receipt instance.
/// - `boundary_id`: boundary context (must match evaluation window).
/// - `backlog_digest`: digest of the backlog state at convergence.
/// - `replay_horizon_tick`: tick marking the replay convergence horizon.
/// - `converged`: whether replay converged within the horizon.
/// - `time_authority_ref`: hash of the time authority envelope.
/// - `window_ref`: hash of the HTF evaluation window.
/// - `content_hash`: content-addressed hash of the receipt payload.
/// - `signer_actor_id`: identity of the signing actor.
/// - `signer_key`: Ed25519 public key bytes.
/// - `signature`: Ed25519 signature over domain-separated canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConvergenceReceiptV1 {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Boundary identifier (must match evaluation context).
    pub boundary_id: String,
    /// Digest of the backlog state at convergence evaluation.
    pub backlog_digest: Hash,
    /// Tick marking the end of the replay convergence horizon.
    pub replay_horizon_tick: u64,
    /// Whether replay converged idempotently within the horizon.
    pub converged: bool,
    /// Time authority reference hash (HTF binding).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Content-addressed hash of the receipt payload.
    pub content_hash: Hash,
    /// Identity of the signing actor.
    pub signer_actor_id: String,
    /// Ed25519 public key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over domain-separated canonical bytes (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl ReplayConvergenceReceiptV1 {
    /// Creates and signs a replay convergence receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        receipt_id: impl Into<String>,
        boundary_id: impl Into<String>,
        backlog_digest: Hash,
        replay_horizon_tick: u64,
        converged: bool,
        time_authority_ref: Hash,
        window_ref: Hash,
        content_hash: Hash,
        signer_actor_id: impl Into<String>,
        signer: &Signer,
    ) -> Result<Self, ReplayRecoveryError> {
        let receipt_id = receipt_id.into();
        let boundary_id = boundary_id.into();
        let signer_actor_id = signer_actor_id.into();

        validate_required_string("receipt_id", &receipt_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("boundary_id", &boundary_id, MAX_BOUNDARY_ID_LENGTH)?;
        validate_required_string("signer_actor_id", &signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("backlog_digest", &backlog_digest)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash("content_hash", &content_hash)?;

        let mut receipt = Self {
            receipt_id,
            boundary_id,
            backlog_digest,
            replay_horizon_tick,
            converged,
            time_authority_ref,
            window_ref,
            content_hash,
            signer_actor_id,
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let sig = sign_with_domain(
            signer,
            REPLAY_CONVERGENCE_RECEIPT_PREFIX,
            &receipt.canonical_bytes(),
        );
        receipt.signature = sig.to_bytes();
        Ok(receipt)
    }

    /// Returns canonical bytes for signing/verification.
    ///
    /// Format: length-prefixed strings + fixed-size fields, all big-endian.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        bytes.extend_from_slice(&self.backlog_digest);
        bytes.extend_from_slice(&self.replay_horizon_tick.to_be_bytes());
        bytes.push(u8::from(self.converged));
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.content_hash);

        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the receipt's Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(&self) -> Result<(), ReplayRecoveryError> {
        if self.signer_key == [0u8; 32] {
            return Err(ReplayRecoveryError::SignatureError {
                detail: DENY_REPLAY_RECEIPT_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            REPLAY_CONVERGENCE_RECEIPT_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(|e: SignerError| ReplayRecoveryError::SignatureError {
            detail: e.to_string(),
        })
    }

    /// Validates structural invariants without verifying the signature.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.receipt_id.is_empty() || self.receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(DENY_REPLAY_RECEIPT_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_REPLAY_RECEIPT_ID_INVALID);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_REPLAY_RECEIPT_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_REPLAY_RECEIPT_WINDOW_ZERO);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_REPLAY_RECEIPT_HASH_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_REPLAY_RECEIPT_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_REPLAY_RECEIPT_SIGNATURE_INVALID);
        }
        Ok(())
    }
}

// ============================================================================
// RecoveryAdmissibilityReceiptV1
// ============================================================================

/// Durable, signed receipt proving recovery admissibility for a partial-loss
/// rebuild within an HTF window.
///
/// Implements `RecoveryAdmissibilityReceiptV1` from RFC-0029 REQ-0005.
/// Each receipt is domain-separated and Ed25519-signed, binding a recovery
/// admissibility decision to specific time authority and evaluation window.
///
/// # Fields
///
/// - `receipt_id`: unique identifier for this receipt instance.
/// - `boundary_id`: boundary context.
/// - `recovery_scope_digest`: digest of the recovery scope (partial-loss
///   rebuild boundary).
/// - `admitted`: whether recovery is admissible within the window.
/// - `time_authority_ref`: hash of the time authority envelope.
/// - `window_ref`: hash of the HTF evaluation window.
/// - `content_hash`: content-addressed hash of the receipt payload.
/// - `signer_actor_id`: identity of the signing actor.
/// - `signer_key`: Ed25519 public key bytes.
/// - `signature`: Ed25519 signature over domain-separated canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAdmissibilityReceiptV1 {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Boundary identifier.
    pub boundary_id: String,
    /// Digest of the recovery scope.
    pub recovery_scope_digest: Hash,
    /// Whether recovery is admissible within the window.
    pub admitted: bool,
    /// Time authority reference hash (HTF binding).
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Content-addressed hash of the receipt payload.
    pub content_hash: Hash,
    /// Identity of the signing actor.
    pub signer_actor_id: String,
    /// Ed25519 public key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over domain-separated canonical bytes (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl RecoveryAdmissibilityReceiptV1 {
    /// Creates and signs a recovery admissibility receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if any field fails validation or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        receipt_id: impl Into<String>,
        boundary_id: impl Into<String>,
        recovery_scope_digest: Hash,
        admitted: bool,
        time_authority_ref: Hash,
        window_ref: Hash,
        content_hash: Hash,
        signer_actor_id: impl Into<String>,
        signer: &Signer,
    ) -> Result<Self, ReplayRecoveryError> {
        let receipt_id = receipt_id.into();
        let boundary_id = boundary_id.into();
        let signer_actor_id = signer_actor_id.into();

        validate_required_string("receipt_id", &receipt_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("boundary_id", &boundary_id, MAX_BOUNDARY_ID_LENGTH)?;
        validate_required_string("signer_actor_id", &signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("recovery_scope_digest", &recovery_scope_digest)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash("content_hash", &content_hash)?;

        let mut receipt = Self {
            receipt_id,
            boundary_id,
            recovery_scope_digest,
            admitted,
            time_authority_ref,
            window_ref,
            content_hash,
            signer_actor_id,
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let sig = sign_with_domain(
            signer,
            RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX,
            &receipt.canonical_bytes(),
        );
        receipt.signature = sig.to_bytes();
        Ok(receipt)
    }

    /// Returns canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        bytes.extend_from_slice(&self.recovery_scope_digest);
        bytes.push(u8::from(self.admitted));
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.content_hash);

        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the receipt's Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_signature(&self) -> Result<(), ReplayRecoveryError> {
        if self.signer_key == [0u8; 32] {
            return Err(ReplayRecoveryError::SignatureError {
                detail: DENY_RECOVERY_RECEIPT_SIGNER_ZERO.to_string(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        let sig = parse_signature(&self.signature).map_err(|e: SignerError| {
            ReplayRecoveryError::SignatureError {
                detail: e.to_string(),
            }
        })?;

        verify_with_domain(
            &key,
            RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX,
            &self.canonical_bytes(),
            &sig,
        )
        .map_err(|e: SignerError| ReplayRecoveryError::SignatureError {
            detail: e.to_string(),
        })
    }

    /// Validates structural invariants without verifying the signature.
    ///
    /// # Errors
    ///
    /// Returns a stable deny reason for any structural violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.receipt_id.is_empty() || self.receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(DENY_RECOVERY_RECEIPT_ID_INVALID);
        }
        if self.boundary_id.is_empty() || self.boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(DENY_RECOVERY_RECEIPT_ID_INVALID);
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err(DENY_RECOVERY_RECEIPT_TIME_AUTH_ZERO);
        }
        if is_zero_hash(&self.window_ref) {
            return Err(DENY_RECOVERY_RECEIPT_WINDOW_ZERO);
        }
        if is_zero_hash(&self.content_hash) {
            return Err(DENY_RECOVERY_RECEIPT_HASH_ZERO);
        }
        if self.signer_key == [0u8; 32] {
            return Err(DENY_RECOVERY_RECEIPT_SIGNER_ZERO);
        }
        if self.signature.ct_eq(&[0u8; 64]).unwrap_u8() == 1 {
            return Err(DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID);
        }
        Ok(())
    }
}

// ============================================================================
// TP-EIO29-004: replay_convergence_horizon_satisfied
// ============================================================================

/// Replay convergence horizon reference for TP-EIO29-004 evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConvergenceHorizonRef {
    /// Whether the horizon reference is resolved.
    pub resolved: bool,
    /// End tick of the replay convergence horizon.
    pub horizon_end_tick: u64,
    /// Hash binding of the horizon reference.
    pub horizon_digest: Hash,
}

/// Backlog state snapshot for TP-EIO29-004 evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacklogState {
    /// Whether the backlog is fully resolved.
    pub resolved: bool,
    /// Digest of the backlog state.
    pub backlog_digest: Hash,
    /// Current tick of the backlog evaluation.
    pub current_tick: u64,
}

/// Deny defect emitted when a replay-recovery admission check fails.
///
/// Provides auditable structured evidence for why an admission was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRecoveryDenyDefect {
    /// Stable deny reason code.
    pub reason: String,
    /// The temporal predicate that was violated.
    pub predicate_id: TemporalPredicateId,
    /// Boundary context of the denial.
    pub boundary_id: String,
    /// Tick at which the denial occurred.
    pub denied_at_tick: u64,
    /// Hash of the time authority envelope (if available).
    pub envelope_hash: Hash,
    /// Window reference hash (if available).
    pub window_ref: Hash,
}

/// Validates TP-EIO29-004: replay convergence horizon satisfied.
///
/// Checks that:
/// 1. The replay convergence horizon reference is present and resolved.
/// 2. Replay receipts are present and within bounds.
/// 3. The backlog state is resolved.
/// 4. All receipts have valid structural form.
/// 5. All receipts match the evaluation boundary.
/// 6. The backlog converged idempotently within the horizon.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation. All unknown
/// or missing states fail closed.
pub fn validate_replay_convergence_tp004(
    horizon: Option<&ReplayConvergenceHorizonRef>,
    backlog: Option<&BacklogState>,
    receipts: &[ReplayConvergenceReceiptV1],
    eval_boundary_id: &str,
) -> Result<(), &'static str> {
    // Fail-closed: missing horizon reference.
    let horizon = horizon.ok_or(DENY_REPLAY_HORIZON_UNRESOLVED)?;

    if !horizon.resolved {
        return Err(DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    if is_zero_hash(&horizon.horizon_digest) {
        return Err(DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    // Fail-closed: missing backlog state.
    let backlog = backlog.ok_or(DENY_BACKLOG_UNRESOLVED)?;

    if !backlog.resolved {
        return Err(DENY_BACKLOG_UNRESOLVED);
    }

    if is_zero_hash(&backlog.backlog_digest) {
        return Err(DENY_BACKLOG_UNRESOLVED);
    }

    // Bounded receipt count.
    if receipts.len() > MAX_REPLAY_RECEIPTS {
        return Err(DENY_REPLAY_RECEIPTS_EXCEEDED);
    }

    // Fail-closed: at least one receipt must be present.
    if receipts.is_empty() {
        return Err(DENY_REPLAY_RECEIPT_MISSING);
    }

    // Validate each receipt structurally and check boundary match.
    for receipt in receipts {
        receipt.validate()?;

        if receipt.boundary_id != eval_boundary_id {
            return Err(DENY_REPLAY_RECEIPT_BOUNDARY_MISMATCH);
        }

        // Receipt must be within the replay horizon.
        if receipt.replay_horizon_tick > horizon.horizon_end_tick {
            return Err(DENY_STALE_REPLAY_RECEIPT);
        }

        // Receipt must have converged.
        if !receipt.converged {
            return Err(DENY_BACKLOG_UNRESOLVED);
        }
    }

    Ok(())
}

// ============================================================================
// TP-EIO29-007: replay_idempotency_monotone
// ============================================================================

/// Adjacent-window pair for TP-EIO29-007 evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjacentWindowPair {
    /// Earlier window tick range.
    pub w_t_start: u64,
    /// Earlier window tick end.
    pub w_t_end: u64,
    /// Later window tick range.
    pub w_t1_start: u64,
    /// Later window tick end.
    pub w_t1_end: u64,
}

impl AdjacentWindowPair {
    /// Checks whether the two windows are adjacent.
    ///
    /// Windows are adjacent if the later window starts exactly one tick after
    /// the earlier window ends (no gap, no overlap).
    #[must_use]
    pub const fn is_adjacent(&self) -> bool {
        // Guard: earlier window must end before later window starts.
        if self.w_t_end >= self.w_t1_start {
            return false;
        }
        // Adjacent: gap of exactly 1 tick.
        self.w_t1_start == self.w_t_end.saturating_add(1)
    }
}

/// Validates TP-EIO29-007: replay idempotency monotone.
///
/// Checks that:
/// 1. Windows are adjacent.
/// 2. No revoked effect is present in the later window.
/// 3. No authoritative effect in the earlier window appears in the later window
///    (dedup closure).
/// 4. All effect identity digests are non-zero.
///
/// # Errors
///
/// Returns a stable deny reason string for any violation. Unresolved
/// effect identities and unknown state fail closed.
pub fn validate_replay_idempotency_tp007(
    windows: &AdjacentWindowPair,
    effects_t: &[Hash],
    effects_t1: &[Hash],
    revoked_t1: &[Hash],
) -> Result<(), &'static str> {
    // Bounded input validation.
    if effects_t.len() > MAX_EFFECT_IDENTITIES {
        return Err(DENY_EFFECT_SET_EXCEEDED);
    }
    if effects_t1.len() > MAX_EFFECT_IDENTITIES {
        return Err(DENY_EFFECT_SET_EXCEEDED);
    }
    if revoked_t1.len() > MAX_REVOKED_EFFECTS {
        return Err(DENY_REVOKED_SET_EXCEEDED);
    }

    // Adjacency check.
    if !windows.is_adjacent() {
        return Err(DENY_WINDOWS_NOT_ADJACENT);
    }

    // Validate all effect identity digests are non-zero.
    for effect in effects_t {
        if is_zero_hash(effect) {
            return Err(DENY_EFFECT_IDENTITY_ZERO);
        }
    }
    for effect in effects_t1 {
        if is_zero_hash(effect) {
            return Err(DENY_EFFECT_IDENTITY_ZERO);
        }
    }
    for effect in revoked_t1 {
        if is_zero_hash(effect) {
            return Err(DENY_EFFECT_IDENTITY_ZERO);
        }
    }

    // TP-EIO29-007 clause: forall e in Rev_t1, e notin E_t1
    // Revoked effects must not appear in the later window.
    for revoked in revoked_t1 {
        for effect in effects_t1 {
            if revoked.ct_eq(effect).unwrap_u8() == 1 {
                return Err(DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
            }
        }
    }

    // TP-EIO29-007 clause: no duplicate authoritative effects across windows.
    // effects_in_later_window_do_not_duplicate_authoritative_outcome(E_t, E_t1)
    for e_earlier in effects_t {
        for e_later in effects_t1 {
            if e_earlier.ct_eq(e_later).unwrap_u8() == 1 {
                return Err(DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
            }
        }
    }

    Ok(())
}

// ============================================================================
// Combined evaluation
// ============================================================================

/// Verdict for a replay-recovery admission evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayRecoveryVerdict {
    /// Admission allowed.
    Allow,
    /// Admission denied with structured defect.
    Deny,
}

/// Decision from a replay-recovery admission evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRecoveryDecision {
    /// Verdict of the admission evaluation.
    pub verdict: ReplayRecoveryVerdict,
    /// Deny defect (present when verdict is `Deny`).
    pub defect: Option<ReplayRecoveryDenyDefect>,
    /// Temporal predicate results: (`predicate_id`, passed).
    pub predicate_results: Vec<(TemporalPredicateId, bool)>,
}

impl ReplayRecoveryDecision {
    /// Creates an allow decision with predicate results.
    #[must_use]
    const fn allow(predicate_results: Vec<(TemporalPredicateId, bool)>) -> Self {
        Self {
            verdict: ReplayRecoveryVerdict::Allow,
            defect: None,
            predicate_results,
        }
    }

    /// Creates a deny decision with a structured defect.
    #[must_use]
    fn deny(
        reason: &str,
        predicate_id: TemporalPredicateId,
        boundary_id: &str,
        denied_at_tick: u64,
        envelope_hash: Hash,
        window_ref: Hash,
        predicate_results: Vec<(TemporalPredicateId, bool)>,
    ) -> Self {
        Self {
            verdict: ReplayRecoveryVerdict::Deny,
            defect: Some(ReplayRecoveryDenyDefect {
                reason: reason.to_string(),
                predicate_id,
                boundary_id: boundary_id.to_string(),
                denied_at_tick,
                envelope_hash,
                window_ref,
            }),
            predicate_results,
        }
    }
}

/// Evaluates replay-recovery admission for a given evaluation context.
///
/// This is the top-level evaluator that checks TP-EIO29-004 (replay
/// convergence) and optionally TP-EIO29-007 (idempotency monotone) if
/// adjacent-window data is provided.
///
/// # Arguments
///
/// - `horizon`: replay convergence horizon reference.
/// - `backlog`: current backlog state.
/// - `receipts`: replay convergence receipts.
/// - `eval_boundary_id`: boundary identifier for this evaluation.
/// - `eval_tick`: current tick for deny defect reporting.
/// - `envelope_hash`: time authority envelope hash for defect reporting.
/// - `window_ref_hash`: window reference hash for defect reporting.
/// - `idempotency`: optional adjacent-window idempotency check data.
///
/// # Returns
///
/// A [`ReplayRecoveryDecision`] with verdict and structured defect.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_replay_recovery(
    horizon: Option<&ReplayConvergenceHorizonRef>,
    backlog: Option<&BacklogState>,
    receipts: &[ReplayConvergenceReceiptV1],
    eval_boundary_id: &str,
    eval_tick: u64,
    envelope_hash: Hash,
    window_ref_hash: Hash,
    idempotency: Option<&IdempotencyCheckInput>,
) -> ReplayRecoveryDecision {
    let mut predicate_results = Vec::new();

    // TP-EIO29-004: replay convergence horizon satisfied.
    let tp004_result =
        validate_replay_convergence_tp004(horizon, backlog, receipts, eval_boundary_id);
    let tp004_passed = tp004_result.is_ok();
    predicate_results.push((TemporalPredicateId::TpEio29004, tp004_passed));

    if let Err(reason) = tp004_result {
        return ReplayRecoveryDecision::deny(
            reason,
            TemporalPredicateId::TpEio29004,
            eval_boundary_id,
            eval_tick,
            envelope_hash,
            window_ref_hash,
            predicate_results,
        );
    }

    // TP-EIO29-007: replay idempotency monotone (only if provided).
    if let Some(idem) = idempotency {
        let tp007_result = validate_replay_idempotency_tp007(
            &idem.windows,
            &idem.effects_t,
            &idem.effects_t1,
            &idem.revoked_t1,
        );
        let tp007_passed = tp007_result.is_ok();
        predicate_results.push((TemporalPredicateId::TpEio29007, tp007_passed));

        if let Err(reason) = tp007_result {
            return ReplayRecoveryDecision::deny(
                reason,
                TemporalPredicateId::TpEio29007,
                eval_boundary_id,
                eval_tick,
                envelope_hash,
                window_ref_hash,
                predicate_results,
            );
        }
    }

    ReplayRecoveryDecision::allow(predicate_results)
}

/// Input data for the TP-EIO29-007 idempotency check.
#[derive(Debug, Clone)]
pub struct IdempotencyCheckInput {
    /// Adjacent window pair.
    pub windows: AdjacentWindowPair,
    /// Admitted effect digests from the earlier window.
    pub effects_t: Vec<Hash>,
    /// Admitted effect digests from the later window.
    pub effects_t1: Vec<Hash>,
    /// Revoked effect digests in the later window.
    pub revoked_t1: Vec<Hash>,
}

// ============================================================================
// Validation helpers
// ============================================================================

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.ct_eq(&ZERO_HASH).unwrap_u8() == 1
}

fn validate_required_string(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), ReplayRecoveryError> {
    if value.is_empty() {
        return Err(ReplayRecoveryError::RequiredFieldMissing {
            field: field.to_string(),
        });
    }
    if value.len() > max_len {
        return Err(ReplayRecoveryError::FieldTooLong {
            field: field.to_string(),
            actual: value.len(),
            max: max_len,
        });
    }
    Ok(())
}

fn validate_non_zero_hash(field: &str, hash: &Hash) -> Result<(), ReplayRecoveryError> {
    if is_zero_hash(hash) {
        return Err(ReplayRecoveryError::ZeroHash {
            field: field.to_string(),
        });
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn test_hash(val: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = val;
        h[31] = val;
        h
    }

    fn valid_signer() -> Signer {
        Signer::generate()
    }

    fn valid_replay_receipt(signer: &Signer) -> ReplayConvergenceReceiptV1 {
        ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            test_hash(0xAA),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid receipt")
    }

    fn valid_recovery_receipt(signer: &Signer) -> RecoveryAdmissibilityReceiptV1 {
        RecoveryAdmissibilityReceiptV1::create_signed(
            "rcpt-002",
            "boundary-1",
            test_hash(0xAA),
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            signer,
        )
        .expect("valid receipt")
    }

    fn valid_horizon() -> ReplayConvergenceHorizonRef {
        ReplayConvergenceHorizonRef {
            resolved: true,
            horizon_end_tick: 2000,
            horizon_digest: test_hash(0xEE),
        }
    }

    fn valid_backlog() -> BacklogState {
        BacklogState {
            resolved: true,
            backlog_digest: test_hash(0xFF),
            current_tick: 500,
        }
    }

    // ========================================================================
    // ReplayConvergenceReceiptV1 — creation and signing
    // ========================================================================

    #[test]
    fn replay_receipt_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        assert!(receipt.verify_signature().is_ok());
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.receipt_id, "rcpt-001");
        assert_eq!(receipt.boundary_id, "boundary-1");
        assert!(receipt.converged);
    }

    #[test]
    fn replay_receipt_deterministic_signature() {
        let signer = valid_signer();
        let r1 = valid_replay_receipt(&signer);
        let r2 = valid_replay_receipt(&signer);
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn replay_receipt_wrong_key_fails_verification() {
        let signer1 = valid_signer();
        let signer2 = valid_signer();
        let receipt = valid_replay_receipt(&signer1);

        let mut tampered = receipt;
        tampered.signer_key = signer2.public_key_bytes();
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn replay_receipt_tampered_data_fails_verification() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.boundary_id = "tampered".to_string();
        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn replay_receipt_zero_signer_key_denied() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.signer_key = [0u8; 32];
        assert!(receipt.verify_signature().is_err());
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_REPLAY_RECEIPT_SIGNER_ZERO
        );
    }

    #[test]
    fn replay_receipt_zero_signature_denied() {
        let signer = valid_signer();
        let mut receipt = valid_replay_receipt(&signer);
        receipt.signature = [0u8; 64];
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_REPLAY_RECEIPT_SIGNATURE_INVALID
        );
    }

    #[test]
    fn replay_receipt_empty_receipt_id_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "",
            "boundary-1",
            test_hash(0xAA),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_oversized_receipt_id_denied() {
        let signer = valid_signer();
        let big_id = "x".repeat(MAX_RECEIPT_ID_LENGTH + 1);
        let result = ReplayConvergenceReceiptV1::create_signed(
            big_id,
            "boundary-1",
            test_hash(0xAA),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_time_authority_ref_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            test_hash(0xAA),
            1000,
            true,
            [0u8; 32], // zero time_authority_ref
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_window_ref_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            test_hash(0xAA),
            1000,
            true,
            test_hash(0xBB),
            [0u8; 32], // zero window_ref
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_content_hash_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            test_hash(0xAA),
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            [0u8; 32], // zero content_hash
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_zero_backlog_digest_denied() {
        let signer = valid_signer();
        let result = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-001",
            "boundary-1",
            [0u8; 32], // zero backlog_digest
            1000,
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn replay_receipt_serde_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: ReplayConvergenceReceiptV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, decoded);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn replay_receipt_domain_separation_prevents_cross_type_replay() {
        let signer = valid_signer();
        let replay_receipt = valid_replay_receipt(&signer);

        // Try to verify with recovery receipt domain — should fail.
        let key = parse_verifying_key(&replay_receipt.signer_key).unwrap();
        let sig = parse_signature(&replay_receipt.signature).unwrap();
        let result = verify_with_domain(
            &key,
            RECOVERY_ADMISSIBILITY_RECEIPT_PREFIX,
            &replay_receipt.canonical_bytes(),
            &sig,
        );
        assert!(result.is_err());
    }

    // ========================================================================
    // RecoveryAdmissibilityReceiptV1 — creation and signing
    // ========================================================================

    #[test]
    fn recovery_receipt_create_and_sign_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_recovery_receipt(&signer);
        assert!(receipt.verify_signature().is_ok());
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.receipt_id, "rcpt-002");
        assert!(receipt.admitted);
    }

    #[test]
    fn recovery_receipt_deterministic_signature() {
        let signer = valid_signer();
        let r1 = valid_recovery_receipt(&signer);
        let r2 = valid_recovery_receipt(&signer);
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn recovery_receipt_wrong_key_fails_verification() {
        let signer1 = valid_signer();
        let signer2 = valid_signer();
        let receipt = valid_recovery_receipt(&signer1);
        let mut tampered = receipt;
        tampered.signer_key = signer2.public_key_bytes();
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn recovery_receipt_tampered_data_fails_verification() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.boundary_id = "tampered".to_string();
        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn recovery_receipt_zero_signer_key_denied() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.signer_key = [0u8; 32];
        assert!(receipt.verify_signature().is_err());
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECOVERY_RECEIPT_SIGNER_ZERO
        );
    }

    #[test]
    fn recovery_receipt_zero_signature_denied() {
        let signer = valid_signer();
        let mut receipt = valid_recovery_receipt(&signer);
        receipt.signature = [0u8; 64];
        assert_eq!(
            receipt.validate().unwrap_err(),
            DENY_RECOVERY_RECEIPT_SIGNATURE_INVALID
        );
    }

    #[test]
    fn recovery_receipt_serde_roundtrip() {
        let signer = valid_signer();
        let receipt = valid_recovery_receipt(&signer);
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: RecoveryAdmissibilityReceiptV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, decoded);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn recovery_receipt_domain_separation_prevents_cross_type_replay() {
        let signer = valid_signer();
        let recovery_receipt = valid_recovery_receipt(&signer);

        // Try to verify with replay receipt domain — should fail.
        let key = parse_verifying_key(&recovery_receipt.signer_key).unwrap();
        let sig = parse_signature(&recovery_receipt.signature).unwrap();
        let result = verify_with_domain(
            &key,
            REPLAY_CONVERGENCE_RECEIPT_PREFIX,
            &recovery_receipt.canonical_bytes(),
            &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn recovery_receipt_empty_receipt_id_denied() {
        let signer = valid_signer();
        let result = RecoveryAdmissibilityReceiptV1::create_signed(
            "",
            "boundary-1",
            test_hash(0xAA),
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    #[test]
    fn recovery_receipt_zero_time_authority_ref_denied() {
        let signer = valid_signer();
        let result = RecoveryAdmissibilityReceiptV1::create_signed(
            "rcpt-002",
            "boundary-1",
            test_hash(0xAA),
            true,
            [0u8; 32],
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        );
        assert!(result.is_err());
    }

    // ========================================================================
    // TP-EIO29-004: replay convergence horizon satisfied
    // ========================================================================

    #[test]
    fn tp004_valid_inputs_pass() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp004_missing_horizon_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let result = validate_replay_convergence_tp004(
            None,
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp004_unresolved_horizon_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let mut horizon = valid_horizon();
        horizon.resolved = false;
        let result = validate_replay_convergence_tp004(
            Some(&horizon),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp004_zero_horizon_digest_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let mut horizon = valid_horizon();
        horizon.horizon_digest = [0u8; 32];
        let result = validate_replay_convergence_tp004(
            Some(&horizon),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_HORIZON_UNRESOLVED);
    }

    #[test]
    fn tp004_missing_backlog_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            None,
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_unresolved_backlog_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let mut backlog = valid_backlog();
        backlog.resolved = false;
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&backlog),
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_zero_backlog_digest_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let mut backlog = valid_backlog();
        backlog.backlog_digest = [0u8; 32];
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&backlog),
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_empty_receipts_denies() {
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_MISSING);
    }

    #[test]
    fn tp004_receipt_boundary_mismatch_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "wrong-boundary",
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPT_BOUNDARY_MISMATCH);
    }

    #[test]
    fn tp004_receipt_beyond_horizon_denies() {
        let signer = valid_signer();
        let receipt = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-stale",
            "boundary-1",
            test_hash(0xAA),
            3000, // beyond horizon_end_tick=2000
            true,
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .unwrap();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_STALE_REPLAY_RECEIPT);
    }

    #[test]
    fn tp004_non_converged_receipt_denies() {
        let signer = valid_signer();
        let receipt = ReplayConvergenceReceiptV1::create_signed(
            "rcpt-nc",
            "boundary-1",
            test_hash(0xAA),
            1000,
            false, // not converged
            test_hash(0xBB),
            test_hash(0xCC),
            test_hash(0xDD),
            "actor-1",
            &signer,
        )
        .unwrap();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_BACKLOG_UNRESOLVED);
    }

    #[test]
    fn tp004_exceeds_max_receipts_denies() {
        let signer = valid_signer();
        let receipts: Vec<_> = (0..=MAX_REPLAY_RECEIPTS)
            .map(|i| {
                ReplayConvergenceReceiptV1::create_signed(
                    format!("rcpt-{i}"),
                    "boundary-1",
                    test_hash(0xAA),
                    1000,
                    true,
                    test_hash(0xBB),
                    test_hash(0xCC),
                    test_hash(0xDD),
                    "actor-1",
                    &signer,
                )
                .unwrap()
            })
            .collect();
        let result = validate_replay_convergence_tp004(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &receipts,
            "boundary-1",
        );
        assert_eq!(result.unwrap_err(), DENY_REPLAY_RECEIPTS_EXCEEDED);
    }

    // ========================================================================
    // TP-EIO29-007: replay idempotency monotone
    // ========================================================================

    fn adjacent_windows() -> AdjacentWindowPair {
        AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 999,
            w_t1_start: 1000,
            w_t1_end: 1999,
        }
    }

    #[test]
    fn tp007_valid_disjoint_effects_pass() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01), test_hash(0x02)],
            &[test_hash(0x03), test_hash(0x04)],
            &[], // no revoked effects
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tp007_non_adjacent_windows_denies() {
        let windows = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 999,
            w_t1_start: 1001, // gap of 2 ticks
            w_t1_end: 1999,
        };
        let result = validate_replay_idempotency_tp007(
            &windows,
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_WINDOWS_NOT_ADJACENT);
    }

    #[test]
    fn tp007_overlapping_windows_denies() {
        let windows = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 1000,
            w_t1_start: 1000, // overlap
            w_t1_end: 1999,
        };
        let result = validate_replay_idempotency_tp007(
            &windows,
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_WINDOWS_NOT_ADJACENT);
    }

    #[test]
    fn tp007_revoked_effect_in_later_window_denies() {
        let revoked = test_hash(0x05);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x03), revoked], // revoked effect appears in later window
            &[revoked],
        );
        assert_eq!(result.unwrap_err(), DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
    }

    #[test]
    fn tp007_duplicate_authoritative_effect_denies() {
        let shared = test_hash(0x01);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[shared],
            &[shared], // same effect in both windows
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
    }

    #[test]
    fn tp007_zero_effect_identity_denies() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[[0u8; 32]], // zero effect identity
            &[test_hash(0x03)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_IDENTITY_ZERO);
    }

    #[test]
    fn tp007_zero_effect_identity_in_later_window_denies() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[[0u8; 32]], // zero effect identity
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_IDENTITY_ZERO);
    }

    #[test]
    fn tp007_zero_revoked_effect_denies() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[[0u8; 32]], // zero revoked effect
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_IDENTITY_ZERO);
    }

    #[test]
    fn tp007_exceeds_max_effects_denies() {
        #[allow(clippy::cast_possible_truncation)]
        let effects: Vec<Hash> = (0..=MAX_EFFECT_IDENTITIES)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                h[31] = 0xFF;
                h
            })
            .collect();
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &effects,
            &[test_hash(0x99)],
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_EFFECT_SET_EXCEEDED);
    }

    #[test]
    fn tp007_exceeds_max_revoked_denies() {
        #[allow(clippy::cast_possible_truncation)]
        let revoked: Vec<Hash> = (0..=MAX_REVOKED_EFFECTS)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                h[31] = 0xFF;
                h
            })
            .collect();
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x99)],
            &revoked,
        );
        assert_eq!(result.unwrap_err(), DENY_REVOKED_SET_EXCEEDED);
    }

    #[test]
    fn tp007_empty_effects_passes() {
        let result = validate_replay_idempotency_tp007(&adjacent_windows(), &[], &[], &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn tp007_revoked_not_in_later_window_passes() {
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01)],
            &[test_hash(0x03)],
            &[test_hash(0x05)], // revoked but not in effects_t1
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // AdjacentWindowPair
    // ========================================================================

    #[test]
    fn adjacent_pair_exact_gap_of_one() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 99,
            w_t1_start: 100,
            w_t1_end: 199,
        };
        assert!(pair.is_adjacent());
    }

    #[test]
    fn adjacent_pair_gap_of_two_not_adjacent() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 99,
            w_t1_start: 101,
            w_t1_end: 199,
        };
        assert!(!pair.is_adjacent());
    }

    #[test]
    fn adjacent_pair_overlap_not_adjacent() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: 100,
            w_t1_start: 100,
            w_t1_end: 199,
        };
        assert!(!pair.is_adjacent());
    }

    #[test]
    fn adjacent_pair_saturating_add_at_max() {
        let pair = AdjacentWindowPair {
            w_t_start: 0,
            w_t_end: u64::MAX,
            w_t1_start: u64::MAX, // saturating_add(1) wraps to MAX
            w_t1_end: u64::MAX,
        };
        // Not adjacent: w_t_end == w_t1_start so fails first guard.
        assert!(!pair.is_adjacent());
    }

    // ========================================================================
    // Combined evaluation
    // ========================================================================

    #[test]
    fn evaluate_replay_recovery_tp004_only_allows() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            None, // no idempotency check
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Allow);
        assert!(decision.defect.is_none());
        assert_eq!(decision.predicate_results.len(), 1);
        assert_eq!(
            decision.predicate_results[0],
            (TemporalPredicateId::TpEio29004, true)
        );
    }

    #[test]
    fn evaluate_replay_recovery_tp004_denies_produces_defect() {
        let decision = evaluate_replay_recovery(
            None, // missing horizon -> deny
            Some(&valid_backlog()),
            &[],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            None,
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_REPLAY_HORIZON_UNRESOLVED);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29004);
        assert_eq!(defect.boundary_id, "boundary-1");
        assert_eq!(defect.denied_at_tick, 500);
    }

    #[test]
    fn evaluate_replay_recovery_tp007_denies_duplicate_effect() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let shared = test_hash(0x01);
        let idem = IdempotencyCheckInput {
            windows: adjacent_windows(),
            effects_t: vec![shared],
            effects_t1: vec![shared],
            revoked_t1: vec![],
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            Some(&idem),
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29007);
    }

    #[test]
    fn evaluate_replay_recovery_tp004_and_tp007_both_pass() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let idem = IdempotencyCheckInput {
            windows: adjacent_windows(),
            effects_t: vec![test_hash(0x01)],
            effects_t1: vec![test_hash(0x02)],
            revoked_t1: vec![],
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            Some(&idem),
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Allow);
        assert_eq!(decision.predicate_results.len(), 2);
        assert_eq!(
            decision.predicate_results[0],
            (TemporalPredicateId::TpEio29004, true)
        );
        assert_eq!(
            decision.predicate_results[1],
            (TemporalPredicateId::TpEio29007, true)
        );
    }

    #[test]
    fn evaluate_replay_recovery_tp007_revoked_effect_denies() {
        let signer = valid_signer();
        let receipt = valid_replay_receipt(&signer);
        let revoked = test_hash(0x05);
        let idem = IdempotencyCheckInput {
            windows: adjacent_windows(),
            effects_t: vec![test_hash(0x01)],
            effects_t1: vec![test_hash(0x02), revoked],
            revoked_t1: vec![revoked],
        };
        let decision = evaluate_replay_recovery(
            Some(&valid_horizon()),
            Some(&valid_backlog()),
            &[receipt],
            "boundary-1",
            500,
            test_hash(0xBB),
            test_hash(0xCC),
            Some(&idem),
        );
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
        let defect = decision.defect.as_ref().unwrap();
        assert_eq!(defect.reason, DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
        assert_eq!(defect.predicate_id, TemporalPredicateId::TpEio29007);
    }

    // ========================================================================
    // Partition/rejoin negative tests
    // ========================================================================

    #[test]
    fn partition_rejoin_duplicate_effect_denied() {
        // Simulate: partition isolates effect 0x01. On rejoin, both
        // partitions try to admit the same effect. TP-EIO29-007 denies.
        let earlier_partition_effects = vec![test_hash(0x01)];
        let later_partition_effects = vec![test_hash(0x01)]; // duplicate

        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &earlier_partition_effects,
            &later_partition_effects,
            &[],
        );
        assert_eq!(result.unwrap_err(), DENY_DUPLICATE_AUTHORITATIVE_EFFECT);
    }

    #[test]
    fn retry_restart_revoked_effect_denied_on_replay() {
        // Simulate: effect 0x05 is revoked during a retry/restart cycle.
        // On replay, the same effect must not be re-admitted.
        let revoked = test_hash(0x05);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01), test_hash(0x02)],
            &[test_hash(0x03), revoked], // re-admitted revoked effect
            &[revoked],
        );
        assert_eq!(result.unwrap_err(), DENY_REVOKED_EFFECT_IN_LATER_WINDOW);
    }

    #[test]
    fn retry_restart_fresh_effects_after_revocation_pass() {
        // After revocation, completely new effects in later window pass.
        let revoked = test_hash(0x05);
        let result = validate_replay_idempotency_tp007(
            &adjacent_windows(),
            &[test_hash(0x01), test_hash(0x02)],
            &[test_hash(0x03), test_hash(0x04)], // all fresh
            &[revoked],                          // revoked but not in effects_t1
        );
        assert!(result.is_ok());
    }

    // ========================================================================
    // Fail-closed unknown state tests
    // ========================================================================

    #[test]
    fn unknown_temporal_state_fails_closed_missing_horizon() {
        let result = validate_replay_convergence_tp004(None, None, &[], "boundary-1");
        assert!(result.is_err());
    }

    #[test]
    fn unknown_temporal_state_fails_closed_missing_everything() {
        let decision =
            evaluate_replay_recovery(None, None, &[], "boundary-1", 0, [0u8; 32], [0u8; 32], None);
        assert_eq!(decision.verdict, ReplayRecoveryVerdict::Deny);
    }
}
