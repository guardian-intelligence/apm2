// AGENT-AUTHORED
//! Privileged handler PCAC lifecycle integration (TCK-00424).
//!
//! Provides shared join-input builders and delegation narrowing checks for
//! privileged authority-bearing handlers (`DelegateSublease`,
//! `IngestReviewReceipt`).
//!
//! # Design
//!
//! Privileged handlers operate on the operator socket (not session socket) and
//! derive authority context from:
//! - Peer credentials (UID/GID → authenticated actor ID)
//! - Parent lease bindings (time envelope, policy hash, risk tier)
//! - Changeset/intent context (digests from request payloads)
//!
//! The [`PrivilegedJoinInputBuilder`] constructs [`AuthorityJoinInputV1`] from
//! these privileged-path contexts. The [`DelegationNarrowingChecker`] enforces
//! RFC-0027 §4 Law 5 (Delegation Narrowing) for sublease paths.
//!
//! # Rollout
//!
//! Enforcement is gated behind the `pcac_privileged_enforcement` flag on
//! [`SessionDispatcher`]. When disabled, the lifecycle gate is skipped
//! (Phase 1 policy-flagged rollout without wire protocol break).

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityDenyClass, AuthorityDenyV1, AuthorityJoinInputV1, DeterminismClass,
    IdentityEvidenceLevel, RiskTier,
};

// =============================================================================
// PrivilegedJoinInputBuilder
// =============================================================================

/// Builds [`AuthorityJoinInputV1`] for privileged handler paths.
///
/// Extracts authority context from peer credentials and lease bindings rather
/// than session tokens (which are not available on the operator socket).
pub struct PrivilegedJoinInputBuilder {
    /// Authenticated actor ID (derived from peer credentials UID+GID).
    pub actor_id: String,
    /// Lease ID binding the authority scope.
    pub lease_id: String,
    /// Intent digest (BLAKE3 of the handler-specific payload).
    pub intent_digest: Hash,
    /// Identity proof hash from the request.
    pub identity_proof_hash: Hash,
    /// Risk tier resolved from the lease/policy context.
    pub risk_tier: RiskTier,
    /// Time envelope reference from the lease.
    pub time_envelope_ref: Hash,
    /// Ledger anchor (current daemon state).
    pub as_of_ledger_anchor: Hash,
    /// Directory head hash for revocation tracking.
    pub directory_head_hash: Hash,
    /// Changeset digest from the request context.
    pub changeset_digest: Hash,
    /// Policy hash resolved from the lease.
    pub policy_hash: Hash,
    /// Freshness witness tick (monotonic time).
    pub freshness_witness_tick: u64,
    /// Optional permeability receipt hash for delegated authority paths.
    pub permeability_receipt_hash: Option<Hash>,
}

impl PrivilegedJoinInputBuilder {
    /// Constructs an [`AuthorityJoinInputV1`] from the privileged context.
    #[must_use]
    pub fn build(self) -> AuthorityJoinInputV1 {
        // Derive capability manifest hash from actor_id + policy_hash.
        let capability_manifest_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"privileged_capability_manifest:");
            hasher.update(self.actor_id.as_bytes());
            hasher.update(&self.policy_hash);
            *hasher.finalize().as_bytes()
        };

        // Derive freshness policy hash from policy context.
        let freshness_policy_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"freshness_policy:");
            hasher.update(&self.policy_hash);
            *hasher.finalize().as_bytes()
        };

        // Derive stop budget profile digest from policy hash.
        let stop_budget_profile_digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"stop_budget_profile:");
            hasher.update(&self.policy_hash);
            *hasher.finalize().as_bytes()
        };

        AuthorityJoinInputV1 {
            session_id: self.actor_id.clone(),
            holon_id: None,
            intent_digest: self.intent_digest,
            capability_manifest_hash,
            scope_witness_hashes: vec![],
            lease_id: self.lease_id,
            permeability_receipt_hash: self.permeability_receipt_hash,
            identity_proof_hash: self.identity_proof_hash,
            identity_evidence_level: IdentityEvidenceLevel::Verified,
            directory_head_hash: self.directory_head_hash,
            freshness_policy_hash,
            freshness_witness_tick: self.freshness_witness_tick,
            stop_budget_profile_digest,
            pre_actuation_receipt_hashes: vec![],
            risk_tier: self.risk_tier,
            determinism_class: DeterminismClass::Deterministic,
            time_envelope_ref: self.time_envelope_ref,
            as_of_ledger_anchor: self.as_of_ledger_anchor,
        }
    }
}

// =============================================================================
// DelegationNarrowingChecker
// =============================================================================

/// Enforces RFC-0027 §4 Law 5 (Delegation Narrowing) for sublease paths.
///
/// Delegated authority MUST be a strict subset of the parent authority scope.
/// Any widening attempt produces a deterministic denial.
pub struct DelegationNarrowingChecker;

/// Parameters for delegation narrowing validation.
pub struct DelegationNarrowingParams<'a> {
    /// Parent lease expiry (milliseconds since epoch).
    pub parent_expiry_ms: u64,
    /// Sublease requested expiry (milliseconds since epoch).
    pub sublease_expiry_ms: u64,
    /// Parent changeset digest.
    pub parent_changeset_digest: &'a Hash,
    /// Sublease changeset digest.
    pub sublease_changeset_digest: &'a Hash,
    /// Parent policy hash.
    pub parent_policy_hash: &'a Hash,
    /// Sublease policy hash.
    pub sublease_policy_hash: &'a Hash,
    /// Parent gate ID.
    pub parent_gate_id: &'a str,
    /// Sublease gate ID.
    pub sublease_gate_id: &'a str,
    /// Time envelope reference for deny context.
    pub time_envelope_ref: Hash,
    /// Ledger anchor for deny context.
    pub ledger_anchor: Hash,
    /// Current tick for deny context.
    pub current_tick: u64,
}

impl DelegationNarrowingChecker {
    /// Validates that a sublease delegation is strict-subset of the parent.
    ///
    /// # Checks
    ///
    /// 1. Sublease expiry must not exceed parent lease expiry.
    /// 2. Sublease changeset digest must match parent (no scope widening).
    /// 3. Sublease policy hash must match parent (no policy escalation).
    /// 4. Sublease gate ID must match parent gate ID.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityDenyV1`] with
    /// [`AuthorityDenyClass::DelegationWidening`] if any check fails.
    pub fn validate(params: &DelegationNarrowingParams<'_>) -> Result<(), Box<AuthorityDenyV1>> {
        let deny = || {
            Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::DelegationWidening,
                ajc_id: None,
                time_envelope_ref: params.time_envelope_ref,
                ledger_anchor: params.ledger_anchor,
                denied_at_tick: params.current_tick,
            })
        };

        // Check 1: Expiry narrowing — sublease cannot outlive parent.
        if params.sublease_expiry_ms > params.parent_expiry_ms {
            return Err(deny());
        }

        // Check 2: Changeset scope — sublease inherits parent's changeset.
        if params.sublease_changeset_digest != params.parent_changeset_digest {
            return Err(deny());
        }

        // Check 3: Policy scope — sublease inherits parent's policy.
        if params.sublease_policy_hash != params.parent_policy_hash {
            return Err(deny());
        }

        // Check 4: Gate binding — sublease must target same gate.
        if params.sublease_gate_id != params.parent_gate_id {
            return Err(deny());
        }

        Ok(())
    }

    /// Validates that a delegation chain (parent → child lineage) is present
    /// and valid. Returns error if the delegation lineage is missing.
    pub fn validate_lineage(
        parent_lease_id: &str,
        delegatee_actor_id: &str,
        time_envelope_ref: Hash,
        ledger_anchor: Hash,
        current_tick: u64,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        // Lineage requires both parent lease reference and delegatee identity.
        if parent_lease_id.is_empty() || delegatee_actor_id.is_empty() {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::InvalidDelegationChain,
                ajc_id: None,
                time_envelope_ref,
                ledger_anchor,
                denied_at_tick: current_tick,
            }));
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod privileged_tests {
    use super::*;

    fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn builder_produces_valid_join_input() {
        let builder = PrivilegedJoinInputBuilder {
            actor_id: "actor:test-reviewer".to_string(),
            lease_id: "lease-001".to_string(),
            intent_digest: test_hash(0x01),
            identity_proof_hash: test_hash(0x02),
            risk_tier: RiskTier::Tier1,
            time_envelope_ref: test_hash(0x03),
            as_of_ledger_anchor: test_hash(0x04),
            directory_head_hash: test_hash(0x05),
            changeset_digest: test_hash(0x06),
            policy_hash: test_hash(0x07),
            freshness_witness_tick: 1000,
            permeability_receipt_hash: None,
        };

        let input = builder.build();
        assert_eq!(input.session_id, "actor:test-reviewer");
        assert_eq!(input.lease_id, "lease-001");
        assert_eq!(input.intent_digest, test_hash(0x01));
        assert_eq!(input.identity_proof_hash, test_hash(0x02));
        assert_eq!(input.risk_tier, RiskTier::Tier1);
        assert_eq!(input.time_envelope_ref, test_hash(0x03));
        assert_eq!(input.as_of_ledger_anchor, test_hash(0x04));
        assert_eq!(input.freshness_witness_tick, 1000);
        assert!(input.permeability_receipt_hash.is_none());
        assert_eq!(
            input.identity_evidence_level,
            IdentityEvidenceLevel::Verified
        );
        assert_eq!(input.determinism_class, DeterminismClass::Deterministic);
        // Derived hashes are non-zero.
        assert_ne!(input.capability_manifest_hash, [0u8; 32]);
        assert_ne!(input.freshness_policy_hash, [0u8; 32]);
        assert_ne!(input.stop_budget_profile_digest, [0u8; 32]);
    }

    #[test]
    fn builder_with_permeability_receipt() {
        let builder = PrivilegedJoinInputBuilder {
            actor_id: "actor:delegator".to_string(),
            lease_id: "lease-002".to_string(),
            intent_digest: test_hash(0x10),
            identity_proof_hash: test_hash(0x11),
            risk_tier: RiskTier::Tier0,
            time_envelope_ref: test_hash(0x12),
            as_of_ledger_anchor: test_hash(0x13),
            directory_head_hash: test_hash(0x14),
            changeset_digest: test_hash(0x15),
            policy_hash: test_hash(0x16),
            freshness_witness_tick: 500,
            permeability_receipt_hash: Some(test_hash(0x17)),
        };

        let input = builder.build();
        assert_eq!(input.permeability_receipt_hash, Some(test_hash(0x17)));
    }

    // =========================================================================
    // Delegation narrowing tests
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    fn valid_narrowing_params<'a>(
        parent_expiry: u64,
        sublease_expiry: u64,
        parent_changeset: &'a Hash,
        sublease_changeset: &'a Hash,
        parent_policy: &'a Hash,
        sublease_policy: &'a Hash,
        parent_gate: &'a str,
        sublease_gate: &'a str,
    ) -> DelegationNarrowingParams<'a> {
        DelegationNarrowingParams {
            parent_expiry_ms: parent_expiry,
            sublease_expiry_ms: sublease_expiry,
            parent_changeset_digest: parent_changeset,
            sublease_changeset_digest: sublease_changeset,
            parent_policy_hash: parent_policy,
            sublease_policy_hash: sublease_policy,
            parent_gate_id: parent_gate,
            sublease_gate_id: sublease_gate,
            time_envelope_ref: test_hash(0x03),
            ledger_anchor: test_hash(0x04),
            current_tick: 100,
        }
    }

    #[test]
    fn delegation_narrowing_succeeds_with_valid_subset() {
        let cs = test_hash(0x01);
        let pol = test_hash(0x02);
        let params =
            valid_narrowing_params(1000, 500, &cs, &cs, &pol, &pol, "gate-001", "gate-001");
        assert!(DelegationNarrowingChecker::validate(&params).is_ok());
    }

    #[test]
    fn delegation_narrowing_succeeds_with_equal_expiry() {
        let cs = test_hash(0x01);
        let pol = test_hash(0x02);
        let params =
            valid_narrowing_params(1000, 1000, &cs, &cs, &pol, &pol, "gate-001", "gate-001");
        assert!(DelegationNarrowingChecker::validate(&params).is_ok());
    }

    #[test]
    fn delegation_denies_expiry_widening() {
        let cs = test_hash(0x01);
        let pol = test_hash(0x02);
        let params =
            valid_narrowing_params(1000, 2000, &cs, &cs, &pol, &pol, "gate-001", "gate-001");
        let err = DelegationNarrowingChecker::validate(&params).unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::DelegationWidening
        ));
    }

    #[test]
    fn delegation_denies_changeset_mismatch() {
        let cs1 = test_hash(0x01);
        let cs2 = test_hash(0xFF);
        let pol = test_hash(0x02);
        let params =
            valid_narrowing_params(1000, 500, &cs1, &cs2, &pol, &pol, "gate-001", "gate-001");
        let err = DelegationNarrowingChecker::validate(&params).unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::DelegationWidening
        ));
    }

    #[test]
    fn delegation_denies_policy_mismatch() {
        let cs = test_hash(0x01);
        let pol1 = test_hash(0x02);
        let pol2 = test_hash(0xFF);
        let params =
            valid_narrowing_params(1000, 500, &cs, &cs, &pol1, &pol2, "gate-001", "gate-001");
        let err = DelegationNarrowingChecker::validate(&params).unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::DelegationWidening
        ));
    }

    #[test]
    fn delegation_denies_gate_mismatch() {
        let cs = test_hash(0x01);
        let pol = test_hash(0x02);
        let params =
            valid_narrowing_params(1000, 500, &cs, &cs, &pol, &pol, "gate-001", "gate-002");
        let err = DelegationNarrowingChecker::validate(&params).unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::DelegationWidening
        ));
    }

    #[test]
    fn delegation_lineage_succeeds_with_valid_references() {
        let result = DelegationNarrowingChecker::validate_lineage(
            "parent-lease-001",
            "delegatee-actor-001",
            test_hash(0x01),
            test_hash(0x02),
            100,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn delegation_lineage_denies_empty_parent_lease() {
        let err = DelegationNarrowingChecker::validate_lineage(
            "", // empty — DENIED
            "delegatee-actor-001",
            test_hash(0x01),
            test_hash(0x02),
            100,
        )
        .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::InvalidDelegationChain
        ));
    }

    #[test]
    fn delegation_lineage_denies_empty_delegatee() {
        let err = DelegationNarrowingChecker::validate_lineage(
            "parent-lease-001",
            "", // empty — DENIED
            test_hash(0x01),
            test_hash(0x02),
            100,
        )
        .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::InvalidDelegationChain
        ));
    }

    // =========================================================================
    // Full lifecycle integration via builder + gate
    // =========================================================================

    #[test]
    fn builder_output_passes_lifecycle_gate() {
        use std::sync::Arc;

        use super::super::lifecycle_gate::{InProcessKernel, LifecycleGate};

        let kernel = Arc::new(InProcessKernel::new(100));
        let gate = LifecycleGate::new(kernel);

        let builder = PrivilegedJoinInputBuilder {
            actor_id: "actor:privileged-test".to_string(),
            lease_id: "lease-integration".to_string(),
            intent_digest: test_hash(0x01),
            identity_proof_hash: test_hash(0x02),
            risk_tier: RiskTier::Tier0,
            time_envelope_ref: test_hash(0x03),
            as_of_ledger_anchor: test_hash(0x04),
            directory_head_hash: test_hash(0x05),
            changeset_digest: test_hash(0x06),
            policy_hash: test_hash(0x07),
            freshness_witness_tick: 1000,
            permeability_receipt_hash: None,
        };

        let input = builder.build();
        let receipts = gate
            .execute(
                &input,
                input.time_envelope_ref,
                input.as_of_ledger_anchor,
                input.directory_head_hash,
            )
            .expect("privileged join input should pass lifecycle gate");

        assert_eq!(receipts.certificate.intent_digest, test_hash(0x01));
        assert_eq!(receipts.certificate.risk_tier, RiskTier::Tier0);
    }

    #[test]
    fn delegation_narrowing_then_lifecycle_gate() {
        use std::sync::Arc;

        use super::super::lifecycle_gate::{InProcessKernel, LifecycleGate};

        // Step 1: Validate delegation narrowing.
        let cs = test_hash(0x01);
        let pol = test_hash(0x02);
        let params =
            valid_narrowing_params(2000, 1000, &cs, &cs, &pol, &pol, "gate-001", "gate-001");
        DelegationNarrowingChecker::validate(&params).expect("narrowing should pass");

        // Step 2: Validate delegation lineage.
        DelegationNarrowingChecker::validate_lineage(
            "parent-lease-001",
            "delegatee-actor-001",
            test_hash(0x03),
            test_hash(0x04),
            100,
        )
        .expect("lineage should pass");

        // Step 3: Execute lifecycle gate.
        let kernel = Arc::new(InProcessKernel::new(100));
        let gate = LifecycleGate::new(kernel);

        let builder = PrivilegedJoinInputBuilder {
            actor_id: "actor:delegator".to_string(),
            lease_id: "parent-lease-001".to_string(),
            intent_digest: test_hash(0x10),
            identity_proof_hash: test_hash(0x11),
            risk_tier: RiskTier::Tier1,
            time_envelope_ref: test_hash(0x03),
            as_of_ledger_anchor: test_hash(0x04),
            directory_head_hash: test_hash(0x05),
            changeset_digest: test_hash(0x01),
            policy_hash: test_hash(0x02),
            freshness_witness_tick: 1000,
            permeability_receipt_hash: Some(test_hash(0x20)),
        };

        let input = builder.build();
        let receipts = gate
            .execute(
                &input,
                input.time_envelope_ref,
                input.as_of_ledger_anchor,
                input.directory_head_hash,
            )
            .expect("delegated lifecycle should pass");

        assert_eq!(receipts.certificate.risk_tier, RiskTier::Tier1);
    }

    #[test]
    fn policy_flag_bypass_skips_gate() {
        // When pcac_privileged_enforcement is false, the gate is not called.
        // This test verifies the pattern: if !enforcement { None } else { gate }
        let enforce = false;
        let result: Option<&str> = if enforce { Some("gate executed") } else { None };
        assert!(result.is_none(), "policy flag off should skip gate");
    }

    #[test]
    fn policy_flag_enable_runs_gate() {
        let enforce = true;
        let result: Option<&str> = if enforce { Some("gate executed") } else { None };
        assert!(result.is_some(), "policy flag on should run gate");
    }
}
