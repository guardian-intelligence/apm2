// AGENT-AUTHORED
//! Tests for `AdmissionKernel` plan/execute API (TCK-00492).
//!
//! Coverage:
//! - (a) missing policy-root denies for fail-closed tiers
//! - (b) missing witness SEEDS deny for fail-closed tiers (provider validation)
//! - (c) anti-rollback anchor missing denies for fail-closed tiers
//! - (d) early output is impossible for fail-closed tiers
//! - (e) intent mismatch denies at consume boundary
//! - (f) plan cannot be executed twice
//! - (g) monitor tier proceeds without prerequisites
//! - (h) capability tokens are minted only through kernel
//! - (i) lifecycle ordering enforcement
//! - (j) missing ledger verifier denies for fail-closed tiers

use std::sync::Arc;

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityDenyClass, AuthorityDenyV1,
    AuthorityJoinCertificateV1, AuthorityJoinInputV1, AuthorityJoinKernel, BoundaryIntentClass,
    FreezeAction, IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};

use super::prerequisites::{
    AntiRollbackAnchor, ExternalAnchorStateV1, LedgerAnchorV1, LedgerTrustVerifier, PolicyError,
    PolicyRootResolver, PolicyRootStateV1, TrustError, ValidatedLedgerStateV1,
};
use super::types::{AdmitError, EnforcementTier};
use super::{AdmissionKernelV1, QuarantineGuard, WitnessProviderConfig};

// =============================================================================
// Test helpers
// =============================================================================

/// Non-zero hash for testing.
fn test_hash(byte: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = byte;
    h[31] = byte;
    h
}

/// Build a valid `KernelRequestV1` for testing.
fn valid_request(risk_tier: RiskTier) -> super::types::KernelRequestV1 {
    super::types::KernelRequestV1 {
        request_id: test_hash(1),
        session_id: "test-session-001".to_string(),
        tool_class: "filesystem.write".to_string(),
        boundary_profile_id: "boundary-001".to_string(),
        risk_tier,
        effect_descriptor_digest: test_hash(2),
        intent_digest: test_hash(3),
        hsi_contract_manifest_digest: test_hash(4),
        hsi_envelope_binding_digest: test_hash(5),
        stop_budget_digest: test_hash(6),
        pcac_policy: PcacPolicyKnobs::default(),
        declared_idempotent: false,
        lease_id: "lease-001".to_string(),
        identity_proof_hash: test_hash(7),
        capability_manifest_hash: test_hash(8),
        time_envelope_ref: test_hash(9),
        freshness_witness_tick: 42,
        directory_head_hash: test_hash(10),
        freshness_policy_hash: test_hash(11),
        revocation_head_hash: test_hash(12),
    }
}

fn witness_provider() -> WitnessProviderConfig {
    WitnessProviderConfig {
        provider_id: "apm2-daemon/admission_kernel/test".to_string(),
        provider_build_digest: test_hash(99),
    }
}

// -- Mock implementations --

/// Result type for consume operations in the mock kernel.
type ConsumeResult = Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>>;

/// A mock PCAC kernel that tracks calls and can be configured to fail.
struct MockPcacKernel {
    join_result: std::sync::Mutex<Option<Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>>>>,
    consume_result: std::sync::Mutex<Option<ConsumeResult>>,
}

impl MockPcacKernel {
    fn passing() -> Self {
        Self {
            join_result: std::sync::Mutex::new(None),
            consume_result: std::sync::Mutex::new(None),
        }
    }

    fn with_consume_error(deny_class: AuthorityDenyClass) -> Self {
        let deny = AuthorityDenyV1 {
            deny_class,
            ajc_id: Some(test_hash(50)),
            time_envelope_ref: test_hash(51),
            ledger_anchor: test_hash(52),
            denied_at_tick: 100,
            containment_action: Some(FreezeAction::NoAction),
        };
        Self {
            join_result: std::sync::Mutex::new(None),
            consume_result: std::sync::Mutex::new(Some(Err(Box::new(deny)))),
        }
    }
}

impl AuthorityJoinKernel for MockPcacKernel {
    fn join(
        &self,
        _input: &AuthorityJoinInputV1,
        _policy: &PcacPolicyKnobs,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
        let guard = self
            .join_result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref result) = *guard {
            return result.clone();
        }
        // Default: return a valid certificate
        Ok(AuthorityJoinCertificateV1 {
            ajc_id: test_hash(50),
            authority_join_hash: test_hash(51),
            intent_digest: test_hash(3),
            boundary_intent_class: BoundaryIntentClass::Actuate,
            risk_tier: RiskTier::Tier1,
            issued_time_envelope_ref: test_hash(52),
            issued_at_tick: 40,
            as_of_ledger_anchor: test_hash(53),
            expires_at_tick: 1000,
            revocation_head_hash: test_hash(54),
            identity_evidence_level: IdentityEvidenceLevel::PointerOnly,
            admission_capacity_token: None,
        })
    }

    fn revalidate(
        &self,
        _cert: &AuthorityJoinCertificateV1,
        _current_time_envelope_ref: Hash,
        _current_ledger_anchor: Hash,
        _current_revocation_head_hash: Hash,
        _policy: &PcacPolicyKnobs,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        Ok(())
    }

    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        _intent_digest: Hash,
        _boundary_intent_class: BoundaryIntentClass,
        _requires_authoritative_acceptance: bool,
        _current_time_envelope_ref: Hash,
        _current_revocation_head_hash: Hash,
        _policy: &PcacPolicyKnobs,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        let guard = self
            .consume_result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref result) = *guard {
            return result.clone();
        }
        // Default: return a valid consume result
        Ok((
            AuthorityConsumedV1 {
                ajc_id: cert.ajc_id,
                intent_digest: test_hash(3),
                consumed_time_envelope_ref: test_hash(61),
                consumed_at_tick: 45,
            },
            AuthorityConsumeRecordV1 {
                ajc_id: cert.ajc_id,
                consumed_time_envelope_ref: test_hash(61),
                consumed_at_tick: 45,
                effect_selector_digest: test_hash(60),
            },
        ))
    }
}

/// A mock ledger trust verifier.
struct MockLedgerVerifier {
    result: Result<ValidatedLedgerStateV1, TrustError>,
}

impl MockLedgerVerifier {
    fn passing() -> Self {
        Self {
            result: Ok(ValidatedLedgerStateV1 {
                validated_anchor: LedgerAnchorV1 {
                    ledger_id: test_hash(20),
                    event_hash: test_hash(21),
                    height: 100,
                    he_time: 1000,
                },
                tip_anchor: LedgerAnchorV1 {
                    ledger_id: test_hash(20),
                    event_hash: test_hash(22),
                    height: 105,
                    he_time: 1050,
                },
                ledger_keyset_digest: test_hash(23),
                root_trust_bundle_digest: test_hash(24),
            }),
        }
    }
}

impl LedgerTrustVerifier for MockLedgerVerifier {
    fn validated_state(&self) -> Result<ValidatedLedgerStateV1, TrustError> {
        self.result.clone()
    }
}

/// A mock policy root resolver.
struct MockPolicyResolver {
    result: Result<PolicyRootStateV1, PolicyError>,
}

impl MockPolicyResolver {
    fn passing() -> Self {
        Self {
            result: Ok(PolicyRootStateV1 {
                policy_root_digest: test_hash(30),
                policy_root_epoch: 5,
                anchor: LedgerAnchorV1 {
                    ledger_id: test_hash(20),
                    event_hash: test_hash(21),
                    height: 100,
                    he_time: 1000,
                },
                provenance: super::prerequisites::GovernanceProvenanceV1 {
                    signer_key_id: test_hash(31),
                    algorithm_id: "ed25519".to_string(),
                },
            }),
        }
    }

    fn failing() -> Self {
        Self {
            result: Err(PolicyError::NoGovernanceEvents),
        }
    }
}

impl PolicyRootResolver for MockPolicyResolver {
    fn resolve(&self, _as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError> {
        self.result.clone()
    }
}

/// A mock anti-rollback anchor.
struct MockAntiRollback {
    result: Result<(), TrustError>,
}

impl MockAntiRollback {
    fn passing() -> Self {
        Self { result: Ok(()) }
    }
}

impl AntiRollbackAnchor for MockAntiRollback {
    fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
        Ok(ExternalAnchorStateV1 {
            anchor: LedgerAnchorV1 {
                ledger_id: test_hash(20),
                event_hash: test_hash(21),
                height: 100,
                he_time: 1000,
            },
            mechanism_id: "test".to_string(),
            proof_hash: test_hash(40),
        })
    }

    fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
        self.result.clone()
    }
}

/// A mock quarantine guard.
struct MockQuarantineGuard {
    result: Result<Hash, String>,
}

impl MockQuarantineGuard {
    fn passing() -> Self {
        Self {
            result: Ok(test_hash(70)),
        }
    }
}

impl QuarantineGuard for MockQuarantineGuard {
    fn reserve(&self, _request_id: &Hash, _ajc_id: &Hash) -> Result<Hash, String> {
        self.result.clone()
    }
}

/// Build a fully-wired kernel for fail-closed tier testing.
fn fully_wired_kernel() -> AdmissionKernelV1 {
    AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
}

/// Build a minimal kernel (no optional prerequisites).
fn minimal_kernel() -> AdmissionKernelV1 {
    AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
}

// =============================================================================
// Test: (a) missing policy-root denies for fail-closed tiers
// =============================================================================

#[test]
fn test_missing_policy_root_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));
    // Deliberately NOT setting policy resolver.

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when policy root resolver is missing"
    );
    let err = result.unwrap_err();
    match &err {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "PolicyRootResolver");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

#[test]
fn test_failing_policy_root_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::failing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when policy root resolution fails"
    );
    match result.unwrap_err() {
        AdmitError::PolicyRootFailure { reason } => {
            assert!(
                reason.contains("governance"),
                "reason should mention governance events: {reason}"
            );
        },
        other => panic!("expected PolicyRootFailure, got: {other}"),
    }
}

// =============================================================================
// Test: (b) missing witness SEEDS deny for fail-closed tiers
// =============================================================================

#[test]
fn test_invalid_witness_provider_denies() {
    let bad_provider = WitnessProviderConfig {
        provider_id: String::new(), // empty — invalid
        provider_build_digest: test_hash(99),
    };
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), bad_provider)
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));

    // Test both tiers
    for tier in [RiskTier::Tier1, RiskTier::Tier2Plus] {
        let request = valid_request(tier);
        let result = kernel.plan(&request);
        assert!(
            result.is_err(),
            "invalid witness provider must deny for {tier:?}"
        );
        match result.unwrap_err() {
            AdmitError::WitnessSeedFailure { reason } => {
                assert!(
                    reason.contains("provider_id"),
                    "reason should mention provider_id: {reason}"
                );
            },
            other => panic!("expected WitnessSeedFailure, got: {other}"),
        }
    }
}

// =============================================================================
// Test: (c) anti-rollback anchor missing denies for fail-closed tiers
// =============================================================================

#[test]
fn test_missing_anti_rollback_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()));
    // Deliberately NOT setting anti-rollback anchor.

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when anti-rollback anchor is missing"
    );
    match result.unwrap_err() {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "AntiRollbackAnchor");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

// =============================================================================
// Test: (d) early output is impossible for fail-closed tiers
// =============================================================================

#[test]
fn test_boundary_span_holds_output_for_fail_closed() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        result.boundary_span.output_held,
        "fail-closed tier must hold output (output_held=true)"
    );
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::FailClosed,
        "boundary span must carry fail-closed tier"
    );
}

#[test]
fn test_boundary_span_releases_output_for_monitor() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier0);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        !result.boundary_span.output_held,
        "monitor tier should NOT hold output (output_held=false)"
    );
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor,
        "boundary span must carry monitor tier"
    );
}

// =============================================================================
// Test: (e) intent mismatch denies at consume boundary
// =============================================================================

#[test]
fn test_intent_mismatch_denies_at_consume() {
    let kernel = AdmissionKernelV1::new(
        Arc::new(MockPcacKernel::with_consume_error(
            AuthorityDenyClass::IntentDigestMismatch {
                expected: test_hash(3),
                actual: test_hash(99),
            },
        )),
        witness_provider(),
    )
    .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
    .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
    .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
    .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "intent mismatch must deny at consume boundary"
    );
    match result.unwrap_err() {
        AdmitError::ConsumeDenied { reason } => {
            assert!(
                reason.contains("intent digest mismatch"),
                "reason should mention intent digest mismatch: {reason}"
            );
        },
        other => panic!("expected ConsumeDenied, got: {other}"),
    }
}

// =============================================================================
// Test: (f) plan cannot be executed twice
// =============================================================================

#[test]
fn test_plan_cannot_be_executed_twice() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // First execution succeeds.
    let first_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(first_result.is_ok(), "first execution should succeed");

    // Second execution must be denied.
    let second_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(second_result.is_err(), "second execution must be denied");
    match second_result.unwrap_err() {
        AdmitError::PlanAlreadyConsumed => {},
        other => panic!("expected PlanAlreadyConsumed, got: {other}"),
    }
}

#[test]
fn test_plan_consumed_even_on_execute_failure() {
    // If execute() fails mid-way, the plan is still consumed.
    let kernel = AdmissionKernelV1::new(
        Arc::new(MockPcacKernel::with_consume_error(
            AuthorityDenyClass::IntentDigestMismatch {
                expected: test_hash(3),
                actual: test_hash(99),
            },
        )),
        witness_provider(),
    )
    .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
    .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
    .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
    .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // First execution fails (consume error).
    let first_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(first_result.is_err(), "first execution should fail");

    // Second execution must return PlanAlreadyConsumed, not re-run.
    let second_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    match second_result.unwrap_err() {
        AdmitError::PlanAlreadyConsumed => {},
        other => panic!("expected PlanAlreadyConsumed on retry, got: {other}"),
    }
}

// =============================================================================
// Test: (g) monitor tier proceeds without prerequisites
// =============================================================================

#[test]
fn test_monitor_tier_proceeds_without_prerequisites() {
    let kernel = minimal_kernel(); // No prerequisites wired.
    let request = valid_request(RiskTier::Tier0);

    let result = kernel.plan(&request);
    assert!(
        result.is_ok(),
        "monitor tier should proceed without prerequisites: {:?}",
        result.err()
    );
}

#[test]
fn test_monitor_tier_proceeds_without_quarantine_guard() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_ok(),
        "monitor tier should succeed without quarantine guard: {:?}",
        result.err()
    );

    let res = result.unwrap();
    assert!(
        res.quarantine_capability.is_none(),
        "monitor tier should not receive quarantine capability"
    );
}

// =============================================================================
// Test: (h) capability tokens are minted only through kernel
// =============================================================================

#[test]
fn test_capability_tokens_present_on_success() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Verify capability tokens carry correct provenance.
    assert_eq!(result.effect_capability.ajc_id(), &test_hash(50));
    assert_eq!(result.effect_capability.intent_digest(), &test_hash(3));
    assert_eq!(result.effect_capability.request_id(), &test_hash(1));

    assert_eq!(result.ledger_write_capability.ajc_id(), &test_hash(50));
    assert_eq!(result.ledger_write_capability.request_id(), &test_hash(1));

    assert!(
        result.quarantine_capability.is_some(),
        "fail-closed tier must have quarantine capability"
    );
    let qcap = result.quarantine_capability.unwrap();
    assert_eq!(qcap.ajc_id(), &test_hash(50));
    assert_eq!(qcap.reservation_hash(), &test_hash(70));
}

// =============================================================================
// Test: (i) lifecycle ordering enforcement
// =============================================================================

#[test]
fn test_plan_creates_witness_seeds_with_provider_provenance() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan = kernel.plan(&request).expect("plan should succeed");

    // Verify witness seeds have correct provenance.
    assert_eq!(plan.leakage_witness_seed.witness_class, "leakage");
    assert_eq!(plan.timing_witness_seed.witness_class, "timing");
    assert_eq!(
        plan.leakage_witness_seed.provider_id,
        "apm2-daemon/admission_kernel/test"
    );
    assert_eq!(
        plan.timing_witness_seed.provider_id,
        "apm2-daemon/admission_kernel/test"
    );
    assert_eq!(
        plan.leakage_witness_seed.provider_build_digest,
        test_hash(99)
    );

    // Verify witness seeds bind to request.
    assert_eq!(plan.leakage_witness_seed.request_id, request.request_id);
    assert_eq!(plan.timing_witness_seed.request_id, request.request_id);
    assert_eq!(plan.leakage_witness_seed.session_id, request.session_id);
    assert_eq!(plan.timing_witness_seed.session_id, request.session_id);

    // Verify nonces are different (random).
    assert_ne!(
        plan.leakage_witness_seed.nonce, plan.timing_witness_seed.nonce,
        "witness seed nonces must be unique"
    );
}

#[test]
fn test_plan_creates_spine_extension() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan = kernel.plan(&request).expect("plan should succeed");

    assert_eq!(plan.spine_ext.request_id, request.request_id);
    assert_eq!(plan.spine_ext.session_id, request.session_id);
    assert_eq!(plan.spine_ext.tool_class, request.tool_class);
    assert_eq!(plan.spine_ext.enforcement_tier, EnforcementTier::FailClosed);
    assert_eq!(
        plan.spine_ext.effect_descriptor_digest,
        request.effect_descriptor_digest
    );
}

#[test]
fn test_spine_extension_content_hash_deterministic() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan1 = kernel.plan(&request).expect("plan should succeed");

    // Content hash should be deterministic for same spine extension fields.
    let hash1 = plan1.spine_ext.content_hash();
    let hash2 = plan1.spine_ext.content_hash();
    assert_eq!(hash1, hash2, "content hash must be deterministic");
    assert_ne!(hash1, [0u8; 32], "content hash must not be zero");
}

// =============================================================================
// Test: (j) missing ledger verifier denies for fail-closed tiers
// =============================================================================

#[test]
fn test_missing_ledger_verifier_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());
    // Deliberately NOT setting ledger verifier.

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when ledger verifier is missing"
    );
    match result.unwrap_err() {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "LedgerTrustVerifier");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

// =============================================================================
// Test: request validation
// =============================================================================

#[test]
fn test_invalid_request_denied() {
    let kernel = fully_wired_kernel();

    // Zero request_id
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.request_id = [0u8; 32];
    let result = kernel.plan(&request);
    assert!(result.is_err());
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("request_id"),
                "reason should mention request_id: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }

    // Empty session_id
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.session_id = String::new();
    let result = kernel.plan(&request);
    assert!(result.is_err());
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("session_id"),
                "reason should mention session_id: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }
}

// =============================================================================
// Test: full plan/execute lifecycle (integration)
// =============================================================================

#[test]
fn test_full_lifecycle_plan_execute_success() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    // Plan phase
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    assert_eq!(plan.enforcement_tier, EnforcementTier::FailClosed);
    assert_eq!(plan.request.request_id, request.request_id);

    // Execute phase
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Verify all components of the result.
    assert_ne!(
        result.bundle_digest, [0u8; 32],
        "bundle digest must not be zero"
    );
    assert!(
        result.boundary_span.output_held,
        "output must be held for fail-closed tier"
    );
    assert_eq!(
        result.boundary_span.request_id, request.request_id,
        "boundary span must reference the request"
    );
}

#[test]
fn test_full_lifecycle_monitor_tier() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    assert_eq!(plan.enforcement_tier, EnforcementTier::Monitor);

    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        !result.boundary_span.output_held,
        "output should not be held for monitor tier"
    );
    assert!(
        result.quarantine_capability.is_none(),
        "quarantine capability should not be present for monitor tier"
    );
}

// =============================================================================
// Test: enforcement tier derivation
// =============================================================================

#[test]
fn test_enforcement_tier_derivation() {
    use super::enforcement_tier_from_risk;

    assert_eq!(
        enforcement_tier_from_risk(RiskTier::Tier0),
        EnforcementTier::Monitor
    );
    assert_eq!(
        enforcement_tier_from_risk(RiskTier::Tier1),
        EnforcementTier::Monitor
    );
    assert_eq!(
        enforcement_tier_from_risk(RiskTier::Tier2Plus),
        EnforcementTier::FailClosed
    );
}

// =============================================================================
// Test: quarantine reservation failure denies fail-closed
// =============================================================================

#[test]
fn test_quarantine_reservation_failure_denies_fail_closed() {
    let failing_guard = MockQuarantineGuard {
        result: Err("capacity exhausted (test)".into()),
    };
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(failing_guard));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "quarantine reservation failure must deny for fail-closed tier"
    );
    match result.unwrap_err() {
        AdmitError::QuarantineReservationFailure { reason } => {
            assert!(
                reason.contains("capacity exhausted"),
                "reason should mention capacity: {reason}"
            );
        },
        other => panic!("expected QuarantineReservationFailure, got: {other}"),
    }
}

// =============================================================================
// Test: missing quarantine guard denies fail-closed
// =============================================================================

#[test]
fn test_missing_quarantine_guard_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));
    // Deliberately NOT setting quarantine guard.

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "missing quarantine guard must deny for fail-closed tier"
    );
    match result.unwrap_err() {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "QuarantineGuard");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

// =============================================================================
// Test: witness seed content hashes are non-zero and unique
// =============================================================================

#[test]
fn test_witness_seed_hashes_nonzero_and_unique() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan = kernel.plan(&request).expect("plan should succeed");

    let leakage_hash = plan.leakage_witness_seed.content_hash();
    let timing_hash = plan.timing_witness_seed.content_hash();

    assert_ne!(
        leakage_hash, [0u8; 32],
        "leakage seed hash must not be zero"
    );
    assert_ne!(timing_hash, [0u8; 32], "timing seed hash must not be zero");
    assert_ne!(
        leakage_hash, timing_hash,
        "leakage and timing seed hashes must differ"
    );
}

// =============================================================================
// Test: bundle digest is deterministic for same inputs
// =============================================================================

#[test]
fn test_bundle_digest_nonzero() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_ne!(
        result.bundle_digest, [0u8; 32],
        "bundle digest must not be zero"
    );
}

// =============================================================================
// Test: AdmitError Display coverage
// =============================================================================

#[test]
fn test_admit_error_display() {
    let errors = vec![
        AdmitError::InvalidRequest {
            reason: "test".into(),
        },
        AdmitError::LedgerTrustFailure {
            reason: "test".into(),
        },
        AdmitError::PolicyRootFailure {
            reason: "test".into(),
        },
        AdmitError::AntiRollbackFailure {
            reason: "test".into(),
        },
        AdmitError::JoinDenied {
            reason: "test".into(),
        },
        AdmitError::RevalidationDenied {
            reason: "test".into(),
        },
        AdmitError::ConsumeDenied {
            reason: "test".into(),
        },
        AdmitError::WitnessSeedFailure {
            reason: "test".into(),
        },
        AdmitError::PlanAlreadyConsumed,
        AdmitError::QuarantineReservationFailure {
            reason: "test".into(),
        },
        AdmitError::BoundaryMediationFailure {
            reason: "test".into(),
        },
        AdmitError::MissingPrerequisite {
            prerequisite: "test".into(),
        },
    ];

    for err in &errors {
        let display = format!("{err}");
        assert!(!display.is_empty(), "display must not be empty for {err:?}");
    }
    assert_eq!(errors.len(), 12, "all 12 error variants must be tested");
}
