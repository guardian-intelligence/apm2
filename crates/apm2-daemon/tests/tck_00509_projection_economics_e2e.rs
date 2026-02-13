//! TCK-00509: End-to-end projection replay economics and lifecycle tests.

use std::sync::{Arc, Mutex};

use apm2_core::crypto::{EventHasher, Hash, Signer};
use apm2_core::economics::{MultiSinkIdentitySnapshotV1, SinkIdentityEntry};
use apm2_core::pcac::{
    AuthorityJoinInputV1, BoundaryIntentClass, IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};
use apm2_daemon::pcac::{InProcessKernel, LifecycleGate};
use apm2_daemon::projection::continuity_resolver::{
    ResolvedContinuityProfile, ResolvedContinuityWindow,
};
use apm2_daemon::projection::intent_buffer::{IntentBuffer, IntentLifecycleArtifacts};
use apm2_daemon::projection::worker::AdmissionTelemetry;
use apm2_daemon::projection::{
    ContinuityProfileResolver, DENY_REPLAY_ECONOMICS_GATE, DENY_REPLAY_HORIZON_OUT_OF_WINDOW,
    DENY_REPLAY_LIFECYCLE_GATE, DeferredReplayWorker, DeferredReplayWorkerConfig, IntentVerdict,
    ProjectionIntent, ReplayCycleResult, ReplayProjectionEffect,
};
use rusqlite::Connection;

const REPLAY_BATCH_SIZE: usize = 16;
const PRIVILEGED_REGISTER_RECOVERY_PREFIX: &str = "pcac-privileged-register-recovery-evidence";

const fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn domain_tagged_hash(handler_prefix: &str, hash_type: &str, data: &[&[u8]]) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    let tag = format!("{handler_prefix}-{hash_type}-v1");
    hasher.update(tag.as_bytes());
    for chunk in data {
        hasher.update(chunk);
    }
    *hasher.finalize().as_bytes()
}

fn build_authority_join_input(
    intent_id: &str,
    work_id: &str,
    changeset_digest: &[u8; 32],
    ledger_head: &[u8; 32],
    eval_tick: u64,
    time_authority_ref: [u8; 32],
    revocation_head: [u8; 32],
) -> AuthorityJoinInputV1 {
    let intent_digest = EventHasher::hash_content(changeset_digest);
    let scope_witness_hash = EventHasher::hash_content(ledger_head);
    let freshness_policy_hash = EventHasher::hash_content(ledger_head);
    let freshness_tick = eval_tick.max(1);
    let capability_manifest_hash = EventHasher::hash_content(changeset_digest);
    let identity_proof_hash = EventHasher::hash_content(work_id.as_bytes());
    let ledger_anchor = EventHasher::hash_content(intent_id.as_bytes());

    let join_tick_bytes = freshness_tick.to_le_bytes();
    let leakage_witness_hash = domain_tagged_hash(
        PRIVILEGED_REGISTER_RECOVERY_PREFIX,
        "boundary_leakage_witness_hash",
        &[&intent_digest, &scope_witness_hash, &join_tick_bytes],
    );
    let timing_witness_hash = domain_tagged_hash(
        PRIVILEGED_REGISTER_RECOVERY_PREFIX,
        "boundary_timing_witness_hash",
        &[&time_authority_ref, &ledger_anchor, &join_tick_bytes],
    );

    AuthorityJoinInputV1 {
        session_id: intent_id.to_string(),
        holon_id: None,
        intent_digest,
        boundary_intent_class: BoundaryIntentClass::Actuate,
        capability_manifest_hash,
        scope_witness_hashes: vec![scope_witness_hash],
        lease_id: work_id.to_string(),
        permeability_receipt_hash: None,
        identity_proof_hash,
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        pointer_only_waiver_hash: None,
        directory_head_hash: revocation_head,
        freshness_policy_hash,
        freshness_witness_tick: freshness_tick,
        stop_budget_profile_digest: capability_manifest_hash,
        pre_actuation_receipt_hashes: Vec::new(),
        leakage_witness_hash,
        timing_witness_hash,
        risk_tier: RiskTier::Tier2Plus,
        determinism_class: apm2_core::pcac::DeterminismClass::Deterministic,
        time_envelope_ref: time_authority_ref,
        as_of_ledger_anchor: ledger_anchor,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum ResolverMode {
    Allow,
    MissingProfile,
}

struct TestContinuityResolver {
    mode: ResolverMode,
    profile: ResolvedContinuityProfile,
    window: ResolvedContinuityWindow,
    snapshot: MultiSinkIdentitySnapshotV1,
}

impl TestContinuityResolver {
    fn new(signer: &Signer) -> Self {
        let identities = vec![
            SinkIdentityEntry {
                sink_id: "sink-a".to_string(),
                identity_digest: EventHasher::hash_content(b"sink-a"),
            },
            SinkIdentityEntry {
                sink_id: "sink-b".to_string(),
                identity_digest: EventHasher::hash_content(b"sink-b"),
            },
        ];

        let mut snapshot = MultiSinkIdentitySnapshotV1 {
            sink_identities: identities,
            snapshot_digest: [0u8; 32],
        };
        snapshot.snapshot_digest = snapshot.compute_digest();

        Self {
            mode: ResolverMode::Allow,
            profile: ResolvedContinuityProfile {
                sink_id: "test-boundary".to_string(),
                outage_window_ticks: 2_000,
                replay_window_ticks: 1_000,
                churn_tolerance: 1,
                partition_tolerance: 1,
                trusted_signer_keys: vec![signer.public_key_bytes()],
            },
            window: ResolvedContinuityWindow {
                boundary_id: "test-boundary".to_string(),
                outage_window_ticks: 2_000,
                replay_window_ticks: 1_000,
            },
            snapshot,
        }
    }

    fn with_missing_profile(signer: &Signer) -> Self {
        let mut resolver = Self::new(signer);
        resolver.mode = ResolverMode::MissingProfile;
        resolver
    }
}

impl ContinuityProfileResolver for TestContinuityResolver {
    fn resolve_continuity_profile(&self, _sink_id: &str) -> Option<ResolvedContinuityProfile> {
        (self.mode == ResolverMode::Allow).then_some(self.profile.clone())
    }

    fn resolve_sink_snapshot(&self, _sink_id: &str) -> Option<MultiSinkIdentitySnapshotV1> {
        Some(self.snapshot.clone())
    }

    fn resolve_continuity_window(&self, _boundary_id: &str) -> Option<ResolvedContinuityWindow> {
        Some(self.window.clone())
    }
}

struct SpyReplayProjectionEffect {
    calls: Arc<Mutex<Vec<String>>>,
    fail_reason: Arc<Mutex<Option<String>>>,
}

impl SpyReplayProjectionEffect {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            fail_reason: Arc::new(Mutex::new(None)),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("projection call log lock should be available")
            .clone()
    }

    fn call_count(&self) -> usize {
        self.calls
            .lock()
            .expect("projection call log lock should be available")
            .len()
    }

    fn never_called(&self) -> bool {
        self.calls().is_empty()
    }
}

impl ReplayProjectionEffect for SpyReplayProjectionEffect {
    fn execute_projection(
        &self,
        work_id: &str,
        _changeset_digest: [u8; 32],
        _ledger_head: [u8; 32],
        _status: apm2_daemon::projection::ProjectedStatus,
    ) -> Result<(), String> {
        let fail_reason = self
            .fail_reason
            .lock()
            .expect("projection fail reason lock should be available")
            .clone();

        if let Some(reason) = fail_reason {
            return Err(reason);
        }

        self.calls
            .lock()
            .expect("projection call log lock should be available")
            .push(work_id.to_string());

        Ok(())
    }
}

struct Harness {
    intent_conn: Arc<Mutex<Connection>>,
    intent_buffer: Arc<IntentBuffer>,
    lifecycle_gate: Arc<LifecycleGate>,
    worker: DeferredReplayWorker,
    effect: Arc<SpyReplayProjectionEffect>,
}

impl Harness {
    fn new(
        resolver: Arc<dyn ContinuityProfileResolver>,
        kernel_start_tick: u64,
        gate_signer: Arc<Signer>,
    ) -> Self {
        let intent_conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory DB should open"),
        ));
        let intent_buffer = Arc::new(
            IntentBuffer::new(Arc::clone(&intent_conn))
                .expect("intent buffer should initialize in-memory"),
        );
        let tick_kernel = Arc::new(InProcessKernel::new(kernel_start_tick));
        let kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> = tick_kernel.clone();
        let lifecycle_gate = Arc::new(LifecycleGate::with_tick_kernel(kernel, tick_kernel));
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let effect = Arc::new(SpyReplayProjectionEffect::new());
        let config =
            DeferredReplayWorkerConfig::new("test-boundary".to_string(), "test-actor".to_string())
                .with_batch_size(REPLAY_BATCH_SIZE);

        let worker = DeferredReplayWorker::new(
            config,
            Arc::clone(&intent_buffer),
            resolver,
            gate_signer,
            lifecycle_gate.clone(),
            telemetry,
            effect.clone(),
        )
        .expect("deferred replay worker should initialize");

        Self {
            intent_conn,
            intent_buffer,
            lifecycle_gate,
            worker,
            effect,
        }
    }

    fn insert_intent(
        &self,
        intent_id: &str,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        eval_tick: u64,
    ) -> bool {
        self.intent_buffer
            .insert(
                intent_id,
                work_id,
                &changeset_digest,
                &ledger_head,
                "success",
                eval_tick,
                eval_tick,
            )
            .expect("insert should not fail")
    }

    fn insert_backlog(&self, intent_id: &str, work_id: &str, replay_horizon_tick: u64) -> bool {
        self.intent_buffer
            .insert_backlog(intent_id, work_id, &digest(0xAA), replay_horizon_tick)
            .expect("insert_backlog should not fail")
    }

    fn insert_intent_with_backlog(
        &self,
        intent_id: &str,
        work_id: &str,
        changeset: [u8; 32],
        ledger_head: [u8; 32],
        eval_tick: u64,
        replay_horizon_tick: u64,
    ) -> bool {
        if !self.insert_intent(intent_id, work_id, changeset, ledger_head, eval_tick) {
            return false;
        }

        assert!(
            self.insert_backlog(intent_id, work_id, replay_horizon_tick),
            "backlog insertion should succeed when intent insert succeeds"
        );

        true
    }

    fn drain(
        &self,
        current_tick: u64,
        time_authority_ref: [u8; 32],
        window_ref: [u8; 32],
        current_revocation_head: [u8; 32],
    ) -> ReplayCycleResult {
        self.worker
            .drain_cycle(
                current_tick,
                time_authority_ref,
                window_ref,
                current_revocation_head,
            )
            .expect("drain cycle should succeed")
    }

    fn intent(&self, intent_id: &str) -> Option<ProjectionIntent> {
        self.intent_buffer
            .get_intent(intent_id)
            .expect("intent lookup should not fail")
    }

    fn effect_calls(&self) -> Vec<String> {
        self.effect.calls()
    }

    fn lifecycle_artifacts_direct(&self, intent_id: &str) -> Option<IntentLifecycleArtifacts> {
        let conn = self
            .intent_conn
            .lock()
            .expect("intent DB lock should be available for artifact query");
        let bytes_to_array = |v: Vec<u8>| -> Option<[u8; 32]> { v.as_slice().try_into().ok() };
        let row = conn
            .query_row(
                "SELECT lifecycle_ajc_id, lifecycle_intent_digest, lifecycle_consume_selector_digest, lifecycle_consume_tick, lifecycle_time_envelope_ref
                 FROM projection_intents
                 WHERE intent_id = ?1
                   AND lifecycle_ajc_id IS NOT NULL
                   AND lifecycle_intent_digest IS NOT NULL
                   AND lifecycle_consume_selector_digest IS NOT NULL
                   AND lifecycle_consume_tick IS NOT NULL
                   AND lifecycle_time_envelope_ref IS NOT NULL",
                [intent_id],
                |row| {
                    let ajc: Vec<u8> = row.get(0)?;
                    let intent: Vec<u8> = row.get(1)?;
                    let selector: Vec<u8> = row.get(2)?;
                    let tick: i64 = row.get(3)?;
                    let envelope: Vec<u8> = row.get(4)?;

                    Ok((
                        bytes_to_array(ajc),
                        bytes_to_array(intent),
                        bytes_to_array(selector),
                        tick,
                        bytes_to_array(envelope),
                    ))
                },
            )
            .ok()?;
        let (ajc_id, intent_digest, consume_selector_digest, consume_tick, time_envelope_ref) = row;
        let (
            Some(ajc_id),
            Some(intent_digest),
            Some(consume_selector_digest),
            Some(time_envelope_ref),
        ) = (
            ajc_id,
            intent_digest,
            consume_selector_digest,
            time_envelope_ref,
        )
        else {
            return None;
        };
        let consume_tick = u64::try_from(consume_tick).ok()?;

        Some(IntentLifecycleArtifacts {
            ajc_id,
            intent_digest,
            consume_selector_digest,
            consume_tick,
            time_envelope_ref,
        })
    }

    fn assert_no_projection_call(&self) {
        assert!(
            self.effect.never_called(),
            "projection effect must not be called"
        );
    }

    fn preconsume_intent_token(
        &self,
        intent_id: &str,
        eval_tick: u64,
        time_authority_ref: [u8; 32],
        revocation_head: [u8; 32],
    ) {
        let intent = self
            .intent(intent_id)
            .expect("intent should exist before preconsumption");

        let join_input = build_authority_join_input(
            &intent.intent_id,
            &intent.work_id,
            &intent.changeset_digest,
            &intent.ledger_head,
            eval_tick,
            time_authority_ref,
            revocation_head,
        );

        let policy = PcacPolicyKnobs::default();
        self.lifecycle_gate.advance_tick(eval_tick);
        let cert = self
            .lifecycle_gate
            .join_and_revalidate(
                &join_input,
                time_authority_ref,
                EventHasher::hash_content(intent.intent_id.as_bytes()),
                revocation_head,
                &policy,
            )
            .expect("join_and_revalidate should succeed for preconsume");

        self.lifecycle_gate.advance_tick(eval_tick);
        self.lifecycle_gate
            .revalidate_before_execution(
                &cert,
                time_authority_ref,
                EventHasher::hash_content(intent.intent_id.as_bytes()),
                revocation_head,
                &policy,
            )
            .expect("revalidate_before_execution should succeed for preconsume");

        self.lifecycle_gate.advance_tick(eval_tick);
        let (consumed_witness, consume_record) = self
            .lifecycle_gate
            .consume_before_effect(
                &cert,
                intent_digest_for_join(&intent),
                join_input.boundary_intent_class,
                true,
                time_authority_ref,
                revocation_head,
                &policy,
            )
            .expect("consume_before_effect should mark token consumed before drain");

        let _ = (consumed_witness, consume_record);
    }
}

fn intent_digest_for_join(intent: &ProjectionIntent) -> Hash {
    EventHasher::hash_content(&intent.changeset_digest)
}

fn ledger_anchor(intent_id: &str) -> Hash {
    EventHasher::hash_content(intent_id.as_bytes())
}

fn assert_projected_path(artifact: &IntentLifecycleArtifacts, intent: &ProjectionIntent) {
    assert_ne!(artifact.ajc_id, [0u8; 32]);
    assert_ne!(artifact.time_envelope_ref, [0u8; 32]);
    assert_eq!(artifact.intent_digest, intent_digest_for_join(intent));
}

fn assert_deny_with_reason(
    harness: &Harness,
    intent_id: &str,
    reason_prefix: &str,
    result: &ReplayCycleResult,
) {
    harness.assert_no_projection_call();
    assert!(result.denied_count > 0 || result.expired_count > 0);
    let intent = harness
        .intent(intent_id)
        .expect("intent should still exist after deny path");
    assert_eq!(intent.verdict, IntentVerdict::Denied);
    assert!(
        intent.deny_reason.contains(reason_prefix),
        "unexpected deny reason: {}",
        intent.deny_reason
    );
}

#[test]
fn test_happy_path_economics_allow_lifecycle_allow_projects() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-happy-001",
        "work-happy-001",
        digest(0x10),
        digest(0x55),
        100,
        100,
    );
    assert!(inserted);

    let result = harness.drain(
        100,
        digest(0xAA),
        digest(0xBB),
        ledger_anchor("intent-happy-001"),
    );

    assert!(result.replayed_count > 0);
    let calls = harness.effect_calls();
    assert_eq!(calls.as_slice(), ["work-happy-001"]);

    let intent = harness
        .intent("intent-happy-001")
        .expect("intent should exist");
    assert_eq!(intent.verdict, IntentVerdict::Admitted);
    assert!(result.converged);

    let artifacts = harness
        .lifecycle_artifacts_direct("intent-happy-001")
        .expect("lifecycle artifacts should be attached");
    assert_projected_path(&artifacts, &intent);
}

#[test]
fn test_deny_stale_temporal_authority() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 1_000, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-stale-temporal-001",
        "work-stale-temporal-001",
        digest(0x11),
        digest(0x56),
        10,
        10,
    );
    assert!(inserted);

    harness.preconsume_intent_token(
        "intent-stale-temporal-001",
        10,
        digest(0xAA),
        ledger_anchor("intent-stale-temporal-001"),
    );

    let result = harness.drain(
        10,
        digest(0xAA),
        digest(0xBB),
        ledger_anchor("intent-stale-temporal-001"),
    );

    assert_deny_with_reason(
        &harness,
        "intent-stale-temporal-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        &result,
    );
}

#[test]
fn test_deny_missing_continuity_profile() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::with_missing_profile(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-missing-profile-001",
        "work-missing-profile-001",
        digest(0x12),
        digest(0x57),
        100,
        100,
    );
    assert!(inserted);

    let result = harness.drain(
        100,
        digest(0xAA),
        digest(0xBB),
        ledger_anchor("intent-missing-profile-001"),
    );

    assert_deny_with_reason(
        &harness,
        "intent-missing-profile-001",
        DENY_REPLAY_ECONOMICS_GATE,
        &result,
    );
}

#[test]
fn test_lifecycle_deny_revoked_authority() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-revoked-001",
        "work-revoked-001",
        digest(0x13),
        digest(0x58),
        100,
        100,
    );
    assert!(inserted);

    let revoked_revocation = ledger_anchor("intent-revoked-001");
    harness.preconsume_intent_token("intent-revoked-001", 100, digest(0xAA), revoked_revocation);
    let result = harness.drain(100, digest(0xAA), digest(0xBB), revoked_revocation);

    assert_deny_with_reason(
        &harness,
        "intent-revoked-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        &result,
    );
}

#[test]
fn test_lifecycle_deny_consumed_token() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-consumed-001",
        "work-consumed-001",
        digest(0x14),
        digest(0x59),
        200,
        200,
    );
    assert!(inserted);

    let preconsume_tick = 200;
    let time_authority_ref = digest(0xAA);
    let revocation_head = ledger_anchor("intent-consumed-001");

    // Pre-consume the lifecycle token in the same gate before replay.
    harness.preconsume_intent_token(
        "intent-consumed-001",
        preconsume_tick,
        time_authority_ref,
        revocation_head,
    );

    let result = harness.drain(
        preconsume_tick,
        time_authority_ref,
        digest(0xBB),
        revocation_head,
    );

    assert_deny_with_reason(
        &harness,
        "intent-consumed-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        &result,
    );
}

#[test]
fn test_lifecycle_deny_stale_authority_freshness() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 2_000, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-stale-freshness-001",
        "work-stale-freshness-001",
        digest(0x15),
        digest(0x5A),
        150,
        150,
    );
    assert!(inserted);

    harness.preconsume_intent_token(
        "intent-stale-freshness-001",
        150,
        digest(0xAA),
        ledger_anchor("intent-stale-freshness-001"),
    );

    let result = harness.drain(
        150,
        digest(0xAA),
        digest(0xBB),
        ledger_anchor("intent-stale-freshness-001"),
    );

    assert_deny_with_reason(
        &harness,
        "intent-stale-freshness-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        &result,
    );
}

#[test]
fn test_outage_recovery_replay_in_order() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    assert!(harness.insert_intent_with_backlog(
        "intent-order-001",
        "work-order-001",
        digest(0x16),
        digest(0x61),
        300,
        300,
    ));
    assert!(harness.insert_intent_with_backlog(
        "intent-order-002",
        "work-order-002",
        digest(0x17),
        digest(0x62),
        300,
        300,
    ));
    assert!(harness.insert_intent_with_backlog(
        "intent-order-003",
        "work-order-003",
        digest(0x18),
        digest(0x63),
        300,
        300,
    ));

    let result = harness.drain(300, digest(0xAA), digest(0xBB), digest(0xCC));

    assert_eq!(result.replayed_count, 3);
    assert!(result.converged);

    let calls = harness.effect_calls();
    assert_eq!(
        calls,
        vec![
            "work-order-001".to_string(),
            "work-order-002".to_string(),
            "work-order-003".to_string(),
        ]
    );
}

#[test]
fn test_outage_revoked_authority_replay_deny() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-outage-revoked-001",
        "work-outage-revoked-001",
        digest(0x19),
        digest(0x64),
        400,
        400,
    );
    assert!(inserted);

    let revoked_frontier = ledger_anchor("intent-outage-revoked-001");
    harness.preconsume_intent_token(
        "intent-outage-revoked-001",
        400,
        digest(0xAA),
        ledger_anchor("intent-outage-revoked-001"),
    );
    let result = harness.drain(400, digest(0xAA), digest(0xBB), revoked_frontier);

    assert_deny_with_reason(
        &harness,
        "intent-outage-revoked-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        &result,
    );
}

#[test]
fn test_window_expiration() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    let inserted = harness.insert_intent_with_backlog(
        "intent-expired-001",
        "work-expired-001",
        digest(0x1A),
        digest(0x65),
        5,
        5,
    );
    assert!(inserted);

    // Resolver replay window is 1_000 ticks, so this is far beyond window
    // and should expire as DENY_REPLAY_HORIZON_OUT_OF_WINDOW.
    let result = harness.drain(
        5_000,
        digest(0xAA),
        digest(0xBB),
        ledger_anchor("intent-expired-001"),
    );

    let intent = harness
        .intent("intent-expired-001")
        .expect("intent should exist");
    assert_eq!(intent.verdict, IntentVerdict::Denied);
    assert!(result.denied_count > 0 || result.expired_count > 0);
    assert!(
        intent
            .deny_reason
            .contains(DENY_REPLAY_HORIZON_OUT_OF_WINDOW)
    );
    harness.assert_no_projection_call();
}

#[test]
fn test_idempotency_same_work_changeset() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));

    assert!(harness.insert_intent_with_backlog(
        "intent-idempotent-001",
        "work-idempotent",
        digest(0x1B),
        digest(0x66),
        600,
        600,
    ));

    let second = harness.insert_intent(
        "intent-idempotent-002",
        "work-idempotent",
        digest(0x1B),
        digest(0x66),
        600,
    );
    assert!(!second, "same (work_id, changeset) must be rejected");

    let result = harness.drain(
        600,
        digest(0xAA),
        digest(0xBB),
        ledger_anchor("intent-idempotent-001"),
    );

    assert!(result.replayed_count > 0);
    assert_eq!(harness.effect.call_count(), 1);

    let intent = harness
        .intent("intent-idempotent-001")
        .expect("intent should exist");
    assert_eq!(intent.verdict, IntentVerdict::Admitted);

    let maybe_already_projected = harness
        .intent_buffer
        .query_by_verdict(IntentVerdict::Admitted, 10)
        .expect("query by verdict should succeed")
        .into_iter()
        .any(|i| i.intent_id == "intent-idempotent-001");
    assert!(maybe_already_projected);
}
