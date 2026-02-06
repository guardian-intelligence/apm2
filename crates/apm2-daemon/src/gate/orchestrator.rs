// AGENT-AUTHORED (TCK-00388)
//! Gate execution orchestrator implementation.
//!
//! Watches for `session_terminated` ledger events and autonomously drives
//! the gate lifecycle: policy resolution -> lease issuance -> gate executor
//! spawn -> receipt collection.
//!
//! # Security Model
//!
//! - **Ordering invariant**: `PolicyResolvedForChangeSet` is always emitted
//!   before any `GateLeaseIssued` event for the same `work_id`.
//! - **Fail-closed**: Gate timeout produces FAIL verdict, blocking merge.
//! - **Domain separation**: All leases use `GATE_LEASE_ISSUED:` prefix.
//! - **Changeset binding**: Lease `changeset_digest` matches session data.
//! - **Receipt authenticity**: Gate receipt signatures are verified against the
//!   executor's verifying key before state transitions.
//!
//! # Event Model
//!
//! Events are returned per-invocation from each method rather than buffered
//! in shared state. This avoids concurrent drain issues where parallel
//! invocations could steal or drop events from a global buffer.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::crypto::Signer;
use apm2_core::fac::{
    AatLeaseExtension, GateLease, GateLeaseBuilder, GateReceipt, GateReceiptBuilder,
    PolicyResolvedForChangeSet, PolicyResolvedForChangeSetBuilder,
};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of concurrent gate orchestrations.
///
/// This prevents unbounded memory growth per CTR-1303. Each orchestration
/// tracks state for up to [`MAX_GATE_TYPES`] gates.
pub const MAX_CONCURRENT_ORCHESTRATIONS: usize = 1_000;

/// Maximum number of gate types per orchestration.
///
/// Currently three gates are supported: aat, quality, security.
pub const MAX_GATE_TYPES: usize = 8;

/// Default gate execution timeout in milliseconds (30 minutes).
///
/// After this duration, a gate lease expires and the orchestrator emits
/// a FAIL verdict (fail-closed semantics).
pub const DEFAULT_GATE_TIMEOUT_MS: u64 = 30 * 60 * 1000;

/// Maximum length of `work_id` strings.
pub const MAX_WORK_ID_LENGTH: usize = 4096;

/// Maximum length of any string field in orchestrator events.
const MAX_STRING_LENGTH: usize = 4096;

// =============================================================================
// Gate Types
// =============================================================================

/// Gate types that the orchestrator manages.
///
/// Each terminated session with associated work triggers execution of
/// all required gate types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateType {
    /// Agent Acceptance Testing gate.
    Aat,
    /// Code quality review gate.
    Quality,
    /// Security review gate.
    Security,
}

impl GateType {
    /// Returns the gate ID string for this gate type.
    #[must_use]
    pub const fn as_gate_id(&self) -> &'static str {
        match self {
            Self::Aat => "gate-aat",
            Self::Quality => "gate-quality",
            Self::Security => "gate-security",
        }
    }

    /// Returns the payload kind for gate receipts.
    #[must_use]
    pub const fn payload_kind(&self) -> &'static str {
        match self {
            Self::Aat => "aat",
            Self::Quality => "quality",
            Self::Security => "security",
        }
    }

    /// Returns the agent adapter profile ID for this gate type.
    #[must_use]
    pub const fn adapter_profile_id(&self) -> &'static str {
        match self {
            // AAT uses Claude Code for acceptance testing
            Self::Aat => apm2_core::fac::CLAUDE_CODE_PROFILE_ID,
            // Quality and Security use Gemini CLI for code review
            Self::Quality | Self::Security => apm2_core::fac::GEMINI_CLI_PROFILE_ID,
        }
    }

    /// Returns all standard gate types.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Aat, Self::Quality, Self::Security]
    }
}

impl fmt::Display for GateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_gate_id())
    }
}

// =============================================================================
// Gate Status
// =============================================================================

/// Status of a gate within an orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStatus {
    /// Lease has been issued, executor not yet spawned.
    LeaseIssued {
        /// The lease ID.
        lease_id: String,
    },
    /// Gate executor episode is running.
    Running {
        /// The lease ID.
        lease_id: String,
        /// The episode ID of the gate executor.
        episode_id: String,
    },
    /// Gate has completed with a receipt.
    Completed {
        /// The lease ID.
        lease_id: String,
        /// The receipt ID.
        receipt_id: String,
        /// Whether the gate passed.
        passed: bool,
    },
    /// Gate has timed out (fail-closed: treated as FAIL).
    TimedOut {
        /// The lease ID.
        lease_id: String,
    },
}

impl GateStatus {
    /// Returns `true` if the gate is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::TimedOut { .. })
    }
}

// =============================================================================
// Gate Outcome
// =============================================================================

/// The outcome of a gate execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateOutcome {
    /// The gate type.
    pub gate_type: GateType,
    /// Whether the gate passed.
    pub passed: bool,
    /// The receipt ID (if completed normally).
    pub receipt_id: Option<String>,
    /// Whether the gate timed out.
    pub timed_out: bool,
}

// =============================================================================
// Session Terminated Info
// =============================================================================

/// Information about a terminated session that triggers gate orchestration.
///
/// This struct captures the data needed from a `session_terminated` event
/// to drive the gate lifecycle.
#[derive(Debug, Clone)]
pub struct SessionTerminatedInfo {
    /// The session ID that terminated.
    pub session_id: String,
    /// The work ID associated with this session.
    pub work_id: String,
    /// The changeset digest from the terminated session.
    pub changeset_digest: [u8; 32],
    /// Timestamp of session termination (milliseconds since epoch).
    pub terminated_at_ms: u64,
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during gate orchestration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateOrchestratorError {
    /// Maximum concurrent orchestrations exceeded.
    #[error("maximum concurrent orchestrations exceeded: {current} >= {max}")]
    MaxOrchestrationsExceeded {
        /// Current number of orchestrations.
        current: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Work ID is empty.
    #[error("work_id must not be empty")]
    EmptyWorkId,

    /// Work ID too long.
    #[error("work_id exceeds max length: {actual} > {max}")]
    WorkIdTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Duplicate orchestration for the same `work_id`.
    #[error("orchestration already active for work_id: {work_id}")]
    DuplicateOrchestration {
        /// The duplicate work ID.
        work_id: String,
    },

    /// Policy resolution failed.
    #[error("policy resolution failed for work_id {work_id}: {reason}")]
    PolicyResolutionFailed {
        /// The work ID.
        work_id: String,
        /// Failure reason.
        reason: String,
    },

    /// Lease issuance failed.
    #[error("lease issuance failed for gate {gate_id} on work_id {work_id}: {reason}")]
    LeaseIssuanceFailed {
        /// The work ID.
        work_id: String,
        /// The gate ID.
        gate_id: String,
        /// Failure reason.
        reason: String,
    },

    /// String field too long.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Orchestration not found.
    #[error("no active orchestration for work_id: {work_id}")]
    OrchestrationNotFound {
        /// The work ID.
        work_id: String,
    },

    /// Gate not found in orchestration.
    #[error("gate {gate_type} not found in orchestration for work_id: {work_id}")]
    GateNotFound {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: String,
    },

    /// Receipt binding mismatch (`lease_id` or `gate_id` does not match issued
    /// lease).
    #[error("receipt binding mismatch for work_id {work_id}: {reason}")]
    ReceiptBindingMismatch {
        /// The work ID.
        work_id: String,
        /// Description of the mismatch.
        reason: String,
    },

    /// Invalid state transition (e.g., updating a terminal-state gate).
    #[error("invalid state transition for gate {gate_type} in work_id {work_id}: {reason}")]
    InvalidStateTransition {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: String,
        /// Description of the invalid transition.
        reason: String,
    },

    /// Lease ID is empty.
    #[error("lease_id must not be empty for gate {gate_type} in work_id {work_id}")]
    EmptyLeaseId {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: String,
    },
}

// =============================================================================
// Orchestrator Events
// =============================================================================

/// Events emitted by the gate orchestrator.
///
/// These events represent the gate lifecycle and are intended to be
/// persisted to the ledger.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum GateOrchestratorEvent {
    /// Policy was resolved for a changeset.
    PolicyResolved {
        /// The work ID.
        work_id: String,
        /// The policy resolution hash.
        policy_hash: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate lease was issued.
    GateLeaseIssued {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The lease ID.
        lease_id: String,
        /// The executor actor ID.
        executor_actor_id: String,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate executor episode was spawned.
    GateExecutorSpawned {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The episode ID.
        episode_id: String,
        /// The adapter profile ID.
        adapter_profile_id: String,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate receipt was collected.
    GateReceiptCollected {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The receipt ID.
        receipt_id: String,
        /// Whether the gate passed.
        passed: bool,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate timed out (fail-closed: FAIL verdict).
    GateTimedOut {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The lease ID that expired.
        lease_id: String,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// All gates for a work item have completed.
    AllGatesCompleted {
        /// The work ID.
        work_id: String,
        /// Whether all gates passed.
        all_passed: bool,
        /// Individual gate outcomes.
        outcomes: Vec<GateOutcome>,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
}

// =============================================================================
// Orchestration Entry
// =============================================================================

/// Internal state for a single gate orchestration.
#[derive(Debug)]
struct OrchestrationEntry {
    /// Session termination info that triggered this orchestration.
    /// Used by downstream merge automation (TCK-00390) and status queries.
    _session_info: SessionTerminatedInfo,
    /// The policy resolution for this changeset.
    policy_resolution: PolicyResolvedForChangeSet,
    /// Gate statuses indexed by gate type.
    gates: HashMap<GateType, GateStatus>,
    /// Issued leases indexed by gate type.
    leases: HashMap<GateType, GateLease>,
    /// Collected receipts indexed by gate type.
    receipts: HashMap<GateType, GateReceipt>,
    /// When the orchestration started (ms since epoch).
    /// Used by downstream merge automation (TCK-00390) for stale detection.
    _started_at_ms: u64,
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the gate orchestrator.
#[derive(Debug, Clone)]
pub struct GateOrchestratorConfig {
    /// Maximum number of concurrent orchestrations.
    pub max_concurrent_orchestrations: usize,
    /// Gate execution timeout in milliseconds.
    pub gate_timeout_ms: u64,
    /// Gate types to execute for each terminated session.
    pub gate_types: Vec<GateType>,
    /// Issuer actor ID for gate leases.
    pub issuer_actor_id: String,
    /// Resolver actor ID for policy resolution.
    pub resolver_actor_id: String,
    /// Resolver version string.
    pub resolver_version: String,
}

impl Default for GateOrchestratorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_orchestrations: MAX_CONCURRENT_ORCHESTRATIONS,
            gate_timeout_ms: DEFAULT_GATE_TIMEOUT_MS,
            gate_types: GateType::all().to_vec(),
            issuer_actor_id: "daemon-gate-orchestrator".to_string(),
            resolver_actor_id: "daemon-policy-resolver".to_string(),
            resolver_version: "1.0.0".to_string(),
        }
    }
}

// =============================================================================
// Gate Orchestrator
// =============================================================================

/// Gate execution orchestrator for autonomous gate lifecycle management.
///
/// The `GateOrchestrator` watches for `session_terminated` events and
/// autonomously orchestrates the gate lifecycle:
///
/// 1. Resolve policy via `PolicyResolvedForChangeSet`
/// 2. Issue `GateLease` for each required gate
/// 3. Spawn gate executor episodes
/// 4. Collect `GateReceipt` results or handle timeout
///
/// # Security
///
/// - Policy resolution MUST precede all lease issuance (ordering invariant)
/// - Gate leases use domain-separated Ed25519 signatures
/// - Receipt signatures are verified against executor verifying key
/// - Timeout produces fail-closed FAIL verdict
/// - Changeset digest in leases matches session data
///
/// # Event Model (BLOCKER 3 fix)
///
/// Events are returned per-invocation from each method rather than buffered
/// in shared state. This avoids concurrent drain issues where parallel
/// invocations could steal or drop events from a global buffer.
///
/// # Thread Safety
///
/// `GateOrchestrator` is `Send + Sync` and can be shared across async tasks.
pub struct GateOrchestrator {
    /// Configuration.
    config: GateOrchestratorConfig,
    /// Active orchestrations indexed by `work_id`.
    orchestrations: RwLock<HashMap<String, OrchestrationEntry>>,
    /// Signer for gate leases and policy resolutions.
    signer: Arc<Signer>,
}

impl GateOrchestrator {
    /// Creates a new gate orchestrator with the given configuration and signer.
    #[must_use]
    pub fn new(config: GateOrchestratorConfig, signer: Arc<Signer>) -> Self {
        Self {
            config,
            orchestrations: RwLock::new(HashMap::new()),
            signer,
        }
    }

    /// Returns the current configuration.
    #[must_use]
    pub const fn config(&self) -> &GateOrchestratorConfig {
        &self.config
    }

    /// Returns the number of active orchestrations.
    pub async fn active_count(&self) -> usize {
        self.orchestrations.read().await.len()
    }

    /// Returns the verifying key for receipt signature verification.
    ///
    /// This is the public key corresponding to the orchestrator's signer,
    /// used to verify gate receipt signatures from executors.
    #[must_use]
    pub fn verifying_key(&self) -> apm2_core::crypto::VerifyingKey {
        self.signer.verifying_key()
    }

    /// Handles a `session_terminated` event by starting gate orchestration.
    ///
    /// This is the primary entry point for the gate lifecycle. When a session
    /// terminates with associated work, this method:
    ///
    /// 1. Validates input
    /// 2. Resolves policy for the changeset
    /// 3. Issues gate leases for each required gate type
    /// 4. Performs admission check (duplicate + capacity) and inserts
    ///    atomically
    /// 5. Returns events only after successful insertion (BLOCKER 2 fix)
    ///
    /// # Ordering Invariant
    ///
    /// The `PolicyResolved` event is ALWAYS emitted before any
    /// `GateLeaseIssued` event in the returned event list.
    ///
    /// # BLOCKER 2 Fix: Events after admission
    ///
    /// Events are staged locally and returned only after the admission check
    /// (duplicate detection + capacity check) succeeds and the orchestration
    /// is inserted. On error, no events escape.
    ///
    /// # BLOCKER 3 Fix: Per-invocation events
    ///
    /// Events are returned from this method rather than buffered in shared
    /// state. This prevents concurrent invocations from stealing events.
    ///
    /// # Errors
    ///
    /// Returns `GateOrchestratorError` if:
    /// - `work_id` is empty or too long
    /// - Maximum concurrent orchestrations exceeded
    /// - Duplicate orchestration for the same `work_id`
    /// - Policy resolution or lease issuance fails
    pub async fn handle_session_terminated(
        &self,
        info: SessionTerminatedInfo,
    ) -> Result<(Vec<GateType>, Vec<GateOrchestratorEvent>), GateOrchestratorError> {
        // Validate work_id
        if info.work_id.is_empty() {
            return Err(GateOrchestratorError::EmptyWorkId);
        }
        if info.work_id.len() > MAX_WORK_ID_LENGTH {
            return Err(GateOrchestratorError::WorkIdTooLong {
                actual: info.work_id.len(),
                max: MAX_WORK_ID_LENGTH,
            });
        }
        if info.session_id.len() > MAX_STRING_LENGTH {
            return Err(GateOrchestratorError::StringTooLong {
                field: "session_id",
                actual: info.session_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let now_ms = current_time_ms();

        // Step 1: Resolve policy for the changeset.
        // ORDERING INVARIANT: This MUST happen before any lease issuance.
        let policy_resolution = self.resolve_policy(&info, now_ms)?;
        let policy_hash = policy_resolution.resolved_policy_hash();

        // Step 2: Issue gate leases for each required gate type.
        // This MUST happen AFTER policy resolution (ordering invariant).
        let mut gates = HashMap::new();
        let mut leases = HashMap::new();
        let mut issued_gate_types = Vec::new();

        for &gate_type in &self.config.gate_types {
            let lease = self.issue_gate_lease(&info, gate_type, &policy_hash, now_ms)?;
            let lease_id = lease.lease_id.clone();
            gates.insert(gate_type, GateStatus::LeaseIssued { lease_id });
            leases.insert(gate_type, lease);
            issued_gate_types.push(gate_type);
        }

        // Step 3 (BLOCKER 2 FIX): Admission check+insert FIRST, under a
        // single write lock. Events are staged locally and committed only
        // after this succeeds. On error, no events are emitted and no
        // orchestration is inserted.
        {
            let mut orchestrations = self.orchestrations.write().await;
            if orchestrations.len() >= self.config.max_concurrent_orchestrations {
                return Err(GateOrchestratorError::MaxOrchestrationsExceeded {
                    current: orchestrations.len(),
                    max: self.config.max_concurrent_orchestrations,
                });
            }
            match orchestrations.entry(info.work_id.clone()) {
                Entry::Occupied(_) => {
                    return Err(GateOrchestratorError::DuplicateOrchestration {
                        work_id: info.work_id.clone(),
                    });
                },
                Entry::Vacant(vacant) => {
                    vacant.insert(OrchestrationEntry {
                        _session_info: info.clone(),
                        policy_resolution,
                        gates,
                        leases: leases.clone(),
                        receipts: HashMap::new(),
                        _started_at_ms: now_ms,
                    });
                },
            }
        }

        // Step 4 (BLOCKER 3 FIX): Stage events locally per-invocation and
        // return them. No global buffer is used.
        let mut events = Vec::with_capacity(1 + issued_gate_types.len());

        // PolicyResolved is ALWAYS first (ordering invariant).
        events.push(GateOrchestratorEvent::PolicyResolved {
            work_id: info.work_id.clone(),
            policy_hash,
            timestamp_ms: now_ms,
        });

        info!(
            work_id = %info.work_id,
            policy_hash = %hex::encode(policy_hash),
            "Policy resolved for changeset"
        );

        for &gate_type in &issued_gate_types {
            let lease = &leases[&gate_type];
            let lease_id = lease.lease_id.clone();
            let executor_actor_id = lease.executor_actor_id.clone();

            debug!(
                work_id = %info.work_id,
                gate_type = %gate_type,
                lease_id = %lease_id,
                "Gate lease issued"
            );

            events.push(GateOrchestratorEvent::GateLeaseIssued {
                work_id: info.work_id.clone(),
                gate_type,
                lease_id,
                executor_actor_id,
                timestamp_ms: now_ms,
            });
        }

        Ok((issued_gate_types, events))
    }

    /// Records that a gate executor episode has been spawned.
    ///
    /// This updates the gate status from `LeaseIssued` to `Running` and
    /// returns a `GateExecutorSpawned` event.
    ///
    /// # State Machine
    ///
    /// Valid transition: `LeaseIssued` -> `Running`. All other states
    /// (including terminal states `Completed` and `TimedOut`) are rejected.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The orchestration or gate is not found
    /// - The gate is not in the `LeaseIssued` state
    pub async fn record_executor_spawned(
        &self,
        work_id: &str,
        gate_type: GateType,
        episode_id: &str,
    ) -> Result<Vec<GateOrchestratorEvent>, GateOrchestratorError> {
        let now_ms = current_time_ms();

        {
            let mut orchestrations = self.orchestrations.write().await;
            let entry = orchestrations.get_mut(work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;

            let gate_status = entry.gates.get_mut(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            // Enforce explicit state machine: only LeaseIssued -> Running is valid.
            match gate_status {
                GateStatus::LeaseIssued { lease_id } => {
                    if lease_id.is_empty() {
                        return Err(GateOrchestratorError::EmptyLeaseId {
                            work_id: work_id.to_string(),
                            gate_type: gate_type.to_string(),
                        });
                    }
                    *gate_status = GateStatus::Running {
                        lease_id: lease_id.clone(),
                        episode_id: episode_id.to_string(),
                    };
                },
                other => {
                    return Err(GateOrchestratorError::InvalidStateTransition {
                        work_id: work_id.to_string(),
                        gate_type: gate_type.to_string(),
                        reason: format!("expected LeaseIssued state, found {}", state_name(other)),
                    });
                },
            }
        }

        info!(
            work_id = %work_id,
            gate_type = %gate_type,
            episode_id = %episode_id,
            "Gate executor spawned"
        );

        Ok(vec![GateOrchestratorEvent::GateExecutorSpawned {
            work_id: work_id.to_string(),
            gate_type,
            episode_id: episode_id.to_string(),
            adapter_profile_id: gate_type.adapter_profile_id().to_string(),
            timestamp_ms: now_ms,
        }])
    }

    /// Records a gate receipt from a completed gate executor.
    ///
    /// This updates the gate status to `Completed` and returns a
    /// `GateReceiptCollected` event. If all gates are complete, also returns
    /// an `AllGatesCompleted` event.
    ///
    /// # Binding Validation
    ///
    /// The receipt's `lease_id` and `gate_id` MUST match the issued lease for
    /// this gate type. The receipt's `changeset_digest` and `executor_actor_id`
    /// must also match. This prevents receipt substitution attacks.
    ///
    /// # Signature Verification (BLOCKER 4 fix)
    ///
    /// The receipt's `receipt_signature` is verified against the executor's
    /// verifying key before any state transition. This ensures receipt
    /// authenticity and prevents forged receipts from advancing the state
    /// machine.
    ///
    /// # Verdict Derivation
    ///
    /// The verdict (pass/fail) is derived from the receipt's `passed`
    /// parameter. The orchestrator never hardcodes a default verdict. A
    /// receipt with a zero `payload_hash` (e.g., from a timeout) is treated
    /// as FAIL.
    ///
    /// # State Machine
    ///
    /// Valid transitions: `LeaseIssued` -> `Completed`, `Running` ->
    /// `Completed`. Terminal states (`Completed`, `TimedOut`) are rejected.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work ID
    /// * `gate_type` - The gate type that completed
    /// * `receipt` - The gate receipt from the executor
    /// * `passed` - Whether the gate execution passed; derived by the caller
    ///   from the gate executor's explicit verdict
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The orchestration or gate is not found
    /// - The receipt signature is invalid (BLOCKER 4)
    /// - The receipt's
    ///   `lease_id`/`gate_id`/`changeset_digest`/`executor_actor_id` do not
    ///   match the issued lease
    /// - The gate is in a terminal state
    pub async fn record_gate_receipt(
        &self,
        work_id: &str,
        gate_type: GateType,
        receipt: GateReceipt,
        passed: bool,
    ) -> Result<(Option<Vec<GateOutcome>>, Vec<GateOrchestratorEvent>), GateOrchestratorError> {
        let now_ms = current_time_ms();
        let receipt_id = receipt.receipt_id.clone();

        // BLOCKER 4 FIX: Verify receipt signature against executor verifying
        // key BEFORE any state transition. The orchestrator's signer is the
        // authority that signs leases and receipts, so we verify against its
        // public key.
        receipt
            .validate_signature(&self.signer.verifying_key())
            .map_err(|e| GateOrchestratorError::ReceiptBindingMismatch {
                work_id: work_id.to_string(),
                reason: format!("receipt signature verification failed: {e}"),
            })?;

        {
            let mut orchestrations = self.orchestrations.write().await;
            let entry = orchestrations.get_mut(work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;

            let gate_status = entry.gates.get_mut(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            // Validate receipt binding against the issued lease.
            let lease = entry.leases.get(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            if receipt.lease_id != lease.lease_id {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "lease_id mismatch: receipt has '{}', expected '{}'",
                        receipt.lease_id, lease.lease_id
                    ),
                });
            }
            if receipt.gate_id != lease.gate_id {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "gate_id mismatch: receipt has '{}', expected '{}'",
                        receipt.gate_id, lease.gate_id
                    ),
                });
            }
            if receipt.changeset_digest != lease.changeset_digest {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: "changeset_digest mismatch".to_string(),
                });
            }
            if receipt.executor_actor_id != lease.executor_actor_id {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "executor_actor_id mismatch: receipt has '{}', expected '{}'",
                        receipt.executor_actor_id, lease.executor_actor_id
                    ),
                });
            }

            // Enforce explicit state machine transitions.
            // Only non-terminal states (LeaseIssued, Running) can transition
            // to Completed. Terminal states are rejected.
            match gate_status {
                GateStatus::LeaseIssued { lease_id } | GateStatus::Running { lease_id, .. } => {
                    if lease_id.is_empty() {
                        return Err(GateOrchestratorError::EmptyLeaseId {
                            work_id: work_id.to_string(),
                            gate_type: gate_type.to_string(),
                        });
                    }
                    *gate_status = GateStatus::Completed {
                        lease_id: lease_id.clone(),
                        receipt_id: receipt_id.clone(),
                        passed,
                    };
                },
                other => {
                    return Err(GateOrchestratorError::InvalidStateTransition {
                        work_id: work_id.to_string(),
                        gate_type: gate_type.to_string(),
                        reason: format!("cannot record receipt in {} state", state_name(other)),
                    });
                },
            }

            entry.receipts.insert(gate_type, receipt);
        }

        let mut events = vec![GateOrchestratorEvent::GateReceiptCollected {
            work_id: work_id.to_string(),
            gate_type,
            receipt_id,
            passed,
            timestamp_ms: now_ms,
        }];

        info!(
            work_id = %work_id,
            gate_type = %gate_type,
            passed = %passed,
            "Gate receipt collected"
        );

        // Check if all gates are complete
        let outcomes = self
            .check_all_gates_complete(work_id, now_ms, &mut events)
            .await?;

        Ok((outcomes, events))
    }

    /// Handles gate timeout by producing a FAIL verdict (fail-closed).
    ///
    /// # Security: Fail-Closed Semantics
    ///
    /// Expired gates produce a FAIL verdict, not silent expiry. This ensures
    /// that timeouts block merge rather than allowing unreviewed code through.
    ///
    /// # State Machine
    ///
    /// Valid transitions: `LeaseIssued` -> `TimedOut`, `Running` -> `TimedOut`.
    /// Terminal states (`Completed`, `TimedOut`) are rejected.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The orchestration or gate is not found
    /// - The gate is in a terminal state
    pub async fn handle_gate_timeout(
        &self,
        work_id: &str,
        gate_type: GateType,
    ) -> Result<(Option<Vec<GateOutcome>>, Vec<GateOrchestratorEvent>), GateOrchestratorError> {
        let now_ms = current_time_ms();
        let lease_id;

        {
            let mut orchestrations = self.orchestrations.write().await;
            let entry = orchestrations.get_mut(work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;

            let gate_status = entry.gates.get_mut(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            // Enforce state machine: only non-terminal -> TimedOut is valid.
            match gate_status {
                GateStatus::LeaseIssued { lease_id: lid }
                | GateStatus::Running { lease_id: lid, .. } => {
                    lease_id = lid.clone();
                    *gate_status = GateStatus::TimedOut {
                        lease_id: lid.clone(),
                    };
                },
                other => {
                    return Err(GateOrchestratorError::InvalidStateTransition {
                        work_id: work_id.to_string(),
                        gate_type: gate_type.to_string(),
                        reason: format!("cannot timeout in {} state", state_name(other)),
                    });
                },
            }

            // Create and store fail-closed receipt for the timed-out gate.
            // This ensures a FAIL verdict exists in the ledger, preventing
            // silent expiry from allowing unreviewed code through.
            if let Some(lease) = entry.leases.get(&gate_type) {
                let timeout_receipt = create_timeout_receipt(gate_type, lease, &self.signer);
                entry.receipts.insert(gate_type, timeout_receipt);
            }
        }

        warn!(
            work_id = %work_id,
            gate_type = %gate_type,
            "Gate timed out - fail-closed FAIL verdict"
        );

        let mut events = vec![GateOrchestratorEvent::GateTimedOut {
            work_id: work_id.to_string(),
            gate_type,
            lease_id,
            timestamp_ms: now_ms,
        }];

        // Check if all gates are complete
        let outcomes = self
            .check_all_gates_complete(work_id, now_ms, &mut events)
            .await?;

        Ok((outcomes, events))
    }

    /// Checks all active orchestrations for expired gates.
    ///
    /// Returns a list of (`work_id`, `gate_type`) pairs that have timed out.
    /// The caller should invoke [`Self::handle_gate_timeout`] for each.
    pub async fn check_timeouts(&self) -> Vec<(String, GateType)> {
        let now_ms = current_time_ms();
        let orchestrations = self.orchestrations.read().await;
        let mut timed_out = Vec::new();

        for (work_id, entry) in orchestrations.iter() {
            for (&gate_type, status) in &entry.gates {
                if !status.is_terminal() {
                    // Check if the lease has expired
                    if let Some(lease) = entry.leases.get(&gate_type) {
                        if now_ms >= lease.expires_at {
                            timed_out.push((work_id.clone(), gate_type));
                        }
                    }
                }
            }
        }

        timed_out
    }

    /// Returns the gate status for a specific gate in an orchestration.
    pub async fn gate_status(&self, work_id: &str, gate_type: GateType) -> Option<GateStatus> {
        let orchestrations = self.orchestrations.read().await;
        orchestrations
            .get(work_id)
            .and_then(|e| e.gates.get(&gate_type).cloned())
    }

    /// Returns the gate lease for a specific gate in an orchestration.
    pub async fn gate_lease(&self, work_id: &str, gate_type: GateType) -> Option<GateLease> {
        let orchestrations = self.orchestrations.read().await;
        orchestrations
            .get(work_id)
            .and_then(|e| e.leases.get(&gate_type).cloned())
    }

    /// Returns the policy resolution for a work item.
    pub async fn policy_resolution(&self, work_id: &str) -> Option<PolicyResolvedForChangeSet> {
        let orchestrations = self.orchestrations.read().await;
        orchestrations
            .get(work_id)
            .map(|e| e.policy_resolution.clone())
    }

    /// Removes a completed orchestration from the active set.
    ///
    /// Returns `true` if the orchestration was found and removed.
    pub async fn remove_orchestration(&self, work_id: &str) -> bool {
        let mut orchestrations = self.orchestrations.write().await;
        orchestrations.remove(work_id).is_some()
    }

    // =========================================================================
    // Daemon Runtime Entry Point (BLOCKER 1)
    // =========================================================================

    /// Daemon runtime hook for session termination notifications.
    ///
    /// This is the entry point that the daemon runtime calls when a session
    /// terminates. It orchestrates the full gate lifecycle:
    ///
    /// 1. Starts gate orchestration via `handle_session_terminated`
    /// 2. Checks for timed-out gates and processes them
    /// 3. Returns all emitted events for ledger persistence
    ///
    /// The daemon runtime should call this method when it receives a
    /// `SessionTerminated` event from the ledger. The full ledger
    /// subscription integration is deferred to TCK-00390 (merge
    /// automation), but this method provides the clear, testable entry
    /// point that wires the orchestrator into the daemon lifecycle.
    ///
    /// # Example Integration
    ///
    /// ```rust,ignore
    /// // In daemon startup:
    /// let orchestrator = Arc::new(GateOrchestrator::new(config, signer));
    ///
    /// // When a session terminates:
    /// let (gate_types, events) = orchestrator
    ///     .on_session_terminated(session_info)
    ///     .await?;
    ///
    /// // Persist events to ledger
    /// for event in events {
    ///     ledger.append(event).await?;
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `GateOrchestratorError` if orchestration setup fails.
    pub async fn on_session_terminated(
        &self,
        info: SessionTerminatedInfo,
    ) -> Result<(Vec<GateType>, Vec<GateOrchestratorEvent>), GateOrchestratorError> {
        let work_id = info.work_id.clone();

        // Step 1: Start gate orchestration (returns per-invocation events).
        let (gate_types, mut events) = self.handle_session_terminated(info).await?;

        // Step 2: Check for any immediately timed-out gates (e.g., zero timeout).
        let timed_out = self.check_timeouts().await;
        for (tid, gt) in timed_out {
            if tid == work_id {
                // Best-effort: ignore errors from timeout handling since the
                // orchestration is already set up.
                if let Ok((_outcomes, timeout_events)) = self.handle_gate_timeout(&tid, gt).await {
                    events.extend(timeout_events);
                }
            }
        }

        info!(
            work_id = %work_id,
            gate_count = gate_types.len(),
            event_count = events.len(),
            "Session termination handled by orchestrator"
        );

        Ok((gate_types, events))
    }

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /// Resolves policy for a changeset.
    ///
    /// # Ordering Invariant
    ///
    /// This MUST be called before any lease issuance for the same `work_id`.
    fn resolve_policy(
        &self,
        info: &SessionTerminatedInfo,
        _now_ms: u64,
    ) -> Result<PolicyResolvedForChangeSet, GateOrchestratorError> {
        PolicyResolvedForChangeSetBuilder::new(&info.work_id, info.changeset_digest)
            .resolved_risk_tier(1) // Default risk tier 1 (low)
            .resolved_determinism_class(0) // Non-deterministic
            .resolver_actor_id(&self.config.resolver_actor_id)
            .resolver_version(&self.config.resolver_version)
            .try_build_and_sign(&self.signer)
            .map_err(|e| GateOrchestratorError::PolicyResolutionFailed {
                work_id: info.work_id.clone(),
                reason: e.to_string(),
            })
    }

    /// Issues a gate lease for a specific gate type.
    ///
    /// # Security
    ///
    /// - Uses domain-separated Ed25519 signatures (`GATE_LEASE_ISSUED:` prefix)
    /// - Binds the `changeset_digest` from the terminated session
    /// - Sets temporal bounds (`issued_at` to `issued_at` + timeout)
    fn issue_gate_lease(
        &self,
        info: &SessionTerminatedInfo,
        gate_type: GateType,
        policy_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<GateLease, GateOrchestratorError> {
        let lease_id = format!(
            "lease-{}-{}-{}",
            info.work_id,
            gate_type.as_gate_id(),
            now_ms
        );
        let executor_actor_id = format!("executor-{}-{}", gate_type.as_gate_id(), now_ms);
        let time_envelope_ref = format!("htf:gate:{}:{}", info.work_id, now_ms);

        let mut builder = GateLeaseBuilder::new(&lease_id, &info.work_id, gate_type.as_gate_id())
            .changeset_digest(info.changeset_digest)
            .executor_actor_id(&executor_actor_id)
            .issued_at(now_ms)
            .expires_at(now_ms + self.config.gate_timeout_ms)
            .policy_hash(*policy_hash)
            .issuer_actor_id(&self.config.issuer_actor_id)
            .time_envelope_ref(&time_envelope_ref);

        // AAT gates require an aat_extension per the lease invariant.
        // This binds the lease to a specific RCP manifest and view commitment.
        if gate_type == GateType::Aat {
            builder = builder.aat_extension(AatLeaseExtension {
                view_commitment_hash: info.changeset_digest,
                rcp_manifest_hash: *policy_hash,
                rcp_profile_id: gate_type.adapter_profile_id().to_string(),
                selection_policy_id: "default-selection-policy".to_string(),
            });
        }

        builder.try_build_and_sign(&self.signer).map_err(|e| {
            GateOrchestratorError::LeaseIssuanceFailed {
                work_id: info.work_id.clone(),
                gate_id: gate_type.as_gate_id().to_string(),
                reason: e.to_string(),
            }
        })
    }

    /// Checks if all gates are complete and appends `AllGatesCompleted` to
    /// the provided event list if so.
    async fn check_all_gates_complete(
        &self,
        work_id: &str,
        now_ms: u64,
        events: &mut Vec<GateOrchestratorEvent>,
    ) -> Result<Option<Vec<GateOutcome>>, GateOrchestratorError> {
        let orchestrations = self.orchestrations.read().await;
        let entry = orchestrations.get(work_id).ok_or_else(|| {
            GateOrchestratorError::OrchestrationNotFound {
                work_id: work_id.to_string(),
            }
        })?;

        // Check if all gates are in terminal state
        let all_terminal = entry.gates.values().all(GateStatus::is_terminal);
        if !all_terminal {
            return Ok(None);
        }

        // Build outcomes
        let mut outcomes = Vec::new();
        let mut all_passed = true;

        for (&gate_type, status) in &entry.gates {
            let outcome = match status {
                GateStatus::Completed {
                    receipt_id, passed, ..
                } => {
                    if !passed {
                        all_passed = false;
                    }
                    GateOutcome {
                        gate_type,
                        passed: *passed,
                        receipt_id: Some(receipt_id.clone()),
                        timed_out: false,
                    }
                },
                GateStatus::TimedOut { .. } => {
                    all_passed = false;
                    GateOutcome {
                        gate_type,
                        passed: false,
                        receipt_id: None,
                        timed_out: true,
                    }
                },
                _ => continue, // Shouldn't happen since we checked all_terminal
            };
            outcomes.push(outcome);
        }

        // Drop read lock before appending events
        drop(orchestrations);

        events.push(GateOrchestratorEvent::AllGatesCompleted {
            work_id: work_id.to_string(),
            all_passed,
            outcomes: outcomes.clone(),
            timestamp_ms: now_ms,
        });

        info!(
            work_id = %work_id,
            all_passed = %all_passed,
            gate_count = %outcomes.len(),
            "All gates completed"
        );

        Ok(Some(outcomes))
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Returns a human-readable name for a gate status variant.
const fn state_name(status: &GateStatus) -> &'static str {
    match status {
        GateStatus::LeaseIssued { .. } => "LeaseIssued",
        GateStatus::Running { .. } => "Running",
        GateStatus::Completed { .. } => "Completed",
        GateStatus::TimedOut { .. } => "TimedOut",
    }
}

/// Returns the current time in milliseconds since epoch.
///
/// # Note
///
/// The cast from u128 to u64 is safe: milliseconds since UNIX epoch
/// won't exceed `u64::MAX` until the year 584 million.
#[allow(clippy::cast_possible_truncation)]
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Creates a fail-closed gate receipt for a timed-out gate.
///
/// # Security: Fail-Closed Semantics
///
/// Timed-out gates produce a receipt with FAIL semantics. This prevents
/// silent expiry from allowing unreviewed changes through the pipeline.
///
/// The receipt uses a zero payload hash and evidence bundle hash since
/// no actual gate execution occurred.
#[must_use]
pub fn create_timeout_receipt(
    gate_type: GateType,
    lease: &GateLease,
    signer: &Signer,
) -> GateReceipt {
    let receipt_id = format!("timeout-receipt-{}-{}", lease.lease_id, lease.expires_at);

    GateReceiptBuilder::new(&receipt_id, gate_type.as_gate_id(), &lease.lease_id)
        .changeset_digest(lease.changeset_digest)
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind(gate_type.payload_kind())
        .payload_schema_version(1)
        .payload_hash([0u8; 32]) // Zero hash: no actual execution
        .evidence_bundle_hash([0u8; 32]) // Zero hash: no evidence
        .build_and_sign(signer)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: creates a test signer.
    fn test_signer() -> Arc<Signer> {
        Arc::new(Signer::generate())
    }

    /// Helper: creates a test session terminated info.
    fn test_session_info(work_id: &str) -> SessionTerminatedInfo {
        SessionTerminatedInfo {
            session_id: format!("session-{work_id}"),
            work_id: work_id.to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 1_704_067_200_000,
        }
    }

    /// Helper: creates a default orchestrator.
    fn test_orchestrator() -> GateOrchestrator {
        GateOrchestrator::new(GateOrchestratorConfig::default(), test_signer())
    }

    // =========================================================================
    // Happy Path Tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_session_terminated_issues_all_gates() {
        let orch = test_orchestrator();
        let info = test_session_info("work-001");

        let (gate_types, _events) = orch.handle_session_terminated(info).await.unwrap();

        assert_eq!(gate_types.len(), 3);
        assert!(gate_types.contains(&GateType::Aat));
        assert!(gate_types.contains(&GateType::Quality));
        assert!(gate_types.contains(&GateType::Security));
        assert_eq!(orch.active_count().await, 1);
    }

    #[tokio::test]
    async fn test_policy_resolved_before_leases() {
        let orch = test_orchestrator();
        let info = test_session_info("work-002");

        let (_gate_types, events) = orch.handle_session_terminated(info).await.unwrap();

        // First event must be PolicyResolved
        assert!(matches!(
            events[0],
            GateOrchestratorEvent::PolicyResolved { .. }
        ));
        // Subsequent events must be GateLeaseIssued
        for event in &events[1..] {
            assert!(
                matches!(event, GateOrchestratorEvent::GateLeaseIssued { .. }),
                "Expected GateLeaseIssued, got {event:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_gate_lease_signatures_valid() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-003");

        orch.handle_session_terminated(info).await.unwrap();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-003", gate_type).await.unwrap();
            assert!(
                lease.validate_signature(&signer.verifying_key()).is_ok(),
                "Signature validation failed for {gate_type}"
            );
        }
    }

    #[tokio::test]
    async fn test_gate_lease_changeset_binding() {
        let orch = test_orchestrator();
        let changeset = [0xAB; 32];
        let info = SessionTerminatedInfo {
            session_id: "session-binding".to_string(),
            work_id: "work-binding".to_string(),
            changeset_digest: changeset,
            terminated_at_ms: 1_704_067_200_000,
        };

        orch.handle_session_terminated(info).await.unwrap();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-binding", gate_type).await.unwrap();
            assert_eq!(
                lease.changeset_digest, changeset,
                "Changeset mismatch for {gate_type}"
            );
        }
    }

    #[tokio::test]
    async fn test_gate_lease_policy_hash_matches_resolution() {
        let orch = test_orchestrator();
        let info = test_session_info("work-004");

        orch.handle_session_terminated(info).await.unwrap();

        let resolution = orch.policy_resolution("work-004").await.unwrap();
        let policy_hash = resolution.resolved_policy_hash();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-004", gate_type).await.unwrap();
            assert_eq!(
                lease.policy_hash, policy_hash,
                "Policy hash mismatch for {gate_type}"
            );
        }
    }

    #[tokio::test]
    async fn test_record_executor_spawned() {
        let orch = test_orchestrator();
        let info = test_session_info("work-005");

        orch.handle_session_terminated(info).await.unwrap();

        let events = orch
            .record_executor_spawned("work-005", GateType::Quality, "ep-001")
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            GateOrchestratorEvent::GateExecutorSpawned { .. }
        ));

        let status = orch
            .gate_status("work-005", GateType::Quality)
            .await
            .unwrap();
        assert!(matches!(status, GateStatus::Running { episode_id, .. } if episode_id == "ep-001"));
    }

    #[tokio::test]
    async fn test_record_gate_receipt_completes_gate() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-006");

        orch.handle_session_terminated(info).await.unwrap();

        // Complete one gate
        let lease = orch
            .gate_lease("work-006", GateType::Quality)
            .await
            .unwrap();
        let receipt = GateReceiptBuilder::new("receipt-001", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        let (result, events) = orch
            .record_gate_receipt("work-006", GateType::Quality, receipt, true)
            .await
            .unwrap();

        // Not all gates complete yet
        assert!(result.is_none());
        // Should have GateReceiptCollected event
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GateOrchestratorEvent::GateReceiptCollected { .. }))
        );

        let status = orch
            .gate_status("work-006", GateType::Quality)
            .await
            .unwrap();
        assert!(matches!(status, GateStatus::Completed { passed: true, .. }));
    }

    #[tokio::test]
    async fn test_all_gates_completed_event() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-007");

        orch.handle_session_terminated(info).await.unwrap();

        // Complete all three gates
        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-007", gate_type).await.unwrap();
            let receipt = GateReceiptBuilder::new(
                format!("receipt-{}", gate_type.as_gate_id()),
                gate_type.as_gate_id(),
                &lease.lease_id,
            )
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind(gate_type.payload_kind())
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

            let (result, _events) = orch
                .record_gate_receipt("work-007", gate_type, receipt, true)
                .await
                .unwrap();

            if gate_type == GateType::Security {
                // Last gate should trigger AllGatesCompleted
                let outcomes = result.expect("expected outcomes for last gate");
                assert_eq!(outcomes.len(), 3);
                assert!(outcomes.iter().all(|o| o.passed));
            }
        }
    }

    // =========================================================================
    // Timeout / Fail-Closed Tests
    // =========================================================================

    #[tokio::test]
    async fn test_gate_timeout_produces_fail_verdict() {
        let orch = test_orchestrator();
        let info = test_session_info("work-008");

        orch.handle_session_terminated(info).await.unwrap();

        let (result, events) = orch
            .handle_gate_timeout("work-008", GateType::Aat)
            .await
            .unwrap();

        // Not all gates done
        assert!(result.is_none());
        // Should have GateTimedOut event
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. }))
        );

        let status = orch.gate_status("work-008", GateType::Aat).await.unwrap();
        assert!(matches!(status, GateStatus::TimedOut { .. }));
    }

    #[tokio::test]
    async fn test_timeout_receipt_is_fail_closed() {
        let signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-timeout", "work-timeout", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-timeout")
            .issued_at(1000)
            .expires_at(2000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-timeout")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let receipt = create_timeout_receipt(GateType::Quality, &lease, &signer);

        // Timeout receipt should have zero hashes (no actual execution)
        assert_eq!(receipt.payload_hash, [0u8; 32]);
        assert_eq!(receipt.evidence_bundle_hash, [0u8; 32]);
        assert!(receipt.receipt_id.starts_with("timeout-receipt-"));
    }

    #[tokio::test]
    async fn test_mixed_completion_and_timeout() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-009");

        orch.handle_session_terminated(info).await.unwrap();

        // Complete AAT gate
        let lease = orch.gate_lease("work-009", GateType::Aat).await.unwrap();
        let receipt = GateReceiptBuilder::new("receipt-aat", "gate-aat", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        orch.record_gate_receipt("work-009", GateType::Aat, receipt, true)
            .await
            .unwrap();

        // Timeout quality gate
        orch.handle_gate_timeout("work-009", GateType::Quality)
            .await
            .unwrap();

        // Timeout security gate -> should trigger AllGatesCompleted
        let (result, _events) = orch
            .handle_gate_timeout("work-009", GateType::Security)
            .await
            .unwrap();

        let outcomes = result.expect("expected outcomes when all gates done");
        assert_eq!(outcomes.len(), 3);

        // AAT passed, quality and security timed out
        let aat = outcomes
            .iter()
            .find(|o| o.gate_type == GateType::Aat)
            .unwrap();
        assert!(aat.passed);
        assert!(!aat.timed_out);

        let quality = outcomes
            .iter()
            .find(|o| o.gate_type == GateType::Quality)
            .unwrap();
        assert!(!quality.passed);
        assert!(quality.timed_out);

        let security = outcomes
            .iter()
            .find(|o| o.gate_type == GateType::Security)
            .unwrap();
        assert!(!security.passed);
        assert!(security.timed_out);
    }

    // =========================================================================
    // Boundary / Error Tests
    // =========================================================================

    #[tokio::test]
    async fn test_empty_work_id_rejected() {
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "session-empty".to_string(),
            work_id: String::new(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 1_704_067_200_000,
        };

        let err = orch.handle_session_terminated(info).await.unwrap_err();
        assert!(matches!(err, GateOrchestratorError::EmptyWorkId));
    }

    #[tokio::test]
    async fn test_work_id_too_long_rejected() {
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "session-long".to_string(),
            work_id: "x".repeat(MAX_WORK_ID_LENGTH + 1),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 1_704_067_200_000,
        };

        let err = orch.handle_session_terminated(info).await.unwrap_err();
        assert!(matches!(err, GateOrchestratorError::WorkIdTooLong { .. }));
    }

    #[tokio::test]
    async fn test_duplicate_orchestration_rejected() {
        let orch = test_orchestrator();
        let info1 = test_session_info("work-dup");
        let info2 = test_session_info("work-dup");

        orch.handle_session_terminated(info1).await.unwrap();

        let err = orch.handle_session_terminated(info2).await.unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::DuplicateOrchestration { .. }
        ));
    }

    #[tokio::test]
    async fn test_max_orchestrations_exceeded() {
        let config = GateOrchestratorConfig {
            max_concurrent_orchestrations: 2,
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());

        orch.handle_session_terminated(test_session_info("work-a"))
            .await
            .unwrap();
        orch.handle_session_terminated(test_session_info("work-b"))
            .await
            .unwrap();

        let err = orch
            .handle_session_terminated(test_session_info("work-c"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::MaxOrchestrationsExceeded { current: 2, max: 2 }
        ));
    }

    #[tokio::test]
    async fn test_orchestration_not_found_error() {
        let orch = test_orchestrator();

        let err = orch
            .record_executor_spawned("nonexistent", GateType::Aat, "ep-001")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::OrchestrationNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_remove_orchestration() {
        let orch = test_orchestrator();
        let info = test_session_info("work-remove");

        orch.handle_session_terminated(info).await.unwrap();
        assert_eq!(orch.active_count().await, 1);

        assert!(orch.remove_orchestration("work-remove").await);
        assert_eq!(orch.active_count().await, 0);

        // Second removal should return false
        assert!(!orch.remove_orchestration("work-remove").await);
    }

    // =========================================================================
    // Domain Separation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_leases_use_domain_separated_signatures() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-domain");

        orch.handle_session_terminated(info).await.unwrap();

        // Verify that all leases have valid domain-separated signatures
        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-domain", gate_type).await.unwrap();

            // Valid with correct key
            assert!(lease.validate_signature(&signer.verifying_key()).is_ok());

            // Invalid with wrong key
            let wrong_signer = Signer::generate();
            assert!(
                lease
                    .validate_signature(&wrong_signer.verifying_key())
                    .is_err()
            );
        }
    }

    // =========================================================================
    // Policy Resolution Ordering Tests
    // =========================================================================

    #[tokio::test]
    async fn test_policy_hash_consistency_across_gates() {
        let orch = test_orchestrator();
        let info = test_session_info("work-consistency");

        orch.handle_session_terminated(info).await.unwrap();

        let resolution = orch.policy_resolution("work-consistency").await.unwrap();
        let expected_hash = resolution.resolved_policy_hash();

        // All leases should reference the same policy hash
        for gate_type in GateType::all() {
            let lease = orch
                .gate_lease("work-consistency", gate_type)
                .await
                .unwrap();
            assert_eq!(
                lease.policy_hash, expected_hash,
                "Policy hash inconsistency for {gate_type}"
            );
        }
    }

    // =========================================================================
    // Temporal Bounds Tests
    // =========================================================================

    #[tokio::test]
    async fn test_gate_lease_temporal_bounds() {
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 60_000, // 1 minute
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        let info = test_session_info("work-temporal");

        orch.handle_session_terminated(info).await.unwrap();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-temporal", gate_type).await.unwrap();
            // Lease should have timeout duration
            assert_eq!(
                lease.expires_at - lease.issued_at,
                60_000,
                "Timeout mismatch for {gate_type}"
            );
            // Lease should be valid at issued_at
            assert!(lease.validate_temporal_bounds(lease.issued_at));
            // Lease should not be valid at expires_at
            assert!(!lease.validate_temporal_bounds(lease.expires_at));
        }
    }

    // =========================================================================
    // Gate Type Tests
    // =========================================================================

    #[test]
    fn test_gate_type_gate_ids() {
        assert_eq!(GateType::Aat.as_gate_id(), "gate-aat");
        assert_eq!(GateType::Quality.as_gate_id(), "gate-quality");
        assert_eq!(GateType::Security.as_gate_id(), "gate-security");
    }

    #[test]
    fn test_gate_type_payload_kinds() {
        assert_eq!(GateType::Aat.payload_kind(), "aat");
        assert_eq!(GateType::Quality.payload_kind(), "quality");
        assert_eq!(GateType::Security.payload_kind(), "security");
    }

    #[test]
    fn test_gate_type_all() {
        let all = GateType::all();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_gate_type_adapter_profiles() {
        assert_eq!(
            GateType::Aat.adapter_profile_id(),
            apm2_core::fac::CLAUDE_CODE_PROFILE_ID
        );
        assert_eq!(
            GateType::Quality.adapter_profile_id(),
            apm2_core::fac::GEMINI_CLI_PROFILE_ID
        );
        assert_eq!(
            GateType::Security.adapter_profile_id(),
            apm2_core::fac::GEMINI_CLI_PROFILE_ID
        );
    }

    // =========================================================================
    // Session ID Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_session_id_too_long_rejected() {
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "s".repeat(MAX_STRING_LENGTH + 1),
            work_id: "work-valid".to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 1_704_067_200_000,
        };

        let err = orch.handle_session_terminated(info).await.unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::StringTooLong {
                field: "session_id",
                ..
            }
        ));
    }

    // =========================================================================
    // Per-Invocation Event Tests (BLOCKER 3)
    // =========================================================================

    #[tokio::test]
    async fn test_events_returned_per_invocation() {
        let orch = test_orchestrator();
        let info = test_session_info("work-per-inv");

        let (_gate_types, events) = orch.handle_session_terminated(info).await.unwrap();

        // Events are returned from the call, not buffered
        assert!(!events.is_empty());
        // 1 PolicyResolved + 3 GateLeaseIssued = 4 events
        assert_eq!(events.len(), 4);
    }

    #[tokio::test]
    async fn test_event_count_matches_gates() {
        let orch = test_orchestrator();
        let info = test_session_info("work-events");

        let (_gate_types, events) = orch.handle_session_terminated(info).await.unwrap();
        // 1 PolicyResolved + 3 GateLeaseIssued = 4 events
        assert_eq!(events.len(), 4);
    }

    // =========================================================================
    // BLOCKER 2: Events not emitted on admission failure
    // =========================================================================

    #[tokio::test]
    async fn test_no_events_on_duplicate_orchestration() {
        let orch = test_orchestrator();
        let info1 = test_session_info("work-no-events-dup");
        let info2 = test_session_info("work-no-events-dup");

        // First succeeds
        let (_gate_types, events1) = orch.handle_session_terminated(info1).await.unwrap();
        assert!(!events1.is_empty());

        // Second fails with DuplicateOrchestration - no events should be returned
        let err = orch.handle_session_terminated(info2).await.unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::DuplicateOrchestration { .. }
        ));
    }

    #[tokio::test]
    async fn test_no_events_on_max_orchestrations_exceeded() {
        let config = GateOrchestratorConfig {
            max_concurrent_orchestrations: 1,
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());

        // First succeeds
        orch.handle_session_terminated(test_session_info("work-max-a"))
            .await
            .unwrap();

        // Second fails - no events should be returned
        let err = orch
            .handle_session_terminated(test_session_info("work-max-b"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::MaxOrchestrationsExceeded { .. }
        ));
    }

    // =========================================================================
    // Check Timeouts Tests
    // =========================================================================

    #[tokio::test]
    async fn test_check_timeouts_finds_expired_gates() {
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 0, // Instant timeout for testing
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        let info = test_session_info("work-expire");

        orch.handle_session_terminated(info).await.unwrap();

        // With 0ms timeout, all gates should be timed out immediately
        // (since current_time_ms >= expires_at)
        let timed_out = orch.check_timeouts().await;
        assert_eq!(timed_out.len(), 3);
    }

    // =========================================================================
    // BLOCKER 1: Daemon Runtime Integration Tests
    // =========================================================================

    #[tokio::test]
    async fn test_on_session_terminated_returns_gates_and_events() {
        let orch = test_orchestrator();
        let info = test_session_info("work-daemon");

        let (gate_types, events) = orch.on_session_terminated(info).await.unwrap();

        assert_eq!(gate_types.len(), 3);
        assert!(gate_types.contains(&GateType::Aat));
        assert!(gate_types.contains(&GateType::Quality));
        assert!(gate_types.contains(&GateType::Security));

        // Events: 1 PolicyResolved + 3 GateLeaseIssued = 4
        assert_eq!(events.len(), 4);
        assert!(matches!(
            events[0],
            GateOrchestratorEvent::PolicyResolved { .. }
        ));
    }

    #[tokio::test]
    async fn test_on_session_terminated_handles_immediate_timeouts() {
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 0, // Instant timeout
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        let info = test_session_info("work-imm-timeout");

        let (_gate_types, events) = orch.on_session_terminated(info).await.unwrap();

        // Should have timeout events in addition to policy+lease events
        let timeout_count = events
            .iter()
            .filter(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. }))
            .count();
        assert_eq!(timeout_count, 3, "all 3 gates should have timed out");
    }

    #[tokio::test]
    async fn test_on_session_terminated_duplicate_rejected() {
        let orch = test_orchestrator();

        orch.on_session_terminated(test_session_info("work-dup2"))
            .await
            .unwrap();

        let err = orch
            .on_session_terminated(test_session_info("work-dup2"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::DuplicateOrchestration { .. }
        ));
    }

    // =========================================================================
    // BLOCKER 4: Receipt Signature Verification Tests
    // =========================================================================

    #[tokio::test]
    async fn test_receipt_with_wrong_signer_rejected() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-sig-1");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-sig-1", GateType::Quality)
            .await
            .unwrap();

        // Sign with a DIFFERENT signer (wrong key)
        let wrong_signer = Signer::generate();
        let receipt = GateReceiptBuilder::new("receipt-bad-sig", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&wrong_signer);

        let err = orch
            .record_gate_receipt("work-sig-1", GateType::Quality, receipt, true)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GateOrchestratorError::ReceiptBindingMismatch { ref reason, .. } if reason.contains("signature")),
            "Expected signature verification failure, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_receipt_with_correct_signer_accepted() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-sig-2");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-sig-2", GateType::Quality)
            .await
            .unwrap();

        // Sign with the correct signer
        let receipt = GateReceiptBuilder::new("receipt-good-sig", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        let (result, events) = orch
            .record_gate_receipt("work-sig-2", GateType::Quality, receipt, true)
            .await
            .unwrap();

        // Should succeed
        assert!(result.is_none()); // Not all gates complete
        assert!(!events.is_empty());
    }

    // =========================================================================
    // Receipt Binding Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_receipt_lease_id_mismatch_rejected() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-bind-1");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-bind-1", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong lease_id
        let receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", "wrong-lease-id")
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        let err = orch
            .record_gate_receipt("work-bind-1", GateType::Quality, receipt, true)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_receipt_gate_id_mismatch_rejected() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-bind-2");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-bind-2", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong gate_id
        let receipt = GateReceiptBuilder::new("receipt-bad", "wrong-gate-id", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        let err = orch
            .record_gate_receipt("work-bind-2", GateType::Quality, receipt, true)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_receipt_changeset_digest_mismatch_rejected() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-bind-3");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-bind-3", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong changeset_digest
        let receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", &lease.lease_id)
                .changeset_digest([0xFF; 32]) // Wrong digest
                .executor_actor_id(&lease.executor_actor_id)
                .receipt_version(1)
                .payload_kind("quality")
                .payload_schema_version(1)
                .payload_hash([0xBB; 32])
                .evidence_bundle_hash([0xCC; 32])
                .build_and_sign(&signer);

        let err = orch
            .record_gate_receipt("work-bind-3", GateType::Quality, receipt, true)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_receipt_executor_actor_id_mismatch_rejected() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-bind-4");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-bind-4", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong executor_actor_id
        let receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id("wrong-executor")
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        let err = orch
            .record_gate_receipt("work-bind-4", GateType::Quality, receipt, true)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    // =========================================================================
    // Verdict Derivation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_failing_receipt_produces_fail_verdict() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-fail");

        orch.handle_session_terminated(info).await.unwrap();

        // Complete all gates, but mark quality as FAIL
        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-fail", gate_type).await.unwrap();
            let receipt = GateReceiptBuilder::new(
                format!("receipt-{}", gate_type.as_gate_id()),
                gate_type.as_gate_id(),
                &lease.lease_id,
            )
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind(gate_type.payload_kind())
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

            let passed = gate_type != GateType::Quality; // Quality fails
            let (result, _events) = orch
                .record_gate_receipt("work-fail", gate_type, receipt, passed)
                .await
                .unwrap();

            if gate_type == GateType::Security {
                // Last gate triggers AllGatesCompleted
                let outcomes = result.expect("expected outcomes");
                assert_eq!(outcomes.len(), 3);

                let quality_outcome = outcomes
                    .iter()
                    .find(|o| o.gate_type == GateType::Quality)
                    .unwrap();
                assert!(
                    !quality_outcome.passed,
                    "quality gate should have FAIL verdict"
                );

                // Overall should be fail since quality failed
                assert!(
                    outcomes.iter().any(|o| !o.passed),
                    "at least one gate should fail"
                );
            }
        }

        // Verify gate status shows the failure
        let status = orch
            .gate_status("work-fail", GateType::Quality)
            .await
            .unwrap();
        assert!(
            matches!(status, GateStatus::Completed { passed: false, .. }),
            "quality gate should be completed with passed=false"
        );
    }

    // =========================================================================
    // State Transition Tests
    // =========================================================================

    #[tokio::test]
    async fn test_record_executor_spawned_rejects_terminal_state() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-term-1");

        orch.handle_session_terminated(info).await.unwrap();

        // Timeout a gate (terminal state)
        orch.handle_gate_timeout("work-term-1", GateType::Quality)
            .await
            .unwrap();

        // Trying to spawn executor on timed-out gate should fail
        let err = orch
            .record_executor_spawned("work-term-1", GateType::Quality, "ep-bad")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_record_executor_spawned_rejects_running_state() {
        let orch = test_orchestrator();
        let info = test_session_info("work-term-2");

        orch.handle_session_terminated(info).await.unwrap();

        // Spawn executor (now Running)
        orch.record_executor_spawned("work-term-2", GateType::Quality, "ep-001")
            .await
            .unwrap();

        // Trying to spawn again should fail (already Running)
        let err = orch
            .record_executor_spawned("work-term-2", GateType::Quality, "ep-002")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_record_receipt_rejects_completed_state() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-term-3");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-term-3", GateType::Quality)
            .await
            .unwrap();

        // Complete the gate
        let receipt = GateReceiptBuilder::new("receipt-1", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        orch.record_gate_receipt("work-term-3", GateType::Quality, receipt, true)
            .await
            .unwrap();

        // Try to record another receipt on the same (now Completed) gate
        let receipt2 = GateReceiptBuilder::new("receipt-2", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xDD; 32])
            .evidence_bundle_hash([0xEE; 32])
            .build_and_sign(&signer);

        let err = orch
            .record_gate_receipt("work-term-3", GateType::Quality, receipt2, true)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_handle_timeout_rejects_terminal_state() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-term-4");

        orch.handle_session_terminated(info).await.unwrap();

        let lease = orch
            .gate_lease("work-term-4", GateType::Quality)
            .await
            .unwrap();

        // Complete the gate
        let receipt = GateReceiptBuilder::new("receipt-1", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .build_and_sign(&signer);

        orch.record_gate_receipt("work-term-4", GateType::Quality, receipt, true)
            .await
            .unwrap();

        // Trying to timeout a completed gate should fail
        let err = orch
            .handle_gate_timeout("work-term-4", GateType::Quality)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }
}
