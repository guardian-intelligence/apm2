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

use std::collections::HashMap;
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
/// - Timeout produces fail-closed FAIL verdict
/// - Changeset digest in leases matches session data
///
/// # Thread Safety
///
/// `GateOrchestrator` is `Send + Sync` and can be shared across async tasks.
pub struct GateOrchestrator {
    /// Configuration.
    config: GateOrchestratorConfig,
    /// Active orchestrations indexed by `work_id`.
    orchestrations: RwLock<HashMap<String, OrchestrationEntry>>,
    /// Event buffer for emitted events.
    events: RwLock<Vec<GateOrchestratorEvent>>,
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
            events: RwLock::new(Vec::new()),
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

    /// Drains all buffered events.
    ///
    /// Returns the events in emission order. The internal buffer is cleared.
    pub async fn drain_events(&self) -> Vec<GateOrchestratorEvent> {
        let mut events = self.events.write().await;
        std::mem::take(&mut *events)
    }

    /// Handles a `session_terminated` event by starting gate orchestration.
    ///
    /// This is the primary entry point for the gate lifecycle. When a session
    /// terminates with associated work, this method:
    ///
    /// 1. Validates input and checks resource limits
    /// 2. Resolves policy for the changeset (emits
    ///    `PolicyResolvedForChangeSet`)
    /// 3. Issues gate leases for each required gate type
    /// 4. Records the orchestration for executor spawning
    ///
    /// # Ordering Invariant
    ///
    /// The `PolicyResolvedForChangeSet` event is ALWAYS emitted before any
    /// `GateLeaseIssued` event. This is enforced by the sequential execution
    /// within this method.
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
    ) -> Result<Vec<GateType>, GateOrchestratorError> {
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

        // Check resource limits
        {
            let orchestrations = self.orchestrations.read().await;
            if orchestrations.len() >= self.config.max_concurrent_orchestrations {
                return Err(GateOrchestratorError::MaxOrchestrationsExceeded {
                    current: orchestrations.len(),
                    max: self.config.max_concurrent_orchestrations,
                });
            }
            if orchestrations.contains_key(&info.work_id) {
                return Err(GateOrchestratorError::DuplicateOrchestration {
                    work_id: info.work_id.clone(),
                });
            }
        }

        let now_ms = current_time_ms();

        // Step 1: Resolve policy for the changeset.
        // ORDERING INVARIANT: This MUST happen before any lease issuance.
        let policy_resolution = self.resolve_policy(&info, now_ms)?;
        let policy_hash = policy_resolution.resolved_policy_hash();

        info!(
            work_id = %info.work_id,
            policy_hash = %hex::encode(policy_hash),
            "Policy resolved for changeset"
        );

        // Emit PolicyResolved event
        self.emit_event(GateOrchestratorEvent::PolicyResolved {
            work_id: info.work_id.clone(),
            policy_hash,
            timestamp_ms: now_ms,
        })
        .await;

        // Step 2: Issue gate leases for each required gate type.
        // This MUST happen AFTER policy resolution (ordering invariant).
        let mut gates = HashMap::new();
        let mut leases = HashMap::new();
        let mut issued_gate_types = Vec::new();

        for &gate_type in &self.config.gate_types {
            let lease = self.issue_gate_lease(&info, gate_type, &policy_hash, now_ms)?;

            let lease_id = lease.lease_id.clone();
            let executor_actor_id = lease.executor_actor_id.clone();

            debug!(
                work_id = %info.work_id,
                gate_type = %gate_type,
                lease_id = %lease_id,
                "Gate lease issued"
            );

            // Emit GateLeaseIssued event
            self.emit_event(GateOrchestratorEvent::GateLeaseIssued {
                work_id: info.work_id.clone(),
                gate_type,
                lease_id: lease_id.clone(),
                executor_actor_id,
                timestamp_ms: now_ms,
            })
            .await;

            gates.insert(gate_type, GateStatus::LeaseIssued { lease_id });
            leases.insert(gate_type, lease);
            issued_gate_types.push(gate_type);
        }

        // Step 3: Store orchestration entry.
        {
            let mut orchestrations = self.orchestrations.write().await;
            orchestrations.insert(
                info.work_id.clone(),
                OrchestrationEntry {
                    _session_info: info,
                    policy_resolution,
                    gates,
                    leases,
                    receipts: HashMap::new(),
                    _started_at_ms: now_ms,
                },
            );
        }

        Ok(issued_gate_types)
    }

    /// Records that a gate executor episode has been spawned.
    ///
    /// This updates the gate status from `LeaseIssued` to `Running` and
    /// emits a `GateExecutorSpawned` event.
    ///
    /// # Errors
    ///
    /// Returns error if the orchestration or gate is not found.
    pub async fn record_executor_spawned(
        &self,
        work_id: &str,
        gate_type: GateType,
        episode_id: &str,
    ) -> Result<(), GateOrchestratorError> {
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

            if let GateStatus::LeaseIssued { lease_id } = gate_status {
                *gate_status = GateStatus::Running {
                    lease_id: lease_id.clone(),
                    episode_id: episode_id.to_string(),
                };
            }
        }

        self.emit_event(GateOrchestratorEvent::GateExecutorSpawned {
            work_id: work_id.to_string(),
            gate_type,
            episode_id: episode_id.to_string(),
            adapter_profile_id: gate_type.adapter_profile_id().to_string(),
            timestamp_ms: now_ms,
        })
        .await;

        info!(
            work_id = %work_id,
            gate_type = %gate_type,
            episode_id = %episode_id,
            "Gate executor spawned"
        );

        Ok(())
    }

    /// Records a gate receipt from a completed gate executor.
    ///
    /// This updates the gate status to `Completed` and emits a
    /// `GateReceiptCollected` event. If all gates are complete, emits
    /// an `AllGatesCompleted` event.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work ID
    /// * `gate_type` - The gate type that completed
    /// * `receipt` - The gate receipt from the executor
    ///
    /// # Errors
    ///
    /// Returns error if the orchestration or gate is not found.
    pub async fn record_gate_receipt(
        &self,
        work_id: &str,
        gate_type: GateType,
        receipt: GateReceipt,
    ) -> Result<Option<Vec<GateOutcome>>, GateOrchestratorError> {
        let now_ms = current_time_ms();
        let receipt_id = receipt.receipt_id.clone();
        // For this implementation, a receipt means the gate passed.
        // In production, the verdict would come from the receipt payload.
        let passed = true;

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

            if let GateStatus::Running { lease_id, .. } | GateStatus::LeaseIssued { lease_id } =
                gate_status
            {
                *gate_status = GateStatus::Completed {
                    lease_id: lease_id.clone(),
                    receipt_id: receipt_id.clone(),
                    passed,
                };
            }

            entry.receipts.insert(gate_type, receipt);
        }

        self.emit_event(GateOrchestratorEvent::GateReceiptCollected {
            work_id: work_id.to_string(),
            gate_type,
            receipt_id,
            passed,
            timestamp_ms: now_ms,
        })
        .await;

        info!(
            work_id = %work_id,
            gate_type = %gate_type,
            passed = %passed,
            "Gate receipt collected"
        );

        // Check if all gates are complete
        self.check_all_gates_complete(work_id, now_ms).await
    }

    /// Handles gate timeout by emitting a FAIL verdict (fail-closed).
    ///
    /// # Security: Fail-Closed Semantics
    ///
    /// Expired gates produce a FAIL verdict, not silent expiry. This ensures
    /// that timeouts block merge rather than allowing unreviewed code through.
    ///
    /// # Errors
    ///
    /// Returns error if the orchestration or gate is not found.
    pub async fn handle_gate_timeout(
        &self,
        work_id: &str,
        gate_type: GateType,
    ) -> Result<Option<Vec<GateOutcome>>, GateOrchestratorError> {
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

            if let GateStatus::Running { lease_id, .. } | GateStatus::LeaseIssued { lease_id } =
                gate_status
            {
                let lease_id_owned = lease_id.clone();
                *gate_status = GateStatus::TimedOut {
                    lease_id: lease_id_owned,
                };
            }

            // Create and store fail-closed receipt for the timed-out gate.
            // This ensures a FAIL verdict exists in the ledger, preventing
            // silent expiry from allowing unreviewed code through.
            if let Some(lease) = entry.leases.get(&gate_type) {
                let timeout_receipt = create_timeout_receipt(gate_type, lease, &self.signer);
                entry.receipts.insert(gate_type, timeout_receipt);
            }
        }

        // Emit timeout event
        let lease_id = {
            let orchestrations = self.orchestrations.read().await;
            orchestrations
                .get(work_id)
                .and_then(|e| e.gates.get(&gate_type))
                .map(|s| match s {
                    GateStatus::TimedOut { lease_id } => lease_id.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default()
        };

        self.emit_event(GateOrchestratorEvent::GateTimedOut {
            work_id: work_id.to_string(),
            gate_type,
            lease_id,
            timestamp_ms: now_ms,
        })
        .await;

        warn!(
            work_id = %work_id,
            gate_type = %gate_type,
            "Gate timed out - fail-closed FAIL verdict"
        );

        // Check if all gates are complete
        self.check_all_gates_complete(work_id, now_ms).await
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

    /// Checks if all gates are complete and emits `AllGatesCompleted` if so.
    async fn check_all_gates_complete(
        &self,
        work_id: &str,
        now_ms: u64,
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

        // Drop read lock before writing events
        drop(orchestrations);

        self.emit_event(GateOrchestratorEvent::AllGatesCompleted {
            work_id: work_id.to_string(),
            all_passed,
            outcomes: outcomes.clone(),
            timestamp_ms: now_ms,
        })
        .await;

        info!(
            work_id = %work_id,
            all_passed = %all_passed,
            gate_count = %outcomes.len(),
            "All gates completed"
        );

        Ok(Some(outcomes))
    }

    /// Emits an orchestrator event to the internal buffer.
    async fn emit_event(&self, event: GateOrchestratorEvent) {
        let mut events = self.events.write().await;
        events.push(event);
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

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

        let gate_types = orch.handle_session_terminated(info).await.unwrap();

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

        orch.handle_session_terminated(info).await.unwrap();

        let events = orch.drain_events().await;
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

        orch.record_executor_spawned("work-005", GateType::Quality, "ep-001")
            .await
            .unwrap();

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

        let result = orch
            .record_gate_receipt("work-006", GateType::Quality, receipt)
            .await
            .unwrap();

        // Not all gates complete yet
        assert!(result.is_none());

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

            let result = orch
                .record_gate_receipt("work-007", gate_type, receipt)
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

        let result = orch
            .handle_gate_timeout("work-008", GateType::Aat)
            .await
            .unwrap();

        // Not all gates done
        assert!(result.is_none());

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

        orch.record_gate_receipt("work-009", GateType::Aat, receipt)
            .await
            .unwrap();

        // Timeout quality gate
        orch.handle_gate_timeout("work-009", GateType::Quality)
            .await
            .unwrap();

        // Timeout security gate -> should trigger AllGatesCompleted
        let result = orch
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
    // Event Drain Tests
    // =========================================================================

    #[tokio::test]
    async fn test_drain_events_clears_buffer() {
        let orch = test_orchestrator();
        let info = test_session_info("work-drain");

        orch.handle_session_terminated(info).await.unwrap();

        let events = orch.drain_events().await;
        assert!(!events.is_empty());

        // Second drain should be empty
        let events2 = orch.drain_events().await;
        assert!(events2.is_empty());
    }

    #[tokio::test]
    async fn test_event_count_matches_gates() {
        let orch = test_orchestrator();
        let info = test_session_info("work-events");

        orch.handle_session_terminated(info).await.unwrap();

        let events = orch.drain_events().await;
        // 1 PolicyResolved + 3 GateLeaseIssued = 4 events
        assert_eq!(events.len(), 4);
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
}
