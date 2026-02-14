//! Reducer-first FAC lifecycle authority.
//!
//! This module defines a machine-readable lifecycle model and a single
//! reducer entrypoint for PR/SHA lifecycle transitions and agent lifecycle
//! bookkeeping.

use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use clap::ValueEnum;
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::projection::fetch_pr_head_sha_authoritative;
use super::target::resolve_pr_target;
use super::types::{
    TerminationAuthority, apm2_home_dir, ensure_parent_dir,
    normalize_decision_dimension as normalize_verdict_dimension, now_iso8601, sanitize_for_path,
    validate_expected_head_sha,
};
use super::{dispatch, projection_store, state, verdict_projection};
use crate::exit_codes::codes as exit_codes;

const MACHINE_SCHEMA: &str = "apm2.fac.lifecycle_machine.v1";
const PR_STATE_SCHEMA: &str = "apm2.fac.lifecycle_state.v1";
const AGENT_REGISTRY_SCHEMA: &str = "apm2.fac.agent_registry.v1";
const RECOVER_SUMMARY_SCHEMA: &str = "apm2.fac.recover_summary.v1";
const MAX_EVENT_HISTORY: usize = 256;
const MAX_ACTIVE_AGENTS_PER_PR: usize = 2;
const MAX_ERROR_BUDGET: u32 = 10;
const DEFAULT_RETRY_BUDGET: u32 = 3;
const DEFAULT_TOKEN_TTL_SECS: i64 = 3600;

pub(super) const fn default_retry_budget() -> u32 {
    DEFAULT_RETRY_BUDGET
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrLifecycleState {
    Untracked,
    Pushed,
    GatesRunning,
    GatesPassed,
    GatesFailed,
    ReviewsDispatched,
    ReviewInProgress,
    VerdictPending,
    VerdictApprove,
    VerdictDeny,
    MergeReady,
    Merged,
    Stuck,
    Stale,
    Recovering,
    Quarantined,
}

impl PrLifecycleState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Untracked => "untracked",
            Self::Pushed => "pushed",
            Self::GatesRunning => "gates_running",
            Self::GatesPassed => "gates_passed",
            Self::GatesFailed => "gates_failed",
            Self::ReviewsDispatched => "reviews_dispatched",
            Self::ReviewInProgress => "review_in_progress",
            Self::VerdictPending => "verdict_pending",
            Self::VerdictApprove => "verdict_approve",
            Self::VerdictDeny => "verdict_deny",
            Self::MergeReady => "merge_ready",
            Self::Merged => "merged",
            Self::Stuck => "stuck",
            Self::Stale => "stale",
            Self::Recovering => "recovering",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Implementer,
    ReviewerSecurity,
    ReviewerQuality,
    Orchestrator,
    GateExecutor,
}

impl AgentType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Implementer => "implementer",
            Self::ReviewerSecurity => "reviewer_security",
            Self::ReviewerQuality => "reviewer_quality",
            Self::Orchestrator => "orchestrator",
            Self::GateExecutor => "gate_executor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VerdictValueArg {
    Approve,
    Deny,
}

impl VerdictValueArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrackedAgentState {
    Dispatched,
    Running,
    Completed,
    Crashed,
    Reaped,
    Stuck,
}

impl TrackedAgentState {
    const fn is_active(self) -> bool {
        matches!(self, Self::Dispatched | Self::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvent {
    pub seq: u64,
    pub ts: String,
    pub sha: String,
    pub event: String,
    #[serde(default)]
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrLifecycleRecord {
    pub schema: String,
    pub owner_repo: String,
    pub pr_number: u32,
    pub current_sha: String,
    pub pr_state: PrLifecycleState,
    #[serde(default)]
    pub verdicts: BTreeMap<String, String>,
    pub error_budget_used: u32,
    pub retry_budget_remaining: u32,
    pub updated_at: String,
    pub last_event_seq: u64,
    #[serde(default)]
    pub events: Vec<LifecycleEvent>,
}

impl PrLifecycleRecord {
    fn new(owner_repo: &str, pr_number: u32, sha: &str) -> Self {
        Self {
            schema: PR_STATE_SCHEMA.to_string(),
            owner_repo: owner_repo.to_ascii_lowercase(),
            pr_number,
            current_sha: sha.to_ascii_lowercase(),
            pr_state: PrLifecycleState::Untracked,
            verdicts: BTreeMap::new(),
            error_budget_used: 0,
            retry_budget_remaining: DEFAULT_RETRY_BUDGET,
            updated_at: now_iso8601(),
            last_event_seq: 0,
            events: Vec::new(),
        }
    }

    fn append_event(&mut self, sha: &str, event: &str, detail: serde_json::Value) {
        self.last_event_seq = self.last_event_seq.saturating_add(1);
        self.updated_at = now_iso8601();
        self.events.push(LifecycleEvent {
            seq: self.last_event_seq,
            ts: self.updated_at.clone(),
            sha: sha.to_ascii_lowercase(),
            event: event.to_string(),
            detail,
        });
        if self.events.len() > MAX_EVENT_HISTORY {
            let excess = self.events.len() - MAX_EVENT_HISTORY;
            self.events.drain(0..excess);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackedAgent {
    agent_id: String,
    owner_repo: String,
    pr_number: u32,
    sha: String,
    run_id: String,
    agent_type: AgentType,
    state: TrackedAgentState,
    started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proc_start_time: Option<u64>,
    completion_token_hash: String,
    token_expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reap_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRegistry {
    schema: String,
    updated_at: String,
    #[serde(default)]
    entries: Vec<TrackedAgent>,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self {
            schema: AGENT_REGISTRY_SCHEMA.to_string(),
            updated_at: now_iso8601(),
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoverSummary {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    refreshed_identity: bool,
    head_sha: String,
    reaped_agents: usize,
    state: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum LifecycleEventKind {
    PushObserved,
    GatesStarted,
    GatesPassed,
    GatesFailed,
    ReviewsDispatched,
    ReviewerSpawned { review_type: String },
    VerdictSet { dimension: String, decision: String },
    AgentCrashed { agent_type: AgentType },
    ShaDriftDetected,
    RecoverRequested,
    RecoverCompleted,
    Quarantined { reason: String },
    ProjectionFailed { reason: String },
}

impl LifecycleEventKind {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::PushObserved => "push_observed",
            Self::GatesStarted => "gates_started",
            Self::GatesPassed => "gates_passed",
            Self::GatesFailed => "gates_failed",
            Self::ReviewsDispatched => "reviews_dispatched",
            Self::ReviewerSpawned { .. } => "reviewer_spawned",
            Self::VerdictSet { .. } => "verdict_set",
            Self::AgentCrashed { .. } => "agent_crashed",
            Self::ShaDriftDetected => "sha_drift_detected",
            Self::RecoverRequested => "recover_requested",
            Self::RecoverCompleted => "recover_completed",
            Self::Quarantined { .. } => "quarantined",
            Self::ProjectionFailed { .. } => "projection_failed",
        }
    }
}

fn lifecycle_root() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("fac_lifecycle"))
}

fn pr_state_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(lifecycle_root()?
        .join("pr")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}.json")))
}

fn pr_state_lock_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(lifecycle_root()?
        .join("pr")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}.lock")))
}

fn machine_artifact_path() -> Result<PathBuf, String> {
    Ok(lifecycle_root()?.join("fac_lifecycle_machine.v1.json"))
}

fn registry_path() -> Result<PathBuf, String> {
    Ok(lifecycle_root()?.join("agent_registry.v1.json"))
}

fn registry_lock_path() -> Result<PathBuf, String> {
    Ok(lifecycle_root()?.join("agent_registry.lock"))
}

fn acquire_registry_lock() -> Result<std::fs::File, String> {
    let lock_path = registry_lock_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open registry lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "failed to acquire registry lock {}: {err}",
            lock_path.display()
        )
    })?;
    Ok(lock_file)
}

fn acquire_pr_state_lock(owner_repo: &str, pr_number: u32) -> Result<std::fs::File, String> {
    let lock_path = pr_state_lock_path(owner_repo, pr_number)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open lifecycle state lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "failed to acquire lifecycle state lock {}: {err}",
            lock_path.display()
        )
    })?;
    Ok(lock_file)
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create temp file: {err}"))?;
    temp.write_all(&payload)
        .map_err(|err| format!("failed to write temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

fn load_pr_state(owner_repo: &str, pr_number: u32, sha: &str) -> Result<PrLifecycleRecord, String> {
    let path = pr_state_path(owner_repo, pr_number)?;
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PrLifecycleRecord::new(owner_repo, pr_number, sha));
        },
        Err(err) => {
            return Err(format!(
                "failed to read lifecycle state {}: {err}",
                path.display()
            ));
        },
    };
    let mut parsed: PrLifecycleRecord = serde_json::from_slice(&bytes)
        .map_err(|err| format!("failed to parse lifecycle state {}: {err}", path.display()))?;
    if parsed.schema != PR_STATE_SCHEMA {
        return Err(format!(
            "unexpected lifecycle state schema {} at {}",
            parsed.schema,
            path.display()
        ));
    }
    parsed.owner_repo = parsed.owner_repo.to_ascii_lowercase();
    if parsed.pr_number != pr_number {
        return Err(format!(
            "lifecycle state identity mismatch for {}: expected pr={}, got pr={}",
            path.display(),
            pr_number,
            parsed.pr_number
        ));
    }
    Ok(parsed)
}

fn save_pr_state(state: &PrLifecycleRecord) -> Result<PathBuf, String> {
    let path = pr_state_path(&state.owner_repo, state.pr_number)?;
    atomic_write_json(&path, state)?;
    Ok(path)
}

fn load_registry() -> Result<AgentRegistry, String> {
    let path = registry_path()?;
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AgentRegistry::default());
        },
        Err(err) => {
            return Err(format!(
                "failed to read agent registry {}: {err}",
                path.display()
            ));
        },
    };
    let mut parsed: AgentRegistry = serde_json::from_slice(&bytes)
        .map_err(|err| format!("failed to parse agent registry {}: {err}", path.display()))?;
    if parsed.schema != AGENT_REGISTRY_SCHEMA {
        return Err(format!(
            "unexpected agent registry schema {} at {}",
            parsed.schema,
            path.display()
        ));
    }
    parsed.updated_at = now_iso8601();
    Ok(parsed)
}

fn save_registry(registry: &AgentRegistry) -> Result<PathBuf, String> {
    let path = registry_path()?;
    atomic_write_json(&path, registry)?;
    Ok(path)
}

fn token_ttl() -> Duration {
    let secs = std::env::var("APM2_FAC_DONE_TOKEN_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_TOKEN_TTL_SECS);
    Duration::seconds(secs)
}

fn generate_completion_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_utc(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn tracked_agent_id(
    owner_repo: &str,
    pr_number: u32,
    run_id: &str,
    agent_type: AgentType,
) -> String {
    format!(
        "{}::pr{}::{}::{}",
        owner_repo.to_ascii_lowercase(),
        pr_number,
        run_id,
        agent_type.as_str()
    )
}

fn active_agents_for_pr(registry: &AgentRegistry, owner_repo: &str, pr_number: u32) -> usize {
    let owner_repo = owner_repo.to_ascii_lowercase();
    registry
        .entries
        .iter()
        .filter(|entry| entry.owner_repo.eq_ignore_ascii_case(&owner_repo))
        .filter(|entry| entry.pr_number == pr_number)
        .filter(|entry| entry.state.is_active())
        .count()
}

fn reap_registry_stale_entries(registry: &mut AgentRegistry) -> usize {
    let mut reaped = 0usize;
    let stale_without_pid_after = token_ttl() * 2;
    for entry in &mut registry.entries {
        if !entry.state.is_active() {
            continue;
        }

        let mut reap_reason = None;
        if let Some(pid) = entry.pid {
            if !state::is_process_alive(pid) {
                reap_reason = Some("pid_not_alive");
            } else if let Some(expected_start) = entry.proc_start_time {
                let observed = state::get_process_start_time(pid);
                if observed.is_some_and(|value| value != expected_start) {
                    reap_reason = Some("pid_reused");
                }
            }
        } else {
            let started_at = parse_utc(&entry.started_at);
            if started_at
                .and_then(|value| Utc::now().signed_duration_since(value).to_std().ok())
                .is_some_and(|value| value >= stale_without_pid_after.to_std().unwrap_or_default())
            {
                reap_reason = Some("stale_without_pid");
            }
        }

        if let Some(reason) = reap_reason {
            entry.state = TrackedAgentState::Reaped;
            entry.completed_at = Some(now_iso8601());
            entry.reap_reason = Some(reason.to_string());
            reaped = reaped.saturating_add(1);
        }
    }
    if reaped > 0 {
        registry.updated_at = now_iso8601();
    }
    reaped
}

fn normalize_verdict_decision(decision: &str) -> Result<&'static str, String> {
    let normalized = decision.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "approve" => Ok("approve"),
        "deny" => Ok("deny"),
        _ => Err(format!(
            "invalid verdict decision `{decision}` (expected approve|deny)"
        )),
    }
}

fn next_state_for_event(
    state: &PrLifecycleRecord,
    event: &LifecycleEventKind,
) -> Result<PrLifecycleState, String> {
    use PrLifecycleState as S;
    match event {
        LifecycleEventKind::PushObserved => match state.pr_state {
            S::Untracked
            | S::Pushed
            | S::GatesRunning
            | S::GatesPassed
            | S::GatesFailed
            | S::ReviewsDispatched
            | S::ReviewInProgress
            | S::VerdictPending
            | S::VerdictApprove
            | S::VerdictDeny
            | S::MergeReady
            | S::Stuck
            | S::Stale
            | S::Recovering => Ok(S::Pushed),
            _ => Err(format!(
                "illegal transition: {} + push_observed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::GatesStarted => match state.pr_state {
            S::Pushed | S::GatesFailed | S::Recovering => Ok(S::GatesRunning),
            _ => Err(format!(
                "illegal transition: {} + gates_started",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::GatesPassed => match state.pr_state {
            S::GatesRunning => Ok(S::GatesPassed),
            _ => Err(format!(
                "illegal transition: {} + gates_passed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::GatesFailed => match state.pr_state {
            S::GatesRunning => Ok(S::GatesFailed),
            _ => Err(format!(
                "illegal transition: {} + gates_failed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::ReviewsDispatched => match state.pr_state {
            S::GatesPassed | S::ReviewsDispatched | S::ReviewInProgress | S::VerdictPending => {
                Ok(S::ReviewsDispatched)
            },
            _ => Err(format!(
                "illegal transition: {} + reviews_dispatched",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::ReviewerSpawned { .. } => match state.pr_state {
            S::ReviewsDispatched | S::ReviewInProgress | S::VerdictPending => {
                Ok(S::ReviewInProgress)
            },
            _ => Err(format!(
                "illegal transition: {} + reviewer_spawned",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::VerdictSet {
            dimension,
            decision,
        } => {
            let _ = normalize_verdict_dimension(dimension)?;
            let normalized_decision = normalize_verdict_decision(decision)?;
            match state.pr_state {
                S::ReviewsDispatched
                | S::ReviewInProgress
                | S::VerdictPending
                | S::VerdictApprove
                | S::VerdictDeny
                | S::MergeReady => {
                    if normalized_decision == "deny" {
                        return Ok(S::VerdictDeny);
                    }
                    if state
                        .verdicts
                        .values()
                        .any(|value| value.eq_ignore_ascii_case("deny"))
                    {
                        return Ok(S::VerdictDeny);
                    }
                    let sec = state
                        .verdicts
                        .get("security")
                        .is_some_and(|value| value.eq_ignore_ascii_case("approve"));
                    let qual = state
                        .verdicts
                        .get("code-quality")
                        .is_some_and(|value| value.eq_ignore_ascii_case("approve"));
                    if sec && qual {
                        Ok(S::MergeReady)
                    } else {
                        Ok(S::VerdictPending)
                    }
                },
                _ => Err(format!(
                    "illegal transition: {} + verdict_set",
                    state.pr_state.as_str()
                )),
            }
        },
        LifecycleEventKind::AgentCrashed { .. } => Ok(S::Stuck),
        LifecycleEventKind::ShaDriftDetected => Ok(S::Stale),
        LifecycleEventKind::RecoverRequested => match state.pr_state {
            S::Stale | S::Stuck | S::Quarantined => Ok(S::Recovering),
            _ => Err(format!(
                "illegal transition: {} + recover_requested",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::RecoverCompleted => match state.pr_state {
            S::Recovering => Ok(S::Pushed),
            _ => Err(format!(
                "illegal transition: {} + recover_completed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::Quarantined { .. } => Ok(S::Quarantined),
        LifecycleEventKind::ProjectionFailed { .. } => Ok(state.pr_state),
    }
}

fn event_detail(event: &LifecycleEventKind) -> serde_json::Value {
    match event {
        LifecycleEventKind::ReviewerSpawned { review_type } => {
            serde_json::json!({ "review_type": review_type })
        },
        LifecycleEventKind::VerdictSet {
            dimension,
            decision,
        } => serde_json::json!({
            "dimension": dimension,
            "decision": decision,
        }),
        LifecycleEventKind::AgentCrashed { agent_type } => serde_json::json!({
            "agent_type": agent_type.as_str(),
        }),
        LifecycleEventKind::Quarantined { reason }
        | LifecycleEventKind::ProjectionFailed { reason } => serde_json::json!({
            "reason": reason,
        }),
        _ => serde_json::json!({}),
    }
}

pub fn ensure_machine_artifact() -> Result<PathBuf, String> {
    let path = machine_artifact_path()?;
    if path.exists() {
        return Ok(path);
    }
    let transitions = vec![
        serde_json::json!({"from":"untracked|pushed|gates_running|gates_passed|gates_failed|reviews_dispatched|review_in_progress|verdict_pending|verdict_approve|verdict_deny|merge_ready|stuck|stale|recovering","event":"push_observed","to":"pushed"}),
        serde_json::json!({"from":"pushed|gates_failed|recovering","event":"gates_started","to":"gates_running"}),
        serde_json::json!({"from":"gates_running","event":"gates_passed","to":"gates_passed"}),
        serde_json::json!({"from":"gates_running","event":"gates_failed","to":"gates_failed"}),
        serde_json::json!({"from":"gates_passed|reviews_dispatched|review_in_progress|verdict_pending","event":"reviews_dispatched","to":"reviews_dispatched"}),
        serde_json::json!({"from":"reviews_dispatched|review_in_progress|verdict_pending","event":"reviewer_spawned","to":"review_in_progress"}),
        serde_json::json!({"from":"reviews_dispatched|review_in_progress|verdict_pending|verdict_approve|verdict_deny|merge_ready","event":"verdict_set","to":"verdict_pending|verdict_deny|merge_ready"}),
        serde_json::json!({"from":"*","event":"sha_drift_detected","to":"stale"}),
        serde_json::json!({"from":"stale|stuck|quarantined","event":"recover_requested","to":"recovering"}),
        serde_json::json!({"from":"recovering","event":"recover_completed","to":"pushed"}),
    ];
    let machine = serde_json::json!({
        "schema": MACHINE_SCHEMA,
        "generated_at": now_iso8601(),
        "illegal_transition_policy": "fail_closed",
        "states": {
            "pr_lifecycle": [
                "untracked","pushed","gates_running","gates_passed","gates_failed",
                "reviews_dispatched","review_in_progress","verdict_pending",
                "verdict_approve","verdict_deny","merge_ready","merged",
                "stuck","stale","recovering","quarantined"
            ],
            "agent_lifecycle": [
                "dispatched","running","completed","crashed","reaped","stuck"
            ]
        },
        "transitions": transitions
    });
    atomic_write_json(&path, &machine)?;
    Ok(path)
}

pub fn apply_event(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    event: &LifecycleEventKind,
) -> Result<PrLifecycleRecord, String> {
    validate_expected_head_sha(sha)?;
    ensure_machine_artifact()?;
    let _state_lock = acquire_pr_state_lock(owner_repo, pr_number)?;
    let mut record = load_pr_state(owner_repo, pr_number, sha)?;
    let sha = sha.to_ascii_lowercase();

    if !record.current_sha.eq_ignore_ascii_case(&sha) {
        record.pr_state = PrLifecycleState::Stale;
        record.current_sha.clone_from(&sha);
        record.append_event(
            &sha,
            "sha_drift_detected",
            serde_json::json!({"reason":"event_sha_mismatch"}),
        );
    }

    match &event {
        LifecycleEventKind::VerdictSet {
            dimension,
            decision,
        } => {
            let dim = normalize_verdict_dimension(dimension)?;
            let dec = normalize_verdict_decision(decision)?;
            record.verdicts.insert(dim.to_string(), dec.to_string());
        },
        LifecycleEventKind::ShaDriftDetected => {
            record.current_sha.clone_from(&sha);
        },
        _ => {},
    }

    let next_state = next_state_for_event(&record, event)?;
    record.pr_state = next_state;
    if record.pr_state == PrLifecycleState::Stuck {
        record.error_budget_used = record.error_budget_used.saturating_add(1);
        if record.error_budget_used >= MAX_ERROR_BUDGET {
            record.append_event(
                &sha,
                "error_budget_exhausted",
                serde_json::json!({
                    "error_budget_used": record.error_budget_used,
                    "max_error_budget": MAX_ERROR_BUDGET,
                }),
            );
        }
    }
    record.append_event(&sha, event.as_str(), event_detail(event));
    save_pr_state(&record)?;
    Ok(record)
}

pub fn enforce_pr_capacity(owner_repo: &str, pr_number: u32) -> Result<(), String> {
    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let _ = reap_registry_stale_entries(&mut registry);
    let active = active_agents_for_pr(&registry, owner_repo, pr_number);
    if active >= MAX_ACTIVE_AGENTS_PER_PR {
        save_registry(&registry)?;
        return Err(format!(
            "at_capacity: PR #{pr_number} already has {active} active agents (max={MAX_ACTIVE_AGENTS_PER_PR})"
        ));
    }
    save_registry(&registry)?;
    Ok(())
}

pub fn register_agent_spawn(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    run_id: &str,
    agent_type: AgentType,
    pid: Option<u32>,
    proc_start_time: Option<u64>,
) -> Result<String, String> {
    validate_expected_head_sha(sha)?;
    if run_id.trim().is_empty() {
        return Err("cannot register agent spawn with empty run_id".to_string());
    }

    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let _ = reap_registry_stale_entries(&mut registry);
    let active = active_agents_for_pr(&registry, owner_repo, pr_number);
    if active >= MAX_ACTIVE_AGENTS_PER_PR {
        save_registry(&registry)?;
        return Err(format!(
            "at_capacity: PR #{pr_number} already has {active} active agents (max={MAX_ACTIVE_AGENTS_PER_PR})"
        ));
    }

    let token = generate_completion_token();
    let token_hash = token_hash(&token);
    let expires_at = (Utc::now() + token_ttl()).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let agent_id = tracked_agent_id(owner_repo, pr_number, run_id, agent_type);
    registry.entries.retain(|entry| entry.agent_id != agent_id);
    registry.entries.push(TrackedAgent {
        agent_id,
        owner_repo: owner_repo.to_ascii_lowercase(),
        pr_number,
        sha: sha.to_ascii_lowercase(),
        run_id: run_id.to_string(),
        agent_type,
        state: if pid.is_some() {
            TrackedAgentState::Running
        } else {
            TrackedAgentState::Dispatched
        },
        started_at: now_iso8601(),
        completed_at: None,
        pid,
        proc_start_time,
        completion_token_hash: token_hash,
        token_expires_at: expires_at,
        completion_status: None,
        completion_summary: None,
        reap_reason: None,
    });
    registry.updated_at = now_iso8601();
    save_registry(&registry)?;
    Ok(token)
}

fn mark_registered_agent_reaped(
    owner_repo: &str,
    pr_number: u32,
    run_id: &str,
    agent_type: AgentType,
    reason: &str,
) -> Result<(), String> {
    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let agent_id = tracked_agent_id(owner_repo, pr_number, run_id, agent_type);
    let mut changed = false;
    for entry in &mut registry.entries {
        if entry.agent_id == agent_id {
            entry.state = TrackedAgentState::Reaped;
            entry.completed_at = Some(now_iso8601());
            entry.reap_reason = Some(reason.to_string());
            changed = true;
            break;
        }
    }
    if changed {
        registry.updated_at = now_iso8601();
        save_registry(&registry)?;
    }
    Ok(())
}

fn rollback_registered_reviewer_dispatch(
    owner_repo: &str,
    pr_number: u32,
    run_id: &str,
    agent_type: AgentType,
    pid: Option<u32>,
    reason: &str,
) -> Result<(), String> {
    if let Some(pid) = pid
        && state::is_process_alive(pid)
    {
        dispatch::terminate_process_with_timeout(pid).map_err(|err| {
            format!("failed to terminate spawned reviewer pid={pid} during rollback: {err}")
        })?;
    }
    mark_registered_agent_reaped(owner_repo, pr_number, run_id, agent_type, reason)
}

pub fn register_reviewer_dispatch(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    review_type: &str,
    run_id: Option<&str>,
    pid: Option<u32>,
    proc_start_time: Option<u64>,
) -> Result<Option<String>, String> {
    let agent_type = match review_type {
        "security" => AgentType::ReviewerSecurity,
        "quality" => AgentType::ReviewerQuality,
        _ => return Ok(None),
    };
    let Some(run_id) = run_id else {
        return Ok(None);
    };
    let token = match register_agent_spawn(
        owner_repo,
        pr_number,
        sha,
        run_id,
        agent_type,
        pid,
        proc_start_time,
    ) {
        Ok(token) => token,
        Err(err) => {
            if let Some(pid) = pid
                && state::is_process_alive(pid)
            {
                dispatch::terminate_process_with_timeout(pid).map_err(|kill_err| {
                    format!(
                        "{err}; additionally failed to terminate unregistered reviewer pid={pid}: {kill_err}"
                    )
                })?;
            }
            return Err(err);
        },
    };
    if let Err(err) = apply_event(
        owner_repo,
        pr_number,
        sha,
        &LifecycleEventKind::ReviewsDispatched,
    ) {
        let rollback_reason = "rollback:lifecycle_reviews_dispatched_failed";
        match rollback_registered_reviewer_dispatch(
            owner_repo,
            pr_number,
            run_id,
            agent_type,
            pid,
            rollback_reason,
        ) {
            Ok(()) => return Err(err),
            Err(rollback_err) => {
                return Err(format!(
                    "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}"
                ));
            },
        }
    }
    if let Err(err) = apply_event(
        owner_repo,
        pr_number,
        sha,
        &LifecycleEventKind::ReviewerSpawned {
            review_type: review_type.to_string(),
        },
    ) {
        let rollback_reason = "rollback:lifecycle_reviewer_spawned_failed";
        match rollback_registered_reviewer_dispatch(
            owner_repo,
            pr_number,
            run_id,
            agent_type,
            pid,
            rollback_reason,
        ) {
            Ok(()) => return Err(err),
            Err(rollback_err) => {
                return Err(format!(
                    "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}"
                ));
            },
        }
    }
    Ok(Some(token))
}

#[allow(clippy::too_many_arguments)]
pub fn run_verdict_set(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    verdict: VerdictValueArg,
    reason: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> u8 {
    match run_verdict_set_inner(
        repo,
        pr_number,
        sha,
        dimension,
        verdict,
        reason,
        keep_prepared_inputs,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_verdict_set_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn run_verdict_set_inner(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    verdict: VerdictValueArg,
    reason: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> Result<u8, String> {
    let projected = verdict_projection::persist_verdict_projection(
        repo,
        pr_number,
        sha,
        dimension,
        verdict.as_str(),
        reason,
        json_output,
    )?;
    if !keep_prepared_inputs {
        if let Err(err) = super::prepare::cleanup_prepared_review_inputs(
            &projected.owner_repo,
            projected.pr_number,
            &projected.head_sha,
        ) {
            eprintln!("WARNING: failed to clean prepared review inputs: {err}");
        }
    }

    let termination_state =
        state::load_review_run_state_strict(projected.pr_number, &projected.review_state_type)?;
    let termination_state_non_terminal_alive = termination_state
        .as_ref()
        .is_some_and(|state| state.status == super::types::ReviewRunStatus::Alive);
    let run_id = termination_state
        .as_ref()
        .map(|state| state.run_id.clone())
        .unwrap_or_default();
    let authority = TerminationAuthority::new(
        &projected.owner_repo,
        projected.pr_number,
        &projected.review_state_type,
        &projected.head_sha,
        &run_id,
        projected.decision_comment_id,
        &projected.decision_author,
        &now_iso8601(),
        &projected.decision_signature,
    );
    let home = apm2_home_dir()?;
    let projected_decision = projected.decision.clone();

    match dispatch::terminate_review_agent_for_home(&home, &authority)? {
        dispatch::TerminationOutcome::Killed | dispatch::TerminationOutcome::AlreadyDead => {
            let lifecycle_dimension = match projected.review_state_type.as_str() {
                "quality" => "code-quality".to_string(),
                "security" => "security".to_string(),
                _ => normalize_verdict_dimension(dimension)?.to_string(),
            };
            apply_event(
                &projected.owner_repo,
                projected.pr_number,
                &projected.head_sha,
                &LifecycleEventKind::VerdictSet {
                    dimension: lifecycle_dimension,
                    decision: projected_decision.clone(),
                },
            )?;
            dispatch::write_completion_receipt_for_verdict(&home, &authority, &projected_decision)?;
            Ok(exit_codes::SUCCESS)
        },
        dispatch::TerminationOutcome::SkippedMismatch => {
            if termination_state_non_terminal_alive {
                return Err(format!(
                    "verdict NOT finalized for PR #{} type={}: termination authority mismatch while lane was alive",
                    projected.pr_number, dimension
                ));
            }
            let lifecycle_dimension = match projected.review_state_type.as_str() {
                "quality" => "code-quality".to_string(),
                "security" => "security".to_string(),
                _ => normalize_verdict_dimension(dimension)?.to_string(),
            };
            apply_event(
                &projected.owner_repo,
                projected.pr_number,
                &projected.head_sha,
                &LifecycleEventKind::VerdictSet {
                    dimension: lifecycle_dimension,
                    decision: projected_decision.clone(),
                },
            )?;
            dispatch::write_completion_receipt_for_verdict(&home, &authority, &projected_decision)?;
            Ok(exit_codes::SUCCESS)
        },
        dispatch::TerminationOutcome::IdentityFailure(reason) => Err(format!(
            "verdict NOT finalized for PR #{} type={}: reviewer termination failed (identity): {reason}",
            projected.pr_number, dimension
        )),
        dispatch::TerminationOutcome::IntegrityFailure(reason) => Err(format!(
            "verdict NOT finalized for PR #{} type={}: reviewer termination integrity check failed: {reason}",
            projected.pr_number, dimension
        )),
    }
}

pub fn run_verdict_show(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match verdict_projection::run_verdict_show(repo, pr_number, sha, json_output) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_verdict_show_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_recover(
    repo: &str,
    pr_number: Option<u32>,
    refresh_identity: bool,
    json_output: bool,
) -> u8 {
    match run_recover_inner(repo, pr_number, refresh_identity) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Recover");
                println!("  Repo:              {}", summary.owner_repo);
                println!("  PR:                #{}", summary.pr_number);
                println!("  Head SHA:          {}", summary.head_sha);
                println!("  Reaped Agents:     {}", summary.reaped_agents);
                println!("  Refreshed Identity:{}", summary.refreshed_identity);
                println!("  Lifecycle State:   {}", summary.state);
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_recover_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_recover_inner(
    repo: &str,
    pr_number: Option<u32>,
    refresh_identity: bool,
) -> Result<RecoverSummary, String> {
    ensure_machine_artifact()?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let head_sha = fetch_pr_head_sha_authoritative(&owner_repo, resolved_pr)?;
    validate_expected_head_sha(&head_sha)?;

    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let reaped = reap_registry_stale_entries(&mut registry);
    save_registry(&registry)?;

    apply_event(
        &owner_repo,
        resolved_pr,
        &head_sha,
        &LifecycleEventKind::RecoverRequested,
    )?;
    let reduced = apply_event(
        &owner_repo,
        resolved_pr,
        &head_sha,
        &LifecycleEventKind::RecoverCompleted,
    )?;

    if refresh_identity {
        projection_store::save_identity_with_context(
            &owner_repo,
            resolved_pr,
            &head_sha,
            "recover",
        )
        .map_err(|err| format!("failed to refresh local projection identity: {err}"))?;
    }

    Ok(RecoverSummary {
        schema: RECOVER_SUMMARY_SCHEMA.to_string(),
        owner_repo,
        pr_number: resolved_pr,
        refreshed_identity: refresh_identity,
        head_sha: head_sha.to_ascii_lowercase(),
        reaped_agents: reaped,
        state: reduced.pr_state.as_str().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{
        AgentType, LifecycleEventKind, PrLifecycleState, TrackedAgentState, active_agents_for_pr,
        apply_event, load_registry, register_agent_spawn, register_reviewer_dispatch, token_hash,
    };
    use crate::commands::fac_review::lifecycle::tracked_agent_id;

    static UNIQUE_PR_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn next_pr() -> u32 {
        let seq = UNIQUE_PR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let entropy = now.subsec_nanos() ^ seq.rotate_left(13) ^ std::process::id();
        1_000_000 + (entropy % 3_000_000_000)
    }

    fn next_repo(tag: &str, pr: u32) -> String {
        format!("example/{tag}-{pr}")
    }

    #[test]
    fn reducer_transitions_to_merge_ready_after_dual_approve() {
        let pr = next_pr();
        let repo = next_repo("reducer", pr);
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates start");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("gates pass");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("dispatch");
        let _ = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "security".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("security approve");
        let state = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "code-quality".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("quality approve");
        assert_eq!(state.pr_state, PrLifecycleState::MergeReady);
    }

    #[test]
    fn reducer_remains_verdict_deny_after_other_dimension_approves() {
        let pr = next_pr();
        let repo = next_repo("deny-sticky", pr);
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates start");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("gates pass");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("dispatch");
        let denied = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "security".to_string(),
                decision: "deny".to_string(),
            },
        )
        .expect("security deny");
        assert_eq!(denied.pr_state, PrLifecycleState::VerdictDeny);

        let still_denied = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "code-quality".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("quality approve");
        assert_eq!(still_denied.pr_state, PrLifecycleState::VerdictDeny);
    }

    #[test]
    fn recover_requested_is_rejected_from_non_recovery_states() {
        let pr = next_pr();
        let repo = next_repo("recover-guard", pr);
        let sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let err = apply_event(&repo, pr, sha, &LifecycleEventKind::RecoverRequested)
            .expect_err("recover_requested should be illegal from untracked");
        assert!(err.contains("illegal transition"));
    }

    #[test]
    fn recover_completed_requires_recovering_state() {
        let pr = next_pr();
        let repo = next_repo("recover-complete-guard", pr);
        let sha = "cccccccccccccccccccccccccccccccccccccccc";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let err = apply_event(&repo, pr, sha, &LifecycleEventKind::RecoverCompleted)
            .expect_err("recover_completed should require recovering");
        assert!(err.contains("illegal transition"));
    }

    #[test]
    fn at_capacity_is_enforced_for_same_pr() {
        let pr = next_pr();
        let repo = next_repo("capacity", pr);
        let sha = "2222222222222222222222222222222222222222";
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-security-s1-22222222"),
            AgentType::ReviewerSecurity,
            None,
            None,
        )
        .expect("first");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-quality-s2-22222222"),
            AgentType::ReviewerQuality,
            None,
            None,
        )
        .expect("second");
        let err = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-impl-s3-22222222"),
            AgentType::Implementer,
            None,
            None,
        )
        .expect_err("third should fail");
        assert!(err.contains("at_capacity"));
    }

    #[test]
    fn helper_functions_are_stable() {
        let id = tracked_agent_id("owner/repo", 99, "run-1", AgentType::Implementer);
        assert!(id.contains("owner/repo"));
        assert!(id.contains("run-1"));
        let hash = token_hash("token");
        assert_eq!(hash.len(), 64);
        let registry = load_registry().expect("registry");
        let _ = active_agents_for_pr(&registry, "owner/repo", 99);
    }

    #[test]
    fn register_reviewer_dispatch_rolls_back_registry_on_illegal_lifecycle_transition() {
        let pr = next_pr();
        let repo = next_repo("dispatch-rollback", pr);
        let sha = "dddddddddddddddddddddddddddddddddddddddd";
        let run_id = format!("pr{pr}-security-s1-dddddddd");

        let err = register_reviewer_dispatch(&repo, pr, sha, "security", Some(&run_id), None, None)
            .expect_err(
                "register should fail because lifecycle transition is illegal from untracked",
            );
        assert!(err.contains("illegal transition"));

        let registry = load_registry().expect("registry");
        assert_eq!(active_agents_for_pr(&registry, &repo, pr), 0);
        let entry_id = tracked_agent_id(&repo, pr, &run_id, AgentType::ReviewerSecurity);
        let entry = registry
            .entries
            .iter()
            .find(|value| value.agent_id == entry_id)
            .expect("spawned registry entry should exist for forensic audit");
        assert_eq!(entry.state, TrackedAgentState::Reaped);
        assert_eq!(
            entry.reap_reason.as_deref(),
            Some("rollback:lifecycle_reviews_dispatched_failed")
        );
    }
}
