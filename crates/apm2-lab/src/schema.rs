use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdlcToySpec {
    pub kind: String,
    pub version: String,
    pub goal: GoalSpec,
    pub task: TaskTemplateSpec,
    pub agents: Vec<SdlcAgentSpec>,
    pub policy: SdlcPolicySpec,
    #[serde(default)]
    pub sandbox: SandboxPolicySpec,
    pub outputs: SdlcOutputSpec,
}

impl SdlcToySpec {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).with_context(|| format!("read spec {}", path.display()))?;
        let spec: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse spec {}", path.display()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.agents.len() < 2 {
            return Err(anyhow!("toy SDLC spec requires at least two agents"));
        }
        if self.policy.max_ticks == 0 {
            return Err(anyhow!("policy.max_ticks must be > 0"));
        }
        if self.policy.requirement_quorum < 2 {
            return Err(anyhow!("policy.requirement_quorum must be >= 2"));
        }
        if self.policy.submit_deadline_ticks == 0 {
            return Err(anyhow!("policy.submit_deadline_ticks must be > 0"));
        }
        if self.policy.verify_deadline_ticks == 0 {
            return Err(anyhow!("policy.verify_deadline_ticks must be > 0"));
        }
        if self.goal.id.trim().is_empty() {
            return Err(anyhow!("goal.id must not be empty"));
        }
        if self.task.command_name.trim().is_empty() {
            return Err(anyhow!("task.command_name must not be empty"));
        }

        let mut seen_agents = BTreeSet::new();
        for agent in &self.agents {
            if !seen_agents.insert(agent.id.clone()) {
                return Err(anyhow!("duplicate agent id '{}'", agent.id));
            }
            if agent.initial_budget_tokens == 0 {
                return Err(anyhow!(
                    "agent '{}' initial_budget_tokens must be > 0",
                    agent.id
                ));
            }
        }

        if self.outputs.metrics_path.trim().is_empty()
            || self.outputs.summary_path.trim().is_empty()
            || self.outputs.trace_path.trim().is_empty()
            || self.outputs.ledger_path.trim().is_empty()
        {
            return Err(anyhow!("all output paths must be non-empty"));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalSpec {
    pub id: String,
    pub statement: String,
    pub problem_statement: String,
    pub objective_function: String,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub acceptance_predicates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskTemplateSpec {
    pub command_name: String,
    pub summary: String,
    #[serde(default)]
    pub target_paths: Vec<String>,
    #[serde(default)]
    pub acceptance_predicates: Vec<String>,
    #[serde(default)]
    pub verification_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdlcAgentSpec {
    pub id: String,
    pub specialty: String,
    pub initial_budget_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdlcPolicySpec {
    pub max_ticks: u64,
    pub requirement_quorum: usize,
    pub submit_deadline_ticks: u64,
    pub verify_deadline_ticks: u64,
    pub action_costs: ActionCostSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCostSpec {
    pub propose_requirement: u64,
    pub attest_requirement: u64,
    pub propose_ticket: u64,
    pub claim_ticket: u64,
    pub submit_ticket: u64,
    pub verify_ticket: u64,
    pub pass: u64,
    pub obligation_breach_penalty: u64,
    pub ticket_reward: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdlcOutputSpec {
    pub metrics_path: String,
    pub summary_path: String,
    pub trace_path: String,
    pub ledger_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicySpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub simulate_command_results: bool,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub allowed_command_prefixes: Vec<String>,
    #[serde(default = "default_command_timeout_ms")]
    pub command_timeout_ms: u64,
}

impl Default for SandboxPolicySpec {
    fn default() -> Self {
        Self {
            enabled: false,
            simulate_command_results: true,
            allowed_paths: Vec::new(),
            allowed_command_prefixes: vec!["echo".to_string()],
            command_timeout_ms: default_command_timeout_ms(),
        }
    }
}

const fn default_command_timeout_ms() -> u64 {
    60_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementSpec {
    pub id: String,
    pub problem_statement: String,
    pub scope: Vec<String>,
    pub assumptions: Vec<String>,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub invariants: Vec<String>,
    pub acceptance_predicates: Vec<String>,
    pub non_goals: Vec<String>,
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub compose_with: Vec<String>,
    #[serde(default = "default_true")]
    pub critical: bool,
    pub trace: TraceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRef {
    pub goal_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketSpec {
    pub id: String,
    pub requirement_ids: Vec<String>,
    pub deliverables: Vec<String>,
    pub verification_plan: Vec<String>,
    pub commands_to_run: Vec<String>,
    pub evidence_required: Vec<String>,
    pub estimated_cost: TicketCost,
    pub depends_on_tickets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketCost {
    pub tokens: u64,
    pub commands: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub evidence_id: String,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionReceipt {
    pub subject_id: String,
    pub admitted: bool,
    pub by: String,
    pub tick: u64,
    pub reason: String,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLink {
    pub from_id: String,
    pub to_id: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum ObligationTarget {
    SubmitTicket { ticket_id: String },
    VerifyTicket { ticket_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    pub obligation_id: String,
    pub target: ObligationTarget,
    pub subject_agent: String,
    pub due_tick: u64,
    pub penalty_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SdlcEventKind {
    GoalProposed {
        goal: GoalSpec,
    },
    RequirementProposed {
        requirement: RequirementSpec,
    },
    RequirementAttested {
        requirement_id: String,
        approve: bool,
        rationale: String,
    },
    RequirementAdmitted {
        requirement_id: String,
        receipt: AdmissionReceipt,
    },
    TicketProposed {
        ticket: TicketSpec,
    },
    TicketClaimed {
        ticket_id: String,
    },
    TicketSubmitted {
        ticket_id: String,
        evidence: Vec<EvidenceRef>,
    },
    TicketVerified {
        ticket_id: String,
        verifier_id: String,
        pass: bool,
        notes: String,
        evidence: Vec<EvidenceRef>,
    },
    TicketAdmitted {
        ticket_id: String,
        receipt: AdmissionReceipt,
    },
    ObligationIssued {
        obligation: Obligation,
    },
    ObligationSatisfied {
        obligation_id: String,
    },
    ObligationBreached {
        obligation_id: String,
        subject_agent: String,
        penalty_tokens: u64,
        reason: String,
    },
    BudgetDebited {
        agent_id: String,
        amount: u64,
        reason: String,
    },
    BudgetCredited {
        agent_id: String,
        amount: u64,
        reason: String,
    },
    GoalCompleted {
        goal_id: String,
        receipt: AdmissionReceipt,
    },
    GoalFailed {
        goal_id: String,
        reason: String,
    },
    Pass {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdlcEvent {
    pub seq: u64,
    pub tick: u64,
    pub author_id: String,
    pub event: SdlcEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdlcAgentMetric {
    pub id: String,
    pub budget_tokens: u64,
    pub last_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdlcTickMetric {
    pub tick: u64,
    pub new_events: usize,
    pub requirements_admitted: usize,
    pub tickets_admitted: usize,
    pub obligations_open: usize,
    pub obligations_breached_total: usize,
    pub cumulative_cost_tokens: u64,
    pub agents: Vec<SdlcAgentMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SdlcRunSummary {
    pub seed: u64,
    pub goal_id: String,
    pub completed: bool,
    pub completion_tick: Option<u64>,
    pub max_ticks: u64,
    pub requirements_total: usize,
    pub requirements_admitted: usize,
    pub tickets_total: usize,
    pub tickets_admitted: usize,
    pub obligation_breaches: usize,
    pub overlap_violations: usize,
    pub contradiction_violations: usize,
    pub traceability_completeness: f64,
    pub total_tokens_spent: u64,
    pub total_events: usize,
}

const fn default_true() -> bool {
    true
}
