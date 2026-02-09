use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::closure_sdlc::{SdlcClosureConfig, SdlcClosureReducer};
use crate::decompose::{
    decompose_goal, requirements_to_tickets, validate_requirements, validate_ticket_plan,
};
use crate::obligation::{submit_obligation, verify_obligation};
use crate::sandbox::{SandboxCommandResult, ensure_paths_allowed, run_commands};
use crate::schema::{
    EvidenceRef, SdlcAgentMetric, SdlcAgentSpec, SdlcEvent, SdlcEventKind, SdlcRunSummary,
    SdlcTickMetric, SdlcToySpec, TicketSpec, TraceLink,
};

#[derive(Debug, Clone)]
struct AgentRuntime {
    id: String,
    specialty: String,
    budget_tokens: u64,
    last_action: String,
}

#[derive(Debug, Clone, Default)]
struct SdlcStateView {
    requirement_proposed: BTreeSet<String>,
    requirement_attested_by: HashMap<String, BTreeSet<String>>,
    requirement_admitted: BTreeSet<String>,
    tickets_proposed: BTreeMap<String, TicketSpec>,
    ticket_claimed_by: HashMap<String, String>,
    ticket_submitted_by: HashMap<String, String>,
    ticket_verified_by: HashMap<String, BTreeSet<String>>,
    ticket_admitted: BTreeSet<String>,
    open_obligation_ids: BTreeSet<String>,
    goal_completed: bool,
    goal_failed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct TraceArtifact {
    goal_id: String,
    requirements: Vec<String>,
    tickets: Vec<String>,
    links: Vec<TraceLink>,
    admitted_requirements: Vec<String>,
    admitted_tickets: Vec<String>,
}

pub async fn run_sdlc_toy_from_path(
    spec_path: impl AsRef<Path>,
    seed: u64,
) -> Result<SdlcRunSummary> {
    let spec = SdlcToySpec::load(spec_path)?;
    run_sdlc_toy(spec, seed).await
}

pub async fn run_sdlc_toy(spec: SdlcToySpec, seed: u64) -> Result<SdlcRunSummary> {
    let requirements = decompose_goal(&spec.goal, &spec.task);
    let tickets = requirements_to_tickets(&requirements, &spec.task);
    let validation = validate_requirements(&requirements);
    validate_ticket_plan(&requirements, &tickets)?;

    ensure_paths_allowed(&spec.sandbox, &spec.task.target_paths)?;

    let expected_requirements: BTreeSet<_> =
        requirements.iter().map(|req| req.id.clone()).collect();
    let expected_tickets: BTreeSet<_> = tickets.iter().map(|ticket| ticket.id.clone()).collect();

    let mut rng = StdRng::seed_from_u64(seed ^ 0x5D1C_u64);
    let mut agents = init_agents(&spec.agents);
    let mut events = Vec::new();
    let mut seq = 1u64;
    let mut metrics = Vec::new();

    append_event(
        &mut events,
        &mut seq,
        1,
        "world",
        SdlcEventKind::GoalProposed {
            goal: spec.goal.clone(),
        },
        &mut agents,
    );

    let reducer = SdlcClosureReducer::new(SdlcClosureConfig {
        requirement_quorum: spec.policy.requirement_quorum,
        ticket_verify_quorum: 1,
    });

    for tick in 1..=spec.policy.max_ticks {
        let start_events = events.len();

        for (agent_index, agent_id) in agents
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .iter()
            .enumerate()
        {
            let mut state = build_state(&events);
            let mut actions = 0usize;

            actions += run_requirement_stage(
                tick,
                agent_id,
                agent_index,
                agents.len(),
                &requirements,
                &state,
                &spec,
                &mut events,
                &mut seq,
                &mut agents,
            );

            state = build_state(&events);
            actions += run_ticket_proposal_stage(
                tick,
                agent_id,
                agent_index,
                agents.len(),
                &tickets,
                &state,
                &spec,
                &mut events,
                &mut seq,
                &mut agents,
            );

            state = build_state(&events);
            actions += run_ticket_execution_stage(
                tick,
                agent_id,
                &state,
                &spec,
                &mut events,
                &mut seq,
                &mut agents,
                &mut rng,
            )
            .await?;

            if actions == 0 {
                charge_agent(
                    &mut events,
                    &mut seq,
                    tick,
                    agent_id,
                    spec.policy.action_costs.pass,
                    "pass",
                    &mut agents,
                );
                append_event(
                    &mut events,
                    &mut seq,
                    tick,
                    agent_id,
                    SdlcEventKind::Pass {
                        reason: "no admissible action".to_string(),
                    },
                    &mut agents,
                );
                set_last_action(&mut agents, agent_id, "pass");
            }
        }

        let closure = reducer.evaluate(&events, tick, &expected_requirements, &expected_tickets)?;
        for derived in closure.derived_events {
            append_event(&mut events, &mut seq, tick, "closure", derived, &mut agents);
        }

        let state = build_state(&events);
        metrics.push(SdlcTickMetric {
            tick,
            new_events: events.len().saturating_sub(start_events),
            requirements_admitted: state.requirement_admitted.len(),
            tickets_admitted: state.ticket_admitted.len(),
            obligations_open: state.open_obligation_ids.len(),
            obligations_breached_total: count_obligation_breaches(&events),
            cumulative_cost_tokens: total_debited_tokens(&events),
            agents: agents
                .values()
                .map(|agent| SdlcAgentMetric {
                    id: agent.id.clone(),
                    budget_tokens: agent.budget_tokens,
                    last_action: agent.last_action.clone(),
                })
                .collect(),
        });

        if state.goal_completed {
            break;
        }
    }

    let final_state = build_state(&events);
    if !final_state.goal_completed {
        append_event(
            &mut events,
            &mut seq,
            spec.policy.max_ticks,
            "closure",
            SdlcEventKind::GoalFailed {
                goal_id: spec.goal.id.clone(),
                reason: "max ticks exhausted before all tickets admitted".to_string(),
            },
            &mut agents,
        );
    }

    write_metrics(&spec.outputs.metrics_path, &metrics)?;
    write_ledger(&spec.outputs.ledger_path, &events)?;

    let summary = SdlcRunSummary {
        seed,
        goal_id: spec.goal.id.clone(),
        completed: build_state(&events).goal_completed,
        completion_tick: goal_completion_tick(&events),
        max_ticks: spec.policy.max_ticks,
        requirements_total: expected_requirements.len(),
        requirements_admitted: build_state(&events).requirement_admitted.len(),
        tickets_total: expected_tickets.len(),
        tickets_admitted: build_state(&events).ticket_admitted.len(),
        obligation_breaches: count_obligation_breaches(&events),
        overlap_violations: validation.overlaps.len(),
        contradiction_violations: validation.contradictions.len(),
        traceability_completeness: traceability_completeness(&requirements, &tickets, &events),
        total_tokens_spent: total_debited_tokens(&events),
        total_events: events.len(),
    };

    write_summary(&spec.outputs.summary_path, &summary)?;
    write_trace(
        &spec.outputs.trace_path,
        &spec.goal.id,
        &requirements,
        &tickets,
        &events,
    )?;

    Ok(summary)
}

fn init_agents(specs: &[SdlcAgentSpec]) -> BTreeMap<String, AgentRuntime> {
    specs
        .iter()
        .map(|spec| {
            (
                spec.id.clone(),
                AgentRuntime {
                    id: spec.id.clone(),
                    specialty: spec.specialty.clone(),
                    budget_tokens: spec.initial_budget_tokens,
                    last_action: "init".to_string(),
                },
            )
        })
        .collect()
}

fn run_requirement_stage(
    tick: u64,
    agent_id: &str,
    agent_index: usize,
    agent_count: usize,
    requirements: &[crate::schema::RequirementSpec],
    state: &SdlcStateView,
    spec: &SdlcToySpec,
    events: &mut Vec<SdlcEvent>,
    seq: &mut u64,
    agents: &mut BTreeMap<String, AgentRuntime>,
) -> usize {
    let mut actions = 0usize;

    for (idx, requirement) in requirements.iter().enumerate() {
        if idx % agent_count == agent_index && !state.requirement_proposed.contains(&requirement.id)
        {
            if charge_agent(
                events,
                seq,
                tick,
                agent_id,
                spec.policy.action_costs.propose_requirement,
                &format!("propose requirement {}", requirement.id),
                agents,
            ) {
                append_event(
                    events,
                    seq,
                    tick,
                    agent_id,
                    SdlcEventKind::RequirementProposed {
                        requirement: requirement.clone(),
                    },
                    agents,
                );
                set_last_action(
                    agents,
                    agent_id,
                    &format!("propose_requirement({})", requirement.id),
                );
                actions += 1;
            }
        }
    }

    let refreshed = build_state(events);
    for requirement in requirements {
        if !refreshed.requirement_proposed.contains(&requirement.id) {
            continue;
        }
        let already_attested = refreshed
            .requirement_attested_by
            .get(&requirement.id)
            .is_some_and(|attesters| attesters.contains(agent_id));
        if already_attested {
            continue;
        }

        if charge_agent(
            events,
            seq,
            tick,
            agent_id,
            spec.policy.action_costs.attest_requirement,
            &format!("attest requirement {}", requirement.id),
            agents,
        ) {
            append_event(
                events,
                seq,
                tick,
                agent_id,
                SdlcEventKind::RequirementAttested {
                    requirement_id: requirement.id.clone(),
                    approve: true,
                    rationale: "meets measurable acceptance predicates".to_string(),
                },
                agents,
            );
            set_last_action(
                agents,
                agent_id,
                &format!("attest_requirement({})", requirement.id),
            );
            actions += 1;
        }
    }

    actions
}

fn run_ticket_proposal_stage(
    tick: u64,
    agent_id: &str,
    agent_index: usize,
    agent_count: usize,
    tickets: &[TicketSpec],
    state: &SdlcStateView,
    spec: &SdlcToySpec,
    events: &mut Vec<SdlcEvent>,
    seq: &mut u64,
    agents: &mut BTreeMap<String, AgentRuntime>,
) -> usize {
    if state.requirement_admitted.is_empty() {
        return 0;
    }

    let mut actions = 0usize;
    for (idx, ticket) in tickets.iter().enumerate() {
        if idx % agent_count == agent_index && !state.tickets_proposed.contains_key(&ticket.id) {
            if charge_agent(
                events,
                seq,
                tick,
                agent_id,
                spec.policy.action_costs.propose_ticket,
                &format!("propose ticket {}", ticket.id),
                agents,
            ) {
                append_event(
                    events,
                    seq,
                    tick,
                    agent_id,
                    SdlcEventKind::TicketProposed {
                        ticket: ticket.clone(),
                    },
                    agents,
                );
                set_last_action(agents, agent_id, &format!("propose_ticket({})", ticket.id));
                actions += 1;
            }
        }
    }

    actions
}

async fn run_ticket_execution_stage(
    tick: u64,
    agent_id: &str,
    state: &SdlcStateView,
    spec: &SdlcToySpec,
    events: &mut Vec<SdlcEvent>,
    seq: &mut u64,
    agents: &mut BTreeMap<String, AgentRuntime>,
    rng: &mut StdRng,
) -> Result<usize> {
    let mut actions = 0usize;

    // Verify first: independent verification is required for admission.
    for (ticket_id, submitter) in &state.ticket_submitted_by {
        if submitter == agent_id || state.ticket_admitted.contains(ticket_id) {
            continue;
        }
        let already_verified = state
            .ticket_verified_by
            .get(ticket_id)
            .is_some_and(|verifiers| verifiers.contains(agent_id));
        if already_verified {
            continue;
        }

        let Some(ticket) = state.tickets_proposed.get(ticket_id) else {
            continue;
        };

        if charge_agent(
            events,
            seq,
            tick,
            agent_id,
            spec.policy.action_costs.verify_ticket,
            &format!("verify ticket {ticket_id}"),
            agents,
        ) {
            let command_results =
                run_commands(&spec.sandbox, &ticket.commands_to_run, Path::new(".")).await?;
            let pass = command_results.iter().all(|result| result.passed);
            let evidence = command_results_to_evidence(ticket_id, &command_results);

            append_event(
                events,
                seq,
                tick,
                agent_id,
                SdlcEventKind::TicketVerified {
                    ticket_id: ticket_id.clone(),
                    verifier_id: agent_id.to_string(),
                    pass,
                    notes: if pass {
                        "sandbox verification commands passed".to_string()
                    } else {
                        "sandbox verification command failed".to_string()
                    },
                    evidence,
                },
                agents,
            );

            let obligation_id = format!("obl-verify-{ticket_id}-{agent_id}");
            append_event(
                events,
                seq,
                tick,
                agent_id,
                SdlcEventKind::ObligationSatisfied { obligation_id },
                agents,
            );

            set_last_action(agents, agent_id, &format!("verify_ticket({ticket_id})"));
            actions += 1;
            return Ok(actions);
        }
    }

    // Submit claimed ticket if pending.
    for (ticket_id, claimant) in &state.ticket_claimed_by {
        if claimant != agent_id {
            continue;
        }
        if state.ticket_submitted_by.contains_key(ticket_id)
            || state.ticket_admitted.contains(ticket_id)
        {
            continue;
        }

        if charge_agent(
            events,
            seq,
            tick,
            agent_id,
            spec.policy.action_costs.submit_ticket,
            &format!("submit ticket {ticket_id}"),
            agents,
        ) {
            let evidence = vec![EvidenceRef {
                evidence_id: format!("patch-{ticket_id}-{tick}"),
                kind: "synthetic_patch".to_string(),
                value: format!("applied deliverables for {ticket_id}"),
            }];
            append_event(
                events,
                seq,
                tick,
                agent_id,
                SdlcEventKind::TicketSubmitted {
                    ticket_id: ticket_id.clone(),
                    evidence,
                },
                agents,
            );

            let submit_obligation_id = format!("obl-submit-{ticket_id}-{agent_id}");
            append_event(
                events,
                seq,
                tick,
                agent_id,
                SdlcEventKind::ObligationSatisfied {
                    obligation_id: submit_obligation_id,
                },
                agents,
            );

            if let Some(partner) = pick_partner(agent_id, agents.keys()) {
                append_event(
                    events,
                    seq,
                    tick,
                    "governor",
                    SdlcEventKind::ObligationIssued {
                        obligation: verify_obligation(
                            ticket_id,
                            &partner,
                            tick + spec.policy.verify_deadline_ticks,
                            spec.policy.action_costs.obligation_breach_penalty,
                        ),
                    },
                    agents,
                );
            }

            set_last_action(agents, agent_id, &format!("submit_ticket({ticket_id})"));
            actions += 1;
            return Ok(actions);
        }
    }

    // Claim next ready ticket.
    let mut candidates = Vec::new();
    for (ticket_id, ticket) in &state.tickets_proposed {
        if state.ticket_claimed_by.contains_key(ticket_id)
            || state.ticket_admitted.contains(ticket_id)
        {
            continue;
        }
        if !ticket
            .requirement_ids
            .iter()
            .all(|req| state.requirement_admitted.contains(req))
        {
            continue;
        }
        if !ticket
            .depends_on_tickets
            .iter()
            .all(|dep| state.ticket_admitted.contains(dep))
        {
            continue;
        }

        let preference = agent_preference_for_ticket(agent_id, agents, ticket, rng);
        candidates.push((ticket_id.clone(), preference));
    }
    candidates.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some((ticket_id, _)) = candidates.first() {
        if charge_agent(
            events,
            seq,
            tick,
            agent_id,
            spec.policy.action_costs.claim_ticket,
            &format!("claim ticket {ticket_id}"),
            agents,
        ) {
            append_event(
                events,
                seq,
                tick,
                agent_id,
                SdlcEventKind::TicketClaimed {
                    ticket_id: ticket_id.clone(),
                },
                agents,
            );

            append_event(
                events,
                seq,
                tick,
                "governor",
                SdlcEventKind::ObligationIssued {
                    obligation: submit_obligation(
                        ticket_id,
                        agent_id,
                        tick + spec.policy.submit_deadline_ticks,
                        spec.policy.action_costs.obligation_breach_penalty,
                    ),
                },
                agents,
            );

            set_last_action(agents, agent_id, &format!("claim_ticket({ticket_id})"));
            actions += 1;
        }
    }

    Ok(actions)
}

fn command_results_to_evidence(
    ticket_id: &str,
    results: &[SandboxCommandResult],
) -> Vec<EvidenceRef> {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| EvidenceRef {
            evidence_id: format!("verify-{ticket_id}-{index}"),
            kind: if result.passed {
                "command_success".to_string()
            } else {
                "command_failure".to_string()
            },
            value: format!("{} :: {}", result.command, result.reason),
        })
        .collect()
}

fn append_event(
    events: &mut Vec<SdlcEvent>,
    seq: &mut u64,
    tick: u64,
    author_id: &str,
    event: SdlcEventKind,
    agents: &mut BTreeMap<String, AgentRuntime>,
) {
    apply_budget_effect(&event, agents);
    events.push(SdlcEvent {
        seq: *seq,
        tick,
        author_id: author_id.to_string(),
        event,
    });
    *seq += 1;
}

fn apply_budget_effect(event: &SdlcEventKind, agents: &mut BTreeMap<String, AgentRuntime>) {
    match event {
        SdlcEventKind::BudgetDebited {
            agent_id, amount, ..
        } => {
            if let Some(agent) = agents.get_mut(agent_id) {
                agent.budget_tokens = agent.budget_tokens.saturating_sub(*amount);
            }
        },
        SdlcEventKind::BudgetCredited {
            agent_id, amount, ..
        } => {
            if let Some(agent) = agents.get_mut(agent_id) {
                agent.budget_tokens = agent.budget_tokens.saturating_add(*amount);
            }
        },
        _ => {},
    }
}

fn charge_agent(
    events: &mut Vec<SdlcEvent>,
    seq: &mut u64,
    tick: u64,
    agent_id: &str,
    amount: u64,
    reason: &str,
    agents: &mut BTreeMap<String, AgentRuntime>,
) -> bool {
    let Some(agent) = agents.get(agent_id) else {
        return false;
    };
    if agent.budget_tokens < amount {
        return false;
    }

    append_event(
        events,
        seq,
        tick,
        "economy",
        SdlcEventKind::BudgetDebited {
            agent_id: agent_id.to_string(),
            amount,
            reason: reason.to_string(),
        },
        agents,
    );
    true
}

fn set_last_action(agents: &mut BTreeMap<String, AgentRuntime>, agent_id: &str, action: &str) {
    if let Some(agent) = agents.get_mut(agent_id) {
        agent.last_action = action.to_string();
    }
}

fn pick_partner<'a>(agent_id: &str, ids: impl Iterator<Item = &'a String>) -> Option<String> {
    ids.filter(|id| id.as_str() != agent_id).next().cloned()
}

fn agent_preference_for_ticket(
    agent_id: &str,
    agents: &BTreeMap<String, AgentRuntime>,
    ticket: &TicketSpec,
    rng: &mut StdRng,
) -> f64 {
    let specialty_bias = agents
        .get(agent_id)
        .map(|agent| {
            if ticket.id.contains("tests") && agent.specialty.contains("verify") {
                1.4
            } else if ticket.id.contains("cli") && agent.specialty.contains("decompose") {
                1.2
            } else {
                1.0
            }
        })
        .unwrap_or(1.0);

    let uncertainty: f64 = rng.gen_range(0.0..0.2);
    specialty_bias * 10.0 - (ticket.estimated_cost.tokens as f64 / 100.0) + uncertainty
}

fn build_state(events: &[SdlcEvent]) -> SdlcStateView {
    let mut state = SdlcStateView::default();

    for event in events {
        match &event.event {
            SdlcEventKind::RequirementProposed { requirement } => {
                state.requirement_proposed.insert(requirement.id.clone());
            },
            SdlcEventKind::RequirementAttested {
                requirement_id,
                approve,
                ..
            } => {
                if *approve {
                    state
                        .requirement_attested_by
                        .entry(requirement_id.clone())
                        .or_default()
                        .insert(event.author_id.clone());
                }
            },
            SdlcEventKind::RequirementAdmitted { requirement_id, .. } => {
                state.requirement_admitted.insert(requirement_id.clone());
            },
            SdlcEventKind::TicketProposed { ticket } => {
                state
                    .tickets_proposed
                    .insert(ticket.id.clone(), ticket.clone());
            },
            SdlcEventKind::TicketClaimed { ticket_id } => {
                state
                    .ticket_claimed_by
                    .insert(ticket_id.clone(), event.author_id.clone());
            },
            SdlcEventKind::TicketSubmitted { ticket_id, .. } => {
                state
                    .ticket_submitted_by
                    .insert(ticket_id.clone(), event.author_id.clone());
            },
            SdlcEventKind::TicketVerified {
                ticket_id,
                verifier_id,
                pass,
                ..
            } => {
                if *pass {
                    state
                        .ticket_verified_by
                        .entry(ticket_id.clone())
                        .or_default()
                        .insert(verifier_id.clone());
                }
            },
            SdlcEventKind::TicketAdmitted { ticket_id, .. } => {
                state.ticket_admitted.insert(ticket_id.clone());
            },
            SdlcEventKind::ObligationIssued { obligation } => {
                state
                    .open_obligation_ids
                    .insert(obligation.obligation_id.clone());
            },
            SdlcEventKind::ObligationSatisfied { obligation_id }
            | SdlcEventKind::ObligationBreached { obligation_id, .. } => {
                state.open_obligation_ids.remove(obligation_id);
            },
            SdlcEventKind::GoalCompleted { .. } => {
                state.goal_completed = true;
            },
            SdlcEventKind::GoalFailed { .. } => {
                state.goal_failed = true;
            },
            _ => {},
        }
    }

    state
}

fn count_obligation_breaches(events: &[SdlcEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event.event, SdlcEventKind::ObligationBreached { .. }))
        .count()
}

fn total_debited_tokens(events: &[SdlcEvent]) -> u64 {
    events
        .iter()
        .filter_map(|event| {
            if let SdlcEventKind::BudgetDebited { amount, .. } = event.event {
                Some(amount)
            } else {
                None
            }
        })
        .sum()
}

fn goal_completion_tick(events: &[SdlcEvent]) -> Option<u64> {
    events.iter().find_map(|event| {
        if matches!(event.event, SdlcEventKind::GoalCompleted { .. }) {
            Some(event.tick)
        } else {
            None
        }
    })
}

fn traceability_completeness(
    requirements: &[crate::schema::RequirementSpec],
    tickets: &[TicketSpec],
    events: &[SdlcEvent],
) -> f64 {
    let state = build_state(events);
    let requirement_ratio = if requirements.is_empty() {
        1.0
    } else {
        state.requirement_admitted.len() as f64 / requirements.len() as f64
    };
    let ticket_ratio = if tickets.is_empty() {
        1.0
    } else {
        state.ticket_admitted.len() as f64 / tickets.len() as f64
    };

    ((requirement_ratio + ticket_ratio) / 2.0).clamp(0.0, 1.0)
}

fn write_metrics(path: &str, metrics: &[SdlcTickMetric]) -> Result<()> {
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create metrics dir {}", parent.display()))?;
    }

    let file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for metric in metrics {
        let line = serde_json::to_string(metric).context("serialize sdlc tick metric")?;
        writer
            .write_all(line.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        writer
            .write_all(b"\n")
            .with_context(|| format!("write newline {}", path.display()))?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))?;

    Ok(())
}

fn write_summary(path: &str, summary: &SdlcRunSummary) -> Result<()> {
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create summary dir {}", parent.display()))?;
    }

    let json = serde_json::to_string_pretty(summary).context("serialize sdlc summary")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_ledger(path: &str, events: &[SdlcEvent]) -> Result<()> {
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create ledger dir {}", parent.display()))?;
    }

    let file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for event in events {
        let line = serde_json::to_string(event).context("serialize sdlc event")?;
        writer
            .write_all(line.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        writer
            .write_all(b"\n")
            .with_context(|| format!("write newline {}", path.display()))?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))?;

    Ok(())
}

fn write_trace(
    path: &str,
    goal_id: &str,
    requirements: &[crate::schema::RequirementSpec],
    tickets: &[TicketSpec],
    events: &[SdlcEvent],
) -> Result<()> {
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create trace dir {}", parent.display()))?;
    }

    let state = build_state(events);
    let mut links = Vec::new();

    for requirement in requirements {
        links.push(TraceLink {
            from_id: goal_id.to_string(),
            to_id: requirement.id.clone(),
            kind: "goal_to_requirement".to_string(),
        });
    }

    for ticket in tickets {
        for requirement_id in &ticket.requirement_ids {
            links.push(TraceLink {
                from_id: requirement_id.clone(),
                to_id: ticket.id.clone(),
                kind: "requirement_to_ticket".to_string(),
            });
        }
    }

    let trace = TraceArtifact {
        goal_id: goal_id.to_string(),
        requirements: requirements.iter().map(|req| req.id.clone()).collect(),
        tickets: tickets.iter().map(|ticket| ticket.id.clone()).collect(),
        links,
        admitted_requirements: state.requirement_admitted.into_iter().collect(),
        admitted_tickets: state.ticket_admitted.into_iter().collect(),
    };

    let json = serde_json::to_string_pretty(&trace).context("serialize trace artifact")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_sdlc_toy;
    use crate::schema::{
        ActionCostSpec, SandboxPolicySpec, SdlcAgentSpec, SdlcOutputSpec, SdlcPolicySpec,
        SdlcToySpec,
    };
    use crate::task_cli_subcommand::{default_goal, default_task_template};

    fn test_spec(temp_dir: &tempfile::TempDir) -> SdlcToySpec {
        SdlcToySpec {
            kind: "apm2.lab.sdlc_toy".to_string(),
            version: "v1".to_string(),
            goal: default_goal(),
            task: default_task_template(),
            agents: vec![
                SdlcAgentSpec {
                    id: "alpha".to_string(),
                    specialty: "decompose".to_string(),
                    initial_budget_tokens: 20_000,
                },
                SdlcAgentSpec {
                    id: "beta".to_string(),
                    specialty: "verify".to_string(),
                    initial_budget_tokens: 20_000,
                },
            ],
            policy: SdlcPolicySpec {
                max_ticks: 40,
                requirement_quorum: 2,
                submit_deadline_ticks: 3,
                verify_deadline_ticks: 2,
                action_costs: ActionCostSpec {
                    propose_requirement: 5,
                    attest_requirement: 2,
                    propose_ticket: 4,
                    claim_ticket: 3,
                    submit_ticket: 15,
                    verify_ticket: 8,
                    pass: 1,
                    obligation_breach_penalty: 20,
                    ticket_reward: 50,
                },
            },
            sandbox: SandboxPolicySpec {
                enabled: true,
                simulate_command_results: true,
                allowed_paths: vec![
                    "crates/apm2-cli/src/main.rs".to_string(),
                    "crates/apm2-cli/src/commands".to_string(),
                    "crates/apm2-cli/tests".to_string(),
                ],
                allowed_command_prefixes: vec![
                    "cargo test".to_string(),
                    "cargo clippy".to_string(),
                    "echo".to_string(),
                ],
                command_timeout_ms: 5_000,
            },
            outputs: SdlcOutputSpec {
                metrics_path: temp_dir.path().join("metrics.jsonl").display().to_string(),
                summary_path: temp_dir.path().join("summary.json").display().to_string(),
                trace_path: temp_dir.path().join("trace.json").display().to_string(),
                ledger_path: temp_dir.path().join("ledger.jsonl").display().to_string(),
            },
        }
    }

    #[tokio::test]
    async fn toy_run_completes_and_writes_outputs() {
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let spec = test_spec(&temp_dir);

        let summary = run_sdlc_toy(spec, 7).await.expect("toy run");
        assert!(summary.completed);
        assert!(summary.traceability_completeness >= 1.0);
    }
}
