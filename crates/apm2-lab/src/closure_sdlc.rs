use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use apm2_core::crypto::EventHasher;

use crate::decompose::validate_requirements;
use crate::obligation::evaluate_obligations;
use crate::schema::{AdmissionReceipt, RequirementSpec, SdlcEvent, SdlcEventKind, TicketSpec};

#[derive(Debug, Clone)]
pub struct SdlcClosureConfig {
    pub requirement_quorum: usize,
    pub ticket_verify_quorum: usize,
}

impl Default for SdlcClosureConfig {
    fn default() -> Self {
        Self {
            requirement_quorum: 2,
            ticket_verify_quorum: 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SdlcClosureSnapshot {
    pub derived_events: Vec<SdlcEventKind>,
    pub admitted_requirements: BTreeSet<String>,
    pub admitted_tickets: BTreeSet<String>,
    pub pending_requirements: usize,
    pub pending_tickets: usize,
    pub obligations_open: usize,
    pub obligations_breaches_total: usize,
    pub goal_completed: bool,
}

pub struct SdlcClosureReducer {
    config: SdlcClosureConfig,
}

impl SdlcClosureReducer {
    #[must_use]
    pub const fn new(config: SdlcClosureConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(
        &self,
        events: &[SdlcEvent],
        current_tick: u64,
        expected_requirements: &BTreeSet<String>,
        expected_tickets: &BTreeSet<String>,
    ) -> Result<SdlcClosureSnapshot> {
        let mut snapshot = SdlcClosureSnapshot::default();

        let mut goal_id = String::new();
        let mut goal_completed_exists = false;

        let mut requirement_specs: BTreeMap<String, RequirementSpec> = BTreeMap::new();
        let mut requirement_attestations: HashMap<String, HashMap<String, bool>> = HashMap::new();
        let mut admitted_requirements = BTreeSet::new();

        let mut ticket_specs: BTreeMap<String, TicketSpec> = BTreeMap::new();
        let mut ticket_submitter: HashMap<String, String> = HashMap::new();
        let mut ticket_verifications: HashMap<String, Vec<(String, bool)>> = HashMap::new();
        let mut admitted_tickets = BTreeSet::new();

        for event in events {
            match &event.event {
                SdlcEventKind::GoalProposed { goal } => {
                    goal_id = goal.id.clone();
                },
                SdlcEventKind::RequirementProposed { requirement } => {
                    requirement_specs.insert(requirement.id.clone(), requirement.clone());
                },
                SdlcEventKind::RequirementAttested {
                    requirement_id,
                    approve,
                    ..
                } => {
                    requirement_attestations
                        .entry(requirement_id.clone())
                        .or_default()
                        .insert(event.author_id.clone(), *approve);
                },
                SdlcEventKind::RequirementAdmitted { requirement_id, .. } => {
                    admitted_requirements.insert(requirement_id.clone());
                },
                SdlcEventKind::TicketProposed { ticket } => {
                    ticket_specs.insert(ticket.id.clone(), ticket.clone());
                },
                SdlcEventKind::TicketSubmitted { ticket_id, .. } => {
                    ticket_submitter.insert(ticket_id.clone(), event.author_id.clone());
                },
                SdlcEventKind::TicketVerified {
                    ticket_id,
                    verifier_id,
                    pass,
                    ..
                } => {
                    ticket_verifications
                        .entry(ticket_id.clone())
                        .or_default()
                        .push((verifier_id.clone(), *pass));
                },
                SdlcEventKind::TicketAdmitted { ticket_id, .. } => {
                    admitted_tickets.insert(ticket_id.clone());
                },
                SdlcEventKind::GoalCompleted { .. } => {
                    goal_completed_exists = true;
                },
                _ => {},
            }
        }

        let obligation_snapshot = evaluate_obligations(events, current_tick);
        snapshot.obligations_open = obligation_snapshot.open_obligations.len();
        snapshot.obligations_breaches_total = obligation_snapshot.breached_obligations;
        for derived in obligation_snapshot.derived_events {
            if let SdlcEventKind::ObligationBreached {
                subject_agent,
                penalty_tokens,
                reason,
                ..
            } = &derived
            {
                snapshot.derived_events.push(derived.clone());
                snapshot.derived_events.push(SdlcEventKind::BudgetDebited {
                    agent_id: subject_agent.clone(),
                    amount: *penalty_tokens,
                    reason: reason.clone(),
                });
            }
        }

        for requirement_id in expected_requirements {
            if admitted_requirements.contains(requirement_id) {
                continue;
            }

            let Some(requirement) = requirement_specs.get(requirement_id) else {
                continue;
            };
            let attestations = requirement_attestations
                .get(requirement_id)
                .cloned()
                .unwrap_or_default();

            let approvals = attestations.values().filter(|approve| **approve).count();
            let any_deny = attestations.values().any(|approve| !*approve);
            if approvals < self.config.requirement_quorum || any_deny {
                continue;
            }
            if requirement.acceptance_predicates.is_empty() {
                continue;
            }

            let mut compatible = true;
            for admitted_id in &admitted_requirements {
                let Some(admitted_spec) = requirement_specs.get(admitted_id) else {
                    continue;
                };
                let check = vec![requirement.clone(), admitted_spec.clone()];
                let validation = validate_requirements(&check);
                if !validation.overlaps.is_empty() || !validation.contradictions.is_empty() {
                    compatible = false;
                    break;
                }
            }
            if !compatible {
                continue;
            }

            let receipt = AdmissionReceipt {
                subject_id: requirement_id.clone(),
                admitted: true,
                by: "closure".to_string(),
                tick: current_tick,
                reason: "requirement quorum and consistency checks passed".to_string(),
                evidence_ids: attestations.keys().cloned().collect(),
                receipt_hash: receipt_hash_hex(
                    requirement_id,
                    current_tick,
                    "requirement_admitted",
                ),
            };
            snapshot
                .derived_events
                .push(SdlcEventKind::RequirementAdmitted {
                    requirement_id: requirement_id.clone(),
                    receipt,
                });
            admitted_requirements.insert(requirement_id.clone());
        }

        for ticket_id in expected_tickets {
            if admitted_tickets.contains(ticket_id) {
                continue;
            }

            let Some(ticket) = ticket_specs.get(ticket_id) else {
                continue;
            };

            let requirements_ok = ticket
                .requirement_ids
                .iter()
                .all(|requirement_id| admitted_requirements.contains(requirement_id));
            if !requirements_ok {
                continue;
            }

            let deps_ok = ticket
                .depends_on_tickets
                .iter()
                .all(|dep| admitted_tickets.contains(dep));
            if !deps_ok {
                continue;
            }

            let Some(submitter_id) = ticket_submitter.get(ticket_id).cloned() else {
                continue;
            };
            let verifications = ticket_verifications
                .get(ticket_id)
                .cloned()
                .unwrap_or_default();
            let pass_votes = verifications
                .iter()
                .filter(|(verifier_id, pass)| *pass && *verifier_id != submitter_id)
                .count();
            if pass_votes < self.config.ticket_verify_quorum {
                continue;
            }

            let evidence_ids: Vec<String> = verifications
                .iter()
                .map(|(verifier_id, _)| format!("verification:{verifier_id}:{ticket_id}"))
                .collect();

            let receipt = AdmissionReceipt {
                subject_id: ticket_id.clone(),
                admitted: true,
                by: "closure".to_string(),
                tick: current_tick,
                reason: "ticket submission independently verified".to_string(),
                evidence_ids,
                receipt_hash: receipt_hash_hex(ticket_id, current_tick, "ticket_admitted"),
            };
            snapshot.derived_events.push(SdlcEventKind::TicketAdmitted {
                ticket_id: ticket_id.clone(),
                receipt,
            });
            snapshot.derived_events.push(SdlcEventKind::BudgetCredited {
                agent_id: submitter_id,
                amount: ticket.estimated_cost.tokens,
                reason: format!("ticket admitted {ticket_id}"),
            });
            admitted_tickets.insert(ticket_id.clone());
        }

        snapshot.admitted_requirements = admitted_requirements;
        snapshot.admitted_tickets = admitted_tickets;
        snapshot.pending_requirements = expected_requirements
            .len()
            .saturating_sub(snapshot.admitted_requirements.len());
        snapshot.pending_tickets = expected_tickets
            .len()
            .saturating_sub(snapshot.admitted_tickets.len());

        if !goal_completed_exists
            && !goal_id.is_empty()
            && snapshot.pending_requirements == 0
            && snapshot.pending_tickets == 0
        {
            snapshot.goal_completed = true;
            let receipt = AdmissionReceipt {
                subject_id: goal_id.clone(),
                admitted: true,
                by: "closure".to_string(),
                tick: current_tick,
                reason: "all critical requirements and tickets admitted".to_string(),
                evidence_ids: snapshot.admitted_tickets.iter().cloned().collect(),
                receipt_hash: receipt_hash_hex(&goal_id, current_tick, "goal_completed"),
            };
            snapshot
                .derived_events
                .push(SdlcEventKind::GoalCompleted { goal_id, receipt });
        }

        Ok(snapshot)
    }
}

fn receipt_hash_hex(subject_id: &str, tick: u64, label: &str) -> String {
    let material = format!("{label}:{subject_id}:{tick}");
    let hash = EventHasher::hash_content(material.as_bytes());
    hash.iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{SdlcClosureConfig, SdlcClosureReducer};
    use crate::schema::{
        GoalSpec, RequirementSpec, SdlcEvent, SdlcEventKind, TicketCost, TicketSpec, TraceRef,
    };

    #[test]
    fn admits_requirement_and_ticket_then_goal() {
        let reducer = SdlcClosureReducer::new(SdlcClosureConfig {
            requirement_quorum: 2,
            ticket_verify_quorum: 1,
        });

        let requirement = RequirementSpec {
            id: "REQ-1".to_string(),
            problem_statement: "demo".to_string(),
            scope: vec!["a".to_string()],
            assumptions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: vec!["p".to_string()],
            invariants: Vec::new(),
            acceptance_predicates: vec!["x".to_string()],
            non_goals: Vec::new(),
            dependencies: Vec::new(),
            compose_with: Vec::new(),
            critical: true,
            trace: TraceRef {
                goal_id: "g".to_string(),
            },
        };

        let ticket = TicketSpec {
            id: "TKT-1".to_string(),
            requirement_ids: vec!["REQ-1".to_string()],
            deliverables: vec!["d".to_string()],
            verification_plan: vec!["v".to_string()],
            commands_to_run: vec!["echo ok".to_string()],
            evidence_required: vec!["ev".to_string()],
            estimated_cost: TicketCost {
                tokens: 10,
                commands: 1,
            },
            depends_on_tickets: Vec::new(),
        };

        let events = vec![
            SdlcEvent {
                seq: 1,
                tick: 1,
                author_id: "world".to_string(),
                event: SdlcEventKind::GoalProposed {
                    goal: GoalSpec {
                        id: "g".to_string(),
                        statement: "goal".to_string(),
                        problem_statement: "problem".to_string(),
                        objective_function: "obj".to_string(),
                        constraints: Vec::new(),
                        assumptions: Vec::new(),
                        acceptance_predicates: Vec::new(),
                    },
                },
            },
            SdlcEvent {
                seq: 2,
                tick: 1,
                author_id: "alpha".to_string(),
                event: SdlcEventKind::RequirementProposed {
                    requirement: requirement.clone(),
                },
            },
            SdlcEvent {
                seq: 3,
                tick: 1,
                author_id: "alpha".to_string(),
                event: SdlcEventKind::RequirementAttested {
                    requirement_id: requirement.id.clone(),
                    approve: true,
                    rationale: "good".to_string(),
                },
            },
            SdlcEvent {
                seq: 4,
                tick: 1,
                author_id: "beta".to_string(),
                event: SdlcEventKind::RequirementAttested {
                    requirement_id: requirement.id.clone(),
                    approve: true,
                    rationale: "good".to_string(),
                },
            },
            SdlcEvent {
                seq: 5,
                tick: 2,
                author_id: "beta".to_string(),
                event: SdlcEventKind::TicketProposed {
                    ticket: ticket.clone(),
                },
            },
            SdlcEvent {
                seq: 6,
                tick: 2,
                author_id: "alpha".to_string(),
                event: SdlcEventKind::TicketSubmitted {
                    ticket_id: ticket.id.clone(),
                    evidence: Vec::new(),
                },
            },
            SdlcEvent {
                seq: 7,
                tick: 2,
                author_id: "beta".to_string(),
                event: SdlcEventKind::TicketVerified {
                    ticket_id: ticket.id.clone(),
                    verifier_id: "beta".to_string(),
                    pass: true,
                    notes: "ok".to_string(),
                    evidence: Vec::new(),
                },
            },
        ];

        let mut expected_req = BTreeSet::new();
        expected_req.insert("REQ-1".to_string());
        let mut expected_tkt = BTreeSet::new();
        expected_tkt.insert("TKT-1".to_string());

        let snapshot = reducer
            .evaluate(&events, 3, &expected_req, &expected_tkt)
            .expect("evaluate");

        assert!(
            snapshot
                .derived_events
                .iter()
                .any(|event| matches!(event, SdlcEventKind::RequirementAdmitted { .. }))
        );
        assert!(
            snapshot
                .derived_events
                .iter()
                .any(|event| matches!(event, SdlcEventKind::TicketAdmitted { .. }))
        );
    }
}
