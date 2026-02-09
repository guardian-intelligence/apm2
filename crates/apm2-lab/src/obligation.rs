use std::collections::{BTreeMap, BTreeSet};

use crate::schema::{Obligation, ObligationTarget, SdlcEvent, SdlcEventKind};

#[derive(Debug, Clone, Default)]
pub struct ObligationSnapshot {
    pub open_obligations: Vec<Obligation>,
    pub breached_obligations: usize,
    pub derived_events: Vec<SdlcEventKind>,
}

pub fn submit_obligation(
    ticket_id: &str,
    agent_id: &str,
    due_tick: u64,
    penalty_tokens: u64,
) -> Obligation {
    Obligation {
        obligation_id: format!("obl-submit-{ticket_id}-{agent_id}"),
        target: ObligationTarget::SubmitTicket {
            ticket_id: ticket_id.to_string(),
        },
        subject_agent: agent_id.to_string(),
        due_tick,
        penalty_tokens,
    }
}

pub fn verify_obligation(
    ticket_id: &str,
    agent_id: &str,
    due_tick: u64,
    penalty_tokens: u64,
) -> Obligation {
    Obligation {
        obligation_id: format!("obl-verify-{ticket_id}-{agent_id}"),
        target: ObligationTarget::VerifyTicket {
            ticket_id: ticket_id.to_string(),
        },
        subject_agent: agent_id.to_string(),
        due_tick,
        penalty_tokens,
    }
}

pub fn evaluate_obligations(events: &[SdlcEvent], current_tick: u64) -> ObligationSnapshot {
    let mut issued: BTreeMap<String, Obligation> = BTreeMap::new();
    let mut satisfied: BTreeSet<String> = BTreeSet::new();
    let mut breached: BTreeSet<String> = BTreeSet::new();

    for event in events {
        match &event.event {
            SdlcEventKind::ObligationIssued { obligation } => {
                issued.insert(obligation.obligation_id.clone(), obligation.clone());
            },
            SdlcEventKind::ObligationSatisfied { obligation_id } => {
                satisfied.insert(obligation_id.clone());
            },
            SdlcEventKind::ObligationBreached { obligation_id, .. } => {
                breached.insert(obligation_id.clone());
            },
            _ => {},
        }
    }

    let mut snapshot = ObligationSnapshot::default();
    for obligation in issued.values() {
        if satisfied.contains(&obligation.obligation_id)
            || breached.contains(&obligation.obligation_id)
        {
            continue;
        }

        if current_tick > obligation.due_tick {
            snapshot.breached_obligations += 1;
            snapshot
                .derived_events
                .push(SdlcEventKind::ObligationBreached {
                    obligation_id: obligation.obligation_id.clone(),
                    subject_agent: obligation.subject_agent.clone(),
                    penalty_tokens: obligation.penalty_tokens,
                    reason: format!(
                        "obligation '{}' missed deadline at tick {}",
                        obligation.obligation_id, obligation.due_tick
                    ),
                });
        } else {
            snapshot.open_obligations.push(obligation.clone());
        }
    }

    snapshot
}

#[cfg(test)]
mod tests {
    use super::{evaluate_obligations, submit_obligation};
    use crate::schema::{GoalSpec, SdlcEvent, SdlcEventKind};

    #[test]
    fn overdue_obligation_breaches_once() {
        let mut events = vec![SdlcEvent {
            seq: 1,
            tick: 1,
            author_id: "world".to_string(),
            event: SdlcEventKind::GoalProposed {
                goal: GoalSpec {
                    id: "g".to_string(),
                    statement: "demo".to_string(),
                    problem_statement: "demo".to_string(),
                    objective_function: "demo".to_string(),
                    constraints: Vec::new(),
                    assumptions: Vec::new(),
                    acceptance_predicates: Vec::new(),
                },
            },
        }];

        events.push(SdlcEvent {
            seq: 2,
            tick: 1,
            author_id: "alpha".to_string(),
            event: SdlcEventKind::ObligationIssued {
                obligation: submit_obligation("t1", "alpha", 1, 10),
            },
        });

        let snapshot = evaluate_obligations(&events, 2);
        assert_eq!(snapshot.breached_obligations, 1);

        events.push(SdlcEvent {
            seq: 3,
            tick: 2,
            author_id: "closure".to_string(),
            event: snapshot.derived_events[0].clone(),
        });
        let later = evaluate_obligations(&events, 3);
        assert_eq!(later.breached_obligations, 0);
    }
}
