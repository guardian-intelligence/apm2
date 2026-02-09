use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{Result, anyhow};

use crate::schema::{
    GoalSpec, RequirementSpec, TaskTemplateSpec, TicketCost, TicketSpec, TraceRef,
};

#[derive(Debug, Clone, Default)]
pub struct RequirementValidation {
    pub overlaps: Vec<RequirementOverlap>,
    pub contradictions: Vec<RequirementContradiction>,
}

#[derive(Debug, Clone)]
pub struct RequirementOverlap {
    pub left_requirement_id: String,
    pub right_requirement_id: String,
    pub shared_scope: String,
}

#[derive(Debug, Clone)]
pub struct RequirementContradiction {
    pub left_requirement_id: String,
    pub right_requirement_id: String,
    pub predicate: String,
}

pub fn decompose_goal(goal: &GoalSpec, task: &TaskTemplateSpec) -> Vec<RequirementSpec> {
    let command_path = format!("crates/apm2-cli/src/commands/{}.rs", task.command_name);
    let main_path = "crates/apm2-cli/src/main.rs".to_string();
    let test_path = "crates/apm2-cli/tests/".to_string();

    vec![
        RequirementSpec {
            id: "REQ-001-command-surface".to_string(),
            problem_statement: "Expose the new command in the CLI surface and parser graph"
                .to_string(),
            scope: vec![main_path],
            assumptions: vec!["CLI uses clap-based subcommand registration".to_string()],
            preconditions: vec!["Existing command hierarchy compiles".to_string()],
            postconditions: vec!["command_is_discoverable".to_string()],
            invariants: vec!["existing_commands_unchanged".to_string()],
            acceptance_predicates: vec![
                "help_includes_new_command".to_string(),
                "parsing_accepts_command".to_string(),
            ],
            non_goals: vec!["daemon_protocol_changes".to_string()],
            dependencies: Vec::new(),
            compose_with: Vec::new(),
            critical: true,
            trace: TraceRef {
                goal_id: goal.id.clone(),
            },
        },
        RequirementSpec {
            id: "REQ-002-ledger-parse".to_string(),
            problem_statement: "Read and parse ledger JSONL into typed counters for work outcomes"
                .to_string(),
            scope: vec![format!("{command_path}::parse")],
            assumptions: vec!["ledger lines are JSON event objects".to_string()],
            preconditions: vec!["input_path_exists_or_returns_error".to_string()],
            postconditions: vec!["admitted_rejected_pending_counts_emitted".to_string()],
            invariants: vec!["invalid_lines_fail_closed".to_string()],
            acceptance_predicates: vec![
                "valid_jsonl_is_parsed".to_string(),
                "invalid_jsonl_returns_error".to_string(),
            ],
            non_goals: vec!["mutating_ledger".to_string()],
            dependencies: Vec::new(),
            compose_with: vec!["REQ-003-output-modes".to_string()],
            critical: true,
            trace: TraceRef {
                goal_id: goal.id.clone(),
            },
        },
        RequirementSpec {
            id: "REQ-003-output-modes".to_string(),
            problem_statement: "Support plain and JSON output with deterministic field ordering"
                .to_string(),
            scope: vec![format!("{command_path}::output")],
            assumptions: vec!["serde_json available".to_string()],
            preconditions: vec!["aggregation_result_available".to_string()],
            postconditions: vec!["json_mode_and_plain_mode_supported".to_string()],
            invariants: vec!["json_schema_stable".to_string()],
            acceptance_predicates: vec![
                "plain_output_deterministic".to_string(),
                "json_output_schema_stable".to_string(),
            ],
            non_goals: vec!["streaming_output".to_string()],
            dependencies: vec!["REQ-002-ledger-parse".to_string()],
            compose_with: vec!["REQ-002-ledger-parse".to_string()],
            critical: true,
            trace: TraceRef {
                goal_id: goal.id.clone(),
            },
        },
        RequirementSpec {
            id: "REQ-004-error-handling".to_string(),
            problem_statement: "Return bounded actionable errors for file and parse failures"
                .to_string(),
            scope: vec![format!("{command_path}::errors")],
            assumptions: vec!["anyhow context available".to_string()],
            preconditions: vec!["error_paths_enumerated".to_string()],
            postconditions: vec!["errors_are_contextual_and_non_panicking".to_string()],
            invariants: vec!["no_silent_failure".to_string()],
            acceptance_predicates: vec![
                "missing_file_returns_error".to_string(),
                "bad_json_returns_error".to_string(),
            ],
            non_goals: vec!["error_retries".to_string()],
            dependencies: vec!["REQ-002-ledger-parse".to_string()],
            compose_with: Vec::new(),
            critical: true,
            trace: TraceRef {
                goal_id: goal.id.clone(),
            },
        },
        RequirementSpec {
            id: "REQ-005-tests".to_string(),
            problem_statement: "Ship targeted tests covering parser, outputs, and failures"
                .to_string(),
            scope: vec![test_path],
            assumptions: vec!["cargo test available".to_string()],
            preconditions: vec!["command_implementation_compiles".to_string()],
            postconditions: vec!["coverage_for_happy_and_failure_paths".to_string()],
            invariants: vec!["deterministic_assertions".to_string()],
            acceptance_predicates: task.acceptance_predicates.clone(),
            non_goals: vec!["benchmark_suite".to_string()],
            dependencies: vec![
                "REQ-001-command-surface".to_string(),
                "REQ-002-ledger-parse".to_string(),
                "REQ-003-output-modes".to_string(),
                "REQ-004-error-handling".to_string(),
            ],
            compose_with: Vec::new(),
            critical: true,
            trace: TraceRef {
                goal_id: goal.id.clone(),
            },
        },
    ]
}

pub fn requirements_to_tickets(
    requirements: &[RequirementSpec],
    task: &TaskTemplateSpec,
) -> Vec<TicketSpec> {
    let req_by_id: HashMap<_, _> = requirements
        .iter()
        .map(|requirement| (requirement.id.clone(), requirement))
        .collect();

    let mut tickets = Vec::new();

    if req_by_id.contains_key("REQ-002-ledger-parse") {
        tickets.push(TicketSpec {
            id: "TKT-001-parser-aggregation".to_string(),
            requirement_ids: vec!["REQ-002-ledger-parse".to_string()],
            deliverables: vec![
                "read ledger jsonl".to_string(),
                "aggregate admitted/rejected/pending".to_string(),
            ],
            verification_plan: vec!["unit tests for parser".to_string()],
            commands_to_run: task.verification_commands.clone(),
            evidence_required: vec!["test_output".to_string(), "diff".to_string()],
            estimated_cost: TicketCost {
                tokens: 180,
                commands: task.verification_commands.len() as u32,
            },
            depends_on_tickets: Vec::new(),
        });
    }

    if req_by_id.contains_key("REQ-003-output-modes") {
        tickets.push(TicketSpec {
            id: "TKT-002-output-contract".to_string(),
            requirement_ids: vec!["REQ-003-output-modes".to_string()],
            deliverables: vec![
                "plain output mode".to_string(),
                "json output mode".to_string(),
            ],
            verification_plan: vec!["snapshot-like output assertions".to_string()],
            commands_to_run: task.verification_commands.clone(),
            evidence_required: vec!["test_output".to_string()],
            estimated_cost: TicketCost {
                tokens: 140,
                commands: task.verification_commands.len() as u32,
            },
            depends_on_tickets: vec!["TKT-001-parser-aggregation".to_string()],
        });
    }

    if req_by_id.contains_key("REQ-001-command-surface") {
        tickets.push(TicketSpec {
            id: "TKT-003-cli-wiring".to_string(),
            requirement_ids: vec!["REQ-001-command-surface".to_string()],
            deliverables: vec!["subcommand registration".to_string()],
            verification_plan: vec!["help text includes command".to_string()],
            commands_to_run: task.verification_commands.clone(),
            evidence_required: vec!["help_output".to_string()],
            estimated_cost: TicketCost {
                tokens: 120,
                commands: task.verification_commands.len() as u32,
            },
            depends_on_tickets: vec!["TKT-001-parser-aggregation".to_string()],
        });
    }

    if req_by_id.contains_key("REQ-004-error-handling") {
        tickets.push(TicketSpec {
            id: "TKT-004-errors".to_string(),
            requirement_ids: vec!["REQ-004-error-handling".to_string()],
            deliverables: vec!["contextual error paths".to_string()],
            verification_plan: vec!["error tests".to_string()],
            commands_to_run: task.verification_commands.clone(),
            evidence_required: vec!["error_test_output".to_string()],
            estimated_cost: TicketCost {
                tokens: 100,
                commands: task.verification_commands.len() as u32,
            },
            depends_on_tickets: vec!["TKT-001-parser-aggregation".to_string()],
        });
    }

    if req_by_id.contains_key("REQ-005-tests") {
        tickets.push(TicketSpec {
            id: "TKT-005-regression-tests".to_string(),
            requirement_ids: vec!["REQ-005-tests".to_string()],
            deliverables: vec!["end-to-end tests".to_string()],
            verification_plan: vec!["run selected package tests".to_string()],
            commands_to_run: task.verification_commands.clone(),
            evidence_required: vec!["test_output".to_string(), "coverage_assertion".to_string()],
            estimated_cost: TicketCost {
                tokens: 220,
                commands: task.verification_commands.len() as u32,
            },
            depends_on_tickets: vec![
                "TKT-002-output-contract".to_string(),
                "TKT-003-cli-wiring".to_string(),
                "TKT-004-errors".to_string(),
            ],
        });
    }

    tickets
}

pub fn validate_requirements(requirements: &[RequirementSpec]) -> RequirementValidation {
    let mut validation = RequirementValidation::default();

    for (idx, left) in requirements.iter().enumerate() {
        for right in requirements.iter().skip(idx + 1) {
            for shared in shared_scope(left, right) {
                let composed =
                    left.compose_with.contains(&right.id) || right.compose_with.contains(&left.id);
                if !composed {
                    validation.overlaps.push(RequirementOverlap {
                        left_requirement_id: left.id.clone(),
                        right_requirement_id: right.id.clone(),
                        shared_scope: shared,
                    });
                }
            }

            for contradiction in contradictions_between(left, right) {
                validation.contradictions.push(RequirementContradiction {
                    left_requirement_id: left.id.clone(),
                    right_requirement_id: right.id.clone(),
                    predicate: contradiction,
                });
            }
        }
    }

    validation
}

pub fn validate_ticket_plan(
    requirements: &[RequirementSpec],
    tickets: &[TicketSpec],
) -> Result<()> {
    let req_ids: BTreeSet<_> = requirements.iter().map(|req| req.id.clone()).collect();

    let mut covered = BTreeSet::new();
    for ticket in tickets {
        if ticket.requirement_ids.is_empty() {
            return Err(anyhow!("ticket '{}' has no linked requirements", ticket.id));
        }
        for req_id in &ticket.requirement_ids {
            if !req_ids.contains(req_id) {
                return Err(anyhow!(
                    "ticket '{}' references unknown requirement '{}'",
                    ticket.id,
                    req_id
                ));
            }
            covered.insert(req_id.clone());
        }
    }

    for req_id in req_ids {
        if !covered.contains(&req_id) {
            return Err(anyhow!(
                "requirement '{}' is not covered by any ticket",
                req_id
            ));
        }
    }

    validate_ticket_dag(tickets)
}

pub fn validate_ticket_dag(tickets: &[TicketSpec]) -> Result<()> {
    let by_id: BTreeMap<_, _> = tickets
        .iter()
        .map(|ticket| (ticket.id.clone(), ticket))
        .collect();

    for ticket in tickets {
        for dep in &ticket.depends_on_tickets {
            if !by_id.contains_key(dep) {
                return Err(anyhow!(
                    "ticket '{}' depends on unknown ticket '{}'",
                    ticket.id,
                    dep
                ));
            }
        }
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();

    for ticket in tickets {
        dfs_ticket(ticket.id.as_str(), &by_id, &mut visiting, &mut visited)?;
    }

    Ok(())
}

fn dfs_ticket<'a>(
    node: &'a str,
    by_id: &'a BTreeMap<String, &TicketSpec>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
) -> Result<()> {
    if visited.contains(node) {
        return Ok(());
    }
    if visiting.contains(node) {
        return Err(anyhow!("ticket dependency cycle detected at '{node}'"));
    }

    visiting.insert(node.to_string());
    let ticket = by_id
        .get(node)
        .ok_or_else(|| anyhow!("missing ticket node '{node}'"))?;
    for dep in &ticket.depends_on_tickets {
        dfs_ticket(dep, by_id, visiting, visited)?;
    }
    visiting.remove(node);
    visited.insert(node.to_string());
    Ok(())
}

fn shared_scope(left: &RequirementSpec, right: &RequirementSpec) -> Vec<String> {
    let right_set: HashSet<_> = right.scope.iter().cloned().collect();
    left.scope
        .iter()
        .filter(|scope| right_set.contains(*scope))
        .cloned()
        .collect()
}

fn contradictions_between(left: &RequirementSpec, right: &RequirementSpec) -> Vec<String> {
    let mut out = Vec::new();
    for predicate in left
        .postconditions
        .iter()
        .chain(left.invariants.iter())
        .chain(left.acceptance_predicates.iter())
    {
        if right
            .postconditions
            .iter()
            .chain(right.invariants.iter())
            .chain(right.acceptance_predicates.iter())
            .any(|other| is_contradiction(predicate, other))
        {
            out.push(predicate.clone());
        }
    }
    out
}

fn is_contradiction(left: &str, right: &str) -> bool {
    let left = normalize_predicate(left);
    let right = normalize_predicate(right);

    if left == format!("NOT:{right}") || right == format!("NOT:{left}") {
        return true;
    }

    if let Some(stripped) = left.strip_prefix("MUST_") {
        if right == format!("MUST_NOT_{stripped}") {
            return true;
        }
    }
    if let Some(stripped) = right.strip_prefix("MUST_") {
        if left == format!("MUST_NOT_{stripped}") {
            return true;
        }
    }

    false
}

fn normalize_predicate(value: &str) -> String {
    value
        .trim()
        .replace([' ', '-', '.'], "_")
        .to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::{
        GoalSpec, RequirementSpec, TaskTemplateSpec, decompose_goal, requirements_to_tickets,
        validate_requirements, validate_ticket_plan,
    };

    fn sample_goal() -> GoalSpec {
        GoalSpec {
            id: "goal-1".to_string(),
            statement: "Add work summarize command".to_string(),
            problem_statement: "Need fast aggregate visibility".to_string(),
            objective_function: "maximize admitted signal".to_string(),
            constraints: vec!["no daemon changes".to_string()],
            assumptions: vec!["ledger lines are events".to_string()],
            acceptance_predicates: vec!["tests_pass".to_string()],
        }
    }

    fn sample_task() -> TaskTemplateSpec {
        TaskTemplateSpec {
            command_name: "work_summarize".to_string(),
            summary: "Summarize work outcomes".to_string(),
            target_paths: vec!["crates/apm2-cli/src/commands".to_string()],
            acceptance_predicates: vec!["parse_valid".to_string(), "parse_invalid".to_string()],
            verification_commands: vec!["echo verify".to_string()],
        }
    }

    #[test]
    fn decomposition_has_no_uncomposed_overlap_or_contradiction() {
        let requirements = decompose_goal(&sample_goal(), &sample_task());
        let validation = validate_requirements(&requirements);
        assert!(validation.overlaps.is_empty());
        assert!(validation.contradictions.is_empty());
    }

    #[test]
    fn ticket_plan_covers_all_requirements() {
        let requirements = decompose_goal(&sample_goal(), &sample_task());
        let tickets = requirements_to_tickets(&requirements, &sample_task());
        validate_ticket_plan(&requirements, &tickets).expect("valid ticket plan");
    }

    #[test]
    fn contradiction_detection_catches_must_vs_must_not() {
        let base = decompose_goal(&sample_goal(), &sample_task());
        let mut modified: Vec<RequirementSpec> = base.into_iter().take(2).collect();
        modified[0].postconditions = vec!["must_json_output".to_string()];
        modified[1].postconditions = vec!["must_not_json_output".to_string()];

        let validation = validate_requirements(&modified);
        assert!(!validation.contradictions.is_empty());
    }
}
