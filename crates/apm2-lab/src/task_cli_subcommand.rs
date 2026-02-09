use crate::schema::{GoalSpec, TaskTemplateSpec, TraceLink};

pub fn default_goal() -> GoalSpec {
    GoalSpec {
        id: "GOAL-CLI-WORK-SUMMARIZE".to_string(),
        statement: "Add a CLI subcommand that summarizes work outcomes from ledger JSONL"
            .to_string(),
        problem_statement:
            "Operators need quick visibility into admitted/rejected/pending work outcomes"
                .to_string(),
        objective_function:
            "maximize outcome visibility with deterministic outputs and bounded errors".to_string(),
        constraints: vec![
            "no daemon protocol changes".to_string(),
            "cli-only implementation".to_string(),
            "tests required".to_string(),
        ],
        assumptions: vec![
            "ledger is available as JSONL".to_string(),
            "clap command hierarchy is extensible".to_string(),
        ],
        acceptance_predicates: vec![
            "command_accepts_ledger_path".to_string(),
            "plain_and_json_output_modes_work".to_string(),
            "invalid_lines_are_fail_closed".to_string(),
            "tests_cover_happy_and_failure_paths".to_string(),
        ],
    }
}

pub fn default_task_template() -> TaskTemplateSpec {
    TaskTemplateSpec {
        command_name: "work_summarize".to_string(),
        summary: "Summarize work outcomes by status and work type from ledger JSONL".to_string(),
        target_paths: vec![
            "crates/apm2-cli/src/main.rs".to_string(),
            "crates/apm2-cli/src/commands".to_string(),
            "crates/apm2-cli/tests".to_string(),
        ],
        acceptance_predicates: vec![
            "parse_valid_ledger".to_string(),
            "invalid_line_returns_error".to_string(),
            "empty_ledger_returns_zero_counts".to_string(),
            "json_output_matches_schema".to_string(),
            "plain_output_is_deterministic".to_string(),
        ],
        verification_commands: vec![
            "cargo test -p apm2-cli -- work".to_string(),
            "cargo clippy -p apm2-cli --all-targets -- -D warnings".to_string(),
        ],
    }
}

pub fn build_trace_links(
    requirement_ids: &[String],
    ticket_ids: &[String],
    goal_id: &str,
) -> Vec<TraceLink> {
    let mut links = Vec::new();

    for requirement_id in requirement_ids {
        links.push(TraceLink {
            from_id: goal_id.to_string(),
            to_id: requirement_id.clone(),
            kind: "goal_to_requirement".to_string(),
        });
    }

    for ticket_id in ticket_ids {
        for requirement_id in requirement_ids {
            links.push(TraceLink {
                from_id: requirement_id.clone(),
                to_id: ticket_id.clone(),
                kind: "requirement_to_ticket".to_string(),
            });
        }
    }

    links
}
