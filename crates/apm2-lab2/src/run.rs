use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use uuid::Uuid;

use crate::agent::{AgentBackend, AgentTurn, ClaudeBackend, new_session_id, parse_structured_json};
use crate::artifact::{RunPaths, append_jsonl, hash_json, hash_text, write_json, write_text};
use crate::controller::{DecisionInputs, evaluate_iteration};
use crate::council::aggregate;
use crate::git_audit;
use crate::prompt::{self, APPLIER_ROLE, PROPOSER_ROLE};
use crate::schema::{
    ApplierOutput, CouncilScore, IterationDecision, IterationEvent, PatchProposal, QualityVector,
    RunSummary, SweepSummary,
};
use crate::spec::RfcControlSpec;

pub async fn run_rfc_control_from_path(
    spec_path: impl AsRef<Path>,
    seed: u64,
) -> Result<RunSummary> {
    let spec = RfcControlSpec::load(spec_path)?;
    run_rfc_control(spec, seed, None).await
}

pub async fn run_rfc_control(
    spec: RfcControlSpec,
    seed: u64,
    base_ref_override: Option<&str>,
) -> Result<RunSummary> {
    let mut backend = ClaudeBackend::new(spec.runtime.command.clone());
    run_rfc_control_with_backend(spec, seed, base_ref_override, &mut backend).await
}

pub async fn run_rfc_control_with_backend<B: AgentBackend>(
    spec: RfcControlSpec,
    seed: u64,
    base_ref_override: Option<&str>,
    backend: &mut B,
) -> Result<RunSummary> {
    let repo_root = git_audit::repo_root()?;

    if spec.git.enabled && !spec.git.allow_dirty && git_audit::is_dirty(&repo_root)? {
        return Err(anyhow!(
            "working tree is dirty; commit/stash or set git.allow_dirty=true in spec"
        ));
    }

    let base_ref = if let Some(base) = base_ref_override {
        base.to_string()
    } else {
        git_audit::current_head(&repo_root)?
    };

    let run_id = build_run_id(seed);
    println!("[lab2] starting run_id={run_id} seed={seed}");
    let branch_name = if spec.git.enabled {
        let branch = format!("{}/{}", spec.git.branch_prefix, run_id);
        git_audit::create_and_checkout_branch(&repo_root, &branch, &base_ref)?;
        println!("[lab2] git branch created: {branch}");
        Some(branch)
    } else {
        println!("[lab2] git integration disabled");
        None
    };

    let output_root = repo_root.join(&spec.outputs.root_dir);
    let paths = RunPaths::new(&output_root, &run_id)?;
    println!("[lab2] artifacts dir: {}", paths.run_dir.display());

    let prompt_files = prompt::write_system_prompts(&paths.run_dir, &spec)?;

    let target_path = repo_root.join(spec.target_path());
    let mut current_doc = fs::read_to_string(&target_path)
        .with_context(|| format!("read target RFC {}", target_path.display()))?;
    println!("[lab2] target RFC: {}", target_path.display());

    let mut sessions = BTreeMap::new();
    sessions.insert(PROPOSER_ROLE.to_string(), new_session_id(PROPOSER_ROLE));
    sessions.insert(APPLIER_ROLE.to_string(), new_session_id(APPLIER_ROLE));
    for reviewer in &spec.council.reviewer_ids {
        sessions.insert(reviewer.clone(), new_session_id(reviewer));
    }

    let mut total_tokens = 0u64;
    let mut total_calls = 0u64;
    let mut total_elapsed = 0.0f64;
    let mut total_delta_u = 0.0f64;
    let mut total_cost = 0.0f64;
    let mut total_disagreement = 0.0f64;
    let mut critical_regression_count = 0u64;
    let mut iterations_admitted = 0u64;
    let mut last_stop_reason = String::from("max_iterations_reached");
    let mut final_quality = QualityVector {
        security: 0.0,
        robustness: 0.0,
        reliability: 0.0,
        performance: 0.0,
        implementability: 0.0,
        verifiability: 0.0,
    };
    let mut iterations_executed = 0u64;

    for iteration in 0..spec.runtime.max_iterations {
        iterations_executed = iteration + 1;
        println!("[lab2] iteration={iteration} begin");
        let iter_dir = paths.iterations_dir.join(format!("iter_{iteration:03}"));
        fs::create_dir_all(&iter_dir).with_context(|| format!("create {}", iter_dir.display()))?;

        let before_hash = hash_text(&current_doc);
        let before_doc_path = iter_dir.join("before.md");
        write_text(&before_doc_path, &current_doc)?;

        let proposer_prompt =
            prompt::proposer_prompt(&spec, &before_hash, iteration, seed, &current_doc);
        write_text(iter_dir.join("prompt_proposer.txt"), &proposer_prompt)?;

        let proposer_response = backend
            .complete(&build_turn(
                PROPOSER_ROLE,
                &spec.runtime.model,
                &sessions,
                &prompt_files,
                proposer_prompt,
            )?)
            .await?;
        println!(
            "[lab2] iteration={iteration} role={} tokens={} elapsed_s={:.3}",
            PROPOSER_ROLE, proposer_response.token_estimate, proposer_response.elapsed_seconds
        );
        write_text(
            iter_dir.join("raw_proposer.json"),
            &proposer_response.raw_output,
        )?;
        let mut iter_tokens = proposer_response.token_estimate;
        let mut iter_elapsed = proposer_response.elapsed_seconds;
        total_tokens = total_tokens.saturating_add(proposer_response.token_estimate);
        total_calls = total_calls.saturating_add(1);
        total_elapsed += proposer_response.elapsed_seconds;

        let proposal = parse_structured_json::<PatchProposal>(&proposer_response.raw_output)
            .context("parse proposer output")?;
        write_json(iter_dir.join("proposal.json"), &proposal)?;

        if proposal.base_revision_hash != before_hash {
            last_stop_reason = "base_hash_mismatch_proposer".to_string();
            break;
        }

        let proposal_hash = hash_json(&proposal)?;
        let applier_prompt = prompt::applier_prompt(&before_hash, &proposal, &current_doc)?;
        write_text(iter_dir.join("prompt_applier.txt"), &applier_prompt)?;

        let applier_response = backend
            .complete(&build_turn(
                APPLIER_ROLE,
                &spec.runtime.model,
                &sessions,
                &prompt_files,
                applier_prompt,
            )?)
            .await?;
        println!(
            "[lab2] iteration={iteration} role={} tokens={} elapsed_s={:.3}",
            APPLIER_ROLE, applier_response.token_estimate, applier_response.elapsed_seconds
        );
        write_text(
            iter_dir.join("raw_applier.json"),
            &applier_response.raw_output,
        )?;
        iter_tokens = iter_tokens.saturating_add(applier_response.token_estimate);
        iter_elapsed += applier_response.elapsed_seconds;
        total_tokens = total_tokens.saturating_add(applier_response.token_estimate);
        total_calls = total_calls.saturating_add(1);
        total_elapsed += applier_response.elapsed_seconds;

        let applier = parse_structured_json::<ApplierOutput>(&applier_response.raw_output)
            .context("parse applier output")?;
        write_json(iter_dir.join("applier.json"), &applier)?;

        if applier.updated_document.trim().is_empty() {
            last_stop_reason = "empty_applier_document".to_string();
            break;
        }

        let after_doc_path = iter_dir.join("after.md");
        write_text(&after_doc_path, &applier.updated_document)?;

        let mut precheck_notes = Vec::new();
        if applier.base_revision_hash != before_hash {
            let note = format!(
                "applier base hash mismatch: expected={} got={}",
                before_hash, applier.base_revision_hash
            );
            println!("[lab2] iteration={iteration} warning: {note}");
            precheck_notes.push(note);
        }

        if applier.proposal_hash != proposal_hash {
            let note = format!(
                "applier proposal hash mismatch: expected={} got={}",
                proposal_hash, applier.proposal_hash
            );
            println!("[lab2] iteration={iteration} warning: {note}");
            precheck_notes.push(note);
        }

        let (diff_text, line_churn) = git_audit::make_diff(&before_doc_path, &after_doc_path)?;
        write_text(iter_dir.join("diff.patch"), &diff_text)?;

        let mut council_scores = Vec::new();
        for reviewer_id in &spec.council.reviewer_ids {
            let council_prompt =
                prompt::council_prompt(reviewer_id, &current_doc, &applier.updated_document);
            write_text(
                iter_dir.join(format!("prompt_council_{reviewer_id}.txt")),
                &council_prompt,
            )?;

            let council_response = backend
                .complete(&build_turn(
                    reviewer_id,
                    &spec.runtime.model,
                    &sessions,
                    &prompt_files,
                    council_prompt,
                )?)
                .await?;
            println!(
                "[lab2] iteration={iteration} role={} tokens={} elapsed_s={:.3}",
                reviewer_id, council_response.token_estimate, council_response.elapsed_seconds
            );
            write_text(
                iter_dir.join(format!("raw_council_{reviewer_id}.json")),
                &council_response.raw_output,
            )?;
            iter_tokens = iter_tokens.saturating_add(council_response.token_estimate);
            iter_elapsed += council_response.elapsed_seconds;
            total_tokens = total_tokens.saturating_add(council_response.token_estimate);
            total_calls = total_calls.saturating_add(1);
            total_elapsed += council_response.elapsed_seconds;

            let mut score = parse_structured_json::<CouncilScore>(&council_response.raw_output)
                .with_context(|| format!("parse council output for {reviewer_id}"))?;
            score.reviewer_id.clone_from(reviewer_id);
            score.before = score.before.clamp();
            score.after = score.after.clamp();
            score.confidence = score.confidence.clamp(0.0, 1.0);

            write_json(iter_dir.join(format!("council_{reviewer_id}.json")), &score)?;
            council_scores.push(score);
        }

        let aggregate = aggregate(&council_scores)?;

        let input = DecisionInputs {
            quality_before: aggregate.quality_before,
            quality_after: aggregate.quality_after,
            disagreement: aggregate.disagreement,
            token_cost: iter_tokens,
            elapsed_seconds: iter_elapsed,
            cli_calls: 2_u64 + spec.council.reviewer_ids.len() as u64,
            line_churn,
        };

        let mut outcome = evaluate_iteration(&spec.controller, &input);
        outcome.notes.extend(precheck_notes);
        println!(
            "[lab2] iteration={iteration} delta_u={:.6} cost={:.6} efficiency={:.6} disagreement={:.6}",
            outcome.delta_u, outcome.cost, outcome.efficiency, aggregate.disagreement
        );

        let budget_exhausted = total_tokens > spec.budget.max_tokens
            || total_calls > spec.budget.max_cli_calls
            || total_elapsed > spec.budget.max_elapsed_seconds;

        if budget_exhausted {
            outcome.admitted = false;
            outcome.continue_loop = false;
            outcome.stop_reason = "budget_exhausted".to_string();
            outcome.notes.push("budget limit exceeded".to_string());
            println!("[lab2] iteration={iteration} budget exhausted");
        }

        if outcome.critical_regression {
            critical_regression_count = critical_regression_count.saturating_add(1);
        }

        let decision = IterationDecision {
            run_id: run_id.clone(),
            seed,
            iteration,
            admitted: outcome.admitted,
            continue_loop: outcome.continue_loop,
            stop_reason: outcome.stop_reason.clone(),
            critical_regression: outcome.critical_regression,
            disagreement: aggregate.disagreement,
            quality_before: aggregate.quality_before,
            quality_after: aggregate.quality_after,
            delta_u: outcome.delta_u,
            cost: outcome.cost,
            efficiency: outcome.efficiency,
            token_cost: input.token_cost,
            elapsed_seconds: input.elapsed_seconds,
            cli_calls: input.cli_calls,
            line_churn,
            notes: outcome.notes.clone(),
        };

        write_json(iter_dir.join("decision.json"), &decision)?;

        let event = IterationEvent {
            run_id: run_id.clone(),
            seed,
            iteration,
            admitted: decision.admitted,
            stop_reason: decision.stop_reason.clone(),
            delta_u: decision.delta_u,
            cost: decision.cost,
            efficiency: decision.efficiency,
            disagreement: decision.disagreement,
            token_cost: decision.token_cost,
            elapsed_seconds: decision.elapsed_seconds,
            cli_calls: decision.cli_calls,
            line_churn: decision.line_churn,
            quality_before: decision.quality_before,
            quality_after: decision.quality_after,
        };
        append_jsonl(&paths.events_path, &event)?;

        total_disagreement += decision.disagreement;
        total_cost += decision.cost;

        if decision.admitted {
            println!(
                "[lab2] iteration={iteration} admitted=true stop_reason={}",
                decision.stop_reason
            );
            write_text(&target_path, &applier.updated_document)?;
            current_doc = applier.updated_document;
            total_delta_u += decision.delta_u;
            iterations_admitted = iterations_admitted.saturating_add(1);
            final_quality = decision.quality_after;

            if spec.git.enabled && spec.git.commit_each_admission {
                let message = format!(
                    "exp(rfc0022): iter {} seed {} delta_u={:.5} efficiency={:.5}",
                    iteration, seed, decision.delta_u, decision.efficiency
                );
                let commit_paths = vec![target_path.clone(), iter_dir.clone()];
                let committed = git_audit::commit_paths(&repo_root, &message, &commit_paths)?;
                println!("[lab2] iteration={iteration} commit_written={committed}");
            }
        } else {
            println!(
                "[lab2] iteration={iteration} admitted=false stop_reason={}",
                decision.stop_reason
            );
            final_quality = decision.quality_before;
            last_stop_reason = decision.stop_reason;
            break;
        }

        if !decision.continue_loop {
            last_stop_reason = decision.stop_reason;
            break;
        }
    }

    if iterations_executed == spec.runtime.max_iterations {
        last_stop_reason = "max_iterations_reached".to_string();
    }

    let final_hash = hash_text(&current_doc);
    let disagreement_mean = if iterations_executed == 0 {
        0.0
    } else {
        total_disagreement / iterations_executed as f64
    };

    let summary = RunSummary {
        run_id: run_id.clone(),
        seed,
        target_rfc_path: spec.target_rfc_path.clone(),
        branch_name,
        completed: iterations_admitted > 0,
        stop_reason: last_stop_reason,
        iterations_executed,
        iterations_admitted,
        final_quality,
        total_delta_u,
        total_cost,
        total_tokens,
        total_cli_calls: total_calls,
        total_elapsed_seconds: total_elapsed,
        critical_regression_count,
        council_disagreement_mean: disagreement_mean,
        final_rfc_hash: final_hash,
        summary_path: paths.summary_path.display().to_string(),
        events_path: paths.events_path.display().to_string(),
    };

    write_json(&paths.summary_path, &summary)?;
    write_json(
        &paths.hypothesis_path,
        &serde_json::json!({
            "h1_supported": summary.total_delta_u > 0.0 && summary.critical_regression_count == 0,
            "h0_supported": summary.total_delta_u <= 0.0 || summary.critical_regression_count > 0,
            "iterations_admitted": summary.iterations_admitted,
            "stop_reason": summary.stop_reason,
        }),
    )?;

    println!(
        "[lab2] completed run_id={} iterations_executed={} admitted={} stop_reason={} summary={}",
        summary.run_id,
        summary.iterations_executed,
        summary.iterations_admitted,
        summary.stop_reason,
        summary.summary_path
    );

    Ok(summary)
}

pub async fn run_sweep_from_path(
    spec_path: impl AsRef<Path>,
    seeds: &[u64],
) -> Result<SweepSummary> {
    if seeds.is_empty() {
        return Err(anyhow!("sweep requires at least one seed"));
    }

    let spec = RfcControlSpec::load(spec_path)?;
    let base_ref = if spec.git.enabled {
        Some(git_audit::current_head(&git_audit::repo_root()?)?)
    } else {
        None
    };

    let mut summaries = Vec::new();
    for &seed in seeds {
        let summary = run_rfc_control(spec.clone(), seed, base_ref.as_deref()).await?;
        summaries.push(summary);
    }

    Ok(aggregate_sweep(seeds, summaries))
}

fn aggregate_sweep(seeds: &[u64], summaries: Vec<RunSummary>) -> SweepSummary {
    let n = summaries.len().max(1) as f64;
    let mean_total_delta_u = summaries.iter().map(|s| s.total_delta_u).sum::<f64>() / n;
    let mean_total_cost = summaries.iter().map(|s| s.total_cost).sum::<f64>() / n;
    let mean_efficiency = if mean_total_cost > 0.0 {
        mean_total_delta_u / mean_total_cost
    } else {
        0.0
    };

    let mut admitted = summaries
        .iter()
        .map(|s| s.iterations_admitted as f64)
        .collect::<Vec<_>>();
    admitted.sort_by(f64::total_cmp);
    let median_iterations_admitted = admitted[admitted.len() / 2];

    let success_rate = summaries
        .iter()
        .filter(|s| s.total_delta_u > 0.0 && s.critical_regression_count == 0)
        .count() as f64
        / n;

    SweepSummary {
        runs: summaries.len(),
        seeds: seeds.to_vec(),
        mean_total_delta_u,
        mean_total_cost,
        mean_efficiency,
        median_iterations_admitted,
        success_rate,
        summaries,
    }
}

fn build_turn(
    role_id: &str,
    model: &str,
    sessions: &BTreeMap<String, String>,
    prompt_files: &BTreeMap<String, PathBuf>,
    prompt: String,
) -> Result<AgentTurn> {
    let session_id = sessions
        .get(role_id)
        .cloned()
        .ok_or_else(|| anyhow!("missing session for role {role_id}"))?;
    let system_prompt_file = prompt_files
        .get(role_id)
        .cloned()
        .ok_or_else(|| anyhow!("missing system prompt for role {role_id}"))?;

    Ok(AgentTurn {
        role_id: role_id.to_string(),
        model: model.to_string(),
        session_id,
        system_prompt_file,
        prompt,
    })
}

fn build_run_id(seed: u64) -> String {
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
    let nonce = Uuid::new_v4().simple().to_string();
    format!("run-{}-seed-{}-{}", ts, seed, &nonce[..8])
}

#[cfg(test)]
mod tests {
    use super::aggregate_sweep;
    use crate::schema::{QualityVector, RunSummary};

    fn summary(seed: u64, delta: f64, cost: f64, admitted: u64) -> RunSummary {
        RunSummary {
            run_id: format!("r{seed}"),
            seed,
            target_rfc_path: "documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md"
                .to_string(),
            branch_name: None,
            completed: admitted > 0,
            stop_reason: "test".to_string(),
            iterations_executed: 1,
            iterations_admitted: admitted,
            final_quality: QualityVector {
                security: 0.5,
                robustness: 0.5,
                reliability: 0.5,
                performance: 0.5,
                implementability: 0.5,
                verifiability: 0.5,
            },
            total_delta_u: delta,
            total_cost: cost,
            total_tokens: 100,
            total_cli_calls: 5,
            total_elapsed_seconds: 1.0,
            critical_regression_count: 0,
            council_disagreement_mean: 0.1,
            final_rfc_hash: "abc".to_string(),
            summary_path: "s".to_string(),
            events_path: "e".to_string(),
        }
    }

    #[test]
    fn aggregate_sweep_computes_expected_rates() {
        let seeds = vec![1, 2, 3];
        let sweep = aggregate_sweep(
            &seeds,
            vec![
                summary(1, 0.6, 2.0, 2),
                summary(2, -0.1, 1.5, 0),
                summary(3, 0.3, 1.0, 1),
            ],
        );
        assert_eq!(sweep.runs, 3);
        assert!(sweep.mean_total_delta_u > 0.0);
        assert!(sweep.success_rate > 0.0);
    }
}
