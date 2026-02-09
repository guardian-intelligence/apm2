use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::schema::PatchProposal;
use crate::spec::RfcControlSpec;

pub const PROPOSER_ROLE: &str = "rfc_proposer";
pub const APPLIER_ROLE: &str = "rfc_applier";

pub fn write_system_prompts(
    run_dir: &Path,
    spec: &RfcControlSpec,
) -> Result<BTreeMap<String, PathBuf>> {
    let system_dir = run_dir.join("system_prompts");
    fs::create_dir_all(&system_dir).with_context(|| format!("create {}", system_dir.display()))?;

    let mut out = BTreeMap::new();

    let mut roles = Vec::new();
    roles.push(PROPOSER_ROLE.to_string());
    roles.push(APPLIER_ROLE.to_string());
    roles.extend(spec.council.reviewer_ids.clone());

    let alien_block = if spec.runtime.include_alien_protocol {
        Some(load_alien_protocol_summary())
    } else {
        None
    };

    for role in roles {
        let text = system_prompt_for_role(&role, alien_block.as_deref());
        let path = system_dir.join(format!("{role}.md"));
        fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
        out.insert(role, path);
    }

    Ok(out)
}

pub fn proposer_prompt(
    spec: &RfcControlSpec,
    base_hash: &str,
    iteration: u64,
    seed: u64,
    current_doc: &str,
) -> String {
    format!(
        "You are improving an RFC through auditable diffs.\n\nGoal:\n{goal}\n\nIteration: {iteration}\nSeed: {seed}\nBase revision hash: {base_hash}\n\nCurrent RFC document:\n```markdown\n{doc}\n```\n\nReturn ONLY a JSON object with this exact shape:\n{{\n  \"kind\": \"apm2.rfc.proposal.v1\",\n  \"base_revision_hash\": \"{base_hash}\",\n  \"summary\": \"...\",\n  \"rationale\": \"...\",\n  \"diffs\": [\"unified diff against the current RFC\"],\n  \"predicted_delta\": {{\"security\":0.0,\"robustness\":0.0,\"reliability\":0.0,\"performance\":0.0,\"implementability\":0.0,\"verifiability\":0.0}},\n  \"risk_flags\": [\"...\"]\n}}\n\nRules:\n- Diffs must target only this file path: {path}\n- Improve across containment/security > verification/correctness > liveness/progress.\n- If no safe improvement exists, return empty diffs with rationale.\n- Do not include markdown fences around JSON.",
        goal = spec.goal_statement,
        path = spec.target_rfc_path,
        doc = current_doc
    )
}

pub fn applier_prompt(
    base_hash: &str,
    proposal: &PatchProposal,
    current_doc: &str,
) -> Result<String> {
    let proposal_json = serde_json::to_string_pretty(proposal).context("serialize proposal")?;
    Ok(format!(
        "Apply the proposal to the RFC text exactly and return a full updated document.\n\nBase revision hash: {base_hash}\n\nCurrent RFC:\n```markdown\n{current_doc}\n```\n\nProposal:\n```json\n{proposal_json}\n```\n\nReturn ONLY JSON with this exact shape:\n{{\n  \"kind\": \"apm2.rfc.applier_output.v1\",\n  \"base_revision_hash\": \"{base_hash}\",\n  \"proposal_hash\": \"blake3 hash of canonicalized proposal json\",\n  \"updated_document\": \"full markdown document\",\n  \"notes\": \"...\"\n}}\n\nRules:\n- Keep all existing valid content unless the proposal changes it.\n- Produce complete RFC markdown in updated_document.\n- No markdown fences around JSON output."
    ))
}

pub fn council_prompt(reviewer_id: &str, before_doc: &str, after_doc: &str) -> String {
    format!(
        "You are council reviewer '{reviewer_id}'. Score document quality before and after independently.\n\nReturn ONLY JSON with this exact shape:\n{{\n  \"kind\": \"apm2.rfc.council_score.v1\",\n  \"reviewer_id\": \"{reviewer_id}\",\n  \"before\": {{\"security\":0.0,\"robustness\":0.0,\"reliability\":0.0,\"performance\":0.0,\"implementability\":0.0,\"verifiability\":0.0}},\n  \"after\": {{\"security\":0.0,\"robustness\":0.0,\"reliability\":0.0,\"performance\":0.0,\"implementability\":0.0,\"verifiability\":0.0}},\n  \"confidence\": 0.0,\n  \"regressions\": [\"...\"],\n  \"rationale\": \"...\"\n}}\n\nScoring rules:\n- All scores must be in [0,1].\n- Be strict on security and robustness.\n- Penalize unverifiable claims and missing machine-checkable predicates.\n- Confidence must be in [0,1].\n\nBefore document:\n```markdown\n{before_doc}\n```\n\nAfter document:\n```markdown\n{after_doc}\n```\n\nNo markdown fences around JSON output.",
    )
}

fn system_prompt_for_role(role: &str, alien_block: Option<&str>) -> String {
    let mut base = String::from(
        "You operate in a deterministic, auditable RFC improvement harness. \
All outputs must be machine-parseable JSON and fail-closed by default. \
Honor dominance order: containment/security > verification/correctness > liveness/progress.\n",
    );

    if let Some(block) = alien_block {
        base.push('\n');
        base.push_str("Alien Engineering Protocol context:\n");
        base.push_str(block);
        base.push('\n');
    }

    match role {
        PROPOSER_ROLE => {
            base.push_str("\nRole: propose precise RFC improvements as unified diffs with rationale and risk flags.");
        },
        APPLIER_ROLE => {
            base.push_str(
                "\nRole: apply proposed diffs faithfully and return full updated RFC text.",
            );
        },
        _ => {
            base.push_str(
                "\nRole: independent council reviewer. Score before/after quality and identify regressions.",
            );
        },
    }

    base
}

fn load_alien_protocol_summary() -> String {
    let path = Path::new("documents/prompts/instruction.alien_engineering_protocol.v1.json");
    let bytes = fs::read(path).ok();
    let Some(bytes) = bytes else {
        return "alien protocol unavailable".to_string();
    };

    let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
    let Some(value) = value else {
        return "alien protocol unavailable".to_string();
    };

    let instruction = value
        .pointer("/payload/i")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Alien Engineering Protocol active.");

    let dominance = value
        .pointer("/payload/lex/DOMINANCE_ORDER")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("containment/security > verification/correctness > liveness/progress");

    format!("- {instruction}\n- {dominance}")
}
