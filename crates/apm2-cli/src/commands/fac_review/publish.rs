//! `apm2 fac review publish` — publish review comments with generated metadata.

use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;

use super::github_auth::resolve_local_reviewer_identity;
use super::target::resolve_pr_target;
use super::types::{
    QUALITY_MARKER, SECURITY_MARKER, allocate_local_comment_id, validate_expected_head_sha,
};
use super::{findings_store, github_projection, projection_store, verdict_projection};
use crate::exit_codes::codes as exit_codes;

const PUBLISH_SCHEMA: &str = "apm2.fac.review.publish.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReviewPublishTypeArg {
    Security,
    #[value(alias = "quality")]
    CodeQuality,
}

impl ReviewPublishTypeArg {
    const fn metadata_spec(self) -> (&'static str, &'static str) {
        match self {
            Self::Security => (SECURITY_MARKER, "security"),
            Self::CodeQuality => (QUALITY_MARKER, "code-quality"),
        }
    }
}

#[derive(Debug, Serialize)]
struct PublishSummary {
    schema: String,
    repo: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    review_type: String,
    body_file: String,
    comment_id: u64,
    comment_url: String,
}

pub fn run_publish(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    review_type: ReviewPublishTypeArg,
    body_file: &Path,
    json_output: bool,
) -> Result<u8, String> {
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let reviewer_id = resolve_reviewer_id(&owner_repo, resolved_pr)?;
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;

    let raw_body = std::fs::read_to_string(body_file)
        .map_err(|err| format!("failed to read body file {}: {err}", body_file.display()))?;
    let (marker, review_type_label) = review_type.metadata_spec();
    let verdict =
        resolve_dimension_verdict(&owner_repo, resolved_pr, &head_sha, review_type_label)?;
    let enriched_body = render_comment_with_generated_metadata(
        &raw_body,
        marker,
        review_type_label,
        resolved_pr,
        &head_sha,
        &reviewer_id,
        &verdict,
    )?;
    let (comment_id, comment_url) = match github_projection::create_issue_comment(
        &owner_repo,
        resolved_pr,
        &enriched_body,
    ) {
        Ok(response) => (response.id, response.html_url),
        Err(err) => {
            eprintln!(
                "WARNING: failed to project publish comment to GitHub for PR #{resolved_pr}: {err}"
            );
            let fallback_id = next_local_comment_id(&owner_repo, resolved_pr);
            let fallback_url = format!(
                "local://fac_projection/{owner_repo}/pr-{resolved_pr}/issue_comments#{fallback_id}"
            );
            (fallback_id, fallback_url)
        },
    };

    let summary = PublishSummary {
        schema: PUBLISH_SCHEMA.to_string(),
        repo: owner_repo.clone(),
        pr_number: resolved_pr,
        pr_url: format!("https://github.com/{owner_repo}/pull/{resolved_pr}"),
        head_sha,
        review_type: review_type_label.to_string(),
        body_file: body_file.display().to_string(),
        comment_id,
        comment_url,
    };

    findings_store::upsert_dimension_verdict(
        &owner_repo,
        resolved_pr,
        &summary.head_sha,
        review_type_label,
        &verdict,
        "publish",
    )?;

    let _ = projection_store::save_trusted_reviewer_id(&owner_repo, resolved_pr, &reviewer_id);
    let _ = projection_store::save_identity_with_context(
        &owner_repo,
        resolved_pr,
        &summary.head_sha,
        "publish",
    );
    let _ = projection_store::upsert_issue_comment_cache_entry(
        &owner_repo,
        resolved_pr,
        summary.comment_id,
        &summary.comment_url,
        &enriched_body,
        &reviewer_id,
    );

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("FAC Review Publish");
        println!("  Repo:         {}", summary.repo);
        println!("  PR Number:    {}", summary.pr_number);
        println!("  PR URL:       {}", summary.pr_url);
        println!("  Head SHA:     {}", summary.head_sha);
        println!("  Review Type:  {}", summary.review_type);
        println!("  Body File:    {}", summary.body_file);
        println!("  Comment ID:   {}", summary.comment_id);
        println!("  Comment URL:  {}", summary.comment_url);
    }

    Ok(exit_codes::SUCCESS)
}

fn resolve_head_sha(owner_repo: &str, pr_number: u32, sha: Option<&str>) -> Result<String, String> {
    if let Some(value) = sha {
        validate_expected_head_sha(value)?;
        return Ok(value.to_ascii_lowercase());
    }

    if let Some(identity) = projection_store::load_pr_identity(owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        return Ok(identity.head_sha.to_ascii_lowercase());
    }

    if let Some(value) = super::state::resolve_local_review_head_sha(pr_number) {
        return Ok(value);
    }

    Err(format!(
        "missing local head SHA for PR #{pr_number}; pass --sha explicitly or run local FAC review first"
    ))
}

fn resolve_reviewer_id(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    if let Some(cached) = projection_store::load_trusted_reviewer_id(owner_repo, pr_number)? {
        return Ok(cached);
    }

    let reviewer_id = resolve_local_reviewer_identity();
    let _ = projection_store::save_trusted_reviewer_id(owner_repo, pr_number, &reviewer_id);
    Ok(reviewer_id)
}

fn strip_existing_metadata_block(body: &str, marker: &str) -> String {
    let pattern = format!(r"(?s){}\s*```json.*?```", regex::escape(marker));
    let Ok(re) = regex::Regex::new(&pattern) else {
        return body.to_string();
    };
    re.replacen(body, 1, "").to_string()
}

fn build_generated_metadata_block(
    marker: &str,
    review_type: &str,
    pr_number: u32,
    head_sha: &str,
    reviewer_id: &str,
    verdict: &str,
) -> Result<String, String> {
    let payload = serde_json::json!({
        "schema": "apm2.review.metadata.v1",
        "review_type": review_type,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "verdict": verdict,
        "reviewer_id": reviewer_id,
    });
    let json = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("failed to serialize generated review metadata: {err}"))?;
    Ok(format!("{marker}\n```json\n{json}\n```"))
}

fn render_comment_with_generated_metadata(
    body: &str,
    marker: &str,
    review_type: &str,
    pr_number: u32,
    head_sha: &str,
    reviewer_id: &str,
    verdict: &str,
) -> Result<String, String> {
    let stripped = strip_existing_metadata_block(body, marker);
    let metadata = build_generated_metadata_block(
        marker,
        review_type,
        pr_number,
        head_sha,
        reviewer_id,
        verdict,
    )?;
    let normalized = stripped.trim_end();
    if normalized.is_empty() {
        Ok(format!("{metadata}\n"))
    } else {
        Ok(format!("{normalized}\n\n{metadata}\n"))
    }
}

fn resolve_dimension_verdict(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
) -> Result<String, String> {
    verdict_projection::resolve_verdict_for_dimension(owner_repo, pr_number, head_sha, dimension)?
        .ok_or_else(|| {
            format!(
                "missing explicit verdict for PR #{pr_number} sha {head_sha} dimension `{dimension}`; run `apm2 fac review verdict set` first"
            )
        })
}

fn next_local_comment_id(_owner_repo: &str, pr_number: u32) -> u64 {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    allocate_local_comment_id(pr_number, Some(seed))
}

#[cfg(test)]
mod tests {
    use super::{ReviewPublishTypeArg, render_comment_with_generated_metadata};
    use crate::commands::fac_review::types::SECURITY_MARKER;

    #[test]
    fn review_publish_type_arg_maps_to_expected_metadata_spec() {
        let (security_marker, security_type) = ReviewPublishTypeArg::Security.metadata_spec();
        assert!(security_marker.contains("security"));
        assert_eq!(security_type, "security");

        let (quality_marker, quality_type) = ReviewPublishTypeArg::CodeQuality.metadata_spec();
        assert!(quality_marker.contains("code-quality"));
        assert_eq!(quality_type, "code-quality");
    }

    #[test]
    fn publish_metadata_generation_appends_machine_readable_block() {
        let body = r"
## Security Review: FAIL

### **BLOCKER FINDINGS**
1. Issue: auth bypass
";
        let rendered = render_comment_with_generated_metadata(
            body,
            "<!-- apm2-review-metadata:v1:security -->",
            "security",
            321,
            "0123456789abcdef0123456789abcdef01234567",
            "fac-reviewer",
            "FAIL",
        )
        .expect("rendered");

        assert!(rendered.contains("apm2-review-metadata:v1:security"));
        assert!(rendered.contains("\"schema\": \"apm2.review.metadata.v1\""));
        assert!(rendered.contains("\"review_type\": \"security\""));
        assert!(rendered.contains("\"reviewer_id\": \"fac-reviewer\""));
        assert!(rendered.contains("\"verdict\": \"FAIL\""));
        assert!(!rendered.contains("\"severity_counts\""));
    }

    #[test]
    fn render_comment_with_generated_metadata_replaces_existing_block() {
        let body = r#"
## Security Review: PASS

<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 1,
  "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verdict": "PASS",
  "severity_counts": { "blocker": 0, "major": 0, "minor": 0, "nit": 0 },
  "reviewer_id": "old"
}
```
"#;
        let rendered = render_comment_with_generated_metadata(
            body,
            SECURITY_MARKER,
            "security",
            441,
            "0123456789abcdef0123456789abcdef01234567",
            "new-reviewer",
            "PASS",
        )
        .expect("rendered");
        assert_eq!(rendered.matches(SECURITY_MARKER).count(), 1);
        assert!(rendered.contains("\"pr_number\": 441"));
        assert!(rendered.contains("\"reviewer_id\": \"new-reviewer\""));
        assert!(!rendered.contains("\"head_sha\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
        assert!(!rendered.contains("\"severity_counts\""));
    }

    #[test]
    fn render_comment_with_generated_metadata_uses_current_header_not_stale_metadata_verdict() {
        let body = r#"
## Security Review: PASS

<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 1,
  "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verdict": "FAIL",
  "reviewer_id": "old"
}
```
"#;
        let rendered = render_comment_with_generated_metadata(
            body,
            SECURITY_MARKER,
            "security",
            441,
            "0123456789abcdef0123456789abcdef01234567",
            "new-reviewer",
            "PASS",
        )
        .expect("rendered");
        assert!(rendered.contains("## Security Review: PASS"));
        assert!(rendered.contains("\"verdict\": \"PASS\""));
        assert!(!rendered.contains("\"verdict\": \"FAIL\""));
    }
}
