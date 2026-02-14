//! Local SHA-bound findings storage and projection helpers.

use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::types::{
    apm2_home_dir, ensure_parent_dir, normalize_decision_dimension, now_iso8601, sanitize_for_path,
    validate_expected_head_sha,
};

pub(super) const FINDINGS_BUNDLE_SCHEMA: &str = "apm2.fac.sha_findings.bundle.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FindingsBundle {
    pub schema: String,
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub source: String,
    pub updated_at: String,
    pub dimensions: Vec<StoredDimensionFindings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredDimensionFindings {
    pub dimension: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    pub findings: Vec<StoredFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredFinding {
    pub finding_id: String,
    pub severity: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,
    #[serde(default)]
    pub created_at: String,
    pub evidence_digest: String,
    pub raw_evidence_pointer: String,
}

pub(super) fn findings_bundle_path(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<PathBuf, String> {
    validate_expected_head_sha(head_sha)?;
    Ok(apm2_home_dir()?
        .join("private")
        .join("fac")
        .join("findings")
        .join("repos")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}"))
        .join(format!("sha-{}", sanitize_for_path(head_sha)))
        .join("bundle.json"))
}

fn findings_lock_path(owner_repo: &str, pr_number: u32, head_sha: &str) -> Result<PathBuf, String> {
    let bundle_path = findings_bundle_path(owner_repo, pr_number, head_sha)?;
    let parent = bundle_path.parent().ok_or_else(|| {
        format!(
            "findings bundle path has no parent: {}",
            bundle_path.display()
        )
    })?;
    Ok(parent.join("bundle.lock"))
}

fn acquire_findings_lock(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<std::fs::File, String> {
    let lock_path = findings_lock_path(owner_repo, pr_number, head_sha)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open findings lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file
        .lock_exclusive()
        .map_err(|err| format!("failed to lock findings {}: {err}", lock_path.display()))?;
    Ok(lock_file)
}

pub(super) fn load_findings_bundle(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Option<FindingsBundle>, String> {
    let path = findings_bundle_path(owner_repo, pr_number, head_sha)?;
    let bytes = match fs::read(&path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read findings bundle {}: {err}",
                path.display()
            ));
        },
    };

    let bundle = serde_json::from_slice::<FindingsBundle>(&bytes)
        .map_err(|err| format!("failed to parse findings bundle {}: {err}", path.display()))?;
    Ok(Some(bundle))
}

pub(super) fn save_findings_bundle(bundle: &FindingsBundle) -> Result<(), String> {
    let path = findings_bundle_path(&bundle.owner_repo, bundle.pr_number, &bundle.head_sha)?;
    write_json_atomic(&path, bundle)
}

pub(super) fn upsert_dimension_verdict(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
    verdict: &str,
    source: &str,
) -> Result<FindingsBundle, String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_sha = head_sha.to_ascii_lowercase();
    let _lock = acquire_findings_lock(owner_repo, pr_number, &normalized_sha)?;
    let normalized_dimension = normalize_decision_dimension(dimension)?.to_string();
    let _normalized_verdict = normalize_verdict(verdict)?;

    let mut bundle = load_findings_bundle(owner_repo, pr_number, &normalized_sha)?
        .unwrap_or_else(|| empty_bundle(owner_repo, pr_number, &normalized_sha, source));

    if bundle.schema != FINDINGS_BUNDLE_SCHEMA {
        return Err(format!(
            "unsupported findings bundle schema `{}` at repo={} pr={} sha={}",
            bundle.schema, owner_repo, pr_number, normalized_sha
        ));
    }

    let _ = upsert_dimension(&mut bundle, &normalized_dimension);

    bundle.source = source.to_string();
    bundle.updated_at = now_iso8601();
    save_findings_bundle(&bundle)?;
    Ok(bundle)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_dimension_finding(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
    severity: &str,
    summary: &str,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    evidence_pointer: Option<&str>,
    source: &str,
) -> Result<(FindingsBundle, StoredFinding), String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_sha = head_sha.to_ascii_lowercase();
    let _lock = acquire_findings_lock(owner_repo, pr_number, &normalized_sha)?;
    let normalized_dimension = normalize_decision_dimension(dimension)?.to_string();
    let normalized_severity = normalize_severity(severity)?.to_string();
    let normalized_summary = summary.trim();
    if normalized_summary.is_empty() {
        return Err("finding summary is empty".to_string());
    }

    let mut bundle = load_findings_bundle(owner_repo, pr_number, &normalized_sha)?
        .unwrap_or_else(|| empty_bundle(owner_repo, pr_number, &normalized_sha, source));
    if bundle.schema != FINDINGS_BUNDLE_SCHEMA {
        return Err(format!(
            "unsupported findings bundle schema `{}` at repo={} pr={} sha={}",
            bundle.schema, owner_repo, pr_number, normalized_sha
        ));
    }

    let dimension_entry = upsert_dimension(&mut bundle, &normalized_dimension);
    let created_at = now_iso8601();
    let finding_id = allocate_finding_id(pr_number, &normalized_dimension);
    let finding = StoredFinding {
        finding_id,
        severity: normalized_severity,
        summary: normalized_summary.to_string(),
        risk: normalize_optional_text(risk),
        impact: normalize_optional_text(impact),
        location: normalize_optional_text(location),
        reviewer_id: normalize_optional_text(reviewer_id),
        created_at,
        evidence_digest: finding_digest(
            owner_repo,
            pr_number,
            &normalized_sha,
            &normalized_dimension,
            severity,
            normalized_summary,
            risk,
            impact,
            location,
            reviewer_id,
            evidence_pointer,
        ),
        raw_evidence_pointer: normalize_optional_text(evidence_pointer)
            .unwrap_or_else(|| "none".to_string()),
    };
    dimension_entry.findings.push(finding.clone());
    bundle.source = source.to_string();
    bundle.updated_at = now_iso8601();
    save_findings_bundle(&bundle)?;
    Ok((bundle, finding))
}

pub(super) fn find_dimension<'a>(
    bundle: &'a FindingsBundle,
    dimension: &str,
) -> Option<&'a StoredDimensionFindings> {
    let normalized = normalize_decision_dimension(dimension).ok()?;
    bundle
        .dimensions
        .iter()
        .find(|entry| normalize_decision_dimension(&entry.dimension).ok() == Some(normalized))
}

pub(super) fn find_finding<'a>(
    bundle: &'a FindingsBundle,
    dimension: &str,
    finding_id: &str,
) -> Option<&'a StoredFinding> {
    find_dimension(bundle, dimension)?
        .findings
        .iter()
        .find(|entry| entry.finding_id == finding_id)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create temp file in {}: {err}", parent.display()))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), value)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))?;
    tmp.as_file_mut()
        .flush()
        .map_err(|err| format!("failed to flush {}: {err}", path.display()))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", path.display()))?;
    tmp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

fn empty_bundle(owner_repo: &str, pr_number: u32, head_sha: &str, source: &str) -> FindingsBundle {
    FindingsBundle {
        schema: FINDINGS_BUNDLE_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: head_sha.to_string(),
        source: source.to_string(),
        updated_at: now_iso8601(),
        dimensions: vec![
            StoredDimensionFindings {
                dimension: "security".to_string(),
                status: "MISSING".to_string(),
                verdict: None,
                findings: Vec::new(),
            },
            StoredDimensionFindings {
                dimension: "code-quality".to_string(),
                status: "MISSING".to_string(),
                verdict: None,
                findings: Vec::new(),
            },
        ],
    }
}

fn normalize_verdict(verdict: &str) -> Result<&'static str, String> {
    match verdict.trim().to_ascii_uppercase().as_str() {
        "PASS" => Ok("PASS"),
        "FAIL" => Ok("FAIL"),
        other => Err(format!(
            "invalid verdict `{other}` (expected PASS|FAIL) for SHA-bound findings store"
        )),
    }
}

fn normalize_severity(severity: &str) -> Result<&'static str, String> {
    match severity.trim().to_ascii_uppercase().as_str() {
        "BLOCKER" => Ok("BLOCKER"),
        "MAJOR" => Ok("MAJOR"),
        "MINOR" => Ok("MINOR"),
        "NIT" => Ok("NIT"),
        other => Err(format!(
            "invalid finding severity `{other}` (expected BLOCKER|MAJOR|MINOR|NIT)"
        )),
    }
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
}

fn allocate_finding_id(pr_number: u32, dimension: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let dim = dimension.replace('-', "_");
    format!("f-{pr_number}-{dim}-{nanos}")
}

#[allow(clippy::too_many_arguments)]
fn finding_digest(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
    severity: &str,
    summary: &str,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    evidence_pointer: Option<&str>,
) -> String {
    let payload = serde_json::json!({
        "owner_repo": owner_repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "dimension": dimension,
        "severity": severity.trim().to_ascii_uppercase(),
        "summary": summary.trim(),
        "risk": risk.map_or("", str::trim),
        "impact": impact.map_or("", str::trim),
        "location": location.map_or("", str::trim),
        "reviewer_id": reviewer_id.map_or("", str::trim),
        "evidence_pointer": evidence_pointer.map_or("", str::trim),
    });
    let canonical = serde_json::to_string(&payload).unwrap_or_default();
    let digest = sha2::Sha256::digest(canonical.as_bytes());
    hex::encode(digest)
}

fn upsert_dimension<'a>(
    bundle: &'a mut FindingsBundle,
    dimension: &str,
) -> &'a mut StoredDimensionFindings {
    if let Some(pos) = bundle
        .dimensions
        .iter()
        .position(|entry| normalize_decision_dimension(&entry.dimension).ok() == Some(dimension))
    {
        return &mut bundle.dimensions[pos];
    }

    bundle.dimensions.push(StoredDimensionFindings {
        dimension: dimension.to_string(),
        status: "MISSING".to_string(),
        verdict: None,
        findings: Vec::new(),
    });
    let len = bundle.dimensions.len();
    &mut bundle.dimensions[len - 1]
}

#[cfg(test)]
mod tests {
    use super::normalize_verdict;

    #[test]
    fn normalize_verdict_accepts_pass_fail() {
        assert_eq!(normalize_verdict("PASS").expect("pass"), "PASS");
        assert_eq!(normalize_verdict("fail").expect("fail"), "FAIL");
        assert!(normalize_verdict("unknown").is_err());
    }
}
