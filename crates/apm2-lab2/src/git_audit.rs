use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};

pub fn repo_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("run git rev-parse --show-toplevel")?;
    if !output.status.success() {
        return Err(anyhow!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(text))
}

pub fn current_head(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .with_context(|| format!("git rev-parse HEAD at {}", repo_root.display()))?;

    if !output.status.success() {
        return Err(anyhow!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn is_dirty(repo_root: &Path) -> Result<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .with_context(|| format!("git status at {}", repo_root.display()))?;

    if !output.status.success() {
        return Err(anyhow!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

pub fn create_and_checkout_branch(repo_root: &Path, branch: &str, base_ref: &str) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["checkout", "-b", branch, base_ref])
        .output()
        .with_context(|| format!("git checkout -b {branch} {base_ref}"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "git checkout -b failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

pub fn commit_paths(repo_root: &Path, message: &str, paths: &[PathBuf]) -> Result<bool> {
    if paths.is_empty() {
        return Ok(false);
    }

    let mut add_cmd = Command::new("git");
    add_cmd.arg("-C").arg(repo_root).arg("add").arg("--");
    for path in paths {
        let rel = to_repo_relative(repo_root, path)?;
        add_cmd.arg(rel);
    }

    let add = add_cmd.output().context("git add for experiment commit")?;
    if !add.status.success() {
        return Err(anyhow!(
            "git add failed: {}",
            String::from_utf8_lossy(&add.stderr).trim()
        ));
    }

    let staged = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--cached", "--quiet"])
        .status()
        .context("git diff --cached --quiet")?;

    if staged.success() {
        return Ok(false);
    }

    let commit = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["commit", "-m", message, "--no-verify"])
        .output()
        .context("git commit for experiment")?;

    if !commit.status.success() {
        return Err(anyhow!(
            "git commit failed: {}",
            String::from_utf8_lossy(&commit.stderr).trim()
        ));
    }

    Ok(true)
}

pub fn make_diff(before: &Path, after: &Path) -> Result<(String, u64)> {
    let before_str = before.display().to_string();
    let after_str = after.display().to_string();

    let output = Command::new("git")
        .args([
            "diff",
            "--no-index",
            "--",
            before_str.as_str(),
            after_str.as_str(),
        ])
        .output()
        .context("git diff --no-index")?;

    let status_code = output.status.code().unwrap_or_default();
    if status_code != 0 && status_code != 1 {
        return Err(anyhow!(
            "git diff --no-index failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let diff_text = String::from_utf8_lossy(&output.stdout).to_string();

    let numstat = Command::new("git")
        .args([
            "diff",
            "--no-index",
            "--numstat",
            "--",
            before_str.as_str(),
            after_str.as_str(),
        ])
        .output()
        .context("git diff --no-index --numstat")?;

    let numstat_code = numstat.status.code().unwrap_or_default();
    if numstat_code != 0 && numstat_code != 1 {
        return Err(anyhow!(
            "git diff --numstat failed: {}",
            String::from_utf8_lossy(&numstat.stderr).trim()
        ));
    }

    let churn = parse_numstat(&String::from_utf8_lossy(&numstat.stdout));

    Ok((diff_text, churn))
}

fn parse_numstat(text: &str) -> u64 {
    text.lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let added = cols.next()?.parse::<u64>().ok()?;
            let removed = cols.next()?.parse::<u64>().ok()?;
            Some(added.saturating_add(removed))
        })
        .sum()
}

fn to_repo_relative(repo_root: &Path, path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        let rel = path.strip_prefix(repo_root).with_context(|| {
            format!("{} not under repo {}", path.display(), repo_root.display())
        })?;
        Ok(rel.to_path_buf())
    } else {
        Ok(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_numstat;

    #[test]
    fn parse_numstat_sums_added_and_removed() {
        let input = "12\t3\ta.md\n5\t7\tb.md\n";
        assert_eq!(parse_numstat(input), 27);
    }
}
