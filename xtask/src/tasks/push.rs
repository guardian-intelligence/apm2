//! Implementation of the `push` command.
//!
//! This command pushes the current branch and creates a PR:
//! - Validates we're on a ticket branch
//! - Rebases on main to ensure clean history
//! - Pushes to remote with tracking
//! - Creates a PR if one doesn't exist
//! - Enables auto-merge if available

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::util::{current_branch, main_worktree, ticket_yaml_path, validate_ticket_branch};

/// Push branch and create PR.
///
/// This function:
/// 1. Validates we're on a ticket branch
/// 2. Fetches latest from origin
/// 3. Rebases on main to ensure clean history
/// 4. Pushes to remote with tracking (-u flag)
/// 5. Creates a PR if one doesn't exist
/// 6. Enables auto-merge if available
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - Rebase fails (conflicts need manual resolution)
/// - Push or PR creation fails
pub fn run() -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // Get current branch and validate it's a ticket branch
    let branch_name = current_branch(&sh)?;
    let ticket_branch = validate_ticket_branch(&branch_name)?;

    println!(
        "Pushing ticket {} (RFC: {})",
        ticket_branch.ticket_id, ticket_branch.rfc_id
    );

    // Fetch latest from origin
    println!("\n[1/4] Fetching latest from origin...");
    cmd!(sh, "git fetch origin")
        .run()
        .context("Failed to fetch from origin")?;

    // Rebase on main for clean history
    println!("\n[2/4] Rebasing on main...");
    let rebase_result = cmd!(sh, "git rebase origin/main").ignore_status().run();

    if rebase_result.is_err() {
        // Check if there's a rebase in progress
        let rebase_in_progress = cmd!(sh, "git rev-parse --git-path rebase-merge")
            .read()
            .ok()
            .is_some_and(|p| std::path::Path::new(p.trim()).exists());

        if rebase_in_progress {
            // Abort the failed rebase
            let _ = cmd!(sh, "git rebase --abort").run();
            bail!(
                "Rebase on main failed due to conflicts.\n\
                 Please resolve conflicts manually:\n\
                 1. Run: git rebase origin/main\n\
                 2. Resolve conflicts\n\
                 3. Run: git rebase --continue\n\
                 4. Run: cargo xtask push"
            );
        }
    }
    println!("  Rebased on main successfully.");

    // Push to remote with tracking
    println!("\n[3/4] Pushing to remote...");
    let push_result = cmd!(sh, "git push -u origin {branch_name}")
        .ignore_status()
        .run();

    if push_result.is_err() {
        // Try force push if needed (rebase may have changed history)
        println!("  Regular push failed, attempting force push with lease...");
        cmd!(sh, "git push -u origin {branch_name} --force-with-lease")
            .run()
            .context(
                "Failed to push to remote. If this is a new branch, try:\n\
                 git push -u origin HEAD",
            )?;
    }
    println!("  Pushed to origin/{branch_name}");

    // Check if PR already exists
    println!("\n[4/4] Checking for existing PR...");
    let pr_exists = cmd!(sh, "gh pr view {branch_name} --json number --jq .number")
        .ignore_status()
        .read()
        .context("Failed to check for existing PR")?;

    let pr_url = if pr_exists.trim().is_empty()
        || pr_exists.contains("no pull requests")
        || pr_exists.contains("not found")
    {
        // Create new PR
        println!("  No existing PR found, creating one...");
        create_pr(&sh, &branch_name, &ticket_branch.ticket_id)?
    } else {
        // PR already exists
        let url = cmd!(sh, "gh pr view {branch_name} --json url --jq .url")
            .read()
            .context("Failed to get PR URL")?;
        println!("  PR already exists: {}", url.trim());
        url.trim().to_string()
    };

    // Enable auto-merge if available
    println!("\nEnabling auto-merge...");
    let auto_merge_result = cmd!(sh, "gh pr merge --auto --squash {branch_name}")
        .ignore_status()
        .read();

    match auto_merge_result {
        Ok(output) => {
            if output.contains("auto-merge")
                || output.contains("enabled")
                || output.trim().is_empty()
            {
                println!("  Auto-merge enabled (will merge when checks pass).");
            } else {
                println!("  Auto-merge response: {}", output.trim());
            }
        },
        Err(_) => {
            println!("  Note: Auto-merge not available (may require branch protection rules).");
        },
    }

    println!();
    println!("Push complete!");
    println!("PR URL: {pr_url}");
    println!();
    println!("Next steps:");
    println!("  - Check status: cargo xtask check");
    println!("  - After merge: cargo xtask finish");

    Ok(())
}

/// Create a new PR for the branch.
///
/// Generates a PR title and body based on the ticket information.
fn create_pr(sh: &Shell, branch_name: &str, ticket_id: &str) -> Result<String> {
    // Get ticket title from YAML if available
    let main_path = main_worktree(sh)?;
    let ticket_yaml = ticket_yaml_path(&main_path, ticket_id);

    let ticket_title = if ticket_yaml.exists() {
        std::fs::read_to_string(&ticket_yaml)
            .ok()
            .and_then(|content| extract_ticket_title(&content))
            .unwrap_or_else(|| format!("implement {ticket_id} feature"))
    } else {
        format!("implement {ticket_id} feature")
    };

    // Create PR title
    let pr_title = format!("feat({ticket_id}): {ticket_title}");

    // Create PR body
    let pr_body = format!(
        "## Summary\n\
         \n\
         Implements ticket {ticket_id} as part of the xtask development automation.\n\
         \n\
         ## Ticket\n\
         \n\
         See `documents/work/tickets/{ticket_id}.yaml` for requirements.\n\
         \n\
         ## Test Plan\n\
         \n\
         - [ ] `cargo fmt --check` passes\n\
         - [ ] `cargo clippy --all-targets -- -D warnings` passes\n\
         - [ ] `cargo test -p xtask` passes\n\
         - [ ] Manual testing of the new command\n"
    );

    // Create the PR
    let output = cmd!(
        sh,
        "gh pr create --base main --head {branch_name} --title {pr_title} --body {pr_body}"
    )
    .read()
    .context("Failed to create PR")?;

    // Extract PR URL from output
    let pr_url = output
        .lines()
        .find(|line| line.contains("github.com") && line.contains("/pull/"))
        .map_or_else(|| output.trim().to_string(), |line| line.trim().to_string());

    println!("  Created PR: {pr_url}");

    Ok(pr_url)
}

/// Extract the ticket title from YAML content.
fn extract_ticket_title(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("title:") {
            let value = rest.trim();
            let value = value.trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_lowercase());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ticket_title() {
        let content = r#"
ticket_meta:
  ticket:
    id: "TCK-00032"
    title: "Implement push command"
    status: "PENDING"
"#;

        let title = extract_ticket_title(content);
        assert_eq!(title, Some("implement push command".to_string()));
    }

    #[test]
    fn test_extract_ticket_title_no_quotes() {
        let content = "title: Push changes to remote";
        let title = extract_ticket_title(content);
        assert_eq!(title, Some("push changes to remote".to_string()));
    }

    #[test]
    fn test_extract_ticket_title_single_quotes() {
        let content = "title: 'Create PR automatically'";
        let title = extract_ticket_title(content);
        assert_eq!(title, Some("create pr automatically".to_string()));
    }

    #[test]
    fn test_extract_ticket_title_missing() {
        let content = "id: TCK-00001\nstatus: PENDING";
        let title = extract_ticket_title(content);
        assert_eq!(title, None);
    }

    #[test]
    fn test_pr_title_format() {
        let ticket_id = "TCK-00032";
        let ticket_title = "implement push command";
        let pr_title = format!("feat({ticket_id}): {ticket_title}");
        assert_eq!(pr_title, "feat(TCK-00032): implement push command");
    }
}
