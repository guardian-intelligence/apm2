use std::path::Path;
use std::process::Stdio;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::schema::SandboxPolicySpec;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCommandResult {
    pub command: String,
    pub passed: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub reason: String,
}

pub async fn run_commands(
    policy: &SandboxPolicySpec,
    commands: &[String],
    workdir: &Path,
) -> Result<Vec<SandboxCommandResult>> {
    if !policy.enabled || policy.simulate_command_results {
        return Ok(commands
            .iter()
            .map(|command| SandboxCommandResult {
                command: command.clone(),
                passed: true,
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                reason: if policy.enabled {
                    "simulated success".to_string()
                } else {
                    "sandbox disabled".to_string()
                },
            })
            .collect());
    }

    let mut results = Vec::new();
    for command in commands {
        if !is_prefix_allowed(command, &policy.allowed_command_prefixes) {
            results.push(SandboxCommandResult {
                command: command.clone(),
                passed: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                reason: "command prefix is not allowlisted".to_string(),
            });
            continue;
        }

        let mut child = Command::new("bash");
        child
            .arg("-lc")
            .arg(command)
            .current_dir(workdir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = timeout(
            Duration::from_millis(policy.command_timeout_ms),
            child.output(),
        )
        .await;

        match output {
            Ok(Ok(output)) => {
                let passed = output.status.success();
                results.push(SandboxCommandResult {
                    command: command.clone(),
                    passed,
                    exit_code: output.status.code(),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    reason: if passed {
                        "command succeeded".to_string()
                    } else {
                        format!("command exited with status {}", output.status)
                    },
                });
            },
            Ok(Err(error)) => {
                results.push(SandboxCommandResult {
                    command: command.clone(),
                    passed: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    reason: format!("command spawn failed: {error}"),
                });
            },
            Err(_) => {
                results.push(SandboxCommandResult {
                    command: command.clone(),
                    passed: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    reason: format!("command timed out after {} ms", policy.command_timeout_ms),
                });
            },
        }
    }

    Ok(results)
}

pub fn ensure_paths_allowed(policy: &SandboxPolicySpec, paths: &[String]) -> Result<()> {
    if !policy.enabled {
        return Ok(());
    }

    for path in paths {
        if !is_path_allowed(path, &policy.allowed_paths) {
            return Err(anyhow!("path '{path}' not allowed by sandbox policy"));
        }
    }

    Ok(())
}

fn is_prefix_allowed(command: &str, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return false;
    }

    prefixes
        .iter()
        .any(|prefix| command == prefix || command.starts_with(&format!("{prefix} ")))
}

fn is_path_allowed(path: &str, allowed_paths: &[String]) -> bool {
    if allowed_paths.is_empty() {
        return false;
    }

    allowed_paths
        .iter()
        .any(|allowed| path == allowed || path.starts_with(&format!("{allowed}/")))
}

#[cfg(test)]
mod tests {
    use super::{ensure_paths_allowed, is_prefix_allowed};
    use crate::schema::SandboxPolicySpec;

    #[test]
    fn prefix_allowlist_applies() {
        assert!(is_prefix_allowed(
            "cargo test -p apm2-cli",
            &["cargo test".to_string()]
        ));
        assert!(!is_prefix_allowed("rm -rf /", &["cargo test".to_string()]));
    }

    #[test]
    fn path_guard_rejects_outside_root() {
        let policy = SandboxPolicySpec {
            enabled: true,
            simulate_command_results: true,
            allowed_paths: vec!["crates/apm2-cli/src".to_string()],
            allowed_command_prefixes: vec!["echo".to_string()],
            command_timeout_ms: 100,
        };

        assert!(
            ensure_paths_allowed(&policy, &["crates/apm2-cli/src/main.rs".to_string()]).is_ok()
        );
        assert!(
            ensure_paths_allowed(&policy, &["crates/apm2-core/src/lib.rs".to_string()]).is_err()
        );
    }
}
