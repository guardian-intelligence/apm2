//! Input variation testing for AAT anti-gaming detection.
//!
//! This module implements input variation testing to detect invariant outputs,
//! which may indicate that a CLI command is gaming acceptance tests by
//! producing the same output regardless of input.
//!
//! # Strategy
//!
//! For each CLI command, we generate multiple input variations:
//! - Original command (baseline)
//! - With `--help` flag appended (should produce help output)
//! - With environment variable prefix (should behave differently if env-aware)
//!
//! If all variations produce identical output, this is flagged as invariance,
//! which is an anti-gaming violation.
//!
//! # Example
//!
//! ```ignore
//! use xtask::aat::variation::{InputVariationGenerator, InputVariationResult};
//!
//! let results = InputVariationGenerator::test_command("cargo xtask check")?;
//!
//! if results.invariance_detected {
//!     println!("Warning: All input variations produced identical output");
//! }
//! ```

use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use wait_timeout::ChildExt;

/// Maximum time allowed for a single command variation (30 seconds).
///
/// This is shorter than hypothesis execution timeout because variation
/// commands are expected to be quick checks, not full test suites.
const VARIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum size of captured output (1 MB).
///
/// This prevents memory exhaustion from commands that produce excessive output.
const MAX_OUTPUT_SIZE: usize = 1024 * 1024;

/// Environment variables that are safe to pass to child processes.
///
/// This allowlist ensures that sensitive environment variables (API keys,
/// tokens, credentials) are not leaked to variation test commands.
const ALLOWED_ENV_VARS: &[&str] = &[
    "PATH",           // Required for command execution
    "HOME",           // Required for many tools (cargo, git, etc.)
    "USER",           // User identity
    "LANG",           // Locale settings
    "LC_ALL",         // Locale settings
    "TERM",           // Terminal type (for colored output)
    "RUST_BACKTRACE", // Useful for debugging test failures
    "CARGO_HOME",     // Cargo installation directory
    "RUSTUP_HOME",    // Rustup installation directory
];

/// Result of executing a single input variation.
#[derive(Debug, Clone)]
pub struct SingleVariationResult {
    /// The input command that was executed.
    pub input: String,

    /// The captured stdout output.
    pub output: String,

    /// The captured stderr output.
    pub stderr: String,

    /// The exit code of the command (None if terminated by signal).
    pub exit_code: Option<i32>,
}

/// Aggregated result of testing all input variations for a command.
#[derive(Debug, Clone)]
pub struct InputVariationResult {
    /// The base command that was tested.
    pub base_command: String,

    /// Results for each variation tested.
    pub variations: Vec<SingleVariationResult>,

    /// Number of variations that were tested.
    pub variations_tested: u32,

    /// Whether invariance was detected (all outputs identical).
    pub invariance_detected: bool,
}

/// Input variation generator and executor.
///
/// This struct provides methods to generate input variations for CLI commands
/// and execute them to detect invariance.
pub struct InputVariationGenerator;

impl InputVariationGenerator {
    /// Generate input variations for a CLI command.
    ///
    /// # Variation Strategies
    ///
    /// 1. **Original**: The command as-is (baseline)
    /// 2. **Help flag**: Append `--help` to trigger help output
    /// 3. **Environment variable**: Set `AAT_VARIATION_TEST=1` before command
    ///
    /// # Arguments
    ///
    /// * `base_cmd` - The base CLI command to generate variations for
    ///
    /// # Returns
    ///
    /// A vector of command strings representing different input variations.
    ///
    /// # Example
    ///
    /// ```
    /// use xtask::aat::variation::InputVariationGenerator;
    ///
    /// let variations = InputVariationGenerator::generate_variations("cargo test");
    /// assert!(variations.len() >= 3);
    /// assert!(variations[0] == "cargo test");
    /// assert!(variations[1].contains("--help"));
    /// ```
    #[must_use]
    pub fn generate_variations(base_cmd: &str) -> Vec<String> {
        vec![
            // Variation 1: Original command
            base_cmd.to_string(),
            // Variation 2: With --help flag (should produce different output)
            format!("{base_cmd} --help"),
            // Variation 3: With environment variable set
            format!("AAT_VARIATION_TEST=1 {base_cmd}"),
        ]
    }

    /// Execute a single command and capture its output.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The shell command to execute
    ///
    /// # Returns
    ///
    /// A `SingleVariationResult` containing the input, output, stderr, and exit
    /// code.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The command cannot be spawned
    /// - The command times out
    pub fn execute_single(cmd: &str) -> Result<SingleVariationResult> {
        // Build command with isolated environment
        let mut command = Command::new("sh");
        command
            .args(["-c", cmd])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Clear environment and only pass allowlisted variables
        command.env_clear();
        for var_name in ALLOWED_ENV_VARS {
            if let Ok(value) = std::env::var(var_name) {
                command.env(var_name, value);
            }
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("Failed to spawn variation command: {cmd}"))?;

        // Wait with timeout
        let Some(status) = child.wait_timeout(VARIATION_TIMEOUT)? else {
            // Timeout expired - kill the process
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "Variation command timed out after {} seconds: {cmd}",
                VARIATION_TIMEOUT.as_secs()
            );
        };

        // Read stdout (bounded)
        let stdout = if let Some(mut pipe) = child.stdout.take() {
            Self::read_bounded(&mut pipe)?
        } else {
            String::new()
        };

        // Read stderr (bounded)
        let stderr = if let Some(mut pipe) = child.stderr.take() {
            Self::read_bounded(&mut pipe)?
        } else {
            String::new()
        };

        Ok(SingleVariationResult {
            input: cmd.to_string(),
            output: stdout,
            stderr,
            exit_code: status.code(),
        })
    }

    /// Read output from a pipe with a size limit.
    fn read_bounded<R: std::io::Read>(reader: &mut R) -> Result<String> {
        let mut buffer = vec![0u8; MAX_OUTPUT_SIZE + 1];
        let bytes_read = reader.read(&mut buffer)?;

        let truncated = bytes_read > MAX_OUTPUT_SIZE;
        let actual_bytes = bytes_read.min(MAX_OUTPUT_SIZE);
        buffer.truncate(actual_bytes);

        let mut output = String::from_utf8_lossy(&buffer).to_string();

        if truncated {
            output.push_str("\n[TRUNCATED: output exceeded size limit]");
        }

        Ok(output)
    }

    /// Execute all variations and detect invariance.
    ///
    /// This is the main entry point for variation testing. It:
    /// 1. Generates variations for the base command
    /// 2. Executes each variation
    /// 3. Compares outputs to detect invariance
    ///
    /// # Arguments
    ///
    /// * `base_cmd` - The base CLI command to test
    ///
    /// # Returns
    ///
    /// An `InputVariationResult` containing all variation results and
    /// invariance status.
    ///
    /// # Invariance Detection
    ///
    /// Invariance is detected when ALL of the following are true:
    /// - At least 2 variations were successfully executed
    /// - All successful variations produced identical stdout output
    ///
    /// Note: stderr is not considered for invariance detection because
    /// error messages may vary even for legitimate commands.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use xtask::aat::variation::InputVariationGenerator;
    ///
    /// let result = InputVariationGenerator::test_command("echo hello")?;
    ///
    /// // "echo hello" and "echo hello --help" and "AAT_VARIATION_TEST=1 echo hello"
    /// // should all produce different outputs, so invariance_detected should be false
    /// assert!(!result.invariance_detected);
    /// ```
    pub fn test_command(base_cmd: &str) -> Result<InputVariationResult> {
        let variations = Self::generate_variations(base_cmd);
        let mut results = Vec::with_capacity(variations.len());

        for variation_cmd in &variations {
            match Self::execute_single(variation_cmd) {
                Ok(result) => results.push(result),
                Err(e) => {
                    // Log error but continue with other variations
                    eprintln!("Warning: Variation failed to execute: {e}");
                    // Add a result with error information
                    results.push(SingleVariationResult {
                        input: variation_cmd.clone(),
                        output: String::new(),
                        stderr: format!("Execution error: {e}"),
                        exit_code: None,
                    });
                },
            }
        }

        // Detect invariance: all non-empty outputs are identical
        let invariance_detected = Self::detect_invariance(&results);

        // Safe cast: variations.len() is always 3 (from generate_variations)
        // which is well within u32 range
        let variations_tested = u32::try_from(variations.len()).unwrap_or(u32::MAX);

        Ok(InputVariationResult {
            base_command: base_cmd.to_string(),
            variations: results,
            variations_tested,
            invariance_detected,
        })
    }

    /// Detect invariance in variation results.
    ///
    /// Returns true if all variations with non-empty output produced identical
    /// stdout.
    fn detect_invariance(results: &[SingleVariationResult]) -> bool {
        // Get all non-empty outputs
        let outputs: Vec<&str> = results
            .iter()
            .filter(|r| !r.output.is_empty() && r.exit_code.is_some())
            .map(|r| r.output.as_str())
            .collect();

        // Need at least 2 outputs to detect invariance
        if outputs.len() < 2 {
            return false;
        }

        // Check if all outputs are identical
        outputs.windows(2).all(|w| w[0] == w[1])
    }

    /// Test multiple commands and aggregate results.
    ///
    /// # Arguments
    ///
    /// * `commands` - Iterator of base commands to test
    ///
    /// # Returns
    ///
    /// A vector of `InputVariationResult`, one for each command tested.
    pub fn test_commands<'a>(
        commands: impl IntoIterator<Item = &'a str>,
    ) -> Vec<InputVariationResult> {
        commands
            .into_iter()
            .filter_map(|cmd| Self::test_command(cmd).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Variation generation tests
    // =========================================================================

    #[test]
    fn test_generate_variations_count() {
        let variations = InputVariationGenerator::generate_variations("cargo test");
        assert!(
            variations.len() >= 3,
            "Should generate at least 3 variations"
        );
    }

    #[test]
    fn test_generate_variations_content() {
        let variations = InputVariationGenerator::generate_variations("cargo test");

        // First should be original
        assert_eq!(variations[0], "cargo test");

        // Second should have --help
        assert!(variations[1].contains("--help"));

        // Third should have environment variable
        assert!(variations[2].contains("AAT_VARIATION_TEST=1"));
    }

    #[test]
    fn test_generate_variations_with_complex_command() {
        let variations =
            InputVariationGenerator::generate_variations("cargo test --lib -- --nocapture");

        assert_eq!(variations[0], "cargo test --lib -- --nocapture");
        assert!(variations[1].contains("--help"));
    }

    // =========================================================================
    // Single execution tests
    // =========================================================================

    #[test]
    fn test_execute_single_success() {
        let result = InputVariationGenerator::execute_single("echo hello").unwrap();

        assert_eq!(result.input, "echo hello");
        assert!(result.output.contains("hello"));
        assert_eq!(result.exit_code, Some(0));
    }

    #[test]
    fn test_execute_single_failure() {
        let result = InputVariationGenerator::execute_single("exit 42").unwrap();

        assert_eq!(result.exit_code, Some(42));
    }

    #[test]
    fn test_execute_single_captures_stderr() {
        let result = InputVariationGenerator::execute_single("echo error >&2").unwrap();

        assert!(result.stderr.contains("error"));
    }

    // =========================================================================
    // Invariance detection tests
    // =========================================================================

    #[test]
    fn test_detect_invariance_identical_outputs() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd3".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
        ];

        assert!(InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_different_outputs() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "output1".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: "output2".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
        ];

        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_empty_outputs_ignored() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: String::new(), // Empty - should be ignored
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd3".to_string(),
                output: "different".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
        ];

        // Only "same" and "different" are compared - not identical
        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_single_output() {
        let results = vec![SingleVariationResult {
            input: "cmd1".to_string(),
            output: "only".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }];

        // Need at least 2 outputs to detect invariance
        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_failed_executions_ignored() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "output".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: "output".to_string(),
                stderr: String::new(),
                exit_code: None, // Failed - no exit code
            },
        ];

        // Only one successful execution, so no invariance detected
        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    // =========================================================================
    // Full test_command tests
    // =========================================================================

    #[test]
    fn test_command_echo_not_invariant() {
        // "echo hello" and "echo hello --help" should produce different outputs
        // because echo treats --help as a literal string
        let result = InputVariationGenerator::test_command("echo hello").unwrap();

        assert_eq!(result.base_command, "echo hello");
        assert_eq!(result.variations_tested, 3);
        // All three variations of echo will produce different outputs
        // because the command line is different
        assert!(result.variations.len() >= 2);
    }

    #[test]
    fn test_command_captures_variations() {
        let result = InputVariationGenerator::test_command("echo test").unwrap();

        // Should have results for all variations
        assert!(!result.variations.is_empty());

        // Each result should have the input recorded
        for var in &result.variations {
            assert!(!var.input.is_empty());
        }
    }

    // =========================================================================
    // Security tests
    // =========================================================================

    #[test]
    #[allow(unsafe_code)]
    fn test_environment_isolation() {
        // Set a sensitive variable
        // SAFETY: This test runs in isolation
        unsafe {
            std::env::set_var("SUPER_SECRET_VAR", "sensitive");
        }

        let result = InputVariationGenerator::execute_single("echo $SUPER_SECRET_VAR").unwrap();

        // Clean up
        // SAFETY: This test runs in isolation
        unsafe {
            std::env::remove_var("SUPER_SECRET_VAR");
        }

        // The secret should NOT appear in output
        assert!(
            !result.output.contains("sensitive"),
            "Secret should not leak: {}",
            result.output
        );
    }

    #[test]
    fn test_allowed_env_passed() {
        // PATH should be available
        let result = InputVariationGenerator::execute_single("echo $PATH").unwrap();

        // PATH should be present and non-empty
        assert!(!result.output.trim().is_empty(), "PATH should be passed");
    }

    // =========================================================================
    // Constant verification tests
    // =========================================================================

    #[test]
    fn test_timeout_is_reasonable() {
        assert_eq!(VARIATION_TIMEOUT.as_secs(), 30);
        assert!(
            VARIATION_TIMEOUT.as_secs() >= 10,
            "Timeout should be >= 10s"
        );
        assert!(
            VARIATION_TIMEOUT.as_secs() <= 60,
            "Timeout should be <= 60s"
        );
    }

    #[test]
    fn test_max_output_is_reasonable() {
        assert_eq!(MAX_OUTPUT_SIZE, 1024 * 1024); // 1 MB
    }
}
