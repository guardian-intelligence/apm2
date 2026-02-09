use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfcControlSpec {
    pub kind: String,
    pub version: String,
    pub goal_statement: String,
    pub target_rfc_path: String,
    pub runtime: RuntimeSpec,
    pub council: CouncilSpec,
    pub controller: ControllerSpec,
    pub budget: BudgetSpec,
    pub git: GitSpec,
    pub outputs: OutputSpec,
}

impl RfcControlSpec {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let spec = serde_json::from_slice::<Self>(&bytes)
            .with_context(|| format!("parse {}", path.display()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.goal_statement.trim().is_empty() {
            return Err(anyhow!("goal_statement must not be empty"));
        }
        if self.target_rfc_path.trim().is_empty() {
            return Err(anyhow!("target_rfc_path must not be empty"));
        }
        if self.runtime.model.trim().is_empty() {
            return Err(anyhow!("runtime.model must not be empty"));
        }
        if self.runtime.command.trim().is_empty() {
            return Err(anyhow!("runtime.command must not be empty"));
        }
        if self.runtime.max_iterations == 0 {
            return Err(anyhow!("runtime.max_iterations must be > 0"));
        }

        if self.council.reviewer_ids.len() < 3 {
            return Err(anyhow!(
                "council.reviewer_ids must include at least 3 reviewers"
            ));
        }

        let weights = &self.controller.quality_weights;
        if !weights.all_non_negative() {
            return Err(anyhow!("quality weights must be non-negative"));
        }
        let total_weight = weights.total();
        if total_weight <= 0.0 {
            return Err(anyhow!("quality weights total must be > 0"));
        }

        if self.controller.thresholds.min_absolute_delta_u < 0.0 {
            return Err(anyhow!(
                "controller.thresholds.min_absolute_delta_u must be >= 0"
            ));
        }

        if self.controller.thresholds.max_disagreement < 0.0 {
            return Err(anyhow!(
                "controller.thresholds.max_disagreement must be >= 0"
            ));
        }

        if self.budget.max_tokens == 0 {
            return Err(anyhow!("budget.max_tokens must be > 0"));
        }
        if self.budget.max_cli_calls == 0 {
            return Err(anyhow!("budget.max_cli_calls must be > 0"));
        }
        if self.budget.max_elapsed_seconds <= 0.0 {
            return Err(anyhow!("budget.max_elapsed_seconds must be > 0"));
        }

        if self.outputs.root_dir.trim().is_empty() {
            return Err(anyhow!("outputs.root_dir must not be empty"));
        }

        Ok(())
    }

    #[must_use]
    pub fn target_path(&self) -> PathBuf {
        PathBuf::from(&self.target_rfc_path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSpec {
    #[serde(default = "default_claude_command")]
    pub command: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u64,
    #[serde(default)]
    pub include_alien_protocol: bool,
}

fn default_claude_command() -> String {
    "claude".to_string()
}

fn default_model() -> String {
    "sonnet".to_string()
}

const fn default_max_iterations() -> u64 {
    6
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilSpec {
    pub reviewer_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerSpec {
    pub quality_weights: QualityWeights,
    pub cost_coefficients: CostCoefficients,
    pub thresholds: Thresholds,
    #[serde(default = "default_critical_penalty")]
    pub critical_regression_penalty: f64,
}

const fn default_critical_penalty() -> f64 {
    5.0
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct QualityWeights {
    pub security: f64,
    pub robustness: f64,
    pub reliability: f64,
    pub performance: f64,
    pub implementability: f64,
    pub verifiability: f64,
}

impl QualityWeights {
    #[must_use]
    pub fn total(self) -> f64 {
        self.security
            + self.robustness
            + self.reliability
            + self.performance
            + self.implementability
            + self.verifiability
    }

    #[must_use]
    pub fn all_non_negative(self) -> bool {
        self.security >= 0.0
            && self.robustness >= 0.0
            && self.reliability >= 0.0
            && self.performance >= 0.0
            && self.implementability >= 0.0
            && self.verifiability >= 0.0
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CostCoefficients {
    pub token: f64,
    pub elapsed_second: f64,
    pub call: f64,
    pub line_churn: f64,
    pub disagreement: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Thresholds {
    pub min_absolute_delta_u: f64,
    pub min_efficiency: f64,
    pub max_disagreement: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BudgetSpec {
    pub max_tokens: u64,
    pub max_cli_calls: u64,
    pub max_elapsed_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSpec {
    #[serde(default = "default_branch_prefix")]
    pub branch_prefix: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub allow_dirty: bool,
    #[serde(default = "default_true")]
    pub commit_each_admission: bool,
}

fn default_branch_prefix() -> String {
    "exp/rfc0022-control".to_string()
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSpec {
    pub root_dir: String,
}
