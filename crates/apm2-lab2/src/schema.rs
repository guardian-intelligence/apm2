use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct QualityVector {
    pub security: f64,
    pub robustness: f64,
    pub reliability: f64,
    pub performance: f64,
    pub implementability: f64,
    pub verifiability: f64,
}

impl QualityVector {
    #[must_use]
    pub const fn clamp(self) -> Self {
        Self {
            security: self.security.clamp(0.0, 1.0),
            robustness: self.robustness.clamp(0.0, 1.0),
            reliability: self.reliability.clamp(0.0, 1.0),
            performance: self.performance.clamp(0.0, 1.0),
            implementability: self.implementability.clamp(0.0, 1.0),
            verifiability: self.verifiability.clamp(0.0, 1.0),
        }
    }

    #[must_use]
    pub const fn as_array(self) -> [f64; 6] {
        [
            self.security,
            self.robustness,
            self.reliability,
            self.performance,
            self.implementability,
            self.verifiability,
        ]
    }

    #[must_use]
    pub const fn from_array(values: [f64; 6]) -> Self {
        Self {
            security: values[0],
            robustness: values[1],
            reliability: values[2],
            performance: values[3],
            implementability: values[4],
            verifiability: values[5],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchProposal {
    pub kind: String,
    pub base_revision_hash: String,
    pub summary: String,
    pub rationale: String,
    pub diffs: Vec<String>,
    #[serde(default)]
    pub predicted_delta: Option<QualityVector>,
    #[serde(default)]
    pub risk_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplierOutput {
    pub kind: String,
    pub base_revision_hash: String,
    pub proposal_hash: String,
    pub updated_document: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilScore {
    pub kind: String,
    pub reviewer_id: String,
    pub before: QualityVector,
    pub after: QualityVector,
    pub confidence: f64,
    #[serde(default)]
    pub regressions: Vec<String>,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationDecision {
    pub run_id: String,
    pub seed: u64,
    pub iteration: u64,
    pub admitted: bool,
    pub continue_loop: bool,
    pub stop_reason: String,
    pub critical_regression: bool,
    pub disagreement: f64,
    pub quality_before: QualityVector,
    pub quality_after: QualityVector,
    pub delta_u: f64,
    pub cost: f64,
    pub efficiency: f64,
    pub token_cost: u64,
    pub elapsed_seconds: f64,
    pub cli_calls: u64,
    pub line_churn: u64,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationEvent {
    pub run_id: String,
    pub seed: u64,
    pub iteration: u64,
    pub admitted: bool,
    pub stop_reason: String,
    pub delta_u: f64,
    pub cost: f64,
    pub efficiency: f64,
    pub disagreement: f64,
    pub token_cost: u64,
    pub elapsed_seconds: f64,
    pub cli_calls: u64,
    pub line_churn: u64,
    pub quality_before: QualityVector,
    pub quality_after: QualityVector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub seed: u64,
    pub target_rfc_path: String,
    pub branch_name: Option<String>,
    pub completed: bool,
    pub stop_reason: String,
    pub iterations_executed: u64,
    pub iterations_admitted: u64,
    pub final_quality: QualityVector,
    pub total_delta_u: f64,
    pub total_cost: f64,
    pub total_tokens: u64,
    pub total_cli_calls: u64,
    pub total_elapsed_seconds: f64,
    pub critical_regression_count: u64,
    pub council_disagreement_mean: f64,
    pub final_rfc_hash: String,
    pub summary_path: String,
    pub events_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepSummary {
    pub runs: usize,
    pub seeds: Vec<u64>,
    pub mean_total_delta_u: f64,
    pub mean_total_cost: f64,
    pub mean_efficiency: f64,
    pub median_iterations_admitted: f64,
    pub success_rate: f64,
    pub summaries: Vec<RunSummary>,
}
