#![allow(clippy::suboptimal_flops)]

use crate::schema::QualityVector;
use crate::spec::{ControllerSpec, QualityWeights};

#[derive(Debug, Clone)]
pub struct DecisionInputs {
    pub quality_before: QualityVector,
    pub quality_after: QualityVector,
    pub disagreement: f64,
    pub token_cost: u64,
    pub elapsed_seconds: f64,
    pub cli_calls: u64,
    pub line_churn: u64,
}

#[derive(Debug, Clone)]
pub struct DecisionOutcome {
    pub delta_u: f64,
    pub cost: f64,
    pub efficiency: f64,
    pub critical_regression: bool,
    pub admitted: bool,
    pub continue_loop: bool,
    pub stop_reason: String,
    pub notes: Vec<String>,
}

#[must_use]
pub fn weighted_quality(weights: QualityWeights, quality: QualityVector) -> f64 {
    (weights.security * quality.security)
        + (weights.robustness * quality.robustness)
        + (weights.reliability * quality.reliability)
        + (weights.performance * quality.performance)
        + (weights.implementability * quality.implementability)
        + (weights.verifiability * quality.verifiability)
}

#[must_use]
pub fn evaluate_iteration(config: &ControllerSpec, input: &DecisionInputs) -> DecisionOutcome {
    let before = input.quality_before.clamp();
    let after = input.quality_after.clamp();

    let q_before = weighted_quality(config.quality_weights, before);
    let q_after = weighted_quality(config.quality_weights, after);

    let security_drop = (before.security - after.security).max(0.0);
    let robustness_drop = (before.robustness - after.robustness).max(0.0);
    let penalty = config.critical_regression_penalty * (security_drop + robustness_drop);

    let delta_u = (q_after - penalty) - q_before;

    let c = config.cost_coefficients;
    let cost = (c.token * input.token_cost as f64)
        + (c.elapsed_second * input.elapsed_seconds)
        + (c.call * input.cli_calls as f64)
        + (c.line_churn * input.line_churn as f64)
        + (c.disagreement * input.disagreement.max(0.0));

    let efficiency = if cost > 0.0 {
        delta_u / cost
    } else {
        f64::NEG_INFINITY
    };

    let critical_regression = security_drop > 0.0 || robustness_drop > 0.0;
    let mut notes = Vec::new();

    let disagreement_ok = input.disagreement <= config.thresholds.max_disagreement;
    if !disagreement_ok {
        notes.push(format!(
            "council disagreement {:.4} exceeded max {:.4}",
            input.disagreement, config.thresholds.max_disagreement
        ));
    }

    let delta_ok = delta_u >= config.thresholds.min_absolute_delta_u;
    if !delta_ok {
        notes.push(format!(
            "delta_u {:.6} below min {:.6}",
            delta_u, config.thresholds.min_absolute_delta_u
        ));
    }

    let efficiency_ok = efficiency >= config.thresholds.min_efficiency;
    if !efficiency_ok {
        notes.push(format!(
            "efficiency {:.6} below min {:.6}",
            efficiency, config.thresholds.min_efficiency
        ));
    }

    if critical_regression {
        notes.push("critical regression detected in security/robustness".to_string());
    }

    let admitted = !critical_regression && disagreement_ok && delta_ok && efficiency_ok;
    let continue_loop = admitted;

    let stop_reason = if admitted {
        "continue".to_string()
    } else if critical_regression {
        "critical_regression".to_string()
    } else if !disagreement_ok {
        "council_disagreement".to_string()
    } else if !delta_ok {
        "insufficient_delta_u".to_string()
    } else {
        "insufficient_efficiency".to_string()
    };

    DecisionOutcome {
        delta_u,
        cost,
        efficiency,
        critical_regression,
        admitted,
        continue_loop,
        stop_reason,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::{DecisionInputs, evaluate_iteration};
    use crate::schema::QualityVector;
    use crate::spec::{ControllerSpec, CostCoefficients, QualityWeights, Thresholds};

    fn base_controller() -> ControllerSpec {
        ControllerSpec {
            quality_weights: QualityWeights {
                security: 0.3,
                robustness: 0.2,
                reliability: 0.2,
                performance: 0.1,
                implementability: 0.1,
                verifiability: 0.1,
            },
            cost_coefficients: CostCoefficients {
                token: 0.001,
                elapsed_second: 0.01,
                call: 0.1,
                line_churn: 0.02,
                disagreement: 0.2,
            },
            thresholds: Thresholds {
                min_absolute_delta_u: 0.01,
                min_efficiency: 0.01,
                max_disagreement: 0.2,
            },
            critical_regression_penalty: 5.0,
        }
    }

    #[test]
    fn accepts_improving_iteration() {
        let cfg = base_controller();
        let input = DecisionInputs {
            quality_before: QualityVector {
                security: 0.50,
                robustness: 0.50,
                reliability: 0.50,
                performance: 0.50,
                implementability: 0.50,
                verifiability: 0.50,
            },
            quality_after: QualityVector {
                security: 0.62,
                robustness: 0.60,
                reliability: 0.58,
                performance: 0.55,
                implementability: 0.61,
                verifiability: 0.64,
            },
            disagreement: 0.10,
            token_cost: 100,
            elapsed_seconds: 3.0,
            cli_calls: 5,
            line_churn: 15,
        };

        let outcome = evaluate_iteration(&cfg, &input);
        assert!(outcome.admitted);
        assert!(outcome.continue_loop);
        assert_eq!(outcome.stop_reason, "continue");
    }

    #[test]
    fn rejects_security_regression() {
        let cfg = base_controller();
        let input = DecisionInputs {
            quality_before: QualityVector {
                security: 0.70,
                robustness: 0.60,
                reliability: 0.50,
                performance: 0.50,
                implementability: 0.50,
                verifiability: 0.50,
            },
            quality_after: QualityVector {
                security: 0.68,
                robustness: 0.61,
                reliability: 0.60,
                performance: 0.55,
                implementability: 0.65,
                verifiability: 0.66,
            },
            disagreement: 0.05,
            token_cost: 100,
            elapsed_seconds: 2.0,
            cli_calls: 5,
            line_churn: 10,
        };

        let outcome = evaluate_iteration(&cfg, &input);
        assert!(!outcome.admitted);
        assert_eq!(outcome.stop_reason, "critical_regression");
    }
}
