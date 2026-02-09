use anyhow::{Result, anyhow};

use crate::schema::{CouncilScore, QualityVector};

#[derive(Debug, Clone)]
pub struct CouncilAggregate {
    pub quality_before: QualityVector,
    pub quality_after: QualityVector,
    pub disagreement: f64,
    pub mean_confidence: f64,
}

pub fn aggregate(scores: &[CouncilScore]) -> Result<CouncilAggregate> {
    if scores.len() < 3 {
        return Err(anyhow!("council requires at least 3 scores"));
    }

    let quality_before = aggregate_vector(scores, true);
    let quality_after = aggregate_vector(scores, false);

    let disagreement = mean_pairwise_disagreement(scores);
    let mean_confidence =
        scores.iter().map(|s| s.confidence.max(0.0)).sum::<f64>() / scores.len() as f64;

    Ok(CouncilAggregate {
        quality_before,
        quality_after,
        disagreement,
        mean_confidence,
    })
}

fn aggregate_vector(scores: &[CouncilScore], before: bool) -> QualityVector {
    let dimension = |f: fn(QualityVector) -> f64| {
        let mut weighted = Vec::with_capacity(scores.len());
        for score in scores {
            let q = if before { score.before } else { score.after };
            weighted.push((f(q), score.confidence.max(0.01)));
        }
        weighted_median(&mut weighted)
    };

    QualityVector {
        security: dimension(|q| q.security),
        robustness: dimension(|q| q.robustness),
        reliability: dimension(|q| q.reliability),
        performance: dimension(|q| q.performance),
        implementability: dimension(|q| q.implementability),
        verifiability: dimension(|q| q.verifiability),
    }
    .clamp()
}

fn weighted_median(values: &mut [(f64, f64)]) -> f64 {
    values.sort_by(|a, b| a.0.total_cmp(&b.0));
    let total_weight: f64 = values.iter().map(|(_, w)| *w).sum();
    let midpoint = total_weight / 2.0;

    let mut running = 0.0;
    for (value, weight) in values.iter() {
        running += *weight;
        if running >= midpoint {
            return *value;
        }
    }

    values.last().map_or(0.0, |(v, _)| *v)
}

fn mean_pairwise_disagreement(scores: &[CouncilScore]) -> f64 {
    if scores.len() < 2 {
        return 0.0;
    }

    let mut total = 0.0;
    let mut pairs = 0u64;
    for i in 0..scores.len() {
        for j in (i + 1)..scores.len() {
            total += quality_distance(scores[i].after, scores[j].after);
            pairs = pairs.saturating_add(1);
        }
    }

    if pairs == 0 {
        0.0
    } else {
        total / pairs as f64
    }
}

fn quality_distance(a: QualityVector, b: QualityVector) -> f64 {
    let av = a.as_array();
    let bv = b.as_array();
    av.into_iter()
        .zip(bv)
        .map(|(x, y)| (x - y).abs())
        .sum::<f64>()
        / 6.0
}

#[cfg(test)]
mod tests {
    use super::aggregate;
    use crate::schema::{CouncilScore, QualityVector};

    #[test]
    fn aggregate_returns_clamped_weighted_values() {
        let scores = vec![
            CouncilScore {
                kind: "apm2.rfc.council_score.v1".to_string(),
                reviewer_id: "a".to_string(),
                before: QualityVector {
                    security: 0.5,
                    robustness: 0.5,
                    reliability: 0.5,
                    performance: 0.5,
                    implementability: 0.5,
                    verifiability: 0.5,
                },
                after: QualityVector {
                    security: 0.6,
                    robustness: 0.6,
                    reliability: 0.6,
                    performance: 0.6,
                    implementability: 0.6,
                    verifiability: 0.6,
                },
                confidence: 0.9,
                regressions: vec![],
                rationale: String::new(),
            },
            CouncilScore {
                kind: "apm2.rfc.council_score.v1".to_string(),
                reviewer_id: "b".to_string(),
                before: QualityVector {
                    security: 0.4,
                    robustness: 0.4,
                    reliability: 0.4,
                    performance: 0.4,
                    implementability: 0.4,
                    verifiability: 0.4,
                },
                after: QualityVector {
                    security: 0.7,
                    robustness: 0.7,
                    reliability: 0.7,
                    performance: 0.7,
                    implementability: 0.7,
                    verifiability: 0.7,
                },
                confidence: 0.5,
                regressions: vec![],
                rationale: String::new(),
            },
            CouncilScore {
                kind: "apm2.rfc.council_score.v1".to_string(),
                reviewer_id: "c".to_string(),
                before: QualityVector {
                    security: 0.45,
                    robustness: 0.45,
                    reliability: 0.45,
                    performance: 0.45,
                    implementability: 0.45,
                    verifiability: 0.45,
                },
                after: QualityVector {
                    security: 0.65,
                    robustness: 0.65,
                    reliability: 0.65,
                    performance: 0.65,
                    implementability: 0.65,
                    verifiability: 0.65,
                },
                confidence: 0.7,
                regressions: vec![],
                rationale: String::new(),
            },
        ];

        let agg = aggregate(&scores).expect("aggregate");
        assert!(agg.quality_after.security >= 0.6);
        assert!(agg.disagreement >= 0.0);
        assert!(agg.mean_confidence > 0.0);
    }
}
