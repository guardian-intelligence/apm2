# Debiasing / Epistemic Hygiene Reasoning

**Category:** Meta-Level and Reflective Modes

## What it is

A meta-discipline applying specific checks *before* committing to conclusions: base-rate anchoring, alternative-hypothesis generation, premortem analysis, and active disconfirmation search. Not a new inference pattern—a constraint layer that intercepts and stress-tests outputs from other reasoning modes.

## What it outputs

| Artifact | Description |
|----------|-------------|
| **Bias audit log** | List of checked biases with pass/fail + rationale |
| **Alternative-hypothesis list** | ≥3 competing explanations with relative plausibility |
| **Premortem report** | "Assume we failed—why?" with top 3 causes |
| **Base-rate anchor** | Reference-class frequency before inside-view adjustment |
| **Disconfirmation tests** | Specific observations that would falsify the favored view |

## Procedure (decision steps)

1. **Anchor on base rate** — Before analyzing specifics, ask: "What's the reference-class frequency for outcomes like this?" Write it down.
2. **Generate alternatives** — List ≥3 hypotheses that could explain the same evidence. Assign rough plausibility to each.
3. **Run premortem** — Assume the decision failed. Brainstorm top 3 reasons it could fail. Identify which are addressable now.
4. **Seek disconfirmation** — For your favored conclusion, specify 2–3 observations that would change your mind. Actively look for them.
5. **Check cognitive load** — If rushed, tired, or emotionally invested, flag the judgment as provisional and schedule re-evaluation.
6. **Audit for anchoring/availability/confirmation** — Explicitly ask: "Am I weighting first info too heavily? Recent/vivid info? Info that confirms my prior?"
7. **Document residual uncertainty** — Record what you're still uncertain about and why.

## Quick checklist (pre-decision gate)

- [ ] Base rate written before inside-view analysis
- [ ] ≥3 alternative hypotheses listed
- [ ] Premortem completed (top 3 failure causes)
- [ ] ≥2 disconfirming observations specified
- [ ] Anchoring / availability / confirmation bias explicitly checked
- [ ] Cognitive-load flag set if impaired conditions

## Micro-example

**Situation:** Team proposes a new caching layer to fix performance.

1. **Base rate:** "What % of caching projects actually solve the performance problem?" → Historical data: ~40% hit root cause.
2. **Alternatives:** (a) Caching helps, (b) N+1 query is real bottleneck, (c) GC pauses dominate.
3. **Premortem:** "Cache deployed, latency unchanged—why?" → Didn't profile first; cache hit rate low; wrong layer cached.
4. **Disconfirmation:** Profile shows cache-hit rate <50%, or latency unchanged after deployment → abandon caching hypothesis.
5. **Decision:** Profile first, then re-evaluate.

## How it differs

| Mode | Debiasing differs because... |
|------|------------------------------|
| [Meta-reasoning](75-meta-reasoning.md) | Meta-reasoning selects *which* mode to use; debiasing audits *any* mode's output for predictable errors |
| [Calibration](76-calibration-epistemic-humility.md) | Calibration measures accuracy over many judgments; debiasing applies corrective checks to a single judgment |
| [Red-teaming](79-adversarial-red-team.md) | Red-teaming assumes an adversary attacking your system; debiasing assumes your own cognition is the adversary |
| [Heuristic reasoning](53-heuristic.md) | Heuristics are the shortcuts debiasing corrects—System 1 speed vs. System 2 audit |

**Common confusions:**
- *Debiasing vs. calibration:* Calibration tracks long-run accuracy; debiasing intervenes on a single decision. You can be well-calibrated on average but still need debiasing on any specific high-stakes call.
- *Debiasing vs. red-teaming:* Red-teaming asks "how would an attacker break this?" Debiasing asks "how is my own reasoning broken?" Both are adversarial but the threat model differs.

## Best for

- **High-stakes one-shot decisions** — where you can't rely on averaging over many trials
- **Forecasting & estimation** — where base-rate neglect and overconfidence dominate errors
- **Incident postmortems** — where hindsight bias distorts root-cause analysis
- **Investment / resource allocation** — where confirmation bias anchors on early signals
- **Leadership reviews** — where authority gradients suppress disconfirmation

## Common failure mode

**Ritualized checklists that don't change conclusions.** Going through the motions—writing "base rate: N/A" or "alternatives: none convincing"—without genuine consideration.

### Detection signals
- Checklist items are copy-pasted from previous decisions
- Alternative hypotheses are strawmen dismissed in one sentence
- Premortem lists only external/uncontrollable causes
- No decision was ever reversed or modified by the checklist

### Mitigations
1. **Require at least one judgment change per quarter** — Track whether debiasing ever shifted a decision. If never, the process is theatrical.
2. **Rotate devil's advocate** — Assign someone to argue for the second-best alternative; rotate the role so it's not always the same skeptic.
3. **Blind elicitation** — Collect individual base-rate estimates before group discussion to prevent anchoring on the first speaker.
4. **Time-box but enforce** — Debiasing should take 10–15 min, not 2 hours—but those 10 min must happen before commitment, not after.

## Related modes

- [Heuristic reasoning](53-heuristic.md) — the System 1 shortcuts debiasing corrects
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — long-run accuracy tracking that validates debiasing effectiveness
- [Adversarial reasoning](79-adversarial-red-team.md) — structured external criticism (vs. debiasing's internal audit)
- [Meta-reasoning](75-meta-reasoning.md) — choosing reasoning modes (debiasing audits their outputs)
- [Reference-class forecasting](18-reference-class-outside-view.md) — base-rate anchoring technique used in step 1
