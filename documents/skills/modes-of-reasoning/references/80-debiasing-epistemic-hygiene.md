# Debiasing / Epistemic Hygiene Reasoning

**Category:** Meta-Level and Reflective Modes

## What it is

A meta-discipline applying specific checks *before* committing to conclusions: base-rate anchoring, alternative-hypothesis generation, premortem analysis, and active disconfirmation search. Not a new inference pattern—a constraint layer that intercepts and stress-tests outputs from other reasoning modes.

The core insight: human reasoning has *predictable* failure modes (anchoring, availability, confirmation bias, overconfidence). Because they're predictable, they're correctable—but only if you systematically check for them. Debiasing is the quality control layer for cognition.

Key distinction: Debiasing doesn't generate conclusions—it *audits* them. You first reason using another mode (decision theory, abduction, etc.), then run debiasing checks before committing. It's a pre-commit hook for your judgment.

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Base-rate anchor** | Reference-class frequency before inside-view adjustment | Step 1 |
| **Alternative-hypothesis list** | ≥3 competing explanations with relative plausibility | Step 2 |
| **Premortem report** | "Assume we failed—why?" with top 3 causes and addressability | Step 3 |
| **Disconfirmation tests** | Specific observations that would falsify the favored view | Step 4 |
| **Cognitive-load flag** | Assessment of impairment conditions affecting judgment quality | Step 5 |
| **Bias audit log** | List of checked biases (anchoring, availability, confirmation) with pass/fail + rationale | Step 6 |
| **Residual uncertainty statement** | What remains unknown and why, with confidence bounds | Step 7 |

## Procedure (decision steps)

1. **Anchor on base rate** — Before analyzing specifics, ask: "What's the reference-class frequency for outcomes like this?" Write it down *before* looking at inside-view details.
   - *Technique:* Find 5-10 similar past cases. What % succeeded/failed? This is your prior.
   - *Test:* If forced to bet based only on the base rate, what odds would you take?
   - *Output:* "Base rate for [reference class]: X%. Source: [data/judgment]."

2. **Generate alternatives** — List ≥3 hypotheses that could explain the same evidence. Assign rough plausibility to each.
   - *Guard:* Include at least one hypothesis you don't like (the "uncomfortable alternative").
   - *Test:* Could a reasonable person favor any of these alternatives? If not, you've created strawmen.
   - *Output:* Numbered list with plausibility estimates (doesn't need to sum to 100%).

3. **Run premortem** — Assume the decision failed. Brainstorm top 3 reasons it could fail. Identify which are addressable now.
   - *Technique:* "It's one year later. This decision was a disaster. Why?"
   - *Guard:* At least one cause must be *internal* (our error), not just external (bad luck).
   - *Test:* For each cause, can we do something *now* to reduce its probability?
   - *Output:* Top 3 failure causes with addressability assessment.

4. **Seek disconfirmation** — For your favored conclusion, specify 2-3 observations that would change your mind. Then actively look for them.
   - *Key:* Don't just list what *would* disconfirm—go *look* for disconfirming evidence.
   - *Test:* How hard did you actually search for disconfirmation? (5 minutes is not a genuine search)
   - *Output:* Disconfirmation tests with results of active search.

5. **Check cognitive load** — If rushed, tired, or emotionally invested, flag the judgment as provisional and schedule re-evaluation.
   - *Red flags:* Decision at end of long day, personal stakes, time pressure, recent emotional event, strong prior commitment.
   - *Test:* Would you be comfortable defending this decision to a skeptic *tomorrow morning*?
   - *Output:* Load flag (green/yellow/red) with re-evaluation trigger if yellow/red.

6. **Audit for anchoring/availability/confirmation** — Explicitly check the big three:
   - **Anchoring:** Am I weighting the first number/estimate I heard too heavily?
   - **Availability:** Am I weighting recent/vivid examples over base rates?
   - **Confirmation:** Am I seeking/weighting evidence that confirms my prior?
   - *Test:* For each bias, can you point to a specific check you performed?
   - *Output:* 3-item audit log with pass/fail and brief rationale.

7. **Document residual uncertainty** — Record what you're still uncertain about and why. This prevents overconfidence and creates a record for future learning.
   - *Output:* "Key uncertainties: [list]. Confidence in conclusion: [low/medium/high]. Would revise if: [trigger]."

## Quick checklist (pre-decision gate)

- [ ] Base rate written *before* inside-view analysis
- [ ] ≥3 alternative hypotheses listed (including one uncomfortable alternative)
- [ ] Premortem completed with ≥1 internal failure cause
- [ ] ≥2 disconfirming observations specified *and actively searched for*
- [ ] Anchoring / availability / confirmation bias explicitly audited
- [ ] Cognitive-load flag assessed
- [ ] Residual uncertainty documented
- [ ] If high-stakes: second reviewer completed independent debiasing

## Micro-example

**Situation:** Team proposes a new caching layer to fix performance.

| Step | Action | Output |
|------|--------|--------|
| 1. Base rate | "What % of caching projects actually solve the performance problem?" → Internal data: ~40% of cache projects hit root cause | Base rate: 40% |
| 2. Alternatives | (a) Caching helps, (b) N+1 query is real bottleneck, (c) GC pauses dominate, (d) Network latency is culprit | 4 hypotheses; (b) and (c) uncomfortable |
| 3. Premortem | "Cache deployed, latency unchanged—why?" → Didn't profile first; cache hit rate low; cached wrong layer | 3 causes; all addressable |
| 4. Disconfirmation | Profile shows cache-hit rate <50%, or latency unchanged after deployment → abandon caching hypothesis. *Search:* Ran profiler for 30 min | Profiler shows 60% of time in DB queries |
| 5. Load check | Team is frustrated after 3 sprints on performance. Yellow flag—high emotional investment. | Yellow flag; get outside review |
| 6. Bias audit | Anchoring: first suggestion was cache, stuck with it. Availability: recent conference talk on caching. Confirmation: ignored profiler hints toward DB. | All 3 flags raised |
| 7. Decision | Profile first; caching hypothesis demoted. Run DB analysis before next proposal. | Revised approach |

## How it differs

| Mode | Debiasing differs because... |
|------|------------------------------|
| [Meta-reasoning](75-meta-reasoning.md) | Meta-reasoning selects *which* mode to use; debiasing audits *any* mode's output for predictable errors. Meta-reasoning is upstream (mode selection); debiasing is downstream (output validation). |
| [Calibration](76-calibration-epistemic-humility.md) | Calibration measures accuracy over many judgments (long-run tracking); debiasing applies corrective checks to a single judgment (point intervention). You need both: calibration to know if debiasing works, debiasing to improve each judgment. |
| [Red-teaming](79-adversarial-red-team.md) | Red-teaming assumes an *external* adversary attacking your system; debiasing assumes your own cognition is the adversary. Red-team: "How would they break this?" Debiasing: "How am I fooling myself?" |
| [Heuristic reasoning](53-heuristic.md) | Heuristics are the fast-and-frugal shortcuts that produce biased outputs; debiasing is the System 2 audit that catches those errors. Use heuristics for speed, debiasing for stakes. |
| [Reflective equilibrium](77-reflective-equilibrium.md) | Reflective equilibrium seeks coherence among beliefs, principles, and judgments (philosophical method). Debiasing seeks *accuracy* by correcting predictable cognitive errors. RE asks "Are my beliefs consistent?"; debiasing asks "Are my beliefs corrupted by bias?" |
| [Abductive reasoning](13-abductive.md) | Abduction generates hypotheses; debiasing checks whether you've generated *enough* alternatives and whether you've favored one due to bias rather than evidence. Debiasing makes abduction honest. |

**Common confusions:**

1. *Debiasing vs. calibration:* Calibration tracks long-run accuracy ("I'm right 70% when I say 70%"); debiasing intervenes on a single decision. You can be well-calibrated on average but still need debiasing on any specific high-stakes call—calibration doesn't prevent individual errors, only measures them.

2. *Debiasing vs. red-teaming:* Red-teaming asks "how would an attacker break this?" Debiasing asks "how is my own reasoning broken?" Both are adversarial, but the threat model differs. Red-teaming attacks your *system*; debiasing attacks your *cognition*.

3. *Debiasing vs. skepticism:* Debiasing is *targeted* skepticism—checking for specific, known failure modes. General skepticism ("maybe I'm wrong about everything") is unactionable. Debiasing says: "Check anchoring. Check availability. Check confirmation. Then commit."

## Best for

- **High-stakes one-shot decisions** — where you can't rely on averaging over many trials
- **Forecasting and estimation** — where base-rate neglect and overconfidence dominate errors
- **Incident postmortems** — where hindsight bias distorts root-cause analysis
- **Investment / resource allocation** — where confirmation bias anchors on early signals
- **Leadership reviews** — where authority gradients suppress disconfirmation
- **Hiring decisions** — where similarity bias and halo effects corrupt evaluation
- **Strategy formulation** — where planning fallacy and optimism bias inflate projections
- **Medical diagnosis** — where premature closure and anchoring cause errors

## Common failure mode

**Ritualized checklists that don't change conclusions.** Going through the motions—writing "base rate: N/A" or "alternatives: none convincing"—without genuine consideration. The debiasing becomes theater rather than intervention.

### Detection signals

- Checklist items are copy-pasted from previous decisions
- Alternative hypotheses are strawmen dismissed in one sentence
- Premortem lists only external/uncontrollable causes (never "we made a mistake")
- No decision was ever reversed or modified by the checklist (100% pass rate = 0% value)
- Debiasing happens *after* the decision is already made (rationalization, not evaluation)
- Same person always does the checklist (no fresh eyes)
- Checklist completed in under 3 minutes (not enough time for genuine reflection)

### Mitigations

1. **Require at least one judgment change per quarter** — Track whether debiasing ever shifted a decision. If never, the process is theatrical.
   - *Test:* When did debiasing last change a decision?

2. **Rotate devil's advocate** — Assign someone to argue for the second-best alternative; rotate the role so it's not always the same skeptic.
   - *Test:* Who argued the uncomfortable alternative, and did they argue it seriously?

3. **Blind elicitation** — Collect individual base-rate estimates before group discussion to prevent anchoring on the first speaker or the senior voice.
   - *Test:* Were estimates collected independently before discussion?

4. **Time-box but enforce** — Debiasing should take 10-15 min, not 2 hours—but those 10 min must happen *before* commitment, not after.
   - *Test:* Did debiasing happen before the decision was psychologically locked in?

5. **Track debiasing calibration** — Log predictions with confidence levels; compare to outcomes. If debiasing doesn't improve accuracy, iterate on the process.
   - *Test:* Are debiased predictions more accurate than pre-debiased predictions?

6. **Audit the uncomfortable alternative** — For each decision, verify the uncomfortable alternative was genuinely considered: Who proposed it? What evidence was gathered? Why was it rejected?
   - *Test:* Can you explain the uncomfortable alternative's strongest case?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Rubber-stamp checklist** | All boxes checked in 60 seconds, no conclusions changed | Require minimum time + at least one flagged item |
| **Strawman alternatives** | "Alternatives: (a) good option, (b) obviously bad, (c) absurd" | Include uncomfortable-but-plausible alternative |
| **External-only premortem** | "Could fail if: market crashes, competitor moves, acts of God" | Require at least one internal failure cause |
| **Confirmation search disguised as disconfirmation** | "Looked for problems, found none" (didn't look hard) | Log search effort: time spent, sources checked |
| **Senior anchor** | Boss states conclusion; team "discovers" same answer through "independent" analysis | Collect estimates before senior speaks |
| **Post-hoc rationalization** | Debiasing performed after decision is made to justify it | Timestamp debiasing before commitment |

## Related modes

- [Heuristic reasoning](53-heuristic.md) — the System 1 shortcuts debiasing corrects
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — long-run accuracy tracking that validates debiasing effectiveness
- [Adversarial / red-team reasoning](79-adversarial-red-team.md) — structured external criticism (vs. debiasing's internal audit)
- [Meta-reasoning](75-meta-reasoning.md) — choosing reasoning modes (debiasing audits their outputs)
- [Reference-class forecasting](18-reference-class-outside-view.md) — base-rate anchoring technique used in step 1
- [Reflective equilibrium](77-reflective-equilibrium.md) — coherence-seeking (vs. debiasing's accuracy-seeking)
- [Abductive reasoning](13-abductive.md) — hypothesis generation that debiasing quality-checks
- [Decision-theoretic reasoning](45-decision-theoretic.md) — utility calculations that debiasing audits for input biases
