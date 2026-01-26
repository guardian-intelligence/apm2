# Debiasing / Epistemic Hygiene Reasoning

**Category:** Meta-Level and Reflective Modes

## What it is

A meta-discipline applying specific checks *before* committing to conclusions: base-rate anchoring, alternative-hypothesis generation, premortem analysis, and active disconfirmation search. Not a new inference pattern—a **constraint layer** that intercepts and stress-tests outputs from other reasoning modes.

Debiasing recognizes that human cognition has systematic failure modes (heuristics that misfire, motivated reasoning, anchoring effects). Rather than hoping to "just be rational," debiasing installs explicit checkpoints that catch predictable errors before they propagate.

Key insight: Debiasing is most valuable precisely when you feel most confident. High confidence + no debiasing check = maximum risk of undetected bias.

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Base-rate anchor** | Reference-class frequency before inside-view adjustment | Step 1 |
| **Alternative-hypothesis list** | ≥3 competing explanations with relative plausibility scores | Step 2 |
| **Premortem report** | "Assume we failed—why?" with top 3 causes and addressability | Step 3 |
| **Disconfirmation tests** | Specific observations that would falsify the favored view | Step 4 |
| **Cognitive-load flag** | Assessment of impairment conditions (fatigue, emotion, time pressure) | Step 5 |
| **Bias audit log** | Explicit check of anchoring/availability/confirmation with pass/fail | Step 6 |
| **Residual uncertainty statement** | What remains unknown and why | Step 7 |

## Procedure (decision steps)

1. **Anchor on base rate** — Before analyzing specifics, ask: "What's the reference-class frequency for outcomes like this?" Write it down.
   - *Technique:* Use [reference-class forecasting](18-reference-class-outside-view.md): find similar past situations, compute outcome frequency.
   - *Test:* Can you name the reference class and cite the frequency source?
   - *Warning:* "This situation is unique" is usually false and always dangerous—find the relevant comparison class.
   - *Output:* "Base rate for [reference class]: X%. Source: [data/estimate]."

2. **Generate alternatives** — List ≥3 hypotheses that could explain the same evidence. Assign rough plausibility to each.
   - *Technique:* Include at least one "uncomfortable" alternative you'd prefer not to be true.
   - *Technique:* Ask: "What would a smart skeptic believe?"
   - *Test:* Are your alternatives genuinely distinct, or variations of the same story?
   - *Output:* Numbered list with plausibility percentages summing to 100%.

3. **Run premortem** — Assume the decision failed. Brainstorm top 3 reasons it could fail. Identify which are addressable now.
   - *Technique:* Phrase as past tense: "We're 6 months in the future. This failed. What happened?"
   - *Test:* Did you list at least one cause that's within your control?
   - *Warning:* If all failure causes are external ("market changed," "bad luck"), you're not being honest.
   - *Output:* 3 failure causes with "addressable now: yes/no" tag for each.

4. **Seek disconfirmation** — For your favored conclusion, specify 2–3 observations that would change your mind. Actively look for them.
   - *Technique:* Write down: "I would abandon this conclusion if I saw [X]." Then go look for X.
   - *Test:* Have you actually searched for disconfirming evidence, or just specified what would count?
   - *Warning:* If nothing could change your mind, you're not reasoning—you're rationalizing.
   - *Output:* List of disconfirming observations with "searched: yes/no" and "found: [result]."

5. **Check cognitive load** — If rushed, tired, or emotionally invested, flag the judgment as provisional and schedule re-evaluation.
   - *Technique:* Rate yourself 1-5 on: time pressure, fatigue, emotional stake, topic familiarity.
   - *Test:* Would you make this same decision fresh tomorrow morning?
   - *Output:* Cognitive-load score and "provisional: yes/no" flag.

6. **Audit for anchoring/availability/confirmation** — Explicitly ask three questions:
   - **Anchoring:** "Am I weighting the first number/frame I encountered too heavily?"
   - **Availability:** "Am I weighting recent/vivid/emotional information too heavily?"
   - **Confirmation:** "Am I seeking/weighting information that confirms what I already believe?"
   - *Test:* For each bias, can you identify specific information that might be over-weighted?
   - *Output:* 3-item audit log with pass/fail and rationale per bias.

7. **Document residual uncertainty** — Record what you're still uncertain about and why.
   - *Technique:* Distinguish "uncertainty we could reduce with more work" from "irreducible uncertainty."
   - *Test:* If you're not uncertain about anything, you haven't thought hard enough.
   - *Output:* List of remaining unknowns with "reducible: yes/no" tag.

## Quick checklist (pre-decision gate)

- [ ] Base rate written before inside-view analysis (with source)
- [ ] ≥3 alternative hypotheses listed with plausibility percentages
- [ ] Premortem completed (top 3 failure causes, ≥1 addressable)
- [ ] ≥2 disconfirming observations specified AND actively searched
- [ ] Cognitive-load assessed; provisional flag set if impaired
- [ ] Anchoring / availability / confirmation bias explicitly checked (3-item audit)
- [ ] Residual uncertainty documented

## Micro-example

**Situation:** Team proposes a new caching layer to fix performance.

| Step | Action | Output |
|------|--------|--------|
| 1. Base rate | "What % of caching projects solve the root cause?" Historical data: ~40% | Base rate: 40% (source: internal postmortems) |
| 2. Alternatives | (a) Caching helps: 30%, (b) N+1 query: 40%, (c) GC pauses: 20%, (d) Network latency: 10% | 4 hypotheses, plausibilities assigned |
| 3. Premortem | "Cache deployed, latency unchanged—why?" → Didn't profile (addressable), cache hit rate low (addressable), wrong layer cached (addressable) | 3 causes, all addressable |
| 4. Disconfirmation | "Abandon caching if profile shows cache isn't hot path." Searched: yes. Found: profile not yet done. | Disconfirm test specified; not yet executed |
| 5. Cognitive load | Team is 2 days from deadline; time pressure = 4/5. Flag as provisional. | Provisional: yes |
| 6. Bias audit | Anchoring: caching was first suggestion → pass (considered alternatives). Availability: recent caching success → fail (over-weighted). Confirmation: seeking evidence caching works → fail. | Audit: 1 pass, 2 fail |
| 7. Residual | Unknown: actual bottleneck location. Reducible: yes, via profiling. | Key unknown documented |
| **Decision** | Profile first before committing to caching. Re-evaluate in 2 days. | Deferred pending evidence |

## How it differs

| Mode | Debiasing differs because... |
|------|------------------------------|
| [Meta-reasoning](75-meta-reasoning.md) | Meta-reasoning selects *which* mode to use; debiasing audits *any* mode's output for predictable errors. Meta-reasoning is upstream (before analysis); debiasing is downstream (before commitment). |
| [Calibration](76-calibration-epistemic-humility.md) | Calibration measures accuracy over many judgments (statistical); debiasing applies corrective checks to a single judgment (instance-level). Calibration tells you "your 80% forecasts come true 65% of the time"; debiasing asks "is this specific 80% estimate distorted?" |
| [Red-teaming](79-adversarial-red-team.md) | Red-teaming assumes an external adversary attacking your system; debiasing assumes your own cognition is the adversary. Red-team = "how would an attacker break this?"; Debiasing = "how am I fooling myself?" |
| [Heuristic reasoning](53-heuristic.md) | Heuristics are fast cognitive shortcuts (System 1); debiasing is the slow audit layer (System 2) that catches heuristic misfires. Heuristics are the patient; debiasing is the doctor. |
| [Reflective equilibrium](77-reflective-equilibrium.md) | Reflective equilibrium seeks coherence between principles and judgments over time; debiasing applies specific bias checks to a single decision. Equilibrium is about consistency; debiasing is about error correction. |

**Common confusions:**

1. *Debiasing vs. calibration:* Calibration tracks long-run accuracy; debiasing intervenes on a single decision. You can be well-calibrated on average but still need debiasing on any specific high-stakes call. Calibration data can inform debiasing ("my estimates are usually 20% optimistic"), but they're different activities.

2. *Debiasing vs. red-teaming:* Red-teaming asks "how would an attacker break this?" Debiasing asks "how is my own reasoning broken?" Both are adversarial, but the threat model differs. Red-teaming applies to systems; debiasing applies to judgments.

3. *Debiasing vs. critical thinking:* "Think critically" is vague advice. Debiasing provides specific checkpoints: base rate, alternatives, premortem, disconfirmation. It operationalizes critical thinking into a concrete protocol.

4. *Debiasing vs. skepticism:* Skepticism doubts everything equally; debiasing doubts *predictably biased* things more. Not "question everything" but "question anchors, vivid data, and confirming evidence specifically."

## Best for

- **High-stakes one-shot decisions** — where you can't rely on averaging over many trials
- **Forecasting and estimation** — where base-rate neglect and overconfidence dominate errors
- **Incident postmortems** — where hindsight bias distorts root-cause analysis
- **Investment and resource allocation** — where confirmation bias anchors on early signals
- **Leadership reviews** — where authority gradients suppress disconfirmation
- **Hiring decisions** — where first impressions anchor assessment
- **Strategic planning** — where the planning fallacy inflates optimism
- **Performance evaluations** — where recency bias dominates
- **Any decision where you feel very confident** — high confidence is a risk signal

## Common failure mode

**Ritualized checklists that don't change conclusions.** Going through the motions—writing "base rate: N/A" or "alternatives: none convincing"—without genuine consideration. The process becomes a rubber stamp rather than a stress test.

### Detection signals

- Checklist items are copy-pasted from previous decisions
- Alternative hypotheses are strawmen dismissed in one sentence
- Premortem lists only external/uncontrollable causes ("market crashed," "client changed mind")
- No decision was ever reversed or modified by the checklist
- Debiasing happens after the decision is effectively made
- Same person always plays devil's advocate
- "We considered it and rejected it" with no documentation
- Disconfirming evidence is specified but never actually sought
- Time allocated for debiasing is consistently skipped when under pressure

### Mitigations

1. **Require at least one judgment change per quarter** — Track whether debiasing ever shifted a decision. If never, the process is theatrical. Publish the rate: "Debiasing changed 3 of 12 major decisions this quarter."
   - *Test:* When did debiasing last change your mind?

2. **Rotate devil's advocate** — Assign someone to genuinely argue for the second-best alternative; rotate the role so it's not always the same skeptic (who becomes dismissible).
   - *Test:* Is the advocate empowered to actually delay or block decisions?

3. **Blind elicitation** — Collect individual base-rate estimates before group discussion to prevent anchoring on the first speaker (usually the most senior).
   - *Test:* Are estimates collected before the leader speaks?

4. **Time-box but enforce** — Debiasing should take 10–15 min, not 2 hours—but those 10 min must happen before commitment, not after. Schedule it explicitly.
   - *Test:* Is debiasing a calendar item, or an afterthought?

5. **Require disconfirmation search evidence** — Don't just specify what would change your mind; require evidence that you actually looked for it. "Searched X database; no disconfirming evidence found."
   - *Test:* Can you show the search log?

6. **Post-decision audits** — Periodically review past decisions: Did the premortem causes materialize? Were alternatives actually less plausible? This calibrates the debiasing process itself.
   - *Test:* Do you track outcomes against premortems?

7. **Raise the cost of skipping** — If debiasing is optional under time pressure, it will always be skipped. Make it mandatory for decisions above a stake threshold.
   - *Test:* Has anyone ever been blocked from a decision for skipping debiasing?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Checkbox compliance** | "Base rate: N/A" without explanation | Require source citation or explicit "no data available" with workaround |
| **Strawman alternatives** | "Alternative: we do nothing (obviously bad)" | Require at least one alternative the advocate would genuinely defend |
| **Debiasing after commitment** | "We decided, but let's do the checklist for documentation" | Time-box debiasing BEFORE decision meeting |
| **Permanent skeptic** | Same person always plays devil's advocate, becomes tuned out | Rotate role; empower advocate to escalate |
| **Unfalsifiable confidence** | "Nothing would change my mind" | Flag as red flag; require stakeholder review |
| **Debiasing theater** | Elaborate process that never changes anything | Track and publish reversal rate; set minimum threshold |

## Bias Quick Reference

| Bias | What it does | Debiasing check |
|------|--------------|-----------------|
| **Anchoring** | Over-weights first information encountered | "What was my first number/frame? Am I adjusting from it insufficiently?" |
| **Availability** | Over-weights recent, vivid, emotional information | "Is this top-of-mind because it's important or because it's memorable?" |
| **Confirmation** | Seeks/weights evidence that confirms prior beliefs | "Have I searched for disconfirming evidence as hard as confirming?" |
| **Overconfidence** | Estimates are too narrow; calibration is poor | "What's the base rate? Would I bet at these odds?" |
| **Planning fallacy** | Underestimates time/cost; ignores outside view | "How long did similar projects actually take?" |
| **Hindsight bias** | Outcome seems "obvious" after the fact | "What did I actually believe before I knew the outcome?" |
| **Sunk cost** | Over-weights past investments in current decisions | "If I started fresh today, would I make this choice?" |
| **Authority bias** | Over-weights senior/expert opinion | "If a junior person said this, would I evaluate it differently?" |
| **Groupthink** | Suppresses dissent to maintain group harmony | "Has anyone explicitly disagreed? Why not?" |
| **Recency bias** | Over-weights recent events in long-run assessment | "Am I weighting the last 3 months over the last 3 years?" |

## Related modes

- [Heuristic reasoning](53-heuristic.md) — the System 1 shortcuts debiasing corrects
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — long-run accuracy tracking that validates debiasing effectiveness
- [Adversarial / red-team reasoning](79-adversarial-red-team.md) — structured external criticism (vs. debiasing's internal audit)
- [Meta-reasoning](75-meta-reasoning.md) — choosing reasoning modes (debiasing audits their outputs)
- [Reference-class forecasting](18-reference-class-outside-view.md) — base-rate anchoring technique used in step 1
- [Reflective equilibrium](77-reflective-equilibrium.md) — consistency between principles and judgments over time
- [Abductive reasoning](13-abductive.md) — hypothesis generation that debiasing audits for story bias
- [Decision-theoretic reasoning](45-decision-theoretic.md) — utility/probability analysis that debiasing audits for overconfidence
