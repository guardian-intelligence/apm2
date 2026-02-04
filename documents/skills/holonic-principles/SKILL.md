---
name: holonic-principles
description: Reference collection of 99 "Alien Engineering" principles for APM2, covering truth substrate, bounded authority, overload stability, and determinism. Use when designing system invariants, evaluating architectural tradeoffs, or ensuring fail-closed security.
user-invocable: true
argument-hint: "[<principle-number> | <keyword> | empty]"
---

# Holonic Principles

A practical taxonomy of 99 "Alien Engineering" principles stored as CAC assets. These principles guide the design and operation of APM2, from Phase-1 recursive improvement to Phase-5 planetary impact.

## Asset References

- **Principle assets**: `assets/{NN}-{name}.json` (e.g., `assets/01-landauer-s-principle.json`)
- **Selector asset**: `assets/selector.json` - contains indices and metadata for principle selection
- **Stable IDs**: `dcp://apm2.agents/holon/principle/{name}@1`

## Invocation

```
/holonic-principles                     # Browse principle selector
/holonic-principles 1                   # Look up principle #1 (Landauer)
/holonic-principles authority           # Search by keyword
```

## Argument Handling

Parse `$ARGUMENTS`:

- **Empty or omitted** → Load `assets/selector.json` and display quick reference table
- **Number (1-99)** → Read and return the corresponding principle asset
- **Keyword** → Search principle names/titles and return matching entries

## Primary Categories

- **Truth Substrate**: [45, 46, 47, 49, 92, 95]
- **Bounded Authority**: [38, 39, 89, 90, 91, 94]
- **Queueing & Overload Stability**: [9, 25, 26, 27, 28, 29, 53, 54, 55, 56, 57]
- **Determinism & Replay**: [31, 58, 68, 69, 70, 71]

## Quick Reference Table

| # | Principle | Asset |
|---|-----------|-------|
| 1 | Landauer’s principle | `01-landauer-s-principle.json` |
| 2 | Roofline model | `02-roofline-model.json` |
| 3 | Arithmetic intensity predicts compute‑bound vs bandwidth‑bound regimes | `03-arithmetic-intensity-predicts-compute-bound-vs-bandwidth-bound-regimes.json` |
| 4 | GEMM tiling/blocking | `04-gemm-tiling-blocking.json` |
| 5 | Communication‑avoiding algorithms | `05-communication-avoiding-algorithms.json` |
| 6 | Amdahl + Gustafson | `06-amdahl-gustafson.json` |
| 7 | Work–span model | `07-work-span-model.json` |
| 8 | Batching | `08-batching.json` |
| 9 | Tail latency is usually queueing, not kernel speed | `09-tail-latency-is-usually-queueing-not-kernel-speed.json` |
| 10 | Stochastic rounding + mixed precision | `10-stochastic-rounding-mixed-precision.json` |
| 11 | Quantization-aware training/inference | `11-quantization-aware-training-inference.json` |
| 12 | Structured sparsity is only real if hardware exploits it | `12-structured-sparsity-is-only-real-if-hardware-exploits-it.json` |
| 13 | Kernel fusion | `13-kernel-fusion.json` |
| 14 | IO-aware attention | `14-io-aware-attention.json` |
| 15 | KV-cache is a physical resource; budget it like OS pages | `15-kv-cache-is-a-physical-resource-budget-it-like-os-pages.json` |
| 16 | Speculative decoding | `16-speculative-decoding.json` |
| 17 | Continuous batching | `17-continuous-batching.json` |
| 18 | Parallelism modes are topology optimization, not a toggle | `18-parallelism-modes-are-topology-optimization-not-a-toggle.json` |
| 19 | Collectives are topology-sensitive; placement must match fabric | `19-collectives-are-topology-sensitive-placement-must-match-fabric.json` |
| 20 | NUMA locality | `20-numa-locality.json` |
| 21 | Memory tiers (HBM/DRAM/SSD/object store) | `21-memory-tiers-hbm-dram-ssd-object-store.json` |
| 22 | PCIe host↔device transfers are expensive | `22-pcie-host-device-transfers-are-expensive.json` |
| 23 | RDMA/kernel-bypass IO | `23-rdma-kernel-bypass-io.json` |
| 24 | Network topology shapes bisection bandwidth; partition to minimize chatter | `24-network-topology-shapes-bisection-bandwidth-partition-to-minimize-chatter.json` |
| 25 | Congestion control + AQM decide whether the system collapses under load | `25-congestion-control-aqm-decide-whether-the-system-collapses-under-load.json` |
| 26 | Pacing + jitter control + deadline scheduling separate p50 from p99 | `26-pacing-jitter-control-deadline-scheduling-separate-p50-from-p99.json` |
| 27 | Little’s law | `27-little-s-law.json` |
| 28 | Model predictive control (MPC) | `28-model-predictive-control-mpc.json` |
| 29 | Feedback loops oscillate under delayed/noisy observation | `29-feedback-loops-oscillate-under-delayed-noisy-observation.json` |
| 30 | Time synchronization limits tracing and ordering; tolerate skew | `30-time-synchronization-limits-tracing-and-ordering-tolerate-skew.json` |
| 31 | Record/replay debugging | `31-record-replay-debugging.json` |
| 32 | OS scheduler + cgroups are the last line of single-host isolation | `32-os-scheduler-cgroups-are-the-last-line-of-single-host-isolation.json` |
| 33 | eBPF | `33-ebpf.json` |
| 34 | Containers share a kernel; high-risk executors may need microVMs | `34-containers-share-a-kernel-high-risk-executors-may-need-microvms.json` |
| 35 | Side channels are unavoidable; separate secrets by isolation class and hardware domain | `35-side-channels-are-unavoidable-separate-secrets-by-isolation-class-and-hardware-domain.json` |
| 36 | Secure boot + measured boot | `36-secure-boot-measured-boot.json` |
| 37 | Remote attestation | `37-remote-attestation.json` |
| 38 | Capability-based security | `38-capability-based-security.json` |
| 39 | Zero-trust service identity | `39-zero-trust-service-identity.json` |
| 40 | mTLS + automated rotation | `40-mtls-automated-rotation.json` |
| 41 | Post-quantum migration requires crypto agility and hybrid modes | `41-post-quantum-migration-requires-crypto-agility-and-hybrid-modes.json` |
| 42 | Harvest-now-decrypt-later | `42-harvest-now-decrypt-later.json` |
| 43 | Secrets should be short-lived and scoped; prefer “secretless” JIT credentials | `43-secrets-should-be-short-lived-and-scoped-prefer-secretless-jit-credentials.json` |
| 44 | Supply-chain provenance | `44-supply-chain-provenance.json` |
| 45 | Content-addressed storage | `45-content-addressed-storage.json` |
| 46 | Merkle trees + hash chaining | `46-merkle-trees-hash-chaining.json` |
| 47 | Event sourcing | `47-event-sourcing.json` |
| 48 | Idempotency keys + deduplication | `48-idempotency-keys-deduplication.json` |
| 49 | Consensus keeps one truth for critical control state; minimize what needs consensus | `49-consensus-keeps-one-truth-for-critical-control-state-minimize-what-needs-consensus.json` |
| 50 | Vector clocks + causal consistency | `50-vector-clocks-causal-consistency.json` |
| 51 | CRDTs | `51-crdts.json` |
| 52 | Actor model | `52-actor-model.json` |
| 53 | Backpressure | `53-backpressure.json` |
| 54 | Circuit breakers | `54-circuit-breakers.json` |
| 55 | Bulkheads/compartmentalization | `55-bulkheads-compartmentalization.json` |
| 56 | Graceful degradation | `56-graceful-degradation.json` |
| 57 | Fair scheduling + weighted queuing | `57-fair-scheduling-weighted-queuing.json` |
| 58 | Deterministic builds + hermetic environments | `58-deterministic-builds-hermetic-environments.json` |
| 59 | Declarative reconciliation loops | `59-declarative-reconciliation-loops.json` |
| 60 | Configuration drift is inevitable; detect and remediate continuously | `60-configuration-drift-is-inevitable-detect-and-remediate-continuously.json` |
| 61 | Bare metal provisioning | `61-bare-metal-provisioning.json` |
| 62 | Failure domains define correlated risk; schedule with failure-domain awareness | `62-failure-domains-define-correlated-risk-schedule-with-failure-domain-awareness.json` |
| 63 | SLOs + error budgets | `63-slos-error-budgets.json` |
| 64 | Burn-rate alerting | `64-burn-rate-alerting.json` |
| 65 | Tracing with correlation IDs | `65-tracing-with-correlation-ids.json` |
| 66 | Sampling + aggregation | `66-sampling-aggregation.json` |
| 67 | Chaos engineering | `67-chaos-engineering.json` |
| 68 | TLA+/model checking | `68-tla-model-checking.json` |
| 69 | Type/effect systems | `69-type-effect-systems.json` |
| 70 | Refinement types/contracts | `70-refinement-types-contracts.json` |
| 71 | Lattice theory + monotone frameworks | `71-lattice-theory-monotone-frameworks.json` |
| 72 | Fixed-point semantics | `72-fixed-point-semantics.json` |
| 73 | Category theory | `73-category-theory.json` |
| 74 | Monads/algebraic effects | `74-monads-algebraic-effects.json` |
| 75 | Convex optimization | `75-convex-optimization.json` |
| 76 | Bayesian inference | `76-bayesian-inference.json` |
| 77 | Stochastic processes | `77-stochastic-processes.json` |
| 78 | MDPs | `78-mdps.json` |
| 79 | POMDPs | `79-pomdps.json` |
| 80 | Hierarchical RL | `80-hierarchical-rl.json` |
| 81 | Skill discovery + option libraries | `81-skill-discovery-option-libraries.json` |
| 82 | SAT/SMT | `82-sat-smt.json` |
| 83 | Distributed constraint optimization + auctions | `83-distributed-constraint-optimization-auctions.json` |
| 84 | Game theory | `84-game-theory.json` |
| 85 | Mechanism design | `85-mechanism-design.json` |
| 86 | Causal inference | `86-causal-inference.json` |
| 87 | Robust statistics | `87-robust-statistics.json` |
| 88 | Adversarial ML | `88-adversarial-ml.json` |
| 89 | Prompt injection is confused deputy; robust mitigation is capability separation + deny-by-default | `89-prompt-injection-is-confused-deputy-robust-mitigation-is-capability-separation-deny-by-default.json` |
| 90 | Typed tool schemas + structured outputs | `90-typed-tool-schemas-structured-outputs.json` |
| 91 | Sandboxing with deny-by-default network/filesystem scopes bounds damage | `91-sandboxing-with-deny-by-default-network-filesystem-scopes-bounds-damage.json` |
| 92 | Evidence-carrying actions | `92-evidence-carrying-actions.json` |
| 93 | Policy-as-code with signed bundles | `93-policy-as-code-with-signed-bundles.json` |
| 94 | Risk classes + autonomy levels | `94-risk-classes-autonomy-levels.json` |
| 95 | Work graphs as DAGs | `95-work-graphs-as-dags.json` |
| 96 | Cognitive memory hierarchy maps to caches and stores | `96-cognitive-memory-hierarchy-maps-to-caches-and-stores.json` |
| 97 | RAG is cache coherence | `97-rag-is-cache-coherence.json` |
| 98 | Differential testing + continuous red-teaming | `98-differential-testing-continuous-red-teaming.json` |
| 99 | Sociotechnical incident response | `99-sociotechnical-incident-response.json` |
