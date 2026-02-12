# Fix PR #628 (TCK-00501): Round 8 Security Review Failures

## Context
You are working in the worktree at `/home/ubuntu/Projects/apm2-TCK-00501` on branch `TCK-00501`.
PR #628 security review FAILED on SHA `82406a8668ba2cfa5e645f755a8aa8c994d1fb19`.
Quality review PASSED on the same SHA.

Your task is to fix ALL findings below. You MUST pass ALL CI checks.

## Security Review Findings (VERBATIM)

### MAJOR-1: Stale `Started` journal entries created for broker-denied requests (journal-saturation DoS)
- Threat: Availability degradation and eventual fail-closed admission outage from incorrect crash-window classification.
- Exploit path: `handle_request_tool` persists `record_started` before broker evaluation (`session_dispatch.rs:8294`), but `record_completed` is only called on `DecisionType::Allow` (`session_dispatch.rs:8947`). Broker deny paths are reachable and return without side effects (`session_dispatch.rs:9740`). Repeated denied requests accumulate `Started` entries until capacity is exhausted.
- Blast radius: Once capacity is hit, `record_started` fails fail-closed (`effect_journal.rs:980`), denying subsequent authoritative requests and creating cross-session service impact.
- Required remediation: Record `Started` only at a true "effect will execute now" boundary (after policy allow), OR add an explicit durable terminal transition for "no-dispatch/denied" paths that removes/neutralizes the entry before return. Add regression tests that repeatedly trigger deny outcomes and assert journal cardinality stays bounded.

### MAJOR-2: Journal cardinality is monotonic with no compaction/pruning (long-run admission outage)
- Threat: Long-run resource exhaustion and permanent fail-closed denial under sustained legitimate traffic.
- Exploit path: Capacity enforcement is hard fail at `MAX_JOURNAL_ENTRIES` (`effect_journal.rs:980`), but completed entries are never pruned (`effect_journal.rs:1019`). Replay also restores all terminal entries into the in-memory index (`effect_journal.rs:939`). At sufficient request volume, all future `record_started` calls fail.
- Blast radius: Affects all endpoints routing through admission+journal in authoritative mode.
- Required remediation: Implement bounded retention/compaction (durable checkpoint + prune terminal `Completed` entries older than policy horizon), or redesign capacity accounting so terminal entries do not consume active admission slots.

## Root Cause Analysis

### MAJOR-1 Root Cause
The `record_started()` call is placed at the pre-dispatch boundary BEFORE the broker evaluates whether to allow/deny. This means:
1. Request arrives -> `record_started()` -> journal entry created as `Started`
2. Broker denies the request -> handler returns early without calling `record_completed()`
3. `Started` entry is never resolved -> permanently occupies journal capacity

**Fix approach**: Move `record_started()` to AFTER the broker allow decision but BEFORE the actual effect execution. This ensures only requests that WILL execute an effect create a journal entry. Alternatively, add `record_completed()` calls on all deny paths with a terminal status (e.g., `EffectOutcome::Denied`).

The preferred approach is to move `record_started()` later in the flow, because:
- It preserves the semantic that "Started" means "effect is about to execute"
- It avoids needing to add terminal transitions on every deny path
- The crash-recovery window only matters for effects that actually begin executing

Look at the three handler paths in `session_dispatch.rs`:
1. `handle_request_tool` (~line 8294): Move `record_started()` from before broker evaluation to after the `DecisionType::Allow` check
2. `handle_emit_event` (~line 11453 area): Same pattern -- move after allow decision
3. `handle_publish_evidence` (~line 11689 area): Same pattern -- move after allow decision

For each path, the `record_started()` call should be placed:
- AFTER: admission decision is Allow AND broker has approved
- BEFORE: the actual effect execution (ledger write, CAS write, broker dispatch)

### MAJOR-2 Root Cause
The `EffectJournalV1` has a `MAX_JOURNAL_ENTRIES` hard cap but never removes entries. Even completed entries (`Completed` status) stay in the in-memory index and count toward capacity. Over time, all slots are consumed.

**Fix approach**: Change capacity accounting to only count in-flight (Started/non-completed) entries. Completed entries should not count toward the capacity limit.

Change the capacity check in `record_started()` to only count non-terminal entries:
```rust
let active_count = self.entries.values().filter(|e| e.outcome.is_none()).count();
if active_count >= MAX_JOURNAL_ENTRIES {
    return Err(...);
}
```

Also add periodic compaction: after recording a completion, prune completed entries that are no longer needed. Keep a bounded number of total entries (e.g., active + MAX_JOURNAL_ENTRIES completed entries for audit). Evict oldest completed entries first.

## MANDATORY Pre-Commit Steps (in order)
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` (fix ALL warnings)
3. `cargo doc --workspace --no-deps` (fix any doc warnings/errors)
4. `cargo test -p apm2-daemon -- --test-threads=1` (run relevant tests)

## MANDATORY Post-Fix Steps
1. `git add -A && git commit -m "fix(TCK-00501): resolve security round 8 -- move record_started after allow, active-only capacity accounting"`
2. Run `apm2 fac gates` -- all gates must PASS
3. Run `timeout 180s apm2 fac push --ticket documents/work/tickets/TCK-00501.yaml`

## Required Tests
- Test that repeated broker-denied requests do NOT accumulate journal entries (or that accumulated entries are terminal and do not block future admissions)
- Test that journal capacity is not exhausted by completed entries alone
- Test that after many completed requests, new requests can still be admitted

You MUST pass ALL CI checks. Do not skip any pre-commit step. Apply ALL fixes.
