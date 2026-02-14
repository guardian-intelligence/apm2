/implementor-default TCK-00556

# Context

You are fixing review findings on PR #655 for ticket TCK-00556.
- **PR**: https://github.com/guardian-intelligence/apm2/pull/655
- **Branch**: `ticket/RFC-0019/TCK-00556`
- **HEAD SHA**: `4f9b3b3fa012565f3147b9f037794b0b80074f26`
- **Worktree**: `/home/ubuntu/Projects/apm2-worktrees/TCK-00556`
- **Ticket YAML**: `documents/work/tickets/TCK-00556.yaml`
- **Security Review**: PASS (no action needed)
- **Quality Review**: FAIL — you must fix the findings below

Your primary instruction source is `@documents/skills/implementor-default/SKILL.md`. Follow its decision tree.

# CRITICAL: Worktree Setup

1. `cd /home/ubuntu/Projects/apm2-worktrees/TCK-00556`
2. `git fetch origin main`
3. `git merge origin/main` — resolve any conflicts to zero before editing
4. Verify clean worktree with `git status`

# Review Findings (ALL from Code Quality review on SHA 4f9b3b3)

## BLOCKER — `LaneProfileV1` schema compatibility break under unchanged `v1` schema id

**Path**: `crates/apm2-core/src/fac/lane.rs:327`, `crates/apm2-core/src/fac/lane.rs:406`

**Impact**: `boundary_id` is now required on `LaneProfileV1`, but the schema tag remains `apm2.fac.lane_profile.v1`. Previously persisted `profile.v1.json` records without `boundary_id` will fail deserialization during load, creating an upgrade-time data compatibility break under the same schema version.

**Required action**: Preserve backward compatibility for `v1` by adding `#[serde(default)]` on the `boundary_id` field and adding validation/defaulting on load. If `boundary_id` is missing from a loaded profile, use a deterministic default value derived from existing fields (e.g., a stable fallback like the node fingerprint or "unknown"). Add a deserialization test that proves an old-format v1 JSON (without `boundary_id`) still loads successfully.

## MAJOR — File-size bound is checked pre-read but not enforced during read

**Path**: `crates/apm2-core/src/fac/node_identity.rs:289`, `crates/apm2-core/src/fac/node_identity.rs:307`

**Impact**: `read_bounded_bytes` validates `metadata.len() <= max_size` and then performs unbounded `read_to_end`. If the file grows after metadata read (or metadata is stale), reads can exceed the intended cap and violate bounded-decoding guarantees.

**Required action**: Replace the unbounded `read_to_end` with `Read::take(max_size as u64 + 1)` and then read. If bytes read exceed `max_size`, return an error. This enforces the cap at the actual read operation, not just at the metadata check. Add a test that verifies oversized reads are rejected.

## MINOR — Source fallback short-circuits on first empty identity file

**Path**: `crates/apm2-core/src/fac/node_identity.rs:246`, `crates/apm2-core/src/fac/node_identity.rs:264`

**Impact**: `trim_identity_value(...)?` inside the source loops causes an early error on empty candidate files, preventing fallback to later configured identity sources (`/proc/sys/kernel/hostname`, `/var/lib/dbus/machine-id`, `HOSTNAME` env for hostname).

**Required action**: Treat empty/invalid candidate content as "try next source" rather than returning an error. Use `match` or `if let Ok(val) = ...` pattern instead of `?` propagation. Only return an error after ALL candidates are exhausted. Add a test showing fallback works when the first source is empty but the second has a valid value.

# Mandatory Pre-Commit Steps (IN ORDER — DO NOT SKIP)

After all code changes, before committing:

1. `cargo fmt --all` — actually format, not just --check
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps` — fix any doc warnings/errors
4. `cargo test -p apm2-core` — run the relevant crate's tests
5. Verify ALL pass before committing

You MUST pass ALL CI checks.

# Push Protocol

1. Commit all changes with a message describing what was fixed
2. Run `apm2 fac gates` (requires clean working tree — everything must be committed)
3. If gates pass: `timeout 180s apm2 fac push --ticket documents/work/tickets/TCK-00556.yaml`
4. If gates fail: fix, re-commit, re-run gates, then push

# Quality Patterns (inject into your work)

- Transactional state mutations (check admission BEFORE mutating state)
- Atomic event emission (per-invocation Vec, no shared buffers)
- Fail-closed semantics (never default to pass)
- Deterministic SQL ordering (rowid tiebreaker)
- Wire production paths (no dead code / unused methods)
- Binding test evidence (no zero-count assertions)
- Every in-memory collection with external input MUST have MAX_* constant
- No `unwrap()` on untrusted input — use `Result` types
- Bounded reads: use `Read::take()`, never unbounded `read_to_end()` on untrusted
- `#[serde(default)]` for backward compat when adding fields to persisted schemas

Output DONE when complete.
