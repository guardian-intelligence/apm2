/implementor-default TCK-00556

# Context

You are finishing a fix round on PR #655 for ticket TCK-00556.
- **Branch**: `ticket/RFC-0019/TCK-00556`
- **Worktree**: `/home/ubuntu/Projects/apm2-worktrees/TCK-00556`
- **Ticket YAML**: `documents/work/tickets/TCK-00556.yaml`

The previous agent already applied the code changes to fix review findings. The changes are correct but have 2 clippy warnings that must be fixed before committing.

# Your ONLY task: fix these 2 clippy warnings

## Warning 1: Unnecessary `mut` on `file` variable
**File**: `crates/apm2-core/src/fac/node_identity.rs:294`
**Issue**: `let mut file = open_file_no_follow(path)?;` — the `mut` is no longer needed because `.take()` consumes the file by value.
**Fix**: Change `let mut file` to `let file`.

## Warning 2: Unnecessary closure in `ok_or_else`
**File**: `crates/apm2-core/src/fac/node_identity.rs:261`
**Issue**: `read_identity_value_from_sources(MACHINE_ID_PATHS).ok_or_else(|| { NodeIdentityError::MissingInput { detail: "machine-id" } })` — clippy says this should use `ok_or` since the error value doesn't need lazy evaluation.
**Fix**: Change `.ok_or_else(|| { NodeIdentityError::MissingInput { detail: "machine-id" } })` to `.ok_or(NodeIdentityError::MissingInput { detail: "machine-id" })`.

# After fixing, run mandatory pre-commit steps IN ORDER:

1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — must pass clean
3. `cargo doc --workspace --no-deps`
4. `cargo test -p apm2-core`
5. Verify ALL pass

You MUST pass ALL CI checks.

# Then commit and push:

1. `git add -A`
2. `git commit -m "fix(fac): address quality review findings for PR #655 - Add #[serde(default)] to LaneProfileV1.boundary_id for v1 compat - Enforce read-time size cap via Read::take() in read_bounded_file - Fix source fallback to skip empty/invalid candidates - Add regression tests for all three fixes"`
3. Run `apm2 fac gates`
4. If gates pass: `timeout 180s apm2 fac push --ticket documents/work/tickets/TCK-00556.yaml`

Output DONE when complete.
