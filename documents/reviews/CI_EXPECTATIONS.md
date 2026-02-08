{
  "schema": "apm2.ci_expectations.v1",
  "schema_version": "1.0.0",
  "kind": "review.ci_expectations",
  "meta": {
    "stable_id": "dcp://apm2.agents/reviews/ci_expectations@1",
    "classification": "PUBLIC"
  },
  "payload": {
    "required_branch_gate": {
      "branch": "main",
      "required_check": "CI Success",
      "merge_queue": {
        "enabled": true,
        "require_merge_queue": true,
        "why": "Avoid per-PR base-branch rerun churn by validating merge-group SHAs once in queue order.",
        "workflow_trigger_requirement": {
          "event": "merge_group",
          "types": [
            "checks_requested"
          ],
          "note": "Required checks must report on merge_group commits, not only pull_request commits."
        }
      }
    },
    "execution_model": {
      "github_surface": "single required workflow job `CI Success` on runner labels [self-hosted, linux, x64, fac-ovh]",
      "local_executor": "./scripts/ci/run_bounded_tests.sh --timeout-seconds 1800 --kill-after-seconds 30 --memory-max 64G --pids-max 8192 --cpu-quota 1600% -- ./scripts/ci/run_local_ci_orchestrator.sh",
      "note": "The entire local CI suite runs in one transient user unit/cgroup boundary; GitHub is projection/status surface only."
    },
    "checks": [
      {
        "id": "bounded-ci-suite",
        "name": "Bounded CI Suite",
        "command": "./scripts/ci/run_bounded_tests.sh --timeout-seconds 1800 --kill-after-seconds 30 --memory-max 64G --pids-max 8192 --cpu-quota 1600% -- ./scripts/ci/run_local_ci_orchestrator.sh",
        "validates": "Single-shot fail-closed bounded execution for the complete CI suite"
      },
      {
        "id": "build-all-targets",
        "name": "Build All Targets",
        "command": "CARGO_TARGET_DIR=target/ci/target-build-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT} cargo build --workspace --all-features --all-targets --locked",
        "validates": "A holon change compiles across the entire workspace with per-run target isolation suitable for parallel worktrees"
      }
    ]
  }
}
