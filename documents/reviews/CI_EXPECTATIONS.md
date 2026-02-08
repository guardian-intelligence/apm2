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
      "local_executor": "./scripts/ci/run_local_ci_orchestrator.sh",
      "note": "GitHub is projection/status surface; gate computation happens locally on the self-hosted machine."
    },
    "checks": [
      {
        "id": "rustfmt",
        "name": "Rustfmt",
        "command": "cargo fmt --all --check",
        "validates": "Code formatting matches rustfmt standards"
      },
      {
        "id": "clippy",
        "name": "Clippy",
        "command": "cargo clippy --all-targets --all-features -- -D warnings",
        "validates": "No lint warnings or errors"
      },
      {
        "id": "test-safety-guard",
        "name": "Test Safety Guard",
        "command": "./scripts/ci/test_safety_guard.sh",
        "validates": "No destructive test patterns (rm -rf, unbounded shell, git clean -fdx) present in test code without allowlist approval"
      },
      {
        "id": "legacy-ipc-guard",
        "name": "Legacy IPC Guard",
        "command": "./scripts/ci/legacy_ipc_guard.sh",
        "validates": "Legacy JSON IPC patterns remain blocked"
      },
      {
        "id": "evidence-refs-lint",
        "name": "Evidence Refs Lint",
        "command": "./scripts/ci/evidence_refs_lint.sh",
        "validates": "Evidence/requirement references are internally consistent"
      },
      {
        "id": "test-refs-lint",
        "name": "Test Refs Lint",
        "command": "./scripts/ci/test_refs_lint.sh",
        "validates": "Evidence source_refs point to existing files"
      },
      {
        "id": "proto-enum-drift",
        "name": "Proto Enum Drift",
        "command": "./scripts/ci/proto_enum_drift.sh",
        "validates": "Proto enum definitions and generated Rust code stay in sync"
      },
      {
        "id": "review-artifact-lint",
        "name": "Review Artifact Lint",
        "command": "./scripts/ci/review_artifact_lint.sh",
        "validates": "Review prompts/artifacts preserve SHA and policy integrity"
      },
      {
        "id": "status-write-command-lint",
        "name": "Status Write Command Lint",
        "command": "./scripts/lint/no_direct_status_write_commands.sh",
        "validates": "Direct status-write drift is blocked (projection contract enforcement)"
      },
      {
        "id": "workspace-integrity-guard",
        "name": "Workspace Integrity Guard",
        "command": "./scripts/ci/workspace_integrity_guard.sh -- ./scripts/ci/run_bounded_tests.sh -- cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci",
        "validates": "Tracked repository state is unchanged after bounded full-workspace test execution"
      },
      {
        "id": "test-vectors",
        "name": "Test Vectors",
        "command": "cargo test --package apm2-core --features test_vectors canonicalization",
        "validates": "Canonicalization vectors remain valid"
      },
      {
        "id": "msrv-check",
        "name": "MSRV Check",
        "command": "cargo +1.85 check --workspace --all-features",
        "validates": "Workspace builds at MSRV"
      },
      {
        "id": "guardrail-fixtures",
        "name": "Guardrail Fixtures",
        "command": "./scripts/ci/test_guardrail_fixtures.sh",
        "validates": "Safety guards correctly block dangerous patterns and detect workspace mutations"
      },
      {
        "id": "doc",
        "name": "Doc",
        "command": "cargo doc --no-deps",
        "validates": "Documentation builds without errors"
      },
      {
        "id": "deny",
        "name": "Deny",
        "command": "cargo deny check",
        "validates": "No banned dependencies or license violations"
      },
      {
        "id": "audit",
        "name": "Audit",
        "command": "cargo audit",
        "validates": "No known security vulnerabilities"
      }
    ]
  }
}
