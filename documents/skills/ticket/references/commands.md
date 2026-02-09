title: Dev Ticket Command Reference

commands[19]:
  - name: start-ticket-default
    command: "cargo xtask start-ticket"
    purpose: "Setup dev environment for next unblocked ticket. Expect an error for work already in progress."
  - name: start-ticket-rfc
    command: "cargo xtask start-ticket RFC-XXXX"
    purpose: "Setup dev environment for next unblocked ticket in RFC. Expect an error for work already in progress."
  - name: start-ticket-ticket
    command: "cargo xtask start-ticket TCK-XXXXX"
    purpose: "Setup dev environment for a specific ticket."
  - name: start-ticket-print-path
    command: "cargo xtask start-ticket [target] --print-path"
    purpose: "Output only worktree path (use for cd)."
  - name: format
    command: "cargo fmt --all --check"
    purpose: "Verify formatting across all workspace members before committing."
  - name: lint
    command: "cargo clippy --fix --allow-dirty --all-targets --all-features -- -D warnings"
    purpose: "Fix linting issues and enforce quality standards before committing."
  - name: commit
    command: "cargo xtask commit \"<message>\""
    note: "Stage-2 demotion (TCK-00419): projection-only by default. Direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check` and `apm2 fac work status` for ledger-authoritative lifecycle state."
    purpose: "Verify, sync with main, and commit."
  - name: push
    command: "cargo xtask push"
    note: "Stage-2 demotion (TCK-00419): projection-only by default. Direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check` and `apm2 fac work status` for ledger-authoritative lifecycle state."
    purpose: "Push, create/update PR, run AI reviews, enable auto-merge."
  - name: push-force-review
    command: "cargo xtask push --force-review"
    note: "Stage-2 demotion (TCK-00419): projection-only by default. Direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check` and `apm2 fac work status` for ledger-authoritative lifecycle state."
    purpose: "Force re-run reviews after addressing feedback."
  - name: gate-status
    command: "gh api repos/guardian-intelligence/apm2/commits/<HEAD_SHA>/status --jq '.statuses[] | select(.context == \"Guardian Intelligence - Barrier\" or .context == \"Forge Admission Cycle\") | \"\\(.context)=\\(.state): \\(.description)\"'"
    purpose: "Inspect required FAC gate contexts bound to the exact commit SHA."
  - name: fac-retrigger-cli
    command: "apm2 fac review retrigger --repo guardian-intelligence/apm2 --pr <PR_NUMBER> --mode <dispatch_and_gate|gate_only> --type <all|security|quality> --projection-seconds 30"
    purpose: "Projection-native retrigger path: dispatch Forge Admission Cycle workflow from apm2 CLI."
  - name: barrier-rerun
    command: "gh workflow run guardian-intelligence-barrier.yml --repo guardian-intelligence/apm2 -f pr_number=<PR_NUMBER>"
    purpose: "Fallback: re-run fast barrier authorization checks for a PR."
  - name: fac-rerun-all
    command: "gh workflow run forge-admission-cycle.yml --repo guardian-intelligence/apm2 -f pr_number=<PR_NUMBER> -f mode=dispatch_and_gate -f review_type=all -f projection_seconds=30"
    purpose: "Fallback: re-run full FAC dispatch + gate projection for a PR."
  - name: fac-rerun-stream
    command: "gh workflow run forge-admission-cycle.yml --repo guardian-intelligence/apm2 -f pr_number=<PR_NUMBER> -f mode=dispatch_and_gate -f review_type=<security|quality> -f projection_seconds=30"
    purpose: "Fallback: re-run only one FAC review stream (security or quality)."
  - name: fac-gate-only
    command: "gh workflow run forge-admission-cycle.yml --repo guardian-intelligence/apm2 -f pr_number=<PR_NUMBER> -f mode=gate_only -f review_type=all -f projection_seconds=30"
    purpose: "Fallback: re-evaluate and re-project Forge Admission Cycle status without launching new reviewers."
  - name: fetch-latest-feedback
    command: "gh pr view <PR_URL> --json reviews,reviewThreads --jq '{latest_review: (.reviews[-1].body // \"N/A\"), unresolved_threads: [.reviewThreads[]? | select(.isResolved == false) | {path: .path, body: .comments[-1].body}]}'"
    purpose: "Get the most recent review body and all unresolved comment threads."
  - name: finish
    command: "cargo xtask finish"
    purpose: "Cleanup worktree and branch after PR merges."
  - name: security-review-approve
    command: "cargo xtask security-review-exec approve [TCK-XXXXX]"
    note: "Stage-2 demotion (TCK-00419): projection-only by default. Direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check` for authoritative review gate evidence."
    purpose: "Approve PR after security review."
  - name: security-review-deny
    command: "cargo xtask security-review-exec deny [TCK-XXXXX] --reason <reason>"
    note: "Stage-2 demotion (TCK-00419): projection-only by default. Direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check` for authoritative review gate evidence."
    purpose: "Deny PR with a reason after security review."
