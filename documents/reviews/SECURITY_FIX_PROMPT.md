title: Security Fix Prompt
protocol:
  id: SECURITY-FIX
  version: 1.0.0
  type: executable_specification
  constraints[4]:
    - "Fix all security issues found in the current branch."
    - "Edit files directly to apply fixes."
    - "Commit each fix with a descriptive message."
    - "Exit 0 if no issues remain, exit 1 if issues still exist."
  inputs[1]:
    - TICKET_ID (optional)
  outputs[2]:
    - FileEdits
    - GitCommits

variables:
  TICKET_ID: "$TICKET_ID"

decision_tree:
  entrypoint: PHASE_0_BOOTSTRAP
  nodes[6]:
    - id: PHASE_0_BOOTSTRAP
      purpose: "Load security baseline and review context."
      context_files[11]:
        - path: documents/security/SECURITY_POLICY.md
        - path: documents/security/CI_SECURITY_GATES.md
        - path: documents/security/THREAT_MODEL.md
        - path: documents/security/SECRETS_MANAGEMENT.md
        - path: documents/skills/rust-standards/SKILL.md
        - path: documents/skills/glossary/SKILL.md
        - path: documents/skills/modes-of-reasoning/references/79-adversarial-red-team.md
        - path: documents/skills/modes-of-reasoning/references/08-counterexample-guided.md
        - path: documents/skills/modes-of-reasoning/references/49-robust-worst-case.md
        - path: documents/skills/modes-of-reasoning/references/55-game-theoretic-strategic.md
        - path: documents/skills/modes-of-reasoning/references/36-assurance-case.md
      steps[1]:
        - id: READ_BASELINE
          action: "Read baseline documents and record invariants. Adopt the 5 mandatory security reasoning modes."
      next: PHASE_1_IDENTIFY_BRANCH

    - id: PHASE_1_IDENTIFY_BRANCH
      purpose: "Identify the current branch and gather diff context."
      steps[3]:
        - id: GET_BRANCH
          action: command
          run: "git rev-parse --abbrev-ref HEAD"
          capture_as: current_branch
        - id: GET_DIFF
          action: command
          run: "git diff main...HEAD"
          capture_as: branch_diff
        - id: GET_FILES
          action: command
          run: "git diff --name-only main...HEAD"
          capture_as: changed_files
      next: PHASE_2_SECURITY_AUDIT

    - id: PHASE_2_SECURITY_AUDIT
      purpose: "Perform a security audit on the changed files."
      audit_categories[6]:
        - category: "Identity, Cryptography, and Wire Semantics"
          focus: "Signing, verification, hashing, and deterministic representation."
        - category: "Network and IPC Boundaries"
          focus: "Parsing untrusted data, framing, and DoS mitigation."
        - category: "Filesystem and Process Boundaries"
          focus: "Path traversal, temp files, shell injection, and permissions."
        - category: "Ledger and Evidence Integrity"
          focus: "Append-only persistence, crash recovery, and history verification."
        - category: "Memory Safety and Soundness"
          focus: "Unsafe code, async cancellation safety, and resource exhaustion."
        - category: "Gate, Policy, and Supply Chain"
          focus: "Changes to security docs, CI gates, and new dependencies."
      severity_rubric:
        CRITICAL: "authn/authz bypass, crypto weakness, RCE, secret exfiltration, fail-open in SCP."
        HIGH: "DoS in SCP, corruption-stop failure, widened egress without policy."
        MEDIUM: "Missing strict parsing (deny_unknown_fields), missing timeouts/limits."
        LOW: "Non-SCP hygiene, refactors without boundary change."
      steps[1]:
        - id: RUN_AUDIT
          action: "Analyze each changed file for security issues. Document findings with severity and location."
      next: PHASE_3_FIX_ISSUES

    - id: PHASE_3_FIX_ISSUES
      purpose: "Fix all identified security issues by editing files directly."
      steps[4]:
        - id: PRIORITIZE
          action: "Sort issues by severity: CRITICAL > HIGH > MEDIUM > LOW."
        - id: FIX_EACH
          action: for_each_issue
          do:
            - "Edit the file to fix the security issue."
            - "Verify the fix is correct and complete."
            - "Stage the changed file."
        - id: COMMIT_FIXES
          action: "Create a commit for each logical fix group with descriptive message."
          commit_format: "fix(security): <description of fix>"
        - id: VERIFY_FIXES
          action: "Re-audit the fixed code to ensure the issue is resolved."
      next: PHASE_4_FINAL_CHECK

    - id: PHASE_4_FINAL_CHECK
      purpose: "Determine if any issues remain after fixes."
      steps[2]:
        - id: RE_AUDIT
          action: "Run a final security audit on all changed files."
        - id: COUNT_REMAINING
          action: "Count remaining issues by severity."
      next: PHASE_5_EXIT

    - id: PHASE_5_EXIT
      purpose: "Exit with appropriate code based on remaining issues."
      rules:
        exit_0: "No CRITICAL, HIGH, or MEDIUM issues remain."
        exit_1: "Any CRITICAL, HIGH, or MEDIUM issues still exist."
      steps[1]:
        - id: DETERMINE_EXIT
          action: |
            IF remaining_critical > 0 OR remaining_high > 0 OR remaining_medium > 0:
              PRINT "Issues remain that require fixing."
              EXIT 1
            ELSE:
              PRINT "All security issues resolved."
              EXIT 0

reference:
  related_prompts:
    security_review: "documents/reviews/SECURITY_REVIEW_PROMPT.md"
  commands:
    run_fix: "cargo xtask security-review-fix [TCK-XXXXX]"
