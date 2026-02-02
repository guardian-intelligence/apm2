title: Dispatch Implementer and Monitor Until Merge

decision_tree:
  entrypoint: DISPATCH
  nodes[1]:
    - id: DISPATCH
      purpose: "Activate implementer, supervise progress, enforce SLA, loop until merge."
      steps[12]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID>, <BRANCH_NAME>, <IMPLEMENTER_LOG_FILE>, <IMPLEMENTER_PID>."
        - id: ESTABLISH_IMPLEMENTER_CONTRACT
          action: "Spawn background implementer. Execute `/ticket <TICKET_ID>`."
        - id: REQUIRE_DEDICATED_LOG
          action: "Use `start-claude-implementer-with-log`. Record PID, log path."
        - id: VERIFY_SKILL_INVOCATION
          action: "Check log for `/ticket` call."
        - id: CHECK_CADENCE
          action: "Follow `references/subagent-supervision.md` (60s cadence; 5m stall; 15m limit)."
        - id: PR_STATUS_CHECK
          action: command
          run: "gh pr view <BRANCH_NAME> --json state,reviewDecision,statusCheckRollup,headRefOid,url,comments"
          capture_as: pr_status_json
        - id: AI_REVIEW_STATUS_CHECK
          action: command
          run: "gh api repos/:owner/:repo/commits/<headRefOid>/status --jq '.statuses[] | select(.context | startswith(\"ai-review/\")) | \"\(.context): \(.state)\"''"
          capture_as: ai_review_statuses
        - id: MONITOR_REVIEWER_FEEDBACK
          action: "Check `pr_status_json` for comments. Verify implementer log action."
        - id: VERIFY_REVIEWER_ALIGNMENT
          action: "Check `reviewer-state-show`. If `head_sha` mismatch or inactive, trigger reviews."
        - id: REVIEW_SLA_ENFORCEMENT
          action: "If reviews pending (per `ai_review_statuses`), enforce 15m SLA via reviewer PIDs, logs."
        - id: MERGE_WAIT
          action: "If CI/reviews pass, poll for merge."
        - id: CLEANUP_AFTER_MERGE
          action: "Run `references/post-merge-cleanup.md`, return to loop."
        - id: LOOP
          action: "Repeat check and supervision every 60s until stop."
      decisions[5]:
        - id: MERGED
          if: "pr_status_json indicates MERGED"
          then:
            next_reference: references/post-merge-cleanup.md
        - id: NO_PR
          if: "gh pr view indicates no PR"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: CI_FAILED
          if: "pr_status_json indicates FAILURE"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: CHANGES_REQUESTED
          if: "pr_status_json indicates reviewDecision is CHANGES_REQUESTED"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: REVIEWS_PENDING_OR_STUCK
          if: "ai_review_statuses indicate pending OR reviewer unhealthy OR SLA risk"
          then:
            next_reference: references/review-sla.md
