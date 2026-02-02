title: Post-Merge Cleanup

decision_tree:
  entrypoint: CLEANUP
  nodes[1]:
    - id: CLEANUP
      purpose: "Delete branch after merge."
      steps[2]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <BRANCH_NAME>, <TICKET_ID>."
        - id: FINISH
          action: command
          run: "bash -lc 'set -euo pipefail; git checkout main && git pull && git branch -D <BRANCH_NAME>'"
          capture_as: finish_output
      decisions[1]:
        - id: NEXT
          if: "always"
          then:
            next_reference: references/ticket-queue-loop.md
