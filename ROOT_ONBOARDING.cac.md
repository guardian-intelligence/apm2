{
  "schema": "apm2.repo_root_markdown_onboarding.v1",
  "schema_version": "1.0.0",
  "repo": {
    "name": "apm2-rfc-consensus",
    "root": ".",
    "git": {
      "head_commit": { "algo": "sha1", "object_kind": "commit", "object_id": "d992b2323f8fe2884226dd8716f286e6ffbf5e4d" },
      "head_tree": { "algo": "sha1", "object_kind": "tree", "object_id": "28dac4f95e6527b1987fbde38d6336b4b7f27474" },
      "dirty_worktree_expected": true
    }
  },
  "onboarding": {
    "goals": ["token_efficiency", "auditability"],
    "read_first": ["AGENTS.md", "README.md", "SECURITY.md"],
    "precedence": [
      "AGENTS.md",
      "documents/skills/**/SKILL.md",
      "crates/**/AGENTS.md",
      "README.md",
      "other_docs"
    ],
    "ticket_agent_exclusions": [
      {
        "path": "CONTRIBUTING.md",
        "why": "Human-oriented workflow notes; for agents use documents/skills/dev-eng-ticket/SKILL.md + AGENTS.md."
      },
      {
        "path": "CHANGELOG.md",
        "why": "Non-authoritative feature/status signal; use README.md + documents/rfcs/ instead."
      },
      {
        "path": "research.md",
        "why": "Long-form research notes; not required for most implementation tickets."
      }
    ],
    "worktree_rules": [
      "Assume the repo may be dirty.",
      "Do not revert/clean unrelated changes unless explicitly requested.",
      "If unrelated changes block the task (e.g., merge conflict in same file), ask for guidance."
    ]
  },
  "root_markdown": [
    {
      "path": "AGENTS.md",
      "bytes": 14281,
      "sha256": "sha256:65b382e2323a73b6ebd69f74959f469af2a12c4016592681e89f2778000aa7fd",
      "audience": ["agents", "humans"],
      "agent_onboarding": { "read": true, "priority": 1 },
      "abstract": "Authoritative agent-facing architecture + invariants (incl. dirty-worktree rule), module index, type glossary, and security pointers."
    },
    {
      "path": "README.md",
      "bytes": 10287,
      "sha256": "sha256:15b46cc6a6ae280afd800fa5075c797063624f3b44c4bd87a33f4ea1ac125357",
      "audience": ["humans", "agents"],
      "agent_onboarding": { "read": true, "priority": 2 },
      "abstract": "User-facing overview, current command behavior, and project status (including planned vs implemented)."
    },
    {
      "path": "SECURITY.md",
      "bytes": 701,
      "sha256": "sha256:0934aebd28fe4247e942a7a6eeafe8f5bb9419ccee6999a09112c61a57bde522",
      "audience": ["governance", "humans", "agents"],
      "agent_onboarding": { "read": true, "priority": 3 },
      "abstract": "Vulnerability reporting and pointers to full security documentation under documents/security/."
    },
    {
      "path": "CHANGELOG.md",
      "bytes": 655,
      "sha256": "sha256:ae433ffb1e27b6c62f8a5cee40b1f9406ac9763f4fce5f0abbffbc5601088e11",
      "audience": ["humans"],
      "agent_onboarding": { "read": false },
      "abstract": "Change log placeholder; not a reliable signal for current behavior in a fast-moving pre-1.0 repo."
    },
    {
      "path": "CONTRIBUTING.md",
      "bytes": 6471,
      "sha256": "sha256:546887fcd6d7103af8315223410995dc76ad9874b9815555cd51fe210d42bce2",
      "audience": ["humans"],
      "agent_onboarding": { "read": false },
      "superseded_by": ["documents/skills/dev-eng-ticket/SKILL.md", "AGENTS.md"],
      "abstract": "Human contributor workflow and tooling notes; includes pointers to agent skill docs."
    },
    {
      "path": "research.md",
      "bytes": 24071,
      "sha256": "sha256:934ef4baadb2163883c66596e81717a42df9f626157111f49a94165c2d7f997b",
      "audience": ["humans"],
      "agent_onboarding": { "read": false },
      "abstract": "Long-form research notes (2025-Jan 2026) about agent systems; not onboarding-critical."
    }
  ],
  "facts": {
    "project": {
      "name": "APM2 - Holonic AI Process Manager",
      "version": "0.3.0",
      "edition": "2024",
      "msrv": "1.85"
    },
    "summary": [
      "APM2 is a Linux-only local daemon + CLI for supervising agent processes via Unix domain sockets.",
      "APM2 emphasizes event sourcing (append-only ledger), reducer-based projections, and content-addressed evidence storage.",
      "Agent execution is expected to be bounded; authority is committed-to by hashes/selectors, not by unbounded in-window history.",
      "Governance dominance: containment/security > verification/correctness > liveness/progress (fail-closed on unsafe or unverifiable tasks)."
    ],
    "key_paths": {
      "skills": "documents/skills/",
      "glossary": "documents/skills/glossary/",
      "holonic_laws_unified_theory": "documents/skills/laws-of-holonic-agent-systems/references/unified-theory.md",
      "security_docs": "documents/security/",
      "crates": "crates/",
      "proto": "proto/",
      "proto_event_schema": "proto/kernel_events.proto",
      "proto_tool_protocol": "proto/tool_protocol.proto"
    }
  }
}
