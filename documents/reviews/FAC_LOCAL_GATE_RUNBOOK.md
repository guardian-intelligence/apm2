# FAC Local Gate Runbook (TCK-00410)

## Purpose
Operate FAC-local CI gate execution on OVH self-hosted runners while keeping GitHub as projection-only status surface and preserving required `CI Success` merge-gate semantics.

## Required Runner Profile
- Labels: `self-hosted`, `linux`, `x64`, `fac-ovh`
- Machine identity mapping:
  - `fac-ovh` means this specific host: `rust-forge-01`.
  - Registered runner service on this host: `actions.runner.guardian-intelligence-apm2.ubuntu-ovh-runner.service`.
  - This runbook assumes CI compute happens on this machine and GitHub only receives projected status.
- Host requirements:
  - Linux with cgroup v2 mounted at `/sys/fs/cgroup`
  - `systemd-run` available for transient bounded scopes
  - Rust toolchain baseline `nightly-2025-12-01`
  - `cargo-nextest`, `protoc`, and GitHub Actions runner service installed
  - Parallel job execution requires multiple runner agents registered on this machine with the same labels (one runner process executes one job at a time).

## Blocking Guard Checks
- These run inside the single GitHub job `CI Success` via `./scripts/ci/run_local_ci_orchestrator.sh`.
- `Test Safety Guard`
  - Command: `./scripts/ci/test_safety_guard.sh`
  - Blocks destructive test signatures pre-execution.
- `Bounded Test Runner`
  - Command: `./scripts/ci/run_bounded_tests.sh`
  - Enforces timeout + cgroup/systemd ceilings (CPU/memory/pids).
- `Workspace Integrity Guard`
  - Command: `./scripts/ci/workspace_integrity_guard.sh -- <bounded test command>`
  - Fails if tracked repository content mutates unexpectedly after tests.

## Failure-Injection Validation
- Command: `./scripts/ci/test_guardrail_fixtures.sh`
- Verifies:
  - dangerous test signatures are rejected
  - tracked workspace mutation is detected
  - hung commands are terminated by watchdog limits

## Operational Procedure
1. Confirm `fac-ovh` resolves to this host and runner service:
   - `hostnamectl --static` must return `rust-forge-01`.
   - `systemctl status actions.runner.guardian-intelligence-apm2.ubuntu-ovh-runner.service` must be `active (running)`.
2. Confirm runner is online in GitHub Actions with label set: `self-hosted`, `linux`, `x64`, `fac-ovh`.
3. Trigger CI on PR and merge-group SHA.
4. Verify `CI Success` job logs show these checks passing:
   - `Test Safety Guard`
   - `Bounded Test Runner`
   - `Workspace Integrity Guard`
5. On failures, inspect job logs and corresponding guard script output.
6. If test-safety false positives occur, add minimal scoped entries to `scripts/ci/test_safety_allowlist.txt`.

## Triage Notes
- `systemd-run` authentication errors:
  - Ensure `systemd-run --user` is functional for the runner account.
  - Verify linger and user manager: `loginctl show-user ubuntu` includes `Linger=yes`, and `systemctl status user@1000.service` is active.
  - Verify runner service exports user-bus environment:
    - `XDG_RUNTIME_DIR=/run/user/1000`
    - `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus`
- Missing cgroup controllers:
  - Validate cgroup v2 mount and controller availability (`cat /sys/fs/cgroup/cgroup.controllers`).
- Workspace drift failures:
  - Use `git diff --name-only` to inspect unexpected tracked file mutation after tests.
