# RFC-0018 Evidence Appendix

This appendix enumerates evidence for current behavior claims used in RFC-0018.
Line ranges are from `nl -ba` output.

## IPC and ProtocolServer
- ProtocolServer framing is length-prefixed with a 4-byte big-endian length and a
  16 MiB max frame size: `crates/apm2-daemon/src/protocol/mod.rs:38-48`,
  `crates/apm2-daemon/src/protocol/error.rs:21-25`.
- Dual-socket operator.sock/session.sock with privilege separation and socket
  permissions are specified: `crates/apm2-daemon/AGENTS.md:123-139`.
- Connection privilege is derived from socket type in ConnectionContext:
  `crates/apm2-daemon/src/protocol/dispatch.rs:724-783`.
- Session dispatcher denies operator connections and requires session_token:
  `crates/apm2-daemon/src/protocol/session_dispatch.rs:225-246`,
  `crates/apm2-daemon/src/protocol/session_dispatch.rs:272-299`.
- DD-009 hard cutover forbids legacy JSON IPC:
  `documents/rfcs/RFC-0017/02_design_decisions.yaml:632-649`,
  `crates/apm2-core/src/ipc/AGENTS.md:5-23`.

## Ledger and CAS
- Ledger append-only semantics and cursor-based reads:
  `crates/apm2-core/src/ledger/storage.rs:303-307`,
  `crates/apm2-core/src/ledger/storage.rs:412-518`.
- Ledger head pointer (max seq id): `crates/apm2-core/src/ledger/storage.rs:719-736`.
- CAS immutability and size limits:
  `crates/apm2-core/src/evidence/cas.rs:1-18`,
  `crates/apm2-core/src/evidence/cas.rs:27-31`,
  `crates/apm2-core/src/evidence/cas.rs:119-150`.

## Kernel event schema (truth-plane)
- KernelEvent payload list (no defect or episode events shown):
  `proto/kernel_events.proto:52-93`.
- WorkEvent types: `proto/kernel_events.proto:187-239`.
- ToolEvent types: `proto/kernel_events.proto:243-282`.
- PolicyResolvedForChangeSet and GateReceipt:
  `proto/kernel_events.proto:723-791`.

## Runtime IPC (non-ledger)
- EpisodeCreated/Started/Stopped messages (IPC-only):
  `proto/apm2d_runtime_v1.proto:29-55`.
- StreamOutput message (IPC-only): `proto/apm2d_runtime_v1.proto:92-109`.

## Projection-only external posture
- Projection adapters are write-only; ledger is the source of truth:
  `crates/apm2-daemon/src/projection/mod.rs:4-21`.

## xtask bypass surfaces
- xtask AAT sets GitHub status checks via gh api:
  `xtask/src/tasks/aat.rs:172-207`.
- xtask push creates pending GitHub status checks:
  `xtask/src/tasks/push.rs:239-365`.
- xtask review updates GitHub status checks:
  `xtask/src/tasks/review.rs:351-369`.

## Ledger event emission status
- StubLedgerEventEmitter is in-memory and intended for testing, not persistence:
  `crates/apm2-daemon/src/protocol/dispatch.rs:148-169`.

## NEW WORK REQUIRED (from evidence gaps)
- Defect ledger event is not present in KernelEvent payload list:
  `proto/kernel_events.proto:52-93`. Ticket: `TCK-00307`.
- Episode lifecycle/tool/io events are not present in kernel_events.proto; only
  IPC messages exist: `proto/kernel_events.proto:52-93`,
  `proto/apm2d_runtime_v1.proto:29-109`. Ticket: `TCK-00306`.
- Ledger API exposes append/read/head but no outbox/pulse publisher surface:
  `crates/apm2-core/src/ledger/storage.rs:412-518`,
  `crates/apm2-core/src/ledger/storage.rs:719-736`. Ticket: `TCK-00304`.
