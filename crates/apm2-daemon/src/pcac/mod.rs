// AGENT-AUTHORED
//! PCAC lifecycle gate for `RequestTool` and privileged handler authority
//! control (TCK-00423, TCK-00424).
//!
//! This module wires the `AuthorityJoinKernel` lifecycle into the daemon's
//! session dispatch path. Every authoritative side effect (tool execution,
//! sublease delegation, review receipt ingestion) must pass through
//! `join -> revalidate -> consume` before the effect is permitted.
//!
//! # Integration Points
//!
//! - [`LifecycleGate`] gates `handle_request_tool` (TCK-00423).
//! - [`PrivilegedJoinInputBuilder`] + [`DelegationNarrowingChecker`] gate
//!   `handle_delegate_sublease` and `handle_ingest_review_receipt` (TCK-00424).
//!
//! # Rollout
//!
//! Privileged handler enforcement is gated behind
//! `pcac_privileged_enforcement` on `SessionDispatcher` for policy-switchable
//! rollout without wire protocol breakage.

mod lifecycle_gate;
pub mod privileged;

#[cfg(test)]
mod tests;

pub use lifecycle_gate::{InProcessKernel, LifecycleGate, LifecycleReceipts};
pub use privileged::{
    DelegationNarrowingChecker, DelegationNarrowingParams, PrivilegedJoinInputBuilder,
};
