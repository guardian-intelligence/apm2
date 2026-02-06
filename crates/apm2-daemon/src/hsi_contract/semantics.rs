//! Per-route semantics annotations for HSI contract manifest.
//!
//! This module defines the semantics annotation structure for each route in
//! the dispatch registry. Per RFC-0020 section 3.1, every route MUST have
//! a semantics annotation describing whether it is authoritative vs advisory,
//! its idempotency requirement, and its receipt obligation.
//!
//! # Fail-closed Build Enforcement
//!
//! The `annotate_route` function returns `Option<HsiRouteSemantics>`. When
//! building the manifest via `build_manifest()`, any route missing a semantics
//! annotation causes the build to fail. This is enforced at manifest
//! construction time (not just compile time) so that new routes added to the
//! dispatcher without annotations are caught immediately.
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1: Missing annotations MUST fail the build
//! - REQ-0001: `Missing route semantics annotation fails CI/build`

use super::manifest::{HsiRouteSemantics, IdempotencyRequirement};

/// Authoritative + idempotency-required + receipt-required semantics.
///
/// Used for core state-mutating routes that produce world effects.
const AUTH_IDEMPOTENT_RECEIPT: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::Required,
    receipt_required: true,
};

/// Authoritative + best-effort idempotency + receipt-required semantics.
///
/// Used for lifecycle operations (stop, restart, reload, end session).
const AUTH_BESTEFFORT_RECEIPT: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::BestEffort,
    receipt_required: true,
};

/// Authoritative + best-effort idempotency + no receipt.
///
/// Used for local-only operations (shutdown, credential management).
const AUTH_BESTEFFORT_NO_RECEIPT: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::BestEffort,
    receipt_required: false,
};

/// Authoritative + idempotency-required + no receipt.
///
/// Used for local credential storage operations.
const AUTH_IDEMPOTENT_NO_RECEIPT: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::Required,
    receipt_required: false,
};

/// Advisory (read-only) semantics: no idempotency, no receipts.
const ADVISORY: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: false,
    idempotency: IdempotencyRequirement::NotRequired,
    receipt_required: false,
};

/// Returns the semantics annotation for a given route string.
///
/// Every route in the daemon/CLI dispatch registry MUST have an entry here.
/// Adding a new route to the dispatcher without adding a corresponding
/// annotation will cause `build_manifest()` to return an error, which
/// fails the build per RFC-0020 section 3.1.1.
///
/// # Fail-closed
///
/// Returns `None` for unknown routes. The caller MUST treat `None` as a
/// build failure.
#[must_use]
pub fn annotate_route(route: &str) -> Option<HsiRouteSemantics> {
    match route {
        // =================================================================
        // Authoritative + idempotent + receipt-required
        // Core state-mutating operations with world effects.
        // =================================================================
        "hsi.work.claim"
        | "hsi.episode.spawn"
        | "hsi.capability.issue"
        | "hsi.process.start"
        | "hsi.review.ingest_receipt"
        | "hsi.changeset.publish"
        | "hsi.tool.request"
        | "hsi.event.emit"
        | "hsi.evidence.publish" => Some(AUTH_IDEMPOTENT_RECEIPT),

        // =================================================================
        // Authoritative + best-effort idempotency + receipt-required
        // Lifecycle operations that may retry but track effects.
        // =================================================================
        "hsi.process.stop" | "hsi.process.restart" | "hsi.process.reload" | "hsi.session.end" => {
            Some(AUTH_BESTEFFORT_RECEIPT)
        },

        // =================================================================
        // Authoritative + best-effort idempotency + no receipt
        // Local-only operations (daemon shutdown, credential management).
        // =================================================================
        "hsi.daemon.shutdown"
        | "hsi.credential.remove"
        | "hsi.credential.refresh"
        | "hsi.credential.switch"
        | "hsi.credential.login" => Some(AUTH_BESTEFFORT_NO_RECEIPT),

        // =================================================================
        // Authoritative + idempotent + no receipt
        // Local credential storage (add is idempotent by key).
        // =================================================================
        "hsi.credential.add" => Some(AUTH_IDEMPOTENT_NO_RECEIPT),

        // =================================================================
        // Advisory (read-only) endpoints
        // No state mutation, no receipts required.
        // =================================================================
        "hsi.process.list"
        | "hsi.process.status"
        | "hsi.consensus.status"
        | "hsi.consensus.validators"
        | "hsi.consensus.byzantine_evidence"
        | "hsi.consensus.metrics"
        | "hsi.work.status"
        | "hsi.credential.list"
        | "hsi.pulse.subscribe"
        | "hsi.pulse.unsubscribe"
        | "hsi.telemetry.stream"
        | "hsi.logs.stream"
        | "hsi.session.status" => Some(ADVISORY),

        // Unknown route: fail-closed
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_routes_have_annotations() {
        // Verify a representative sample of routes have annotations
        let known_routes = [
            "hsi.work.claim",
            "hsi.episode.spawn",
            "hsi.capability.issue",
            "hsi.daemon.shutdown",
            "hsi.tool.request",
            "hsi.event.emit",
            "hsi.evidence.publish",
            "hsi.session.status",
            "hsi.changeset.publish",
        ];
        for route in &known_routes {
            assert!(
                annotate_route(route).is_some(),
                "route {route} must have semantics annotation"
            );
        }
    }

    #[test]
    fn unknown_route_returns_none() {
        assert!(annotate_route("hsi.nonexistent.route").is_none());
        assert!(annotate_route("").is_none());
        assert!(annotate_route("invalid").is_none());
    }

    #[test]
    fn authoritative_routes_require_receipts() {
        let authoritative_routes = [
            "hsi.work.claim",
            "hsi.episode.spawn",
            "hsi.capability.issue",
            "hsi.tool.request",
            "hsi.event.emit",
            "hsi.evidence.publish",
        ];
        for route in &authoritative_routes {
            let sem = annotate_route(route).unwrap();
            assert!(sem.authoritative, "route {route} must be authoritative");
            assert!(
                sem.receipt_required,
                "authoritative route {route} must require receipts"
            );
        }
    }

    #[test]
    fn advisory_routes_do_not_require_receipts() {
        let advisory_routes = [
            "hsi.process.list",
            "hsi.process.status",
            "hsi.consensus.status",
            "hsi.work.status",
            "hsi.telemetry.stream",
            "hsi.session.status",
        ];
        for route in &advisory_routes {
            let sem = annotate_route(route).unwrap();
            assert!(!sem.authoritative, "route {route} must be advisory");
            assert!(
                !sem.receipt_required,
                "advisory route {route} must not require receipts"
            );
        }
    }
}
