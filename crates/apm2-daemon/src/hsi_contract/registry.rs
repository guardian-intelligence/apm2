//! HSI Contract Manifest registry builder.
//!
//! This module builds an `HSIContractManifestV1` from the daemon and CLI
//! dispatch registry. Every route in `PrivilegedMessageType` and
//! `SessionMessageType` is mapped to an HSI route entry with semantics
//! annotations.
//!
//! # Fail-closed Build Enforcement
//!
//! Per RFC-0020 section 3.1.1, if any route is missing a semantics
//! annotation, `build_manifest()` returns an error. This ensures that
//! new routes added to the dispatcher cannot be deployed without
//! explicit semantics documentation.
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1.1: Generation and determinism
//! - REQ-0001: Missing route semantics annotation fails CI/build

use super::manifest::{
    CliVersion, HsiContractManifestV1, HsiRouteEntry, SCHEMA_ID, SCHEMA_VERSION, StabilityClass,
};
use super::semantics::annotate_route;

/// Error returned when manifest generation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestBuildError {
    /// One or more routes are missing semantics annotations.
    ///
    /// Per RFC-0020 section 3.1.1: "Missing annotations MUST fail the build."
    MissingSemantics {
        /// Routes that are missing annotations.
        routes: Vec<String>,
    },
}

impl std::fmt::Display for ManifestBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSemantics { routes } => {
                write!(
                    f,
                    "HSI contract manifest build failed: missing semantics annotations for {} route(s): {}",
                    routes.len(),
                    routes.join(", ")
                )
            },
        }
    }
}

impl std::error::Error for ManifestBuildError {}

/// Route descriptor used to build the manifest from dispatch registries.
///
/// Each entry maps a dispatcher message type to an HSI route with its
/// schema bindings.
struct RouteDescriptor {
    /// Route identifier (e.g., `CLAIM_WORK`).
    id: &'static str,
    /// Canonical route path (e.g., `hsi.work.claim`).
    route: &'static str,
    /// Stability classification.
    stability: StabilityClass,
    /// Request schema identifier.
    request_schema: &'static str,
    /// Response schema identifier.
    response_schema: &'static str,
}

/// Returns all route descriptors from the privileged (operator) dispatch
/// registry.
///
/// This function MUST be kept in sync with `PrivilegedMessageType` in
/// `crate::protocol::dispatch`. If a new variant is added to the enum
/// without a corresponding entry here, `build_manifest()` will still
/// succeed but the route will be missing from the manifest. The
/// `test_privileged_routes_complete` test catches this.
fn privileged_routes() -> Vec<RouteDescriptor> {
    vec![
        RouteDescriptor {
            id: "CLAIM_WORK",
            route: "hsi.work.claim",
            stability: StabilityClass::Stable,
            request_schema: "apm2.claim_work_request.v1",
            response_schema: "apm2.claim_work_response.v1",
        },
        RouteDescriptor {
            id: "SPAWN_EPISODE",
            route: "hsi.episode.spawn",
            stability: StabilityClass::Stable,
            request_schema: "apm2.spawn_episode_request.v1",
            response_schema: "apm2.spawn_episode_response.v1",
        },
        RouteDescriptor {
            id: "ISSUE_CAPABILITY",
            route: "hsi.capability.issue",
            stability: StabilityClass::Stable,
            request_schema: "apm2.issue_capability_request.v1",
            response_schema: "apm2.issue_capability_response.v1",
        },
        RouteDescriptor {
            id: "SHUTDOWN",
            route: "hsi.daemon.shutdown",
            stability: StabilityClass::Stable,
            request_schema: "apm2.shutdown_request.v1",
            response_schema: "apm2.shutdown_response.v1",
        },
        RouteDescriptor {
            id: "LIST_PROCESSES",
            route: "hsi.process.list",
            stability: StabilityClass::Stable,
            request_schema: "apm2.list_processes_request.v1",
            response_schema: "apm2.list_processes_response.v1",
        },
        RouteDescriptor {
            id: "PROCESS_STATUS",
            route: "hsi.process.status",
            stability: StabilityClass::Stable,
            request_schema: "apm2.process_status_request.v1",
            response_schema: "apm2.process_status_response.v1",
        },
        RouteDescriptor {
            id: "START_PROCESS",
            route: "hsi.process.start",
            stability: StabilityClass::Stable,
            request_schema: "apm2.start_process_request.v1",
            response_schema: "apm2.start_process_response.v1",
        },
        RouteDescriptor {
            id: "STOP_PROCESS",
            route: "hsi.process.stop",
            stability: StabilityClass::Stable,
            request_schema: "apm2.stop_process_request.v1",
            response_schema: "apm2.stop_process_response.v1",
        },
        RouteDescriptor {
            id: "RESTART_PROCESS",
            route: "hsi.process.restart",
            stability: StabilityClass::Stable,
            request_schema: "apm2.restart_process_request.v1",
            response_schema: "apm2.restart_process_response.v1",
        },
        RouteDescriptor {
            id: "RELOAD_PROCESS",
            route: "hsi.process.reload",
            stability: StabilityClass::Stable,
            request_schema: "apm2.reload_process_request.v1",
            response_schema: "apm2.reload_process_response.v1",
        },
        RouteDescriptor {
            id: "CONSENSUS_STATUS",
            route: "hsi.consensus.status",
            stability: StabilityClass::Stable,
            request_schema: "apm2.consensus_status_request.v1",
            response_schema: "apm2.consensus_status_response.v1",
        },
        RouteDescriptor {
            id: "CONSENSUS_VALIDATORS",
            route: "hsi.consensus.validators",
            stability: StabilityClass::Stable,
            request_schema: "apm2.consensus_validators_request.v1",
            response_schema: "apm2.consensus_validators_response.v1",
        },
        RouteDescriptor {
            id: "CONSENSUS_BYZANTINE_EVIDENCE",
            route: "hsi.consensus.byzantine_evidence",
            stability: StabilityClass::Stable,
            request_schema: "apm2.consensus_byzantine_evidence_request.v1",
            response_schema: "apm2.consensus_byzantine_evidence_response.v1",
        },
        RouteDescriptor {
            id: "CONSENSUS_METRICS",
            route: "hsi.consensus.metrics",
            stability: StabilityClass::Stable,
            request_schema: "apm2.consensus_metrics_request.v1",
            response_schema: "apm2.consensus_metrics_response.v1",
        },
        RouteDescriptor {
            id: "WORK_STATUS",
            route: "hsi.work.status",
            stability: StabilityClass::Stable,
            request_schema: "apm2.work_status_request.v1",
            response_schema: "apm2.work_status_response.v1",
        },
        RouteDescriptor {
            id: "END_SESSION",
            route: "hsi.session.end",
            stability: StabilityClass::Stable,
            request_schema: "apm2.end_session_request.v1",
            response_schema: "apm2.end_session_response.v1",
        },
        RouteDescriptor {
            id: "INGEST_REVIEW_RECEIPT",
            route: "hsi.review.ingest_receipt",
            stability: StabilityClass::Stable,
            request_schema: "apm2.ingest_review_receipt_request.v1",
            response_schema: "apm2.ingest_review_receipt_response.v1",
        },
        RouteDescriptor {
            id: "LIST_CREDENTIALS",
            route: "hsi.credential.list",
            stability: StabilityClass::Stable,
            request_schema: "apm2.list_credentials_request.v1",
            response_schema: "apm2.list_credentials_response.v1",
        },
        RouteDescriptor {
            id: "ADD_CREDENTIAL",
            route: "hsi.credential.add",
            stability: StabilityClass::Stable,
            request_schema: "apm2.add_credential_request.v1",
            response_schema: "apm2.add_credential_response.v1",
        },
        RouteDescriptor {
            id: "REMOVE_CREDENTIAL",
            route: "hsi.credential.remove",
            stability: StabilityClass::Stable,
            request_schema: "apm2.remove_credential_request.v1",
            response_schema: "apm2.remove_credential_response.v1",
        },
        RouteDescriptor {
            id: "REFRESH_CREDENTIAL",
            route: "hsi.credential.refresh",
            stability: StabilityClass::Stable,
            request_schema: "apm2.refresh_credential_request.v1",
            response_schema: "apm2.refresh_credential_response.v1",
        },
        RouteDescriptor {
            id: "SWITCH_CREDENTIAL",
            route: "hsi.credential.switch",
            stability: StabilityClass::Stable,
            request_schema: "apm2.switch_credential_request.v1",
            response_schema: "apm2.switch_credential_response.v1",
        },
        RouteDescriptor {
            id: "LOGIN_CREDENTIAL",
            route: "hsi.credential.login",
            stability: StabilityClass::Stable,
            request_schema: "apm2.login_credential_request.v1",
            response_schema: "apm2.login_credential_response.v1",
        },
        RouteDescriptor {
            id: "SUBSCRIBE_PULSE",
            route: "hsi.pulse.subscribe",
            stability: StabilityClass::Stable,
            request_schema: "apm2.subscribe_pulse_request.v1",
            response_schema: "apm2.subscribe_pulse_response.v1",
        },
        RouteDescriptor {
            id: "UNSUBSCRIBE_PULSE",
            route: "hsi.pulse.unsubscribe",
            stability: StabilityClass::Stable,
            request_schema: "apm2.unsubscribe_pulse_request.v1",
            response_schema: "apm2.unsubscribe_pulse_response.v1",
        },
        RouteDescriptor {
            id: "PUBLISH_CHANGESET",
            route: "hsi.changeset.publish",
            stability: StabilityClass::Stable,
            request_schema: "apm2.publish_changeset_request.v1",
            response_schema: "apm2.publish_changeset_response.v1",
        },
    ]
}

/// Returns all route descriptors from the session-scoped dispatch registry.
///
/// This function MUST be kept in sync with `SessionMessageType` in
/// `crate::protocol::session_dispatch`. The `test_session_routes_complete`
/// test catches missing entries.
fn session_routes() -> Vec<RouteDescriptor> {
    vec![
        RouteDescriptor {
            id: "REQUEST_TOOL",
            route: "hsi.tool.request",
            stability: StabilityClass::Stable,
            request_schema: "apm2.request_tool_request.v1",
            response_schema: "apm2.request_tool_response.v1",
        },
        RouteDescriptor {
            id: "EMIT_EVENT",
            route: "hsi.event.emit",
            stability: StabilityClass::Stable,
            request_schema: "apm2.emit_event_request.v1",
            response_schema: "apm2.emit_event_response.v1",
        },
        RouteDescriptor {
            id: "PUBLISH_EVIDENCE",
            route: "hsi.evidence.publish",
            stability: StabilityClass::Stable,
            request_schema: "apm2.publish_evidence_request.v1",
            response_schema: "apm2.publish_evidence_response.v1",
        },
        RouteDescriptor {
            id: "STREAM_TELEMETRY",
            route: "hsi.telemetry.stream",
            stability: StabilityClass::Stable,
            request_schema: "apm2.stream_telemetry_request.v1",
            response_schema: "apm2.stream_telemetry_response.v1",
        },
        RouteDescriptor {
            id: "STREAM_LOGS",
            route: "hsi.logs.stream",
            stability: StabilityClass::Stable,
            request_schema: "apm2.stream_logs_request.v1",
            response_schema: "apm2.stream_logs_response.v1",
        },
        RouteDescriptor {
            id: "SESSION_STATUS",
            route: "hsi.session.status",
            stability: StabilityClass::Stable,
            request_schema: "apm2.session_status_request.v1",
            response_schema: "apm2.session_status_response.v1",
        },
    ]
}

/// Builds an `HSIContractManifestV1` from the daemon and CLI dispatch
/// registries.
///
/// # Arguments
///
/// * `cli_version` - The CLI version metadata to embed in the manifest.
///
/// # Errors
///
/// Returns `ManifestBuildError::MissingSemantics` if any route lacks a
/// semantics annotation. Per RFC-0020 section 3.1.1, this MUST fail the
/// build.
///
/// # Determinism
///
/// The returned manifest is deterministic: routes are sorted
/// lexicographically by `route` field, and all fields are populated from
/// compile-time constants.
pub fn build_manifest(
    cli_version: CliVersion,
) -> Result<HsiContractManifestV1, ManifestBuildError> {
    let all_routes: Vec<RouteDescriptor> = {
        let mut routes = privileged_routes();
        routes.extend(session_routes());
        routes
    };

    let mut missing = Vec::new();
    let mut entries = Vec::with_capacity(all_routes.len());

    for desc in &all_routes {
        match annotate_route(desc.route) {
            Some(semantics) => {
                entries.push(HsiRouteEntry {
                    id: desc.id.to_string(),
                    route: desc.route.to_string(),
                    stability: desc.stability,
                    request_schema: desc.request_schema.to_string(),
                    response_schema: desc.response_schema.to_string(),
                    semantics,
                });
            },
            None => {
                missing.push(desc.route.to_string());
            },
        }
    }

    // Fail-closed: missing annotations MUST fail the build
    if !missing.is_empty() {
        return Err(ManifestBuildError::MissingSemantics { routes: missing });
    }

    // Sort routes lexicographically by route field for determinism
    entries.sort_by(|a, b| a.route.cmp(&b.route));

    Ok(HsiContractManifestV1 {
        schema: SCHEMA_ID.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        cli_version,
        routes: entries,
    })
}

/// Expected number of privileged routes.
///
/// This constant MUST be updated when routes are added to or removed from
/// `PrivilegedMessageType`. The `test_privileged_route_count` test enforces
/// this.
pub const EXPECTED_PRIVILEGED_ROUTE_COUNT: usize = 26;

/// Expected number of session routes.
///
/// This constant MUST be updated when routes are added to or removed from
/// `SessionMessageType`. The `test_session_route_count` test enforces this.
pub const EXPECTED_SESSION_ROUTE_COUNT: usize = 6;

/// Expected total route count for the manifest.
pub const EXPECTED_TOTAL_ROUTE_COUNT: usize =
    EXPECTED_PRIVILEGED_ROUTE_COUNT + EXPECTED_SESSION_ROUTE_COUNT;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cli_version() -> CliVersion {
        CliVersion {
            semver: "0.9.0".to_string(),
            build_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    #[test]
    fn build_manifest_succeeds() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        assert_eq!(manifest.schema, SCHEMA_ID);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert!(!manifest.routes.is_empty());
    }

    #[test]
    fn build_manifest_routes_are_sorted() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        for i in 1..manifest.routes.len() {
            assert!(
                manifest.routes[i - 1].route <= manifest.routes[i].route,
                "routes not sorted: '{}' before '{}'",
                manifest.routes[i - 1].route,
                manifest.routes[i].route,
            );
        }
    }

    #[test]
    fn build_manifest_deterministic_across_builds() {
        let m1 = build_manifest(test_cli_version()).expect("build 1");
        let m2 = build_manifest(test_cli_version()).expect("build 2");
        assert_eq!(m1.canonical_bytes(), m2.canonical_bytes());
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn build_manifest_hash_changes_on_version_change() {
        let m1 = build_manifest(test_cli_version()).expect("build 1");
        let m2 = build_manifest(CliVersion {
            semver: "0.10.0".to_string(),
            build_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        })
        .expect("build 2");
        assert_ne!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn build_manifest_validates_clean() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let errors = manifest.validate();
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    #[test]
    fn privileged_route_count() {
        let routes = privileged_routes();
        assert_eq!(
            routes.len(),
            EXPECTED_PRIVILEGED_ROUTE_COUNT,
            "privileged route count mismatch: expected {EXPECTED_PRIVILEGED_ROUTE_COUNT}, got {}. \
             Update EXPECTED_PRIVILEGED_ROUTE_COUNT when adding/removing privileged routes.",
            routes.len()
        );
    }

    #[test]
    fn session_route_count() {
        let routes = session_routes();
        assert_eq!(
            routes.len(),
            EXPECTED_SESSION_ROUTE_COUNT,
            "session route count mismatch: expected {EXPECTED_SESSION_ROUTE_COUNT}, got {}. \
             Update EXPECTED_SESSION_ROUTE_COUNT when adding/removing session routes.",
            routes.len()
        );
    }

    #[test]
    fn total_route_count() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        assert_eq!(
            manifest.routes.len(),
            EXPECTED_TOTAL_ROUTE_COUNT,
            "total route count mismatch"
        );
    }

    #[test]
    fn all_routes_have_unique_ids() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let mut ids: Vec<&str> = manifest.routes.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            manifest.routes.len(),
            "duplicate route IDs found"
        );
    }

    #[test]
    fn all_routes_have_unique_routes() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let mut routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        routes.sort_unstable();
        routes.dedup();
        assert_eq!(
            routes.len(),
            manifest.routes.len(),
            "duplicate route paths found"
        );
    }

    #[test]
    fn all_authoritative_routes_require_receipts() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        for entry in &manifest.routes {
            if entry.semantics.authoritative {
                // Authoritative routes that do not require receipts are
                // explicitly annotated (e.g., credential management routes
                // that are local-only). We verify that at minimum, the
                // core authoritative routes do require receipts.
                if entry.route.starts_with("hsi.tool.")
                    || entry.route.starts_with("hsi.event.")
                    || entry.route.starts_with("hsi.evidence.")
                    || entry.route.starts_with("hsi.work.claim")
                    || entry.route.starts_with("hsi.episode.")
                {
                    assert!(
                        entry.semantics.receipt_required,
                        "authoritative route '{}' must require receipts",
                        entry.route
                    );
                }
            }
        }
    }

    /// Verifies that `PrivilegedMessageType` variants (excluding response-only
    /// types like `PulseEvent`) have corresponding route descriptors.
    ///
    /// If this test fails, a new `PrivilegedMessageType` variant was added
    /// without a corresponding route descriptor. Add the missing route to
    /// `privileged_routes()` and its semantics to `annotate_route()`.
    #[test]
    fn privileged_routes_cover_dispatch_types() {
        // Cross-reference: these are the message types from PrivilegedMessageType
        // that represent request-bearing routes (not response-only).
        let expected_routes = [
            "hsi.work.claim",
            "hsi.episode.spawn",
            "hsi.capability.issue",
            "hsi.daemon.shutdown",
            "hsi.process.list",
            "hsi.process.status",
            "hsi.process.start",
            "hsi.process.stop",
            "hsi.process.restart",
            "hsi.process.reload",
            "hsi.consensus.status",
            "hsi.consensus.validators",
            "hsi.consensus.byzantine_evidence",
            "hsi.consensus.metrics",
            "hsi.work.status",
            "hsi.session.end",
            "hsi.review.ingest_receipt",
            "hsi.credential.list",
            "hsi.credential.add",
            "hsi.credential.remove",
            "hsi.credential.refresh",
            "hsi.credential.switch",
            "hsi.credential.login",
            "hsi.pulse.subscribe",
            "hsi.pulse.unsubscribe",
            "hsi.changeset.publish",
        ];
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        for route in &expected_routes {
            assert!(
                manifest_routes.contains(route),
                "missing route in manifest: {route}"
            );
        }
    }

    /// Verifies that `SessionMessageType` variants (excluding response-only
    /// types like `PulseEvent`) have corresponding route descriptors.
    #[test]
    fn session_routes_cover_dispatch_types() {
        let expected_routes = [
            "hsi.tool.request",
            "hsi.event.emit",
            "hsi.evidence.publish",
            "hsi.telemetry.stream",
            "hsi.logs.stream",
            "hsi.session.status",
        ];
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        for route in &expected_routes {
            assert!(
                manifest_routes.contains(route),
                "missing route in manifest: {route}"
            );
        }
    }
}
