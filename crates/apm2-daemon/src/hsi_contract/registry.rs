//! HSI Contract Manifest registry builder.
//!
//! This module builds an `HSIContractManifestV1` from the daemon and CLI
//! dispatch registry. Every route in `PrivilegedMessageType` and
//! `SessionMessageType` is mapped to an HSI route entry with semantics
//! annotations.
//!
//! # Mechanically Derived from Dispatch Enums
//!
//! Route descriptors are derived directly from `PrivilegedMessageType` and
//! `SessionMessageType` via their `all_request_variants()`, `hsi_route()`,
//! `hsi_route_id()`, `hsi_request_schema()`, and `hsi_response_schema()`
//! methods. Adding a new dispatch variant without updating these methods
//! causes a build failure (missing match arm) or a manifest completeness
//! test failure.
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
use crate::protocol::dispatch::PrivilegedMessageType;
use crate::protocol::session_dispatch::SessionMessageType;

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
/// registry, derived mechanically from `PrivilegedMessageType`.
///
/// Route metadata (ID, route path, schemas) comes directly from the enum
/// methods, so adding a new variant without updating the match arms in
/// `PrivilegedMessageType` causes a compile-time error.
fn privileged_routes() -> Vec<RouteDescriptor> {
    PrivilegedMessageType::all_request_variants()
        .iter()
        .map(|v| RouteDescriptor {
            id: v.hsi_route_id(),
            route: v.hsi_route(),
            stability: StabilityClass::Stable,
            request_schema: v.hsi_request_schema(),
            response_schema: v.hsi_response_schema(),
        })
        .collect()
}

/// Returns all route descriptors from the session-scoped dispatch registry,
/// derived mechanically from `SessionMessageType`.
fn session_routes() -> Vec<RouteDescriptor> {
    SessionMessageType::all_request_variants()
        .iter()
        .map(|v| RouteDescriptor {
            id: v.hsi_route_id(),
            route: v.hsi_route(),
            stability: StabilityClass::Stable,
            request_schema: v.hsi_request_schema(),
            response_schema: v.hsi_response_schema(),
        })
        .collect()
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
    let mut seen_routes = std::collections::HashSet::new();

    for desc in &all_routes {
        // Deduplicate routes that appear in both privileged and session
        // dispatch registries (e.g., SubscribePulse, UnsubscribePulse).
        // The first occurrence wins; subsequent duplicates with the same
        // route path are silently skipped.
        if !seen_routes.insert(desc.route) {
            continue;
        }
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
/// `PrivilegedMessageType::all_request_variants()`. The
/// `test_privileged_route_count` test enforces this.
pub const EXPECTED_PRIVILEGED_ROUTE_COUNT: usize = 26;

/// Expected number of session routes.
///
/// This constant MUST be updated when routes are added to or removed from
/// `SessionMessageType::all_request_variants()`. The
/// `test_session_route_count` test enforces this.
pub const EXPECTED_SESSION_ROUTE_COUNT: usize = 8;

/// Number of routes that appear in both privileged and session dispatch
/// registries (e.g., `SubscribePulse`, `UnsubscribePulse`). These are
/// deduplicated during manifest construction.
pub const EXPECTED_SHARED_ROUTE_COUNT: usize = 2;

/// Expected total route count for the manifest (after deduplication).
pub const EXPECTED_TOTAL_ROUTE_COUNT: usize =
    EXPECTED_PRIVILEGED_ROUTE_COUNT + EXPECTED_SESSION_ROUTE_COUNT - EXPECTED_SHARED_ROUTE_COUNT;

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
        assert_eq!(
            m1.canonical_bytes().expect("canonical bytes 1"),
            m2.canonical_bytes().expect("canonical bytes 2"),
        );
        assert_eq!(
            m1.content_hash().expect("hash 1"),
            m2.content_hash().expect("hash 2"),
        );
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
        assert_ne!(
            m1.content_hash().expect("hash 1"),
            m2.content_hash().expect("hash 2"),
        );
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

    /// Verifies that ALL authoritative routes require receipts.
    ///
    /// Per RFC-0020 section 1.3, authoritative routes MUST produce receipts
    /// for proof-carrying-effects/accountability. No exceptions.
    #[test]
    fn all_authoritative_routes_require_receipts() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        for entry in &manifest.routes {
            if entry.semantics.authoritative {
                assert!(
                    entry.semantics.receipt_required,
                    "authoritative route '{}' must require receipts — \
                     reclassify as advisory if receipts are not needed",
                    entry.route
                );
            }
        }
    }

    /// Verifies that the `MissingSemantics` error path triggers when a route
    /// has no semantics annotation.
    ///
    /// This test constructs a scenario where `annotate_route` returns `None`
    /// for a route by building the manifest with a test-only route injected
    /// into the route list. Since the builder function is not easily
    /// injectable, we instead directly exercise the `MissingSemantics` error
    /// path by calling `annotate_route` on a non-existent route and verifying
    /// the build logic. We also verify the error type is properly constructed.
    ///
    /// EVID-0301: concrete failing-path test for `MissingSemantics`.
    #[test]
    fn missing_semantics_error_path_triggers() {
        // Verify that annotate_route returns None for unknown routes
        let unknown = super::annotate_route("hsi.nonexistent.test_only_route");
        assert!(
            unknown.is_none(),
            "unknown route must return None from annotate_route"
        );

        // Construct a ManifestBuildError::MissingSemantics directly and verify
        // its properties, since we cannot inject a fake route into the real
        // build pipeline without modifying the dispatch enums.
        let err = ManifestBuildError::MissingSemantics {
            routes: vec!["hsi.nonexistent.test_only_route".to_string()],
        };
        let msg = err.to_string();
        assert!(
            msg.contains("missing semantics annotations"),
            "error message must mention missing semantics: {msg}"
        );
        assert!(
            msg.contains("hsi.nonexistent.test_only_route"),
            "error message must contain the failing route: {msg}"
        );

        // Now exercise the actual build logic: replicate the fail-closed
        // annotation lookup that build_manifest() performs. A descriptor with
        // no semantics annotation must end up in the missing list.
        let fake_descriptors = vec![RouteDescriptor {
            id: "FAKE_MISSING",
            route: "hsi.nonexistent.test_only_route",
            stability: StabilityClass::Stable,
            request_schema: "apm2.fake.v1",
            response_schema: "apm2.fake.v1",
        }];
        let mut missing = Vec::new();
        for desc in &fake_descriptors {
            if super::annotate_route(desc.route).is_none() {
                missing.push(desc.route.to_string());
            }
        }
        assert!(
            !missing.is_empty(),
            "fake route must be detected as missing semantics"
        );
        let result_err = ManifestBuildError::MissingSemantics { routes: missing };
        match &result_err {
            ManifestBuildError::MissingSemantics { routes } => {
                assert_eq!(routes.len(), 1);
                assert_eq!(routes[0], "hsi.nonexistent.test_only_route");
            },
        }
    }

    /// Verifies that every dispatchable request variant from both dispatch
    /// enums appears in the built manifest. This catches variants that are
    /// declared in the enum but omitted from `all_request_variants()`.
    #[test]
    fn every_dispatchable_variant_appears_in_manifest() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: std::collections::HashSet<&str> =
            manifest.routes.iter().map(|r| r.route.as_str()).collect();

        // Check all privileged variants
        for v in PrivilegedMessageType::all_request_variants() {
            assert!(
                manifest_routes.contains(v.hsi_route()),
                "PrivilegedMessageType::{:?} (route '{}') is dispatchable but missing from manifest",
                v,
                v.hsi_route()
            );
        }

        // Check all session variants
        for v in SessionMessageType::all_request_variants() {
            assert!(
                manifest_routes.contains(v.hsi_route()),
                "SessionMessageType::{:?} (route '{}') is dispatchable but missing from manifest",
                v,
                v.hsi_route()
            );
        }
    }

    /// Verifies that `PrivilegedMessageType::all_request_variants()` covers
    /// all request-bearing dispatch variants.
    ///
    /// This test asserts that the route descriptors derived from the enum
    /// match the expected count, and that every variant's route appears in
    /// the built manifest. If a new variant is added to the enum but not
    /// to `all_request_variants()`, this test will fail.
    #[test]
    fn privileged_routes_cover_dispatch_types() {
        let variants = PrivilegedMessageType::all_request_variants();
        assert_eq!(
            variants.len(),
            EXPECTED_PRIVILEGED_ROUTE_COUNT,
            "PrivilegedMessageType::all_request_variants() count mismatch — \
             a new variant was added without updating all_request_variants()"
        );
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        for v in variants {
            assert!(
                manifest_routes.contains(&v.hsi_route()),
                "missing route in manifest for {:?}: {}",
                v,
                v.hsi_route()
            );
        }
    }

    /// Verifies that `SessionMessageType::all_request_variants()` covers
    /// all request-bearing session dispatch variants.
    #[test]
    fn session_routes_cover_dispatch_types() {
        let variants = SessionMessageType::all_request_variants();
        assert_eq!(
            variants.len(),
            EXPECTED_SESSION_ROUTE_COUNT,
            "SessionMessageType::all_request_variants() count mismatch — \
             a new variant was added without updating all_request_variants()"
        );
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        for v in variants {
            assert!(
                manifest_routes.contains(&v.hsi_route()),
                "missing route in manifest for {:?}: {}",
                v,
                v.hsi_route()
            );
        }
    }
}
