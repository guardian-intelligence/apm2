//! Golden test vectors for HSI Contract Manifest determinism verification.
//!
//! This module contains golden vectors that verify the deterministic encoding
//! of the `HSIContractManifestV1` artifact. Each vector consists of:
//!
//! 1. A manifest constructed from the dispatch registry
//! 2. The expected canonical bytes (hex-encoded)
//! 3. The expected domain-separated BLAKE3 hash
//!
//! # Purpose
//!
//! Golden vectors serve multiple purposes:
//!
//! - **Determinism verification**: Ensure encoding produces identical bytes
//!   across versions, platforms, and library updates
//! - **Contract stability**: Verify that `cli_contract_hash` is stable when
//!   dispatch registry is unchanged
//! - **Cross-platform consistency**: Ensure wire format is consistent
//!   regardless of compilation target
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1: `HSIContractManifestV1`
//! - RFC-0020 section 3.1.1: Generation and determinism
//! - RFC-0020 section 1.5.2: Domain separation
//! - REQ-0001: Manifest generation deterministic across repeat builds
//! - EVID-0001: HSI contract manifest determinism evidence

/// A golden test vector for the HSI contract manifest.
pub struct GoldenVector {
    /// Human-readable name for the vector.
    pub name: &'static str,
    /// Contract reference.
    pub contract: &'static str,
    /// Expected domain-separated BLAKE3 hash (hex-encoded, no prefix).
    pub expected_hash: &'static str,
}

/// Golden vector: full manifest from dispatch registry with test CLI version.
///
/// This vector pins the manifest hash for the current dispatch registry.
/// If the registry changes (routes added/removed/modified), this hash
/// MUST be updated intentionally.
pub const MANIFEST_FULL_VECTOR: GoldenVector = GoldenVector {
    name: "manifest_full_registry",
    contract: "CTR-0001",
    // This hash is computed from the full dispatch registry with test CLI
    // version "0.9.0" and zero build hash. It MUST be updated when routes
    // are added, removed, or their semantics change.
    expected_hash: "5fd32e6d97f638e963c49871e1e0bab50cc7a7f4ddb1c968ecdac96af1d49194",
};

/// Golden vector: minimal manifest with a single route.
///
/// This vector pins the encoding format for a minimal manifest. It is
/// independent of the dispatch registry and should rarely change.
pub const MANIFEST_MINIMAL_VECTOR: GoldenVector = GoldenVector {
    name: "manifest_minimal_single_route",
    contract: "CTR-0001",
    // Computed from a single-route manifest with known fields.
    expected_hash: "4c6a6f64a3fd26e1e4b6447d0f64784be8e7135dfdc6c588758f4412478ac5d6",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsi_contract::manifest::*;
    use crate::hsi_contract::registry::build_manifest;

    fn test_cli_version() -> CliVersion {
        CliVersion {
            semver: "0.9.0".to_string(),
            build_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    fn minimal_manifest() -> HsiContractManifestV1 {
        HsiContractManifestV1 {
            schema: SCHEMA_ID.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            cli_version: CliVersion {
                semver: "1.0.0".to_string(),
                build_hash:
                    "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
            },
            routes: vec![HsiRouteEntry {
                id: "TEST_ROUTE".to_string(),
                route: "hsi.test.route".to_string(),
                stability: StabilityClass::Stable,
                request_schema: "apm2.test_request.v1".to_string(),
                response_schema: "apm2.test_response.v1".to_string(),
                semantics: HsiRouteSemantics {
                    authoritative: true,
                    idempotency: IdempotencyRequirement::Required,
                    receipt_required: true,
                },
            }],
        }
    }

    /// Prints the actual hashes for updating golden vectors.
    ///
    /// Run with `cargo test -p apm2-daemon golden_vector_discovery --
    /// --nocapture` to see the hash values that should be placed in the
    /// golden vectors.
    #[test]
    fn golden_vector_discovery() {
        let full_manifest =
            build_manifest(test_cli_version()).expect("manifest build must succeed");
        let full_hash = full_manifest.content_hash();
        let full_hex = &full_hash[7..]; // strip "blake3:" prefix
        eprintln!("=== GOLDEN VECTOR DISCOVERY ===");
        eprintln!("Full manifest hash:    {full_hex}");
        eprintln!("Full manifest routes:  {}", full_manifest.routes.len());

        let min_manifest = minimal_manifest();
        let min_hash = min_manifest.content_hash();
        let min_hex = &min_hash[7..];
        eprintln!("Minimal manifest hash: {min_hex}");
    }

    #[test]
    fn full_manifest_determinism() {
        let m1 = build_manifest(test_cli_version()).expect("build 1");
        let m2 = build_manifest(test_cli_version()).expect("build 2");
        assert_eq!(
            m1.content_hash(),
            m2.content_hash(),
            "manifest hash must be deterministic across builds"
        );
        assert_eq!(
            m1.canonical_bytes(),
            m2.canonical_bytes(),
            "canonical bytes must be deterministic across builds"
        );
    }

    #[test]
    fn full_manifest_golden_hash() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let hash = manifest.content_hash();
        let hex = &hash[7..]; // strip "blake3:"
        assert_eq!(
            hex, MANIFEST_FULL_VECTOR.expected_hash,
            "full manifest golden hash mismatch — did the dispatch registry change? \
             Update MANIFEST_FULL_VECTOR.expected_hash if the change is intentional."
        );
    }

    #[test]
    fn minimal_manifest_golden_hash() {
        let manifest = minimal_manifest();
        let hash = manifest.content_hash();
        let hex = &hash[7..];
        assert_eq!(
            hex, MANIFEST_MINIMAL_VECTOR.expected_hash,
            "minimal manifest golden hash mismatch — did the encoding format change? \
             Update MANIFEST_MINIMAL_VECTOR.expected_hash if the change is intentional."
        );
    }

    #[test]
    fn canonical_bytes_are_nonempty() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let bytes = manifest.canonical_bytes();
        assert!(
            bytes.len() > 100,
            "canonical bytes too short: {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn content_hash_is_valid_blake3() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let hash = manifest.content_hash();
        assert!(hash.starts_with("blake3:"), "hash must start with blake3:");
        let hex = &hash[7..];
        assert_eq!(hex.len(), 64, "BLAKE3 hex must be 64 chars");
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be valid hex"
        );
    }

    #[test]
    fn content_hash_bytes_matches_text() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let hash_text = manifest.content_hash();
        let hash_bytes = manifest.content_hash_bytes();
        let hex_from_bytes = hex::encode(hash_bytes);
        assert_eq!(
            &hash_text[7..],
            hex_from_bytes,
            "text and bytes hash forms must match"
        );
    }
}
