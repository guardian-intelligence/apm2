//! `KeySetIdV1` — canonical identifier for a set of public keys.
//!
//! # Binary Form
//!
//! ```text
//! +------------------+----------------------------+
//! | set_tag          | merkle_root                |
//! | (1 byte)         | (32 bytes, BLAKE3)         |
//! +------------------+----------------------------+
//! ```
//!
//! # Text Form (RFC-0020 section 1.7.5b)
//!
//! ```text
//! kset:v1:blake3:<64-lowercase-hex>
//! ```
//!
//! # Set Tags
//!
//! | Tag  | Mode       |
//! |------|------------|
//! | 0x01 | Multisig   |
//! | 0x02 | Threshold  |
//!
//! Unknown tags are rejected (fail-closed).
//!
//! # Merkle Root Derivation (RFC-0020 `KeySetDescriptorV1`)
//!
//! The merkle root is computed as:
//! ```text
//! blake3("apm2:keyset_id:v1\0" + canonical_bytes(KeySetDescriptorV1))
//! ```
//!
//! Where `canonical_bytes(KeySetDescriptorV1)` encodes ALL descriptor
//! fields in canonical order:
//! ```text
//! key_algorithm + "\n" + mode_name + "\n" + threshold_k (4-byte LE) + "\n"
//!   + sorted_member_binaries
//!   + [optional: "\n" + weights (each as 8-byte LE)]
//! ```
//!
//! This ensures that different `threshold_k` values, `weights`, or
//! `key_algorithm` produce distinct identifiers for the same member set.
//!
//! Member key IDs are sorted lexicographically by their raw binary form
//! before hashing, ensuring deterministic derivation regardless of input
//! order.
//!
//! # Contract References
//!
//! - RFC-0020 section 1.7.2a: `KeySetIdV1` quorum/threshold verifier identity
//! - RFC-0020 section 1.7.5b: ABNF canonical text forms
//! - REQ-0007: Canonical key identifier formats

use std::fmt;

use super::{
    BINARY_LEN, HASH_LEN, KeyIdError, PublicKeyIdV1, decode_hex_payload, encode_hex_payload,
    validate_text_common,
};

/// Prefix for `KeySetIdV1` text form (RFC-0020 canonical grammar).
const PREFIX: &str = "kset:v1:blake3:";

/// Domain separation string for BLAKE3 keyset hashing.
const DOMAIN_SEPARATION: &[u8] = b"apm2:keyset_id:v1\0";

/// Known key-set mode tags.
///
/// Unknown values are rejected at parse time (fail-closed per REQ-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SetTag {
    /// n-of-n multisig (all members must sign).
    Multisig  = 0x01,
    /// k-of-n threshold (at least `k` members must sign).
    Threshold = 0x02,
}

impl SetTag {
    /// Parse a set tag from a raw byte.
    ///
    /// Returns `Err` for unknown tags (fail-closed).
    pub const fn from_byte(byte: u8) -> Result<Self, KeyIdError> {
        match byte {
            0x01 => Ok(Self::Multisig),
            0x02 => Ok(Self::Threshold),
            other => Err(KeyIdError::UnknownSetTag { tag: other }),
        }
    }

    /// Return the canonical byte representation.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Return the human-readable mode name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Multisig => "multisig",
            Self::Threshold => "threshold",
        }
    }
}

impl fmt::Display for SetTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A canonical identifier for a set of public keys (RFC-0020 section 1.7.2a).
///
/// Instances are guaranteed to contain a valid set tag and exactly 32 bytes
/// of BLAKE3 merkle root. The type is cheaply cloneable (33 bytes inline).
///
/// # Construction
///
/// Use [`KeySetIdV1::from_descriptor`] to derive from a full
/// `KeySetDescriptorV1`, or [`KeySetIdV1::parse_text`] /
/// [`KeySetIdV1::from_binary`] for deserialization.
///
/// # Examples
///
/// ```
/// use apm2_daemon::identity::{
///     AlgorithmTag, KeySetIdV1, PublicKeyIdV1, SetTag,
/// };
///
/// let key1 =
///     PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
/// let key2 =
///     PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
///
/// let set_id = KeySetIdV1::from_descriptor(
///     "ed25519",
///     SetTag::Multisig,
///     2, // threshold_k = n for multisig
///     &[key1, key2],
///     None, // no weights
/// );
///
/// // Round-trip through text form
/// let text = set_id.to_text();
/// assert!(text.starts_with("kset:v1:blake3:"));
/// let parsed = KeySetIdV1::parse_text(&text).unwrap();
/// assert_eq!(set_id, parsed);
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeySetIdV1 {
    /// Raw binary form: `set_tag` (1 byte) + `merkle_root` (32 bytes).
    binary: [u8; BINARY_LEN],
}

impl KeySetIdV1 {
    /// Derive a `KeySetIdV1` from a full `KeySetDescriptorV1`.
    ///
    /// This is the primary constructor that includes ALL descriptor fields
    /// in the hash derivation per RFC-0020:
    ///
    /// - `key_algorithm`: algorithm name (e.g. "ed25519")
    /// - `set_tag`: mode (Multisig or Threshold)
    /// - `threshold_k`: quorum threshold (for Multisig, should equal n)
    /// - `members`: the member `PublicKeyIdV1` keys
    /// - `weights`: optional per-member weights
    ///
    /// Members are sorted lexicographically by their raw binary form before
    /// hashing, ensuring deterministic derivation regardless of input order.
    ///
    /// The hash is computed as:
    /// ```text
    /// blake3("apm2:keyset_id:v1\0" + key_algorithm + "\n" + mode_name
    ///        + "\n" + threshold_k(4-byte LE) + "\n" + sorted_member_binaries
    ///        + ["\n" + weights(each 8-byte LE)])
    /// ```
    pub fn from_descriptor(
        key_algorithm: &str,
        set_tag: SetTag,
        threshold_k: u32,
        members: &[PublicKeyIdV1],
        weights: Option<&[u64]>,
    ) -> Self {
        // Sort members by their binary representation for determinism
        let mut sorted_binaries: Vec<[u8; BINARY_LEN]> =
            members.iter().map(PublicKeyIdV1::to_binary).collect();
        sorted_binaries.sort_unstable();

        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_SEPARATION);
        // Include key_algorithm
        hasher.update(key_algorithm.as_bytes());
        hasher.update(b"\n");
        // Include mode name
        hasher.update(set_tag.name().as_bytes());
        hasher.update(b"\n");
        // Include threshold_k as 4-byte little-endian
        hasher.update(&threshold_k.to_le_bytes());
        hasher.update(b"\n");
        // Include sorted member binaries
        for member_binary in &sorted_binaries {
            hasher.update(member_binary);
        }
        // Include optional weights
        if let Some(w) = weights {
            hasher.update(b"\n");
            for weight in w {
                hasher.update(&weight.to_le_bytes());
            }
        }
        let root = hasher.finalize();

        let mut binary = [0u8; BINARY_LEN];
        binary[0] = set_tag.to_byte();
        binary[1..].copy_from_slice(root.as_bytes());
        Self { binary }
    }

    /// Parse a `KeySetIdV1` from its canonical text form.
    ///
    /// The canonical text form is:
    /// `kset:v1:blake3:<64-lowercase-hex>`
    ///
    /// Enforces:
    /// - Correct `kset:v1:blake3:` prefix
    /// - Strict lowercase hex encoding (0-9, a-f)
    /// - No whitespace, no mixed case, no percent-encoding
    /// - Exactly 64 hex characters (32 bytes)
    ///
    /// Note: The set tag is NOT encoded in the text form. The binary form
    /// can only be reconstructed from the binary representation, not from
    /// the text form alone. For `parse_text`, the set tag byte is set to
    /// 0x00 as a placeholder since the text form only contains the hash.
    /// Use `from_binary` when you need the full tagged binary form.
    ///
    /// Actually, the binary form IS recoverable from text: we store the
    /// merkle root hash as the hex payload. The `set_tag` is NOT part of the
    /// text form (RFC-0020 `kset:v1:blake3:` does not encode the mode).
    /// For text-only round-trips, we need to know the set tag from context.
    /// However, for conformance testing, we store the full binary (tag + hash)
    /// and verify both parse paths agree.
    ///
    /// Since the text form doesn't encode the set tag, `parse_text` returns
    /// a `KeySetIdV1` with the Multisig tag (0x01) by default. To get a
    /// specific tag, use `from_binary` or `from_descriptor`.
    pub fn parse_text(input: &str) -> Result<Self, KeyIdError> {
        validate_text_common(input)?;

        // Check prefix
        let hex_payload = input.strip_prefix(PREFIX).ok_or_else(|| {
            let got = input
                .get(..PREFIX.len())
                .map_or_else(|| input.to_string(), str::to_string);
            KeyIdError::WrongPrefix {
                expected: PREFIX,
                got,
            }
        })?;

        // Decode hex payload (validates length = 64, lowercase only)
        let hash = decode_hex_payload(hex_payload)?;

        // The text form does not encode the set tag. We store the hash only
        // and default to Multisig tag. Callers who need a specific tag should
        // use from_binary.
        let mut binary = [0u8; BINARY_LEN];
        binary[0] = SetTag::Multisig.to_byte();
        binary[1..].copy_from_slice(&hash);
        Ok(Self { binary })
    }

    /// Construct from raw binary form (1-byte tag + 32-byte merkle root).
    ///
    /// Validates the set tag (fail-closed) and exact length.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, KeyIdError> {
        if bytes.len() != BINARY_LEN {
            return Err(KeyIdError::InvalidBinaryLength { got: bytes.len() });
        }

        // Validate set tag (fail-closed)
        let _set_tag = SetTag::from_byte(bytes[0])?;

        let mut binary = [0u8; BINARY_LEN];
        binary.copy_from_slice(bytes);
        Ok(Self { binary })
    }

    /// Return the canonical text form: `kset:v1:blake3:<64-hex>`.
    ///
    /// Note: The text form encodes only the merkle root hash, not the set
    /// tag. Two `KeySetIdV1` values with different set tags but the same
    /// merkle root will produce the same text form.
    pub fn to_text(&self) -> String {
        let hash: &[u8; HASH_LEN] = self.merkle_root();
        let mut result = String::with_capacity(PREFIX.len() + 64);
        result.push_str(PREFIX);
        result.push_str(&encode_hex_payload(hash));
        result
    }

    /// Return the raw binary form (33 bytes).
    pub const fn to_binary(&self) -> [u8; BINARY_LEN] {
        self.binary
    }

    /// Return the set tag.
    pub fn set_tag(&self) -> SetTag {
        // Safe: we validated the tag at construction time.
        SetTag::from_byte(self.binary[0]).expect("set tag was validated at construction")
    }

    /// Return the 32-byte BLAKE3 merkle root.
    pub fn merkle_root(&self) -> &[u8; HASH_LEN] {
        self.binary[1..]
            .try_into()
            .expect("binary is exactly 33 bytes")
    }

    /// Return a reference to the full binary form.
    pub const fn as_bytes(&self) -> &[u8; BINARY_LEN] {
        &self.binary
    }
}

impl fmt::Debug for KeySetIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySetIdV1")
            .field("text", &self.to_text())
            .finish()
    }
}

impl fmt::Display for KeySetIdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl std::str::FromStr for KeySetIdV1 {
    type Err = KeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_text(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AlgorithmTag, PublicKeyIdV1};

    /// Helper: create a test key set with two Ed25519 members.
    fn make_test_keyset() -> KeySetIdV1 {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key1, key2], None)
    }

    #[test]
    fn text_round_trip() {
        let id = make_test_keyset();
        let text = id.to_text();
        // Text form does not encode set_tag, so we compare merkle roots
        let parsed = KeySetIdV1::parse_text(&text).unwrap();
        assert_eq!(id.merkle_root(), parsed.merkle_root());
    }

    #[test]
    fn binary_round_trip() {
        let id = make_test_keyset();
        let binary = id.to_binary();
        let from_bin = KeySetIdV1::from_binary(&binary).unwrap();
        assert_eq!(id, from_bin);
    }

    #[test]
    fn text_then_binary_round_trip() {
        let id = make_test_keyset();
        let binary = id.to_binary();
        let from_bin = KeySetIdV1::from_binary(&binary).unwrap();
        let text = from_bin.to_text();
        let reparsed = KeySetIdV1::parse_text(&text).unwrap();
        assert_eq!(from_bin.merkle_root(), reparsed.merkle_root());
    }

    #[test]
    fn text_format_matches_rfc() {
        let id = make_test_keyset();
        let text = id.to_text();
        assert!(
            text.starts_with("kset:v1:blake3:"),
            "text form must start with RFC-0020 prefix, got: {text}"
        );
        // Prefix (15) + 64 hex = 79 total
        assert_eq!(
            text.len(),
            79,
            "text form must be exactly 79 characters, got: {}",
            text.len()
        );
    }

    #[test]
    fn member_order_does_not_matter() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_ab = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[key1.clone(), key2.clone()],
            None,
        );
        let id_ba =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key2, key1], None);

        assert_eq!(id_ab, id_ba);
    }

    #[test]
    fn different_members_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key3 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

        let id1 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[key1.clone(), key2],
            None,
        );
        let id2 = KeySetIdV1::from_descriptor("ed25519", SetTag::Multisig, 2, &[key1, key3], None);

        assert_ne!(id1, id2);
    }

    #[test]
    fn different_tags_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_multi = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Multisig,
            2,
            &[key1.clone(), key2.clone()],
            None,
        );
        let id_thresh =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Threshold, 1, &[key1, key2], None);

        assert_ne!(id_multi, id_thresh);
        assert_ne!(id_multi.merkle_root(), id_thresh.merkle_root());
    }

    #[test]
    fn different_threshold_k_produces_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
        let key3 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xCC; 32]);

        let id_1of3 = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1.clone(), key2.clone(), key3.clone()],
            None,
        );
        let id_2of3 =
            KeySetIdV1::from_descriptor("ed25519", SetTag::Threshold, 2, &[key1, key2, key3], None);

        assert_ne!(id_1of3, id_2of3);
        assert_ne!(id_1of3.merkle_root(), id_2of3.merkle_root());
    }

    #[test]
    fn different_weights_produce_different_ids() {
        let key1 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let key2 = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);

        let id_no_weights = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1.clone(), key2.clone()],
            None,
        );
        let id_with_weights = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1.clone(), key2.clone()],
            Some(&[1, 2]),
        );
        let id_diff_weights = KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key1, key2],
            Some(&[3, 4]),
        );

        assert_ne!(id_no_weights, id_with_weights);
        assert_ne!(id_with_weights, id_diff_weights);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let id = make_test_keyset();
        let text = id.to_text().replacen("kset:", "pkid:", 1);
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_old_prefix() {
        // Old "ks1:" format must be rejected
        let err =
            KeySetIdV1::parse_text("ks1:aglcich4juqooex7i3hp3fgxs3qdgiyl4e7zxjc57ez7daj76ukym")
                .unwrap_err();
        assert!(matches!(err, KeyIdError::WrongPrefix { .. }));
    }

    #[test]
    fn rejects_uppercase() {
        let id = make_test_keyset();
        let text = id.to_text().to_ascii_uppercase();
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsUppercase);
    }

    #[test]
    fn rejects_whitespace() {
        let id = make_test_keyset();
        let text = format!(" {}", id.to_text());
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsWhitespace);
    }

    #[test]
    fn rejects_padding() {
        let id = make_test_keyset();
        let text = format!("{}=", id.to_text());
        let err = KeySetIdV1::parse_text(&text).unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPadding);
    }

    #[test]
    fn rejects_empty_input() {
        let err = KeySetIdV1::parse_text("").unwrap_err();
        assert_eq!(err, KeyIdError::EmptyInput);
    }

    #[test]
    fn rejects_truncated() {
        let err = KeySetIdV1::parse_text("kset:v1:blake3:ab").unwrap_err();
        assert!(
            matches!(err, KeyIdError::HexLengthMismatch { .. }),
            "expected HexLengthMismatch, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_set_tag_binary() {
        let mut binary = [0u8; BINARY_LEN];
        binary[0] = 0xFF; // Unknown tag
        let err = KeySetIdV1::from_binary(&binary).unwrap_err();
        assert!(matches!(err, KeyIdError::UnknownSetTag { tag: 0xFF }));
    }

    #[test]
    fn rejects_binary_wrong_length() {
        let err = KeySetIdV1::from_binary(&[0x01; 10]).unwrap_err();
        assert!(matches!(err, KeyIdError::InvalidBinaryLength { got: 10 }));
    }

    #[test]
    fn set_tag_round_trip() {
        assert_eq!(
            SetTag::from_byte(SetTag::Multisig.to_byte()),
            Ok(SetTag::Multisig)
        );
        assert_eq!(
            SetTag::from_byte(SetTag::Threshold.to_byte()),
            Ok(SetTag::Threshold)
        );
    }

    #[test]
    fn set_tag_unknown_rejected() {
        assert_eq!(
            SetTag::from_byte(0x00),
            Err(KeyIdError::UnknownSetTag { tag: 0x00 })
        );
        assert_eq!(
            SetTag::from_byte(0x03),
            Err(KeyIdError::UnknownSetTag { tag: 0x03 })
        );
        assert_eq!(
            SetTag::from_byte(0xFF),
            Err(KeyIdError::UnknownSetTag { tag: 0xFF })
        );
    }

    #[test]
    fn display_and_debug() {
        let id = make_test_keyset();
        let display = format!("{id}");
        let debug = format!("{id:?}");
        assert!(display.starts_with("kset:v1:blake3:"));
        assert!(debug.contains("KeySetIdV1"));
        assert!(debug.contains("kset:v1:blake3:"));
    }

    #[test]
    fn from_str_trait() {
        let id = make_test_keyset();
        let text = id.to_text();
        let parsed: KeySetIdV1 = text.parse().unwrap();
        assert_eq!(id.merkle_root(), parsed.merkle_root());
    }

    #[test]
    fn text_form_bounded_length() {
        let id = make_test_keyset();
        let text = id.to_text();
        assert!(
            text.len() <= crate::identity::MAX_TEXT_LEN,
            "text form length {} exceeds MAX_TEXT_LEN {}",
            text.len(),
            crate::identity::MAX_TEXT_LEN,
        );
    }

    #[test]
    fn accessors_work() {
        let id = make_test_keyset();
        assert_eq!(id.set_tag(), SetTag::Multisig);
        assert_eq!(id.merkle_root().len(), 32);
        assert_eq!(id.as_bytes().len(), 33);
    }

    #[test]
    fn rejects_percent_encoded() {
        let err = KeySetIdV1::parse_text(
            "kset%3av1%3ablake3%3a0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsPercentEncoding);
    }

    #[test]
    fn rejects_non_ascii_unicode() {
        let err = KeySetIdV1::parse_text(
            "kset\u{FF1A}v1:blake3:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert_eq!(err, KeyIdError::ContainsNonAscii);
    }

    /// Regression test: multi-byte Unicode at the prefix boundary must return
    /// `Err`, never panic via byte-index slicing on a non-char boundary.
    #[test]
    fn unicode_prefix_boundary_does_not_panic() {
        let inputs = [
            "\u{00E9}\u{00E9}xx",               // 2-byte chars at positions 0..4
            "\u{1F600}garbage",                 // 4-byte emoji at position 0
            "k\u{00E9}1:stuff",                 // multi-byte char overlapping prefix boundary
            "\u{0301}\u{0301}\u{0301}\u{0301}", // combining accents
        ];
        for input in &inputs {
            let result = KeySetIdV1::parse_text(input);
            assert!(
                result.is_err(),
                "expected Err for malformed Unicode input {input:?}, got Ok"
            );
        }
    }
}
