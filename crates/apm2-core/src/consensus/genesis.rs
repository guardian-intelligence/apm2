//! Consensus genesis adoption and validation.
//!
//! This module implements genesis creation for the consensus layer that adopts
//! the existing ledger head hash as the epoch-0 `prev_hash`. It provides
//! validation of genesis signatures and rejection of join attempts on mismatch.
//!
//! # Protocol
//!
//! 1. Genesis block is created by adopting the current ledger head hash
//! 2. Genesis is signed by the T0 (root) key
//! 3. Joining nodes verify the genesis signature against the T0 public key
//! 4. Nodes reject join if genesis doesn't match
//! 5. Join attempts are rate-limited per source/identity
//! 6. Join requests require quorum-signed invitation tokens
//!
//! # Security Invariants
//!
//! - INV-0030: Genesis signature verified against T0 key using constant-time
//!   comparison
//! - INV-0031: Join attempts rate-limited per source IP or identity
//! - INV-0032: Genesis mismatch causes join rejection (fail-closed)
//! - INV-0033: Invitation tokens require quorum signatures (2f+1)
//!
//! # Design Rationale (RFC-0014)
//!
//! The consensus genesis "adopts" rather than "creates" a new hash because:
//! - Existing ledger history is preserved without rehashing
//! - Epoch-0 consensus builds on top of the existing local ledger
//! - This enables incremental migration to consensus without data loss
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::genesis::{GenesisConfig, Genesis};
//!
//! // Create genesis adopting current ledger head
//! let config = GenesisConfig::builder()
//!     .namespace("kernel")
//!     .ledger_head_hash(current_head_hash)
//!     .t0_public_key(t0_key)
//!     .build()?;
//!
//! let genesis = Genesis::create_and_sign(&config, &t0_signer)?;
//!
//! // Joining node validates genesis
//! genesis.verify()?;
//! ```

// Timestamps won't overflow u64 until the year 2554.
// const fn on builder methods with non-Copy types isn't stable yet.
#![allow(clippy::cast_possible_truncation, clippy::missing_const_for_fn)]

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::crypto::{
    HASH_SIZE, Hash, Signature, Signer, SignerError, VerifyingKey, parse_signature,
    parse_verifying_key, verify_signature,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum namespace length (CTR-1303: Bounded Stores).
pub const MAX_NAMESPACE_LEN: usize = 128;

/// Maximum genesis metadata length in bytes.
pub const MAX_METADATA_LEN: usize = 4096;

/// Maximum number of validator signatures in a quorum certificate.
pub const MAX_QUORUM_SIGNATURES: usize = 128;

/// Minimum quorum size (2f+1 where f=1 means 3 validators minimum).
pub const MIN_QUORUM_SIZE: usize = 3;

/// Rate limit window for join attempts.
pub const JOIN_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Maximum join attempts per source within the rate limit window.
pub const MAX_JOIN_ATTEMPTS_PER_MINUTE: usize = 10;

/// Maximum tracked sources for rate limiting (CTR-1303: Bounded Stores).
pub const MAX_RATE_LIMIT_SOURCES: usize = 1024;

/// Invitation token validity duration.
pub const INVITATION_TOKEN_VALIDITY: Duration = Duration::from_secs(3600);

/// Maximum invitation token nonce length.
pub const MAX_INVITATION_NONCE_LEN: usize = 64;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during genesis operations.
#[derive(Debug, Error)]
pub enum GenesisError {
    /// Invalid namespace.
    #[error("invalid namespace: {0}")]
    InvalidNamespace(String),

    /// Invalid hash size.
    #[error("invalid hash size: expected {expected}, got {actual}")]
    InvalidHashSize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },

    /// Signature error.
    #[error("signature error: {0}")]
    Signature(#[from] SignerError),

    /// Genesis signature verification failed.
    #[error("genesis signature verification failed")]
    SignatureVerificationFailed,

    /// Genesis mismatch with remote node.
    #[error("genesis mismatch: local hash {local_hash} != remote hash {remote_hash}")]
    GenesisMismatch {
        /// Local genesis hash.
        local_hash: String,
        /// Remote genesis hash.
        remote_hash: String,
    },

    /// Rate limit exceeded for join attempts.
    #[error("join rate limit exceeded: {attempts} attempts in {window_secs}s")]
    JoinRateLimitExceeded {
        /// Number of attempts made.
        attempts: usize,
        /// Window duration in seconds.
        window_secs: u64,
    },

    /// Invalid invitation token.
    #[error("invalid invitation token: {0}")]
    InvalidInvitationToken(String),

    /// Invitation token expired.
    #[error("invitation token expired: token issued at {issued_at}, now {now}")]
    InvitationTokenExpired {
        /// When the token was issued (Unix timestamp).
        issued_at: u64,
        /// Current time (Unix timestamp).
        now: u64,
    },

    /// Insufficient quorum signatures on invitation token.
    #[error("insufficient quorum: have {have} signatures, need {need}")]
    InsufficientQuorum {
        /// Number of valid signatures present.
        have: usize,
        /// Number of signatures required.
        need: usize,
    },

    /// Duplicate validator signature.
    #[error("duplicate validator signature: {validator_id}")]
    DuplicateSignature {
        /// The validator ID that signed twice.
        validator_id: String,
    },

    /// Invalid validator in quorum.
    #[error("invalid validator: {validator_id}")]
    InvalidValidator {
        /// The invalid validator ID.
        validator_id: String,
    },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Maximum metadata size exceeded.
    #[error("metadata too large: {size} bytes exceeds maximum {max} bytes")]
    MetadataTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// Genesis Configuration
// =============================================================================

/// Configuration for creating a genesis block.
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    /// Namespace this genesis is for.
    pub namespace: String,
    /// The ledger head hash to adopt as epoch-0 `prev_hash`.
    pub ledger_head_hash: Hash,
    /// T0 (root) public key for signature verification.
    pub t0_public_key: VerifyingKey,
    /// Epoch number (always 0 for genesis).
    pub epoch: u64,
    /// Optional metadata (e.g., version, creation reason).
    pub metadata: Option<Vec<u8>>,
}

impl GenesisConfig {
    /// Creates a new builder for genesis configuration.
    #[must_use]
    pub fn builder() -> GenesisConfigBuilder {
        GenesisConfigBuilder::new()
    }
}

/// Builder for genesis configuration.
#[derive(Debug, Default)]
pub struct GenesisConfigBuilder {
    namespace: Option<String>,
    ledger_head_hash: Option<Hash>,
    t0_public_key: Option<VerifyingKey>,
    metadata: Option<Vec<u8>>,
}

impl GenesisConfigBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the namespace.
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Sets the ledger head hash to adopt.
    #[must_use]
    pub fn ledger_head_hash(mut self, hash: Hash) -> Self {
        self.ledger_head_hash = Some(hash);
        self
    }

    /// Sets the ledger head hash from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash is not exactly 32 bytes.
    pub fn ledger_head_hash_bytes(mut self, bytes: &[u8]) -> Result<Self, GenesisError> {
        if bytes.len() != HASH_SIZE {
            return Err(GenesisError::InvalidHashSize {
                expected: HASH_SIZE,
                actual: bytes.len(),
            });
        }
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(bytes);
        self.ledger_head_hash = Some(hash);
        Ok(self)
    }

    /// Sets the T0 public key.
    #[must_use]
    pub fn t0_public_key(mut self, key: VerifyingKey) -> Self {
        self.t0_public_key = Some(key);
        self
    }

    /// Sets the T0 public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid.
    pub fn t0_public_key_bytes(mut self, bytes: &[u8]) -> Result<Self, GenesisError> {
        let key = parse_verifying_key(bytes)?;
        self.t0_public_key = Some(key);
        Ok(self)
    }

    /// Sets optional metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata exceeds the maximum size.
    pub fn metadata(mut self, metadata: Vec<u8>) -> Result<Self, GenesisError> {
        if metadata.len() > MAX_METADATA_LEN {
            return Err(GenesisError::MetadataTooLarge {
                size: metadata.len(),
                max: MAX_METADATA_LEN,
            });
        }
        self.metadata = Some(metadata);
        Ok(self)
    }

    /// Builds the genesis configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or invalid.
    pub fn build(self) -> Result<GenesisConfig, GenesisError> {
        let namespace = self
            .namespace
            .ok_or_else(|| GenesisError::Configuration("namespace required".into()))?;

        if namespace.is_empty() {
            return Err(GenesisError::InvalidNamespace("empty namespace".into()));
        }
        if namespace.len() > MAX_NAMESPACE_LEN {
            return Err(GenesisError::InvalidNamespace(format!(
                "namespace too long: {} > {MAX_NAMESPACE_LEN}",
                namespace.len()
            )));
        }

        let ledger_head_hash = self
            .ledger_head_hash
            .ok_or_else(|| GenesisError::Configuration("ledger_head_hash required".into()))?;

        let t0_public_key = self
            .t0_public_key
            .ok_or_else(|| GenesisError::Configuration("t0_public_key required".into()))?;

        Ok(GenesisConfig {
            namespace,
            ledger_head_hash,
            t0_public_key,
            epoch: 0, // Always 0 for genesis
            metadata: self.metadata,
        })
    }
}

// =============================================================================
// Genesis Block
// =============================================================================

/// The genesis block for consensus epoch 0.
///
/// This struct represents the starting point for consensus. It adopts the
/// existing ledger head hash rather than creating a new chain, preserving
/// history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// Namespace this genesis is for.
    pub namespace: String,
    /// The adopted ledger head hash (epoch-0 `prev_hash`).
    #[serde(with = "hash_serde")]
    pub prev_hash: Hash,
    /// The genesis block hash (computed over namespace + `prev_hash` +
    /// metadata).
    #[serde(with = "hash_serde")]
    pub genesis_hash: Hash,
    /// Epoch number (always 0).
    pub epoch: u64,
    /// Timestamp when genesis was created (nanoseconds since Unix epoch).
    pub created_at_ns: u64,
    /// T0 signature over the genesis hash.
    #[serde(with = "signature_serde")]
    pub signature: Signature,
    /// T0 public key (for verification).
    #[serde(with = "verifying_key_serde")]
    pub t0_public_key: VerifyingKey,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<u8>>,
}

impl Genesis {
    /// Creates and signs a new genesis block.
    ///
    /// # Arguments
    ///
    /// * `config` - Genesis configuration with namespace, ledger head hash,
    ///   etc.
    /// * `t0_signer` - The T0 (root) signer for signing the genesis.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn create_and_sign(
        config: &GenesisConfig,
        t0_signer: &Signer,
    ) -> Result<Self, GenesisError> {
        // Verify the signer's public key matches the config's T0 key
        let signer_pub = t0_signer.verifying_key();
        let config_pub = config.t0_public_key;
        let signer_bytes = signer_pub.as_bytes();
        let config_bytes = config_pub.as_bytes();
        let keys_match: bool = signer_bytes.ct_eq(config_bytes).into();

        if !keys_match {
            return Err(GenesisError::Configuration(
                "signer public key does not match config t0_public_key".into(),
            ));
        }

        let created_at_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Compute genesis hash
        let genesis_hash = Self::compute_genesis_hash(
            &config.namespace,
            &config.ledger_head_hash,
            config.epoch,
            created_at_ns,
            config.metadata.as_deref(),
        );

        // Sign the genesis hash
        let signature = t0_signer.sign(&genesis_hash);

        Ok(Self {
            namespace: config.namespace.clone(),
            prev_hash: config.ledger_head_hash,
            genesis_hash,
            epoch: config.epoch,
            created_at_ns,
            signature,
            t0_public_key: config.t0_public_key,
            metadata: config.metadata.clone(),
        })
    }

    /// Computes the genesis hash from its components.
    ///
    /// The hash is computed as: `BLAKE3(namespace || prev_hash || epoch ||
    /// created_at_ns || metadata)`
    #[must_use]
    pub fn compute_genesis_hash(
        namespace: &str,
        prev_hash: &Hash,
        epoch: u64,
        created_at_ns: u64,
        metadata: Option<&[u8]>,
    ) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(namespace.as_bytes());
        hasher.update(prev_hash);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&created_at_ns.to_le_bytes());
        if let Some(meta) = metadata {
            hasher.update(meta);
        }
        *hasher.finalize().as_bytes()
    }

    /// Verifies the genesis signature against the embedded T0 public key.
    ///
    /// # Security
    ///
    /// Uses constant-time comparison internally (via ed25519-dalek).
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self) -> Result<(), GenesisError> {
        // Recompute the genesis hash to verify
        let computed_hash = Self::compute_genesis_hash(
            &self.namespace,
            &self.prev_hash,
            self.epoch,
            self.created_at_ns,
            self.metadata.as_deref(),
        );

        // Verify the computed hash matches the stored hash (constant-time)
        let hashes_match: bool = computed_hash.ct_eq(&self.genesis_hash).into();
        if !hashes_match {
            return Err(GenesisError::SignatureVerificationFailed);
        }

        // Verify signature
        verify_signature(&self.t0_public_key, &self.genesis_hash, &self.signature)?;

        Ok(())
    }

    /// Verifies the genesis signature against a specific T0 public key.
    ///
    /// This is useful when you want to verify against a known T0 key rather
    /// than trusting the embedded key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or keys don't match.
    pub fn verify_with_key(&self, expected_t0_key: &VerifyingKey) -> Result<(), GenesisError> {
        // Verify the embedded key matches the expected key (constant-time)
        let embedded_bytes = self.t0_public_key.as_bytes();
        let expected_bytes = expected_t0_key.as_bytes();
        let keys_match: bool = embedded_bytes.ct_eq(expected_bytes).into();

        if !keys_match {
            return Err(GenesisError::SignatureVerificationFailed);
        }

        self.verify()
    }

    /// Compares this genesis with another for join validation.
    ///
    /// # Errors
    ///
    /// Returns `GenesisMismatch` if the genesis blocks don't match.
    pub fn validate_against(&self, remote: &Self) -> Result<(), GenesisError> {
        // Compare genesis hashes using constant-time comparison
        let hashes_match: bool = self.genesis_hash.ct_eq(&remote.genesis_hash).into();

        if !hashes_match {
            return Err(GenesisError::GenesisMismatch {
                local_hash: hex::encode(self.genesis_hash),
                remote_hash: hex::encode(remote.genesis_hash),
            });
        }

        // Also verify the remote genesis signature
        remote.verify()?;

        Ok(())
    }

    /// Serializes the genesis to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GenesisError> {
        serde_json::to_vec(self).map_err(|e| GenesisError::Serialization(e.to_string()))
    }

    /// Deserializes a genesis from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisError> {
        serde_json::from_slice(bytes).map_err(|e| GenesisError::Serialization(e.to_string()))
    }
}

// =============================================================================
// Invitation Token
// =============================================================================

/// A quorum-signed invitation token for joining the network.
///
/// Join requests require a valid invitation token signed by a quorum of
/// validators (2f+1) to prevent unauthorized nodes from joining.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationToken {
    /// The invitee's node ID (public key hash).
    pub invitee_id: String,
    /// Namespace the invitation is for.
    pub namespace: String,
    /// Genesis hash this invitation is tied to.
    #[serde(with = "hash_serde")]
    pub genesis_hash: Hash,
    /// Unique nonce to prevent replay attacks.
    pub nonce: String,
    /// When the token was issued (Unix timestamp seconds).
    pub issued_at: u64,
    /// When the token expires (Unix timestamp seconds).
    pub expires_at: u64,
    /// Validator signatures over the token content.
    pub signatures: Vec<ValidatorSignature>,
}

/// A validator's signature on an invitation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorSignature {
    /// Validator's node ID.
    pub validator_id: String,
    /// Signature bytes (hex-encoded for JSON).
    pub signature: String,
}

impl InvitationToken {
    /// Creates a new unsigned invitation token.
    ///
    /// Validators must sign this token using `add_signature()`.
    #[must_use]
    pub fn new(
        invitee_id: impl Into<String>,
        namespace: impl Into<String>,
        genesis_hash: Hash,
        nonce: impl Into<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            invitee_id: invitee_id.into(),
            namespace: namespace.into(),
            genesis_hash,
            nonce: nonce.into(),
            issued_at: now,
            expires_at: now + INVITATION_TOKEN_VALIDITY.as_secs(),
            signatures: Vec::new(),
        }
    }

    /// Computes the content hash for signing.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.invitee_id.as_bytes());
        hasher.update(self.namespace.as_bytes());
        hasher.update(&self.genesis_hash);
        hasher.update(self.nonce.as_bytes());
        hasher.update(&self.issued_at.to_le_bytes());
        hasher.update(&self.expires_at.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Adds a validator signature to the token.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator's node ID.
    /// * `signer` - The validator's signer.
    ///
    /// # Errors
    ///
    /// Returns an error if the validator has already signed.
    pub fn add_signature(
        &mut self,
        validator_id: impl Into<String>,
        signer: &Signer,
    ) -> Result<(), GenesisError> {
        let validator_id = validator_id.into();

        // Check for duplicate
        if self
            .signatures
            .iter()
            .any(|s| s.validator_id == validator_id)
        {
            return Err(GenesisError::DuplicateSignature { validator_id });
        }

        // Check bounded size
        if self.signatures.len() >= MAX_QUORUM_SIGNATURES {
            return Err(GenesisError::Configuration(format!(
                "maximum {MAX_QUORUM_SIGNATURES} signatures reached"
            )));
        }

        let content_hash = self.content_hash();
        let signature = signer.sign(&content_hash);

        self.signatures.push(ValidatorSignature {
            validator_id,
            signature: hex::encode(signature.to_bytes()),
        });

        Ok(())
    }

    /// Verifies the invitation token.
    ///
    /// # Arguments
    ///
    /// * `validator_keys` - Map of validator ID to their verifying key.
    /// * `quorum_size` - Required number of valid signatures (2f+1).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token has expired
    /// - Insufficient valid signatures
    /// - Unknown validator
    pub fn verify(
        &self,
        validator_keys: &HashMap<String, VerifyingKey>,
        quorum_size: usize,
    ) -> Result<(), GenesisError> {
        // Check nonce length
        if self.nonce.len() > MAX_INVITATION_NONCE_LEN {
            return Err(GenesisError::InvalidInvitationToken(format!(
                "nonce too long: {} > {MAX_INVITATION_NONCE_LEN}",
                self.nonce.len()
            )));
        }

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > self.expires_at {
            return Err(GenesisError::InvitationTokenExpired {
                issued_at: self.issued_at,
                now,
            });
        }

        // Verify quorum size is reasonable
        if quorum_size < MIN_QUORUM_SIZE {
            return Err(GenesisError::Configuration(format!(
                "quorum size {quorum_size} is less than minimum {MIN_QUORUM_SIZE}"
            )));
        }

        let content_hash = self.content_hash();
        let mut valid_count = 0;
        let mut seen_validators = std::collections::HashSet::new();

        for sig in &self.signatures {
            // Check for duplicate within signatures
            if !seen_validators.insert(&sig.validator_id) {
                return Err(GenesisError::DuplicateSignature {
                    validator_id: sig.validator_id.clone(),
                });
            }

            // Get validator's key
            let Some(key) = validator_keys.get(&sig.validator_id) else {
                return Err(GenesisError::InvalidValidator {
                    validator_id: sig.validator_id.clone(),
                });
            };

            // Parse and verify signature
            let sig_bytes = hex::decode(&sig.signature).map_err(|e| {
                GenesisError::InvalidInvitationToken(format!("invalid signature hex: {e}"))
            })?;

            let signature = parse_signature(&sig_bytes)?;

            if verify_signature(key, &content_hash, &signature).is_ok() {
                valid_count += 1;
            }
        }

        if valid_count < quorum_size {
            return Err(GenesisError::InsufficientQuorum {
                have: valid_count,
                need: quorum_size,
            });
        }

        Ok(())
    }

    /// Serializes the token to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GenesisError> {
        serde_json::to_vec(self).map_err(|e| GenesisError::Serialization(e.to_string()))
    }

    /// Deserializes a token from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisError> {
        serde_json::from_slice(bytes).map_err(|e| GenesisError::Serialization(e.to_string()))
    }
}

// =============================================================================
// Join Rate Limiter
// =============================================================================

/// Rate limiter for join attempts.
///
/// Implements bounded tracking of join attempts per source to enforce rate
/// limits while preventing unbounded memory growth (CTR-1303: Bounded Stores).
pub struct JoinRateLimiter {
    /// Join attempts per source.
    attempts: HashMap<String, Vec<Instant>>,
    /// Maximum attempts per window.
    max_attempts: usize,
    /// Window duration.
    window: Duration,
    /// Maximum number of tracked sources.
    max_sources: usize,
}

impl Default for JoinRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl JoinRateLimiter {
    /// Creates a new rate limiter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_settings(
            MAX_JOIN_ATTEMPTS_PER_MINUTE,
            JOIN_RATE_LIMIT_WINDOW,
            MAX_RATE_LIMIT_SOURCES,
        )
    }

    /// Creates a rate limiter with custom settings.
    #[must_use]
    pub fn with_settings(max_attempts: usize, window: Duration, max_sources: usize) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window,
            max_sources,
        }
    }

    /// Checks if a join attempt is allowed.
    ///
    /// If the maximum number of tracked sources is reached and this is a new
    /// source, the oldest entries are evicted to make room.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limit exceeded.
    pub fn check(&mut self, source: &str) -> Result<(), GenesisError> {
        let now = Instant::now();

        // If this is a new source and we're at capacity, evict old entries first
        if !self.attempts.contains_key(source) && self.attempts.len() >= self.max_sources {
            self.evict_oldest_entries(now);

            // If still at capacity after eviction, reject the request
            // This protects against DoS via unique source flooding
            if self.attempts.len() >= self.max_sources {
                return Err(GenesisError::JoinRateLimitExceeded {
                    attempts: 0,
                    window_secs: self.window.as_secs(),
                });
            }
        }

        let attempts = self.attempts.entry(source.to_string()).or_default();

        // Remove old attempts
        attempts.retain(|t| now.duration_since(*t) < self.window);

        if attempts.len() >= self.max_attempts {
            return Err(GenesisError::JoinRateLimitExceeded {
                attempts: attempts.len(),
                window_secs: self.window.as_secs(),
            });
        }

        attempts.push(now);
        Ok(())
    }

    /// Evicts entries with no recent attempts.
    fn evict_oldest_entries(&mut self, now: Instant) {
        // First, remove entries with no attempts within the window
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });

        // If still over capacity, remove entries with oldest most-recent attempt
        while self.attempts.len() >= self.max_sources {
            let oldest_key = self
                .attempts
                .iter()
                .filter_map(|(k, v)| v.last().map(|t| (k.clone(), *t)))
                .min_by_key(|(_, t)| *t)
                .map(|(k, _)| k);

            if let Some(key) = oldest_key {
                self.attempts.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Cleans up old entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });
    }

    /// Returns the number of tracked sources.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.attempts.len()
    }
}

// =============================================================================
// Genesis Validator
// =============================================================================

/// Validates genesis blocks and manages join requests.
///
/// This struct holds the local genesis and provides methods for validating
/// incoming join requests with rate limiting.
pub struct GenesisValidator {
    /// The local genesis block.
    genesis: Genesis,
    /// Rate limiter for join attempts.
    rate_limiter: JoinRateLimiter,
    /// Validator keys for invitation token verification.
    validator_keys: HashMap<String, VerifyingKey>,
    /// Required quorum size.
    quorum_size: usize,
}

impl GenesisValidator {
    /// Creates a new genesis validator.
    ///
    /// # Arguments
    ///
    /// * `genesis` - The local genesis block.
    /// * `validator_keys` - Map of validator ID to verifying key.
    /// * `quorum_size` - Required quorum size for invitation tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if the genesis is invalid.
    pub fn new(
        genesis: Genesis,
        validator_keys: HashMap<String, VerifyingKey>,
        quorum_size: usize,
    ) -> Result<Self, GenesisError> {
        // Verify the genesis on creation
        genesis.verify()?;

        Ok(Self {
            genesis,
            rate_limiter: JoinRateLimiter::new(),
            validator_keys,
            quorum_size,
        })
    }

    /// Validates a join request.
    ///
    /// # Arguments
    ///
    /// * `source` - Source identifier (IP or node ID) for rate limiting.
    /// * `remote_genesis` - The joining node's genesis.
    /// * `invitation` - The quorum-signed invitation token.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Rate limit exceeded
    /// - Genesis mismatch
    /// - Invalid invitation token
    pub fn validate_join(
        &mut self,
        source: &str,
        remote_genesis: &Genesis,
        invitation: &InvitationToken,
    ) -> Result<(), GenesisError> {
        // Check rate limit first (fail fast)
        self.rate_limiter.check(source)?;

        // Verify invitation token
        invitation.verify(&self.validator_keys, self.quorum_size)?;

        // Verify invitation is for this genesis
        let hashes_match: bool = invitation
            .genesis_hash
            .ct_eq(&self.genesis.genesis_hash)
            .into();
        if !hashes_match {
            return Err(GenesisError::InvalidInvitationToken(
                "invitation token is for a different genesis".into(),
            ));
        }

        // Validate genesis match
        self.genesis.validate_against(remote_genesis)?;

        Ok(())
    }

    /// Returns a reference to the local genesis.
    #[must_use]
    pub const fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// Cleans up stale rate limit entries.
    pub fn cleanup(&mut self) {
        self.rate_limiter.cleanup();
    }

    /// Adds a validator key.
    pub fn add_validator(&mut self, validator_id: impl Into<String>, key: VerifyingKey) {
        self.validator_keys.insert(validator_id.into(), key);
    }

    /// Removes a validator key.
    pub fn remove_validator(&mut self, validator_id: &str) {
        self.validator_keys.remove(validator_id);
    }
}

// =============================================================================
// Serde Helpers
// =============================================================================

mod hash_serde {
    use serde::{Deserialize, Deserializer, Serializer, de};

    use super::{HASH_SIZE, Hash};

    pub fn serialize<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(hash))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(de::Error::custom)?;
        if bytes.len() != HASH_SIZE {
            return Err(de::Error::custom(format!(
                "expected {HASH_SIZE} bytes, got {}",
                bytes.len()
            )));
        }
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }
}

mod signature_serde {
    use serde::{Deserialize, Deserializer, Serializer, de};

    use super::{Signature, parse_signature};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(de::Error::custom)?;
        parse_signature(&bytes).map_err(de::Error::custom)
    }
}

mod verifying_key_serde {
    use serde::{Deserialize, Deserializer, Serializer, de};

    use super::{VerifyingKey, parse_verifying_key};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(de::Error::custom)?;
        parse_verifying_key(&bytes).map_err(de::Error::custom)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_config_builder_valid() {
        let signer = Signer::generate();
        let hash = [0u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        assert_eq!(config.namespace, "kernel");
        assert_eq!(config.ledger_head_hash, hash);
        assert_eq!(config.epoch, 0);
    }

    #[test]
    fn test_genesis_config_builder_missing_namespace() {
        let signer = Signer::generate();
        let hash = [0u8; HASH_SIZE];

        let result = GenesisConfig::builder()
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build();

        assert!(matches!(result, Err(GenesisError::Configuration(_))));
    }

    #[test]
    fn test_genesis_config_builder_empty_namespace() {
        let signer = Signer::generate();
        let hash = [0u8; HASH_SIZE];

        let result = GenesisConfig::builder()
            .namespace("")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build();

        assert!(matches!(result, Err(GenesisError::InvalidNamespace(_))));
    }

    #[test]
    fn test_genesis_config_builder_long_namespace() {
        let signer = Signer::generate();
        let hash = [0u8; HASH_SIZE];

        let result = GenesisConfig::builder()
            .namespace("x".repeat(MAX_NAMESPACE_LEN + 1))
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build();

        assert!(matches!(result, Err(GenesisError::InvalidNamespace(_))));
    }

    #[test]
    fn test_genesis_create_and_sign() {
        let signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &signer).unwrap();

        assert_eq!(genesis.namespace, "kernel");
        assert_eq!(genesis.prev_hash, hash);
        assert_eq!(genesis.epoch, 0);
        assert!(genesis.created_at_ns > 0);
    }

    #[test]
    fn test_genesis_verify_valid() {
        let signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &signer).unwrap();

        assert!(genesis.verify().is_ok());
    }

    #[test]
    fn test_genesis_verify_with_wrong_key() {
        let signer = Signer::generate();
        let other_signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &signer).unwrap();

        let result = genesis.verify_with_key(&other_signer.verifying_key());
        assert!(matches!(
            result,
            Err(GenesisError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_genesis_validate_against_match() {
        let signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let genesis1 = Genesis::create_and_sign(&config, &signer).unwrap();

        // Create another genesis with same config
        // Note: created_at_ns will differ, so genesis_hash will differ
        // For matching, we need to use the same genesis
        let genesis2 = genesis1.clone();

        assert!(genesis1.validate_against(&genesis2).is_ok());
    }

    #[test]
    fn test_genesis_validate_against_mismatch() {
        let signer = Signer::generate();

        let config1 = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash([1u8; HASH_SIZE])
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let config2 = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash([2u8; HASH_SIZE])
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let genesis1 = Genesis::create_and_sign(&config1, &signer).unwrap();
        let genesis2 = Genesis::create_and_sign(&config2, &signer).unwrap();

        let result = genesis1.validate_against(&genesis2);
        assert!(matches!(result, Err(GenesisError::GenesisMismatch { .. })));
    }

    #[test]
    fn test_genesis_serialization_roundtrip() {
        let signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &signer).unwrap();

        let bytes = genesis.to_bytes().unwrap();
        let parsed = Genesis::from_bytes(&bytes).unwrap();

        assert_eq!(genesis.namespace, parsed.namespace);
        assert_eq!(genesis.prev_hash, parsed.prev_hash);
        assert_eq!(genesis.genesis_hash, parsed.genesis_hash);
        assert_eq!(genesis.epoch, parsed.epoch);
        assert_eq!(genesis.created_at_ns, parsed.created_at_ns);

        // Verify the parsed genesis is still valid
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn test_join_rate_limiter_allows_within_limit() {
        let mut limiter = JoinRateLimiter::with_settings(3, Duration::from_secs(60), 100);

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
    }

    #[test]
    fn test_join_rate_limiter_blocks_over_limit() {
        let mut limiter = JoinRateLimiter::with_settings(2, Duration::from_secs(60), 100);

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());

        let result = limiter.check("source1");
        assert!(matches!(
            result,
            Err(GenesisError::JoinRateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_join_rate_limiter_separate_sources() {
        let mut limiter = JoinRateLimiter::with_settings(2, Duration::from_secs(60), 100);

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source2").is_ok()); // Different source

        let result = limiter.check("source1");
        assert!(matches!(
            result,
            Err(GenesisError::JoinRateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_join_rate_limiter_bounded_sources() {
        let max_sources = 3;
        let mut limiter = JoinRateLimiter::with_settings(10, Duration::from_secs(60), max_sources);

        // Fill up sources
        for i in 0..max_sources {
            assert!(limiter.check(&format!("source{i}")).is_ok());
        }

        // New source should still work (eviction)
        assert!(limiter.check("new_source").is_ok());

        // Verify bounded
        assert!(limiter.source_count() <= max_sources);
    }

    #[test]
    fn test_invitation_token_create() {
        let token =
            InvitationToken::new("node-123", "kernel", [0u8; HASH_SIZE], "unique-nonce-456");

        assert_eq!(token.invitee_id, "node-123");
        assert_eq!(token.namespace, "kernel");
        assert!(token.issued_at > 0);
        assert!(token.expires_at > token.issued_at);
        assert!(token.signatures.is_empty());
    }

    #[test]
    fn test_invitation_token_add_signature() {
        let mut token =
            InvitationToken::new("node-123", "kernel", [0u8; HASH_SIZE], "unique-nonce-456");

        let signer = Signer::generate();

        assert!(token.add_signature("validator-1", &signer).is_ok());
        assert_eq!(token.signatures.len(), 1);
        assert_eq!(token.signatures[0].validator_id, "validator-1");
    }

    #[test]
    fn test_invitation_token_duplicate_signature() {
        let mut token =
            InvitationToken::new("node-123", "kernel", [0u8; HASH_SIZE], "unique-nonce-456");

        let signer = Signer::generate();

        assert!(token.add_signature("validator-1", &signer).is_ok());

        let result = token.add_signature("validator-1", &signer);
        assert!(matches!(
            result,
            Err(GenesisError::DuplicateSignature { .. })
        ));
    }

    #[test]
    fn test_invitation_token_verify_valid() {
        let genesis_hash = [0u8; HASH_SIZE];
        let mut token = InvitationToken::new("node-123", "kernel", genesis_hash, "nonce-123");

        // Create 3 validators
        let mut validator_keys: HashMap<String, VerifyingKey> = HashMap::new();
        let signers: Vec<Signer> = (0..3).map(|_| Signer::generate()).collect();

        for (i, signer) in signers.iter().enumerate() {
            let vid = format!("validator-{i}");
            validator_keys.insert(vid.clone(), signer.verifying_key());
            token.add_signature(&vid, signer).unwrap();
        }

        // Should pass with quorum of 3
        assert!(token.verify(&validator_keys, 3).is_ok());
    }

    #[test]
    fn test_invitation_token_verify_insufficient_quorum() {
        let genesis_hash = [0u8; HASH_SIZE];
        let mut token = InvitationToken::new("node-123", "kernel", genesis_hash, "nonce-123");

        // Create only 2 validators
        let mut validator_keys: HashMap<String, VerifyingKey> = HashMap::new();
        let signers: Vec<Signer> = (0..2).map(|_| Signer::generate()).collect();

        for (i, signer) in signers.iter().enumerate() {
            let vid = format!("validator-{i}");
            validator_keys.insert(vid.clone(), signer.verifying_key());
            token.add_signature(&vid, signer).unwrap();
        }

        // Should fail with quorum of 3
        let result = token.verify(&validator_keys, 3);
        assert!(matches!(
            result,
            Err(GenesisError::InsufficientQuorum { have: 2, need: 3 })
        ));
    }

    #[test]
    fn test_invitation_token_verify_unknown_validator() {
        let genesis_hash = [0u8; HASH_SIZE];
        let mut token = InvitationToken::new("node-123", "kernel", genesis_hash, "nonce-123");

        let signer = Signer::generate();
        token.add_signature("unknown-validator", &signer).unwrap();

        // Empty validator keys - unknown-validator is not in the map
        let validator_keys: HashMap<String, VerifyingKey> = HashMap::new();

        // Using MIN_QUORUM_SIZE (3) to pass the minimum check
        let result = token.verify(&validator_keys, MIN_QUORUM_SIZE);
        assert!(matches!(result, Err(GenesisError::InvalidValidator { .. })));
    }

    #[test]
    fn test_invitation_token_serialization_roundtrip() {
        let mut token =
            InvitationToken::new("node-123", "kernel", [42u8; HASH_SIZE], "unique-nonce-789");

        let signer = Signer::generate();
        token.add_signature("validator-1", &signer).unwrap();

        let bytes = token.to_bytes().unwrap();
        let parsed = InvitationToken::from_bytes(&bytes).unwrap();

        assert_eq!(token.invitee_id, parsed.invitee_id);
        assert_eq!(token.namespace, parsed.namespace);
        assert_eq!(token.genesis_hash, parsed.genesis_hash);
        assert_eq!(token.nonce, parsed.nonce);
        assert_eq!(token.signatures.len(), parsed.signatures.len());
    }

    #[test]
    fn test_genesis_with_metadata() {
        let signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];
        let metadata = b"version=1.0.0".to_vec();

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .metadata(metadata.clone())
            .unwrap()
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &signer).unwrap();

        assert_eq!(genesis.metadata, Some(metadata));
        assert!(genesis.verify().is_ok());
    }

    #[test]
    fn test_genesis_metadata_too_large() {
        let signer = Signer::generate();

        let result = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash([0u8; HASH_SIZE])
            .t0_public_key(signer.verifying_key())
            .metadata(vec![0u8; MAX_METADATA_LEN + 1]);

        assert!(matches!(result, Err(GenesisError::MetadataTooLarge { .. })));
    }
}

#[cfg(test)]
mod tck_00185_tests {
    use super::*;
    use crate::crypto::EventHasher;

    // Compile-time assertions for bounded constants
    const _: () = {
        assert!(MAX_NAMESPACE_LEN > 0);
        assert!(MAX_NAMESPACE_LEN <= 256);
        assert!(MAX_METADATA_LEN > 0);
        assert!(MAX_QUORUM_SIGNATURES > 0);
        assert!(MAX_QUORUM_SIGNATURES <= 256);
        assert!(MIN_QUORUM_SIZE >= 3);
        assert!(MAX_JOIN_ATTEMPTS_PER_MINUTE > 0);
        assert!(MAX_RATE_LIMIT_SOURCES > 0);
        assert!(MAX_INVITATION_NONCE_LEN > 0);
    };

    #[test]
    fn test_tck_00185_genesis_adopts_ledger_head_hash() {
        // Acceptance criterion: Genesis adopts existing ledger head hash
        // without rehashing history
        let signer = Signer::generate();

        // Simulate existing ledger head hash
        let ledger_head_hash = EventHasher::hash_content(b"existing ledger content");

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(ledger_head_hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &signer).unwrap();

        // Verify the genesis uses the ledger head hash as prev_hash
        assert_eq!(
            genesis.prev_hash, ledger_head_hash,
            "Genesis must adopt existing ledger head hash as prev_hash"
        );

        // Verify it doesn't rehash - the genesis_hash is different from prev_hash
        assert_ne!(
            genesis.genesis_hash, genesis.prev_hash,
            "Genesis hash should be computed over metadata, not re-hashing history"
        );
    }

    #[test]
    fn test_tck_00185_genesis_signature_verified_against_t0_key() {
        // Acceptance criterion: Genesis signature verified against T0 key
        let t0_signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(t0_signer.verifying_key())
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &t0_signer).unwrap();

        // Verify against embedded key
        assert!(
            genesis.verify().is_ok(),
            "Genesis signature must verify against T0 key"
        );

        // Verify against explicit key
        assert!(
            genesis.verify_with_key(&t0_signer.verifying_key()).is_ok(),
            "Genesis signature must verify against explicit T0 key"
        );

        // Verify wrong key is rejected
        let wrong_signer = Signer::generate();
        assert!(
            genesis
                .verify_with_key(&wrong_signer.verifying_key())
                .is_err(),
            "Genesis signature must fail with wrong key"
        );
    }

    #[test]
    fn test_tck_00185_node_rejects_join_on_genesis_mismatch() {
        // Acceptance criterion: Node rejects join on genesis mismatch
        let signer = Signer::generate();

        // Create two different genesis blocks
        let config1 = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash([1u8; HASH_SIZE])
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let config2 = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash([2u8; HASH_SIZE]) // Different hash
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let local_genesis = Genesis::create_and_sign(&config1, &signer).unwrap();
        let remote_genesis = Genesis::create_and_sign(&config2, &signer).unwrap();

        let result = local_genesis.validate_against(&remote_genesis);

        assert!(
            matches!(result, Err(GenesisError::GenesisMismatch { .. })),
            "Node must reject join on genesis mismatch"
        );
    }

    #[test]
    fn test_tck_00185_join_attempts_rate_limited() {
        // Acceptance criterion: Join attempts rate-limited per source or identity
        let mut limiter = JoinRateLimiter::with_settings(
            MAX_JOIN_ATTEMPTS_PER_MINUTE,
            JOIN_RATE_LIMIT_WINDOW,
            MAX_RATE_LIMIT_SOURCES,
        );

        let source = "192.168.1.100";

        // Should allow up to limit
        for _ in 0..MAX_JOIN_ATTEMPTS_PER_MINUTE {
            assert!(
                limiter.check(source).is_ok(),
                "Should allow attempts up to rate limit"
            );
        }

        // Should reject over limit
        let result = limiter.check(source);
        assert!(
            matches!(result, Err(GenesisError::JoinRateLimitExceeded { .. })),
            "Must reject excessive join attempts"
        );
    }

    #[test]
    fn test_tck_00185_join_requires_quorum_signed_invitation() {
        // Acceptance criterion: Join requests require quorum-signed invitation token
        let genesis_hash = [0u8; HASH_SIZE];
        let mut token = InvitationToken::new("node-to-join", "kernel", genesis_hash, "nonce-abc");

        // Create validators (need 2f+1 = 3 for f=1)
        let mut validator_keys: HashMap<String, VerifyingKey> = HashMap::new();
        let signers: Vec<Signer> = (0..3).map(|_| Signer::generate()).collect();

        for (i, signer) in signers.iter().enumerate() {
            let vid = format!("validator-{i}");
            validator_keys.insert(vid.clone(), signer.verifying_key());
            token.add_signature(&vid, signer).unwrap();
        }

        // Valid quorum (3 signatures, need 3)
        assert!(
            token.verify(&validator_keys, 3).is_ok(),
            "Token with quorum signatures must be valid"
        );

        // Test insufficient quorum
        let mut partial_token =
            InvitationToken::new("node-to-join", "kernel", genesis_hash, "nonce-xyz");
        partial_token
            .add_signature("validator-0", &signers[0])
            .unwrap();
        partial_token
            .add_signature("validator-1", &signers[1])
            .unwrap();
        // Only 2 signatures

        let result = partial_token.verify(&validator_keys, 3);
        assert!(
            matches!(
                result,
                Err(GenesisError::InsufficientQuorum { have: 2, need: 3 })
            ),
            "Must reject token without quorum signatures"
        );
    }

    #[test]
    fn test_tck_00185_genesis_validator_integration() {
        // Integration test for GenesisValidator
        let t0_signer = Signer::generate();
        let ledger_head = [99u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(ledger_head)
            .t0_public_key(t0_signer.verifying_key())
            .build()
            .unwrap();

        let genesis = Genesis::create_and_sign(&config, &t0_signer).unwrap();

        // Create validators
        let mut validator_keys: HashMap<String, VerifyingKey> = HashMap::new();
        let signers: Vec<Signer> = (0..3).map(|_| Signer::generate()).collect();
        for (i, signer) in signers.iter().enumerate() {
            validator_keys.insert(format!("validator-{i}"), signer.verifying_key());
        }

        let mut validator =
            GenesisValidator::new(genesis.clone(), validator_keys.clone(), 3).unwrap();

        // Create valid invitation
        let mut invitation = InvitationToken::new(
            "joining-node",
            "kernel",
            genesis.genesis_hash,
            "unique-nonce",
        );
        for (i, signer) in signers.iter().enumerate() {
            invitation
                .add_signature(format!("validator-{i}"), signer)
                .unwrap();
        }

        // Valid join should succeed
        let result = validator.validate_join("192.168.1.1", &genesis, &invitation);
        assert!(result.is_ok(), "Valid join request should succeed");

        // Wrong genesis should fail
        let wrong_config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash([0u8; HASH_SIZE]) // Different
            .t0_public_key(t0_signer.verifying_key())
            .build()
            .unwrap();
        let wrong_genesis = Genesis::create_and_sign(&wrong_config, &t0_signer).unwrap();

        let result = validator.validate_join("192.168.1.2", &wrong_genesis, &invitation);
        assert!(
            matches!(result, Err(GenesisError::GenesisMismatch { .. })),
            "Mismatched genesis should be rejected"
        );
    }

    #[test]
    fn test_tck_00185_constant_time_comparisons() {
        // Verify that security-sensitive comparisons use constant-time
        // We can't directly test timing, but we verify the code paths use ct_eq

        let signer = Signer::generate();
        let hash = [42u8; HASH_SIZE];

        let config = GenesisConfig::builder()
            .namespace("kernel")
            .ledger_head_hash(hash)
            .t0_public_key(signer.verifying_key())
            .build()
            .unwrap();

        let mut genesis = Genesis::create_and_sign(&config, &signer).unwrap();

        // Verify original is valid
        assert!(genesis.verify().is_ok(), "Original genesis must be valid");

        // Tamper with the genesis hash
        genesis.genesis_hash[0] ^= 0xFF; // Flip some bits

        // Verification should fail (using constant-time internally)
        assert!(
            genesis.verify().is_err(),
            "Tampered genesis must fail verification"
        );
    }

    #[test]
    fn test_tck_00185_bounded_stores() {
        // CTR-1303: All stores must be bounded

        // Rate limiter bounded sources
        let max_sources = 5;
        let mut limiter = JoinRateLimiter::with_settings(10, Duration::from_secs(60), max_sources);

        // Add more than max sources
        for i in 0..(max_sources + 10) {
            let _ = limiter.check(&format!("source-{i}"));
        }

        assert!(
            limiter.source_count() <= max_sources,
            "Rate limiter must enforce bounded source count"
        );

        // Invitation token bounded signatures
        let mut token = InvitationToken::new("node", "ns", [0u8; HASH_SIZE], "nonce");
        for i in 0..MAX_QUORUM_SIGNATURES {
            let signer = Signer::generate();
            let _ = token.add_signature(format!("val-{i}"), &signer);
        }

        let signer = Signer::generate();
        let result = token.add_signature("one-more", &signer);
        assert!(result.is_err(), "Must enforce maximum quorum signatures");
    }

    #[test]
    fn test_tck_00185_invitation_token_expiry() {
        // Test that expired tokens are rejected
        let genesis_hash = [0u8; HASH_SIZE];
        let mut token = InvitationToken::new("node", "kernel", genesis_hash, "nonce");

        // Manually expire the token
        token.expires_at = 0;

        let validator_keys = HashMap::new();
        let result = token.verify(&validator_keys, 0);

        assert!(
            matches!(result, Err(GenesisError::InvitationTokenExpired { .. })),
            "Expired tokens must be rejected"
        );
    }

    #[test]
    fn test_tck_00185_serde_deny_unknown_fields() {
        // Verify that unknown fields in JSON cause deserialization to fail
        // (defense against injection attacks)
        let json_with_unknown = r#"{
            "namespace": "kernel",
            "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "epoch": 0,
            "created_at_ns": 0,
            "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "t0_public_key": "0000000000000000000000000000000000000000000000000000000000000000",
            "unknown_field": "malicious"
        }"#;

        let result: Result<Genesis, _> = serde_json::from_str(json_with_unknown);
        assert!(
            result.is_err(),
            "Unknown fields must cause deserialization to fail (deny_unknown_fields)"
        );
    }
}
