//! Ledger backend trait abstraction.
//!
//! This module defines the `LedgerBackend` trait that abstracts the core
//! operations of an append-only event ledger. The trait enables different
//! storage implementations while maintaining consistent semantics.

use super::storage::{EventRecord, LedgerError};

/// Trait defining the core operations of an append-only event ledger.
///
/// Implementations of this trait provide the fundamental storage operations
/// for the APM2 event-sourcing architecture: append, read, head, and chain
/// verification.
///
/// # Invariants
///
/// - [INV-BKD-001] Events are immutable once appended; the ledger is
///   append-only.
/// - [INV-BKD-002] Sequence IDs are monotonically increasing.
/// - [INV-BKD-003] Hash chain integrity must be maintainable across appends.
///
/// # Contracts
///
/// - [CTR-BKD-001] `append` must return a unique, monotonically increasing
///   sequence ID.
/// - [CTR-BKD-002] `read_from` must return events in sequence order.
/// - [CTR-BKD-003] `head` must return the current maximum sequence ID (0 if
///   empty).
/// - [CTR-BKD-004] `verify_chain` must validate all events from genesis.
pub trait LedgerBackend: Send + Sync {
    /// Appends an event to the ledger.
    ///
    /// Returns the assigned sequence ID for the event.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be inserted.
    fn append(&self, event: &EventRecord) -> Result<u64, LedgerError>;

    /// Reads events starting from a cursor position.
    ///
    /// Returns up to `limit` events with sequence IDs >= `cursor`.
    /// Events are returned in sequence order (ascending by `seq_id`).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    fn read_from(&self, cursor: u64, limit: u64) -> Result<Vec<EventRecord>, LedgerError>;

    /// Gets the current maximum sequence ID (head of the ledger).
    ///
    /// Returns 0 if the ledger is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    fn head(&self) -> Result<u64, LedgerError>;

    /// Verifies the entire hash chain from the beginning of the ledger.
    ///
    /// # Arguments
    ///
    /// * `verify_hash_fn` - Function to compute event hash given payload and
    ///   `prev_hash`.
    /// * `verify_sig_fn` - Function to verify signature (returns true if
    ///   valid).
    ///
    /// # Errors
    ///
    /// Returns an error if any event fails verification:
    /// - `HashChainBroken` if hash chain integrity is violated.
    /// - `SignatureInvalid` if a signature fails verification.
    fn verify_chain<H, V>(&self, verify_hash_fn: H, verify_sig_fn: V) -> Result<(), LedgerError>
    where
        H: Fn(&[u8], &[u8]) -> Vec<u8>,
        V: Fn(&[u8], &[u8]) -> bool;
}
