// AGENT-AUTHORED (TCK-00211)
//! Session handling for the APM2 daemon.
//!
//! This module provides session management functionality for the daemon,
//! including CONSUME mode sessions with context firewall integration.
//!
//! # Modules
//!
//! - [`consume`]: CONSUME mode session handler with context firewall
//!   integration

pub mod consume;

// Re-export main types
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub use consume::{
    ConsumeSessionContext, ConsumeSessionError, ConsumeSessionHandler,
    EXIT_CLASSIFICATION_CONTEXT_MISS, MAX_REFINEMENT_ATTEMPTS, TERMINATION_RATIONALE_CONTEXT_MISS,
    validate_tool_request,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::episode::decision::SessionTerminationInfo;

/// Ephemeral session handle for IPC authentication.
///
/// Per REQ-DCP-0004, the handle is a bearer token for session-scoped IPC.
/// It MUST NOT contain credentials or long-term secrets.
///
/// # Security
///
/// - Generated using UUID v4 (random)
/// - No embedded user data or secrets
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EphemeralHandle(String);

impl EphemeralHandle {
    /// Generates a new random ephemeral handle.
    ///
    /// Format: `H-{uuid}`
    pub fn generate() -> Self {
        Self(format!("H-{}", Uuid::new_v4()))
    }

    /// Returns the handle string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EphemeralHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for EphemeralHandle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Session state for a spawned episode.
///
/// Per TCK-00256, the session state is persisted when `SpawnEpisode` succeeds
/// to enable subsequent session-scoped IPC calls.
///
/// # Persistence (TCK-00266)
///
/// This struct implements `Serialize` and `Deserialize` to support persistent
/// session registry state files for crash recovery.
///
/// # Security Note
///
/// The `Debug` impl manually redacts `lease_id` to prevent accidental leakage
/// in debug logs. The `lease_id` is a security-sensitive credential that should
/// not appear in logs or error messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier.
    pub session_id: String,
    /// Work ID this session is associated with.
    pub work_id: String,
    /// Role claimed for this session.
    pub role: i32, // Using i32 to avoid circular dependency with protocol::messages::WorkRole
    /// Ephemeral handle for IPC communication.
    pub ephemeral_handle: String,
    /// Lease ID authorizing this session.
    ///
    /// **SECURITY**: This field is redacted in Debug output and skipped during
    /// serialization to prevent credential leakage.
    #[serde(skip, default)]
    pub lease_id: String,
    /// Policy resolution reference.
    pub policy_resolved_ref: String,
    /// Hash of the capability manifest for this session.
    pub capability_manifest_hash: Vec<u8>,
    /// Episode ID in the runtime (if created).
    pub episode_id: Option<String>,
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("session_id", &self.session_id)
            .field("work_id", &self.work_id)
            .field("role", &self.role)
            .field("ephemeral_handle", &self.ephemeral_handle)
            .field("lease_id", &"[REDACTED]")
            .field("policy_resolved_ref", &self.policy_resolved_ref)
            .field(
                "capability_manifest_hash",
                &hex::encode(&self.capability_manifest_hash),
            )
            .field("episode_id", &self.episode_id)
            .finish()
    }
}

/// Trait for persisting and querying session state.
///
/// Per TCK-00256, sessions must be persisted to enable subsequent
/// session-scoped IPC calls.
///
/// # TCK-00385: Termination Tracking
///
/// The registry now supports marking sessions as terminated via
/// [`mark_terminated`](Self::mark_terminated) and querying termination info
/// via [`get_termination_info`](Self::get_termination_info). Terminated
/// sessions are preserved in the registry (with TTL) so that
/// `SessionStatus` queries after termination return useful information
/// instead of "session not found".
pub trait SessionRegistry: Send + Sync {
    /// Registers a new session.
    fn register_session(&self, session: SessionState) -> Result<(), SessionRegistryError>;

    /// Queries a session by session ID.
    fn get_session(&self, session_id: &str) -> Option<SessionState>;

    /// Queries a session by ephemeral handle.
    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState>;

    /// Queries a session by work ID (TCK-00344).
    ///
    /// Returns the first session associated with the given `work_id`, or `None`
    /// if no session matches. This is an O(n) scan; a production implementation
    /// could add a secondary index for efficiency.
    fn get_session_by_work_id(&self, work_id: &str) -> Option<SessionState>;

    /// Marks a session as terminated with the given termination info
    /// (TCK-00385).
    ///
    /// The session entry is preserved in the registry so that subsequent
    /// `SessionStatus` queries return TERMINATED state with exit details.
    /// The entry will be cleaned up after the configured TTL.
    ///
    /// Returns `Ok(true)` if the session was found and marked terminated,
    /// `Ok(false)` if the session was not found. Returns `Err` if the
    /// termination could not be persisted (fail-closed: callers MUST treat
    /// persistence failures as fatal for the session lifecycle).
    fn mark_terminated(
        &self,
        session_id: &str,
        info: SessionTerminationInfo,
    ) -> Result<bool, SessionRegistryError>;

    /// Queries termination info for a session (TCK-00385).
    ///
    /// Returns `Some(info)` if the session has been terminated and the
    /// termination entry has not yet expired (TTL). Returns `None` if the
    /// session is still active or not found.
    fn get_termination_info(&self, session_id: &str) -> Option<SessionTerminationInfo>;

    /// Queries a terminated session's preserved state and termination info
    /// (TCK-00385).
    ///
    /// Returns `Some((session, info))` if the session has been terminated
    /// and the entry has not yet expired. Returns `None` otherwise.
    ///
    /// This is used by the `SessionStatus` handler to return `work_id`, role,
    /// and `episode_id` alongside termination details.
    fn get_terminated_session(
        &self,
        session_id: &str,
    ) -> Option<(SessionState, SessionTerminationInfo)>;
}

/// Error type for session registry operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionRegistryError {
    /// Session ID already exists.
    #[error("duplicate session_id: {session_id}")]
    DuplicateSessionId {
        /// The duplicate session ID.
        session_id: String,
    },

    /// Registration failed.
    #[error("session registration failed: {message}")]
    RegistrationFailed {
        /// Error message.
        message: String,
    },
}

// =============================================================================
// Session Telemetry (TCK-00384)
// =============================================================================

/// Per-session telemetry counters.
///
/// Per TCK-00384, tracks tool call and event emission counts as well as
/// session start time. Counters are thread-safe using atomic operations.
///
/// This is stored separately from [`SessionState`] because `SessionState` must
/// remain `Clone + Serialize + Deserialize`, which is incompatible with
/// `AtomicU64`.
pub struct SessionTelemetry {
    /// Number of `RequestTool` calls dispatched for this session.
    pub tool_calls: AtomicU64,
    /// Number of `EmitEvent` calls dispatched for this session.
    pub events_emitted: AtomicU64,
    /// Timestamp (nanoseconds since epoch) when the session was spawned.
    pub started_at_ns: u64,
}

impl SessionTelemetry {
    /// Creates a new telemetry record with the given start timestamp.
    #[must_use]
    pub const fn new(started_at_ns: u64) -> Self {
        Self {
            tool_calls: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
            started_at_ns,
        }
    }

    /// Increments the tool call counter and returns the new value.
    pub fn increment_tool_calls(&self) -> u64 {
        self.tool_calls.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Increments the events emitted counter and returns the new value.
    pub fn increment_events_emitted(&self) -> u64 {
        self.events_emitted.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Returns the current tool call count.
    pub fn get_tool_calls(&self) -> u64 {
        self.tool_calls.load(Ordering::Relaxed)
    }

    /// Returns the current events emitted count.
    pub fn get_events_emitted(&self) -> u64 {
        self.events_emitted.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for SessionTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTelemetry")
            .field("tool_calls", &self.tool_calls.load(Ordering::Relaxed))
            .field(
                "events_emitted",
                &self.events_emitted.load(Ordering::Relaxed),
            )
            .field("started_at_ns", &self.started_at_ns)
            .finish()
    }
}

/// A snapshot of session telemetry values (non-atomic, cloneable).
///
/// Used to return telemetry data from the store without holding references
/// to atomic values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    /// Number of tool calls dispatched.
    pub tool_calls: u64,
    /// Number of events emitted.
    pub events_emitted: u64,
    /// Session start timestamp (nanoseconds since epoch).
    pub started_at_ns: u64,
}

/// Thread-safe store for per-session telemetry data (TCK-00384).
///
/// This store is separate from the session registry because telemetry
/// counters use atomic operations that are incompatible with the `Clone +
/// Serialize` requirements of [`SessionState`].
///
/// # Thread Safety
///
/// Uses `RwLock<HashMap>` for concurrent access. Individual counter updates
/// use atomic operations without holding the write lock.
#[derive(Debug, Default)]
pub struct SessionTelemetryStore {
    /// Per-session telemetry indexed by session ID.
    entries: RwLock<HashMap<String, Arc<SessionTelemetry>>>,
}

impl SessionTelemetryStore {
    /// Creates a new empty telemetry store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers telemetry for a new session.
    ///
    /// Records the session start time and initializes counters to zero.
    /// If a session with the same ID already exists, the existing entry is
    /// preserved (idempotent).
    pub fn register(&self, session_id: &str, started_at_ns: u64) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(SessionTelemetry::new(started_at_ns)));
    }

    /// Returns a reference-counted handle to the session's telemetry.
    ///
    /// The returned `Arc<SessionTelemetry>` can be used to increment
    /// counters without holding the store lock.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<Arc<SessionTelemetry>> {
        let entries = self.entries.read().expect("lock poisoned");
        entries.get(session_id).cloned()
    }

    /// Returns a snapshot of the session's telemetry values.
    #[must_use]
    pub fn snapshot(&self, session_id: &str) -> Option<TelemetrySnapshot> {
        let entries = self.entries.read().expect("lock poisoned");
        entries.get(session_id).map(|t| TelemetrySnapshot {
            tool_calls: t.get_tool_calls(),
            events_emitted: t.get_events_emitted(),
            started_at_ns: t.started_at_ns,
        })
    }

    /// Removes telemetry for a session.
    pub fn remove(&self, session_id: &str) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.remove(session_id);
    }

    /// Returns the number of tracked sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        let entries = self.entries.read().expect("lock poisoned");
        entries.len()
    }

    /// Returns true if no sessions are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// TCK-00384: Session Telemetry Tests
// =============================================================================

#[cfg(test)]
mod telemetry_tests {
    use super::*;

    // =========================================================================
    // SessionTelemetry Unit Tests
    // =========================================================================

    #[test]
    fn test_telemetry_new_initializes_zeros() {
        let telemetry = SessionTelemetry::new(1_000_000);
        assert_eq!(telemetry.get_tool_calls(), 0);
        assert_eq!(telemetry.get_events_emitted(), 0);
        assert_eq!(telemetry.started_at_ns, 1_000_000);
    }

    #[test]
    fn test_telemetry_increment_tool_calls() {
        let telemetry = SessionTelemetry::new(0);
        assert_eq!(telemetry.increment_tool_calls(), 1);
        assert_eq!(telemetry.increment_tool_calls(), 2);
        assert_eq!(telemetry.increment_tool_calls(), 3);
        assert_eq!(telemetry.get_tool_calls(), 3);
    }

    #[test]
    fn test_telemetry_increment_events_emitted() {
        let telemetry = SessionTelemetry::new(0);
        assert_eq!(telemetry.increment_events_emitted(), 1);
        assert_eq!(telemetry.increment_events_emitted(), 2);
        assert_eq!(telemetry.get_events_emitted(), 2);
    }

    #[test]
    fn test_telemetry_counters_independent() {
        let telemetry = SessionTelemetry::new(42);
        telemetry.increment_tool_calls();
        telemetry.increment_tool_calls();
        telemetry.increment_events_emitted();

        assert_eq!(telemetry.get_tool_calls(), 2);
        assert_eq!(telemetry.get_events_emitted(), 1);
        assert_eq!(telemetry.started_at_ns, 42);
    }

    #[test]
    fn test_telemetry_debug_format() {
        let telemetry = SessionTelemetry::new(999);
        telemetry.increment_tool_calls();
        let debug_str = format!("{telemetry:?}");
        assert!(debug_str.contains("tool_calls: 1"));
        assert!(debug_str.contains("events_emitted: 0"));
        assert!(debug_str.contains("started_at_ns: 999"));
    }

    // =========================================================================
    // TelemetrySnapshot Tests
    // =========================================================================

    #[test]
    fn test_snapshot_values() {
        let snap = TelemetrySnapshot {
            tool_calls: 5,
            events_emitted: 3,
            started_at_ns: 1_000_000_000,
        };
        assert_eq!(snap.tool_calls, 5);
        assert_eq!(snap.events_emitted, 3);
        assert_eq!(snap.started_at_ns, 1_000_000_000);
    }

    #[test]
    fn test_snapshot_clone_eq() {
        let snap1 = TelemetrySnapshot {
            tool_calls: 5,
            events_emitted: 3,
            started_at_ns: 1_000_000_000,
        };
        let snap2 = snap1;
        assert_eq!(snap1, snap2);
    }

    // =========================================================================
    // SessionTelemetryStore Tests
    // =========================================================================

    #[test]
    fn test_store_new_is_empty() {
        let store = SessionTelemetryStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_store_register_and_get() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 1_000_000);

        let telemetry = store.get("sess-1");
        assert!(telemetry.is_some());
        let t = telemetry.unwrap();
        assert_eq!(t.get_tool_calls(), 0);
        assert_eq!(t.get_events_emitted(), 0);
        assert_eq!(t.started_at_ns, 1_000_000);
    }

    #[test]
    fn test_store_get_nonexistent() {
        let store = SessionTelemetryStore::new();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn test_store_register_idempotent() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 100);

        // Increment a counter
        store.get("sess-1").unwrap().increment_tool_calls();

        // Re-register with different started_at_ns (should be idempotent)
        store.register("sess-1", 999);

        // Original entry should be preserved
        let t = store.get("sess-1").unwrap();
        assert_eq!(t.started_at_ns, 100);
        assert_eq!(t.get_tool_calls(), 1);
    }

    #[test]
    fn test_store_snapshot() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 42);

        let t = store.get("sess-1").unwrap();
        t.increment_tool_calls();
        t.increment_tool_calls();
        t.increment_events_emitted();

        let snap = store.snapshot("sess-1");
        assert!(snap.is_some());
        let snap = snap.unwrap();
        assert_eq!(snap.tool_calls, 2);
        assert_eq!(snap.events_emitted, 1);
        assert_eq!(snap.started_at_ns, 42);
    }

    #[test]
    fn test_store_snapshot_nonexistent() {
        let store = SessionTelemetryStore::new();
        assert!(store.snapshot("nonexistent").is_none());
    }

    #[test]
    fn test_store_remove() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 100);
        assert_eq!(store.len(), 1);

        store.remove("sess-1");
        assert!(store.is_empty());
        assert!(store.get("sess-1").is_none());
    }

    #[test]
    fn test_store_remove_nonexistent() {
        let store = SessionTelemetryStore::new();
        store.remove("nonexistent"); // Should not panic
        assert!(store.is_empty());
    }

    #[test]
    fn test_store_multiple_sessions() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 100);
        store.register("sess-2", 200);
        store.register("sess-3", 300);
        assert_eq!(store.len(), 3);

        // Increment counters independently
        store.get("sess-1").unwrap().increment_tool_calls();
        store.get("sess-2").unwrap().increment_events_emitted();
        store.get("sess-2").unwrap().increment_events_emitted();

        let snap1 = store.snapshot("sess-1").unwrap();
        assert_eq!(snap1.tool_calls, 1);
        assert_eq!(snap1.events_emitted, 0);

        let snap2 = store.snapshot("sess-2").unwrap();
        assert_eq!(snap2.tool_calls, 0);
        assert_eq!(snap2.events_emitted, 2);

        let snap3 = store.snapshot("sess-3").unwrap();
        assert_eq!(snap3.tool_calls, 0);
        assert_eq!(snap3.events_emitted, 0);
    }

    /// TCK-00384: Verify counters are thread-safe using concurrent
    /// increments from multiple threads.
    #[test]
    fn test_telemetry_thread_safety() {
        use std::sync::Arc;

        let telemetry = Arc::new(SessionTelemetry::new(0));
        let iterations: u64 = 1000;
        let threads: u64 = 4;

        let mut handles = Vec::new();
        for _ in 0..threads {
            let t = Arc::clone(&telemetry);
            handles.push(std::thread::spawn(move || {
                for _ in 0..iterations {
                    t.increment_tool_calls();
                    t.increment_events_emitted();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        let expected = threads * iterations;
        assert_eq!(telemetry.get_tool_calls(), expected);
        assert_eq!(telemetry.get_events_emitted(), expected);
    }
}
