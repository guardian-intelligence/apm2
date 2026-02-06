//! Crash recovery wiring for daemon startup (TCK-00387).
//!
//! This module connects persistent session state to lease revocation and work
//! cleanup. On daemon restart, it:
//!
//! 1. Collects stale sessions from the persistent session registry
//! 2. Emits `LEASE_REVOKED` events to the ledger for each stale session
//! 3. Deletes work claims for stale sessions so work becomes re-claimable
//! 4. Clears the persistent session registry (idempotency guarantee)
//!
//! # Crash-Only Design
//!
//! Per the crash-only design philosophy, sessions are **terminated** on
//! recovery, not resumed. The daemon assumes all previous sessions are invalid
//! after a restart.
//!
//! # Idempotency
//!
//! Recovery is idempotent: the persistent session registry is cleared after
//! successful recovery. A second startup with the same state file will not
//! double-emit events because the sessions are gone from the state file.
//!
//! # Fail-Safety
//!
//! Recovery failure does not prevent daemon startup. Errors are logged and
//! the daemon continues. Orphaned leases will eventually time out via HTF
//! time envelopes even without explicit revocation.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};
use tracing::{info, warn};

use crate::ledger::SqliteLedgerEventEmitter;
use crate::protocol::dispatch::LedgerEventEmitter;
use crate::session::{SessionRegistry, SessionState};

/// Maximum number of sessions to recover in a single batch.
///
/// Per CTR-1303, bounded iteration prevents runaway recovery if the state file
/// is corrupted with an unreasonable number of entries.
const MAX_RECOVERY_SESSIONS: usize = 10_000;

/// Event type string for lease revocation events in the ledger.
const LEASE_REVOKED_EVENT_TYPE: &str = "lease_revoked";

/// Result of the crash recovery process.
#[derive(Debug, Clone)]
pub struct CrashRecoveryOutcome {
    /// Number of stale sessions found and processed.
    pub sessions_recovered: u32,
    /// Number of `LEASE_REVOKED` events emitted to the ledger.
    pub lease_revoked_events_emitted: u32,
    /// Number of work claims released (deleted from `work_claims` table).
    pub work_claims_released: u32,
    /// Time taken for recovery in milliseconds.
    pub recovery_time_ms: u32,
}

/// Error type for crash recovery operations.
#[derive(Debug, thiserror::Error)]
pub enum CrashRecoveryError {
    /// Recovery timed out.
    #[error("recovery timeout: {elapsed_ms}ms elapsed, timeout is {timeout_ms}ms")]
    Timeout {
        /// Elapsed time in milliseconds.
        elapsed_ms: u32,
        /// Configured timeout in milliseconds.
        timeout_ms: u32,
    },

    /// Ledger event emission failed.
    #[error("failed to emit ledger event: {message}")]
    LedgerEmitFailed {
        /// Error message.
        message: String,
    },

    /// Work claim cleanup failed.
    #[error("failed to clean up work claims: {message}")]
    WorkClaimCleanupFailed {
        /// Error message.
        message: String,
    },
}

/// Collects all sessions from the session registry for recovery.
///
/// Uses the `all_sessions_for_recovery()` trait method added in TCK-00387.
/// For `PersistentSessionRegistry`, this returns sessions loaded from the
/// state file. For `InMemorySessionRegistry`, this returns an empty vec
/// (default implementation) since in-memory state doesn't survive restarts.
///
/// # Arguments
///
/// * `registry` - The session registry (typically a
///   `PersistentSessionRegistry`)
#[must_use]
pub fn collect_sessions(registry: &Arc<dyn SessionRegistry>) -> Vec<SessionState> {
    let sessions = registry.all_sessions_for_recovery();
    if sessions.len() > MAX_RECOVERY_SESSIONS {
        warn!(
            total = sessions.len(),
            max = MAX_RECOVERY_SESSIONS,
            "Truncating recovery sessions to maximum"
        );
        sessions.into_iter().take(MAX_RECOVERY_SESSIONS).collect()
    } else {
        sessions
    }
}

/// Recovers stale sessions by emitting `LEASE_REVOKED` events and cleaning up
/// work claims.
///
/// For each stale session:
/// 1. Emits a `LEASE_REVOKED` event to the ledger (if emitter is available)
/// 2. Deletes the work claim from the `work_claims` table (if `SQLite` conn is
///    available) so the work becomes re-claimable
///
/// # Arguments
///
/// * `sessions` - Stale sessions to recover
/// * `emitter` - Optional ledger event emitter for persisting `LEASE_REVOKED`
///   events
/// * `sqlite_conn` - Optional `SQLite` connection for cleaning up work claims
/// * `timeout` - Maximum duration for recovery
///
/// # Returns
///
/// `Ok(CrashRecoveryOutcome)` with recovery statistics, or
/// `Err(CrashRecoveryError)` if recovery failed critically.
#[allow(clippy::cast_possible_truncation)] // Recovery timeout is < 5s, well within u32
pub fn recover_stale_sessions(
    sessions: &[SessionState],
    emitter: Option<&SqliteLedgerEventEmitter>,
    sqlite_conn: Option<&Arc<Mutex<Connection>>>,
    timeout: Duration,
) -> Result<CrashRecoveryOutcome, CrashRecoveryError> {
    let start = Instant::now();
    let deadline = start + timeout;

    let mut lease_revoked_events_emitted: u32 = 0;
    let mut work_claims_released: u32 = 0;

    for session in sessions {
        // Check timeout before each session
        if Instant::now() > deadline {
            return Err(CrashRecoveryError::Timeout {
                elapsed_ms: start.elapsed().as_millis() as u32,
                timeout_ms: timeout.as_millis() as u32,
            });
        }

        // Step 1: Emit LEASE_REVOKED event to ledger
        if let Some(emitter) = emitter {
            match emit_lease_revoked_event(emitter, session) {
                Ok(event_id) => {
                    info!(
                        session_id = %session.session_id,
                        work_id = %session.work_id,
                        event_id = %event_id,
                        "Emitted LEASE_REVOKED event for stale session"
                    );
                    lease_revoked_events_emitted += 1;
                },
                Err(e) => {
                    // Log and continue -- partial recovery is acceptable
                    warn!(
                        session_id = %session.session_id,
                        error = %e,
                        "Failed to emit LEASE_REVOKED event, continuing recovery"
                    );
                },
            }
        } else {
            info!(
                session_id = %session.session_id,
                work_id = %session.work_id,
                "LEASE_REVOKED (no ledger configured, event not persisted)"
            );
        }

        // Step 2: Release work claim so work becomes re-claimable
        if let Some(conn) = sqlite_conn {
            match release_work_claim(conn, &session.work_id) {
                Ok(released) => {
                    if released {
                        info!(
                            work_id = %session.work_id,
                            session_id = %session.session_id,
                            "Released work claim for stale session"
                        );
                        work_claims_released += 1;
                    }
                },
                Err(e) => {
                    warn!(
                        work_id = %session.work_id,
                        error = %e,
                        "Failed to release work claim, continuing recovery"
                    );
                },
            }
        }
    }

    let recovery_time_ms = start.elapsed().as_millis() as u32;

    Ok(CrashRecoveryOutcome {
        sessions_recovered: sessions.len() as u32,
        lease_revoked_events_emitted,
        work_claims_released,
        recovery_time_ms,
    })
}

/// Clears the persistent session registry after recovery.
///
/// Uses the `clear_all_sessions()` trait method added in TCK-00387. For
/// `PersistentSessionRegistry`, this clears the in-memory state and persists
/// the empty state to disk. For `InMemorySessionRegistry`, this is a no-op
/// (default implementation).
///
/// # Arguments
///
/// * `registry` - The session registry to clear
pub fn clear_session_registry(registry: &Arc<dyn SessionRegistry>) {
    match registry.clear_all_sessions() {
        Ok(()) => {
            info!("Cleared session registry after crash recovery");
        },
        Err(e) => {
            warn!(
                error = %e,
                "Failed to clear session registry after recovery"
            );
        },
    }
}

/// Emits a `LEASE_REVOKED` event to the ledger for a stale session.
///
/// The event payload includes the session ID, work ID, and the reason
/// (`daemon_restart`).
fn emit_lease_revoked_event(
    emitter: &SqliteLedgerEventEmitter,
    session: &SessionState,
) -> Result<String, CrashRecoveryError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::cast_possible_truncation)]
    let timestamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // Build the LEASE_REVOKED payload
    let payload = serde_json::json!({
        "event_type": LEASE_REVOKED_EVENT_TYPE,
        "session_id": session.session_id,
        "work_id": session.work_id,
        "reason": "daemon_restart",
        "role": session.role,
    });
    let payload_bytes = payload.to_string().into_bytes();

    // Use emit_session_event to persist the LEASE_REVOKED event
    let signed_event = emitter
        .emit_session_event(
            &session.session_id,
            LEASE_REVOKED_EVENT_TYPE,
            &payload_bytes,
            "daemon",
            timestamp_ns,
        )
        .map_err(|e| CrashRecoveryError::LedgerEmitFailed {
            message: format!(
                "emit_session_event failed for session {}: {e}",
                session.session_id
            ),
        })?;

    Ok(signed_event.event_id)
}

/// Releases a work claim by deleting it from the `work_claims` table.
///
/// This makes the work re-claimable by agents after daemon restart.
///
/// # Returns
///
/// `Ok(true)` if a claim was deleted, `Ok(false)` if no claim existed.
fn release_work_claim(
    conn: &Arc<Mutex<Connection>>,
    work_id: &str,
) -> Result<bool, CrashRecoveryError> {
    let conn = conn
        .lock()
        .map_err(|_| CrashRecoveryError::WorkClaimCleanupFailed {
            message: "connection lock poisoned".to_string(),
        })?;

    let rows_affected = conn
        .execute(
            "DELETE FROM work_claims WHERE work_id = ?1",
            params![work_id],
        )
        .map_err(|e| CrashRecoveryError::WorkClaimCleanupFailed {
            message: format!("sqlite delete failed: {e}"),
        })?;

    Ok(rows_affected > 0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rusqlite::Connection;

    use super::*;
    use crate::episode::registry::InMemorySessionRegistry;
    use crate::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
    use crate::protocol::dispatch::{PolicyResolution, WorkClaim, WorkRegistry};
    use crate::protocol::messages::WorkRole;
    use crate::session::{SessionRegistry, SessionState};

    /// Helper to create a test session.
    fn make_session(id: &str, work_id: &str) -> SessionState {
        SessionState {
            session_id: id.to_string(),
            work_id: work_id.to_string(),
            role: 1,
            ephemeral_handle: format!("handle-{id}"),
            lease_id: String::new(), // Empty after loading from disk
            policy_resolved_ref: "policy-ref".to_string(),
            capability_manifest_hash: vec![],
            episode_id: None,
        }
    }

    /// Creates an in-memory `SQLite` connection with schemas initialized.
    fn setup_sqlite() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        SqliteLedgerEventEmitter::init_schema(&conn).expect("init ledger schema");
        SqliteWorkRegistry::init_schema(&conn).expect("init work schema");
        Arc::new(Mutex::new(conn))
    }

    /// Creates a `SqliteLedgerEventEmitter` with a fresh signing key.
    fn make_emitter(conn: &Arc<Mutex<Connection>>) -> SqliteLedgerEventEmitter {
        use rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        SqliteLedgerEventEmitter::new(Arc::clone(conn), signing_key)
    }

    /// Registers a work claim in the `SQLite` work registry.
    fn register_claim(conn: &Arc<Mutex<Connection>>, work_id: &str) {
        let registry = SqliteWorkRegistry::new(Arc::clone(conn));
        let claim = WorkClaim {
            work_id: work_id.to_string(),
            lease_id: format!("lease-{work_id}"),
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "test-policy".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: Vec::new(),
            author_custody_domains: Vec::new(),
        };
        registry.register_claim(claim).expect("register claim");
    }

    // =========================================================================
    // Happy Path Tests
    // =========================================================================

    #[test]
    fn test_recover_empty_sessions() {
        let result = recover_stale_sessions(&[], None, None, Duration::from_secs(5))
            .expect("recovery should succeed");

        assert_eq!(result.sessions_recovered, 0);
        assert_eq!(result.lease_revoked_events_emitted, 0);
        assert_eq!(result.work_claims_released, 0);
        assert!(result.recovery_time_ms < 100);
    }

    #[test]
    fn test_recover_sessions_emits_lease_revoked_events() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let sessions = vec![
            make_session("sess-1", "work-1"),
            make_session("sess-2", "work-2"),
            make_session("sess-3", "work-3"),
        ];

        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
        )
        .expect("recovery should succeed");

        assert_eq!(result.sessions_recovered, 3);
        assert_eq!(result.lease_revoked_events_emitted, 3);

        // Verify events were persisted to the ledger
        let db = conn.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM ledger_events WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_recover_sessions_releases_work_claims() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);

        // Register work claims
        register_claim(&conn, "work-1");
        register_claim(&conn, "work-2");

        let sessions = vec![
            make_session("sess-1", "work-1"),
            make_session("sess-2", "work-2"),
            make_session("sess-3", "work-3"), // No claim for this one
        ];

        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
        )
        .expect("recovery should succeed");

        assert_eq!(result.sessions_recovered, 3);
        assert_eq!(result.work_claims_released, 2); // Only 2 had claims

        // Verify claims were deleted
        let db = conn.lock().unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM work_claims", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_recover_sessions_completes_within_timeout() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);

        // Create 100 sessions
        let sessions: Vec<SessionState> = (0..100)
            .map(|i| make_session(&format!("sess-{i}"), &format!("work-{i}")))
            .collect();

        let start = Instant::now();
        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
        )
        .expect("recovery should succeed");

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "Recovery took {elapsed:?}"
        );
        assert!(result.recovery_time_ms < 5000);
        assert_eq!(result.sessions_recovered, 100);
    }

    // =========================================================================
    // Idempotency Tests
    // =========================================================================

    #[test]
    fn test_recovery_is_idempotent() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);

        register_claim(&conn, "work-1");

        let sessions = vec![make_session("sess-1", "work-1")];

        // First recovery
        let result1 = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
        )
        .expect("first recovery should succeed");

        assert_eq!(result1.lease_revoked_events_emitted, 1);
        assert_eq!(result1.work_claims_released, 1);

        // Second recovery with same sessions -- should succeed but not find
        // any claims to release (they were already deleted).
        let result2 = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
        )
        .expect("second recovery should succeed");

        assert_eq!(result2.lease_revoked_events_emitted, 1); // New event emitted
        assert_eq!(result2.work_claims_released, 0); // No claims to release

        // In practice, the session registry would be cleared after the first
        // recovery, so the second call wouldn't find any sessions. But the
        // function itself is safe to call repeatedly.
    }

    #[test]
    fn test_recovery_idempotent_via_clear_registry() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create a persistent registry with sessions
        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();
        assert_eq!(registry.session_count(), 1);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);

        // Collect sessions (simulates first startup)
        let sessions = collect_sessions(&registry);
        assert_eq!(sessions.len(), 1);

        // Clear after recovery
        clear_session_registry(&registry);

        // Now collect again (simulates second startup after reload)
        let sessions_after = collect_sessions(&registry);
        assert!(sessions_after.is_empty(), "Sessions should be cleared");
    }

    // =========================================================================
    // Failure Safety Tests
    // =========================================================================

    #[test]
    fn test_recovery_without_ledger_succeeds() {
        // No ledger configured -- events not persisted but recovery succeeds
        let sessions = vec![
            make_session("sess-1", "work-1"),
            make_session("sess-2", "work-2"),
        ];

        let result = recover_stale_sessions(
            &sessions,
            None, // No emitter
            None, // No sqlite conn
            Duration::from_secs(5),
        )
        .expect("recovery should succeed without ledger");

        assert_eq!(result.sessions_recovered, 2);
        assert_eq!(result.lease_revoked_events_emitted, 0);
        assert_eq!(result.work_claims_released, 0);
    }

    #[test]
    fn test_recovery_timeout() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);

        // Create enough sessions with a very short timeout
        let sessions: Vec<SessionState> = (0..1000)
            .map(|i| make_session(&format!("sess-{i}"), &format!("work-{i}")))
            .collect();

        // Use a 0ms timeout to force immediate timeout
        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_millis(0),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            CrashRecoveryError::Timeout { .. } => {
                // Expected
            },
            other => panic!("Expected Timeout, got: {other:?}"),
        }
    }

    #[test]
    fn test_collect_sessions_with_in_memory_registry() {
        // InMemorySessionRegistry should return empty (no persistence)
        let registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

        let sessions = collect_sessions(&registry);
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_collect_sessions_with_persistent_registry() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "work-2"))
            .unwrap();

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let sessions = collect_sessions(&registry);
        assert_eq!(sessions.len(), 2);
    }

    // =========================================================================
    // Integration Test: Full Recovery Cycle
    // =========================================================================

    #[test]
    fn test_full_recovery_cycle() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Phase 1: Simulate daemon that registers sessions and work claims
        let conn = setup_sqlite();
        {
            let registry = PersistentSessionRegistry::new(&state_path);
            registry
                .register_session(make_session("sess-1", "work-1"))
                .unwrap();
            registry
                .register_session(make_session("sess-2", "work-2"))
                .unwrap();
            register_claim(&conn, "work-1");
            register_claim(&conn, "work-2");
        }

        // Verify state file was written
        assert!(state_path.exists());

        // Phase 2: Simulate daemon restart -- load from state file
        let loaded_registry = PersistentSessionRegistry::load_from_file(&state_path).unwrap();
        assert_eq!(loaded_registry.session_count(), 2);

        let registry: Arc<dyn SessionRegistry> = Arc::new(loaded_registry);
        let sessions = collect_sessions(&registry);
        assert_eq!(sessions.len(), 2);

        // Phase 3: Perform crash recovery
        let emitter = make_emitter(&conn);
        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
        )
        .expect("recovery should succeed");

        // Verify outcome
        assert_eq!(result.sessions_recovered, 2);
        assert_eq!(result.lease_revoked_events_emitted, 2);
        assert_eq!(result.work_claims_released, 2);
        assert!(result.recovery_time_ms < 5000);

        // Verify ledger events
        let db = conn.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM ledger_events WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);

        // Verify work claims are gone
        let claims_count: i64 = db
            .query_row("SELECT COUNT(*) FROM work_claims", [], |row| row.get(0))
            .unwrap();
        assert_eq!(claims_count, 0);
        drop(db);

        // Phase 4: Clear registry (idempotency)
        clear_session_registry(&registry);

        // Phase 5: Verify second recovery finds nothing
        let sessions_after = collect_sessions(&registry);
        assert!(sessions_after.is_empty());
    }

    // =========================================================================
    // LEASE_REVOKED Event Content Tests
    // =========================================================================

    #[test]
    fn test_lease_revoked_event_payload_content() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let session = make_session("sess-1", "work-1");

        let result = recover_stale_sessions(
            &[session],
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
        )
        .expect("recovery should succeed");

        assert_eq!(result.lease_revoked_events_emitted, 1);

        // Verify event content
        let db = conn.lock().unwrap();
        let (event_type, work_id, actor_id): (String, String, String) = db
            .query_row(
                "SELECT event_type, work_id, actor_id FROM ledger_events \
                 WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(event_type, LEASE_REVOKED_EVENT_TYPE);
        // emit_session_event uses session_id as work_id for indexing
        assert_eq!(work_id, "sess-1");
        assert_eq!(actor_id, "daemon");
    }
}
