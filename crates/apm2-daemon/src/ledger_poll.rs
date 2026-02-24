//! Shared freeze-aware `SQLite` ledger polling module.
//!
//! # Cursor Contract
//!
//! All consumers use a composite cursor `(timestamp_ns, event_id)` where:
//! - `timestamp_ns` is monotonic nanoseconds since epoch.
//! - `event_id` is a deterministic tie-breaker within the same timestamp. For
//!   canonical `events` table rows, `event_id` is synthesised as
//!   `canonical_event_id(seq_id)` — a 20-digit zero-padded string ensuring
//!   lexicographic ordering matches numeric `seq_id` ordering.
//!
//! The cursor condition is:
//! ```text
//! (timestamp_ns > cursor_ts)
//! OR (timestamp_ns = cursor_ts AND event_id > cursor_event_id)
//! ```
//!
//! Results are always returned sorted by `(timestamp_ns ASC, event_id ASC)`
//! and truncated to `limit`.
//!
//! # Usage
//!
//! This module is the **single canonical implementation** of freeze-aware
//! dual-table (legacy `ledger_events` + canonical `events`) cursor polling.
//! All daemon consumers (projection worker, gate timeout kernel, etc.) MUST
//! delegate to this module.  Hand-rolled cursor comparisons or canonical
//! `event_id` synthesis is a code-quality finding.
//!
//! ```text
//! use crate::ledger_poll::{canonical_event_id, poll_events_blocking};
//! ```

use std::sync::{Arc, Mutex};

use apm2_core::orchestrator_kernel::sort_and_truncate_events;
use rusqlite::Connection;
use tracing::trace;

use crate::protocol::dispatch::SignedLedgerEvent;

/// Canonical event ID prefix for synthesised canonical-table event IDs.
pub const CANONICAL_EVENT_ID_PREFIX: &str = "canonical-";

/// Width of the zero-padded numeric portion of canonical event IDs.
///
/// A 20-digit field covers the full positive range of `i64`
/// (`9_999_999_999_999_999_999`), ensuring lexicographic ordering matches
/// numeric `seq_id` ordering for all valid sequence values.
pub const CANONICAL_EVENT_ID_WIDTH: usize = 20;

/// SQL expression that synthesises the zero-padded canonical `event_id` from
/// a `seq_id` column, for use in cursor comparisons within prepared
/// statements.
///
/// Usage: embed this expression directly in SQL `WHERE` clauses where you need
/// to compare a canonical `seq_id` against a cursor `event_id` string.
///
/// Example:
/// ```sql
/// WHERE ('canonical-' || SUBSTR('00000000000000000000', 1,
///            20 - LENGTH(CAST(seq_id AS TEXT))) || CAST(seq_id AS TEXT)) > ?cursor
/// ```
pub const CANONICAL_EVENT_ID_CMP_SQL_EXPR: &str = "('canonical-' || SUBSTR(\
    '00000000000000000000', 1, 20 - LENGTH(CAST(seq_id AS TEXT))) || CAST(seq_id AS TEXT))";

/// Returns the canonical synthetic event ID for a given `seq_id`.
///
/// The returned string has the form `canonical-{seq_id:020}` where `seq_id`
/// is zero-padded to [`CANONICAL_EVENT_ID_WIDTH`] digits.  This ensures
/// lexicographic ordering matches numeric ordering:
///
/// ```text
/// canonical-00000000000000000009 < canonical-00000000000000000010
/// ```
#[must_use]
#[allow(clippy::uninlined_format_args)] // width param cannot be inlined for const
pub fn canonical_event_id(seq_id: i64) -> String {
    format!(
        "{CANONICAL_EVENT_ID_PREFIX}{seq_id:0width$}",
        width = CANONICAL_EVENT_ID_WIDTH,
    )
}

/// Parses the numeric `seq_id` from a canonical event ID string.
///
/// Returns `None` if the string does not start with
/// [`CANONICAL_EVENT_ID_PREFIX`] or the numeric portion is not a valid `i64`.
#[must_use]
pub fn parse_canonical_event_id(event_id: &str) -> Option<i64> {
    event_id
        .strip_prefix(CANONICAL_EVENT_ID_PREFIX)?
        .parse::<i64>()
        .ok()
}

/// Normalizes a cursor event ID to the fixed-width canonical representation.
///
/// If `cursor_event_id` is a canonical ID (starts with
/// [`CANONICAL_EVENT_ID_PREFIX`]), re-pads it to [`CANONICAL_EVENT_ID_WIDTH`]
/// digits. This preserves compatibility with older unpadded cursor IDs
/// (`canonical-9`) persisted before fixed-width canonical IDs were introduced.
///
/// Non-canonical (legacy) IDs are returned unchanged.
#[must_use]
pub fn normalize_canonical_cursor_event_id(cursor_event_id: &str) -> String {
    parse_canonical_event_id(cursor_event_id)
        .map_or_else(|| cursor_event_id.to_string(), canonical_event_id)
}

/// Maximum number of `event_type` values supported in a single poll.
///
/// This bounds the dynamically constructed `IN (...)` clause to prevent
/// unreasonably large SQL statements.
const MAX_EVENT_TYPES: usize = 32;

/// Checks whether the canonical `events` table exists in the database.
fn is_canonical_table_present(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'events')",
        [],
        |row| row.get(0),
    )
    .unwrap_or(false)
}

/// Maps a canonical `events` row to a `SignedLedgerEvent`.
///
/// Column order: `seq_id, event_type, session_id, actor_id, payload,
///               COALESCE(signature, X''), timestamp_ns`
#[allow(clippy::cast_sign_loss)]
fn canonical_row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignedLedgerEvent> {
    let seq_id: i64 = row.get(0)?;
    Ok(SignedLedgerEvent {
        event_id: canonical_event_id(seq_id),
        event_type: row.get(1)?,
        work_id: row.get(2)?, // session_id maps to work_id
        actor_id: row.get(3)?,
        payload: row.get(4)?,
        signature: row.get(5)?,
        timestamp_ns: row.get(6)?,
    })
}

/// Builds the SQL `IN (...)` clause for `event_types` filtering.
///
/// Returns `(sql_fragment, params)` where `sql_fragment` is like
/// `(?N, ?N+1, ...)` and `params` contains the event type strings.
fn build_event_type_in_clause(
    event_types: &[&str],
    param_offset: usize,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let placeholders: Vec<String> = (0..event_types.len())
        .map(|i| format!("?{}", param_offset + i + 1))
        .collect();
    let sql = placeholders.join(", ");
    let params: Vec<Box<dyn rusqlite::types::ToSql>> = event_types
        .iter()
        .map(|t| Box::new(t.to_string()) as Box<dyn rusqlite::types::ToSql>)
        .collect();
    (sql, params)
}

/// Blocking freeze-aware poll that merges legacy `ledger_events` and
/// canonical `events` tables.
///
/// # Arguments
///
/// * `conn` - Open `SQLite` connection (must NOT be behind a mutex — caller is
///   responsible for locking).
/// * `event_types` - Slice of event type strings to filter (SQL `IN`). Must
///   contain between 1 and `MAX_EVENT_TYPES` (32) entries.
/// * `cursor_ts_ns` - Cursor timestamp in nanoseconds.
/// * `cursor_event_id` - Cursor event ID tie-breaker (empty string means
///   timestamp-only comparison).
/// * `limit` - Maximum number of events to return.
///
/// # Returns
///
/// Events sorted by `(timestamp_ns ASC, event_id ASC)`, truncated to
/// `limit`.  Returns an empty `Vec` when `limit == 0` or no events match.
///
/// # Errors
///
/// Returns `Err(String)` on SQL preparation or execution failure.
pub fn poll_events_blocking(
    conn: &Connection,
    event_types: &[&str],
    cursor_ts_ns: i64,
    cursor_event_id: &str,
    limit: usize,
) -> Result<Vec<SignedLedgerEvent>, String> {
    if limit == 0 || event_types.is_empty() {
        return Ok(Vec::new());
    }
    if event_types.len() > MAX_EVENT_TYPES {
        return Err(format!(
            "event_types count ({}) exceeds maximum ({})",
            event_types.len(),
            MAX_EVENT_TYPES,
        ));
    }
    let limit_i64 = i64::try_from(limit).map_err(|_| "poll limit exceeds i64 range".to_string())?;

    // ---- Legacy ledger_events ----
    let mut events =
        poll_legacy_events(conn, event_types, cursor_ts_ns, cursor_event_id, limit_i64)?;

    // ---- Canonical events (if table exists) ----
    if is_canonical_table_present(conn) {
        let canonical =
            poll_canonical_events(conn, event_types, cursor_ts_ns, cursor_event_id, limit_i64)?;
        if !canonical.is_empty() {
            events.extend(canonical);
            events = sort_and_truncate_events(events, limit);
        }
    }

    // Final sort + truncate in case only legacy was present and exceeds limit
    // (should not happen with SQL LIMIT, but defensive).
    if events.len() > limit {
        events = sort_and_truncate_events(events, limit);
    }

    trace!(
        event_count = events.len(),
        event_types = ?event_types,
        cursor_ts_ns,
        cursor_event_id,
        limit,
        "ledger_poll: poll_events_blocking completed"
    );

    Ok(events)
}

/// Async wrapper for [`poll_events_blocking`] that offloads the blocking
/// `SQLite` I/O to a `tokio::task::spawn_blocking` thread.
///
/// # Arguments
///
/// Same as [`poll_events_blocking`] except `conn` is behind an
/// `Arc<Mutex<Connection>>`.
///
/// # Errors
///
/// Returns `Err(String)` on mutex poisoning, `spawn_blocking` join failure,
/// or any error from [`poll_events_blocking`].
pub async fn poll_events_async(
    conn: Arc<Mutex<Connection>>,
    event_types: Vec<String>,
    cursor_ts_ns: i64,
    cursor_event_id: String,
    limit: usize,
) -> Result<Vec<SignedLedgerEvent>, String> {
    tokio::task::spawn_blocking(move || {
        let guard = conn
            .lock()
            .map_err(|e| format!("ledger_poll: mutex poisoned: {e}"))?;
        let type_refs: Vec<&str> = event_types.iter().map(String::as_str).collect();
        poll_events_blocking(&guard, &type_refs, cursor_ts_ns, &cursor_event_id, limit)
    })
    .await
    .map_err(|e| format!("ledger_poll: spawn_blocking join failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Polls legacy `ledger_events` table.
#[allow(clippy::cast_sign_loss)]
fn poll_legacy_events(
    conn: &Connection,
    event_types: &[&str],
    cursor_ts_ns: i64,
    cursor_event_id: &str,
    limit_i64: i64,
) -> Result<Vec<SignedLedgerEvent>, String> {
    // Check if ledger_events table exists (may not in canonical-only setups).
    let table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ledger_events')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);
    if !table_exists {
        return Ok(Vec::new());
    }

    let (in_clause, mut type_params) = build_event_type_in_clause(event_types, 0);

    let ts_idx = type_params.len() + 1;
    let query = if cursor_event_id.is_empty() {
        let lim_idx = ts_idx + 1;
        format!(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type IN ({in_clause}) AND timestamp_ns > ?{ts_idx} \
             ORDER BY timestamp_ns ASC, event_id ASC \
             LIMIT ?{lim_idx}"
        )
    } else {
        let eid_idx = ts_idx + 1;
        let lim_idx = eid_idx + 1;
        format!(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type IN ({in_clause}) AND ( \
                 timestamp_ns > ?{ts_idx} OR \
                 (timestamp_ns = ?{ts_idx} AND event_id > ?{eid_idx}) \
             ) \
             ORDER BY timestamp_ns ASC, event_id ASC \
             LIMIT ?{lim_idx}"
        )
    };

    // Build params
    type_params.push(Box::new(cursor_ts_ns));
    if !cursor_event_id.is_empty() {
        type_params.push(Box::new(cursor_event_id.to_string()));
    }
    type_params.push(Box::new(limit_i64));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        type_params.iter().map(AsRef::as_ref).collect();

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| format!("failed to prepare legacy poll query: {e}"))?;
    let rows = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(SignedLedgerEvent {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                work_id: row.get(2)?,
                actor_id: row.get(3)?,
                payload: row.get(4)?,
                signature: row.get(5)?,
                timestamp_ns: row.get(6)?,
            })
        })
        .map_err(|e| format!("failed to execute legacy poll query: {e}"))?;

    let mut events = Vec::new();
    for row_result in rows {
        match row_result {
            Ok(event) => events.push(event),
            Err(e) => {
                return Err(format!("failed to decode legacy poll row: {e}"));
            },
        }
    }
    Ok(events)
}

/// Polls canonical `events` table.
#[allow(clippy::cast_sign_loss)]
fn poll_canonical_events(
    conn: &Connection,
    event_types: &[&str],
    cursor_ts_ns: i64,
    cursor_event_id: &str,
    limit_i64: i64,
) -> Result<Vec<SignedLedgerEvent>, String> {
    let (in_clause, mut type_params) = build_event_type_in_clause(event_types, 0);

    let ts_idx = type_params.len() + 1;
    let query = if cursor_event_id.is_empty() {
        let lim_idx = ts_idx + 1;
        format!(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events \
             WHERE event_type IN ({in_clause}) AND timestamp_ns > ?{ts_idx} \
             ORDER BY timestamp_ns ASC, seq_id ASC \
             LIMIT ?{lim_idx}"
        )
    } else {
        let eid_idx = ts_idx + 1;
        let lim_idx = eid_idx + 1;
        format!(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events \
             WHERE event_type IN ({in_clause}) AND ( \
                 timestamp_ns > ?{ts_idx} OR \
                 (timestamp_ns = ?{ts_idx} AND \
                  {CANONICAL_EVENT_ID_CMP_SQL_EXPR} > ?{eid_idx}) \
             ) \
             ORDER BY timestamp_ns ASC, seq_id ASC \
             LIMIT ?{lim_idx}"
        )
    };

    // Build params
    type_params.push(Box::new(cursor_ts_ns));
    if !cursor_event_id.is_empty() {
        type_params.push(Box::new(cursor_event_id.to_string()));
    }
    type_params.push(Box::new(limit_i64));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        type_params.iter().map(AsRef::as_ref).collect();

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| format!("failed to prepare canonical poll query: {e}"))?;
    let rows = stmt
        .query_map(param_refs.as_slice(), canonical_row_to_event)
        .map_err(|e| format!("failed to execute canonical poll query: {e}"))?;

    let mut events = Vec::new();
    for row_result in rows {
        match row_result {
            Ok(event) => events.push(event),
            Err(e) => {
                return Err(format!("failed to decode canonical poll row: {e}"));
            },
        }
    }
    Ok(events)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;

    /// Helper: create an in-memory `SQLite` connection with both legacy and
    /// canonical tables.
    fn setup_dual_table_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE ledger_events (
                 event_id   TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 work_id    TEXT NOT NULL DEFAULT '',
                 actor_id   TEXT NOT NULL DEFAULT '',
                 payload    BLOB NOT NULL DEFAULT X'',
                 signature  BLOB NOT NULL DEFAULT X'',
                 timestamp_ns INTEGER NOT NULL
             );
             CREATE TABLE events (
                 seq_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_type   TEXT NOT NULL,
                 session_id   TEXT NOT NULL DEFAULT '',
                 actor_id     TEXT NOT NULL DEFAULT '',
                 payload      BLOB NOT NULL DEFAULT X'',
                 signature    BLOB,
                 timestamp_ns INTEGER NOT NULL,
                 event_hash   BLOB
             );",
        )
        .expect("schema setup");
        conn
    }

    /// Helper: create an in-memory `SQLite` connection with only legacy table.
    fn setup_legacy_only_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE ledger_events (
                 event_id   TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 work_id    TEXT NOT NULL DEFAULT '',
                 actor_id   TEXT NOT NULL DEFAULT '',
                 payload    BLOB NOT NULL DEFAULT X'',
                 signature  BLOB NOT NULL DEFAULT X'',
                 timestamp_ns INTEGER NOT NULL
             );",
        )
        .expect("schema setup");
        conn
    }

    // -----------------------------------------------------------------------
    // LED-POLL-004: canonical_event_id lexical ordering
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_event_id_single_digit() {
        let id = canonical_event_id(9);
        assert_eq!(id, "canonical-00000000000000000009");
    }

    #[test]
    fn canonical_event_id_multi_digit() {
        let id = canonical_event_id(42);
        assert_eq!(id, "canonical-00000000000000000042");
    }

    #[test]
    fn canonical_event_id_large_number() {
        let id = canonical_event_id(1_000_000_000_000);
        assert_eq!(id, "canonical-00000001000000000000");
    }

    #[test]
    fn canonical_event_id_lexical_ordering() {
        let id_9 = canonical_event_id(9);
        let id_10 = canonical_event_id(10);
        let id_100 = canonical_event_id(100);

        assert!(
            id_9 < id_10,
            "canonical-000...009 must sort before canonical-000...010, got: {id_9} vs {id_10}"
        );
        assert!(
            id_10 < id_100,
            "canonical-000...010 must sort before canonical-000...100, got: {id_10} vs {id_100}"
        );
        assert!(
            id_9 < id_100,
            "canonical-000...009 must sort before canonical-000...100, got: {id_9} vs {id_100}"
        );
    }

    #[test]
    fn canonical_event_id_roundtrip() {
        for seq_id in [0, 1, 9, 10, 100, 999_999_999, i64::MAX] {
            let id = canonical_event_id(seq_id);
            let parsed = parse_canonical_event_id(&id);
            assert_eq!(parsed, Some(seq_id), "roundtrip failed for seq_id={seq_id}");
        }
    }

    #[test]
    fn parse_canonical_event_id_rejects_non_canonical() {
        assert_eq!(parse_canonical_event_id("legacy-evt-001"), None);
        assert_eq!(parse_canonical_event_id(""), None);
        assert_eq!(parse_canonical_event_id("canonical-"), None);
        assert_eq!(parse_canonical_event_id("canonical-abc"), None);
    }

    #[test]
    fn normalize_canonical_cursor_event_id_pads_old_format() {
        // Old unpadded format should be re-padded.
        let normalized = normalize_canonical_cursor_event_id("canonical-9");
        assert_eq!(normalized, "canonical-00000000000000000009");
    }

    #[test]
    fn normalize_canonical_cursor_event_id_preserves_legacy() {
        let normalized = normalize_canonical_cursor_event_id("legacy-evt-42");
        assert_eq!(normalized, "legacy-evt-42");
    }

    // -----------------------------------------------------------------------
    // LED-POLL-004: merged polling with same timestamp_ns
    // -----------------------------------------------------------------------

    #[test]
    fn poll_events_merges_legacy_and_canonical_same_timestamp() {
        let conn = setup_dual_table_db();

        // Insert legacy events at timestamp 1000
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
            params!["legacy-001", "test_event", "W-1", 1000_i64],
        ).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
            params!["legacy-003", "test_event", "W-1", 1000_i64],
        ).unwrap();

        // Insert canonical events at timestamp 1000
        conn.execute(
            "INSERT INTO events (event_type, session_id, timestamp_ns) VALUES (?1, ?2, ?3)",
            params!["test_event", "W-1", 1000_i64],
        )
        .unwrap(); // seq_id=1
        conn.execute(
            "INSERT INTO events (event_type, session_id, timestamp_ns) VALUES (?1, ?2, ?3)",
            params!["test_event", "W-1", 1000_i64],
        )
        .unwrap(); // seq_id=2

        let events = poll_events_blocking(&conn, &["test_event"], 0, "", 100).unwrap();
        assert_eq!(
            events.len(),
            4,
            "should return all 4 events from both tables"
        );

        // Verify stable ordering: (timestamp_ns ASC, event_id ASC)
        // canonical-00000000000000000001 < canonical-00000000000000000002 < legacy-001
        // < legacy-003
        assert_eq!(events[0].event_id, "canonical-00000000000000000001");
        assert_eq!(events[1].event_id, "canonical-00000000000000000002");
        assert_eq!(events[2].event_id, "legacy-001");
        assert_eq!(events[3].event_id, "legacy-003");

        // Verify cursor advancement doesn't skip: start from last event's cursor
        let events2 = poll_events_blocking(
            &conn,
            &["test_event"],
            1000,
            "canonical-00000000000000000001",
            100,
        )
        .unwrap();
        assert_eq!(
            events2.len(),
            3,
            "should return 3 events after cursor at canonical-...001"
        );
        assert_eq!(events2[0].event_id, "canonical-00000000000000000002");
        assert_eq!(events2[1].event_id, "legacy-001");
        assert_eq!(events2[2].event_id, "legacy-003");
    }

    #[test]
    fn poll_events_cursor_no_skips_on_advance() {
        let conn = setup_dual_table_db();

        // Insert 5 canonical events at same timestamp
        for _ in 0..5 {
            conn.execute(
                "INSERT INTO events (event_type, session_id, timestamp_ns) VALUES (?1, ?2, ?3)",
                params!["test_event", "W-1", 5000_i64],
            )
            .unwrap();
        }

        // Poll with limit=2, advance cursor, poll again, etc.
        let batch1 = poll_events_blocking(&conn, &["test_event"], 0, "", 2).unwrap();
        assert_eq!(batch1.len(), 2);
        assert_eq!(batch1[0].event_id, "canonical-00000000000000000001");
        assert_eq!(batch1[1].event_id, "canonical-00000000000000000002");

        let batch2 =
            poll_events_blocking(&conn, &["test_event"], 5000, &batch1[1].event_id, 2).unwrap();
        assert_eq!(batch2.len(), 2);
        assert_eq!(batch2[0].event_id, "canonical-00000000000000000003");
        assert_eq!(batch2[1].event_id, "canonical-00000000000000000004");

        let batch3 =
            poll_events_blocking(&conn, &["test_event"], 5000, &batch2[1].event_id, 2).unwrap();
        assert_eq!(batch3.len(), 1);
        assert_eq!(batch3[0].event_id, "canonical-00000000000000000005");
    }

    #[test]
    fn poll_events_legacy_only_when_no_canonical_table() {
        let conn = setup_legacy_only_db();

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
            params!["evt-001", "test_event", "W-1", 1000_i64],
        ).unwrap();

        let events = poll_events_blocking(&conn, &["test_event"], 0, "", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-001");
    }

    #[test]
    fn poll_events_multi_event_types() {
        let conn = setup_dual_table_db();

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
            params!["evt-a", "type_a", "W-1", 100_i64],
        ).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
            params!["evt-b", "type_b", "W-1", 200_i64],
        ).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
            params!["evt-c", "type_c", "W-1", 300_i64],
        ).unwrap();

        let events = poll_events_blocking(&conn, &["type_a", "type_b"], 0, "", 100).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, "evt-a");
        assert_eq!(events[1].event_id, "evt-b");
    }

    #[test]
    fn poll_events_limit_zero_returns_empty() {
        let conn = setup_dual_table_db();
        let events = poll_events_blocking(&conn, &["test_event"], 0, "", 0).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn poll_events_empty_event_types_returns_empty() {
        let conn = setup_dual_table_db();
        let events: Vec<&str> = Vec::new();
        let result = poll_events_blocking(&conn, &events, 0, "", 10).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn poll_events_too_many_event_types_returns_error() {
        let conn = setup_dual_table_db();
        let types: Vec<&str> = (0..33).map(|_| "x").collect();
        let result = poll_events_blocking(&conn, &types, 0, "", 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn poll_events_limit_truncates_merged_results() {
        let conn = setup_dual_table_db();

        // 3 legacy + 3 canonical at same timestamp
        for i in 1..=3 {
            conn.execute(
                "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
                params![format!("legacy-{i:03}"), "test_event", "W-1", 1000_i64],
            ).unwrap();
            conn.execute(
                "INSERT INTO events (event_type, session_id, timestamp_ns) VALUES (?1, ?2, ?3)",
                params!["test_event", "W-1", 1000_i64],
            )
            .unwrap();
        }

        let events = poll_events_blocking(&conn, &["test_event"], 0, "", 4).unwrap();
        assert_eq!(events.len(), 4, "should be truncated to limit=4");
    }

    // -----------------------------------------------------------------------
    // LED-POLL-004: async poll wrapper test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn poll_events_async_basic() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE ledger_events (
                 event_id   TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 work_id    TEXT NOT NULL DEFAULT '',
                 actor_id   TEXT NOT NULL DEFAULT '',
                 payload    BLOB NOT NULL DEFAULT X'',
                 signature  BLOB NOT NULL DEFAULT X'',
                 timestamp_ns INTEGER NOT NULL
             );",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, timestamp_ns) VALUES (?1, ?2, ?3, ?4)",
            params!["evt-async-1", "test_event", "W-1", 500_i64],
        ).unwrap();

        let conn_arc = Arc::new(Mutex::new(conn));
        let events = poll_events_async(
            conn_arc,
            vec!["test_event".to_string()],
            0,
            String::new(),
            10,
        )
        .await
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-async-1");
    }
}
