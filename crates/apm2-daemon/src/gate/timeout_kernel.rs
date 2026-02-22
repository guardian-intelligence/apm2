//! Orchestrator-kernel reference migration for gate timeout progression.
//!
//! This module wires the existing `GateOrchestrator` timeout flow through the
//! shared `apm2_core::orchestrator_kernel` harness:
//! Observe -> Plan -> Execute -> Receipt.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::orchestrator_kernel::{
    CompositeCursor, CursorEvent, CursorStore, EffectExecutionState, EffectJournal,
    ExecutionOutcome, InDoubtResolution, IntentStore, LedgerReader, OrchestratorDomain,
    ReceiptWriter, TickConfig, TickReport, run_tick,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::gate::{GateOrchestrator, GateOrchestratorEvent, GateType};
use crate::ledger::SqliteLedgerEventEmitter;
use crate::protocol::dispatch::LedgerEventEmitter;

const TIMEOUT_CURSOR_KEY: i64 = 1;
const TIMEOUT_PERSISTOR_SESSION_ID: &str = "gate-timeout-poller";
const TIMEOUT_PERSISTOR_ACTOR_ID: &str = "orchestrator:timeout-poller";

/// Kernel configuration for gate-timeout orchestration ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateTimeoutKernelConfig {
    /// Maximum observe events per tick.
    pub observe_limit: usize,
    /// Maximum timeout intents executed per tick.
    pub execute_limit: usize,
}

impl Default for GateTimeoutKernelConfig {
    fn default() -> Self {
        Self {
            observe_limit: 0,
            execute_limit: 64,
        }
    }
}

/// Errors from timeout-kernel construction or tick execution.
#[derive(Debug, thiserror::Error)]
pub enum GateTimeoutKernelError {
    /// Initialization failure.
    #[error("timeout kernel init failed: {0}")]
    Init(String),
    /// Tick execution failure.
    #[error("timeout kernel tick failed: {0}")]
    Tick(String),
}

/// Durable timeout-kernel runtime state.
pub struct GateTimeoutKernel {
    domain: GateTimeoutDomain,
    ledger_reader: NoopLedgerReader,
    cursor_store: TimeoutCursorStore,
    intent_store: TimeoutIntentStore,
    effect_journal: GateTimeoutEffectJournal,
    receipt_writer: GateTimeoutReceiptWriter,
    tick_config: TickConfig,
}

impl GateTimeoutKernel {
    /// Creates a new timeout kernel instance.
    pub fn new(
        orchestrator: Arc<GateOrchestrator>,
        sqlite_conn: Option<&Arc<Mutex<Connection>>>,
        timeout_ledger_emitter: Option<SqliteLedgerEventEmitter>,
        fac_root: &Path,
        config: GateTimeoutKernelConfig,
    ) -> Result<Self, GateTimeoutKernelError> {
        let cursor_store = if let Some(conn) = sqlite_conn {
            TimeoutCursorStore::Sqlite(SqliteTimeoutCursorStore::new(Arc::clone(conn)).map_err(
                |e| GateTimeoutKernelError::Init(format!("cursor store setup failed: {e}")),
            )?)
        } else {
            TimeoutCursorStore::Memory(MemoryTimeoutCursorStore::default())
        };

        let intent_store = if let Some(conn) = sqlite_conn {
            TimeoutIntentStore::Sqlite(SqliteTimeoutIntentStore::new(Arc::clone(conn)).map_err(
                |e| GateTimeoutKernelError::Init(format!("intent store setup failed: {e}")),
            )?)
        } else {
            TimeoutIntentStore::Memory(MemoryTimeoutIntentStore::default())
        };

        std::fs::create_dir_all(fac_root).map_err(|e| {
            GateTimeoutKernelError::Init(format!(
                "failed to create FAC root '{}': {e}",
                fac_root.display()
            ))
        })?;
        let journal_path = fac_root.join("gate_timeout_effect_journal.sqlite");
        let effect_journal =
            GateTimeoutEffectJournal::open(&journal_path).map_err(GateTimeoutKernelError::Init)?;

        Ok(Self {
            domain: GateTimeoutDomain::new(orchestrator),
            ledger_reader: NoopLedgerReader,
            cursor_store,
            intent_store,
            effect_journal,
            receipt_writer: GateTimeoutReceiptWriter::new(timeout_ledger_emitter),
            tick_config: TickConfig {
                observe_limit: config.observe_limit,
                execute_limit: config.execute_limit,
            },
        })
    }

    /// Runs one timeout-kernel tick.
    pub async fn tick(&mut self) -> Result<TickReport, GateTimeoutKernelError> {
        run_tick(
            &mut self.domain,
            &self.ledger_reader,
            &self.cursor_store,
            &self.intent_store,
            &self.effect_journal,
            &self.receipt_writer,
            self.tick_config,
        )
        .await
        .map_err(|e| GateTimeoutKernelError::Tick(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TimeoutObservedEvent {
    timestamp_ns: u64,
    event_id: String,
}

impl CursorEvent for TimeoutObservedEvent {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn event_id(&self) -> &str {
        &self.event_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateTimeoutIntent {
    work_id: String,
    gate_type: GateType,
}

impl GateTimeoutIntent {
    fn key(&self) -> String {
        format!("{}::{}", self.work_id, gate_type_label(self.gate_type))
    }
}

struct GateTimeoutDomain {
    orchestrator: Arc<GateOrchestrator>,
}

impl GateTimeoutDomain {
    const fn new(orchestrator: Arc<GateOrchestrator>) -> Self {
        Self { orchestrator }
    }
}

impl OrchestratorDomain<TimeoutObservedEvent, GateTimeoutIntent, String, GateOrchestratorEvent>
    for GateTimeoutDomain
{
    type Error = String;

    fn intent_key(&self, intent: &GateTimeoutIntent) -> String {
        intent.key()
    }

    async fn apply_events(&mut self, _events: &[TimeoutObservedEvent]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn plan(&mut self) -> Result<Vec<GateTimeoutIntent>, Self::Error> {
        let timed_out = self.orchestrator.check_timeouts().await;
        Ok(timed_out
            .into_iter()
            .map(|(work_id, gate_type)| GateTimeoutIntent { work_id, gate_type })
            .collect())
    }

    async fn execute(
        &mut self,
        intent: &GateTimeoutIntent,
    ) -> Result<ExecutionOutcome<GateOrchestratorEvent>, Self::Error> {
        match self
            .orchestrator
            .handle_gate_timeout(&intent.work_id, intent.gate_type)
            .await
        {
            Ok((_outcomes, events)) => Ok(ExecutionOutcome::Completed { receipts: events }),
            Err(error) => Ok(ExecutionOutcome::Blocked {
                reason: format!(
                    "timeout execution blocked for work_id='{}' gate='{}': {error}",
                    intent.work_id,
                    gate_type_label(intent.gate_type)
                ),
            }),
        }
    }
}

#[derive(Debug)]
struct NoopLedgerReader;

impl LedgerReader<TimeoutObservedEvent> for NoopLedgerReader {
    type Error = String;

    async fn poll(
        &self,
        _cursor: &CompositeCursor,
        _limit: usize,
    ) -> Result<Vec<TimeoutObservedEvent>, Self::Error> {
        Ok(Vec::new())
    }
}

#[derive(Debug)]
enum TimeoutCursorStore {
    Sqlite(SqliteTimeoutCursorStore),
    Memory(MemoryTimeoutCursorStore),
}

impl CursorStore for TimeoutCursorStore {
    type Error = String;

    async fn load(&self) -> Result<CompositeCursor, Self::Error> {
        match self {
            Self::Sqlite(store) => store.load(),
            Self::Memory(store) => store.load(),
        }
    }

    async fn save(&self, cursor: &CompositeCursor) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.save(cursor),
            Self::Memory(store) => store.save(cursor),
        }
    }
}

#[derive(Debug)]
struct SqliteTimeoutCursorStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutCursorStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        guard
            .execute(
                "CREATE TABLE IF NOT EXISTS gate_timeout_kernel_cursor (
                    cursor_key INTEGER PRIMARY KEY CHECK (cursor_key = 1),
                    timestamp_ns INTEGER NOT NULL,
                    event_id TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| format!("failed to create gate_timeout_kernel_cursor: {e}"))?;
        drop(guard);
        Ok(Self { conn })
    }

    fn load(&self) -> Result<CompositeCursor, String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        let row: Option<(i64, String)> = guard
            .query_row(
                "SELECT timestamp_ns, event_id
                 FROM gate_timeout_kernel_cursor
                 WHERE cursor_key = ?1",
                params![TIMEOUT_CURSOR_KEY],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| format!("failed to load timeout cursor: {e}"))?;
        let Some((timestamp_ns, event_id)) = row else {
            return Ok(CompositeCursor::default());
        };
        let timestamp_ns = u64::try_from(timestamp_ns)
            .map_err(|_| "timeout cursor timestamp is negative".to_string())?;
        Ok(CompositeCursor {
            timestamp_ns,
            event_id,
        })
    }

    fn save(&self, cursor: &CompositeCursor) -> Result<(), String> {
        let timestamp_ns = i64::try_from(cursor.timestamp_ns)
            .map_err(|_| "timeout cursor timestamp exceeds i64 range".to_string())?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO gate_timeout_kernel_cursor (cursor_key, timestamp_ns, event_id)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(cursor_key) DO UPDATE SET
                   timestamp_ns = excluded.timestamp_ns,
                   event_id = excluded.event_id",
                params![TIMEOUT_CURSOR_KEY, timestamp_ns, &cursor.event_id],
            )
            .map_err(|e| format!("failed to save timeout cursor: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MemoryTimeoutCursorStore {
    cursor: Mutex<CompositeCursor>,
}

impl MemoryTimeoutCursorStore {
    fn load(&self) -> Result<CompositeCursor, String> {
        Ok(self
            .cursor
            .lock()
            .map_err(|e| format!("memory cursor lock poisoned: {e}"))?
            .clone())
    }

    fn save(&self, cursor: &CompositeCursor) -> Result<(), String> {
        *self
            .cursor
            .lock()
            .map_err(|e| format!("memory cursor lock poisoned: {e}"))? = cursor.clone();
        Ok(())
    }
}

#[derive(Debug)]
enum TimeoutIntentStore {
    Sqlite(SqliteTimeoutIntentStore),
    Memory(MemoryTimeoutIntentStore),
}

impl IntentStore<GateTimeoutIntent, String> for TimeoutIntentStore {
    type Error = String;

    async fn enqueue_many(&self, intents: &[GateTimeoutIntent]) -> Result<usize, Self::Error> {
        match self {
            Self::Sqlite(store) => store.enqueue_many(intents),
            Self::Memory(store) => store.enqueue_many(intents),
        }
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateTimeoutIntent>, Self::Error> {
        match self {
            Self::Sqlite(store) => store.dequeue_batch(limit),
            Self::Memory(store) => store.dequeue_batch(limit),
        }
    }

    async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_done(key),
            Self::Memory(store) => store.mark_done(key),
        }
    }

    async fn mark_blocked(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_blocked(key, reason),
            Self::Memory(store) => store.mark_blocked(key, reason),
        }
    }
}

#[derive(Debug)]
struct SqliteTimeoutIntentStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutIntentStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "CREATE TABLE IF NOT EXISTS gate_timeout_intents (
                    intent_key TEXT PRIMARY KEY,
                    work_id TEXT NOT NULL,
                    gate_type TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'done', 'blocked')),
                    blocked_reason TEXT,
                    created_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL
                )",
                [],
            )
            .map_err(|e| format!("failed to create gate_timeout_intents: {e}"))?;
        guard
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_gate_timeout_intents_pending
                 ON gate_timeout_intents(state, created_at_ns, intent_key)",
                [],
            )
            .map_err(|e| format!("failed to create idx_gate_timeout_intents_pending: {e}"))?;
        drop(guard);
        Ok(Self { conn })
    }

    fn enqueue_many(&self, intents: &[GateTimeoutIntent]) -> Result<usize, String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let tx = guard
            .unchecked_transaction()
            .map_err(|e| format!("failed to begin timeout intent transaction: {e}"))?;
        let mut inserted = 0usize;
        for intent in intents {
            let key = intent.key();
            let gate_type = gate_type_label(intent.gate_type);
            let rows = tx
                .execute(
                    "INSERT OR IGNORE INTO gate_timeout_intents
                     (intent_key, work_id, gate_type, state, blocked_reason, created_at_ns, updated_at_ns)
                     VALUES (?1, ?2, ?3, 'pending', NULL, ?4, ?5)",
                    params![key, &intent.work_id, gate_type, now_ns, now_ns],
                )
                .map_err(|e| format!("failed to enqueue timeout intent: {e}"))?;
            inserted = inserted.saturating_add(rows);
        }
        tx.commit()
            .map_err(|e| format!("failed to commit timeout intent transaction: {e}"))?;
        Ok(inserted)
    }

    fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateTimeoutIntent>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_i64 =
            i64::try_from(limit).map_err(|_| "execute limit exceeds i64 range".to_string())?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let mut stmt = guard
            .prepare(
                "SELECT work_id, gate_type
                 FROM gate_timeout_intents
                 WHERE state = 'pending'
                 ORDER BY created_at_ns ASC, intent_key ASC
                 LIMIT ?1",
            )
            .map_err(|e| format!("failed to prepare timeout dequeue query: {e}"))?;
        let rows = stmt
            .query_map(params![limit_i64], |row| {
                let work_id: String = row.get(0)?;
                let gate_type_raw: String = row.get(1)?;
                Ok((work_id, gate_type_raw))
            })
            .map_err(|e| format!("failed to query timeout intents: {e}"))?;

        let mut intents = Vec::new();
        for row in rows {
            let (work_id, gate_type_raw) =
                row.map_err(|e| format!("failed to decode timeout intent row: {e}"))?;
            let Some(gate_type) = parse_gate_type(&gate_type_raw) else {
                return Err(format!(
                    "unknown gate_type '{gate_type_raw}' in timeout intents"
                ));
            };
            intents.push(GateTimeoutIntent { work_id, gate_type });
        }
        Ok(intents)
    }

    fn mark_done(&self, key: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE gate_timeout_intents
                 SET state = 'done', blocked_reason = NULL, updated_at_ns = ?2
                 WHERE intent_key = ?1",
                params![key, now_ns],
            )
            .map_err(|e| format!("failed to mark timeout intent done: {e}"))?;
        Ok(())
    }

    fn mark_blocked(&self, key: &str, reason: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE gate_timeout_intents
                 SET state = 'blocked', blocked_reason = ?2, updated_at_ns = ?3
                 WHERE intent_key = ?1",
                params![key, reason, now_ns],
            )
            .map_err(|e| format!("failed to mark timeout intent blocked: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MemoryTimeoutIntentStore {
    pending: Mutex<VecDeque<GateTimeoutIntent>>,
    states: Mutex<HashMap<String, String>>,
}

impl MemoryTimeoutIntentStore {
    fn enqueue_many(&self, intents: &[GateTimeoutIntent]) -> Result<usize, String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|e| format!("memory intent pending lock poisoned: {e}"))?;
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("memory intent states lock poisoned: {e}"))?;
        let mut inserted = 0usize;
        for intent in intents {
            let key = intent.key();
            if states.contains_key(&key) {
                continue;
            }
            states.insert(key, "pending".to_string());
            pending.push_back(intent.clone());
            inserted = inserted.saturating_add(1);
        }
        Ok(inserted)
    }

    fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateTimeoutIntent>, String> {
        let pending = self
            .pending
            .lock()
            .map_err(|e| format!("memory intent pending lock poisoned: {e}"))?;
        Ok(pending.iter().take(limit).cloned().collect())
    }

    fn remove_pending(&self, key: &str) -> Result<(), String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|e| format!("memory intent pending lock poisoned: {e}"))?;
        pending.retain(|intent| intent.key() != key);
        Ok(())
    }

    fn mark_done(&self, key: &str) -> Result<(), String> {
        self.remove_pending(key)?;
        self.states
            .lock()
            .map_err(|e| format!("memory intent states lock poisoned: {e}"))?
            .insert(key.to_string(), "done".to_string());
        Ok(())
    }

    fn mark_blocked(&self, key: &str, _reason: &str) -> Result<(), String> {
        self.remove_pending(key)?;
        self.states
            .lock()
            .map_err(|e| format!("memory intent states lock poisoned: {e}"))?
            .insert(key.to_string(), "blocked".to_string());
        Ok(())
    }
}

#[derive(Debug)]
struct GateTimeoutEffectJournal {
    conn: Arc<Mutex<Connection>>,
}

impl GateTimeoutEffectJournal {
    fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open timeout effect journal sqlite db: {e}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS gate_timeout_effect_journal_state (
                intent_key TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK (state IN ('started', 'completed', 'unknown')),
                updated_at_ns INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("failed to create gate_timeout_effect_journal_state table: {e}"))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn load_state(&self, key: &str) -> Result<Option<String>, String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("timeout effect journal lock poisoned: {e}"))?;
        guard
            .query_row(
                "SELECT state
                 FROM gate_timeout_effect_journal_state
                 WHERE intent_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to load timeout effect state for key '{key}': {e}"))
    }

    fn upsert_state(&self, key: &str, state: &str, updated_at_ns: i64) -> Result<(), String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("timeout effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO gate_timeout_effect_journal_state (intent_key, state, updated_at_ns)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(intent_key) DO UPDATE SET
                     state = excluded.state,
                     updated_at_ns = excluded.updated_at_ns",
                params![key, state, updated_at_ns],
            )
            .map_err(|e| {
                format!("failed to upsert timeout effect state='{state}' for key '{key}': {e}")
            })?;
        Ok(())
    }
}

impl EffectJournal<String> for GateTimeoutEffectJournal {
    type Error = String;

    async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
        let state = self.load_state(key.as_str())?;
        Ok(match state.as_deref() {
            None => EffectExecutionState::NotStarted,
            Some("completed") => EffectExecutionState::Completed,
            // Any non-terminal marker is in-doubt for timeout effects and is
            // handled fail-closed via explicit `resolve_in_doubt`.
            Some(_) => EffectExecutionState::Unknown,
        })
    }

    async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
        if matches!(self.load_state(key.as_str())?.as_deref(), Some("completed")) {
            return Ok(());
        }
        self.upsert_state(key.as_str(), "started", epoch_now_ns_i64()?)
    }

    async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
        self.upsert_state(key.as_str(), "completed", epoch_now_ns_i64()?)
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        self.upsert_state(key.as_str(), "unknown", epoch_now_ns_i64()?)?;
        Ok(InDoubtResolution::Deny {
            reason: "timeout effect state is in-doubt; manual reconciliation required".to_string(),
        })
    }
}

#[derive(Debug)]
struct GateTimeoutReceiptWriter {
    ledger_emitter: Option<SqliteLedgerEventEmitter>,
}

impl GateTimeoutReceiptWriter {
    const fn new(ledger_emitter: Option<SqliteLedgerEventEmitter>) -> Self {
        Self { ledger_emitter }
    }
}

impl ReceiptWriter<GateOrchestratorEvent> for GateTimeoutReceiptWriter {
    type Error = String;

    async fn persist_many(&self, receipts: &[GateOrchestratorEvent]) -> Result<(), Self::Error> {
        let Some(emitter) = self.ledger_emitter.as_ref() else {
            return Ok(());
        };

        for event in receipts {
            let (event_type, timestamp_ns) = timeout_event_persistence_fields(event);
            let payload = serde_json::to_vec(event)
                .map_err(|e| format!("failed to serialize timeout event for persistence: {e}"))?;
            emitter
                .emit_session_event(
                    TIMEOUT_PERSISTOR_SESSION_ID,
                    event_type,
                    &payload,
                    TIMEOUT_PERSISTOR_ACTOR_ID,
                    timestamp_ns,
                )
                .map_err(|e| format!("failed to persist timeout event to ledger: {e}"))?;
        }
        Ok(())
    }
}

/// Maps orchestrator events to persisted event type and timestamp.
#[must_use]
pub fn timeout_event_persistence_fields(event: &GateOrchestratorEvent) -> (&'static str, u64) {
    match event {
        GateOrchestratorEvent::GateTimedOut { timestamp_ms, .. } => {
            ("gate.timed_out", timestamp_ms.saturating_mul(1_000_000))
        },
        GateOrchestratorEvent::GateTimeoutReceiptGenerated { timestamp_ms, .. } => (
            "gate.timeout_receipt_generated",
            timestamp_ms.saturating_mul(1_000_000),
        ),
        GateOrchestratorEvent::AllGatesCompleted { timestamp_ms, .. } => {
            ("gate.all_completed", timestamp_ms.saturating_mul(1_000_000))
        },
        _ => ("gate.event", epoch_now_ns_u64()),
    }
}

const fn gate_type_label(gate_type: GateType) -> &'static str {
    match gate_type {
        GateType::Aat => "aat",
        GateType::Quality => "quality",
        GateType::Security => "security",
    }
}

fn parse_gate_type(raw: &str) -> Option<GateType> {
    match raw {
        "aat" => Some(GateType::Aat),
        "quality" => Some(GateType::Quality),
        "security" => Some(GateType::Security),
        _ => None,
    }
}

fn epoch_now_ns_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn epoch_now_ns_i64() -> Result<i64, String> {
    i64::try_from(epoch_now_ns_u64())
        .map_err(|_| "current epoch timestamp exceeds i64 range".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_event_mapping_uses_expected_types() {
        let (event_type, _) =
            timeout_event_persistence_fields(&GateOrchestratorEvent::GateTimedOut {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                lease_id: "lease-1".to_string(),
                timestamp_ms: 7,
            });
        assert_eq!(event_type, "gate.timed_out");
    }
}
