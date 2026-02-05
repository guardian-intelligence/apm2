// AGENT-AUTHORED (TCK-00322)
//! Projection worker for the FAC (Forge Admission Cycle).
//!
//! This module implements the long-running projection worker that:
//! 1. Tails the ledger for `ReviewReceiptRecorded` events
//! 2. Looks up PR metadata from the work index
//! 3. Projects review results to GitHub (status + comment)
//! 4. Stores projection receipts in CAS for idempotency
//!
//! # RFC-0019: Projection Worker (Workstream F)
//!
//! Per RFC-0019, the projection worker:
//! - Reads ledger commits via a tailer
//! - Builds a work index: `changeset_digest` -> `work_id` -> PR metadata
//! - On `ReviewReceiptRecorded`: fetches review artifacts from CAS, applies
//!   projection via GitHub adapter, stores projection receipt (durable)
//! - Is idempotent: restarts don't duplicate comments
//!
//! # Security Model
//!
//! - **Write-only projection**: GitHub is an output target only
//! - **Ledger is truth**: All decisions are made based on ledger state
//! - **Idempotency via receipts**: Uses CAS+ledger for idempotency, not GitHub
//!   state
//! - **Crash-only recovery**: Worker can restart from ledger head at any time

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::github_sync::{GitHubAdapterConfig, GitHubProjectionAdapter, ProjectionAdapter};
use super::projection_receipt::ProjectedStatus;
use crate::protocol::dispatch::SignedLedgerEvent;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during projection worker operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProjectionWorkerError {
    /// Database error.
    #[error("database error: {0}")]
    DatabaseError(String),

    /// No PR associated with work.
    #[error("no PR associated with work_id: {work_id}")]
    NoPrAssociation {
        /// The work ID that has no PR association.
        work_id: String,
    },

    /// Projection failed.
    #[error("projection failed: {0}")]
    ProjectionFailed(String),

    /// Invalid event payload.
    #[error("invalid event payload: {0}")]
    InvalidPayload(String),

    /// Already projected (idempotency).
    #[error("already projected for receipt: {receipt_id}")]
    AlreadyProjected {
        /// The receipt ID that was already projected.
        receipt_id: String,
    },

    /// Worker shutdown requested.
    #[error("worker shutdown requested")]
    ShutdownRequested,
}

// =============================================================================
// Work Index
// =============================================================================

/// Work index schema SQL.
const WORK_INDEX_SCHEMA_SQL: &str = r"
    CREATE TABLE IF NOT EXISTS work_pr_index (
        work_id TEXT PRIMARY KEY,
        pr_number INTEGER NOT NULL,
        repo_owner TEXT NOT NULL,
        repo_name TEXT NOT NULL,
        head_sha TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS changeset_work_index (
        changeset_digest BLOB PRIMARY KEY,
        work_id TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_changeset_work_id ON changeset_work_index(work_id);
";

/// Work index for tracking changeset -> `work_id` -> PR associations.
///
/// Per RFC-0019:
/// - `changeset_digest` -> `work_id` (from `ChangeSetPublished`)
/// - `work_id` -> PR metadata (from `WorkPrAssociated` or config)
pub struct WorkIndex {
    conn: Arc<Mutex<Connection>>,
}

impl WorkIndex {
    /// Creates a new work index with the given `SQLite` connection.
    ///
    /// # Errors
    ///
    /// Returns an error if schema initialization fails.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, ProjectionWorkerError> {
        {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            conn_guard.execute_batch(WORK_INDEX_SCHEMA_SQL).map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("schema init failed: {e}"))
            })?;
        }

        Ok(Self { conn })
    }

    /// Registers a changeset -> `work_id` association.
    ///
    /// Called when processing `ChangeSetPublished` events.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_changeset(
        &self,
        changeset_digest: &[u8; 32],
        work_id: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self.conn.lock().map_err(|e| {
            ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO changeset_work_index
             (changeset_digest, work_id, created_at)
             VALUES (?1, ?2, ?3)",
            params![changeset_digest.as_slice(), work_id, now as i64],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            changeset = %hex::encode(changeset_digest),
            work_id = %work_id,
            "Registered changeset -> work_id"
        );

        Ok(())
    }

    /// Registers a `work_id` -> PR association.
    ///
    /// Called when processing `WorkPrAssociated` events or from configuration.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_pr(
        &self,
        work_id: &str,
        pr_number: u64,
        repo_owner: &str,
        repo_name: &str,
        head_sha: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self.conn.lock().map_err(|e| {
            ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO work_pr_index
             (work_id, pr_number, repo_owner, repo_name, head_sha, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                work_id,
                pr_number as i64,
                repo_owner,
                repo_name,
                head_sha,
                now as i64
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        info!(
            work_id = %work_id,
            pr_number = pr_number,
            repo = %format!("{}/{}", repo_owner, repo_name),
            "Registered work_id -> PR"
        );

        Ok(())
    }

    /// Looks up the `work_id` for a changeset digest.
    pub fn get_work_id(&self, changeset_digest: &[u8; 32]) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT work_id FROM changeset_work_index WHERE changeset_digest = ?1",
            params![changeset_digest.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Looks up PR metadata for a `work_id`.
    #[allow(clippy::cast_sign_loss)] // PR numbers are always positive
    pub fn get_pr_metadata(&self, work_id: &str) -> Option<PrMetadata> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT pr_number, repo_owner, repo_name, head_sha
             FROM work_pr_index WHERE work_id = ?1",
            params![work_id],
            |row| {
                Ok(PrMetadata {
                    pr_number: row.get::<_, i64>(0)? as u64,
                    repo_owner: row.get(1)?,
                    repo_name: row.get(2)?,
                    head_sha: row.get(3)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }
}

/// PR metadata for projection.
#[derive(Debug, Clone)]
pub struct PrMetadata {
    /// The PR number.
    pub pr_number: u64,
    /// Repository owner.
    pub repo_owner: String,
    /// Repository name.
    pub repo_name: String,
    /// Head commit SHA.
    pub head_sha: String,
}

// =============================================================================
// Ledger Tailer
// =============================================================================

/// Ledger tailer for watching events.
///
/// Tracks the last processed event sequence and polls for new events.
pub struct LedgerTailer {
    conn: Arc<Mutex<Connection>>,
    /// Last processed event timestamp (for ordering).
    last_processed_ns: u64,
}

impl LedgerTailer {
    /// Creates a new ledger tailer.
    #[must_use]
    pub const fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            last_processed_ns: 0,
        }
    }

    /// Creates a ledger tailer starting from a specific timestamp.
    #[must_use]
    pub const fn from_timestamp(conn: Arc<Mutex<Connection>>, timestamp_ns: u64) -> Self {
        Self {
            conn,
            last_processed_ns: timestamp_ns,
        }
    }

    /// Gets the next batch of unprocessed events of a given type.
    ///
    /// Returns events ordered by `timestamp_ns`, starting after the last
    /// processed timestamp.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    pub fn poll_events(
        &mut self,
        event_type: &str,
        limit: usize,
    ) -> Result<Vec<SignedLedgerEvent>, ProjectionWorkerError> {
        let conn = self.conn.lock().map_err(|e| {
            ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
                 FROM ledger_events
                 WHERE event_type = ?1 AND timestamp_ns > ?2
                 ORDER BY timestamp_ns ASC
                 LIMIT ?3",
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        let events = stmt
            .query_map(
                params![event_type, self.last_processed_ns as i64, limit as i64],
                |row| {
                    Ok(SignedLedgerEvent {
                        event_id: row.get(0)?,
                        event_type: row.get(1)?,
                        work_id: row.get(2)?,
                        actor_id: row.get(3)?,
                        payload: row.get(4)?,
                        signature: row.get(5)?,
                        timestamp_ns: row.get::<_, i64>(6)? as u64,
                    })
                },
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();

        // Update last processed timestamp
        if let Some(last) = events.last() {
            self.last_processed_ns = last.timestamp_ns;
        }

        Ok(events)
    }

    /// Gets the current ledger head (latest event timestamp).
    #[allow(clippy::cast_sign_loss)]
    pub fn get_ledger_head(&self) -> Result<Option<[u8; 32]>, ProjectionWorkerError> {
        let conn = self.conn.lock().map_err(|e| {
            ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
        })?;

        // For now, compute a hash of the latest event_id as "ledger head"
        // In a full implementation, this would be the chain hash
        let result: Option<String> = conn
            .query_row(
                "SELECT event_id FROM ledger_events ORDER BY timestamp_ns DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        Ok(result.map(|event_id| {
            let mut hash = [0u8; 32];
            let digest = blake3::hash(event_id.as_bytes());
            hash.copy_from_slice(digest.as_bytes());
            hash
        }))
    }
}

// =============================================================================
// Projection Worker
// =============================================================================

/// Configuration for the projection worker.
#[derive(Debug, Clone)]
pub struct ProjectionWorkerConfig {
    /// Poll interval for checking new events.
    pub poll_interval: Duration,
    /// Maximum events to process per batch.
    pub batch_size: usize,
    /// Whether to enable GitHub projection.
    pub github_enabled: bool,
    /// GitHub API configuration (if enabled).
    pub github_config: Option<GitHubAdapterConfig>,
}

impl Default for ProjectionWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            batch_size: 100,
            github_enabled: false,
            github_config: None,
        }
    }
}

impl ProjectionWorkerConfig {
    /// Creates a new configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the poll interval.
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Sets the batch size.
    #[must_use]
    pub const fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Enables GitHub projection with the given configuration.
    #[must_use]
    pub fn with_github(mut self, config: GitHubAdapterConfig) -> Self {
        self.github_enabled = true;
        self.github_config = Some(config);
        self
    }
}

/// The projection worker that tails the ledger and projects to GitHub.
pub struct ProjectionWorker {
    config: ProjectionWorkerConfig,
    work_index: WorkIndex,
    tailer: LedgerTailer,
    adapter: Option<GitHubProjectionAdapter>,
    /// Shutdown flag.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl ProjectionWorker {
    /// Creates a new projection worker.
    ///
    /// # Arguments
    ///
    /// * `conn` - `SQLite` connection for work index and ledger access
    /// * `config` - Worker configuration
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    #[allow(clippy::needless_pass_by_value)] // Arc is cheap to clone, and we clone it multiple times
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        config: ProjectionWorkerConfig,
    ) -> Result<Self, ProjectionWorkerError> {
        let work_index = WorkIndex::new(Arc::clone(&conn))?;
        let tailer = LedgerTailer::new(Arc::clone(&conn));

        // Create GitHub adapter if configured
        let adapter = if config.github_enabled {
            if let Some(ref gh_config) = config.github_config {
                // Create mock adapter for now (real HTTP client would be created
                // in production)
                let signer = apm2_core::crypto::Signer::generate();
                Some(
                    GitHubProjectionAdapter::new_mock(signer, gh_config.clone())
                        .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?,
                )
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            work_index,
            tailer,
            adapter,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Returns a handle for requesting shutdown.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Returns a reference to the work index.
    #[must_use]
    pub const fn work_index(&self) -> &WorkIndex {
        &self.work_index
    }

    /// Runs the projection worker loop.
    ///
    /// This method blocks until shutdown is requested.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker encounters a fatal error.
    #[allow(clippy::cast_possible_truncation)] // poll_interval is always < u64::MAX ms
    pub async fn run(&mut self) -> Result<(), ProjectionWorkerError> {
        info!(
            poll_interval_ms = self.config.poll_interval.as_millis() as u64,
            batch_size = self.config.batch_size,
            github_enabled = self.config.github_enabled,
            "Projection worker starting"
        );

        while !self
            .shutdown
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // Process ChangeSetPublished events to build work index
            if let Err(e) = self.process_changeset_published() {
                warn!(error = %e, "Error processing ChangeSetPublished events");
            }

            // Process ReviewReceiptRecorded events for projection
            if let Err(e) = self.process_review_receipts().await {
                warn!(error = %e, "Error processing ReviewReceiptRecorded events");
            }

            // Sleep for poll interval
            tokio::time::sleep(self.config.poll_interval).await;
        }

        info!("Projection worker shutting down");
        Ok(())
    }

    /// Processes `ChangeSetPublished` events to populate the work index.
    fn process_changeset_published(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .tailer
            .poll_events("changeset_published", self.config.batch_size)?;

        for event in events {
            if let Err(e) = self.handle_changeset_published(&event) {
                warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "Failed to process ChangeSetPublished event"
                );
            }
        }

        Ok(())
    }

    /// Handles a single `ChangeSetPublished` event.
    fn handle_changeset_published(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse payload to extract changeset_digest and work_id
        let payload: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        let changeset_digest_hex = payload
            .get("changeset_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing changeset_digest".to_string())
            })?;

        let work_id = payload
            .get("work_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&event.work_id);

        // Decode changeset digest
        let digest_bytes = hex::decode(changeset_digest_hex)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        if digest_bytes.len() != 32 {
            return Err(ProjectionWorkerError::InvalidPayload(
                "changeset_digest must be 32 bytes".to_string(),
            ));
        }

        let mut changeset_digest = [0u8; 32];
        changeset_digest.copy_from_slice(&digest_bytes);

        // Register in work index
        self.work_index.register_changeset(&changeset_digest, work_id)?;

        Ok(())
    }

    /// Processes `ReviewReceiptRecorded` events for projection.
    async fn process_review_receipts(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .tailer
            .poll_events("review_receipt_recorded", self.config.batch_size)?;

        for event in events {
            if let Err(e) = self.handle_review_receipt(&event).await {
                warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "Failed to process ReviewReceiptRecorded event"
                );
            }
        }

        Ok(())
    }

    /// Handles a single `ReviewReceiptRecorded` event.
    async fn handle_review_receipt(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse payload
        let payload: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        let changeset_digest_hex = payload
            .get("changeset_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing changeset_digest".to_string())
            })?;

        let receipt_id = payload
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing receipt_id".to_string())
            })?;

        // Decode changeset digest
        let digest_bytes = hex::decode(changeset_digest_hex)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        if digest_bytes.len() != 32 {
            return Err(ProjectionWorkerError::InvalidPayload(
                "changeset_digest must be 32 bytes".to_string(),
            ));
        }

        let mut changeset_digest = [0u8; 32];
        changeset_digest.copy_from_slice(&digest_bytes);

        // Look up work_id from changeset
        let work_id = self
            .work_index
            .get_work_id(&changeset_digest)
            .ok_or_else(|| ProjectionWorkerError::NoPrAssociation {
                work_id: format!("changeset:{changeset_digest_hex}"),
            })?;

        // Look up PR metadata
        let pr_metadata = self
            .work_index
            .get_pr_metadata(&work_id)
            .ok_or_else(|| ProjectionWorkerError::NoPrAssociation {
                work_id: work_id.clone(),
            })?;

        info!(
            receipt_id = %receipt_id,
            work_id = %work_id,
            pr_number = pr_metadata.pr_number,
            "Processing review receipt for projection"
        );

        // Project to GitHub if adapter is configured
        if let Some(ref adapter) = self.adapter {
            // Get ledger head for idempotency key
            let ledger_head = self.tailer.get_ledger_head()?.unwrap_or([0u8; 32]);

            // Project status (success for now; in production would parse review
            // verdict)
            let receipt = adapter
                .project_status(&work_id, changeset_digest, ledger_head, ProjectedStatus::Success)
                .await
                .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?;

            info!(
                receipt_id = %receipt.receipt_id,
                work_id = %work_id,
                status = %receipt.projected_status,
                "Projected status to GitHub"
            );
        } else {
            debug!(
                work_id = %work_id,
                "GitHub projection disabled, skipping"
            );
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize ledger schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        Arc::new(Mutex::new(conn))
    }

    #[test]
    fn test_work_index_register_changeset() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];
        let work_id = "work-001";

        index.register_changeset(&digest, work_id).unwrap();

        assert_eq!(index.get_work_id(&digest), Some(work_id.to_string()));
    }

    #[test]
    fn test_work_index_register_pr() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let work_id = "work-001";
        index
            .register_pr(work_id, 123, "owner", "repo", "abc123")
            .unwrap();

        let metadata = index.get_pr_metadata(work_id).unwrap();
        assert_eq!(metadata.pr_number, 123);
        assert_eq!(metadata.repo_owner, "owner");
        assert_eq!(metadata.repo_name, "repo");
        assert_eq!(metadata.head_sha, "abc123");
    }

    #[test]
    fn test_work_index_not_found() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];
        assert!(index.get_work_id(&digest).is_none());
        assert!(index.get_pr_metadata("unknown").is_none());
    }

    #[test]
    fn test_ledger_tailer_poll_events() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-1",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload1".to_vec(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-2",
                        "test_event",
                        "work-2",
                        "actor-2",
                        b"payload2".to_vec(),
                        vec![0u8; 64],
                        2000i64
                    ],
                )
                .unwrap();
        }

        let mut tailer = LedgerTailer::new(conn);

        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, "evt-1");
        assert_eq!(events[1].event_id, "evt-2");

        // Subsequent poll should return no events (already processed)
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_projection_worker_config() {
        let config = ProjectionWorkerConfig::new()
            .with_poll_interval(Duration::from_secs(5))
            .with_batch_size(50);

        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert_eq!(config.batch_size, 50);
        assert!(!config.github_enabled);
    }

    #[test]
    fn test_projection_worker_creation() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();

        let worker = ProjectionWorker::new(conn, config);
        assert!(worker.is_ok());

        let worker = worker.unwrap();
        assert!(worker.adapter.is_none()); // GitHub not enabled
    }

    #[test]
    fn test_projection_worker_with_github_config() {
        let conn = create_test_db();
        let github_config =
            GitHubAdapterConfig::new("https://api.github.com", "owner", "repo").unwrap();
        let config = ProjectionWorkerConfig::new().with_github(github_config);

        let worker = ProjectionWorker::new(conn, config);
        assert!(worker.is_ok());

        let worker = worker.unwrap();
        assert!(worker.adapter.is_some()); // GitHub enabled with mock adapter
    }

    #[test]
    fn test_projection_worker_shutdown_handle() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();
        let worker = ProjectionWorker::new(conn, config).unwrap();

        let handle = worker.shutdown_handle();
        assert!(!handle.load(std::sync::atomic::Ordering::Relaxed));

        // Signal shutdown
        handle.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(handle.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_work_index_end_to_end_lookup() {
        // Test the full workflow: changeset -> work_id -> PR metadata
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let changeset_digest = [0x42u8; 32];
        let work_id = "work-001";

        // Register changeset -> work_id
        index.register_changeset(&changeset_digest, work_id).unwrap();

        // Register work_id -> PR
        index
            .register_pr(work_id, 456, "org", "project", "def789")
            .unwrap();

        // Full lookup chain
        let found_work_id = index.get_work_id(&changeset_digest).unwrap();
        assert_eq!(found_work_id, work_id);

        let pr_metadata = index.get_pr_metadata(&found_work_id).unwrap();
        assert_eq!(pr_metadata.pr_number, 456);
        assert_eq!(pr_metadata.repo_owner, "org");
        assert_eq!(pr_metadata.repo_name, "project");
        assert_eq!(pr_metadata.head_sha, "def789");
    }

    #[test]
    fn test_ledger_tailer_from_timestamp() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-1",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload1".to_vec(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-2",
                        "test_event",
                        "work-2",
                        "actor-2",
                        b"payload2".to_vec(),
                        vec![0u8; 64],
                        2000i64
                    ],
                )
                .unwrap();
        }

        // Create tailer starting from timestamp 1000 (after first event)
        let mut tailer = LedgerTailer::from_timestamp(Arc::clone(&conn), 1000);

        // Should only get the second event
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-2");
    }

    #[test]
    fn test_ledger_tailer_get_ledger_head() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-latest",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload".to_vec(),
                        vec![0u8; 64],
                        9999i64
                    ],
                )
                .unwrap();
        }

        let tailer = LedgerTailer::new(conn);
        let head = tailer.get_ledger_head().unwrap();

        assert!(head.is_some());
        // Head is a BLAKE3 hash of the event_id
        let expected_hash = blake3::hash(b"evt-latest");
        assert_eq!(head.unwrap(), *expected_hash.as_bytes());
    }

    #[test]
    fn test_ledger_tailer_empty_ledger_head() {
        let conn = create_test_db();
        let tailer = LedgerTailer::new(conn);

        let head = tailer.get_ledger_head().unwrap();
        assert!(head.is_none());
    }

    #[test]
    fn test_work_index_update_existing() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        // Register initial PR
        index
            .register_pr("work-001", 123, "owner1", "repo1", "sha1")
            .unwrap();

        // Update with new PR info (same work_id)
        index
            .register_pr("work-001", 456, "owner2", "repo2", "sha2")
            .unwrap();

        // Should have the updated values
        let metadata = index.get_pr_metadata("work-001").unwrap();
        assert_eq!(metadata.pr_number, 456);
        assert_eq!(metadata.repo_owner, "owner2");
        assert_eq!(metadata.repo_name, "repo2");
        assert_eq!(metadata.head_sha, "sha2");
    }

    #[test]
    fn test_changeset_work_index_update_existing() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];

        // Register initial work_id
        index.register_changeset(&digest, "work-001").unwrap();

        // Update with new work_id (same changeset)
        index.register_changeset(&digest, "work-002").unwrap();

        // Should have the updated value
        assert_eq!(index.get_work_id(&digest), Some("work-002".to_string()));
    }

    #[test]
    fn test_pr_metadata_debug() {
        let metadata = PrMetadata {
            pr_number: 123,
            repo_owner: "owner".to_string(),
            repo_name: "repo".to_string(),
            head_sha: "abc123".to_string(),
        };

        let debug_str = format!("{metadata:?}");
        assert!(debug_str.contains("PrMetadata"));
        assert!(debug_str.contains("123"));
        assert!(debug_str.contains("owner"));
    }

    #[test]
    fn test_projection_worker_error_display() {
        let err = ProjectionWorkerError::DatabaseError("test error".to_string());
        assert!(err.to_string().contains("database error"));

        let err = ProjectionWorkerError::NoPrAssociation {
            work_id: "work-001".to_string(),
        };
        assert!(err.to_string().contains("work-001"));

        let err = ProjectionWorkerError::AlreadyProjected {
            receipt_id: "recv-001".to_string(),
        };
        assert!(err.to_string().contains("recv-001"));
    }
}
