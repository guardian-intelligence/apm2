use std::sync::{Arc, RwLock};

use apm2_core::work::{Work, WorkState};
use thiserror::Error;

use super::projection::{WorkObjectProjection, WorkProjectionError};
use crate::protocol::dispatch::LedgerEventEmitter;

/// Hard server-side cap on the number of rows returned by `WorkList`.
///
/// Enforced regardless of the client-requested `limit` to prevent unbounded
/// full-ledger replay on the request path.
pub const MAX_WORK_LIST_ROWS: usize = 500;

/// Projection-derived authority view for a single work item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAuthorityStatus {
    /// Work identifier.
    pub work_id: String,
    /// Current lifecycle state.
    pub state: WorkState,
    /// Whether the work item is currently claimable.
    pub claimable: bool,
    /// Work-open timestamp.
    pub created_at_ns: u64,
    /// Most recent transition timestamp.
    pub last_transition_at_ns: u64,
    /// Transition counter for replay protection.
    pub transition_count: u32,
    /// Timestamp of first claim transition when derivable.
    pub claimed_at_ns: Option<u64>,
}

/// Authority-layer errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WorkAuthorityError {
    /// Projection lock failed.
    #[error("projection lock failure: {message}")]
    ProjectionLock {
        /// Underlying lock error detail.
        message: String,
    },

    /// Projection rebuild failed.
    #[error("projection rebuild failed: {0}")]
    ProjectionRebuild(#[from] WorkProjectionError),

    /// Work ID is unknown to the projection.
    #[error("work not found in projection: {work_id}")]
    WorkNotFound {
        /// Missing work ID.
        work_id: String,
    },
}

/// Work lifecycle authority contract.
pub trait WorkAuthority: Send + Sync {
    /// Returns projection-derived status for a single work item.
    fn get_work_status(&self, work_id: &str) -> Result<WorkAuthorityStatus, WorkAuthorityError>;

    /// Returns claimable work items, bounded by `limit` and `cursor`.
    ///
    /// `limit` is clamped to `MAX_WORK_LIST_ROWS`. `cursor` is the last
    /// `work_id` from a previous page (exclusive start).
    fn list_claimable(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError>;

    /// Returns all known work items, bounded by `limit` and `cursor`.
    ///
    /// `limit` is clamped to `MAX_WORK_LIST_ROWS`. `cursor` is the last
    /// `work_id` from a previous page (exclusive start).
    fn list_all(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError>;

    /// Returns whether the work item is claimable.
    fn is_claimable(&self, work_id: &str) -> Result<bool, WorkAuthorityError>;
}

/// Projection-backed `WorkAuthority` implementation.
///
/// Authority is rebuilt from ledger events only; filesystem state is never
/// consulted. The projection is cached and only rebuilt when the event count
/// changes, avoiding O(N) full replay on every request.
pub struct ProjectionWorkAuthority {
    event_emitter: Arc<dyn LedgerEventEmitter>,
    projection: Arc<RwLock<WorkObjectProjection>>,
    /// Cached event count from the last successful rebuild. When the emitter
    /// reports a different count the projection is refreshed.
    last_event_count: Arc<RwLock<usize>>,
}

impl ProjectionWorkAuthority {
    /// Creates a projection-backed authority view over the provided emitter.
    #[must_use]
    pub fn new(event_emitter: Arc<dyn LedgerEventEmitter>) -> Self {
        Self {
            event_emitter,
            projection: Arc::new(RwLock::new(WorkObjectProjection::new())),
            last_event_count: Arc::new(RwLock::new(0)),
        }
    }

    fn refresh_projection(&self) -> Result<(), WorkAuthorityError> {
        let signed_events = self.event_emitter.get_all_events();
        let current_count = signed_events.len();

        // Check cached event count to avoid redundant rebuilds.
        {
            let cached =
                self.last_event_count
                    .read()
                    .map_err(|err| WorkAuthorityError::ProjectionLock {
                        message: err.to_string(),
                    })?;
            if *cached == current_count && current_count > 0 {
                return Ok(());
            }
        }

        // Verify signatures before projection admission (fail-closed).
        let verified_events =
            super::projection::verify_signed_events(&signed_events, &self.event_emitter)?;

        let mut projection =
            self.projection
                .write()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;
        projection.rebuild_from_signed_events(&verified_events)?;

        // Update cached event count after successful rebuild.
        if let Ok(mut cached) = self.last_event_count.write() {
            *cached = current_count;
        }
        Ok(())
    }

    fn status_from_work(work: &Work) -> WorkAuthorityStatus {
        WorkAuthorityStatus {
            work_id: work.work_id.clone(),
            state: work.state,
            claimable: work.state.is_claimable(),
            created_at_ns: work.opened_at,
            last_transition_at_ns: work.last_transition_at,
            transition_count: work.transition_count,
            claimed_at_ns: work.claimed_at,
        }
    }

    /// Clamps `limit` to `MAX_WORK_LIST_ROWS` and applies cursor-based
    /// pagination over a deterministically-ordered iterator.
    fn bounded_collect<'a, I>(iter: I, limit: usize, cursor: &str) -> Vec<WorkAuthorityStatus>
    where
        I: Iterator<Item = &'a Work>,
    {
        let effective_limit = if limit == 0 {
            MAX_WORK_LIST_ROWS
        } else {
            limit.min(MAX_WORK_LIST_ROWS)
        };

        let skip_past_cursor = !cursor.is_empty();

        let mut items: Vec<WorkAuthorityStatus> = iter
            .skip_while(|work| skip_past_cursor && work.work_id.as_str() <= cursor)
            .take(effective_limit)
            .map(Self::status_from_work)
            .collect();

        // Ensure deterministic ordering by work_id (BTreeMap already sorted).
        items.sort_by(|a, b| a.work_id.cmp(&b.work_id));
        items
    }
}

impl WorkAuthority for ProjectionWorkAuthority {
    fn get_work_status(&self, work_id: &str) -> Result<WorkAuthorityStatus, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        let work =
            projection
                .get_work(work_id)
                .ok_or_else(|| WorkAuthorityError::WorkNotFound {
                    work_id: work_id.to_string(),
                })?;

        Ok(Self::status_from_work(work))
    }

    fn list_claimable(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        Ok(Self::bounded_collect(
            projection.claimable_work().into_iter(),
            limit,
            cursor,
        ))
    }

    fn list_all(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        Ok(Self::bounded_collect(
            projection.list_work().into_iter(),
            limit,
            cursor,
        ))
    }

    fn is_claimable(&self, work_id: &str) -> Result<bool, WorkAuthorityError> {
        let status = self.get_work_status(work_id)?;
        Ok(status.claimable)
    }
}
