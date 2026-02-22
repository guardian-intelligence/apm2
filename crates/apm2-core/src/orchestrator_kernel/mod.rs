//! Orchestrator kernel runtime harness.
//!
//! The kernel provides a minimal extraction-first control loop:
//! Observe -> Plan -> Execute -> Receipt.
//! It is intentionally narrow and reusable across daemon orchestrators.

pub mod controller_loop;
pub mod effect_journal;
pub mod intent_store;
pub mod ledger_tailer;
pub mod types;

pub use controller_loop::{ControllerLoopError, OrchestratorDomain, ReceiptWriter, run_tick};
pub use effect_journal::{
    EffectExecutionState, EffectJournal, InDoubtResolution, OutputReleaseDenied,
    OutputReleasePolicy, check_output_release_permitted,
};
pub use intent_store::IntentStore;
pub use ledger_tailer::{
    CursorEvent, CursorStore, LedgerReader, advance_cursor_with_event, is_after_cursor,
    sort_and_truncate_events,
};
pub use types::{CompositeCursor, EventEnvelope, ExecutionOutcome, TickConfig, TickReport};
