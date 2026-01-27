//! Defect record types for policy violation tracking.
//!
//! This module provides the [`DefectRecord`] type for capturing and emitting
//! structured defect information when policy violations occur during episode
//! execution.
//!
//! # Design Principles
//!
//! - **Structured Reporting**: Defects include actionable context per CTR-0703
//! - **First-Miss Semantics**: Only the first pack miss emits a `DefectRecord`
//! - **Schema Alignment**: Follows `cac.defect_record.v1` schema
//! - **Strict Serde**: Uses `#[serde(deny_unknown_fields)]` (CTR-1604)
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::defect::{
//!     DefectRecord, DefectSeverity, DefectSignal, SignalType,
//! };
//!
//! let defect = DefectRecord::builder("DEF-001", "UNPLANNED_CONTEXT")
//!     .severity(DefectSeverity::S2)
//!     .work_id("work-123")
//!     .signal(DefectSignal::new(
//!         SignalType::UnplannedContextRead,
//!         "artifact org:doc:missing not in pack",
//!     ))
//!     .build();
//!
//! assert_eq!(defect.defect_id(), "DEF-001");
//! ```

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for defect IDs.
pub const MAX_DEFECT_ID_LENGTH: usize = 256;

/// Maximum length for defect class strings.
pub const MAX_DEFECT_CLASS_LENGTH: usize = 256;

/// Maximum length for work IDs.
pub const MAX_WORK_ID_LENGTH: usize = 256;

/// Maximum length for signal details.
pub const MAX_SIGNAL_DETAILS_LENGTH: usize = 4096;

/// Maximum length for actor IDs.
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum length for session IDs.
pub const MAX_SESSION_ID_LENGTH: usize = 256;

/// Maximum length for stable IDs.
pub const MAX_STABLE_ID_LENGTH: usize = 1024;

/// Maximum number of remediation suggestions.
pub const MAX_REMEDIATIONS: usize = 10;

/// Maximum length for remediation strings.
pub const MAX_REMEDIATION_LENGTH: usize = 1024;

// ============================================================================
// DefectSeverity
// ============================================================================

/// Severity level for defect records.
///
/// Follows the CAC schema severity enumeration:
/// - S0: Critical - immediate intervention required
/// - S1: High - significant impact, needs prompt attention
/// - S2: Medium - moderate impact, address in normal workflow
/// - S3: Low - minor impact, address when convenient
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DefectSeverity {
    /// Critical severity - immediate intervention required.
    S0,
    /// High severity - significant impact.
    S1,
    /// Medium severity - moderate impact (default for pack misses).
    #[default]
    S2,
    /// Low severity - minor impact.
    S3,
}

impl DefectSeverity {
    /// Returns the severity as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::S0 => "S0",
            Self::S1 => "S1",
            Self::S2 => "S2",
            Self::S3 => "S3",
        }
    }
}

// ============================================================================
// SignalType
// ============================================================================

/// Type of defect signal detected.
///
/// Per CAC schema, these are the signal types that can trigger defect records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SignalType {
    /// An unplanned tool call was attempted.
    #[serde(rename = "UNPLANNED_TOOL_CALL")]
    UnplannedToolCall,

    /// An unplanned context read was attempted (pack miss).
    #[serde(rename = "UNPLANNED_CONTEXT_READ")]
    UnplannedContextRead,

    /// Schema validation rejected an artifact.
    #[serde(rename = "SCHEMA_REJECT")]
    SchemaReject,

    /// Canonicalizer produced different output than expected.
    #[serde(rename = "CANONICALIZER_DRIFT")]
    CanonicalizerDrift,

    /// Export produced different output than expected.
    #[serde(rename = "EXPORT_DRIFT")]
    ExportDrift,

    /// Agent Acceptance Test failed.
    #[serde(rename = "AAT_FAIL")]
    AatFail,
}

impl SignalType {
    /// Returns the signal type as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnplannedToolCall => "UNPLANNED_TOOL_CALL",
            Self::UnplannedContextRead => "UNPLANNED_CONTEXT_READ",
            Self::SchemaReject => "SCHEMA_REJECT",
            Self::CanonicalizerDrift => "CANONICALIZER_DRIFT",
            Self::ExportDrift => "EXPORT_DRIFT",
            Self::AatFail => "AAT_FAIL",
        }
    }
}

// ============================================================================
// DefectSignal
// ============================================================================

/// Signal information for a defect record.
///
/// Captures the type of violation and human-readable details about what
/// occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefectSignal {
    /// The type of signal detected.
    #[serde(rename = "type")]
    signal_type: SignalType,

    /// Human-readable details about the signal.
    details: String,
}

impl DefectSignal {
    /// Creates a new defect signal.
    #[must_use]
    pub fn new(signal_type: SignalType, details: impl Into<String>) -> Self {
        Self {
            signal_type,
            details: details.into(),
        }
    }

    /// Returns the signal type.
    #[must_use]
    pub const fn signal_type(&self) -> SignalType {
        self.signal_type
    }

    /// Returns the signal details.
    #[must_use]
    pub fn details(&self) -> &str {
        &self.details
    }
}

// ============================================================================
// DefectContext
// ============================================================================

/// Hash type alias (BLAKE3-256, 32 bytes).
pub type Hash = [u8; 32];

/// Contextual information for a defect record.
///
/// Provides additional context about where and when the defect occurred.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefectContext {
    /// The actor (agent) that triggered the defect.
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_id: Option<String>,

    /// The session in which the defect occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,

    /// The pack manifest hash for reproducibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_manifest_hash: Option<Hash>,

    /// The stable ID of the requested artifact (for context read defects).
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_stable_id: Option<String>,
}

impl DefectContext {
    /// Creates a new empty defect context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            actor_id: None,
            session_id: None,
            pack_manifest_hash: None,
            requested_stable_id: None,
        }
    }

    /// Sets the actor ID.
    #[must_use]
    pub fn with_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.actor_id = Some(actor_id.into());
        self
    }

    /// Sets the session ID.
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the pack manifest hash.
    #[must_use]
    pub const fn with_pack_manifest_hash(mut self, hash: Hash) -> Self {
        self.pack_manifest_hash = Some(hash);
        self
    }

    /// Sets the requested stable ID.
    #[must_use]
    pub fn with_requested_stable_id(mut self, stable_id: impl Into<String>) -> Self {
        self.requested_stable_id = Some(stable_id.into());
        self
    }

    /// Returns the actor ID, if set.
    #[must_use]
    pub fn actor_id(&self) -> Option<&str> {
        self.actor_id.as_deref()
    }

    /// Returns the session ID, if set.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Returns the pack manifest hash, if set.
    #[must_use]
    pub const fn pack_manifest_hash(&self) -> Option<&Hash> {
        self.pack_manifest_hash.as_ref()
    }

    /// Returns the requested stable ID, if set.
    #[must_use]
    pub fn requested_stable_id(&self) -> Option<&str> {
        self.requested_stable_id.as_deref()
    }

    /// Returns true if all fields are None.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.actor_id.is_none()
            && self.session_id.is_none()
            && self.pack_manifest_hash.is_none()
            && self.requested_stable_id.is_none()
    }
}

// ============================================================================
// DefectRecord
// ============================================================================

/// A structured defect record for policy violations.
///
/// `DefectRecord` captures detailed information about policy violations
/// during episode execution, following the `cac.defect_record.v1` schema.
///
/// # Design
///
/// Per the ticket requirements:
/// - Emitted on first pack miss (not subsequent misses)
/// - Includes signal type `UNPLANNED_CONTEXT_READ` for pack misses
/// - Captures context including pack manifest hash and requested stable ID
///
/// # Example
///
/// ```rust
/// use apm2_holon::defect::{
///     DefectRecord, DefectSeverity, DefectSignal, SignalType,
/// };
///
/// let defect = DefectRecord::builder("DEF-001", "PACK_MISS")
///     .severity(DefectSeverity::S2)
///     .work_id("work-123")
///     .signal(DefectSignal::new(
///         SignalType::UnplannedContextRead,
///         "artifact org:doc:missing not found in pack",
///     ))
///     .build();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[must_use]
pub struct DefectRecord {
    /// Unique identifier for this defect.
    defect_id: String,

    /// Classification of the defect type.
    defect_class: String,

    /// Severity level.
    severity: DefectSeverity,

    /// The work ID this defect is associated with.
    work_id: String,

    /// Timestamp when the defect was detected (Unix nanoseconds).
    detected_at: u64,

    /// Signal information describing what triggered the defect.
    signal: DefectSignal,

    /// Additional context about the defect.
    #[serde(default, skip_serializing_if = "DefectContext::is_empty")]
    context: DefectContext,

    /// Evidence hashes linked to this defect.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evidence: Vec<Hash>,

    /// Suggested remediation actions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    suggested_remediations: Vec<String>,
}

impl DefectRecord {
    /// Creates a new builder for constructing a `DefectRecord`.
    #[must_use]
    pub fn builder(
        defect_id: impl Into<String>,
        defect_class: impl Into<String>,
    ) -> DefectRecordBuilder {
        DefectRecordBuilder::new(defect_id, defect_class)
    }

    /// Creates a defect record for a context pack miss.
    ///
    /// This is a convenience constructor for the common case of emitting
    /// a defect when an artifact is requested but not found in the pack.
    ///
    /// # Arguments
    ///
    /// * `defect_id` - Unique identifier for this defect
    /// * `work_id` - The work ID this defect is associated with
    /// * `stable_id` - The stable ID of the missing artifact
    /// * `pack_hash` - The hash of the context pack
    /// * `timestamp_ns` - When the miss was detected (Unix nanoseconds)
    pub fn pack_miss(
        defect_id: impl Into<String>,
        work_id: impl Into<String>,
        stable_id: impl Into<String>,
        pack_hash: Hash,
        timestamp_ns: u64,
    ) -> Self {
        let stable_id_str = stable_id.into();
        Self::builder(defect_id, "UNPLANNED_CONTEXT_READ")
            .severity(DefectSeverity::S2)
            .work_id(work_id)
            .detected_at(timestamp_ns)
            .signal(DefectSignal::new(
                SignalType::UnplannedContextRead,
                format!("artifact '{stable_id_str}' not found in context pack"),
            ))
            .context(
                DefectContext::new()
                    .with_pack_manifest_hash(pack_hash)
                    .with_requested_stable_id(stable_id_str),
            )
            .add_remediation("Add missing artifact to context pack manifest")
            .add_remediation("Verify artifact stable ID is correct")
            .build()
    }

    /// Returns the defect ID.
    #[must_use]
    pub fn defect_id(&self) -> &str {
        &self.defect_id
    }

    /// Returns the defect class.
    #[must_use]
    pub fn defect_class(&self) -> &str {
        &self.defect_class
    }

    /// Returns the severity.
    #[must_use]
    pub const fn severity(&self) -> DefectSeverity {
        self.severity
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the detection timestamp.
    #[must_use]
    pub const fn detected_at(&self) -> u64 {
        self.detected_at
    }

    /// Returns the signal information.
    #[must_use]
    pub const fn signal(&self) -> &DefectSignal {
        &self.signal
    }

    /// Returns the context information.
    #[must_use]
    pub const fn context(&self) -> &DefectContext {
        &self.context
    }

    /// Returns the evidence hashes.
    #[must_use]
    pub fn evidence(&self) -> &[Hash] {
        &self.evidence
    }

    /// Returns the suggested remediations.
    #[must_use]
    pub fn suggested_remediations(&self) -> &[String] {
        &self.suggested_remediations
    }
}

// ============================================================================
// DefectRecordBuilder
// ============================================================================

/// Builder for constructing [`DefectRecord`] instances.
#[derive(Debug, Clone)]
pub struct DefectRecordBuilder {
    defect_id: String,
    defect_class: String,
    severity: DefectSeverity,
    work_id: Option<String>,
    detected_at: Option<u64>,
    signal: Option<DefectSignal>,
    context: DefectContext,
    evidence: Vec<Hash>,
    suggested_remediations: Vec<String>,
}

impl DefectRecordBuilder {
    /// Creates a new builder with the required fields.
    #[must_use]
    pub fn new(defect_id: impl Into<String>, defect_class: impl Into<String>) -> Self {
        Self {
            defect_id: defect_id.into(),
            defect_class: defect_class.into(),
            severity: DefectSeverity::default(),
            work_id: None,
            detected_at: None,
            signal: None,
            context: DefectContext::new(),
            evidence: Vec::new(),
            suggested_remediations: Vec::new(),
        }
    }

    /// Sets the severity.
    #[must_use]
    pub const fn severity(mut self, severity: DefectSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets the work ID.
    #[must_use]
    pub fn work_id(mut self, work_id: impl Into<String>) -> Self {
        self.work_id = Some(work_id.into());
        self
    }

    /// Sets the detection timestamp.
    #[must_use]
    pub const fn detected_at(mut self, timestamp_ns: u64) -> Self {
        self.detected_at = Some(timestamp_ns);
        self
    }

    /// Sets the signal.
    #[must_use]
    pub fn signal(mut self, signal: DefectSignal) -> Self {
        self.signal = Some(signal);
        self
    }

    /// Sets the context.
    #[must_use]
    pub fn context(mut self, context: DefectContext) -> Self {
        self.context = context;
        self
    }

    /// Adds an evidence hash.
    #[must_use]
    pub fn add_evidence(mut self, hash: Hash) -> Self {
        self.evidence.push(hash);
        self
    }

    /// Adds a remediation suggestion.
    #[must_use]
    pub fn add_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.suggested_remediations.push(remediation.into());
        self
    }

    /// Builds the `DefectRecord`.
    ///
    /// # Panics
    ///
    /// Panics if `work_id` or `signal` is not set.
    pub fn build(self) -> DefectRecord {
        DefectRecord {
            defect_id: self.defect_id,
            defect_class: self.defect_class,
            severity: self.severity,
            work_id: self.work_id.expect("work_id is required"),
            detected_at: self.detected_at.unwrap_or_else(current_timestamp_ns),
            signal: self.signal.expect("signal is required"),
            context: self.context,
            evidence: self.evidence,
            suggested_remediations: self.suggested_remediations,
        }
    }
}

/// Returns the current timestamp in nanoseconds since epoch.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defect_severity_default() {
        assert_eq!(DefectSeverity::default(), DefectSeverity::S2);
    }

    #[test]
    fn test_defect_severity_as_str() {
        assert_eq!(DefectSeverity::S0.as_str(), "S0");
        assert_eq!(DefectSeverity::S1.as_str(), "S1");
        assert_eq!(DefectSeverity::S2.as_str(), "S2");
        assert_eq!(DefectSeverity::S3.as_str(), "S3");
    }

    #[test]
    fn test_signal_type_as_str() {
        assert_eq!(
            SignalType::UnplannedContextRead.as_str(),
            "UNPLANNED_CONTEXT_READ"
        );
        assert_eq!(
            SignalType::UnplannedToolCall.as_str(),
            "UNPLANNED_TOOL_CALL"
        );
    }

    #[test]
    fn test_defect_signal_creation() {
        let signal = DefectSignal::new(SignalType::UnplannedContextRead, "test details");
        assert_eq!(signal.signal_type(), SignalType::UnplannedContextRead);
        assert_eq!(signal.details(), "test details");
    }

    #[test]
    fn test_defect_context_builder() {
        let ctx = DefectContext::new()
            .with_actor_id("agent-1")
            .with_session_id("session-1")
            .with_pack_manifest_hash([1u8; 32])
            .with_requested_stable_id("org:doc:readme");

        assert_eq!(ctx.actor_id(), Some("agent-1"));
        assert_eq!(ctx.session_id(), Some("session-1"));
        assert_eq!(ctx.pack_manifest_hash(), Some(&[1u8; 32]));
        assert_eq!(ctx.requested_stable_id(), Some("org:doc:readme"));
        assert!(!ctx.is_empty());
    }

    #[test]
    fn test_defect_context_empty() {
        let ctx = DefectContext::new();
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_defect_record_builder() {
        let defect = DefectRecord::builder("DEF-001", "PACK_MISS")
            .severity(DefectSeverity::S2)
            .work_id("work-123")
            .detected_at(1_000_000_000)
            .signal(DefectSignal::new(
                SignalType::UnplannedContextRead,
                "artifact not found",
            ))
            .context(DefectContext::new().with_actor_id("agent-1"))
            .add_evidence([2u8; 32])
            .add_remediation("Add to pack")
            .build();

        assert_eq!(defect.defect_id(), "DEF-001");
        assert_eq!(defect.defect_class(), "PACK_MISS");
        assert_eq!(defect.severity(), DefectSeverity::S2);
        assert_eq!(defect.work_id(), "work-123");
        assert_eq!(defect.detected_at(), 1_000_000_000);
        assert_eq!(
            defect.signal().signal_type(),
            SignalType::UnplannedContextRead
        );
        assert_eq!(defect.context().actor_id(), Some("agent-1"));
        assert_eq!(defect.evidence().len(), 1);
        assert_eq!(defect.suggested_remediations().len(), 1);
    }

    #[test]
    fn test_defect_record_pack_miss() {
        let defect = DefectRecord::pack_miss(
            "DEF-001",
            "work-123",
            "org:doc:missing",
            [0u8; 32],
            1_000_000,
        );

        assert_eq!(defect.defect_id(), "DEF-001");
        assert_eq!(defect.defect_class(), "UNPLANNED_CONTEXT_READ");
        assert_eq!(defect.severity(), DefectSeverity::S2);
        assert_eq!(defect.work_id(), "work-123");
        assert_eq!(
            defect.signal().signal_type(),
            SignalType::UnplannedContextRead
        );
        assert!(defect.signal().details().contains("org:doc:missing"));
        assert_eq!(defect.context().pack_manifest_hash(), Some(&[0u8; 32]));
        assert_eq!(
            defect.context().requested_stable_id(),
            Some("org:doc:missing")
        );
        assert!(!defect.suggested_remediations().is_empty());
    }

    #[test]
    fn test_defect_record_serialization() {
        let defect = DefectRecord::builder("DEF-001", "TEST")
            .severity(DefectSeverity::S1)
            .work_id("work-123")
            .signal(DefectSignal::new(SignalType::AatFail, "test failed"))
            .build();

        let json = serde_json::to_string(&defect).unwrap();
        assert!(json.contains("\"defect_id\":\"DEF-001\""));
        assert!(json.contains("\"severity\":\"S1\""));

        let deserialized: DefectRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.defect_id(), defect.defect_id());
    }

    #[test]
    fn test_defect_record_rejects_unknown_fields() {
        let json = r#"{
            "defect_id": "DEF-001",
            "defect_class": "TEST",
            "severity": "S2",
            "work_id": "work-123",
            "detected_at": 1000000,
            "signal": {"type": "AAT_FAIL", "details": "test"},
            "unknown_field": "should fail"
        }"#;

        let result: Result<DefectRecord, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_defect_severity_serialization() {
        let json = serde_json::to_string(&DefectSeverity::S0).unwrap();
        assert_eq!(json, "\"S0\"");

        let deserialized: DefectSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, DefectSeverity::S0);
    }

    #[test]
    fn test_signal_type_serialization() {
        let json = serde_json::to_string(&SignalType::UnplannedContextRead).unwrap();
        assert_eq!(json, "\"UNPLANNED_CONTEXT_READ\"");

        let deserialized: SignalType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, SignalType::UnplannedContextRead);
    }
}
