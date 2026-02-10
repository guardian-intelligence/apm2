//! Markov-blanket channel enforcement for RFC-0020.
//!
//! Restricts authoritative actuation to typed tool-intent channel events
//! and emits structured defects for boundary violations.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Maximum string length for channel enforcement detail fields.
pub const MAX_CHANNEL_DETAIL_LENGTH: usize = 512;
const CHANNEL_SOURCE_WITNESS_DOMAIN: &[u8] = b"apm2.channel_source_witness.v1";

/// Channel source classification for actuation boundary enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelSource {
    /// Typed tool-intent channel event (structured, broker-mediated).
    TypedToolIntent,
    /// Free-form model output (unstructured text, non-authoritative).
    FreeFormOutput,
    /// Direct manifest invocation (bypass attempt).
    DirectManifest,
    /// Unknown/missing channel metadata.
    Unknown,
}

impl ChannelSource {
    const fn canonical_label(self) -> &'static str {
        match self {
            Self::TypedToolIntent => "typed_tool_intent",
            Self::FreeFormOutput => "free_form_output",
            Self::DirectManifest => "direct_manifest",
            Self::Unknown => "unknown",
        }
    }
}

/// Channel boundary enforcement result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct ChannelBoundaryCheck {
    /// The classified channel source.
    pub source: ChannelSource,
    /// Witness proving the channel source was attested by a trusted launcher.
    pub channel_source_witness: Option<[u8; 32]>,
    /// Whether the broker path was verified.
    pub broker_verified: bool,
    /// Whether capability enforcement was verified.
    pub capability_verified: bool,
    /// Whether context-firewall integrity was verified.
    pub context_firewall_verified: bool,
    /// Whether policy hash admission was verified against the ledger.
    pub policy_ledger_verified: bool,
}

/// Channel boundary violation defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelBoundaryDefect {
    /// The type of violation.
    pub violation_class: ChannelViolationClass,
    /// Human-readable detail (bounded to `MAX_CHANNEL_DETAIL_LENGTH`).
    pub detail: String,
}

impl ChannelBoundaryDefect {
    /// Construct a channel boundary defect with bounded detail length.
    #[must_use]
    pub fn new(violation_class: ChannelViolationClass, detail: impl Into<String>) -> Self {
        Self {
            violation_class,
            detail: truncate_channel_detail(detail.into()),
        }
    }
}

/// Classification of channel boundary violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelViolationClass {
    /// Free-form model output attempted to drive authoritative actuation.
    UntypedChannelSource,
    /// Direct manifest invocation bypassing broker.
    BrokerBypassDetected,
    /// Capability enforcement not verified before actuation.
    CapabilityNotVerified,
    /// Context-firewall integrity not verified before actuation.
    ContextFirewallNotVerified,
    /// Channel metadata missing or malformed.
    MissingChannelMetadata,
    /// Channel source unknown or unclassifiable.
    UnknownChannelSource,
    /// Policy hash was not verified against authoritative ledger admission.
    PolicyNotLedgerVerified,
}

/// Deterministically derives a witness token for the provided channel source.
///
/// The daemon uses this witness to bind channel-source classification into a
/// replay-stable token carried with boundary checks.
#[must_use]
pub fn derive_channel_source_witness(source: ChannelSource) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHANNEL_SOURCE_WITNESS_DOMAIN);
    hasher.update(source.canonical_label().as_bytes());
    *hasher.finalize().as_bytes()
}

/// Validates a channel source witness token.
#[must_use]
pub fn verify_channel_source_witness(source: ChannelSource, witness: &[u8; 32]) -> bool {
    let expected = derive_channel_source_witness(source);
    bool::from(expected.ct_eq(witness))
}

/// Validate that a channel boundary check satisfies actuation requirements.
///
/// Returns defects for any violations found. Empty vec = authorized.
/// Fail-closed: any missing/ambiguous check results in a defect.
#[must_use]
pub fn validate_channel_boundary(check: &ChannelBoundaryCheck) -> Vec<ChannelBoundaryDefect> {
    let mut defects = Vec::new();

    let source = resolve_effective_source(check, &mut defects);
    match source {
        ChannelSource::TypedToolIntent => {},
        ChannelSource::FreeFormOutput => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::UntypedChannelSource,
            "free-form model output cannot drive authoritative actuation",
        )),
        ChannelSource::DirectManifest => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::BrokerBypassDetected,
            "direct manifest invocation is a broker bypass",
        )),
        ChannelSource::Unknown => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::UnknownChannelSource,
            "channel source is unknown or unclassifiable",
        )),
    }

    if !check.broker_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::BrokerBypassDetected,
            "broker path was not verified",
        ));
    }

    if !check.capability_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::CapabilityNotVerified,
            "capability enforcement was not verified",
        ));
    }

    if !check.context_firewall_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::ContextFirewallNotVerified,
            "context-firewall integrity was not verified",
        ));
    }

    if !check.policy_ledger_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::PolicyNotLedgerVerified,
            "policy hash admission was not verified against ledger state",
        ));
    }

    defects
}

fn resolve_effective_source(
    check: &ChannelBoundaryCheck,
    defects: &mut Vec<ChannelBoundaryDefect>,
) -> ChannelSource {
    if check.source != ChannelSource::TypedToolIntent {
        return check.source;
    }

    if let Some(witness) = check.channel_source_witness {
        if verify_channel_source_witness(ChannelSource::TypedToolIntent, &witness) {
            ChannelSource::TypedToolIntent
        } else {
            defects.push(ChannelBoundaryDefect::new(
                ChannelViolationClass::MissingChannelMetadata,
                "channel source witness verification failed",
            ));
            ChannelSource::Unknown
        }
    } else {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::MissingChannelMetadata,
            "channel source witness is required for typed tool-intent classification",
        ));
        ChannelSource::Unknown
    }
}

fn truncate_channel_detail(mut detail: String) -> String {
    if detail.len() <= MAX_CHANNEL_DETAIL_LENGTH {
        return detail;
    }

    let mut boundary = MAX_CHANNEL_DETAIL_LENGTH;
    while !detail.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    detail.truncate(boundary);
    detail
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_check() -> ChannelBoundaryCheck {
        ChannelBoundaryCheck {
            source: ChannelSource::TypedToolIntent,
            channel_source_witness: Some(derive_channel_source_witness(
                ChannelSource::TypedToolIntent,
            )),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
        }
    }

    #[test]
    fn test_typed_tool_intent_all_verified_passes() {
        let check = baseline_check();
        let defects = validate_channel_boundary(&check);
        assert!(defects.is_empty());
    }

    #[test]
    fn test_freeform_output_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::FreeFormOutput;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::UntypedChannelSource
        );
    }

    #[test]
    fn test_direct_manifest_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::DirectManifest;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::BrokerBypassDetected
        );
    }

    #[test]
    fn test_unknown_source_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::Unknown;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::UnknownChannelSource
        );
    }

    #[test]
    fn test_broker_not_verified_denied() {
        let mut check = baseline_check();
        check.broker_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::BrokerBypassDetected
        );
    }

    #[test]
    fn test_capability_not_verified_denied() {
        let mut check = baseline_check();
        check.capability_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::CapabilityNotVerified
        );
    }

    #[test]
    fn test_context_firewall_not_verified_denied() {
        let mut check = baseline_check();
        check.context_firewall_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::ContextFirewallNotVerified
        );
    }

    #[test]
    fn test_policy_not_ledger_verified_denied() {
        let mut check = baseline_check();
        check.policy_ledger_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::PolicyNotLedgerVerified
        );
    }

    #[test]
    fn test_typed_tool_intent_without_witness_denied() {
        let mut check = baseline_check();
        check.channel_source_witness = None;
        let defects = validate_channel_boundary(&check);
        let classes: Vec<ChannelViolationClass> = defects
            .iter()
            .map(|defect| defect.violation_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ChannelViolationClass::MissingChannelMetadata,
                ChannelViolationClass::UnknownChannelSource,
            ]
        );
    }

    #[test]
    fn test_typed_tool_intent_with_invalid_witness_denied() {
        let mut check = baseline_check();
        check.channel_source_witness = Some([0xAA; 32]);
        let defects = validate_channel_boundary(&check);
        let classes: Vec<ChannelViolationClass> = defects
            .iter()
            .map(|defect| defect.violation_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ChannelViolationClass::MissingChannelMetadata,
                ChannelViolationClass::UnknownChannelSource,
            ]
        );
    }

    #[test]
    fn test_multiple_violations_emitted() {
        let check = ChannelBoundaryCheck {
            source: ChannelSource::FreeFormOutput,
            channel_source_witness: None,
            broker_verified: false,
            capability_verified: false,
            context_firewall_verified: false,
            policy_ledger_verified: false,
        };

        let defects = validate_channel_boundary(&check);
        let classes: Vec<ChannelViolationClass> = defects
            .iter()
            .map(|defect| defect.violation_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ChannelViolationClass::UntypedChannelSource,
                ChannelViolationClass::BrokerBypassDetected,
                ChannelViolationClass::CapabilityNotVerified,
                ChannelViolationClass::ContextFirewallNotVerified,
                ChannelViolationClass::PolicyNotLedgerVerified,
            ]
        );
    }

    #[test]
    fn test_channel_defect_serialization() {
        let detail = "a".repeat(MAX_CHANNEL_DETAIL_LENGTH + 32);
        let defect =
            ChannelBoundaryDefect::new(ChannelViolationClass::CapabilityNotVerified, detail);
        assert_eq!(defect.detail.len(), MAX_CHANNEL_DETAIL_LENGTH);

        let json = serde_json::to_string(&defect).expect("defect should serialize");
        let decoded: ChannelBoundaryDefect =
            serde_json::from_str(&json).expect("defect should deserialize");
        assert_eq!(decoded, defect);
    }
}
