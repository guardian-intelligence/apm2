// AGENT-AUTHORED
//! Dual lattice taint/classification propagation and declassification receipts
//! (TCK-00378).
//!
//! This module enforces RFC-0020 Section 5 dual-lattice security:
//!
//! - **Taint lattice**: Tracks data provenance integrity. Taint propagates
//!   upward via `join` (least upper bound). Higher taint = less trusted input.
//! - **Confidentiality lattice**: Tracks information classification level.
//!   Confidentiality propagates downward via `meet` (greatest lower bound) at
//!   boundary crossings to enforce need-to-know.
//! - **Declassification receipts**: Explicit, policy-gated downgrades of
//!   confidentiality level that produce auditable receipts.
//! - **Boundary crossing hooks**: Dual-lattice policy enforcement at trust
//!   boundary transitions and actuator entry points.
//!
//! # Security Model
//!
//! - **Fail-closed**: Any lattice violation rejects the request.
//! - **No implicit declassification**: Confidentiality can only be lowered via
//!   an explicit [`DeclassificationReceipt`] referencing a policy rule.
//! - **Taint monotonicity**: Taint levels can only increase through joins;
//!   there is no "untainting" operation.
//! - **Tier-gated actuators**: Tier3+ actuators reject inputs above a
//!   configured taint threshold or confidentiality floor.
//!
//! # Contract References
//!
//! - `REQ-0032`: Dual lattice taint/classification propagation
//! - `EVID-0032`: Taint propagation correctness evidence
//! - `EVID-0308`: Declassification receipt evidence

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for a policy reference string in a declassification receipt.
const MAX_POLICY_REF_LEN: usize = 512;

/// Maximum length for the justification field in a declassification receipt.
const MAX_JUSTIFICATION_LEN: usize = 1024;

/// Maximum length for a boundary identifier.
const MAX_BOUNDARY_ID_LEN: usize = 256;

// =============================================================================
// Errors
// =============================================================================

/// Errors from dual-lattice policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaintError {
    /// Taint level exceeds the maximum allowed for this actuator tier.
    #[error("taint level {actual} exceeds maximum {max_allowed} for tier {tier}")]
    TaintCeilingExceeded {
        /// The actual taint level of the input.
        actual: TaintLevel,
        /// The maximum taint level allowed.
        max_allowed: TaintLevel,
        /// The actuator tier that rejected the input.
        tier: u8,
    },

    /// Confidentiality level exceeds the maximum allowed for this boundary.
    #[error(
        "confidentiality level {actual} exceeds maximum {max_allowed} for boundary '{boundary}'"
    )]
    ConfidentialityFloorViolation {
        /// The actual confidentiality level of the data.
        actual: ConfidentialityLevel,
        /// The maximum confidentiality level allowed at this boundary.
        max_allowed: ConfidentialityLevel,
        /// The boundary that rejected the data.
        boundary: String,
    },

    /// Attempted declassification without explicit policy authorization.
    #[error("declassification from {from} to {to} denied: {reason}")]
    DeclassificationDenied {
        /// The current confidentiality level.
        from: ConfidentialityLevel,
        /// The requested target level.
        to: ConfidentialityLevel,
        /// Why the declassification was denied.
        reason: String,
    },

    /// Invalid policy reference in declassification request.
    #[error("invalid policy reference: {reason}")]
    InvalidPolicyRef {
        /// Why the reference is invalid.
        reason: String,
    },

    /// Boundary crossing denied by dual-lattice policy.
    #[error("boundary crossing denied at '{boundary}': {reason}")]
    BoundaryCrossingDenied {
        /// The boundary identifier.
        boundary: String,
        /// Why the crossing was denied.
        reason: String,
    },
}

// =============================================================================
// TaintLevel
// =============================================================================

/// Taint level in the integrity lattice.
///
/// Taint tracks data provenance integrity. Higher values indicate less
/// trustworthy data. Taint propagates upward: when combining data from
/// multiple sources, the result takes the highest (least trusted) taint
/// level via [`TaintLevel::join`] (least upper bound).
///
/// Lattice ordering: `Untainted < LowTaint < MediumTaint < HighTaint < Toxic`
///
/// # Invariants
///
/// - Taint is monotonically non-decreasing through data flow.
/// - There is no "untaint" operation; only the lattice join is provided.
/// - Tier3+ actuators reject inputs with taint above their configured ceiling.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum TaintLevel {
    /// Data from fully trusted, validated sources.
    #[default]
    Untainted   = 0,
    /// Data from partially trusted sources (e.g., authenticated but external).
    LowTaint    = 1,
    /// Data that has passed through semi-trusted processing.
    MediumTaint = 2,
    /// Data from untrusted or unvalidated sources.
    HighTaint   = 3,
    /// Data that is known-compromised or must never reach actuators.
    Toxic       = 4,
}

impl TaintLevel {
    /// Lattice join (least upper bound): returns the higher taint level.
    ///
    /// When combining data from two sources, the result inherits the
    /// taint of the less-trusted source.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Returns `true` if this taint level is at or below the given ceiling.
    #[must_use]
    pub const fn within_ceiling(self, ceiling: Self) -> bool {
        (self as u8) <= (ceiling as u8)
    }

    /// Returns the numeric ordinal for serialization.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// Construct from ordinal, returning `None` for out-of-range values.
    #[must_use]
    pub const fn from_ordinal(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Untainted),
            1 => Some(Self::LowTaint),
            2 => Some(Self::MediumTaint),
            3 => Some(Self::HighTaint),
            4 => Some(Self::Toxic),
            _ => None,
        }
    }
}

impl fmt::Display for TaintLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untainted => write!(f, "Untainted"),
            Self::LowTaint => write!(f, "LowTaint"),
            Self::MediumTaint => write!(f, "MediumTaint"),
            Self::HighTaint => write!(f, "HighTaint"),
            Self::Toxic => write!(f, "Toxic"),
        }
    }
}

// =============================================================================
// ConfidentialityLevel
// =============================================================================

/// Confidentiality level in the classification lattice.
///
/// Confidentiality tracks information sensitivity. Higher values indicate
/// more sensitive data. At boundary crossings, confidentiality propagates
/// via [`ConfidentialityLevel::meet`] (greatest lower bound) to enforce
/// the principle that outbound data cannot exceed the boundary's clearance.
///
/// Lattice ordering: `Public < Internal < Confidential < Secret < TopSecret`
///
/// # Invariants
///
/// - Data cannot cross a boundary whose clearance is below the data's
///   confidentiality level unless a [`DeclassificationReceipt`] is presented.
/// - Combining data from multiple sources takes the *highest* confidentiality
///   via [`ConfidentialityLevel::join`] (a Secret + Public merge is Secret).
/// - Declassification requires explicit policy and produces an auditable
///   receipt.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum ConfidentialityLevel {
    /// Publicly releasable data.
    #[default]
    Public       = 0,
    /// Internal-use-only data (not for external release).
    Internal     = 1,
    /// Confidential data requiring access controls.
    Confidential = 2,
    /// Secret data with strict need-to-know.
    Secret       = 3,
    /// Top-secret data with compartmented access.
    TopSecret    = 4,
}

impl ConfidentialityLevel {
    /// Lattice meet (greatest lower bound): returns the lower confidentiality
    /// level.
    ///
    /// Used at boundary crossings to enforce that outbound data does not
    /// exceed the boundary's clearance.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        if (self as u8) <= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Lattice join (least upper bound): returns the higher confidentiality
    /// level.
    ///
    /// When combining data from multiple sources, the result inherits
    /// the highest classification.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Returns `true` if this level is at or below the given clearance.
    #[must_use]
    pub const fn within_clearance(self, clearance: Self) -> bool {
        (self as u8) <= (clearance as u8)
    }

    /// Returns the numeric ordinal for serialization.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// Construct from ordinal, returning `None` for out-of-range values.
    #[must_use]
    pub const fn from_ordinal(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Public),
            1 => Some(Self::Internal),
            2 => Some(Self::Confidential),
            3 => Some(Self::Secret),
            4 => Some(Self::TopSecret),
            _ => None,
        }
    }
}

impl fmt::Display for ConfidentialityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Internal => write!(f, "Internal"),
            Self::Confidential => write!(f, "Confidential"),
            Self::Secret => write!(f, "Secret"),
            Self::TopSecret => write!(f, "TopSecret"),
        }
    }
}

// =============================================================================
// DataLabel
// =============================================================================

/// Combined taint + confidentiality label for a data item.
///
/// Every data item flowing through the system carries a dual label:
/// taint (integrity) and confidentiality (classification). Policy
/// decisions consider both dimensions simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataLabel {
    /// Integrity dimension: how trusted is this data?
    pub taint: TaintLevel,
    /// Classification dimension: how sensitive is this data?
    pub confidentiality: ConfidentialityLevel,
}

impl DataLabel {
    /// Create a new data label.
    #[must_use]
    pub const fn new(taint: TaintLevel, confidentiality: ConfidentialityLevel) -> Self {
        Self {
            taint,
            confidentiality,
        }
    }

    /// A fully trusted, public data label.
    pub const TRUSTED_PUBLIC: Self = Self {
        taint: TaintLevel::Untainted,
        confidentiality: ConfidentialityLevel::Public,
    };

    /// Join two labels: taint joins (goes up), confidentiality joins (goes up).
    ///
    /// Used when merging/combining data from multiple sources.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        Self {
            taint: self.taint.join(other.taint),
            confidentiality: self.confidentiality.join(other.confidentiality),
        }
    }
}

impl Default for DataLabel {
    fn default() -> Self {
        Self::TRUSTED_PUBLIC
    }
}

impl fmt::Display for DataLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[taint={}, conf={}]", self.taint, self.confidentiality)
    }
}

// =============================================================================
// Free propagation functions
// =============================================================================

/// Propagate taint across multiple inputs via lattice join (least upper bound).
///
/// Returns the highest taint level among all inputs, or
/// [`TaintLevel::Untainted`] for an empty slice (the join identity).
///
/// # Examples
///
/// ```
/// use apm2_core::policy::taint::{TaintLevel, propagate_taint};
///
/// let inputs = [
///     TaintLevel::LowTaint,
///     TaintLevel::HighTaint,
///     TaintLevel::Untainted,
/// ];
/// assert_eq!(propagate_taint(&inputs), TaintLevel::HighTaint);
/// assert_eq!(propagate_taint(&[]), TaintLevel::Untainted);
/// ```
#[must_use]
pub fn propagate_taint(inputs: &[TaintLevel]) -> TaintLevel {
    inputs
        .iter()
        .copied()
        .fold(TaintLevel::Untainted, TaintLevel::join)
}

/// Propagate confidentiality across multiple inputs via lattice join (least
/// upper bound).
///
/// Returns the highest confidentiality level among all inputs, or
/// [`ConfidentialityLevel::Public`] for an empty slice (the join identity).
///
/// # Examples
///
/// ```
/// use apm2_core::policy::taint::{ConfidentialityLevel, propagate_classification};
///
/// let inputs = [ConfidentialityLevel::Internal, ConfidentialityLevel::Secret];
/// assert_eq!(
///     propagate_classification(&inputs),
///     ConfidentialityLevel::Secret
/// );
/// assert_eq!(propagate_classification(&[]), ConfidentialityLevel::Public);
/// ```
#[must_use]
pub fn propagate_classification(inputs: &[ConfidentialityLevel]) -> ConfidentialityLevel {
    inputs
        .iter()
        .copied()
        .fold(ConfidentialityLevel::Public, ConfidentialityLevel::join)
}

// =============================================================================
// BoundaryPolicy
// =============================================================================

/// Policy for a trust boundary crossing point.
///
/// Each boundary defines maximum taint and confidentiality levels. Data
/// crossing the boundary must satisfy both constraints or be rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryPolicy {
    /// Human-readable identifier for this boundary.
    boundary_id: String,
    /// Maximum taint level allowed through this boundary.
    max_taint: TaintLevel,
    /// Maximum confidentiality level allowed through this boundary.
    max_confidentiality: ConfidentialityLevel,
    /// The actuator tier this boundary guards (0 = no tier restriction).
    tier: u8,
}

impl BoundaryPolicy {
    /// Create a new boundary policy.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::InvalidPolicyRef`] if the boundary ID is empty
    /// or too long.
    pub fn new(
        boundary_id: &str,
        max_taint: TaintLevel,
        max_confidentiality: ConfidentialityLevel,
        tier: u8,
    ) -> Result<Self, TaintError> {
        if boundary_id.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "boundary ID must be non-empty".to_string(),
            });
        }
        if boundary_id.len() > MAX_BOUNDARY_ID_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("boundary ID exceeds maximum length of {MAX_BOUNDARY_ID_LEN}"),
            });
        }

        Ok(Self {
            boundary_id: boundary_id.to_string(),
            max_taint,
            max_confidentiality,
            tier,
        })
    }

    /// Returns the boundary identifier.
    #[must_use]
    pub fn boundary_id(&self) -> &str {
        &self.boundary_id
    }

    /// Returns the maximum taint level allowed.
    #[must_use]
    pub const fn max_taint(&self) -> TaintLevel {
        self.max_taint
    }

    /// Returns the maximum confidentiality level allowed.
    #[must_use]
    pub const fn max_confidentiality(&self) -> ConfidentialityLevel {
        self.max_confidentiality
    }

    /// Returns the actuator tier.
    #[must_use]
    pub const fn tier(&self) -> u8 {
        self.tier
    }

    /// Check whether a data label is allowed to cross this boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::TaintCeilingExceeded`] if the taint level is
    /// too high, or [`TaintError::ConfidentialityFloorViolation`] if the
    /// confidentiality level is too high for the boundary's clearance.
    pub fn check(&self, label: &DataLabel) -> Result<(), TaintError> {
        if !label.taint.within_ceiling(self.max_taint) {
            return Err(TaintError::TaintCeilingExceeded {
                actual: label.taint,
                max_allowed: self.max_taint,
                tier: self.tier,
            });
        }

        if !label
            .confidentiality
            .within_clearance(self.max_confidentiality)
        {
            return Err(TaintError::ConfidentialityFloorViolation {
                actual: label.confidentiality,
                max_allowed: self.max_confidentiality,
                boundary: self.boundary_id.clone(),
            });
        }

        Ok(())
    }
}

// =============================================================================
// DeclassificationReceipt
// =============================================================================

/// An auditable receipt for an explicit confidentiality downgrade.
///
/// Declassification is the only way to lower a data item's confidentiality
/// level. It requires:
/// 1. An explicit policy rule authorizing the downgrade.
/// 2. A justification string for audit.
/// 3. The receipt is content-addressed (BLAKE3 hash) for tamper evidence.
///
/// # Security Properties
///
/// - Receipts are immutable once created.
/// - The policy reference must name a real, active declassification rule.
/// - The content hash covers all fields to prevent tampering.
/// - Receipts are logged to the ledger for post-hoc audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationReceipt {
    /// The confidentiality level before declassification.
    from_level: ConfidentialityLevel,
    /// The confidentiality level after declassification.
    to_level: ConfidentialityLevel,
    /// Reference to the policy rule that authorized this declassification.
    policy_ref: String,
    /// Human-readable justification for audit trail.
    justification: String,
    /// BLAKE3 hash of the receipt content for tamper evidence.
    content_hash: [u8; 32],
}

impl DeclassificationReceipt {
    /// Returns the level before declassification.
    #[must_use]
    pub const fn from_level(&self) -> ConfidentialityLevel {
        self.from_level
    }

    /// Returns the level after declassification.
    #[must_use]
    pub const fn to_level(&self) -> ConfidentialityLevel {
        self.to_level
    }

    /// Returns the policy rule reference that authorized this.
    #[must_use]
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// Returns the justification string.
    #[must_use]
    pub fn justification(&self) -> &str {
        &self.justification
    }

    /// Returns the BLAKE3 content hash of this receipt.
    #[must_use]
    pub const fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    /// Returns the content hash as a hex-encoded string.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        self.content_hash.iter().fold(String::new(), |mut acc, b| {
            use fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}

// =============================================================================
// DeclassificationPolicy
// =============================================================================

/// Policy rule authorizing a specific confidentiality downgrade.
///
/// Each rule specifies the allowed downgrade range and is identified
/// by a unique rule ID that must be referenced in the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationPolicy {
    /// Unique rule identifier (referenced by receipts).
    rule_id: String,
    /// Maximum source level this rule can declassify from.
    max_from: ConfidentialityLevel,
    /// Minimum target level this rule allows declassification to.
    min_to: ConfidentialityLevel,
}

impl DeclassificationPolicy {
    /// Create a new declassification policy rule.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::InvalidPolicyRef`] if the rule ID is invalid
    /// or the level range is non-decreasing (from must be strictly greater
    /// than to).
    pub fn new(
        rule_id: &str,
        max_from: ConfidentialityLevel,
        min_to: ConfidentialityLevel,
    ) -> Result<Self, TaintError> {
        if rule_id.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "declassification rule ID must be non-empty".to_string(),
            });
        }
        if rule_id.len() > MAX_POLICY_REF_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!(
                    "declassification rule ID exceeds maximum length of {MAX_POLICY_REF_LEN}"
                ),
            });
        }
        if max_from.ordinal() <= min_to.ordinal() {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!(
                    "declassification range invalid: max_from ({max_from}) must be \
                     strictly greater than min_to ({min_to})"
                ),
            });
        }

        Ok(Self {
            rule_id: rule_id.to_string(),
            max_from,
            min_to,
        })
    }

    /// Returns the rule identifier.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns the maximum source level.
    #[must_use]
    pub const fn max_from(&self) -> ConfidentialityLevel {
        self.max_from
    }

    /// Returns the minimum target level.
    #[must_use]
    pub const fn min_to(&self) -> ConfidentialityLevel {
        self.min_to
    }

    /// Check whether a specific declassification is allowed by this rule.
    const fn allows(&self, from: ConfidentialityLevel, to: ConfidentialityLevel) -> bool {
        from.within_clearance(self.max_from)
            && to.ordinal() >= self.min_to.ordinal()
            && from.ordinal() > to.ordinal()
    }
}

// =============================================================================
// DualLatticePolicy
// =============================================================================

/// The dual-lattice policy engine combining taint and confidentiality.
///
/// Holds boundary policies and declassification rules. All data crossing
/// boundaries or entering actuators is checked against this policy.
///
/// # Fail-Closed Behavior
///
/// - If no boundary policy is configured for a crossing point, the crossing is
///   denied (fail-closed).
/// - If no declassification rule matches a downgrade request, the downgrade is
///   denied.
#[derive(Debug, Clone)]
pub struct DualLatticePolicy {
    /// Boundary policies keyed by boundary ID.
    boundaries: Vec<BoundaryPolicy>,
    /// Declassification rules.
    declassification_rules: Vec<DeclassificationPolicy>,
}

impl DualLatticePolicy {
    /// Create a new dual-lattice policy with the given boundaries and
    /// declassification rules.
    #[must_use]
    pub const fn new(
        boundaries: Vec<BoundaryPolicy>,
        declassification_rules: Vec<DeclassificationPolicy>,
    ) -> Self {
        Self {
            boundaries,
            declassification_rules,
        }
    }

    /// Create an empty (deny-all) policy. No boundaries are configured,
    /// so all crossings are denied.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            boundaries: Vec::new(),
            declassification_rules: Vec::new(),
        }
    }

    /// Check a data label against a named boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::BoundaryCrossingDenied`] if no boundary with
    /// the given ID is configured (fail-closed), or the specific taint/
    /// confidentiality violation error if the label fails the check.
    pub fn check_boundary(&self, boundary_id: &str, label: &DataLabel) -> Result<(), TaintError> {
        let boundary = self
            .boundaries
            .iter()
            .find(|b| b.boundary_id() == boundary_id)
            .ok_or_else(|| TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: "no boundary policy configured (fail-closed)".to_string(),
            })?;

        boundary.check(label)
    }

    /// Check a data label against an actuator tier.
    ///
    /// Tier3+ actuators require taint at or below the boundary's
    /// configured ceiling and confidentiality at or below its clearance.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`TaintError`] variant if the label
    /// violates the tier's policy.
    pub fn check_actuator_tier(&self, tier: u8, label: &DataLabel) -> Result<(), TaintError> {
        // Find all boundary policies for this tier; data must satisfy all.
        let tier_boundaries: Vec<&BoundaryPolicy> = self
            .boundaries
            .iter()
            .filter(|b| b.tier() == tier)
            .collect();

        if tier >= 3 && tier_boundaries.is_empty() {
            return Err(TaintError::BoundaryCrossingDenied {
                boundary: format!("tier-{tier}"),
                reason: "no boundary policy configured for tier (fail-closed)".to_string(),
            });
        }

        for boundary in tier_boundaries {
            boundary.check(label)?;
        }

        Ok(())
    }

    /// Request a declassification, producing a receipt if authorized.
    ///
    /// The caller must specify which policy rule authorizes the downgrade.
    /// If the rule exists and covers the requested range, a
    /// [`DeclassificationReceipt`] is produced. Otherwise the request is
    /// denied.
    ///
    /// # Errors
    ///
    /// Returns [`TaintError::DeclassificationDenied`] if no matching rule
    /// is found or the requested range is not covered.
    /// Returns [`TaintError::InvalidPolicyRef`] if the justification is
    /// too long.
    pub fn declassify(
        &self,
        from: ConfidentialityLevel,
        to: ConfidentialityLevel,
        policy_ref: &str,
        justification: &str,
    ) -> Result<DeclassificationReceipt, TaintError> {
        // Validate inputs.
        if from.ordinal() <= to.ordinal() {
            return Err(TaintError::DeclassificationDenied {
                from,
                to,
                reason: "declassification requires from > to".to_string(),
            });
        }

        if justification.len() > MAX_JUSTIFICATION_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("justification exceeds maximum length of {MAX_JUSTIFICATION_LEN}"),
            });
        }

        if policy_ref.is_empty() {
            return Err(TaintError::InvalidPolicyRef {
                reason: "policy reference must be non-empty".to_string(),
            });
        }

        if policy_ref.len() > MAX_POLICY_REF_LEN {
            return Err(TaintError::InvalidPolicyRef {
                reason: format!("policy reference exceeds maximum length of {MAX_POLICY_REF_LEN}"),
            });
        }

        // Find a matching declassification rule.
        let rule = self
            .declassification_rules
            .iter()
            .find(|r| r.rule_id() == policy_ref && r.allows(from, to))
            .ok_or_else(|| TaintError::DeclassificationDenied {
                from,
                to,
                reason: format!(
                    "no declassification rule '{policy_ref}' authorizes {from} -> {to}"
                ),
            })?;

        // Compute content hash over all receipt fields.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[from.ordinal()]);
        hasher.update(&[to.ordinal()]);
        hasher.update(rule.rule_id().as_bytes());
        hasher.update(justification.as_bytes());
        let content_hash: [u8; 32] = hasher.finalize().into();

        Ok(DeclassificationReceipt {
            from_level: from,
            to_level: to,
            policy_ref: policy_ref.to_string(),
            justification: justification.to_string(),
            content_hash,
        })
    }

    /// Propagate a label through a boundary crossing, applying the meet
    /// on confidentiality.
    ///
    /// Returns the label with confidentiality clamped to the boundary's
    /// clearance. The taint dimension is unchanged (it only grows via join).
    ///
    /// # Errors
    ///
    /// Returns the appropriate error if the label's taint exceeds the
    /// boundary ceiling (taint violations are never auto-clamped).
    pub fn propagate_through_boundary(
        &self,
        boundary_id: &str,
        label: &DataLabel,
    ) -> Result<DataLabel, TaintError> {
        let boundary = self
            .boundaries
            .iter()
            .find(|b| b.boundary_id() == boundary_id)
            .ok_or_else(|| TaintError::BoundaryCrossingDenied {
                boundary: boundary_id.to_string(),
                reason: "no boundary policy configured (fail-closed)".to_string(),
            })?;

        // Taint is checked strictly: never auto-lowered.
        if !label.taint.within_ceiling(boundary.max_taint()) {
            return Err(TaintError::TaintCeilingExceeded {
                actual: label.taint,
                max_allowed: boundary.max_taint(),
                tier: boundary.tier(),
            });
        }

        // Confidentiality propagates via meet (clamp down).
        let clamped_conf = label.confidentiality.meet(boundary.max_confidentiality());

        Ok(DataLabel::new(label.taint, clamped_conf))
    }

    /// Returns the configured boundaries.
    #[must_use]
    pub fn boundaries(&self) -> &[BoundaryPolicy] {
        &self.boundaries
    }

    /// Returns the configured declassification rules.
    #[must_use]
    pub fn declassification_rules(&self) -> &[DeclassificationPolicy] {
        &self.declassification_rules
    }
}

impl Default for DualLatticePolicy {
    fn default() -> Self {
        Self::deny_all()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TaintLevel lattice tests
    // =========================================================================

    #[test]
    fn taint_join_is_commutative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                let la = TaintLevel::from_ordinal(a).unwrap();
                let lb = TaintLevel::from_ordinal(b).unwrap();
                assert_eq!(
                    la.join(lb),
                    lb.join(la),
                    "join({la}, {lb}) != join({lb}, {la})"
                );
            }
        }
    }

    #[test]
    fn taint_join_is_associative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                for c in 0..=4u8 {
                    let la = TaintLevel::from_ordinal(a).unwrap();
                    let lb = TaintLevel::from_ordinal(b).unwrap();
                    let lc = TaintLevel::from_ordinal(c).unwrap();
                    assert_eq!(
                        la.join(lb).join(lc),
                        la.join(lb.join(lc)),
                        "join not associative for ({la}, {lb}, {lc})"
                    );
                }
            }
        }
    }

    #[test]
    fn taint_join_is_idempotent() {
        for a in 0..=4u8 {
            let la = TaintLevel::from_ordinal(a).unwrap();
            assert_eq!(la.join(la), la, "join({la}, {la}) != {la}");
        }
    }

    #[test]
    fn taint_join_selects_higher() {
        assert_eq!(
            TaintLevel::Untainted.join(TaintLevel::HighTaint),
            TaintLevel::HighTaint
        );
        assert_eq!(
            TaintLevel::LowTaint.join(TaintLevel::MediumTaint),
            TaintLevel::MediumTaint
        );
        assert_eq!(
            TaintLevel::Toxic.join(TaintLevel::Untainted),
            TaintLevel::Toxic
        );
    }

    #[test]
    fn taint_within_ceiling() {
        assert!(TaintLevel::Untainted.within_ceiling(TaintLevel::LowTaint));
        assert!(TaintLevel::LowTaint.within_ceiling(TaintLevel::LowTaint));
        assert!(!TaintLevel::MediumTaint.within_ceiling(TaintLevel::LowTaint));
        assert!(!TaintLevel::Toxic.within_ceiling(TaintLevel::HighTaint));
    }

    #[test]
    fn taint_from_ordinal_roundtrip() {
        for v in 0..=4u8 {
            let level = TaintLevel::from_ordinal(v).unwrap();
            assert_eq!(level.ordinal(), v);
        }
        assert!(TaintLevel::from_ordinal(5).is_none());
        assert!(TaintLevel::from_ordinal(255).is_none());
    }

    #[test]
    fn taint_ordering() {
        assert!(TaintLevel::Untainted < TaintLevel::LowTaint);
        assert!(TaintLevel::LowTaint < TaintLevel::MediumTaint);
        assert!(TaintLevel::MediumTaint < TaintLevel::HighTaint);
        assert!(TaintLevel::HighTaint < TaintLevel::Toxic);
    }

    #[test]
    fn taint_default_is_untainted() {
        assert_eq!(TaintLevel::default(), TaintLevel::Untainted);
    }

    #[test]
    fn taint_display() {
        assert_eq!(TaintLevel::Untainted.to_string(), "Untainted");
        assert_eq!(TaintLevel::Toxic.to_string(), "Toxic");
    }

    // =========================================================================
    // ConfidentialityLevel lattice tests
    // =========================================================================

    #[test]
    fn conf_meet_is_commutative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                let la = ConfidentialityLevel::from_ordinal(a).unwrap();
                let lb = ConfidentialityLevel::from_ordinal(b).unwrap();
                assert_eq!(
                    la.meet(lb),
                    lb.meet(la),
                    "meet({la}, {lb}) != meet({lb}, {la})"
                );
            }
        }
    }

    #[test]
    fn conf_meet_is_associative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                for c in 0..=4u8 {
                    let la = ConfidentialityLevel::from_ordinal(a).unwrap();
                    let lb = ConfidentialityLevel::from_ordinal(b).unwrap();
                    let lc = ConfidentialityLevel::from_ordinal(c).unwrap();
                    assert_eq!(
                        la.meet(lb).meet(lc),
                        la.meet(lb.meet(lc)),
                        "meet not associative for ({la}, {lb}, {lc})"
                    );
                }
            }
        }
    }

    #[test]
    fn conf_meet_is_idempotent() {
        for a in 0..=4u8 {
            let la = ConfidentialityLevel::from_ordinal(a).unwrap();
            assert_eq!(la.meet(la), la, "meet({la}, {la}) != {la}");
        }
    }

    #[test]
    fn conf_meet_selects_lower() {
        assert_eq!(
            ConfidentialityLevel::Secret.meet(ConfidentialityLevel::Public),
            ConfidentialityLevel::Public
        );
        assert_eq!(
            ConfidentialityLevel::TopSecret.meet(ConfidentialityLevel::Internal),
            ConfidentialityLevel::Internal
        );
    }

    #[test]
    fn conf_join_selects_higher() {
        assert_eq!(
            ConfidentialityLevel::Public.join(ConfidentialityLevel::Secret),
            ConfidentialityLevel::Secret
        );
        assert_eq!(
            ConfidentialityLevel::Internal.join(ConfidentialityLevel::Confidential),
            ConfidentialityLevel::Confidential
        );
    }

    #[test]
    fn conf_join_is_commutative() {
        for a in 0..=4u8 {
            for b in 0..=4u8 {
                let la = ConfidentialityLevel::from_ordinal(a).unwrap();
                let lb = ConfidentialityLevel::from_ordinal(b).unwrap();
                assert_eq!(la.join(lb), lb.join(la));
            }
        }
    }

    #[test]
    fn conf_within_clearance() {
        assert!(ConfidentialityLevel::Public.within_clearance(ConfidentialityLevel::Internal));
        assert!(ConfidentialityLevel::Secret.within_clearance(ConfidentialityLevel::Secret));
        assert!(!ConfidentialityLevel::TopSecret.within_clearance(ConfidentialityLevel::Secret));
    }

    #[test]
    fn conf_from_ordinal_roundtrip() {
        for v in 0..=4u8 {
            let level = ConfidentialityLevel::from_ordinal(v).unwrap();
            assert_eq!(level.ordinal(), v);
        }
        assert!(ConfidentialityLevel::from_ordinal(5).is_none());
    }

    #[test]
    fn conf_ordering() {
        assert!(ConfidentialityLevel::Public < ConfidentialityLevel::Internal);
        assert!(ConfidentialityLevel::Internal < ConfidentialityLevel::Confidential);
        assert!(ConfidentialityLevel::Confidential < ConfidentialityLevel::Secret);
        assert!(ConfidentialityLevel::Secret < ConfidentialityLevel::TopSecret);
    }

    #[test]
    fn conf_default_is_public() {
        assert_eq!(
            ConfidentialityLevel::default(),
            ConfidentialityLevel::Public
        );
    }

    #[test]
    fn conf_display() {
        assert_eq!(ConfidentialityLevel::Public.to_string(), "Public");
        assert_eq!(ConfidentialityLevel::TopSecret.to_string(), "TopSecret");
    }

    // =========================================================================
    // DataLabel tests
    // =========================================================================

    #[test]
    fn data_label_join_propagates_both() {
        let a = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Internal);
        let b = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Secret);
        let joined = a.join(b);
        assert_eq!(joined.taint, TaintLevel::HighTaint);
        assert_eq!(joined.confidentiality, ConfidentialityLevel::Secret);
    }

    #[test]
    fn data_label_join_is_commutative() {
        let a = DataLabel::new(TaintLevel::MediumTaint, ConfidentialityLevel::Confidential);
        let b = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::TopSecret);
        assert_eq!(a.join(b), b.join(a));
    }

    #[test]
    fn data_label_trusted_public() {
        let label = DataLabel::TRUSTED_PUBLIC;
        assert_eq!(label.taint, TaintLevel::Untainted);
        assert_eq!(label.confidentiality, ConfidentialityLevel::Public);
    }

    #[test]
    fn data_label_display() {
        let label = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Secret);
        assert_eq!(label.to_string(), "[taint=LowTaint, conf=Secret]");
    }

    #[test]
    fn data_label_default() {
        assert_eq!(DataLabel::default(), DataLabel::TRUSTED_PUBLIC);
    }

    // =========================================================================
    // BoundaryPolicy tests
    // =========================================================================

    #[test]
    fn boundary_allows_clean_data() {
        let boundary = BoundaryPolicy::new(
            "actuator-input",
            TaintLevel::LowTaint,
            ConfidentialityLevel::Internal,
            3,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(boundary.check(&label).is_ok());
    }

    #[test]
    fn boundary_rejects_high_taint() {
        let boundary = BoundaryPolicy::new(
            "actuator-input",
            TaintLevel::LowTaint,
            ConfidentialityLevel::Internal,
            3,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Public);
        let err = boundary.check(&label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::TaintCeilingExceeded { tier: 3, .. }
        ));
    }

    #[test]
    fn boundary_rejects_high_confidentiality() {
        let boundary = BoundaryPolicy::new(
            "external-api",
            TaintLevel::Toxic,
            ConfidentialityLevel::Internal,
            0,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let err = boundary.check(&label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::ConfidentialityFloorViolation { .. }
        ));
    }

    #[test]
    fn boundary_at_exact_limits() {
        let boundary = BoundaryPolicy::new(
            "edge",
            TaintLevel::MediumTaint,
            ConfidentialityLevel::Confidential,
            2,
        )
        .unwrap();

        let label = DataLabel::new(TaintLevel::MediumTaint, ConfidentialityLevel::Confidential);
        assert!(boundary.check(&label).is_ok());
    }

    #[test]
    fn boundary_rejects_empty_id() {
        let err = BoundaryPolicy::new("", TaintLevel::Untainted, ConfidentialityLevel::Public, 0)
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn boundary_rejects_long_id() {
        let long_id = "x".repeat(MAX_BOUNDARY_ID_LEN + 1);
        let err = BoundaryPolicy::new(
            &long_id,
            TaintLevel::Untainted,
            ConfidentialityLevel::Public,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    // =========================================================================
    // DeclassificationPolicy tests
    // =========================================================================

    #[test]
    fn declass_policy_valid() {
        let policy = DeclassificationPolicy::new(
            "DECLASS-001",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn declass_policy_rejects_non_decreasing() {
        let err = DeclassificationPolicy::new(
            "DECLASS-BAD",
            ConfidentialityLevel::Internal,
            ConfidentialityLevel::Secret,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declass_policy_rejects_equal() {
        let err = DeclassificationPolicy::new(
            "DECLASS-EQ",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Secret,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declass_policy_rejects_empty_id() {
        let err = DeclassificationPolicy::new(
            "",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Public,
        )
        .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declass_policy_allows_check() {
        let policy = DeclassificationPolicy::new(
            "DECLASS-001",
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Internal,
        )
        .unwrap();

        assert!(policy.allows(ConfidentialityLevel::Secret, ConfidentialityLevel::Internal));
        assert!(policy.allows(
            ConfidentialityLevel::Confidential,
            ConfidentialityLevel::Internal
        ));
        // Cannot declassify below min_to.
        assert!(!policy.allows(ConfidentialityLevel::Secret, ConfidentialityLevel::Public));
        // Cannot declassify above max_from.
        assert!(!policy.allows(
            ConfidentialityLevel::TopSecret,
            ConfidentialityLevel::Internal
        ));
        // Not a downgrade.
        assert!(!policy.allows(ConfidentialityLevel::Internal, ConfidentialityLevel::Secret));
    }

    // =========================================================================
    // DualLatticePolicy boundary crossing tests
    // =========================================================================

    fn test_policy() -> DualLatticePolicy {
        let boundaries = vec![
            BoundaryPolicy::new(
                "tier3-actuator",
                TaintLevel::LowTaint,
                ConfidentialityLevel::Internal,
                3,
            )
            .unwrap(),
            BoundaryPolicy::new(
                "tier4-actuator",
                TaintLevel::Untainted,
                ConfidentialityLevel::Public,
                4,
            )
            .unwrap(),
            BoundaryPolicy::new(
                "external-api",
                TaintLevel::MediumTaint,
                ConfidentialityLevel::Internal,
                0,
            )
            .unwrap(),
        ];

        let declass_rules = vec![
            DeclassificationPolicy::new(
                "DECLASS-SECRET-TO-INTERNAL",
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
            )
            .unwrap(),
            DeclassificationPolicy::new(
                "DECLASS-INTERNAL-TO-PUBLIC",
                ConfidentialityLevel::Internal,
                ConfidentialityLevel::Public,
            )
            .unwrap(),
        ];

        DualLatticePolicy::new(boundaries, declass_rules)
    }

    #[test]
    fn dual_policy_tier3_allows_clean_input() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(policy.check_boundary("tier3-actuator", &label).is_ok());
    }

    #[test]
    fn dual_policy_tier3_rejects_high_taint() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Public);
        let err = policy.check_boundary("tier3-actuator", &label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::TaintCeilingExceeded { tier: 3, .. }
        ));
    }

    #[test]
    fn dual_policy_tier3_rejects_over_confidential() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let err = policy.check_boundary("tier3-actuator", &label).unwrap_err();
        assert!(matches!(
            err,
            TaintError::ConfidentialityFloorViolation { .. }
        ));
    }

    #[test]
    fn dual_policy_tier4_most_restrictive() {
        let policy = test_policy();

        // Only untainted + public passes tier4.
        let good = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(policy.check_boundary("tier4-actuator", &good).is_ok());

        // LowTaint fails tier4.
        let tainted = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Public);
        assert!(policy.check_boundary("tier4-actuator", &tainted).is_err());

        // Internal fails tier4.
        let internal = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Internal);
        assert!(policy.check_boundary("tier4-actuator", &internal).is_err());
    }

    #[test]
    fn dual_policy_unknown_boundary_fails_closed() {
        let policy = test_policy();
        let label = DataLabel::TRUSTED_PUBLIC;
        let err = policy.check_boundary("nonexistent", &label).unwrap_err();
        assert!(matches!(err, TaintError::BoundaryCrossingDenied { .. }));
    }

    #[test]
    fn dual_policy_deny_all_rejects_everything() {
        let policy = DualLatticePolicy::deny_all();
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(policy.check_boundary("anything", &label).is_err());
    }

    // =========================================================================
    // Actuator tier enforcement tests
    // =========================================================================

    #[test]
    fn actuator_tier3_enforced() {
        let policy = test_policy();

        let clean = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Internal);
        assert!(policy.check_actuator_tier(3, &clean).is_ok());

        let dirty = DataLabel::new(TaintLevel::MediumTaint, ConfidentialityLevel::Public);
        assert!(policy.check_actuator_tier(3, &dirty).is_err());
    }

    #[test]
    fn actuator_tier4_strictest() {
        let policy = test_policy();

        let clean = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        assert!(policy.check_actuator_tier(4, &clean).is_ok());

        let any_taint = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Public);
        assert!(policy.check_actuator_tier(4, &any_taint).is_err());
    }

    #[test]
    fn actuator_unconfigured_tier3_fails_closed() {
        let policy = DualLatticePolicy::new(vec![], vec![]);
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(policy.check_actuator_tier(3, &label).is_err());
    }

    #[test]
    fn actuator_tier_below_3_passes_without_boundary() {
        // Tiers below 3 do not require boundary policies.
        let policy = DualLatticePolicy::new(vec![], vec![]);
        let label = DataLabel::new(TaintLevel::Toxic, ConfidentialityLevel::TopSecret);
        assert!(policy.check_actuator_tier(1, &label).is_ok());
        assert!(policy.check_actuator_tier(2, &label).is_ok());
    }

    // =========================================================================
    // Declassification tests
    // =========================================================================

    #[test]
    fn declassification_produces_receipt() {
        let policy = test_policy();
        let receipt = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "Approved by security review SR-2026-042",
            )
            .unwrap();

        assert_eq!(receipt.from_level(), ConfidentialityLevel::Secret);
        assert_eq!(receipt.to_level(), ConfidentialityLevel::Internal);
        assert_eq!(receipt.policy_ref(), "DECLASS-SECRET-TO-INTERNAL");
        assert_eq!(
            receipt.justification(),
            "Approved by security review SR-2026-042"
        );
        assert!(!receipt.content_hash_hex().is_empty());
        assert_eq!(receipt.content_hash_hex().len(), 64); // 32 bytes hex
    }

    #[test]
    fn declassification_receipt_hash_is_deterministic() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "same justification",
            )
            .unwrap();
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn declassification_receipt_hash_varies_with_justification() {
        let policy = test_policy();
        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "justification A",
            )
            .unwrap();
        let r2 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "justification B",
            )
            .unwrap();
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn declassification_denied_without_matching_rule() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::TopSecret,
                ConfidentialityLevel::Public,
                "DECLASS-SECRET-TO-INTERNAL",
                "trying to leak",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_wrong_rule_id() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "NONEXISTENT-RULE",
                "no such rule",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_not_a_downgrade() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Public,
                ConfidentialityLevel::Secret,
                "DECLASS-SECRET-TO-INTERNAL",
                "upgrade attempt",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_same_level() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Secret,
                "DECLASS-SECRET-TO-INTERNAL",
                "no-op attempt",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn declassification_denied_empty_policy_ref() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "",
                "missing ref",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_denied_long_justification() {
        let policy = test_policy();
        let long_just = "x".repeat(MAX_JUSTIFICATION_LEN + 1);
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                &long_just,
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::InvalidPolicyRef { .. }));
    }

    #[test]
    fn declassification_two_step_chain() {
        // First: Secret -> Internal, then Internal -> Public
        let policy = test_policy();

        let r1 = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Internal,
                "DECLASS-SECRET-TO-INTERNAL",
                "step 1",
            )
            .unwrap();
        assert_eq!(r1.to_level(), ConfidentialityLevel::Internal);

        let r2 = policy
            .declassify(
                ConfidentialityLevel::Internal,
                ConfidentialityLevel::Public,
                "DECLASS-INTERNAL-TO-PUBLIC",
                "step 2",
            )
            .unwrap();
        assert_eq!(r2.to_level(), ConfidentialityLevel::Public);
    }

    // =========================================================================
    // Boundary propagation tests
    // =========================================================================

    #[test]
    fn propagation_clamps_confidentiality() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let result = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap();
        assert_eq!(result.taint, TaintLevel::Untainted);
        assert_eq!(result.confidentiality, ConfidentialityLevel::Internal);
    }

    #[test]
    fn propagation_preserves_low_confidentiality() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Public);
        let result = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap();
        assert_eq!(result.confidentiality, ConfidentialityLevel::Public);
    }

    #[test]
    fn propagation_rejects_taint_violation() {
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::HighTaint, ConfidentialityLevel::Public);
        let err = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap_err();
        assert!(matches!(err, TaintError::TaintCeilingExceeded { .. }));
    }

    #[test]
    fn propagation_unknown_boundary_fails_closed() {
        let policy = test_policy();
        let label = DataLabel::TRUSTED_PUBLIC;
        assert!(
            policy
                .propagate_through_boundary("unknown", &label)
                .is_err()
        );
    }

    // =========================================================================
    // Secret leakage adversarial tests
    // =========================================================================

    #[test]
    fn adversarial_secret_to_external_api_blocked() {
        let policy = test_policy();
        let secret_data = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::Secret);
        let err = policy
            .check_boundary("external-api", &secret_data)
            .unwrap_err();
        assert!(matches!(
            err,
            TaintError::ConfidentialityFloorViolation { .. }
        ));
    }

    #[test]
    fn adversarial_top_secret_to_any_boundary_blocked() {
        let policy = test_policy();
        let top_secret = DataLabel::new(TaintLevel::Untainted, ConfidentialityLevel::TopSecret);

        // TopSecret should be blocked at every configured boundary.
        for boundary in policy.boundaries() {
            assert!(
                boundary.check(&top_secret).is_err(),
                "TopSecret should be blocked at boundary '{}'",
                boundary.boundary_id()
            );
        }
    }

    #[test]
    fn adversarial_toxic_taint_blocked_at_all_tier3plus() {
        let policy = test_policy();
        let toxic = DataLabel::new(TaintLevel::Toxic, ConfidentialityLevel::Public);

        // Toxic data should be blocked at tier3 and tier4.
        assert!(policy.check_actuator_tier(3, &toxic).is_err());
        assert!(policy.check_actuator_tier(4, &toxic).is_err());
    }

    #[test]
    fn adversarial_join_elevates_both_dimensions() {
        // An adversary combining clean data with tainted+secret data
        // should produce a label that is blocked everywhere sensitive.
        let clean = DataLabel::TRUSTED_PUBLIC;
        let malicious = DataLabel::new(TaintLevel::Toxic, ConfidentialityLevel::TopSecret);
        let combined = clean.join(malicious);

        assert_eq!(combined.taint, TaintLevel::Toxic);
        assert_eq!(combined.confidentiality, ConfidentialityLevel::TopSecret);

        let policy = test_policy();
        assert!(policy.check_boundary("tier3-actuator", &combined).is_err());
        assert!(policy.check_boundary("tier4-actuator", &combined).is_err());
        assert!(policy.check_boundary("external-api", &combined).is_err());
    }

    #[test]
    fn adversarial_declassify_skip_denied() {
        // Trying to jump Secret -> Public in one step when the rule only
        // allows Secret -> Internal.
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                "DECLASS-SECRET-TO-INTERNAL",
                "trying to skip levels",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn adversarial_declassify_wrong_direction() {
        let policy = test_policy();
        let err = policy
            .declassify(
                ConfidentialityLevel::Internal,
                ConfidentialityLevel::TopSecret,
                "DECLASS-SECRET-TO-INTERNAL",
                "reverse declassification attempt",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    #[test]
    fn adversarial_propagation_does_not_lower_taint() {
        // Propagation through a boundary must never lower taint.
        let policy = test_policy();
        let label = DataLabel::new(TaintLevel::LowTaint, ConfidentialityLevel::Public);
        let result = policy
            .propagate_through_boundary("external-api", &label)
            .unwrap();
        // Taint must be preserved, not lowered.
        assert_eq!(result.taint, TaintLevel::LowTaint);
    }

    #[test]
    fn adversarial_declassify_no_rules_configured() {
        let policy = DualLatticePolicy::new(vec![], vec![]);
        let err = policy
            .declassify(
                ConfidentialityLevel::Secret,
                ConfidentialityLevel::Public,
                "ANY-RULE",
                "no rules exist",
            )
            .unwrap_err();
        assert!(matches!(err, TaintError::DeclassificationDenied { .. }));
    }

    // =========================================================================
    // Error display tests
    // =========================================================================

    #[test]
    fn error_display_taint_ceiling() {
        let err = TaintError::TaintCeilingExceeded {
            actual: TaintLevel::HighTaint,
            max_allowed: TaintLevel::LowTaint,
            tier: 3,
        };
        assert!(err.to_string().contains("HighTaint"));
        assert!(err.to_string().contains("LowTaint"));
        assert!(err.to_string().contains("tier 3"));
    }

    #[test]
    fn error_display_confidentiality_violation() {
        let err = TaintError::ConfidentialityFloorViolation {
            actual: ConfidentialityLevel::Secret,
            max_allowed: ConfidentialityLevel::Internal,
            boundary: "external-api".to_string(),
        };
        assert!(err.to_string().contains("Secret"));
        assert!(err.to_string().contains("Internal"));
        assert!(err.to_string().contains("external-api"));
    }

    #[test]
    fn error_display_declassification_denied() {
        let err = TaintError::DeclassificationDenied {
            from: ConfidentialityLevel::TopSecret,
            to: ConfidentialityLevel::Public,
            reason: "not authorized".to_string(),
        };
        assert!(err.to_string().contains("TopSecret"));
        assert!(err.to_string().contains("Public"));
        assert!(err.to_string().contains("not authorized"));
    }

    // =========================================================================
    // Free propagation function tests
    // =========================================================================

    #[test]
    fn propagate_taint_empty_returns_identity() {
        assert_eq!(super::propagate_taint(&[]), TaintLevel::Untainted);
    }

    #[test]
    fn propagate_taint_single() {
        assert_eq!(
            super::propagate_taint(&[TaintLevel::HighTaint]),
            TaintLevel::HighTaint
        );
    }

    #[test]
    fn propagate_taint_multiple_returns_highest() {
        let inputs = [
            TaintLevel::LowTaint,
            TaintLevel::Untainted,
            TaintLevel::MediumTaint,
            TaintLevel::LowTaint,
        ];
        assert_eq!(super::propagate_taint(&inputs), TaintLevel::MediumTaint);
    }

    #[test]
    fn propagate_taint_all_toxic() {
        let inputs = [TaintLevel::Toxic, TaintLevel::Toxic];
        assert_eq!(super::propagate_taint(&inputs), TaintLevel::Toxic);
    }

    #[test]
    fn propagate_classification_empty_returns_identity() {
        assert_eq!(
            super::propagate_classification(&[]),
            ConfidentialityLevel::Public
        );
    }

    #[test]
    fn propagate_classification_single() {
        assert_eq!(
            super::propagate_classification(&[ConfidentialityLevel::Secret]),
            ConfidentialityLevel::Secret
        );
    }

    #[test]
    fn propagate_classification_multiple_returns_highest() {
        let inputs = [
            ConfidentialityLevel::Internal,
            ConfidentialityLevel::Public,
            ConfidentialityLevel::Secret,
            ConfidentialityLevel::Confidential,
        ];
        assert_eq!(
            super::propagate_classification(&inputs),
            ConfidentialityLevel::Secret
        );
    }

    #[test]
    fn propagate_classification_all_top_secret() {
        let inputs = [
            ConfidentialityLevel::TopSecret,
            ConfidentialityLevel::TopSecret,
        ];
        assert_eq!(
            super::propagate_classification(&inputs),
            ConfidentialityLevel::TopSecret
        );
    }
}

// =============================================================================
// Proptest lattice law invariants
// =============================================================================

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    fn arb_taint_level() -> impl Strategy<Value = TaintLevel> {
        (0u8..=4).prop_map(|v| TaintLevel::from_ordinal(v).unwrap())
    }

    fn arb_conf_level() -> impl Strategy<Value = ConfidentialityLevel> {
        (0u8..=4).prop_map(|v| ConfidentialityLevel::from_ordinal(v).unwrap())
    }

    proptest! {
        // =================================================================
        // TaintLevel join lattice laws
        // =================================================================

        #[test]
        fn taint_join_commutative(a in arb_taint_level(), b in arb_taint_level()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn taint_join_associative(
            a in arb_taint_level(),
            b in arb_taint_level(),
            c in arb_taint_level(),
        ) {
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }

        #[test]
        fn taint_join_idempotent(a in arb_taint_level()) {
            prop_assert_eq!(a.join(a), a);
        }

        #[test]
        fn taint_join_identity(a in arb_taint_level()) {
            // Untainted is the identity for join.
            prop_assert_eq!(a.join(TaintLevel::Untainted), a);
            prop_assert_eq!(TaintLevel::Untainted.join(a), a);
        }

        #[test]
        fn taint_join_absorbing(a in arb_taint_level()) {
            // Toxic is the absorbing element for join.
            prop_assert_eq!(a.join(TaintLevel::Toxic), TaintLevel::Toxic);
        }

        #[test]
        fn taint_join_monotone(a in arb_taint_level(), b in arb_taint_level()) {
            // join(a, b) >= a and join(a, b) >= b
            prop_assert!(a.join(b) >= a);
            prop_assert!(a.join(b) >= b);
        }

        // =================================================================
        // ConfidentialityLevel join lattice laws
        // =================================================================

        #[test]
        fn conf_join_commutative(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn conf_join_associative(
            a in arb_conf_level(),
            b in arb_conf_level(),
            c in arb_conf_level(),
        ) {
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }

        #[test]
        fn conf_join_idempotent(a in arb_conf_level()) {
            prop_assert_eq!(a.join(a), a);
        }

        #[test]
        fn conf_join_identity(a in arb_conf_level()) {
            prop_assert_eq!(a.join(ConfidentialityLevel::Public), a);
            prop_assert_eq!(ConfidentialityLevel::Public.join(a), a);
        }

        #[test]
        fn conf_join_absorbing(a in arb_conf_level()) {
            prop_assert_eq!(a.join(ConfidentialityLevel::TopSecret), ConfidentialityLevel::TopSecret);
        }

        #[test]
        fn conf_join_monotone(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert!(a.join(b) >= a);
            prop_assert!(a.join(b) >= b);
        }

        // =================================================================
        // ConfidentialityLevel meet lattice laws
        // =================================================================

        #[test]
        fn conf_meet_commutative(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert_eq!(a.meet(b), b.meet(a));
        }

        #[test]
        fn conf_meet_associative(
            a in arb_conf_level(),
            b in arb_conf_level(),
            c in arb_conf_level(),
        ) {
            prop_assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
        }

        #[test]
        fn conf_meet_idempotent(a in arb_conf_level()) {
            prop_assert_eq!(a.meet(a), a);
        }

        #[test]
        fn conf_meet_identity(a in arb_conf_level()) {
            prop_assert_eq!(a.meet(ConfidentialityLevel::TopSecret), a);
            prop_assert_eq!(ConfidentialityLevel::TopSecret.meet(a), a);
        }

        #[test]
        fn conf_meet_absorbing(a in arb_conf_level()) {
            prop_assert_eq!(a.meet(ConfidentialityLevel::Public), ConfidentialityLevel::Public);
        }

        #[test]
        fn conf_meet_monotone(a in arb_conf_level(), b in arb_conf_level()) {
            prop_assert!(a.meet(b) <= a);
            prop_assert!(a.meet(b) <= b);
        }

        // =================================================================
        // Absorption law: join and meet interact correctly
        // =================================================================

        #[test]
        fn conf_absorption_law(a in arb_conf_level(), b in arb_conf_level()) {
            // a join (a meet b) == a
            prop_assert_eq!(a.join(a.meet(b)), a);
            // a meet (a join b) == a
            prop_assert_eq!(a.meet(a.join(b)), a);
        }

        // =================================================================
        // DataLabel join lattice laws
        // =================================================================

        #[test]
        fn data_label_join_commutative(
            ta in arb_taint_level(), ca in arb_conf_level(),
            tb in arb_taint_level(), cb in arb_conf_level(),
        ) {
            let a = DataLabel::new(ta, ca);
            let b = DataLabel::new(tb, cb);
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn data_label_join_associative(
            ta in arb_taint_level(), ca in arb_conf_level(),
            tb in arb_taint_level(), cb in arb_conf_level(),
            tc in arb_taint_level(), cc in arb_conf_level(),
        ) {
            let a = DataLabel::new(ta, ca);
            let b = DataLabel::new(tb, cb);
            let c = DataLabel::new(tc, cc);
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }

        #[test]
        fn data_label_join_idempotent(t in arb_taint_level(), c in arb_conf_level()) {
            let a = DataLabel::new(t, c);
            prop_assert_eq!(a.join(a), a);
        }

        // =================================================================
        // Propagation function correctness
        // =================================================================

        #[test]
        fn propagate_taint_matches_fold(
            a in arb_taint_level(),
            b in arb_taint_level(),
            c in arb_taint_level(),
        ) {
            let inputs = [a, b, c];
            let expected = a.join(b).join(c);
            prop_assert_eq!(propagate_taint(&inputs), expected);
        }

        #[test]
        fn propagate_classification_matches_fold(
            a in arb_conf_level(),
            b in arb_conf_level(),
            c in arb_conf_level(),
        ) {
            let inputs = [a, b, c];
            let expected = a.join(b).join(c);
            prop_assert_eq!(propagate_classification(&inputs), expected);
        }

        // =================================================================
        // Taint monotonicity: propagation never decreases
        // =================================================================

        #[test]
        fn propagate_taint_never_decreases(
            a in arb_taint_level(),
            b in arb_taint_level(),
        ) {
            let result = propagate_taint(&[a, b]);
            prop_assert!(result >= a);
            prop_assert!(result >= b);
        }

        #[test]
        fn propagate_classification_never_decreases(
            a in arb_conf_level(),
            b in arb_conf_level(),
        ) {
            let result = propagate_classification(&[a, b]);
            prop_assert!(result >= a);
            prop_assert!(result >= b);
        }
    }
}
