//! Agent capsule containment module (RFC-0020 Section 4).
//!
//! This module implements the `linux-ns-v1` capsule profile for enforcing
//! no-ambient-authority containment of agent processes. It is the primary
//! delivery for REQ-0028 (capsule containment with no ambient authority).
//!
//! # Security Model
//!
//! The capsule profile enforces defense-in-depth containment:
//!
//! - **Namespace isolation**: user, mount, pid namespaces
//! - **Syscall filtering**: seccomp-bpf via
//!   [`SeccompProfileLevel`](crate::adapter::seccomp::SeccompProfileLevel)
//! - **Resource limits**: cgroup controls for CPU, memory, PIDs, I/O
//! - **Network isolation**: deny-by-default egress with explicit route grants
//! - **Workspace confinement**: bind-mounted workspace root with symlink
//!   rejection
//! - **Environment scrubbing**: no inherited credentials or host secrets
//!
//! # Tier Enforcement
//!
//! - **Tier3+**: MUST execute inside an admitted capsule profile (hard fail)
//! - **Tier1-Tier2**: Capsule profile is optional but recommended
//! - **Tier0**: Development mode; capsule is informational only
//!
//! # Invariants
//!
//! - [INV-CAP-001] Capsule profiles are content-addressed (referenced by hash)
//! - [INV-CAP-002] Deny-by-default egress is enforced; no ambient network
//! - [INV-CAP-003] Escape attempts produce `CapsuleViolation` events
//! - [INV-CAP-004] Tier3+ actuation without admitted capsule is rejected
//!
//! # Example
//!
//! ```rust
//! use apm2_core::capsule::{
//!     CapsuleProfile, CapsuleProfileBuilder, CgroupLimits, EgressPolicy, NamespaceConfig,
//!     WorkspaceConfinement,
//! };
//!
//! let profile = CapsuleProfileBuilder::new("linux-ns-v1")
//!     .namespaces(NamespaceConfig::isolated())
//!     .cgroup_limits(CgroupLimits::default_restricted())
//!     .egress_policy(EgressPolicy::deny_all())
//!     .workspace(WorkspaceConfinement::new("/workspace"))
//!     .build()
//!     .expect("valid capsule profile");
//!
//! assert!(profile.egress_policy.deny_by_default);
//! assert!(profile.namespaces.user);
//! assert!(profile.namespaces.mount);
//! assert!(profile.namespaces.pid);
//! ```

mod profile;
mod workspace;

pub use profile::{
    AdmissionError, AdmissionGate, CapsuleProfile, CapsuleProfileBuilder, CapsuleProfileError,
    CgroupLimits, EgressPolicy, EgressRoute, HashInput, MAX_ALLOWED_EXECUTABLES, MAX_EGRESS_ROUTES,
    MAX_PROFILE_ID_LENGTH, NamespaceConfig, ViolationKind,
};
pub use workspace::{
    MAX_WORKSPACE_PATH_DEPTH, WorkspaceConfinement, WorkspaceConfinementError,
    validate_absolute_within_root, validate_workspace_path,
};
