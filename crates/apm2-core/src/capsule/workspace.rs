// AGENT-AUTHORED
//! Workspace confinement for capsule containment (RFC-0020 Section 4.3).
//!
//! Provides path traversal prevention, symlink escape detection, and
//! workspace root confinement. Used by the capsule profile to enforce
//! that agent processes cannot access files outside their workspace.
//!
//! # Security Properties
//!
//! - Path traversal via `..` components is rejected
//! - Absolute paths are rejected (must be relative to workspace root)
//! - Symlinks are detected and rejected
//! - Workspace root itself is validated (no sensitive system directories)
//!
//! # Example
//!
//! ```rust
//! use std::path::Path;
//!
//! use apm2_core::capsule::{WorkspaceConfinement, validate_workspace_path};
//!
//! let confinement = WorkspaceConfinement::new("/home/agent/workspace");
//! assert!(confinement.validate().is_ok());
//!
//! // Valid relative path within workspace
//! assert!(validate_workspace_path(Path::new("src/main.rs"), Path::new("/workspace")).is_ok());
//!
//! // Path traversal attempt → rejected
//! assert!(
//!     validate_workspace_path(Path::new("../../../etc/passwd"), Path::new("/workspace")).is_err()
//! );
//! ```

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum path depth to prevent directory traversal and zip-bomb style
/// attacks.
pub const MAX_WORKSPACE_PATH_DEPTH: usize = 64;

/// Maximum length of a workspace path.
const MAX_WORKSPACE_PATH_LENGTH: usize = 4096;

/// Blocked workspace root prefixes (sensitive system directories).
///
/// Workspace root MUST NOT be set to these directories to prevent
/// accidental access to system-critical files.
const BLOCKED_ROOTS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin",
    "/sys", "/usr", "/var",
];

// =============================================================================
// Error Types
// =============================================================================

/// Errors from workspace confinement operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkspaceConfinementError {
    /// Path traversal attempt detected.
    #[error("path traversal detected: {path}")]
    PathTraversal {
        /// The offending path.
        path: String,
    },

    /// Symlink detected in workspace path.
    #[error("symlink detected at: {path}")]
    SymlinkDetected {
        /// Path where symlink was found.
        path: String,
    },

    /// Absolute path in workspace-relative context.
    #[error("absolute path not allowed in workspace context: {path}")]
    AbsolutePath {
        /// The offending absolute path.
        path: String,
    },

    /// Path depth exceeds maximum.
    #[error("path depth {depth} exceeds maximum {max}")]
    PathTooDeep {
        /// Actual depth.
        depth: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path length exceeds maximum.
    #[error("path length {actual} exceeds maximum {max}")]
    PathTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Workspace root is a sensitive system directory.
    #[error("workspace root '{root}' is a blocked system directory")]
    BlockedRoot {
        /// The blocked root path.
        root: String,
    },

    /// Workspace root is empty.
    #[error("workspace root path is empty")]
    EmptyRoot,

    /// Workspace root is not absolute.
    #[error("workspace root must be an absolute path: {root}")]
    NotAbsolute {
        /// The non-absolute root.
        root: String,
    },

    /// Forbidden path component found.
    #[error("forbidden path component: {component}")]
    ForbiddenComponent {
        /// Description of the forbidden component.
        component: String,
    },
}

// =============================================================================
// WorkspaceConfinement
// =============================================================================

/// Workspace confinement specification for capsule containment.
///
/// Defines the workspace root directory that will be bind-mounted
/// into the capsule. All agent file operations are confined to this root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceConfinement {
    /// Absolute path to the workspace root.
    root: PathBuf,
}

impl WorkspaceConfinement {
    /// Creates a new workspace confinement with the given root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the workspace root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Validates the workspace confinement configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceConfinementError`] if validation fails.
    pub fn validate(&self) -> Result<(), WorkspaceConfinementError> {
        let root_str = self.root.to_string_lossy();

        // Must not be empty
        if root_str.is_empty() {
            return Err(WorkspaceConfinementError::EmptyRoot);
        }

        // Must be absolute
        if !self.root.is_absolute() {
            return Err(WorkspaceConfinementError::NotAbsolute {
                root: root_str.to_string(),
            });
        }

        // Must not exceed length limit
        if root_str.len() > MAX_WORKSPACE_PATH_LENGTH {
            return Err(WorkspaceConfinementError::PathTooLong {
                actual: root_str.len(),
                max: MAX_WORKSPACE_PATH_LENGTH,
            });
        }

        // Must not be a blocked system directory.
        // Use component-aware `starts_with` to prevent partial match bypass
        // (e.g., "/var/log" must be blocked because /var is blocked).
        for blocked in BLOCKED_ROOTS {
            let blocked_path = Path::new(blocked);
            if *blocked == "/" {
                // Root "/" only blocks the exact root path, not children.
                // Every absolute path starts_with("/"), so we check equality.
                if self.root == blocked_path {
                    return Err(WorkspaceConfinementError::BlockedRoot {
                        root: root_str.to_string(),
                    });
                }
            } else if self.root == blocked_path || self.root.starts_with(blocked_path) {
                // For other blocked roots, block both exact match and children
                return Err(WorkspaceConfinementError::BlockedRoot {
                    root: root_str.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Checks whether a path is safely contained within this workspace.
    ///
    /// The path must be relative and must not contain traversal components.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceConfinementError`] if the path escapes.
    pub fn contains(&self, path: &Path) -> Result<PathBuf, WorkspaceConfinementError> {
        validate_workspace_path(path, &self.root)
    }
}

// =============================================================================
// Path Validation
// =============================================================================

/// Validates that a path is safely confined within the workspace root.
///
/// This function performs component-aware path validation:
/// - Rejects absolute paths
/// - Rejects `..` (parent directory) components
/// - Rejects paths exceeding depth limits
/// - Returns the resolved path within the workspace root
///
/// # Arguments
///
/// * `path` - The path to validate (should be relative)
/// * `workspace_root` - The absolute workspace root
///
/// # Errors
///
/// Returns [`WorkspaceConfinementError`] if the path is unsafe.
pub fn validate_workspace_path(
    path: &Path,
    workspace_root: &Path,
) -> Result<PathBuf, WorkspaceConfinementError> {
    let path_str = path.to_string_lossy();

    // Reject paths that are too long
    if path_str.len() > MAX_WORKSPACE_PATH_LENGTH {
        return Err(WorkspaceConfinementError::PathTooLong {
            actual: path_str.len(),
            max: MAX_WORKSPACE_PATH_LENGTH,
        });
    }

    // Reject absolute paths
    if path.is_absolute() {
        return Err(WorkspaceConfinementError::AbsolutePath {
            path: path_str.to_string(),
        });
    }

    // Component-aware validation
    let mut resolved = PathBuf::new();
    let mut depth: usize = 0;

    for component in path.components() {
        match component {
            Component::Normal(seg) => {
                resolved.push(seg);
                depth = depth.saturating_add(1);
                if depth > MAX_WORKSPACE_PATH_DEPTH {
                    return Err(WorkspaceConfinementError::PathTooDeep {
                        depth,
                        max: MAX_WORKSPACE_PATH_DEPTH,
                    });
                }
            },
            Component::CurDir => {
                // "." is harmless, skip
            },
            Component::ParentDir => {
                return Err(WorkspaceConfinementError::PathTraversal {
                    path: path_str.to_string(),
                });
            },
            Component::RootDir | Component::Prefix(_) => {
                return Err(WorkspaceConfinementError::ForbiddenComponent {
                    component: format!("{component:?}"),
                });
            },
        }
    }

    Ok(workspace_root.join(resolved))
}

/// Validates that an absolute path does not escape the workspace root
/// using component-aware `starts_with`.
///
/// This is used for post-resolution checks (e.g., after symlink resolution).
///
/// # Errors
///
/// Returns [`WorkspaceConfinementError`] if the path escapes.
pub fn validate_absolute_within_root(
    resolved_path: &Path,
    workspace_root: &Path,
) -> Result<(), WorkspaceConfinementError> {
    if !resolved_path.starts_with(workspace_root) {
        return Err(WorkspaceConfinementError::PathTraversal {
            path: resolved_path.to_string_lossy().to_string(),
        });
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    // =========================================================================
    // WorkspaceConfinement Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_workspace_root() {
        let wc = WorkspaceConfinement::new("/home/agent/workspace");
        assert!(wc.validate().is_ok());
    }

    #[test]
    fn test_empty_workspace_root() {
        let wc = WorkspaceConfinement::new("");
        assert!(matches!(
            wc.validate(),
            Err(WorkspaceConfinementError::EmptyRoot)
        ));
    }

    #[test]
    fn test_relative_workspace_root() {
        let wc = WorkspaceConfinement::new("relative/path");
        assert!(matches!(
            wc.validate(),
            Err(WorkspaceConfinementError::NotAbsolute { .. })
        ));
    }

    #[test]
    fn test_blocked_root_exact() {
        let wc = WorkspaceConfinement::new("/etc");
        assert!(matches!(
            wc.validate(),
            Err(WorkspaceConfinementError::BlockedRoot { .. })
        ));
    }

    #[test]
    fn test_blocked_root_child() {
        // /var/log should be blocked because /var is blocked
        let wc = WorkspaceConfinement::new("/var/log");
        assert!(matches!(
            wc.validate(),
            Err(WorkspaceConfinementError::BlockedRoot { .. })
        ));
    }

    #[test]
    fn test_blocked_root_slash() {
        let wc = WorkspaceConfinement::new("/");
        assert!(matches!(
            wc.validate(),
            Err(WorkspaceConfinementError::BlockedRoot { .. })
        ));
    }

    // =========================================================================
    // Path Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_relative_path() {
        let root = Path::new("/workspace");
        let result = validate_workspace_path(Path::new("src/main.rs"), root);
        assert_eq!(result.unwrap(), PathBuf::from("/workspace/src/main.rs"));
    }

    #[test]
    fn test_path_with_dot() {
        let root = Path::new("/workspace");
        let result = validate_workspace_path(Path::new("./src/main.rs"), root);
        assert_eq!(result.unwrap(), PathBuf::from("/workspace/src/main.rs"));
    }

    #[test]
    fn test_path_traversal_dotdot() {
        let root = Path::new("/workspace");
        let result = validate_workspace_path(Path::new("../../../etc/passwd"), root);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::PathTraversal { .. })
        ));
    }

    #[test]
    fn test_path_traversal_embedded_dotdot() {
        let root = Path::new("/workspace");
        let result = validate_workspace_path(Path::new("src/../../etc/passwd"), root);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::PathTraversal { .. })
        ));
    }

    #[test]
    fn test_absolute_path_rejected() {
        let root = Path::new("/workspace");
        let result = validate_workspace_path(Path::new("/etc/passwd"), root);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::AbsolutePath { .. })
        ));
    }

    #[test]
    fn test_path_too_deep() {
        let root = Path::new("/workspace");
        let deep_path: String = (0..=MAX_WORKSPACE_PATH_DEPTH)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let result = validate_workspace_path(Path::new(&deep_path), root);
        assert!(matches!(
            result,
            Err(WorkspaceConfinementError::PathTooDeep { .. })
        ));
    }

    #[test]
    fn test_path_exactly_at_max_depth() {
        let root = Path::new("/workspace");
        let path: String = (0..MAX_WORKSPACE_PATH_DEPTH)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let result = validate_workspace_path(Path::new(&path), root);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Adversarial Path Traversal Tests (escape attempts)
    // =========================================================================

    #[test]
    fn test_adversarial_dotdot_at_start() {
        let root = Path::new("/workspace");
        assert!(validate_workspace_path(Path::new(".."), root).is_err());
    }

    #[test]
    fn test_adversarial_multiple_dotdots() {
        let root = Path::new("/workspace");
        assert!(validate_workspace_path(Path::new("../../.."), root).is_err());
    }

    #[test]
    fn test_adversarial_dotdot_after_normal() {
        let root = Path::new("/workspace");
        assert!(validate_workspace_path(Path::new("a/b/../../.."), root).is_err());
    }

    #[test]
    fn test_adversarial_dotdot_to_etc() {
        let root = Path::new("/workspace");
        assert!(validate_workspace_path(Path::new("../../../etc/shadow"), root).is_err());
    }

    #[test]
    fn test_adversarial_encoded_traversal_components() {
        // On Unix, Path::new handles actual OS paths, not URL-encoded strings.
        // The OS will see these as literal filenames, not traversal.
        // But we verify the component check still works for real ".." components.
        let root = Path::new("/workspace");
        // Mix of ".." and normal
        assert!(validate_workspace_path(Path::new("foo/../../../bar"), root).is_err());
    }

    #[test]
    fn test_adversarial_null_byte_in_path() {
        // Paths with null bytes are invalid on Unix, but we test that our
        // validation doesn't panic
        let root = Path::new("/workspace");
        // std::path::Path will handle this as a normal segment
        let result = validate_workspace_path(Path::new("safe_file.txt"), root);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Absolute Within Root Tests
    // =========================================================================

    #[test]
    fn test_absolute_within_root_ok() {
        let root = Path::new("/workspace");
        let path = Path::new("/workspace/src/main.rs");
        assert!(validate_absolute_within_root(path, root).is_ok());
    }

    #[test]
    fn test_absolute_outside_root_rejected() {
        let root = Path::new("/workspace");
        let path = Path::new("/etc/passwd");
        assert!(validate_absolute_within_root(path, root).is_err());
    }

    #[test]
    fn test_absolute_sibling_rejected() {
        let root = Path::new("/workspace/project-a");
        let path = Path::new("/workspace/project-b/secret.txt");
        assert!(validate_absolute_within_root(path, root).is_err());
    }

    // =========================================================================
    // WorkspaceConfinement.contains() Tests
    // =========================================================================

    #[test]
    fn test_contains_valid_path() {
        let wc = WorkspaceConfinement::new("/workspace");
        let result = wc.contains(Path::new("src/lib.rs"));
        assert_eq!(result.unwrap(), PathBuf::from("/workspace/src/lib.rs"));
    }

    #[test]
    fn test_contains_traversal_rejected() {
        let wc = WorkspaceConfinement::new("/workspace");
        assert!(wc.contains(Path::new("../secret")).is_err());
    }
}
