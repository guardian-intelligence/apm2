use std::path::PathBuf;

use thiserror::Error;

/// Error surface for calloc operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Generic I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// I/O failure with source path context.
    #[error("I/O error at '{path}': {source}")]
    IoAtPath {
        /// Path associated with the failure.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Manifest parse failure.
    #[error("manifest parse failed: {0}")]
    ManifestParse(String),

    /// Manifest validation failure.
    #[error("manifest validation failed: {0}")]
    ManifestValidation(String),

    /// Invalid glob pattern in manifest rules.
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        /// Invalid pattern.
        pattern: String,
        /// Parser error.
        #[source]
        source: glob::PatternError,
    },

    /// No files matched include rules.
    #[error("no files matched include rules")]
    NoMatchingFiles,

    /// Allocation exceeds configured byte budget.
    #[error("budget exceeded: max_bytes={max_bytes}, actual_bytes={actual_bytes}")]
    BudgetExceeded {
        /// Maximum allowed bytes.
        max_bytes: u64,
        /// Actual bytes selected.
        actual_bytes: u64,
    },

    /// Unknown allocation handle.
    #[error("allocation handle {id} is unknown")]
    UnknownAllocationHandle {
        /// Handle identifier.
        id: u64,
    },

    /// Allocation handle and stored digest mismatch.
    #[error("allocation handle {id} does not match active pack digest")]
    AllocationHandleDigestMismatch {
        /// Handle identifier.
        id: u64,
    },

    /// Rendering failure.
    #[error("rendering failed: {0}")]
    Render(String),

    /// Pagination operation failure.
    #[error("pagination failed: {0}")]
    Pagination(String),
}

impl Error {
    /// Creates an [`Error::IoAtPath`] helper.
    #[must_use]
    pub fn io_at_path(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::IoAtPath {
            path: path.into(),
            source,
        }
    }
}

impl From<ctxpage::Error> for Error {
    fn from(source: ctxpage::Error) -> Self {
        Self::Pagination(source.to_string())
    }
}
