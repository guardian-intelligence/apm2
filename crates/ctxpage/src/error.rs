use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidInputStream,
    InputLimitExceeded,
    UnsupportedVersion,
    PackDigestMismatch,
    ChainMismatch,
    StreamEndMissing,
    InvalidCursor,
    CursorBudgetMismatch,
    BudgetTooSmall,
    Io,
    Serialization,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInputStream => "INVALID_INPUT_STREAM",
            Self::InputLimitExceeded => "INPUT_LIMIT_EXCEEDED",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::PackDigestMismatch => "PACK_DIGEST_MISMATCH",
            Self::ChainMismatch => "CHAIN_MISMATCH",
            Self::StreamEndMissing => "STREAM_END_MISSING",
            Self::InvalidCursor => "INVALID_CURSOR",
            Self::CursorBudgetMismatch => "CURSOR_BUDGET_MISMATCH",
            Self::BudgetTooSmall => "BUDGET_TOO_SMALL",
            Self::Io => "IO",
            Self::Serialization => "SERIALIZATION",
            Self::Internal => "INTERNAL",
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{message}")]
    InvalidInputStream { message: String },

    #[error("input limit exceeded: {message}")]
    InputLimitExceeded { message: String },

    #[error("unsupported protocol version: expected {expected}, got {actual}")]
    UnsupportedVersion { expected: u8, actual: u8 },

    #[error("input contains mixed pack digests")]
    PackDigestMismatch,

    #[error("chain integrity mismatch: {message}")]
    ChainMismatch { message: String },

    #[error("stream_end record is required but missing")]
    StreamEndMissing,

    #[error("invalid cursor: {message}")]
    InvalidCursor { message: String },

    #[error("cursor budget fingerprint does not match current paginator config")]
    CursorBudgetMismatch,

    #[error("budget too small to emit any segment")]
    BudgetTooSmall,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidInputStream { .. } => ErrorCode::InvalidInputStream,
            Self::InputLimitExceeded { .. } => ErrorCode::InputLimitExceeded,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
            Self::PackDigestMismatch => ErrorCode::PackDigestMismatch,
            Self::ChainMismatch { .. } => ErrorCode::ChainMismatch,
            Self::StreamEndMissing => ErrorCode::StreamEndMissing,
            Self::InvalidCursor { .. } => ErrorCode::InvalidCursor,
            Self::CursorBudgetMismatch => ErrorCode::CursorBudgetMismatch,
            Self::BudgetTooSmall => ErrorCode::BudgetTooSmall,
            Self::Io(_) => ErrorCode::Io,
            Self::Serialization(_) => ErrorCode::Serialization,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}
