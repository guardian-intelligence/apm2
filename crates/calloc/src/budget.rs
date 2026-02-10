use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Context allocation budget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Maximum total bytes allowed in a single pack.
    pub max_bytes: u64,
    /// Optional token budget.
    ///
    /// Phase 0/1 reports token usage but does not enforce this limit.
    #[serde(default)]
    pub max_tokens: Option<u64>,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_bytes: 524_288,
            max_tokens: Some(150_000),
        }
    }
}

impl Budget {
    /// Validates budget shape.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_bytes == 0 {
            return Err(Error::ManifestValidation(
                "budget.max_bytes must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}
