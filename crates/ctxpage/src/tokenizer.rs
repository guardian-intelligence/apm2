use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::error::Error;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TokenizerMode {
    #[default]
    BytesDiv4,
    Utf8CharHeuristic,
    FixedRatio {
        bytes_per_token: u32,
    },
}

impl TokenizerMode {
    #[must_use]
    pub fn estimate_tokens(self, bytes: &[u8]) -> u64 {
        match self {
            Self::BytesDiv4 => {
                let bytes_u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                bytes_u64.saturating_add(3) / 4
            },
            Self::Utf8CharHeuristic => {
                let units =
                    std::str::from_utf8(bytes).map_or(bytes.len(), |text| text.chars().count());
                let units_u64 = u64::try_from(units).unwrap_or(u64::MAX);
                units_u64.saturating_add(3) / 4
            },
            Self::FixedRatio { bytes_per_token } => {
                let ratio_u64 = u64::from(bytes_per_token.max(1));
                let bytes_u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                bytes_u64.saturating_add(ratio_u64.saturating_sub(1)) / ratio_u64
            },
        }
    }

    #[must_use]
    pub fn max_bytes_for_tokens(self, tokens: u64) -> u64 {
        match self {
            Self::BytesDiv4 | Self::Utf8CharHeuristic => tokens.saturating_mul(4),
            Self::FixedRatio { bytes_per_token } => {
                tokens.saturating_mul(u64::from(bytes_per_token.max(1)))
            },
        }
    }
}

impl Display for TokenizerMode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BytesDiv4 => formatter.write_str("bytes_div_4"),
            Self::Utf8CharHeuristic => formatter.write_str("utf8_char_heuristic"),
            Self::FixedRatio { bytes_per_token } => {
                write!(formatter, "fixed_ratio:{bytes_per_token}")
            },
        }
    }
}

impl FromStr for TokenizerMode {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "bytes_div_4" => Ok(Self::BytesDiv4),
            "utf8_char_heuristic" => Ok(Self::Utf8CharHeuristic),
            _ => {
                if let Some(rest) = input.strip_prefix("fixed_ratio:") {
                    let bytes_per_token =
                        rest.parse::<u32>().map_err(|_| Error::InvalidInputStream {
                            message: format!("invalid tokenizer mode '{input}'"),
                        })?;
                    if bytes_per_token == 0 {
                        return Err(Error::InvalidInputStream {
                            message: "fixed_ratio bytes_per_token must be greater than zero"
                                .to_string(),
                        });
                    }
                    return Ok(Self::FixedRatio { bytes_per_token });
                }
                Err(Error::InvalidInputStream {
                    message: format!("invalid tokenizer mode '{input}'"),
                })
            },
        }
    }
}
