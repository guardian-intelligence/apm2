use std::sync::Arc;

use serde::Serialize;

use crate::error::Error;
use crate::tokenizer::TokenizerMode;

pub const WIRE_VERSION: u8 = 1;
pub const BLOCK_CHAIN_DOMAIN_V1: &[u8] = b"ctxpage:block_chain:v1\n";
pub const ZERO_CHAIN: [u8; 32] = [0; 32];

#[derive(Debug, Clone)]
pub struct Block {
    pub pack_digest: [u8; 32],
    pub block_index: u32,
    pub path: String,
    pub block_digest: [u8; 32],
    pub bytes: Arc<[u8]>,
    pub token_estimate: u64,
    pub chain_prev: [u8; 32],
    pub chain_curr: [u8; 32],
}

impl Block {
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct PageBudget {
    pub max_bytes: u64,
    pub max_tokens_estimate: Option<u64>,
    pub max_segments: u32,
}

impl PageBudget {
    pub fn validate(self) -> Result<(), Error> {
        if self.max_bytes == 0 {
            return Err(Error::InvalidInputStream {
                message: "max_bytes must be greater than zero".to_string(),
            });
        }
        if self.max_segments == 0 {
            return Err(Error::InvalidInputStream {
                message: "max_segments must be greater than zero".to_string(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn fingerprint(self, tokenizer: TokenizerMode) -> String {
        let max_tokens = self
            .max_tokens_estimate
            .map_or_else(|| "none".to_string(), |value| value.to_string());
        let material = format!(
            "ctxpage:budget:v1|max_bytes={}|max_tokens={}|max_segments={}|tokenizer={}",
            self.max_bytes, max_tokens, self.max_segments, tokenizer
        );
        blake3::hash(material.as_bytes()).to_hex().to_string()
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    MaxBytes,
    MaxTokensEstimate,
    MaxSegments,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Segment {
    pub block_index: u32,
    pub path: String,
    pub block_digest: String,
    pub range_start: u64,
    pub range_end_exclusive: u64,
    pub content_b64: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct PageUsage {
    pub bytes: u64,
    pub tokens_estimate: u64,
    pub segments: u32,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct PageBudgetReport {
    pub max_bytes: u64,
    pub max_tokens_estimate: Option<u64>,
    pub max_segments: u32,
}

impl From<PageBudget> for PageBudgetReport {
    fn from(value: PageBudget) -> Self {
        Self {
            max_bytes: value.max_bytes,
            max_tokens_estimate: value.max_tokens_estimate,
            max_segments: value.max_segments,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Page {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub pack_digest: String,
    pub page_index: u32,
    pub cursor_in: Option<String>,
    pub cursor_out: Option<String>,
    pub budget: PageBudgetReport,
    pub usage: PageUsage,
    pub segments: Vec<Segment>,
    pub truncated: bool,
    pub truncation_reason: Option<TruncationReason>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InspectReport {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub pack_digest: String,
    pub total_blocks: usize,
    pub total_bytes: u64,
    pub total_tokens_estimate: u64,
    pub projected_pages: usize,
    pub budget: PageBudgetReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEnd {
    pub pack_digest: [u8; 32],
    pub total_blocks: u32,
    pub total_bytes: u64,
    pub final_chain: [u8; 32],
}

#[derive(Debug, Clone)]
pub enum WireEvent {
    Block(Block),
    StreamEnd(StreamEnd),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadLimits {
    pub max_input_bytes: Option<u64>,
    pub max_line_bytes: Option<usize>,
    pub max_decoded_block_bytes: Option<u64>,
}

impl ReadLimits {
    #[must_use]
    pub const fn bounded_default() -> Self {
        Self {
            max_input_bytes: Some(512 * 1024 * 1024),
            max_line_bytes: Some(16 * 1024 * 1024),
            max_decoded_block_bytes: Some(16 * 1024 * 1024),
        }
    }
}

pub fn parse_digest(input: &str, field_name: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(input).map_err(|_| Error::InvalidInputStream {
        message: format!("{field_name} must be a valid 64-character hex digest"),
    })?;
    let Ok(digest) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return Err(Error::InvalidInputStream {
            message: format!("{field_name} must be exactly 32 bytes"),
        });
    };
    Ok(digest)
}
