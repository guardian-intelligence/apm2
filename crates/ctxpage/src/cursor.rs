use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::model::WIRE_VERSION;

pub const CURSOR_ALGO_V1: &str = "greedy-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CursorV1 {
    pub v: u8,
    pub pack_digest: String,
    pub next_block_index: u32,
    pub next_offset: u64,
    pub next_page_index: u32,
    pub algo: String,
    pub budget_fingerprint: String,
    pub expected_chain_at_resume: String,
}

pub fn encode_cursor(cursor: &CursorV1) -> Result<String, Error> {
    let bytes = serde_json::to_vec(cursor).map_err(|source| Error::InvalidCursor {
        message: format!("failed to serialize cursor: {source}"),
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode_cursor(input: &str) -> Result<CursorV1, Error> {
    let raw = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|source| Error::InvalidCursor {
            message: format!("cursor is not valid base64url: {source}"),
        })?;
    let cursor =
        serde_json::from_slice::<CursorV1>(&raw).map_err(|source| Error::InvalidCursor {
            message: format!("cursor JSON parse failed: {source}"),
        })?;
    if cursor.v != WIRE_VERSION {
        return Err(Error::UnsupportedVersion {
            expected: WIRE_VERSION,
            actual: cursor.v,
        });
    }
    if cursor.algo != CURSOR_ALGO_V1 {
        return Err(Error::InvalidCursor {
            message: format!("unsupported cursor algorithm '{}'", cursor.algo),
        });
    }
    Ok(cursor)
}
