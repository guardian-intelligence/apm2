use std::io::{BufRead, Write};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::model::{
    BLOCK_CHAIN_DOMAIN_V1, Block, ReadLimits, StreamEnd, WIRE_VERSION, WireEvent, ZERO_CHAIN,
    parse_digest,
};

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WireRecord {
    #[serde(rename = "block")]
    Block(BlockRecord),
    #[serde(rename = "stream_end")]
    StreamEnd(StreamEndRecord),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockRecord {
    v: u8,
    pack_digest: String,
    block_index: u32,
    path: String,
    block_digest: String,
    byte_len: u64,
    token_estimate: u64,
    content_b64: String,
    chain_prev: String,
    chain_curr: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamEndRecord {
    v: u8,
    pack_digest: String,
    total_blocks: u32,
    total_bytes: u64,
    final_chain: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockRecordCanonical<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    pack_digest: &'a str,
    block_index: u32,
    path: &'a str,
    block_digest: &'a str,
    byte_len: u64,
    token_estimate: u64,
    content_b64: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockRecordOutput<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    pack_digest: &'a str,
    block_index: u32,
    path: &'a str,
    block_digest: &'a str,
    byte_len: u64,
    token_estimate: u64,
    content_b64: &'a str,
    chain_prev: String,
    chain_curr: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct StreamEndRecordOutput<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    pack_digest: &'a str,
    total_blocks: u32,
    total_bytes: u64,
    final_chain: String,
}

pub struct WireEventStream<R: BufRead> {
    reader: R,
    limits: ReadLimits,
    total_input_bytes: u64,
    line_number: usize,
    line: String,
    done: bool,
}

impl<R: BufRead> Iterator for WireEventStream<R> {
    type Item = Result<WireEvent, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        loop {
            self.line.clear();
            let bytes_read = match self.reader.read_line(&mut self.line) {
                Ok(value) => value,
                Err(source) => {
                    self.done = true;
                    return Some(Err(Error::Io(source)));
                },
            };

            if bytes_read == 0 {
                self.done = true;
                return None;
            }

            self.line_number = self.line_number.saturating_add(1);
            let bytes_read_u64 = u64::try_from(bytes_read).unwrap_or(u64::MAX);
            self.total_input_bytes = self.total_input_bytes.saturating_add(bytes_read_u64);

            if let Some(limit) = self.limits.max_input_bytes {
                if self.total_input_bytes > limit {
                    self.done = true;
                    return Some(Err(Error::InputLimitExceeded {
                        message: format!(
                            "input exceeded max_input_bytes limit ({} > {})",
                            self.total_input_bytes, limit
                        ),
                    }));
                }
            }
            if let Some(limit) = self.limits.max_line_bytes {
                if bytes_read > limit {
                    self.done = true;
                    return Some(Err(Error::InputLimitExceeded {
                        message: format!(
                            "line {} exceeded max_line_bytes limit ({} > {})",
                            self.line_number, bytes_read, limit
                        ),
                    }));
                }
            }

            if self.line.trim().is_empty() {
                continue;
            }

            let record = match serde_json::from_str::<WireRecord>(&self.line) {
                Ok(value) => value,
                Err(source) => {
                    self.done = true;
                    return Some(Err(Error::InvalidInputStream {
                        message: format!(
                            "line {} is not valid record JSON: {source}",
                            self.line_number
                        ),
                    }));
                },
            };

            let event = match record {
                WireRecord::Block(record) => parse_block_record(record, self.limits),
                WireRecord::StreamEnd(record) => parse_stream_end_record(&record),
            };
            if event.is_err() {
                self.done = true;
            }
            return Some(event);
        }
    }
}

pub const fn read_blocks_jsonl_stream<R: BufRead>(
    reader: R,
    limits: ReadLimits,
) -> WireEventStream<R> {
    WireEventStream {
        reader,
        limits,
        total_input_bytes: 0,
        line_number: 0,
        line: String::new(),
        done: false,
    }
}

pub fn read_blocks_jsonl(reader: impl BufRead) -> Result<Vec<Block>, Error> {
    read_blocks_jsonl_with_limits(reader, ReadLimits::default(), true)
}

pub fn read_blocks_jsonl_with_limits(
    reader: impl BufRead,
    limits: ReadLimits,
    require_stream_end: bool,
) -> Result<Vec<Block>, Error> {
    let mut blocks = Vec::new();
    let mut expected_pack_digest = None::<[u8; 32]>;
    let mut expected_next_index = 0_u32;
    let mut total_bytes = 0_u64;
    let mut chain = ZERO_CHAIN;
    let mut saw_stream_end = false;

    for event in read_blocks_jsonl_stream(reader, limits) {
        match event? {
            WireEvent::Block(block) => {
                validate_block(
                    &block,
                    expected_pack_digest,
                    expected_next_index,
                    chain,
                    "read_blocks_jsonl_with_limits",
                )?;
                total_bytes = total_bytes
                    .saturating_add(u64::try_from(block.bytes.len()).unwrap_or(u64::MAX));
                chain = block.chain_curr;
                expected_pack_digest.get_or_insert(block.pack_digest);
                expected_next_index = expected_next_index.saturating_add(1);
                blocks.push(block);
            },
            WireEvent::StreamEnd(stream_end) => {
                if saw_stream_end {
                    return Err(Error::InvalidInputStream {
                        message: "multiple stream_end records encountered".to_string(),
                    });
                }
                validate_stream_end(
                    stream_end,
                    expected_pack_digest,
                    expected_next_index,
                    total_bytes,
                    chain,
                )?;
                saw_stream_end = true;
            },
        }
    }

    if require_stream_end && !saw_stream_end {
        return Err(Error::StreamEndMissing);
    }

    Ok(blocks)
}

pub fn write_blocks_jsonl(mut writer: impl Write, blocks: &[Block]) -> Result<(), Error> {
    let mut expected_pack_digest = None::<[u8; 32]>;
    let mut expected_next_index = 0_u32;
    let mut total_bytes = 0_u64;
    let mut chain = ZERO_CHAIN;

    for block in blocks {
        validate_block(
            block,
            expected_pack_digest,
            expected_next_index,
            chain,
            "write_blocks_jsonl",
        )?;
        expected_pack_digest.get_or_insert(block.pack_digest);
        expected_next_index = expected_next_index.saturating_add(1);
        total_bytes =
            total_bytes.saturating_add(u64::try_from(block.bytes.len()).unwrap_or(u64::MAX));
        chain = block.chain_curr;

        let content_b64 = STANDARD.encode(&block.bytes);
        let pack_digest = hex::encode(block.pack_digest);
        let block_digest = hex::encode(block.block_digest);
        let record = BlockRecordOutput {
            v: WIRE_VERSION,
            kind: "block",
            pack_digest: &pack_digest,
            block_index: block.block_index,
            path: &block.path,
            block_digest: &block_digest,
            byte_len: u64::try_from(block.bytes.len()).unwrap_or(u64::MAX),
            token_estimate: block.token_estimate,
            content_b64: &content_b64,
            chain_prev: hex::encode(block.chain_prev),
            chain_curr: hex::encode(block.chain_curr),
        };
        serde_json::to_writer(&mut writer, &record)?;
        writer.write_all(b"\n")?;
    }

    let pack_digest = hex::encode(expected_pack_digest.unwrap_or([0; 32]));
    let stream_end = StreamEndRecordOutput {
        v: WIRE_VERSION,
        kind: "stream_end",
        pack_digest: &pack_digest,
        total_blocks: expected_next_index,
        total_bytes,
        final_chain: hex::encode(chain),
    };
    serde_json::to_writer(&mut writer, &stream_end)?;
    writer.write_all(b"\n")?;
    Ok(())
}

pub fn compute_block_chain_curr(block: &Block) -> Result<[u8; 32], Error> {
    let canonical = canonical_block_json_bytes(block)?;
    Ok(compute_chain_curr(block.chain_prev, &canonical))
}

fn parse_block_record(record: BlockRecord, limits: ReadLimits) -> Result<WireEvent, Error> {
    if record.v != WIRE_VERSION {
        return Err(Error::UnsupportedVersion {
            expected: WIRE_VERSION,
            actual: record.v,
        });
    }

    let bytes = STANDARD
        .decode(record.content_b64.as_bytes())
        .map_err(|source| Error::InvalidInputStream {
            message: format!(
                "invalid base64 content for block {}: {source}",
                record.block_index
            ),
        })?;

    if let Some(limit) = limits.max_decoded_block_bytes {
        let decoded_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if decoded_size > limit {
            return Err(Error::InputLimitExceeded {
                message: format!(
                    "block {} exceeded max_decoded_block_bytes limit ({} > {})",
                    record.block_index, decoded_size, limit
                ),
            });
        }
    }

    let canonical_base64 = STANDARD.encode(&bytes);
    if canonical_base64 != record.content_b64 {
        return Err(Error::InvalidInputStream {
            message: format!(
                "block {} content_b64 is non-canonical; expected standard base64 encoding",
                record.block_index
            ),
        });
    }

    let decoded_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if decoded_len != record.byte_len {
        return Err(Error::InvalidInputStream {
            message: format!(
                "block {} byte_len mismatch: expected {}, decoded {}",
                record.block_index, record.byte_len, decoded_len
            ),
        });
    }

    let block_digest = parse_digest(&record.block_digest, "block_digest")?;
    let computed_digest = *blake3::hash(&bytes).as_bytes();
    if computed_digest != block_digest {
        return Err(Error::InvalidInputStream {
            message: format!("block {} digest mismatch", record.block_index),
        });
    }

    Ok(WireEvent::Block(Block {
        pack_digest: parse_digest(&record.pack_digest, "pack_digest")?,
        block_index: record.block_index,
        path: record.path,
        block_digest,
        bytes: Arc::from(bytes.into_boxed_slice()),
        token_estimate: record.token_estimate,
        chain_prev: parse_digest(&record.chain_prev, "chain_prev")?,
        chain_curr: parse_digest(&record.chain_curr, "chain_curr")?,
    }))
}

fn parse_stream_end_record(record: &StreamEndRecord) -> Result<WireEvent, Error> {
    if record.v != WIRE_VERSION {
        return Err(Error::UnsupportedVersion {
            expected: WIRE_VERSION,
            actual: record.v,
        });
    }

    Ok(WireEvent::StreamEnd(StreamEnd {
        pack_digest: parse_digest(&record.pack_digest, "pack_digest")?,
        total_blocks: record.total_blocks,
        total_bytes: record.total_bytes,
        final_chain: parse_digest(&record.final_chain, "final_chain")?,
    }))
}

fn validate_block(
    block: &Block,
    expected_pack_digest: Option<[u8; 32]>,
    expected_next_index: u32,
    expected_chain_prev: [u8; 32],
    context: &str,
) -> Result<(), Error> {
    if let Some(pack_digest) = expected_pack_digest {
        if block.pack_digest != pack_digest {
            return Err(Error::PackDigestMismatch);
        }
    }
    if block.block_index != expected_next_index {
        return Err(Error::InvalidInputStream {
            message: format!(
                "{context}: expected block_index {}, got {}",
                expected_next_index, block.block_index
            ),
        });
    }
    if block.chain_prev != expected_chain_prev {
        return Err(Error::ChainMismatch {
            message: format!(
                "{context}: block {} chain_prev did not match previous chain",
                block.block_index
            ),
        });
    }
    let computed_chain = compute_block_chain_curr(block)?;
    if computed_chain != block.chain_curr {
        return Err(Error::ChainMismatch {
            message: format!(
                "{context}: block {} chain_curr did not match computed chain",
                block.block_index
            ),
        });
    }
    Ok(())
}

fn validate_stream_end(
    stream_end: StreamEnd,
    expected_pack_digest: Option<[u8; 32]>,
    expected_blocks: u32,
    expected_total_bytes: u64,
    expected_final_chain: [u8; 32],
) -> Result<(), Error> {
    if let Some(pack_digest) = expected_pack_digest {
        if stream_end.pack_digest != pack_digest {
            return Err(Error::PackDigestMismatch);
        }
    }
    if stream_end.total_blocks != expected_blocks {
        return Err(Error::InvalidInputStream {
            message: format!(
                "stream_end total_blocks mismatch: expected {}, got {}",
                expected_blocks, stream_end.total_blocks
            ),
        });
    }
    if stream_end.total_bytes != expected_total_bytes {
        return Err(Error::InvalidInputStream {
            message: format!(
                "stream_end total_bytes mismatch: expected {}, got {}",
                expected_total_bytes, stream_end.total_bytes
            ),
        });
    }
    if stream_end.final_chain != expected_final_chain {
        return Err(Error::ChainMismatch {
            message: "stream_end final_chain did not match computed chain".to_string(),
        });
    }
    Ok(())
}

fn canonical_block_json_bytes(block: &Block) -> Result<Vec<u8>, Error> {
    let content_b64 = STANDARD.encode(&block.bytes);
    let pack_digest = hex::encode(block.pack_digest);
    let block_digest = hex::encode(block.block_digest);
    let canonical = BlockRecordCanonical {
        v: WIRE_VERSION,
        kind: "block",
        pack_digest: &pack_digest,
        block_index: block.block_index,
        path: &block.path,
        block_digest: &block_digest,
        byte_len: u64::try_from(block.bytes.len()).unwrap_or(u64::MAX),
        token_estimate: block.token_estimate,
        content_b64: &content_b64,
    };
    serde_json::to_vec(&canonical).map_err(Error::from)
}

fn compute_chain_curr(chain_prev: [u8; 32], canonical_block_json_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BLOCK_CHAIN_DOMAIN_V1);
    hasher.update(&chain_prev);
    hasher.update(canonical_block_json_bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use super::{read_blocks_jsonl, read_blocks_jsonl_with_limits, write_blocks_jsonl};
    use crate::model::{Block, ReadLimits, ZERO_CHAIN};

    #[test]
    fn blocks_round_trip_with_stream_end() {
        let block = Block {
            pack_digest: [1; 32],
            block_index: 0,
            path: "README.md".to_string(),
            block_digest: *blake3::hash(b"hello\n").as_bytes(),
            bytes: Arc::from(b"hello\n".to_vec().into_boxed_slice()),
            token_estimate: 2,
            chain_prev: ZERO_CHAIN,
            chain_curr: [0; 32], // overwritten below
        };
        let mut blocks = vec![block];
        blocks[0].chain_curr = super::compute_block_chain_curr(&blocks[0]).expect("compute chain");

        let mut out = Vec::new();
        write_blocks_jsonl(&mut out, &blocks).expect("serialize");
        let parsed = read_blocks_jsonl(Cursor::new(out)).expect("parse");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pack_digest, [1; 32]);
        assert_eq!(parsed[0].path, "README.md");
        assert_eq!(&*parsed[0].bytes, b"hello\n");
    }

    #[test]
    fn security_rejects_block_digest_tampering() {
        let block = Block {
            pack_digest: [7; 32],
            block_index: 0,
            path: "README.md".to_string(),
            block_digest: *blake3::hash(b"hello\n").as_bytes(),
            bytes: Arc::from(b"hello\n".to_vec().into_boxed_slice()),
            token_estimate: 2,
            chain_prev: ZERO_CHAIN,
            chain_curr: [0; 32],
        };
        let mut blocks = vec![block];
        blocks[0].chain_curr = super::compute_block_chain_curr(&blocks[0]).expect("compute chain");

        let mut out = Vec::new();
        write_blocks_jsonl(&mut out, &blocks).expect("serialize");

        let mut lines = String::from_utf8(out)
            .expect("utf8")
            .lines()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut block_record =
            serde_json::from_str::<serde_json::Value>(lines.first().expect("block line"))
                .expect("json");
        block_record["block_digest"] = serde_json::Value::String("0".repeat(64));
        lines[0] = serde_json::to_string(&block_record).expect("serialize tampered block");
        let tampered = format!("{}\n{}\n", lines[0], lines[1]);

        let error = read_blocks_jsonl(Cursor::new(tampered.into_bytes())).expect_err("tampered");
        assert_eq!(error.code().as_str(), "INVALID_INPUT_STREAM");
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn security_enforces_line_length_limit() {
        let block = Block {
            pack_digest: [3; 32],
            block_index: 0,
            path: "README.md".to_string(),
            block_digest: *blake3::hash(b"hello\n").as_bytes(),
            bytes: Arc::from(b"hello\n".to_vec().into_boxed_slice()),
            token_estimate: 2,
            chain_prev: ZERO_CHAIN,
            chain_curr: [0; 32],
        };
        let mut blocks = vec![block];
        blocks[0].chain_curr = super::compute_block_chain_curr(&blocks[0]).expect("compute chain");

        let mut out = Vec::new();
        write_blocks_jsonl(&mut out, &blocks).expect("serialize");

        let limits = ReadLimits {
            max_input_bytes: None,
            max_line_bytes: Some(32),
            max_decoded_block_bytes: None,
        };
        let error = read_blocks_jsonl_with_limits(Cursor::new(out), limits, true)
            .expect_err("line should exceed limit");
        assert_eq!(error.code().as_str(), "INPUT_LIMIT_EXCEEDED");
    }
}
