use std::io::BufRead;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::cursor::{CURSOR_ALGO_V1, CursorV1, decode_cursor, encode_cursor};
use crate::error::Error;
use crate::io::{compute_block_chain_curr, read_blocks_jsonl_stream};
use crate::model::{
    Block, Page, PageBudget, PageBudgetReport, PageUsage, ReadLimits, Segment, StreamEnd,
    TruncationReason, WIRE_VERSION, WireEvent, ZERO_CHAIN, parse_digest,
};
use crate::tokenizer::TokenizerMode;

#[derive(Debug, Clone)]
pub struct Paginator {
    budget: PageBudget,
    tokenizer: TokenizerMode,
    strict_cursor: bool,
}

impl Paginator {
    pub fn new(
        budget: PageBudget,
        tokenizer: TokenizerMode,
        strict_cursor: bool,
    ) -> Result<Self, Error> {
        budget.validate()?;
        Ok(Self {
            budget,
            tokenizer,
            strict_cursor,
        })
    }

    #[must_use]
    pub const fn budget(&self) -> PageBudget {
        self.budget
    }

    pub fn page_from_reader(
        &self,
        reader: impl BufRead,
        cursor_in: Option<&str>,
        limits: ReadLimits,
        require_stream_end: bool,
    ) -> Result<Page, Error> {
        self.page_from_events(
            read_blocks_jsonl_stream(reader, limits),
            cursor_in,
            require_stream_end,
        )
    }

    pub fn verify_cursor_from_reader(
        &self,
        reader: impl BufRead,
        cursor_input: &str,
        limits: ReadLimits,
        require_stream_end: bool,
    ) -> Result<CursorV1, Error> {
        let cursor = decode_cursor(cursor_input)?;
        self.validate_cursor_events(
            read_blocks_jsonl_stream(reader, limits),
            &cursor,
            require_stream_end,
        )?;
        Ok(cursor)
    }

    pub fn page_from_cursor(
        &self,
        blocks: &[Block],
        cursor_in: Option<&str>,
    ) -> Result<Page, Error> {
        self.page_from_events(synthetic_events(blocks), cursor_in, true)
    }

    pub fn stream_pages(&self, blocks: &[Block]) -> Result<Vec<Page>, Error> {
        let mut pages = Vec::new();
        let mut cursor = None::<String>;

        loop {
            let page = self.page_from_cursor(blocks, cursor.as_deref())?;
            let next = page.cursor_out.clone();
            pages.push(page);
            let Some(cursor_out) = next else {
                break;
            };
            if cursor.as_deref() == Some(cursor_out.as_str()) {
                return Err(Error::Internal(
                    "pagination generated a non-advancing cursor".to_string(),
                ));
            }
            cursor = Some(cursor_out);
        }
        Ok(pages)
    }

    pub fn verify_cursor(&self, blocks: &[Block], cursor_input: &str) -> Result<CursorV1, Error> {
        let cursor = decode_cursor(cursor_input)?;
        self.validate_cursor_events(synthetic_events(blocks), &cursor, true)?;
        Ok(cursor)
    }

    fn page_from_events<I>(
        &self,
        events: I,
        cursor_in: Option<&str>,
        require_stream_end: bool,
    ) -> Result<Page, Error>
    where
        I: IntoIterator<Item = Result<WireEvent, Error>>,
    {
        let expected_budget_fingerprint = self.budget.fingerprint(self.tokenizer);
        let cursor_state =
            CursorState::from_input(cursor_in, &expected_budget_fingerprint, self.strict_cursor)?;

        let mut expected_pack_digest = None::<[u8; 32]>;
        let mut chain = ZERO_CHAIN;
        let mut seen_blocks = 0_u32;
        let mut seen_total_bytes = 0_u64;
        let mut saw_stream_end = false;
        let mut cursor_chain_validated = cursor_state.cursor.is_none();

        let mut pointer_block_index = cursor_state.next_block_index;
        let mut pointer_offset = cursor_state.next_offset;
        let mut pointer_chain = cursor_state.expected_chain_at_resume;
        let page_index = cursor_state.next_page_index;

        let mut segments = Vec::new();
        let mut usage_bytes = 0_u64;
        let mut usage_tokens = 0_u64;
        let mut stop_reason = None::<TruncationReason>;
        let mut page_stopped = false;

        for event in events {
            match event? {
                WireEvent::Block(block) => {
                    validate_block_integrity(&block, expected_pack_digest, seen_blocks, chain)?;

                    if let Some(cursor) = &cursor_state.cursor {
                        if block.pack_digest != cursor_state.cursor_pack_digest {
                            return Err(Error::PackDigestMismatch);
                        }
                        if block.block_index == cursor.next_block_index {
                            if block.chain_prev != cursor_state.expected_chain_at_resume {
                                return Err(Error::InvalidCursor {
                                    message: format!(
                                        "cursor expected_chain_at_resume mismatch at block {}",
                                        block.block_index
                                    ),
                                });
                            }
                            let block_len = u64::try_from(block.len()).unwrap_or(u64::MAX);
                            if cursor.next_offset > block_len {
                                return Err(Error::InvalidCursor {
                                    message: format!(
                                        "cursor next_offset {} exceeds block length {} at block {}",
                                        cursor.next_offset, block_len, block.block_index
                                    ),
                                });
                            }
                            cursor_chain_validated = true;
                        }
                    }

                    if !page_stopped && block.block_index == pointer_block_index {
                        let mut start =
                            usize::try_from(pointer_offset).map_err(|_| Error::InvalidCursor {
                                message: "next_offset does not fit platform usize".to_string(),
                            })?;
                        if start > block.len() {
                            return Err(Error::InvalidCursor {
                                message: format!(
                                    "cursor offset {} exceeds block length {} at block {}",
                                    pointer_offset,
                                    block.len(),
                                    block.block_index
                                ),
                            });
                        }

                        if start == block.len() {
                            pointer_block_index = pointer_block_index.saturating_add(1);
                            pointer_offset = 0;
                            pointer_chain = block.chain_curr;
                            start = 0;
                        }

                        if start < block.len() {
                            if u32::try_from(segments.len()).unwrap_or(u32::MAX)
                                >= self.budget.max_segments
                            {
                                page_stopped = true;
                                stop_reason = Some(TruncationReason::MaxSegments);
                            } else {
                                let remaining_bytes =
                                    self.budget.max_bytes.saturating_sub(usage_bytes);
                                if remaining_bytes == 0 {
                                    page_stopped = true;
                                    stop_reason = Some(TruncationReason::MaxBytes);
                                } else {
                                    let remaining_tokens = self
                                        .budget
                                        .max_tokens_estimate
                                        .map_or(u64::MAX, |max| max.saturating_sub(usage_tokens));
                                    if self.budget.max_tokens_estimate.is_some()
                                        && remaining_tokens == 0
                                    {
                                        page_stopped = true;
                                        stop_reason = Some(TruncationReason::MaxTokensEstimate);
                                    } else {
                                        let available = block.len().saturating_sub(start);
                                        let remaining_bytes_usize =
                                            usize::try_from(remaining_bytes).unwrap_or(usize::MAX);
                                        let mut take_max = available.min(remaining_bytes_usize);
                                        if self.budget.max_tokens_estimate.is_some() {
                                            let token_bytes = usize::try_from(
                                                self.tokenizer
                                                    .max_bytes_for_tokens(remaining_tokens),
                                            )
                                            .unwrap_or(usize::MAX);
                                            take_max = take_max.min(token_bytes);
                                        }

                                        if take_max == 0 {
                                            page_stopped = true;
                                            stop_reason = Some(TruncationReason::MaxTokensEstimate);
                                        } else {
                                            let take = if self.budget.max_tokens_estimate.is_some()
                                            {
                                                max_take_for_token_budget(
                                                    &block.bytes[start..start + take_max],
                                                    self.tokenizer,
                                                    remaining_tokens,
                                                )
                                            } else {
                                                take_max
                                            };

                                            if take == 0 {
                                                page_stopped = true;
                                                stop_reason =
                                                    Some(TruncationReason::MaxTokensEstimate);
                                            } else {
                                                let end = start + take;
                                                let piece = &block.bytes[start..end];
                                                let piece_tokens =
                                                    self.tokenizer.estimate_tokens(piece);
                                                let piece_bytes =
                                                    u64::try_from(piece.len()).unwrap_or(u64::MAX);

                                                segments.push(Segment {
                                                    block_index: block.block_index,
                                                    path: block.path.clone(),
                                                    block_digest: hex::encode(block.block_digest),
                                                    range_start: u64::try_from(start)
                                                        .unwrap_or(u64::MAX),
                                                    range_end_exclusive: u64::try_from(end)
                                                        .unwrap_or(u64::MAX),
                                                    content_b64: STANDARD.encode(piece),
                                                });

                                                usage_bytes =
                                                    usage_bytes.saturating_add(piece_bytes);
                                                usage_tokens =
                                                    usage_tokens.saturating_add(piece_tokens);

                                                if end == block.len() {
                                                    pointer_block_index =
                                                        pointer_block_index.saturating_add(1);
                                                    pointer_offset = 0;
                                                    pointer_chain = block.chain_curr;
                                                } else {
                                                    pointer_offset =
                                                        u64::try_from(end).unwrap_or(u64::MAX);
                                                    pointer_chain = block.chain_prev;
                                                    page_stopped = true;
                                                    stop_reason = Some(TruncationReason::MaxBytes);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !page_stopped && block.block_index > pointer_block_index {
                        page_stopped = true;
                        stop_reason = Some(TruncationReason::MaxBytes);
                    }

                    expected_pack_digest.get_or_insert(block.pack_digest);
                    seen_blocks = seen_blocks.saturating_add(1);
                    seen_total_bytes = seen_total_bytes
                        .saturating_add(u64::try_from(block.len()).unwrap_or(u64::MAX));
                    chain = block.chain_curr;
                },
                WireEvent::StreamEnd(stream_end) => {
                    if saw_stream_end {
                        return Err(Error::InvalidInputStream {
                            message: "multiple stream_end records encountered".to_string(),
                        });
                    }
                    validate_stream_end_integrity(
                        stream_end,
                        expected_pack_digest,
                        seen_blocks,
                        seen_total_bytes,
                        chain,
                    )?;
                    if expected_pack_digest.is_none() {
                        expected_pack_digest = Some(stream_end.pack_digest);
                    }
                    if cursor_state.cursor.is_some()
                        && stream_end.pack_digest != cursor_state.cursor_pack_digest
                    {
                        return Err(Error::PackDigestMismatch);
                    }
                    saw_stream_end = true;
                },
            }
        }

        if require_stream_end && !saw_stream_end {
            return Err(Error::StreamEndMissing);
        }

        if let Some(cursor) = &cursor_state.cursor {
            if !cursor_chain_validated {
                if cursor.next_block_index == seen_blocks {
                    if cursor.next_offset != 0 {
                        return Err(Error::InvalidCursor {
                            message: "next_offset must be 0 at end of stream".to_string(),
                        });
                    }
                    if cursor_state.expected_chain_at_resume != chain {
                        return Err(Error::InvalidCursor {
                            message: "expected_chain_at_resume mismatch at end of stream"
                                .to_string(),
                        });
                    }
                } else {
                    return Err(Error::InvalidCursor {
                        message: format!(
                            "cursor next_block_index {} exceeds stream block count {}",
                            cursor.next_block_index, seen_blocks
                        ),
                    });
                }
            }
        }

        if pointer_block_index > seen_blocks {
            return Err(Error::InvalidCursor {
                message: format!(
                    "pagination pointer block index {pointer_block_index} exceeds stream block count {seen_blocks}"
                ),
            });
        }

        let at_end = pointer_block_index == seen_blocks && pointer_offset == 0;
        if segments.is_empty() && !at_end {
            return Err(Error::BudgetTooSmall);
        }

        let Some(pack_digest) = expected_pack_digest else {
            return Err(Error::InvalidInputStream {
                message: "stream did not contain pack_digest".to_string(),
            });
        };

        let cursor_out = if at_end {
            None
        } else {
            let next = CursorV1 {
                v: WIRE_VERSION,
                pack_digest: hex::encode(pack_digest),
                next_block_index: pointer_block_index,
                next_offset: pointer_offset,
                next_page_index: page_index.saturating_add(1),
                algo: CURSOR_ALGO_V1.to_string(),
                budget_fingerprint: self.budget.fingerprint(self.tokenizer),
                expected_chain_at_resume: hex::encode(pointer_chain),
            };
            Some(encode_cursor(&next)?)
        };

        let truncated = cursor_out.is_some();
        let truncation_reason = if truncated {
            stop_reason.or(Some(TruncationReason::MaxBytes))
        } else {
            None
        };

        Ok(Page {
            v: WIRE_VERSION,
            kind: "page",
            pack_digest: hex::encode(pack_digest),
            page_index,
            cursor_in: cursor_state.cursor_in,
            cursor_out,
            budget: PageBudgetReport::from(self.budget),
            usage: PageUsage {
                bytes: usage_bytes,
                tokens_estimate: usage_tokens,
                segments: u32::try_from(segments.len()).unwrap_or(u32::MAX),
            },
            segments,
            truncated,
            truncation_reason,
        })
    }

    fn validate_cursor_events<I>(
        &self,
        events: I,
        cursor: &CursorV1,
        require_stream_end: bool,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = Result<WireEvent, Error>>,
    {
        if cursor.algo != CURSOR_ALGO_V1 {
            return Err(Error::InvalidCursor {
                message: format!("unsupported cursor algorithm '{}'", cursor.algo),
            });
        }
        if cursor.v != WIRE_VERSION {
            return Err(Error::UnsupportedVersion {
                expected: WIRE_VERSION,
                actual: cursor.v,
            });
        }
        let expected_budget = self.budget.fingerprint(self.tokenizer);
        if self.strict_cursor && cursor.budget_fingerprint != expected_budget {
            return Err(Error::CursorBudgetMismatch);
        }
        let expected_chain =
            parse_cursor_digest(&cursor.expected_chain_at_resume, "expected_chain_at_resume")?;
        let cursor_pack_digest = parse_cursor_digest(&cursor.pack_digest, "pack_digest")?;

        let mut expected_pack_digest = None::<[u8; 32]>;
        let mut chain = ZERO_CHAIN;
        let mut seen_blocks = 0_u32;
        let mut seen_total_bytes = 0_u64;
        let mut saw_stream_end = false;
        let mut cursor_chain_validated = false;

        for event in events {
            match event? {
                WireEvent::Block(block) => {
                    validate_block_integrity(&block, expected_pack_digest, seen_blocks, chain)?;
                    if block.pack_digest != cursor_pack_digest {
                        return Err(Error::PackDigestMismatch);
                    }

                    if block.block_index == cursor.next_block_index {
                        if block.chain_prev != expected_chain {
                            return Err(Error::InvalidCursor {
                                message: format!(
                                    "cursor expected_chain_at_resume mismatch at block {}",
                                    block.block_index
                                ),
                            });
                        }
                        let block_len = u64::try_from(block.len()).unwrap_or(u64::MAX);
                        if cursor.next_offset > block_len {
                            return Err(Error::InvalidCursor {
                                message: format!(
                                    "cursor next_offset {} exceeds block length {} at block {}",
                                    cursor.next_offset, block_len, block.block_index
                                ),
                            });
                        }
                        cursor_chain_validated = true;
                    }

                    expected_pack_digest.get_or_insert(block.pack_digest);
                    seen_blocks = seen_blocks.saturating_add(1);
                    seen_total_bytes = seen_total_bytes
                        .saturating_add(u64::try_from(block.len()).unwrap_or(u64::MAX));
                    chain = block.chain_curr;
                },
                WireEvent::StreamEnd(stream_end) => {
                    if saw_stream_end {
                        return Err(Error::InvalidInputStream {
                            message: "multiple stream_end records encountered".to_string(),
                        });
                    }
                    validate_stream_end_integrity(
                        stream_end,
                        expected_pack_digest,
                        seen_blocks,
                        seen_total_bytes,
                        chain,
                    )?;
                    if stream_end.pack_digest != cursor_pack_digest {
                        return Err(Error::PackDigestMismatch);
                    }
                    if cursor.next_block_index == seen_blocks {
                        if cursor.next_offset != 0 {
                            return Err(Error::InvalidCursor {
                                message: "next_offset must be 0 at end of stream".to_string(),
                            });
                        }
                        if expected_chain != chain {
                            return Err(Error::InvalidCursor {
                                message: "expected_chain_at_resume mismatch at end of stream"
                                    .to_string(),
                            });
                        }
                        cursor_chain_validated = true;
                    }
                    saw_stream_end = true;
                },
            }
        }

        if require_stream_end && !saw_stream_end {
            return Err(Error::StreamEndMissing);
        }
        if !cursor_chain_validated {
            return Err(Error::InvalidCursor {
                message: format!(
                    "cursor next_block_index {} was not reachable in stream",
                    cursor.next_block_index
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CursorState {
    cursor_in: Option<String>,
    cursor: Option<CursorV1>,
    cursor_pack_digest: [u8; 32],
    expected_chain_at_resume: [u8; 32],
    next_block_index: u32,
    next_offset: u64,
    next_page_index: u32,
}

impl CursorState {
    fn from_input(
        cursor_in: Option<&str>,
        expected_budget_fingerprint: &str,
        strict_cursor: bool,
    ) -> Result<Self, Error> {
        let Some(cursor_text) = cursor_in else {
            return Ok(Self {
                cursor_in: None,
                cursor: None,
                cursor_pack_digest: ZERO_CHAIN,
                expected_chain_at_resume: ZERO_CHAIN,
                next_block_index: 0,
                next_offset: 0,
                next_page_index: 0,
            });
        };

        let cursor = decode_cursor(cursor_text)?;
        if strict_cursor && cursor.budget_fingerprint != expected_budget_fingerprint {
            return Err(Error::CursorBudgetMismatch);
        }
        let expected_chain_at_resume =
            parse_cursor_digest(&cursor.expected_chain_at_resume, "expected_chain_at_resume")?;
        let cursor_pack_digest = parse_cursor_digest(&cursor.pack_digest, "pack_digest")?;
        Ok(Self {
            cursor_in: Some(cursor_text.to_string()),
            cursor_pack_digest,
            expected_chain_at_resume,
            next_block_index: cursor.next_block_index,
            next_offset: cursor.next_offset,
            next_page_index: cursor.next_page_index,
            cursor: Some(cursor),
        })
    }
}

fn parse_cursor_digest(input: &str, field_name: &str) -> Result<[u8; 32], Error> {
    parse_digest(input, field_name).map_err(|error| Error::InvalidCursor {
        message: error.to_string(),
    })
}

fn validate_block_integrity(
    block: &Block,
    expected_pack_digest: Option<[u8; 32]>,
    expected_index: u32,
    expected_chain_prev: [u8; 32],
) -> Result<(), Error> {
    if let Some(pack_digest) = expected_pack_digest {
        if block.pack_digest != pack_digest {
            return Err(Error::PackDigestMismatch);
        }
    }
    if block.block_index != expected_index {
        return Err(Error::InvalidInputStream {
            message: format!(
                "block_index sequence mismatch: expected {}, got {}",
                expected_index, block.block_index
            ),
        });
    }
    if block.chain_prev != expected_chain_prev {
        return Err(Error::ChainMismatch {
            message: format!(
                "block {} chain_prev did not match previous chain",
                block.block_index
            ),
        });
    }
    let computed_chain = compute_block_chain_curr(block)?;
    if computed_chain != block.chain_curr {
        return Err(Error::ChainMismatch {
            message: format!(
                "block {} chain_curr did not match computed chain",
                block.block_index
            ),
        });
    }
    Ok(())
}

fn validate_stream_end_integrity(
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

fn synthetic_events(blocks: &[Block]) -> impl Iterator<Item = Result<WireEvent, Error>> + '_ {
    let total_bytes = blocks.iter().fold(0_u64, |sum, block| {
        sum.saturating_add(u64::try_from(block.len()).unwrap_or(u64::MAX))
    });
    let total_blocks = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
    let final_chain = blocks.last().map_or(ZERO_CHAIN, |block| block.chain_curr);
    let pack_digest = blocks.first().map_or([0; 32], |block| block.pack_digest);

    blocks
        .iter()
        .cloned()
        .map(|block| Ok(WireEvent::Block(block)))
        .chain(std::iter::once(Ok(WireEvent::StreamEnd(StreamEnd {
            pack_digest,
            total_blocks,
            total_bytes,
            final_chain,
        }))))
}

fn max_take_for_token_budget(input: &[u8], tokenizer: TokenizerMode, max_tokens: u64) -> usize {
    if input.is_empty() {
        return 0;
    }
    if tokenizer.estimate_tokens(&input[0..1]) > max_tokens {
        return 0;
    }

    let mut lo = 1_usize;
    let mut hi = input.len();
    let mut best = 1_usize;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let tokens = tokenizer.estimate_tokens(&input[..mid]);
        if tokens <= max_tokens {
            best = mid;
            lo = mid.saturating_add(1);
        } else {
            hi = mid.saturating_sub(1);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::{Paginator, max_take_for_token_budget};
    use crate::io::write_blocks_jsonl;
    use crate::model::{Block, PageBudget, ReadLimits, ZERO_CHAIN};
    use crate::tokenizer::TokenizerMode;

    fn fixture_blocks() -> Vec<Block> {
        let mut block_a = Block {
            pack_digest: [9; 32],
            block_index: 0,
            path: "README.md".to_string(),
            block_digest: *blake3::hash(b"abcdefghij").as_bytes(),
            bytes: Arc::from(b"abcdefghij".to_vec().into_boxed_slice()),
            token_estimate: 3,
            chain_prev: ZERO_CHAIN,
            chain_curr: [0; 32],
        };
        block_a.chain_curr = crate::io::compute_block_chain_curr(&block_a).expect("chain a");

        let mut block_b = Block {
            pack_digest: [9; 32],
            block_index: 1,
            path: "docs/guide.md".to_string(),
            block_digest: *blake3::hash(b"klmnopqrst").as_bytes(),
            bytes: Arc::from(b"klmnopqrst".to_vec().into_boxed_slice()),
            token_estimate: 3,
            chain_prev: block_a.chain_curr,
            chain_curr: [0; 32],
        };
        block_b.chain_curr = crate::io::compute_block_chain_curr(&block_b).expect("chain b");

        vec![block_a, block_b]
    }

    #[test]
    fn page_is_deterministic_for_same_input() {
        let blocks = fixture_blocks();
        let paginator = Paginator::new(
            PageBudget {
                max_bytes: 8,
                max_tokens_estimate: None,
                max_segments: 10,
            },
            TokenizerMode::BytesDiv4,
            true,
        )
        .expect("paginator");

        let page_a = paginator.page_from_cursor(&blocks, None).expect("page a");
        let page_b = paginator.page_from_cursor(&blocks, None).expect("page b");
        assert_eq!(page_a, page_b);
        assert!(page_a.cursor_out.is_some());
    }

    #[test]
    fn cursor_resume_reconstructs_original_bytes() {
        let blocks = fixture_blocks();
        let paginator = Paginator::new(
            PageBudget {
                max_bytes: 6,
                max_tokens_estimate: None,
                max_segments: 10,
            },
            TokenizerMode::BytesDiv4,
            true,
        )
        .expect("paginator");

        let pages = paginator.stream_pages(&blocks).expect("stream pages");
        let mut merged = Vec::new();
        for page in pages {
            for segment in page.segments {
                merged.extend_from_slice(
                    &STANDARD
                        .decode(segment.content_b64.as_bytes())
                        .expect("decode segment"),
                );
            }
        }
        assert_eq!(merged, b"abcdefghijklmnopqrst");
    }

    #[test]
    fn strict_cursor_detects_budget_mismatch() {
        let blocks = fixture_blocks();
        let strict = Paginator::new(
            PageBudget {
                max_bytes: 8,
                max_tokens_estimate: None,
                max_segments: 10,
            },
            TokenizerMode::BytesDiv4,
            true,
        )
        .expect("strict");
        let loose = Paginator::new(
            PageBudget {
                max_bytes: 16,
                max_tokens_estimate: None,
                max_segments: 10,
            },
            TokenizerMode::BytesDiv4,
            true,
        )
        .expect("loose");

        let first_page = strict.page_from_cursor(&blocks, None).expect("first page");
        let cursor = first_page.cursor_out.expect("cursor");
        let error = loose
            .page_from_cursor(&blocks, Some(&cursor))
            .expect_err("must fail");
        assert_eq!(error.code().as_str(), "CURSOR_BUDGET_MISMATCH");
    }

    #[test]
    fn security_rejects_cursor_with_non_hex_pack_digest() {
        let blocks = fixture_blocks();
        let paginator = Paginator::new(
            PageBudget {
                max_bytes: 8,
                max_tokens_estimate: None,
                max_segments: 10,
            },
            TokenizerMode::BytesDiv4,
            true,
        )
        .expect("paginator");

        let first_page = paginator
            .page_from_cursor(&blocks, None)
            .expect("first page");
        let mut cursor =
            crate::cursor::decode_cursor(first_page.cursor_out.as_deref().expect("cursor"))
                .expect("decode cursor");
        cursor.pack_digest = "not-a-hex-digest".to_string();
        let tampered = crate::cursor::encode_cursor(&cursor).expect("encode tampered cursor");

        let error = paginator
            .page_from_cursor(&blocks, Some(&tampered))
            .expect_err("tampered cursor must fail");
        assert_eq!(error.code().as_str(), "INVALID_CURSOR");
    }

    #[test]
    fn page_from_reader_requires_stream_end_when_enabled() {
        let blocks = fixture_blocks();
        let paginator = Paginator::new(
            PageBudget {
                max_bytes: 32,
                max_tokens_estimate: None,
                max_segments: 10,
            },
            TokenizerMode::BytesDiv4,
            true,
        )
        .expect("paginator");

        let mut jsonl = Vec::new();
        write_blocks_jsonl(&mut jsonl, &blocks).expect("write");

        let page = paginator
            .page_from_reader(Cursor::new(jsonl), None, ReadLimits::default(), true)
            .expect("page");
        assert!(page.cursor_out.is_none());
    }

    #[test]
    fn token_binary_search_returns_largest_prefix() {
        let tokenizer = TokenizerMode::BytesDiv4;
        let bytes = b"abcdefghijklmnopqrst";
        let take = max_take_for_token_budget(bytes, tokenizer, 2);
        assert_eq!(take, 8);
    }
}
