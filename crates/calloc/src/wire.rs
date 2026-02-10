use std::io::Write;
use std::sync::Arc;

use ctxpage::{Block, ZERO_CHAIN, compute_block_chain_curr};

use crate::error::Error;
use crate::pack::ContextPack;

/// Converts a context pack into a validated block stream for `ctxpage`.
pub fn blocks_from_pack(pack: &ContextPack) -> Result<Vec<Block>, Error> {
    let mut chain = ZERO_CHAIN;
    let mut blocks = Vec::with_capacity(pack.blocks.len());

    for (index, block) in pack.blocks.iter().enumerate() {
        let mut wire_block = Block {
            pack_digest: pack.digest,
            block_index: u32::try_from(index).unwrap_or(u32::MAX),
            path: block.source_path.to_string_lossy().into_owned(),
            block_digest: block.digest,
            bytes: Arc::clone(&block.bytes),
            token_estimate: block.estimated_tokens,
            chain_prev: chain,
            chain_curr: [0; 32],
        };
        wire_block.chain_curr = compute_block_chain_curr(&wire_block)?;
        chain = wire_block.chain_curr;
        blocks.push(wire_block);
    }

    Ok(blocks)
}

/// Writes deterministic JSONL block records and terminal `stream_end`.
pub fn write_pack_blocks_jsonl(pack: &ContextPack, writer: &mut impl Write) -> Result<(), Error> {
    let blocks = blocks_from_pack(pack)?;
    ctxpage::write_blocks_jsonl(writer, &blocks)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::block::ContextBlock;
    use crate::pack::ContextPack;

    #[test]
    fn block_stream_round_trips_through_ctxpage_reader() {
        let pack = ContextPack::new(vec![ContextBlock {
            digest: *blake3::hash(b"hello\n").as_bytes(),
            source_path: PathBuf::from("README.md"),
            bytes: Arc::from(b"hello\n".to_vec().into_boxed_slice()),
            estimated_tokens: 2,
        }]);

        let mut out = Vec::new();
        super::write_pack_blocks_jsonl(&pack, &mut out).expect("write jsonl");
        let parsed = ctxpage::read_blocks_jsonl(std::io::Cursor::new(out)).expect("parse");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pack_digest, pack.digest);
        assert_eq!(parsed[0].path, "README.md");
    }
}
