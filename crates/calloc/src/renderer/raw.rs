use crate::error::Error;
use crate::pack::ContextPack;

/// Raw deterministic renderer.
#[derive(Debug, Default, Clone)]
pub struct RawRenderer;

impl RawRenderer {
    /// Renders a pack as deterministic concatenated bytes.
    pub fn render(&self, pack: &ContextPack) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();

        for block in &pack.blocks {
            let path = block.source_path.to_string_lossy();
            output.extend_from_slice(b">>> ");
            output.extend_from_slice(path.as_bytes());
            output.extend_from_slice(b"\n");
            output.extend_from_slice(&block.bytes);
            if !block.bytes.ends_with(b"\n") {
                output.push(b'\n');
            }
            output.extend_from_slice(b"<<<\n");
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::RawRenderer;
    use crate::block::ContextBlock;
    use crate::pack::ContextPack;

    #[test]
    fn renders_stably() {
        let pack = ContextPack::new(vec![ContextBlock {
            digest: [1; 32],
            source_path: PathBuf::from("src/lib.rs"),
            bytes: Arc::from(b"pub fn f() {}\n".to_vec().into_boxed_slice()),
            estimated_tokens: 4,
        }]);

        let renderer = RawRenderer;
        let a = renderer.render(&pack).expect("render a");
        let b = renderer.render(&pack).expect("render b");
        assert_eq!(a, b);
    }
}
