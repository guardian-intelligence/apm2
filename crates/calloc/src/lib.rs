//! Deterministic context allocation primitives.
//!
//! `calloc` is a minimal primitive for agent bootstrap flows:
//! select files ad hoc, build a deterministic pack, and emit/resume paginated
//! context output.
#![allow(missing_docs)]

pub mod allocator;
pub mod block;
pub mod budget;
pub mod cli;
pub mod error;
pub mod index;
pub mod manifest;
pub mod ordering;
pub mod pack;
pub mod renderer;
pub mod selection;
pub mod stats;
pub mod wire;

use std::io::Write;
use std::path::Path;

pub use allocator::{AllocationHandle, AllocationReceipt, Allocator};
pub use block::ContextBlock;
pub use budget::Budget;
pub use error::Error;
pub use index::{IndexSnapshot, IndexedFile};
pub use manifest::{ExcludeRule, IncludeRule, IndexConfig, Manifest, ProjectConfig};
pub use pack::ContextPack;
pub use renderer::RawRenderer;
pub use selection::{PageSpec, SelectionSpec};
pub use stats::AllocatorStats;

/// Compiles a selection spec into a deterministic context pack.
pub fn build_pack(selection: &SelectionSpec) -> Result<ContextPack, Error> {
    let manifest = selection.to_manifest()?;
    build_pack_from_manifest_struct(&manifest)
}

/// Compiles a manifest file into a deterministic context pack.
///
/// This is retained as an optional config-path for version-controlled recipes.
pub fn build_pack_from_manifest(manifest_path: impl AsRef<Path>) -> Result<ContextPack, Error> {
    let manifest = Manifest::from_path(manifest_path)?;
    build_pack_from_manifest_struct(&manifest)
}

/// Renders deterministic block JSONL records for paging pipelines.
pub fn write_blocks_jsonl(pack: &ContextPack, writer: &mut impl Write) -> Result<(), Error> {
    wire::write_pack_blocks_jsonl(pack, writer)
}

/// Builds one paginated page from a pack and optional resume cursor.
pub fn page_pack(
    pack: &ContextPack,
    page: PageSpec,
    cursor: Option<&str>,
) -> Result<ctxpage::Page, Error> {
    let blocks = wire::blocks_from_pack(pack)?;
    let paginator = ctxpage::Paginator::new(
        page.to_budget(),
        ctxpage::TokenizerMode::BytesDiv4,
        page.strict_cursor,
    )?;
    paginator
        .page_from_cursor(&blocks, cursor)
        .map_err(Error::from)
}

/// End-to-end helper: selection -> pack -> one paginated page.
pub fn stream_page(
    selection: &SelectionSpec,
    page: PageSpec,
    cursor: Option<&str>,
) -> Result<ctxpage::Page, Error> {
    let pack = build_pack(selection)?;
    page_pack(&pack, page, cursor)
}

fn build_pack_from_manifest_struct(manifest: &Manifest) -> Result<ContextPack, Error> {
    let snapshot = IndexSnapshot::build(&manifest.index)?;
    let mut allocator = Allocator::new(snapshot, manifest.budget.clone());
    let (_handle, pack, _receipt) = allocator.allocate_once(manifest)?;
    Ok(pack)
}
