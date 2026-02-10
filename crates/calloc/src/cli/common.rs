use std::path::PathBuf;

use clap::Args;

use crate::error::Error;
use crate::manifest::Manifest;
use crate::selection::{PageSpec, SelectionSpec};

/// Shared ad hoc file-selection arguments.
#[derive(Debug, Clone, Args)]
pub struct SelectionArgs {
    /// Optional recipe file (TOML manifest).
    #[arg(long)]
    pub recipe: Option<PathBuf>,
    /// Root directory to scan. Repeatable.
    #[arg(long = "root", default_value = ".")]
    pub roots: Vec<PathBuf>,
    /// Include glob. Repeatable.
    #[arg(long = "include")]
    pub includes: Vec<String>,
    /// Exclude glob. Repeatable.
    #[arg(long = "exclude")]
    pub excludes: Vec<String>,
    /// Maximum bytes accepted per indexed file.
    #[arg(long, default_value_t = 524_288)]
    pub max_file_bytes: u64,
    /// Optional byte budget cap for selected files.
    #[arg(long)]
    pub budget_bytes: Option<u64>,
    /// Optional token estimate budget cap.
    #[arg(long)]
    pub budget_tokens_estimate: Option<u64>,
    /// Optional namespace label for generated artifacts.
    #[arg(long, default_value = "adhoc")]
    pub namespace: String,
    /// Additional literal file/directory paths to include.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,
}

impl SelectionArgs {
    pub(crate) fn load_manifest(&self) -> Result<Manifest, Error> {
        if let Some(path) = &self.recipe {
            self.ensure_recipe_not_mixed()?;
            return Manifest::from_path(path);
        }

        let mut includes = self.includes.clone();
        for path in &self.paths {
            includes.push(SelectionSpec::include_glob_from_path(path)?);
        }

        let spec = SelectionSpec {
            namespace: self.namespace.clone(),
            roots: self.roots.clone(),
            includes,
            excludes: self.excludes.clone(),
            max_file_bytes: self.max_file_bytes,
            budget_bytes: self.budget_bytes,
            budget_tokens_estimate: self.budget_tokens_estimate,
        };

        spec.to_manifest()
    }

    fn ensure_recipe_not_mixed(&self) -> Result<(), Error> {
        let using_only_defaults = self.roots == vec![PathBuf::from(".")]
            && self.includes.is_empty()
            && self.excludes.is_empty()
            && self.max_file_bytes == 524_288
            && self.budget_bytes.is_none()
            && self.budget_tokens_estimate.is_none()
            && self.namespace == "adhoc"
            && self.paths.is_empty();

        if using_only_defaults {
            return Ok(());
        }

        Err(Error::ManifestValidation(
            "--recipe cannot be combined with ad hoc selection flags".to_string(),
        ))
    }
}

/// Shared paging arguments.
#[derive(Debug, Clone, Args)]
pub struct PagingArgs {
    /// Maximum bytes emitted in one page.
    #[arg(long = "page-max-bytes")]
    pub max_bytes: u64,
    /// Optional token estimate cap emitted in one page.
    #[arg(long = "page-max-tokens-est")]
    pub max_tokens_estimate: Option<u64>,
    /// Maximum segments emitted in one page.
    #[arg(long = "page-max-segments", default_value_t = 256)]
    pub max_segments: u32,
    /// Resume cursor returned by a previous page.
    #[arg(long)]
    pub cursor: Option<String>,
    /// Allow cursor continuation with a changed budget fingerprint.
    #[arg(long)]
    pub no_strict_cursor: bool,
}

impl PagingArgs {
    pub(crate) const fn to_page_spec(&self) -> PageSpec {
        PageSpec {
            max_bytes: self.max_bytes,
            max_tokens_estimate: self.max_tokens_estimate,
            max_segments: self.max_segments,
            strict_cursor: !self.no_strict_cursor,
        }
    }
}

/// Optional read limits for stdin JSONL parsing.
#[derive(Debug, Clone, Copy, Args)]
pub struct ReadLimitArgs {
    /// Maximum total stdin bytes accepted.
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    pub max_input_bytes: u64,
    /// Maximum size of one JSONL input line.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub max_line_bytes: usize,
    /// Maximum decoded bytes accepted for one block record.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub max_decoded_block_bytes: u64,
    /// Require a terminal `stream_end` record at EOF.
    #[arg(long, default_value_t = true)]
    pub require_stream_end: bool,
}

impl ReadLimitArgs {
    pub(crate) const fn to_read_limits(self) -> ctxpage::ReadLimits {
        ctxpage::ReadLimits {
            max_input_bytes: Some(self.max_input_bytes),
            max_line_bytes: Some(self.max_line_bytes),
            max_decoded_block_bytes: Some(self.max_decoded_block_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::SelectionArgs;

    #[test]
    fn security_recipe_mode_rejects_mixed_flags() {
        let args = SelectionArgs {
            recipe: Some(PathBuf::from("recipe.toml")),
            roots: vec![PathBuf::from(".")],
            includes: vec!["README.md".to_string()],
            excludes: Vec::new(),
            max_file_bytes: 524_288,
            budget_bytes: None,
            budget_tokens_estimate: None,
            namespace: "adhoc".to_string(),
            paths: Vec::new(),
        };

        let error = args.load_manifest().expect_err("must fail");
        assert!(error.to_string().contains("cannot be combined"));
    }
}
