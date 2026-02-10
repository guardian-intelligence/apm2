use std::path::{Path, PathBuf};

use crate::budget::Budget;
use crate::error::Error;
use crate::manifest::{ExcludeRule, IncludeRule, IndexConfig, Manifest, ProjectConfig};

const DEFAULT_NAMESPACE: &str = "adhoc";
const DEFAULT_INDEX_EXCLUDES: [&str; 3] = ["target/**", ".git/**", "*.lock"];

/// Ad hoc file-selection spec for deterministic pack construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionSpec {
    /// Namespace label carried in generated manifests/receipts.
    pub namespace: String,
    /// Roots scanned during indexing.
    pub roots: Vec<PathBuf>,
    /// Include globs matched against canonical relative paths.
    pub includes: Vec<String>,
    /// Exclude globs applied after include matching.
    pub excludes: Vec<String>,
    /// Maximum bytes per file accepted into the index.
    pub max_file_bytes: u64,
    /// Optional hard cap for selected bytes.
    pub budget_bytes: Option<u64>,
    /// Optional token estimate budget.
    pub budget_tokens_estimate: Option<u64>,
}

impl Default for SelectionSpec {
    fn default() -> Self {
        Self {
            namespace: DEFAULT_NAMESPACE.to_string(),
            roots: vec![PathBuf::from(".")],
            includes: Vec::new(),
            excludes: Vec::new(),
            max_file_bytes: 524_288,
            budget_bytes: None,
            budget_tokens_estimate: None,
        }
    }
}

impl SelectionSpec {
    /// Converts this selection spec into an internal manifest.
    pub fn to_manifest(&self) -> Result<Manifest, Error> {
        if self.roots.is_empty() {
            return Err(Error::ManifestValidation(
                "at least one --root is required".to_string(),
            ));
        }
        if self.includes.is_empty() {
            return Err(Error::ManifestValidation(
                "at least one --include or positional path is required".to_string(),
            ));
        }
        if self.max_file_bytes == 0 {
            return Err(Error::ManifestValidation(
                "--max-file-bytes must be greater than zero".to_string(),
            ));
        }

        let mut index_excludes = DEFAULT_INDEX_EXCLUDES
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        for exclude in &self.excludes {
            if !index_excludes.iter().any(|existing| existing == exclude) {
                index_excludes.push(exclude.clone());
            }
        }

        let manifest = Manifest {
            project: ProjectConfig {
                namespace: self.namespace.clone(),
            },
            index: IndexConfig {
                roots: self.roots.clone(),
                exclude: index_excludes,
                max_file_bytes: self.max_file_bytes,
            },
            budget: Budget {
                max_bytes: self.budget_bytes.unwrap_or(u64::MAX),
                max_tokens: self.budget_tokens_estimate,
            },
            include: self
                .includes
                .iter()
                .map(|glob| IncludeRule {
                    glob: glob.clone(),
                    priority: 0,
                    anchor: false,
                })
                .collect(),
            exclude: self
                .excludes
                .iter()
                .map(|glob| ExcludeRule { glob: glob.clone() })
                .collect(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Converts a path into an include glob.
    pub fn include_glob_from_path(path: &Path) -> Result<String, Error> {
        let workspace_root = std::env::current_dir()?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            workspace_root.join(path)
        };

        let relative = absolute
            .strip_prefix(&workspace_root)
            .map_err(|_| {
                Error::ManifestValidation(format!(
                    "path '{}' must be inside current directory '{}'",
                    path.display(),
                    workspace_root.display()
                ))
            })?
            .to_path_buf();

        let normalized = canonical_relative(&relative);
        let is_dir = absolute.is_dir();

        if normalized == "." {
            return Ok("**".to_string());
        }

        if is_dir {
            Ok(format!("{normalized}/**"))
        } else {
            Ok(normalized)
        }
    }
}

/// Page budget and cursor handling spec for paginated output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSpec {
    /// Maximum bytes emitted per page.
    pub max_bytes: u64,
    /// Optional token estimate cap emitted per page.
    pub max_tokens_estimate: Option<u64>,
    /// Maximum segments emitted per page.
    pub max_segments: u32,
    /// Reject cursors built with a different budget/tokenizer fingerprint.
    pub strict_cursor: bool,
}

impl PageSpec {
    /// Builds a `ctxpage` budget from this spec.
    pub const fn to_budget(self) -> ctxpage::PageBudget {
        ctxpage::PageBudget {
            max_bytes: self.max_bytes,
            max_tokens_estimate: self.max_tokens_estimate,
            max_segments: self.max_segments,
        }
    }
}

fn canonical_relative(path: &Path) -> String {
    let canonical = path
        .components()
        .filter_map(|component| {
            let text = component.as_os_str().to_string_lossy();
            if text.is_empty() {
                None
            } else {
                Some(text.into_owned())
            }
        })
        .collect::<Vec<_>>()
        .join("/");

    if canonical.is_empty() {
        ".".to_string()
    } else {
        canonical
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::SelectionSpec;

    #[test]
    fn include_glob_from_file_path() {
        let path = std::path::Path::new("src/lib.rs");
        let glob = SelectionSpec::include_glob_from_path(path).expect("glob");
        assert_eq!(glob, "src/lib.rs");
    }

    #[test]
    fn spec_to_manifest_requires_includes() {
        let spec = SelectionSpec::default();
        let error = spec.to_manifest().expect_err("must fail");
        assert!(error.to_string().contains("at least one --include"));
    }

    #[test]
    fn security_rejects_absolute_path_outside_workspace() {
        let path = PathBuf::from("/tmp");
        let error = SelectionSpec::include_glob_from_path(&path).expect_err("must reject");
        assert!(
            error
                .to_string()
                .contains("must be inside current directory")
        );
    }
}
