use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::budget::Budget;
use crate::error::Error;

/// Root manifest for context allocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Project metadata.
    #[serde(default)]
    pub project: ProjectConfig,
    /// Indexing configuration.
    #[serde(default)]
    pub index: IndexConfig,
    /// Budget constraints.
    #[serde(default)]
    pub budget: Budget,
    /// Include rules evaluated to select files.
    #[serde(default)]
    pub include: Vec<IncludeRule>,
    /// Exclude rules evaluated after includes.
    #[serde(default)]
    pub exclude: Vec<ExcludeRule>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            project: ProjectConfig::default(),
            index: IndexConfig::default(),
            budget: Budget::default(),
            include: vec![
                IncludeRule {
                    glob: "AGENTS.md".to_string(),
                    priority: 300,
                    anchor: true,
                },
                IncludeRule {
                    glob: "README.md".to_string(),
                    priority: 200,
                    anchor: true,
                },
                IncludeRule {
                    glob: "src/**/*.rs".to_string(),
                    priority: 100,
                    anchor: false,
                },
            ],
            exclude: vec![ExcludeRule {
                glob: "src/**/tests/**".to_string(),
            }],
        }
    }
}

impl Manifest {
    /// Parses a manifest from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path_ref = path.as_ref();
        let text = std::fs::read_to_string(path_ref)
            .map_err(|source| Error::io_at_path(path_ref.to_path_buf(), source))?;
        Self::from_toml(&text)
    }

    /// Parses a manifest from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, Error> {
        let parsed: Self =
            toml::from_str(text).map_err(|error| Error::ManifestParse(error.to_string()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Validates manifest invariants.
    pub fn validate(&self) -> Result<(), Error> {
        if self.index.roots.is_empty() {
            return Err(Error::ManifestValidation(
                "index.roots must contain at least one entry".to_string(),
            ));
        }
        if self.index.max_file_bytes == 0 {
            return Err(Error::ManifestValidation(
                "index.max_file_bytes must be greater than zero".to_string(),
            ));
        }
        if self.include.is_empty() {
            return Err(Error::ManifestValidation(
                "include rules must contain at least one entry".to_string(),
            ));
        }
        self.budget.validate()?;
        Ok(())
    }
}

impl std::str::FromStr for Manifest {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_toml(text)
    }
}

/// Project metadata for a manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// Namespace label for reporting and generated files.
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            namespace: default_namespace(),
        }
    }
}

fn default_namespace() -> String {
    "project".to_string()
}

/// Filesystem indexing config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndexConfig {
    /// Root directories scanned during index build.
    #[serde(default = "default_roots")]
    pub roots: Vec<PathBuf>,
    /// Exclude globs applied during indexing.
    #[serde(default = "default_index_excludes")]
    pub exclude: Vec<String>,
    /// Maximum per-file size admitted into the index.
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            roots: default_roots(),
            exclude: default_index_excludes(),
            max_file_bytes: default_max_file_bytes(),
        }
    }
}

fn default_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("src"), PathBuf::from("docs")]
}

fn default_index_excludes() -> Vec<String> {
    vec![
        "target/**".to_string(),
        ".git/**".to_string(),
        "*.lock".to_string(),
    ]
}

const fn default_max_file_bytes() -> u64 {
    524_288
}

/// Include selector rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncludeRule {
    /// Glob pattern matching relative file paths.
    pub glob: String,
    /// Priority used for deterministic ordering.
    #[serde(default)]
    pub priority: i32,
    /// Anchor rules appear before non-anchor rules.
    #[serde(default)]
    pub anchor: bool,
}

/// Exclude selector rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExcludeRule {
    /// Glob pattern matching relative file paths.
    pub glob: String,
}

#[cfg(test)]
mod tests {
    use super::Manifest;

    #[test]
    fn parses_minimal_manifest() {
        let manifest = Manifest::from_toml(
            r#"
[project]
namespace = "demo"

[index]
roots = ["src"]
exclude = ["target/**"]
max_file_bytes = 2048

[budget]
max_bytes = 4096

[[include]]
glob = "src/**/*.rs"
priority = 100
anchor = false
"#,
        )
        .expect("manifest should parse");

        assert_eq!(manifest.project.namespace, "demo");
        assert_eq!(manifest.include.len(), 1);
    }

    #[test]
    fn rejects_unknown_field() {
        let err = Manifest::from_toml(
            r#"
[index]
roots = ["src"]
exclude = []
max_file_bytes = 2048
extra = true

[budget]
max_bytes = 1024

[[include]]
glob = "src/**/*.rs"
"#,
        )
        .expect_err("unknown field must fail");

        assert!(err.to_string().contains("manifest parse failed"));
    }
}
