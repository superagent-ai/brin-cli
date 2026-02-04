//! Unified types for registry adapters

use chrono::{DateTime, Utc};
use std::path::PathBuf;
use tempfile::TempDir;

/// Language of a source file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    JavaScript,
    TypeScript,
    Python,
    Other,
}

impl Language {
    /// Detect language from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
            "ts" | "mts" | "cts" | "tsx" => Language::TypeScript,
            "py" | "pyi" => Language::Python,
            _ => Language::Other,
        }
    }
}

/// A source file from an extracted package
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Relative path within the package
    #[allow(dead_code)]
    pub path: String,
    /// File content
    pub content: String,
    /// Detected language
    pub language: Language,
}

/// Unified extracted package (works for all registries)
pub struct ExtractedPackage {
    /// Temporary directory containing extracted files (must keep for ownership)
    #[allow(dead_code)]
    pub dir: TempDir,
    /// Path to package root
    pub root: PathBuf,
    /// Source files (.js, .ts, .py, etc.)
    pub source_files: Vec<SourceFile>,
    /// Package manifest (package.json, pyproject.toml, etc.)
    pub manifest: serde_json::Value,
    /// Has native code (C extensions, binding.gyp, etc.)
    pub has_native_code: bool,
}

/// Maintainer information
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Maintainer {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Unified package metadata (works for all registries)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PackageMetadata {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package description
    pub description: Option<String>,
    /// Repository URL
    pub repository: Option<String>,
    /// Package maintainers
    pub maintainers: Vec<Maintainer>,
    /// Weekly download count (if available)
    pub downloads: Option<i64>,
    /// When this version was published
    pub published_at: Option<DateTime<Utc>>,
    /// License identifier
    pub license: Option<String>,
    /// Registry-specific extra data
    pub extras: serde_json::Value,
}

impl Default for PackageMetadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: String::new(),
            description: None,
            repository: None,
            maintainers: Vec::new(),
            downloads: None,
            published_at: None,
            license: None,
            extras: serde_json::Value::Null,
        }
    }
}
