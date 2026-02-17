//! Registry adapter module
//!
//! This module provides a unified interface for interacting with different package registries
//! (npm, PyPI, etc.) through the `RegistryAdapter` trait.

mod npm;
mod pypi;
mod skills;
mod types;

pub use npm::NpmAdapter;
pub use pypi::PypiAdapter;
pub use skills::SkillsAdapter;
pub use types::{ExtractedPackage, Language, Maintainer, PackageMetadata, SourceFile};

use anyhow::Result;
use async_trait::async_trait;
use common::Registry;
use std::collections::HashMap;
use std::sync::Arc;

/// Trait for registry-specific operations
///
/// Each registry (npm, PyPI, etc.) implements this trait to provide
/// a unified interface for fetching metadata, downloading packages,
/// and computing trust scores.
#[async_trait]
pub trait RegistryAdapter: Send + Sync {
    /// Which registry this adapter handles
    fn registry(&self) -> Registry;

    /// Fetch package metadata (version, maintainers, downloads, etc.)
    ///
    /// If `version` is None, fetches the latest version.
    async fn fetch_metadata(&self, name: &str, version: Option<&str>) -> Result<PackageMetadata>;

    /// Download and extract package to a temporary directory
    async fn download_package(&self, name: &str, version: &str) -> Result<ExtractedPackage>;

    /// Extract a local tarball/package file
    fn extract_local(&self, path: &std::path::Path) -> Result<ExtractedPackage>;

    /// Compute trust score (0-100) based on registry-specific factors
    fn compute_trust_score(&self, metadata: &PackageMetadata) -> u8;

    /// Get CVE ecosystem identifier (e.g., "npm", "PyPI")
    ///
    /// Returns None if this registry doesn't have CVE tracking.
    fn cve_ecosystem(&self) -> Option<&'static str>;

    /// Fetch weekly download count (if available)
    async fn fetch_downloads(&self, name: &str) -> Result<Option<i64>>;
}

/// Registry for managing all available adapters
pub struct AdapterRegistry {
    adapters: HashMap<Registry, Arc<dyn RegistryAdapter>>,
}

impl AdapterRegistry {
    /// Create a new adapter registry with all built-in adapters
    pub fn new() -> Self {
        let mut adapters: HashMap<Registry, Arc<dyn RegistryAdapter>> = HashMap::new();
        adapters.insert(Registry::Npm, Arc::new(NpmAdapter::new()));
        adapters.insert(Registry::Pypi, Arc::new(PypiAdapter::new()));
        adapters.insert(Registry::Skills, Arc::new(SkillsAdapter::new()));
        Self { adapters }
    }

    /// Get an adapter for a specific registry
    pub fn get(&self, registry: Registry) -> Option<Arc<dyn RegistryAdapter>> {
        self.adapters.get(&registry).cloned()
    }

    /// Register a new adapter (useful for testing or custom registries)
    #[allow(dead_code)]
    pub fn register(&mut self, adapter: Arc<dyn RegistryAdapter>) {
        self.adapters.insert(adapter.registry(), adapter);
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
