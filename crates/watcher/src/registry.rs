//! Registry version checker
//!
//! Fetches latest package versions from npm and PyPI registries.

use anyhow::Result;
use common::Registry;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Registry client for checking package versions
pub struct RegistryClient {
    client: Client,
}

impl RegistryClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("brin-watcher/{}", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Get the latest version of a package from its registry
    pub async fn get_latest_version(
        &self,
        name: &str,
        registry: Registry,
    ) -> Result<Option<String>> {
        match registry {
            Registry::Npm => self.get_npm_latest(name).await,
            Registry::Pypi => self.get_pypi_latest(name).await,
            Registry::Crates => {
                // Crates.io not yet supported
                Ok(None)
            }
        }
    }

    /// Get latest version from npm registry
    async fn get_npm_latest(&self, name: &str) -> Result<Option<String>> {
        // npm registry API: GET /{package}
        // Returns package metadata with dist-tags.latest
        let url = format!("https://registry.npmjs.org/{}", name);

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            anyhow::bail!("npm registry returned status {}", response.status());
        }

        let data: NpmPackageInfo = response.json().await?;
        Ok(data.dist_tags.and_then(|dt| dt.latest))
    }

    /// Get latest version from PyPI registry
    async fn get_pypi_latest(&self, name: &str) -> Result<Option<String>> {
        // PyPI JSON API: GET /pypi/{package}/json
        // Returns package metadata with info.version
        let url = format!("https://pypi.org/pypi/{}/json", name);

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            anyhow::bail!("PyPI registry returned status {}", response.status());
        }

        let data: PypiPackageInfo = response.json().await?;
        Ok(Some(data.info.version))
    }
}

#[derive(Deserialize)]
struct NpmPackageInfo {
    #[serde(rename = "dist-tags")]
    dist_tags: Option<NpmDistTags>,
}

#[derive(Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

#[derive(Deserialize)]
struct PypiPackageInfo {
    info: PypiInfo,
}

#[derive(Deserialize)]
struct PypiInfo {
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_npm_latest() {
        let client = RegistryClient::new();
        let version = client.get_npm_latest("lodash").await.unwrap();
        assert!(version.is_some());
        println!("lodash latest: {:?}", version);
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_pypi_latest() {
        let client = RegistryClient::new();
        let version = client.get_pypi_latest("requests").await.unwrap();
        assert!(version.is_some());
        println!("requests latest: {:?}", version);
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_npm_not_found() {
        let client = RegistryClient::new();
        let version = client
            .get_npm_latest("this-package-definitely-does-not-exist-12345")
            .await
            .unwrap();
        assert!(version.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_pypi_not_found() {
        let client = RegistryClient::new();
        let version = client
            .get_pypi_latest("this-package-definitely-does-not-exist-12345")
            .await
            .unwrap();
        assert!(version.is_none());
    }
}
