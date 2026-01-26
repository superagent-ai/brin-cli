//! API client for the sus backend

use anyhow::{Context, Result};
use reqwest::Client;
use sus_common::{
    BulkLookupRequest, PackageResponse, PackageVersionPair, ScanRequest, ScanRequestResponse,
};

/// Client for the sus API
pub struct SusClient {
    client: Client,
    base_url: String,
}

impl SusClient {
    /// Create a new API client
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-cli/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get package assessment (latest version)
    pub async fn get_package(&self, name: &str) -> Result<PackageResponse> {
        let url = format!("{}/v1/packages/{}", self.base_url, name);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to sus API")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("Package '{}' not found in sus database", name);
        }

        response
            .error_for_status()
            .context("API returned an error")?
            .json()
            .await
            .context("Failed to parse API response")
    }

    /// Get package assessment for a specific version
    pub async fn get_package_version(&self, name: &str, version: &str) -> Result<PackageResponse> {
        let url = format!("{}/v1/packages/{}/{}", self.base_url, name, version);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to sus API")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!(
                "Package '{}@{}' not found in sus database",
                name,
                version
            );
        }

        response
            .error_for_status()
            .context("API returned an error")?
            .json()
            .await
            .context("Failed to parse API response")
    }

    /// Request a scan for a package
    pub async fn request_scan(&self, name: &str, version: Option<&str>) -> Result<ScanRequestResponse> {
        let url = format!("{}/v1/scan", self.base_url);

        let request = ScanRequest {
            name: name.to_string(),
            version: version.map(String::from),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to connect to sus API")?;

        response
            .error_for_status()
            .context("API returned an error")?
            .json()
            .await
            .context("Failed to parse API response")
    }

    /// Bulk lookup multiple packages
    pub async fn bulk_lookup(&self, packages: &[PackageVersionPair]) -> Result<Vec<PackageResponse>> {
        let url = format!("{}/v1/bulk", self.base_url);

        let request = BulkLookupRequest {
            packages: packages.to_vec(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to connect to sus API")?;

        response
            .error_for_status()
            .context("API returned an error")?
            .json()
            .await
            .context("Failed to parse API response")
    }

    /// Check if API is reachable
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.base_url);

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}
