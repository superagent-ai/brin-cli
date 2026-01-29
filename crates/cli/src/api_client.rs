//! API client for the sus backend

use anyhow::{Context, Result};
use common::{
    BulkLookupRequest, PackageResponse, PackageVersionPair, ScanRequest, ScanRequestResponse,
};
use reqwest::Client;

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
            anyhow::bail!("Package '{}@{}' not found in sus database", name, version);
        }

        response
            .error_for_status()
            .context("API returned an error")?
            .json()
            .await
            .context("Failed to parse API response")
    }

    /// Request a scan for a package
    pub async fn request_scan(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<ScanRequestResponse> {
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
    pub async fn bulk_lookup(
        &self,
        packages: &[PackageVersionPair],
    ) -> Result<Vec<PackageResponse>> {
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
    #[allow(dead_code)]
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.base_url);

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_package_response() -> serde_json::Value {
        serde_json::json!({
            "name": "express",
            "version": "4.18.2",
            "risk_level": "clean",
            "risk_reasons": [],
            "trust_score": 85,
            "publisher": null,
            "weekly_downloads": 25000000,
            "install_scripts": {
                "preinstall": false,
                "install": false,
                "postinstall": false,
                "prepare": false
            },
            "cves": [],
            "agentic_threats": [],
            "capabilities": {
                "network": { "makes_requests": false, "domains": [], "protocols": [] },
                "filesystem": { "reads": false, "writes": false, "paths": [] },
                "process": { "spawns_children": false, "commands": [] },
                "environment": { "accessed_vars": [] },
                "native": { "has_native": false, "native_modules": [] }
            },
            "skill_md": null,
            "scanned_at": "2024-01-15T10:30:00Z"
        })
    }

    #[tokio::test]
    async fn test_get_package_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/packages/express"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_package_response()))
            .mount(&mock_server)
            .await;

        let client = SusClient::new(&mock_server.uri());
        let result = client.get_package("express").await;

        assert!(result.is_ok());
        let package = result.unwrap();
        assert_eq!(package.name, "express");
        assert_eq!(package.version, "4.18.2");
    }

    #[tokio::test]
    async fn test_get_package_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/packages/nonexistent-package"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = SusClient::new(&mock_server.uri());
        let result = client.get_package("nonexistent-package").await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "Error should mention not found: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_get_package_version_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/packages/lodash/4.17.21"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_package_response()))
            .mount(&mock_server)
            .await;

        let client = SusClient::new(&mock_server.uri());
        let result = client.get_package_version("lodash", "4.17.21").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_check_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "ok"})),
            )
            .mount(&mock_server)
            .await;

        let client = SusClient::new(&mock_server.uri());
        let result = client.health_check().await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_health_check_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = SusClient::new(&mock_server.uri());
        let result = client.health_check().await;

        assert!(result.is_ok());
        assert!(!result.unwrap(), "Health check should return false for 500");
    }

    #[tokio::test]
    async fn test_request_scan() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/scan"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "estimated_seconds": 30
            })))
            .mount(&mock_server)
            .await;

        let client = SusClient::new(&mock_server.uri());
        let result = client.request_scan("new-package", Some("1.0.0")).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.estimated_seconds, 30);
    }

    #[tokio::test]
    async fn test_base_url_trailing_slash_handling() {
        // Test that trailing slashes are handled correctly
        let client1 = SusClient::new("http://api.example.com/");
        let client2 = SusClient::new("http://api.example.com");

        assert_eq!(client1.base_url, "http://api.example.com");
        assert_eq!(client2.base_url, "http://api.example.com");
    }
}
