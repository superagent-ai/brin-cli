//! OSV (Open Source Vulnerabilities) client

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

const OSV_API_URL: &str = "https://api.osv.dev/v1";

/// An OSV advisory
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvAdvisory {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub severity: Option<Vec<OsvSeverity>>,
    pub affected: Option<Vec<OsvAffected>>,
    pub published: Option<String>,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: Option<String>,
    pub score: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvAffected {
    pub package: Option<OsvPackage>,
    pub ranges: Option<Vec<OsvRange>>,
    pub versions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvPackage {
    pub ecosystem: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: Option<String>,
    pub events: Option<Vec<OsvEvent>>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

/// Response from OSV query all endpoint
#[derive(Deserialize)]
#[allow(dead_code)]
struct OsvQueryAllResponse {
    vulns: Option<Vec<OsvAdvisory>>,
    next_page_token: Option<String>,
}

/// OSV API client
pub struct OsvClient {
    client: Client,
}

impl OsvClient {
    /// Create a new OSV client
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-cve/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Fetch advisories for a list of npm packages from OSV
    pub async fn fetch_advisories_for_packages(
        &self,
        packages: &[(String, String)], // (name, version) pairs
    ) -> Result<Vec<OsvAdvisory>> {
        if packages.is_empty() {
            return Ok(vec![]);
        }

        let mut all_advisories = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        // Filter out invalid packages and process in batches of 100 (OSV limit)
        let valid_packages: Vec<_> = packages
            .iter()
            .filter(|(name, version)| !name.is_empty() && !version.is_empty())
            .collect();

        for chunk in valid_packages.chunks(100) {
            let queries: Vec<serde_json::Value> = chunk
                .iter()
                .map(|(name, version)| {
                    serde_json::json!({
                        "package": {
                            "name": name,
                            "ecosystem": "npm"
                        },
                        "version": version
                    })
                })
                .collect();

            let url = format!("{}/querybatch", OSV_API_URL);
            let request_body = serde_json::json!({ "queries": queries });

            tracing::debug!("OSV querybatch request for {} packages", chunk.len());

            let response = match self.client.post(&url).json(&request_body).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("OSV querybatch request failed: {}", e);
                    continue;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                tracing::warn!("OSV querybatch failed: {} - {}", status, body);
                // If we get a 400, log the request for debugging
                if status.as_u16() == 400 {
                    tracing::debug!(
                        "OSV request body: {}",
                        serde_json::to_string_pretty(&request_body).unwrap_or_default()
                    );
                }
                continue;
            }

            let batch_response: serde_json::Value = match response.json().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("OSV querybatch response parse failed: {}", e);
                    continue;
                }
            };

            // Extract results from each query
            if let Some(results) = batch_response.get("results").and_then(|r| r.as_array()) {
                for (i, result) in results.iter().enumerate() {
                    if let Some(vulns) = result.get("vulns").and_then(|v| v.as_array()) {
                        // Log which package had vulnerabilities
                        if i < chunk.len() && !vulns.is_empty() {
                            let (name, _) = &chunk[i];
                            tracing::info!("Found {} OSV advisories for {}", vulns.len(), name);
                        }

                        for vuln in vulns {
                            // Fetch full advisory details (dedupe by ID)
                            if let Some(vuln_id) = vuln.get("id").and_then(|id| id.as_str()) {
                                if seen_ids.insert(vuln_id.to_string()) {
                                    match self.fetch_advisory(vuln_id).await {
                                        Ok(advisory) => all_advisories.push(advisory),
                                        Err(e) => tracing::debug!(
                                            "Failed to fetch advisory {}: {}",
                                            vuln_id,
                                            e
                                        ),
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        tracing::info!("OSV: fetched {} unique advisories", all_advisories.len());
        Ok(all_advisories)
    }

    /// Fetch a single advisory by ID
    async fn fetch_advisory(&self, id: &str) -> Result<OsvAdvisory> {
        let url = format!("{}/vulns/{}", OSV_API_URL, id);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to fetch advisory {}: {}", id, response.status());
        }

        let advisory: OsvAdvisory = response.json().await?;
        Ok(advisory)
    }

    /// Fetch all npm advisories from OSV (legacy - kept for compatibility)
    #[allow(dead_code)]
    pub async fn fetch_npm_advisories(&self) -> Result<Vec<OsvAdvisory>> {
        // OSV doesn't support ecosystem-wide queries via querybatch
        // Use fetch_advisories_for_packages instead
        tracing::warn!("fetch_npm_advisories is deprecated, use fetch_advisories_for_packages");
        Ok(vec![])
    }

    /// Query vulnerabilities for a specific package
    #[allow(dead_code)]
    pub async fn query_package(&self, name: &str, version: &str) -> Result<Vec<OsvAdvisory>> {
        let url = format!("{}/query", OSV_API_URL);

        let request_body = serde_json::json!({
            "package": {
                "name": name,
                "ecosystem": "npm"
            },
            "version": version
        });

        let response = self.client.post(&url).json(&request_body).send().await?;

        if !response.status().is_success() {
            return Ok(vec![]);
        }

        let query_response: OsvQueryAllResponse = response.json().await?;

        Ok(query_response.vulns.unwrap_or_default())
    }
}
