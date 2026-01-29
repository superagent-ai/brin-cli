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

    /// Fetch all npm advisories from OSV
    pub async fn fetch_npm_advisories(&self) -> Result<Vec<OsvAdvisory>> {
        let mut all_advisories = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let url = format!("{}/querybatch", OSV_API_URL);

            let mut request_body = serde_json::json!({
                "queries": [{
                    "package": {
                        "ecosystem": "npm"
                    }
                }]
            });

            if let Some(token) = &page_token {
                request_body["page_token"] = serde_json::json!(token);
            }

            let response = self.client.post(&url).json(&request_body).send().await?;

            if !response.status().is_success() {
                tracing::warn!(
                    "OSV querybatch failed: {} - {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
                break;
            }

            let batch_response: serde_json::Value = response.json().await?;

            // Extract results from first query
            if let Some(results) = batch_response
                .get("results")
                .and_then(|r| r.as_array())
                .and_then(|arr| arr.first())
            {
                if let Some(vulns) = results.get("vulns").and_then(|v| v.as_array()) {
                    for vuln in vulns {
                        if let Ok(advisory) = serde_json::from_value::<OsvAdvisory>(vuln.clone()) {
                            all_advisories.push(advisory);
                        }
                    }
                }

                page_token = results
                    .get("next_page_token")
                    .and_then(|t| t.as_str())
                    .map(String::from);
            } else {
                break;
            }

            // Stop if no more pages
            if page_token.is_none() {
                break;
            }

            // Rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Limit total pages to avoid very long runs
            if all_advisories.len() > 10000 {
                tracing::warn!("Reached advisory limit, stopping pagination");
                break;
            }
        }

        Ok(all_advisories)
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
