//! NVD (National Vulnerability Database) client

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde::Deserialize;

const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// NVD CVE entry
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct NvdCve {
    pub id: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: Option<String>,
    pub published: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    #[serde(rename = "vulnStatus")]
    pub vuln_status: Option<String>,
    pub descriptions: Option<Vec<NvdDescription>>,
    pub metrics: Option<NvdMetrics>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    pub cvss_v31: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    pub cvss_v30: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    pub cvss_v2: Option<Vec<CvssMetric>>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct CvssMetric {
    #[serde(rename = "cvssData")]
    pub cvss_data: Option<CvssData>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct CvssData {
    #[serde(rename = "baseScore")]
    pub base_score: Option<f32>,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
}

/// NVD API response
#[derive(Deserialize)]
#[allow(dead_code)]
struct NvdResponse {
    vulnerabilities: Option<Vec<NvdVulnerability>>,
    #[serde(rename = "resultsPerPage")]
    results_per_page: Option<u32>,
    #[serde(rename = "startIndex")]
    start_index: Option<u32>,
    #[serde(rename = "totalResults")]
    total_results: Option<u32>,
}

#[derive(Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

/// NVD API client
pub struct NvdClient {
    client: Client,
    api_key: Option<String>,
}

impl NvdClient {
    /// Create a new NVD client
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-cve/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
            api_key,
        }
    }

    /// Fetch CVEs modified in the last duration
    pub async fn fetch_recent(&self, since: std::time::Duration) -> Result<Vec<NvdCve>> {
        let now = Utc::now();
        let start = now - Duration::from_std(since)?;

        self.fetch_modified_between(start, now).await
    }

    /// Fetch CVEs modified between two dates
    pub async fn fetch_modified_between(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<NvdCve>> {
        let mut all_cves = Vec::new();
        let mut start_index = 0;

        loop {
            let mut url = format!(
                "{}?lastModStartDate={}&lastModEndDate={}&startIndex={}",
                NVD_API_URL,
                start.format("%Y-%m-%dT%H:%M:%S.000"),
                end.format("%Y-%m-%dT%H:%M:%S.000"),
                start_index
            );

            // Filter to npm/node-related CVEs (keyword search)
            url.push_str("&keywordSearch=npm%20OR%20node.js%20OR%20nodejs");

            let mut request = self.client.get(&url);

            if let Some(key) = &self.api_key {
                request = request.header("apiKey", key);
            }

            let response = request.send().await?;

            if !response.status().is_success() {
                tracing::warn!(
                    "NVD API error: {} - {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
                break;
            }

            let nvd_response: NvdResponse = response.json().await?;

            let vulnerabilities = nvd_response.vulnerabilities.unwrap_or_default();
            let count = vulnerabilities.len();

            for vuln in vulnerabilities {
                all_cves.push(vuln.cve);
            }

            let total_results = nvd_response.total_results.unwrap_or(0) as usize;

            // Check if there are more pages
            if all_cves.len() >= total_results || count == 0 {
                break;
            }

            start_index += count as u32;

            // Rate limiting (6 requests per minute without API key, 50 with)
            let delay = if self.api_key.is_some() {
                std::time::Duration::from_millis(200)
            } else {
                std::time::Duration::from_secs(10)
            };
            tokio::time::sleep(delay).await;
        }

        Ok(all_cves)
    }
}
