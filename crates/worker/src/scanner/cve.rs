//! CVE scanning using OSV (Open Source Vulnerabilities)

use anyhow::Result;
use common::CveSummary;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// OSV API request
#[derive(Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// OSV API response
#[derive(Deserialize)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVulnerability>>,
}

#[derive(Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    score: Option<String>,
}

#[derive(Deserialize)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Deserialize)]
struct OsvRange {
    events: Option<Vec<OsvEvent>>,
}

#[derive(Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

/// CVE scanner using OSV database
pub struct CveScanner {
    client: Client,
    osv_url: String,
}

impl CveScanner {
    /// Create a new CVE scanner
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-worker/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
            osv_url: "https://api.osv.dev/v1".to_string(),
        }
    }

    /// Scan for CVEs affecting a package version (defaults to npm ecosystem)
    pub async fn scan(&self, package: &str, version: &str) -> Result<Vec<CveSummary>> {
        self.scan_with_ecosystem(package, version, "npm").await
    }

    /// Scan for CVEs affecting a package version with a specific ecosystem
    pub async fn scan_with_ecosystem(
        &self,
        package: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<CveSummary>> {
        let url = format!("{}/query", self.osv_url);

        let request = OsvQueryRequest {
            package: OsvPackage {
                name: package.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: version.to_string(),
        };

        tracing::debug!(
            package,
            version,
            ecosystem,
            "Querying OSV for vulnerabilities"
        );

        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            tracing::warn!(
                "OSV query failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
            return Ok(vec![]);
        }

        let osv_response: OsvQueryResponse = response.json().await?;

        let vulns = osv_response.vulns.unwrap_or_default();

        if !vulns.is_empty() {
            tracing::info!(
                package,
                version,
                ecosystem,
                count = vulns.len(),
                "Found vulnerabilities"
            );
        }

        let cves: Vec<CveSummary> = vulns
            .into_iter()
            .map(|vuln| {
                // Extract severity
                let severity = vuln
                    .severity
                    .as_ref()
                    .and_then(|severities| severities.first())
                    .and_then(|s| {
                        // Try to map CVSS score to severity level
                        if let Some(score) = &s.score {
                            if let Ok(score_f) = score.parse::<f32>() {
                                return Some(cvss_to_severity(score_f));
                            }
                        }
                        None
                    });

                // Extract fixed version
                let fixed_in = vuln
                    .affected
                    .as_ref()
                    .and_then(|affected| affected.first())
                    .and_then(|a| a.ranges.as_ref())
                    .and_then(|ranges| ranges.first())
                    .and_then(|r| r.events.as_ref())
                    .and_then(|events| events.iter().find_map(|e| e.fixed.clone()));

                // Use summary or first part of details for description
                let description = vuln.summary.or_else(|| {
                    vuln.details.as_ref().map(|d| {
                        if d.len() > 200 {
                            format!("{}...", &d[..197])
                        } else {
                            d.clone()
                        }
                    })
                });

                CveSummary {
                    cve_id: vuln.id,
                    severity,
                    description,
                    fixed_in,
                }
            })
            .collect();

        Ok(cves)
    }
}

/// Convert CVSS score to severity label
fn cvss_to_severity(score: f32) -> String {
    match score {
        s if s >= 9.0 => "CRITICAL".to_string(),
        s if s >= 7.0 => "HIGH".to_string(),
        s if s >= 4.0 => "MEDIUM".to_string(),
        s if s >= 0.1 => "LOW".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cvss_to_severity() {
        assert_eq!(cvss_to_severity(9.5), "CRITICAL");
        assert_eq!(cvss_to_severity(7.5), "HIGH");
        assert_eq!(cvss_to_severity(5.0), "MEDIUM");
        assert_eq!(cvss_to_severity(2.0), "LOW");
    }
}
