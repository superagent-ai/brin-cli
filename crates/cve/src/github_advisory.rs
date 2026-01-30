//! GitHub Security Advisory client

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

const GITHUB_API_URL: &str = "https://api.github.com";

/// GitHub Advisory
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GitHubAdvisory {
    pub ghsa_id: String,
    pub cve_id: Option<String>,
    pub summary: String,
    pub description: Option<String>,
    pub severity: String,
    pub published_at: String,
    pub updated_at: Option<String>,
    pub vulnerabilities: Vec<GitHubVulnerability>,
}

/// Vulnerability info from GitHub
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GitHubVulnerability {
    pub package_name: String,
    pub vulnerable_version_range: String,
    pub first_patched_version: Option<String>,
}

/// REST API response for a single advisory
#[derive(Deserialize)]
struct RestAdvisory {
    ghsa_id: String,
    cve_id: Option<String>,
    summary: String,
    description: Option<String>,
    severity: String,
    published_at: String,
    updated_at: Option<String>,
    vulnerabilities: Vec<RestVulnerability>,
}

/// Vulnerability in REST API response
#[derive(Deserialize)]
struct RestVulnerability {
    package: RestPackage,
    vulnerable_version_range: String,
    first_patched_version: Option<String>,
}

#[derive(Deserialize)]
struct RestPackage {
    ecosystem: String,
    name: String,
}

/// GitHub Advisory client
pub struct GitHubAdvisoryClient {
    client: Client,
    token: Option<String>,
}

impl GitHubAdvisoryClient {
    /// Create a new GitHub Advisory client
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-cve/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
            token,
        }
    }

    /// Fetch npm security advisories from GitHub using REST API
    pub async fn fetch_npm_advisories(&self) -> Result<Vec<GitHubAdvisory>> {
        let Some(token) = &self.token else {
            tracing::debug!("No GitHub token, skipping GitHub Advisory fetch");
            return Ok(vec![]);
        };

        let mut all_advisories = Vec::new();
        let mut page = 1;
        let per_page = 100;

        loop {
            // Use REST API endpoint for security advisories
            let url = format!(
                "{}/advisories?ecosystem=npm&per_page={}&page={}",
                GITHUB_API_URL, per_page, page
            );

            tracing::debug!("Fetching GitHub advisories page {}", page);

            let response = match self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("GitHub REST API request failed: {}", e);
                    break;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                tracing::warn!("GitHub REST API error: {} - {}", status, body);
                break;
            }

            let advisories: Vec<RestAdvisory> = match response.json().await {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!("Failed to parse GitHub advisories response: {}", e);
                    break;
                }
            };

            let count = advisories.len();
            tracing::debug!("Received {} advisories from page {}", count, page);

            for advisory in advisories {
                // Filter to npm vulnerabilities only
                let npm_vulns: Vec<GitHubVulnerability> = advisory
                    .vulnerabilities
                    .into_iter()
                    .filter(|v| v.package.ecosystem.to_lowercase() == "npm")
                    .map(|v| GitHubVulnerability {
                        package_name: v.package.name,
                        vulnerable_version_range: v.vulnerable_version_range,
                        first_patched_version: v.first_patched_version,
                    })
                    .collect();

                if !npm_vulns.is_empty() {
                    all_advisories.push(GitHubAdvisory {
                        ghsa_id: advisory.ghsa_id,
                        cve_id: advisory.cve_id,
                        summary: advisory.summary,
                        description: advisory.description,
                        severity: advisory.severity,
                        published_at: advisory.published_at,
                        updated_at: advisory.updated_at,
                        vulnerabilities: npm_vulns,
                    });
                }
            }

            // Check if we should continue pagination
            if count < per_page {
                break;
            }

            page += 1;

            // Safety limit
            if page > 100 || all_advisories.len() > 10000 {
                tracing::warn!("Reached advisory limit, stopping pagination");
                break;
            }

            // Rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        tracing::info!("GitHub: fetched {} npm advisories", all_advisories.len());
        Ok(all_advisories)
    }
}
