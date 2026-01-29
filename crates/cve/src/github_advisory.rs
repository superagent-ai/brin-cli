//! GitHub Security Advisory client

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

const GITHUB_GRAPHQL_URL: &str = "https://api.github.com/graphql";

/// GitHub Advisory
#[derive(Debug, Clone, Deserialize)]
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
pub struct GitHubVulnerability {
    pub package_name: String,
    pub vulnerable_version_range: String,
    pub first_patched_version: Option<String>,
}

/// GraphQL response
#[derive(Deserialize)]
struct GraphQLResponse {
    data: Option<GraphQLData>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Deserialize)]
struct GraphQLData {
    #[serde(rename = "securityAdvisories")]
    security_advisories: SecurityAdvisories,
}

#[derive(Deserialize)]
struct SecurityAdvisories {
    nodes: Vec<AdvisoryNode>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Deserialize)]
struct AdvisoryNode {
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    summary: String,
    description: Option<String>,
    severity: String,
    #[serde(rename = "publishedAt")]
    published_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: Option<String>,
    identifiers: Vec<Identifier>,
    vulnerabilities: Vulnerabilities,
}

#[derive(Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    id_type: String,
    value: String,
}

#[derive(Deserialize)]
struct Vulnerabilities {
    nodes: Vec<VulnerabilityNode>,
}

#[derive(Deserialize)]
struct VulnerabilityNode {
    package: Package,
    #[serde(rename = "vulnerableVersionRange")]
    vulnerable_version_range: String,
    #[serde(rename = "firstPatchedVersion")]
    first_patched_version: Option<FirstPatchedVersion>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct FirstPatchedVersion {
    identifier: String,
}

#[derive(Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
struct GraphQLError {
    message: String,
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

    /// Fetch npm security advisories from GitHub
    pub async fn fetch_npm_advisories(&self) -> Result<Vec<GitHubAdvisory>> {
        let Some(token) = &self.token else {
            tracing::debug!("No GitHub token, skipping GitHub Advisory fetch");
            return Ok(vec![]);
        };

        let mut all_advisories = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let query = self.build_query(cursor.as_deref());

            let response = self
                .client
                .post(GITHUB_GRAPHQL_URL)
                .header("Authorization", format!("Bearer {}", token))
                .json(&serde_json::json!({ "query": query }))
                .send()
                .await?;

            if !response.status().is_success() {
                tracing::warn!(
                    "GitHub GraphQL error: {} - {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
                break;
            }

            let graphql_response: GraphQLResponse = response.json().await?;

            if let Some(errors) = graphql_response.errors {
                for error in errors {
                    tracing::warn!("GitHub GraphQL error: {}", error.message);
                }
                break;
            }

            let Some(data) = graphql_response.data else {
                break;
            };

            let advisories = &data.security_advisories;

            for node in &advisories.nodes {
                let advisory = self.convert_node(node);
                all_advisories.push(advisory);
            }

            if !advisories.page_info.has_next_page {
                break;
            }

            cursor = advisories.page_info.end_cursor.clone();

            // Rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Limit total advisories
            if all_advisories.len() > 5000 {
                tracing::warn!("Reached advisory limit, stopping pagination");
                break;
            }
        }

        Ok(all_advisories)
    }

    /// Build GraphQL query
    fn build_query(&self, cursor: Option<&str>) -> String {
        let after = cursor
            .map(|c| format!(", after: \"{}\"", c))
            .unwrap_or_default();

        format!(
            r#"
            query {{
                securityAdvisories(
                    first: 100
                    ecosystem: NPM
                    orderBy: {{ field: UPDATED_AT, direction: DESC }}
                    {}
                ) {{
                    nodes {{
                        ghsaId
                        summary
                        description
                        severity
                        publishedAt
                        updatedAt
                        identifiers {{
                            type
                            value
                        }}
                        vulnerabilities(first: 20) {{
                            nodes {{
                                package {{
                                    name
                                    ecosystem
                                }}
                                vulnerableVersionRange
                                firstPatchedVersion {{
                                    identifier
                                }}
                            }}
                        }}
                    }}
                    pageInfo {{
                        hasNextPage
                        endCursor
                    }}
                }}
            }}
            "#,
            after
        )
    }

    /// Convert GraphQL node to GitHubAdvisory
    fn convert_node(&self, node: &AdvisoryNode) -> GitHubAdvisory {
        let cve_id = node
            .identifiers
            .iter()
            .find(|id| id.id_type == "CVE")
            .map(|id| id.value.clone());

        let vulnerabilities = node
            .vulnerabilities
            .nodes
            .iter()
            .filter(|v| v.package.ecosystem == "NPM")
            .map(|v| GitHubVulnerability {
                package_name: v.package.name.clone(),
                vulnerable_version_range: v.vulnerable_version_range.clone(),
                first_patched_version: v
                    .first_patched_version
                    .as_ref()
                    .map(|fp| fp.identifier.clone()),
            })
            .collect();

        GitHubAdvisory {
            ghsa_id: node.ghsa_id.clone(),
            cve_id,
            summary: node.summary.clone(),
            description: node.description.clone(),
            severity: node.severity.clone(),
            published_at: node.published_at.clone(),
            updated_at: node.updated_at.clone(),
            vulnerabilities,
        }
    }
}
