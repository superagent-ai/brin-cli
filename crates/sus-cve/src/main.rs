//! sus CVE Enrichment Worker - keeps CVE data fresh

mod github_advisory;
mod nvd;
mod osv;

use anyhow::Result;
use std::time::Duration;
use sus_common::Database;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sus_cve=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Database connection
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://sus:sus@localhost:5432/sus".to_string());

    tracing::info!("Connecting to database...");
    let db = Database::new(&database_url).await?;

    // API keys
    let nvd_api_key = std::env::var("NVD_API_KEY").ok();
    let github_token = std::env::var("GITHUB_TOKEN").ok();

    if nvd_api_key.is_none() {
        tracing::warn!("NVD_API_KEY not set, NVD enrichment will be rate-limited");
    }
    if github_token.is_none() {
        tracing::warn!("GITHUB_TOKEN not set, GitHub Advisory enrichment will be rate-limited");
    }

    // Create clients
    let osv_client = osv::OsvClient::new();
    let nvd_client = nvd::NvdClient::new(nvd_api_key);
    let github_client = github_advisory::GitHubAdvisoryClient::new(github_token);

    tracing::info!("CVE enrichment worker started");

    // Main enrichment loop
    loop {
        tracing::info!("Starting CVE enrichment cycle");

        // Fetch from OSV
        match osv_client.fetch_npm_advisories().await {
            Ok(advisories) => {
                tracing::info!("Fetched {} OSV advisories", advisories.len());
                // TODO: Store advisories and update affected packages
            }
            Err(e) => {
                tracing::error!("Failed to fetch OSV advisories: {}", e);
            }
        }

        // Fetch from NVD (recent)
        match nvd_client.fetch_recent(Duration::from_secs(3600)).await {
            Ok(cves) => {
                tracing::info!("Fetched {} recent NVD CVEs", cves.len());
                // TODO: Correlate with npm packages
            }
            Err(e) => {
                tracing::error!("Failed to fetch NVD CVEs: {}", e);
            }
        }

        // Fetch from GitHub Advisory
        match github_client.fetch_npm_advisories().await {
            Ok(advisories) => {
                tracing::info!("Fetched {} GitHub advisories", advisories.len());
                // TODO: Store and correlate
            }
            Err(e) => {
                tracing::error!("Failed to fetch GitHub advisories: {}", e);
            }
        }

        // Wait before next cycle
        let interval_mins = std::env::var("CVE_POLL_INTERVAL_MINS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        tracing::info!(
            "CVE enrichment cycle complete, sleeping for {} minutes",
            interval_mins
        );

        tokio::time::sleep(Duration::from_secs(interval_mins * 60)).await;
    }
}
