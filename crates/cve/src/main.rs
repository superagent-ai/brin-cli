//! sus CVE Enrichment Worker - keeps CVE data fresh

mod github_advisory;
#[allow(dead_code)]
mod nvd; // NVD disabled - requires API key
mod osv;

use anyhow::Result;
use axum::{routing::get, Json, Router};
use common::{Database, NewPackageCve};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
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
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sus:sus@localhost:5432/sus".to_string());

    tracing::info!("Connecting to database...");
    let db = Arc::new(Database::new(&database_url).await?);

    // API keys (NVD disabled - requires paid API key)
    let github_token = std::env::var("GITHUB_TOKEN").ok().filter(|s| !s.is_empty());

    if github_token.is_none() {
        tracing::warn!("GITHUB_TOKEN not set, GitHub Advisory enrichment will be skipped");
    }

    // Create clients (OSV is free, GitHub requires token)
    let osv_client = osv::OsvClient::new();
    let github_client = github_advisory::GitHubAdvisoryClient::new(github_token);

    tracing::info!("CVE enrichment worker started");

    // Spawn the CVE loop in the background
    let db_clone = Arc::clone(&db);
    tokio::spawn(async move {
        cve_loop(db_clone, osv_client, github_client).await;
    });

    // Start health check server (required for Cloud Run)
    let app = Router::new().route("/health", get(health_check));
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Health server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn cve_loop(
    db: Arc<Database>,
    osv_client: osv::OsvClient,
    github_client: github_advisory::GitHubAdvisoryClient,
) {
    loop {
        tracing::info!("Starting CVE enrichment cycle");

        // Get all packages from database
        let packages = match db.get_all_packages().await {
            Ok(pkgs) => pkgs,
            Err(e) => {
                tracing::error!("Failed to get packages from database: {}", e);
                vec![]
            }
        };

        if packages.is_empty() {
            tracing::info!("No packages in database to check for CVEs");
        } else {
            tracing::info!("Checking {} packages for CVEs", packages.len());

            // Prepare package list for OSV
            let package_list: Vec<(String, String)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone()))
                .collect();

            // Fetch from OSV for our packages
            match osv_client
                .fetch_advisories_for_packages(&package_list)
                .await
            {
                Ok(advisories) => {
                    tracing::info!("Fetched {} OSV advisories", advisories.len());

                    // Store CVEs for affected packages
                    for advisory in &advisories {
                        if let Some(affected) = &advisory.affected {
                            for affected_pkg in affected {
                                if let Some(pkg_info) = &affected_pkg.package {
                                    if pkg_info.ecosystem.as_deref() == Some("npm") {
                                        if let Some(pkg_name) = &pkg_info.name {
                                            // Find matching package in our database
                                            if let Some(db_pkg) =
                                                packages.iter().find(|p| &p.name == pkg_name)
                                            {
                                                let severity = advisory
                                                    .severity
                                                    .as_ref()
                                                    .and_then(|s| s.first())
                                                    .and_then(|s| s.score.clone());

                                                let fixed_in = affected_pkg
                                                    .ranges
                                                    .as_ref()
                                                    .and_then(|r| r.first())
                                                    .and_then(|r| r.events.as_ref())
                                                    .and_then(|e| {
                                                        e.iter().find_map(|ev| ev.fixed.clone())
                                                    });

                                                let cve = NewPackageCve {
                                                    package_id: db_pkg.id,
                                                    cve_id: advisory.id.clone(),
                                                    severity,
                                                    description: advisory
                                                        .summary
                                                        .clone()
                                                        .or_else(|| advisory.details.clone()),
                                                    fixed_in,
                                                    published_at: advisory
                                                        .published
                                                        .as_ref()
                                                        .and_then(|s| {
                                                            chrono::DateTime::parse_from_rfc3339(s)
                                                                .ok()
                                                        })
                                                        .map(|dt| dt.with_timezone(&chrono::Utc)),
                                                };

                                                if let Err(e) = db.insert_cve(&cve).await {
                                                    tracing::debug!(
                                                        "Failed to insert CVE {} for {}: {}",
                                                        advisory.id,
                                                        pkg_name,
                                                        e
                                                    );
                                                } else {
                                                    tracing::info!(
                                                        "Added CVE {} for {}",
                                                        advisory.id,
                                                        pkg_name
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to fetch OSV advisories: {}", e);
                }
            }

            // Fetch from GitHub Advisory
            match github_client.fetch_npm_advisories().await {
                Ok(advisories) => {
                    tracing::info!("Fetched {} GitHub advisories", advisories.len());

                    for advisory in &advisories {
                        for vuln in &advisory.vulnerabilities {
                            // Check if this package is in our database
                            if let Some(db_pkg) =
                                packages.iter().find(|p| p.name == vuln.package_name)
                            {
                                let cve_id = advisory
                                    .cve_id
                                    .clone()
                                    .unwrap_or_else(|| advisory.ghsa_id.clone());

                                let cve = NewPackageCve {
                                    package_id: db_pkg.id,
                                    cve_id,
                                    severity: Some(advisory.severity.clone()),
                                    description: Some(advisory.summary.clone()),
                                    fixed_in: vuln.first_patched_version.clone(),
                                    published_at: chrono::DateTime::parse_from_rfc3339(
                                        &advisory.published_at,
                                    )
                                    .ok()
                                    .map(|dt| dt.with_timezone(&chrono::Utc)),
                                };

                                if let Err(e) = db.insert_cve(&cve).await {
                                    tracing::debug!(
                                        "Failed to insert CVE {} for {}: {}",
                                        cve.cve_id,
                                        vuln.package_name,
                                        e
                                    );
                                } else {
                                    tracing::info!(
                                        "Added CVE {} for {}",
                                        cve.cve_id,
                                        vuln.package_name
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to fetch GitHub advisories: {}", e);
                }
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
