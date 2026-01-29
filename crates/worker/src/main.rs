//! sus Scan Worker - processes package scan jobs from the queue

mod scanner;
mod skill_generator;

use anyhow::Result;
use common::{Database, ScanQueue};
use scanner::{AgenticScanner, PackageScanner};
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
                .unwrap_or_else(|_| "sus_worker=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Ensure OpenCode is installed (used for agentic threat detection)
    tracing::info!("Checking OpenCode installation...");
    AgenticScanner::ensure_installed().await?;

    // Database connection
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sus:sus@localhost:5433/sus".to_string());

    tracing::info!("Connecting to database...");
    let db = Database::new(&database_url).await?;

    // Redis connection
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    tracing::info!("Connecting to Redis...");
    let queue = ScanQueue::new(&redis_url).await?;

    // Create scanner (OpenCode handles its own API key configuration)
    let scanner = PackageScanner::new(db.clone());

    tracing::info!("Worker started, waiting for jobs...");

    // Main processing loop
    loop {
        match queue.pop().await {
            Ok(Some(job)) => {
                let _is_tarball = job.tarball_path.is_some();
                tracing::info!(
                    job_id = %job.id,
                    package = %job.package,
                    version = ?job.version,
                    tarball = ?job.tarball_path,
                    "Processing scan job"
                );

                let start = std::time::Instant::now();

                // Handle tarball jobs vs npm registry jobs
                let scan_result = if let Some(tarball_path) = &job.tarball_path {
                    scanner
                        .scan_tarball(std::path::Path::new(tarball_path))
                        .await
                } else {
                    scanner.scan(&job.package, job.version.as_deref()).await
                };

                match scan_result {
                    Ok(result) => {
                        tracing::info!(
                            package = %job.package,
                            risk_level = ?result.risk_level,
                            duration_ms = start.elapsed().as_millis(),
                            "Scan completed"
                        );

                        // Clean up tarball file after successful scan
                        if let Some(tarball_path) = &job.tarball_path {
                            if let Err(e) = std::fs::remove_file(tarball_path) {
                                tracing::warn!(path = %tarball_path, error = %e, "Failed to clean up tarball");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            package = %job.package,
                            error = %e,
                            "Scan failed"
                        );

                        // Clean up tarball file even on failure
                        if let Some(tarball_path) = &job.tarball_path {
                            let _ = std::fs::remove_file(tarball_path);
                        }
                    }
                }
            }
            Ok(None) => {
                // No jobs available, wait before polling again
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                tracing::error!("Failed to pop job from queue: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
