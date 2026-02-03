//! sus Scan Worker - processes package scan jobs from the queue

mod scanner;
mod skill_generator;

use anyhow::Result;
use axum::{routing::get, Json, Router};
use common::{Database, Registry, ScanQueue};
use scanner::{AgenticScanner, PackageScanner};
use std::net::SocketAddr;
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

    // Try to ensure OpenCode is installed (used for agentic threat detection)
    // If it fails, continue anyway - scans will work without agentic analysis
    tracing::info!("Checking OpenCode installation...");
    if let Err(e) = AgenticScanner::ensure_installed().await {
        tracing::warn!(
            "OpenCode installation failed (agentic analysis will be disabled): {}",
            e
        );
    }

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

    // Spawn the worker loop in the background
    tokio::spawn(async move {
        worker_loop(queue, scanner).await;
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

async fn worker_loop(queue: ScanQueue, scanner: PackageScanner) {
    tracing::info!("Worker loop starting...");
    loop {
        tracing::debug!("Polling queue for jobs...");
        match queue.pop().await {
            Ok(Some(job)) => {
                let _is_tarball = job.tarball_path.is_some();
                tracing::info!(
                    job_id = %job.id,
                    package = %job.package,
                    version = ?job.version,
                    registry = ?job.registry,
                    tarball = ?job.tarball_path,
                    "Processing scan job"
                );

                let start = std::time::Instant::now();

                // Handle tarball jobs vs registry jobs based on registry type
                let scan_result = if let Some(tarball_path) = &job.tarball_path {
                    // Local tarball - determine type based on registry
                    match job.registry {
                        Registry::Pypi => {
                            scanner
                                .scan_pypi_tarball(std::path::Path::new(tarball_path))
                                .await
                        }
                        _ => {
                            // Default to npm for tarballs
                            scanner
                                .scan_tarball(std::path::Path::new(tarball_path))
                                .await
                        }
                    }
                } else {
                    // Remote registry scan
                    match job.registry {
                        Registry::Npm => scanner.scan(&job.package, job.version.as_deref()).await,
                        Registry::Pypi => {
                            scanner
                                .scan_pypi(&job.package, job.version.as_deref())
                                .await
                        }
                        Registry::Crates => {
                            // TODO: Implement crates.io support
                            tracing::warn!(
                                package = %job.package,
                                "Crates.io registry not yet supported"
                            );
                            Err(anyhow::anyhow!("Crates.io registry not yet supported"))
                        }
                    }
                };

                match scan_result {
                    Ok(result) => {
                        tracing::info!(
                            package = %job.package,
                            registry = ?job.registry,
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
                            registry = ?job.registry,
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
