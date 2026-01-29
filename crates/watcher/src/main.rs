//! sus npm Registry Watcher - monitors npm for new packages and updates

mod npm_changes;

use anyhow::Result;
use axum::{routing::get, Json, Router};
use common::{ScanJob, ScanPriority, ScanQueue};
use npm_changes::NpmWatcher;
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
                .unwrap_or_else(|_| "sus_watcher=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Redis connection
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    tracing::info!("Connecting to Redis...");
    let queue = ScanQueue::new(&redis_url).await?;

    // Create watcher
    let watcher = NpmWatcher::new();

    tracing::info!("npm watcher started");

    // Spawn the watcher loop in the background
    tokio::spawn(async move {
        watcher_loop(queue, watcher).await;
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

async fn watcher_loop(queue: ScanQueue, watcher: NpmWatcher) {
    loop {
        match watcher.poll().await {
            Ok(changes) => {
                if !changes.is_empty() {
                    tracing::info!("Received {} package changes", changes.len());

                    for change in changes {
                        let priority = calculate_priority(&change);

                        let job = ScanJob {
                            id: uuid::Uuid::new_v4(),
                            package: change.name,
                            version: change.version,
                            priority,
                            requested_at: chrono::Utc::now(),
                            requested_by: Some("watcher".to_string()),
                            tarball_path: None,
                        };

                        if let Err(e) = queue.push(job).await {
                            tracing::error!("Failed to queue scan job: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to poll npm changes: {}", e);
            }
        }

        // Wait before next poll
        let poll_interval = std::env::var("POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
    }
}

/// Calculate scan priority based on package metadata
fn calculate_priority(change: &npm_changes::PackageChange) -> ScanPriority {
    // Check for known malicious patterns (immediate)
    let malicious_patterns = [
        "crossenv",
        "cross-env.js",
        "mongose",
        "babelcli",
        "nodejs-base64",
    ];

    if malicious_patterns.iter().any(|p| change.name.contains(p)) {
        return ScanPriority::Immediate;
    }

    // Otherwise use medium priority for watcher-discovered packages
    // (user-requested scans get High priority)
    ScanPriority::Medium
}
