//! sus npm Registry Watcher - monitors npm for new packages and updates
//!
//! Only watches for updates to packages that are already in the database.
//! Use the seed script to populate the initial set of tracked packages.

mod npm_changes;

use anyhow::Result;
use axum::{routing::get, Json, Router};
use common::{Database, ScanJob, ScanPriority, ScanQueue};
use npm_changes::NpmWatcher;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Cache of tracked package names, refreshed periodically
struct TrackedPackages {
    names: RwLock<HashSet<String>>,
    db: Database,
}

impl TrackedPackages {
    async fn new(db: Database) -> Result<Self> {
        let names = db.get_all_package_names().await?;
        let names_set: HashSet<String> = names.into_iter().collect();
        tracing::info!("Loaded {} tracked packages from database", names_set.len());

        Ok(Self {
            names: RwLock::new(names_set),
            db,
        })
    }

    /// Check if a package is tracked
    async fn contains(&self, name: &str) -> bool {
        let names = self.names.read().await;
        names.contains(name)
    }

    /// Refresh the cache from the database
    async fn refresh(&self) -> Result<()> {
        let names = self.db.get_all_package_names().await?;
        let names_set: HashSet<String> = names.into_iter().collect();
        let count = names_set.len();

        let mut cache = self.names.write().await;
        *cache = names_set;

        tracing::info!("Refreshed tracked packages cache: {} packages", count);
        Ok(())
    }

    /// Get the count of tracked packages
    async fn len(&self) -> usize {
        self.names.read().await.len()
    }
}

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

    // Database connection
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set - watcher needs DB to check tracked packages");

    tracing::info!("Connecting to database...");
    let db = Database::new(&database_url).await?;

    // Redis connection
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    tracing::info!("Connecting to Redis...");
    let queue = ScanQueue::new(&redis_url).await?;

    // Load tracked packages cache
    tracing::info!("Loading tracked packages...");
    let tracked = Arc::new(TrackedPackages::new(db).await?);

    // Create watcher
    let watcher = NpmWatcher::new();

    tracing::info!(
        "npm watcher started (watching {} packages)",
        tracked.len().await
    );

    // Spawn the cache refresh loop
    let tracked_refresh = Arc::clone(&tracked);
    tokio::spawn(async move {
        cache_refresh_loop(tracked_refresh).await;
    });

    // Spawn the watcher loop in the background
    let tracked_watcher = Arc::clone(&tracked);
    tokio::spawn(async move {
        watcher_loop(queue, watcher, tracked_watcher).await;
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

/// Periodically refresh the tracked packages cache
async fn cache_refresh_loop(tracked: Arc<TrackedPackages>) {
    // Refresh every 5 minutes
    let refresh_interval = std::env::var("CACHE_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    loop {
        tokio::time::sleep(Duration::from_secs(refresh_interval)).await;

        if let Err(e) = tracked.refresh().await {
            tracing::error!("Failed to refresh tracked packages cache: {}", e);
        }
    }
}

async fn watcher_loop(queue: ScanQueue, watcher: NpmWatcher, tracked: Arc<TrackedPackages>) {
    loop {
        match watcher.poll().await {
            Ok(changes) => {
                if !changes.is_empty() {
                    tracing::info!("Received {} package changes from npm", changes.len());

                    let mut queued = 0;
                    let mut skipped = 0;

                    for change in changes {
                        // Only queue if package is already tracked in our database
                        if !tracked.contains(&change.name).await {
                            tracing::debug!("Skipping untracked package: {}", change.name);
                            skipped += 1;
                            continue;
                        }

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
                        } else {
                            queued += 1;
                        }
                    }

                    if queued > 0 || skipped > 0 {
                        tracing::info!(
                            "Processed changes: {} queued, {} skipped (untracked)",
                            queued,
                            skipped
                        );
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
