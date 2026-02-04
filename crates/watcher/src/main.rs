//! sus Registry Watcher - monitors npm and PyPI for package updates
//!
//! Uses a sweep-based approach: iterates through all tracked packages in the database
//! and checks each one against its registry for version updates. Rate-limited to
//! ~100 packages/minute to avoid hitting API rate limits.

mod registry;

use anyhow::Result;
use axum::{routing::get, Json, Router};
use common::{Database, Registry, ScanJob, ScanPriority, ScanQueue};
use registry::RegistryClient;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Package info for version comparison
#[derive(Debug, Clone)]
struct TrackedPackage {
    name: String,
    version: String,
    registry: Registry,
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
    let db = Arc::new(Database::new(&database_url).await?);

    // Redis connection
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    tracing::info!("Connecting to Redis...");
    let queue = ScanQueue::new(&redis_url).await?;

    // Create registry client
    let registry_client = Arc::new(RegistryClient::new());

    // Get package counts
    let npm_count = db.get_package_names_by_registry(Registry::Npm).await?.len();
    let pypi_count = db
        .get_package_names_by_registry(Registry::Pypi)
        .await?
        .len();

    tracing::info!(
        "Watcher started (tracking {} npm, {} pypi packages)",
        npm_count,
        pypi_count
    );

    // Rate limit: packages per minute (default 100)
    let packages_per_minute: u64 = std::env::var("PACKAGES_PER_MINUTE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    // Spawn the sweep loop
    let db_sweep = Arc::clone(&db);
    let client_sweep = Arc::clone(&registry_client);
    tokio::spawn(async move {
        sweep_loop(db_sweep, queue, client_sweep, packages_per_minute).await;
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

/// Main sweep loop - continuously checks all packages for updates
async fn sweep_loop(
    db: Arc<Database>,
    queue: ScanQueue,
    client: Arc<RegistryClient>,
    packages_per_minute: u64,
) {
    // Calculate delay between package checks
    let delay_ms = 60_000 / packages_per_minute;

    loop {
        tracing::info!("Starting new sweep cycle...");

        // Get all packages with their current versions
        let packages = match get_tracked_packages(&db).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to load tracked packages: {}", e);
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
        };

        let total_packages = packages.len();
        tracing::info!(
            "Sweeping {} packages ({} per minute)",
            total_packages,
            packages_per_minute
        );

        let mut checked = 0;
        let mut updates_found = 0;
        let mut errors = 0;
        let sweep_start = std::time::Instant::now();

        for package in &packages {
            // Check for version update
            match check_package_update(&client, &queue, package).await {
                Ok(true) => {
                    updates_found += 1;
                    tracing::info!(
                        "[{}] {} {} -> new version available",
                        package.registry,
                        package.name,
                        package.version
                    );
                }
                Ok(false) => {
                    // No update
                }
                Err(e) => {
                    tracing::debug!(
                        "[{}] {} - error checking: {}",
                        package.registry,
                        package.name,
                        e
                    );
                    errors += 1;
                }
            }

            checked += 1;

            // Log progress every 500 packages
            if checked % 500 == 0 {
                let elapsed = sweep_start.elapsed().as_secs();
                tracing::info!(
                    "Progress: {}/{} checked, {} updates found, {} errors ({} seconds elapsed)",
                    checked,
                    total_packages,
                    updates_found,
                    errors,
                    elapsed
                );
            }

            // Rate limit
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let sweep_duration = sweep_start.elapsed();
        tracing::info!(
            "Sweep complete: {} packages checked, {} updates queued, {} errors ({:.1} minutes)",
            checked,
            updates_found,
            errors,
            sweep_duration.as_secs_f64() / 60.0
        );

        // Small pause between sweeps
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Get all tracked packages with their current versions from the database
async fn get_tracked_packages(db: &Database) -> Result<Vec<TrackedPackage>> {
    // Get latest version of each unique package
    let packages = db.get_all_packages_latest_version().await?;

    Ok(packages
        .into_iter()
        .map(|p| TrackedPackage {
            name: p.name,
            version: p.version,
            registry: p.registry,
        })
        .collect())
}

/// Check if a package has an update available
/// Returns true if update was found and queued
async fn check_package_update(
    client: &RegistryClient,
    queue: &ScanQueue,
    package: &TrackedPackage,
) -> Result<bool> {
    // Fetch latest version from registry
    let latest = client
        .get_latest_version(&package.name, package.registry)
        .await?;

    let Some(latest_version) = latest else {
        // Package not found on registry (might have been deleted)
        return Ok(false);
    };

    // Compare versions
    if latest_version == package.version {
        // No update
        return Ok(false);
    }

    // New version available - queue for scan
    let job = ScanJob {
        id: uuid::Uuid::new_v4(),
        package: package.name.clone(),
        version: Some(latest_version),
        registry: package.registry,
        priority: ScanPriority::Medium,
        requested_at: chrono::Utc::now(),
        requested_by: Some("watcher".to_string()),
        tarball_path: None,
    };

    queue.push(job).await?;

    Ok(true)
}
