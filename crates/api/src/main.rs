//! brin API Server

mod handlers;
mod routes;

use anyhow::Result;
use axum::{routing::get, Json, Router};
use common::{Database, ScanQueue};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub queue: ScanQueue,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "brin_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Start a minimal health check server FIRST (for Cloud Run)
    let health_app = Router::new().route(
        "/health",
        get(|| async { Json(json!({ "status": "starting" })) }),
    );
    let health_listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Health server listening on {}", addr);

    // Spawn health server in background while we initialize
    let health_handle = tokio::spawn(async move {
        let _ = axum::serve(health_listener, health_app).await;
    });

    // Database connection with retries
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://brin:brin@localhost:5432/brin".to_string());

    let db = loop {
        tracing::info!("Connecting to database...");
        match Database::new(&database_url).await {
            Ok(db) => break db,
            Err(e) => {
                tracing::warn!("Database connection failed: {}, retrying in 5s...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    // Run migrations
    tracing::info!("Running migrations...");
    db.migrate().await?;

    // Redis connection with retries
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let queue = loop {
        tracing::info!("Connecting to Redis...");
        match ScanQueue::new(&redis_url).await {
            Ok(queue) => break queue,
            Err(e) => {
                tracing::warn!("Redis connection failed: {}, retrying in 5s...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    // Stop health server and wait for socket to release
    health_handle.abort();
    let _ = health_handle.await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create app state
    let state = Arc::new(AppState { db, queue });

    // Build full router
    let app = Router::new()
        .merge(routes::health_routes())
        .merge(routes::package_routes())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive());

    // Start full server with retries for port binding
    tracing::info!("Starting API server on {}", addr);
    let listener = loop {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => break l,
            Err(e) => {
                tracing::warn!("Port {} not ready yet: {}, retrying...", port, e);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    };
    axum::serve(listener, app).await?;

    Ok(())
}
