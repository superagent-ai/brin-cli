//! sus API Server

mod handlers;
mod routes;

use anyhow::Result;
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use sus_common::{Database, ScanQueue};
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
                .unwrap_or_else(|_| "sus_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Database connection
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://sus:sus@localhost:5432/sus".to_string());

    tracing::info!("Connecting to database...");
    let db = Database::new(&database_url).await?;

    // Run migrations
    tracing::info!("Running migrations...");
    db.migrate().await?;

    // Redis connection
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    tracing::info!("Connecting to Redis...");
    let queue = ScanQueue::new(&redis_url).await?;

    // Create app state
    let state = Arc::new(AppState { db, queue });

    // Build router
    let app = Router::new()
        .merge(routes::health_routes())
        .merge(routes::package_routes())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive());

    // Start server
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
