//! API routes

use crate::handlers;
use crate::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

/// Health check routes
pub fn health_routes() -> Router<Arc<AppState>> {
    Router::new().route("/health", get(handlers::health_check))
}

/// Package-related routes
pub fn package_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/packages", get(handlers::list_packages))
        .route("/v1/packages/{name}", get(handlers::get_package))
        .route(
            "/v1/packages/{name}/{version}",
            get(handlers::get_package_version),
        )
        .route("/v1/scan", post(handlers::request_scan))
        .route("/v1/scan/tarball", post(handlers::scan_tarball))
        .route("/v1/bulk", post(handlers::bulk_lookup))
}
