//! API request handlers

use crate::AppState;
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use common::{
    AgenticThreatSummary, BulkLookupRequest, CveSummary, InstallScripts, PackageCapabilities,
    PackageResponse, PublisherInfo, ScanJob, ScanPriority, ScanRequest, ScanRequestResponse,
};
use serde_json::json;
use std::io::Write;
use std::sync::Arc;

/// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Get the latest scan for a package
pub async fn get_package(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<PackageResponse>, (StatusCode, Json<serde_json::Value>)> {
    // URL-decode the name (for scoped packages like @types%2Fnode)
    let name = urlencoding::decode(&name)
        .map(|s| s.into_owned())
        .unwrap_or(name);

    let package = state.db.get_latest_scan(&name).await.map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Database error" })),
        )
    })?;

    let package = package.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Package not found" })),
        )
    })?;

    // Fetch associated CVEs and threats
    let cves = state.db.get_package_cves(package.id).await.map_err(|e| {
        tracing::error!("Database error fetching CVEs: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Database error" })),
        )
    })?;

    let threats = state
        .db
        .get_package_threats(package.id)
        .await
        .map_err(|e| {
            tracing::error!("Database error fetching threats: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
        })?;

    // Build response
    let risk_reasons: Vec<String> =
        serde_json::from_value(package.risk_reasons.clone()).unwrap_or_default();

    let capabilities: PackageCapabilities =
        serde_json::from_value(package.capabilities.clone()).unwrap_or_default();

    let response = PackageResponse {
        name: package.name,
        version: package.version,
        risk_level: package.risk_level,
        risk_reasons,
        trust_score: package.trust_score.map(|s| s as u8),
        publisher: package.publisher_verified.map(|verified| PublisherInfo {
            name: None, // TODO: store publisher name in DB
            verified,
        }),
        weekly_downloads: package.weekly_downloads.map(|d| d as u64),
        install_scripts: InstallScripts::default(), // TODO: store in DB
        cves: cves
            .into_iter()
            .map(|c| CveSummary {
                cve_id: c.cve_id,
                severity: c.severity,
                description: c.description,
                fixed_in: c.fixed_in,
            })
            .collect(),
        agentic_threats: threats
            .into_iter()
            .map(|t| AgenticThreatSummary {
                threat_type: t.threat_type,
                confidence: t.confidence,
                location: t.location,
                snippet: t.snippet,
            })
            .collect(),
        capabilities,
        skill_md: package.skill_md,
        scanned_at: package.scanned_at,
    };

    Ok(Json(response))
}

/// Get a specific package version
pub async fn get_package_version(
    State(state): State<Arc<AppState>>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<PackageResponse>, (StatusCode, Json<serde_json::Value>)> {
    // URL-decode the name
    let name = urlencoding::decode(&name)
        .map(|s| s.into_owned())
        .unwrap_or(name);

    let package = state.db.get_scan(&name, &version).await.map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Database error" })),
        )
    })?;

    let package = package.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Package version not found" })),
        )
    })?;

    // Fetch associated CVEs and threats
    let cves = state
        .db
        .get_package_cves(package.id)
        .await
        .unwrap_or_default();
    let threats = state
        .db
        .get_package_threats(package.id)
        .await
        .unwrap_or_default();

    // Build response
    let risk_reasons: Vec<String> =
        serde_json::from_value(package.risk_reasons.clone()).unwrap_or_default();

    let capabilities: PackageCapabilities =
        serde_json::from_value(package.capabilities.clone()).unwrap_or_default();

    let response = PackageResponse {
        name: package.name,
        version: package.version,
        risk_level: package.risk_level,
        risk_reasons,
        trust_score: package.trust_score.map(|s| s as u8),
        publisher: package.publisher_verified.map(|verified| PublisherInfo {
            name: None,
            verified,
        }),
        weekly_downloads: package.weekly_downloads.map(|d| d as u64),
        install_scripts: InstallScripts::default(),
        cves: cves
            .into_iter()
            .map(|c| CveSummary {
                cve_id: c.cve_id,
                severity: c.severity,
                description: c.description,
                fixed_in: c.fixed_in,
            })
            .collect(),
        agentic_threats: threats
            .into_iter()
            .map(|t| AgenticThreatSummary {
                threat_type: t.threat_type,
                confidence: t.confidence,
                location: t.location,
                snippet: t.snippet,
            })
            .collect(),
        capabilities,
        skill_md: package.skill_md,
        scanned_at: package.scanned_at,
    };

    Ok(Json(response))
}

/// Request a scan for a package
pub async fn request_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanRequestResponse>, (StatusCode, Json<serde_json::Value>)> {
    let job = ScanJob::new(request.name, request.version, ScanPriority::High);
    let job_id = job.id;

    state.queue.push(job).await.map_err(|e| {
        tracing::error!("Failed to queue scan: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to queue scan" })),
        )
    })?;

    Ok(Json(ScanRequestResponse {
        job_id,
        estimated_seconds: 30,
    }))
}

/// Bulk lookup multiple packages
pub async fn bulk_lookup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BulkLookupRequest>,
) -> Result<Json<Vec<PackageResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let packages = state.db.bulk_lookup(&request.packages).await.map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Database error" })),
        )
    })?;

    let mut responses = Vec::new();

    for package in packages {
        let cves = state
            .db
            .get_package_cves(package.id)
            .await
            .unwrap_or_default();
        let threats = state
            .db
            .get_package_threats(package.id)
            .await
            .unwrap_or_default();

        let risk_reasons: Vec<String> =
            serde_json::from_value(package.risk_reasons.clone()).unwrap_or_default();

        let capabilities: PackageCapabilities =
            serde_json::from_value(package.capabilities.clone()).unwrap_or_default();

        responses.push(PackageResponse {
            name: package.name,
            version: package.version,
            risk_level: package.risk_level,
            risk_reasons,
            trust_score: package.trust_score.map(|s| s as u8),
            publisher: package.publisher_verified.map(|verified| PublisherInfo {
                name: None,
                verified,
            }),
            weekly_downloads: package.weekly_downloads.map(|d| d as u64),
            install_scripts: InstallScripts::default(),
            cves: cves
                .into_iter()
                .map(|c| CveSummary {
                    cve_id: c.cve_id,
                    severity: c.severity,
                    description: c.description,
                    fixed_in: c.fixed_in,
                })
                .collect(),
            agentic_threats: threats
                .into_iter()
                .map(|t| AgenticThreatSummary {
                    threat_type: t.threat_type,
                    confidence: t.confidence,
                    location: t.location,
                    snippet: t.snippet,
                })
                .collect(),
            capabilities,
            skill_md: package.skill_md,
            scanned_at: package.scanned_at,
        });
    }

    Ok(Json(responses))
}

/// Scan a tarball uploaded by the user
pub async fn scan_tarball(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<ScanRequestResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get the tarball file from multipart form
    let mut tarball_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::error!("Failed to read multipart field: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Failed to read upload" })),
        )
    })? {
        let name = field.name().unwrap_or("").to_string();

        if name == "tarball" || name == "file" {
            filename = field.file_name().map(|s| s.to_string());
            tarball_data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to read tarball data: {}", e);
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({ "error": "Failed to read tarball data" })),
                        )
                    })?
                    .to_vec(),
            );
            break;
        }
    }

    let tarball_data = tarball_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "No tarball file provided. Use field name 'tarball' or 'file'" }),
            ),
        )
    })?;

    // Validate it looks like a gzipped tarball
    if tarball_data.len() < 10 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "File too small to be a valid tarball" })),
        ));
    }

    // Check gzip magic bytes
    if tarball_data[0] != 0x1f || tarball_data[1] != 0x8b {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "File does not appear to be a gzipped tarball" })),
        ));
    }

    // Save to temp file
    let tarball_dir = std::env::var("TARBALL_UPLOAD_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());

    std::fs::create_dir_all(&tarball_dir).map_err(|e| {
        tracing::error!("Failed to create tarball directory: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to save tarball" })),
        )
    })?;

    let job_id = uuid::Uuid::new_v4();
    let tarball_filename = format!("{}.tgz", job_id);
    let tarball_path = std::path::Path::new(&tarball_dir).join(&tarball_filename);

    let mut file = std::fs::File::create(&tarball_path).map_err(|e| {
        tracing::error!("Failed to create tarball file: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to save tarball" })),
        )
    })?;

    file.write_all(&tarball_data).map_err(|e| {
        tracing::error!("Failed to write tarball data: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to save tarball" })),
        )
    })?;

    // Extract package name from filename or use a placeholder
    let package_name = filename
        .as_ref()
        .and_then(|f| f.strip_suffix(".tgz").or_else(|| f.strip_suffix(".tar.gz")))
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("uploaded-{}", &job_id.to_string()[..8]));

    // Create a job with the tarball path
    let job = ScanJob::from_tarball(
        package_name,
        "0.0.0".to_string(), // Version will be read from package.json
        tarball_path.to_string_lossy().to_string(),
    );
    let job_id = job.id;

    state.queue.push(job).await.map_err(|e| {
        tracing::error!("Failed to queue tarball scan: {}", e);
        // Clean up the tarball file
        let _ = std::fs::remove_file(&tarball_path);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to queue scan" })),
        )
    })?;

    tracing::info!(
        job_id = %job_id,
        tarball_path = %tarball_path.display(),
        "Queued tarball scan"
    );

    Ok(Json(ScanRequestResponse {
        job_id,
        estimated_seconds: 60, // Tarball scans may take longer
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;

    fn health_router() -> Router {
        Router::new().route("/health", axum::routing::get(health_check))
    }

    #[tokio::test]
    async fn test_health_check_returns_ok() {
        let app = health_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json, serde_json::json!({"status": "ok"}));
    }

    #[tokio::test]
    async fn test_health_check_content_type() {
        let app = health_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let content_type = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""));

        assert!(
            content_type.map_or(false, |ct| ct.contains("application/json")),
            "Content-Type should be application/json"
        );
    }
}
