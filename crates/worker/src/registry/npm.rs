//! npm registry adapter

use super::{ExtractedPackage, Language, Maintainer, PackageMetadata, RegistryAdapter, SourceFile};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use common::{NpmPackageMetadata, NpmVersionInfo, Registry};
use flate2::read::GzDecoder;
use reqwest::Client;
use std::path::{Path, PathBuf};
use tar::Archive;
use tempfile::TempDir;

/// Adapter for npm registry
pub struct NpmAdapter {
    client: Client,
    registry_url: String,
}

impl NpmAdapter {
    /// Create a new npm adapter
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-worker/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
            registry_url: std::env::var("NPM_REGISTRY_URL")
                .unwrap_or_else(|_| "https://registry.npmjs.org".to_string()),
        }
    }

    /// Fetch raw npm package metadata
    async fn fetch_npm_metadata(&self, package: &str) -> Result<NpmPackageMetadata> {
        let url = format!("{}/{}", self.registry_url, encode_package_name(package));

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch package metadata")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("Package '{}' not found on npm", package);
        }

        response
            .error_for_status()
            .context("npm registry returned an error")?
            .json()
            .await
            .context("Failed to parse package metadata")
    }

    /// Fetch specific version info
    async fn fetch_version_info(&self, package: &str, version: &str) -> Result<NpmVersionInfo> {
        let url = format!(
            "{}/{}/{}",
            self.registry_url,
            encode_package_name(package),
            version
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch version info")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("Package '{}@{}' not found on npm", package, version);
        }

        response
            .error_for_status()
            .context("npm registry returned an error")?
            .json()
            .await
            .context("Failed to parse version info")
    }

    /// Extract tarball bytes to a temp directory
    fn extract_tarball_bytes(&self, bytes: &[u8]) -> Result<(TempDir, PathBuf)> {
        let dir = TempDir::new().context("Failed to create temp directory")?;

        let decoder = GzDecoder::new(bytes);
        let mut archive = Archive::new(decoder);

        archive
            .unpack(dir.path())
            .context("Failed to extract tarball")?;

        // npm tarballs have a "package" folder inside
        let root = dir.path().join("package");

        // If no "package" folder, try the first directory
        let root = if root.exists() {
            root
        } else {
            std::fs::read_dir(dir.path())
                .ok()
                .and_then(|mut entries| {
                    entries.find_map(|e| {
                        e.ok().and_then(|entry| {
                            if entry.path().is_dir() {
                                Some(entry.path())
                            } else {
                                None
                            }
                        })
                    })
                })
                .unwrap_or_else(|| dir.path().to_path_buf())
        };

        Ok((dir, root))
    }

    /// Build ExtractedPackage from a root directory
    fn build_extracted_package(&self, dir: TempDir, root: PathBuf) -> Result<ExtractedPackage> {
        // Read package.json
        let package_json_path = root.join("package.json");
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&package_json_path).context("Failed to read package.json")?,
        )
        .context("Failed to parse package.json")?;

        // Check for native modules
        let has_binding_gyp = root.join("binding.gyp").exists();
        let has_napi = manifest
            .get("dependencies")
            .and_then(|d| d.as_object())
            .map(|deps| deps.contains_key("node-addon-api") || deps.contains_key("napi-rs"))
            .unwrap_or(false);

        // Collect source files
        let source_files = collect_source_files(&root)?;

        Ok(ExtractedPackage {
            dir,
            root,
            source_files,
            manifest,
            has_native_code: has_binding_gyp || has_napi,
        })
    }
}

impl Default for NpmAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryAdapter for NpmAdapter {
    fn registry(&self) -> Registry {
        Registry::Npm
    }

    async fn fetch_metadata(&self, name: &str, version: Option<&str>) -> Result<PackageMetadata> {
        let npm_metadata = self.fetch_npm_metadata(name).await?;

        // Determine version
        let version = match version {
            Some(v) => v.to_string(),
            None => npm_metadata
                .dist_tags
                .as_ref()
                .and_then(|tags| tags.get("latest"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .ok_or_else(|| anyhow::anyhow!("Could not determine latest version"))?,
        };

        // Get published_at from time field
        let published_at: Option<DateTime<Utc>> = npm_metadata
            .time
            .as_ref()
            .and_then(|time| time.get(&version))
            .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Convert maintainers
        let maintainers = npm_metadata
            .maintainers
            .as_ref()
            .map(|m| {
                m.iter()
                    .map(|npm_m| Maintainer {
                        name: npm_m.name.clone(),
                        email: npm_m.email.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Extract repository URL
        let repository = npm_metadata.repository.as_ref().and_then(|r| {
            r.get("url")
                .and_then(|u| u.as_str())
                .or_else(|| r.as_str())
                .map(|url| url.to_string())
        });

        Ok(PackageMetadata {
            name: npm_metadata.name.clone(),
            version,
            description: npm_metadata.description.clone(),
            repository,
            maintainers,
            downloads: None, // Fetched separately
            published_at,
            license: None, // Not in top-level metadata
            extras: serde_json::to_value(&npm_metadata).unwrap_or_default(),
        })
    }

    async fn download_package(&self, name: &str, version: &str) -> Result<ExtractedPackage> {
        // Get tarball URL
        let version_info = self.fetch_version_info(name, version).await?;
        let tarball_url = version_info
            .dist
            .as_ref()
            .and_then(|d| d.tarball.clone())
            .ok_or_else(|| anyhow::anyhow!("No tarball URL found"))?;

        // Download tarball
        let response = self
            .client
            .get(&tarball_url)
            .send()
            .await
            .context("Failed to download tarball")?;

        let bytes = response
            .error_for_status()
            .context("Failed to download tarball")?
            .bytes()
            .await?;

        // Extract and build
        let (dir, root) = self.extract_tarball_bytes(&bytes)?;
        self.build_extracted_package(dir, root)
    }

    fn extract_local(&self, path: &Path) -> Result<ExtractedPackage> {
        let bytes = std::fs::read(path).context(format!("Failed to read tarball: {:?}", path))?;

        let (dir, root) = self.extract_tarball_bytes(&bytes)?;
        self.build_extracted_package(dir, root)
    }

    fn compute_trust_score(&self, metadata: &PackageMetadata) -> u8 {
        let mut score = 50u8; // Base score

        // Maintainer count (up to +20)
        match metadata.maintainers.len() {
            0 => score = score.saturating_sub(10),
            1 => {}
            2..=5 => score = score.saturating_add(10),
            _ => score = score.saturating_add(20),
        }

        // Has repository (+10)
        if metadata.repository.is_some() {
            score = score.saturating_add(10);
        }

        // Has description (+5)
        if metadata.description.is_some() {
            score = score.saturating_add(5);
        }

        score.min(100)
    }

    fn cve_ecosystem(&self) -> Option<&'static str> {
        Some("npm")
    }

    async fn fetch_downloads(&self, name: &str) -> Result<Option<i64>> {
        let url = format!(
            "https://api.npmjs.org/downloads/point/last-week/{}",
            encode_package_name(name)
        );

        let response = self.client.get(&url).send().await;

        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    tracing::debug!("Downloads API returned {} for {}", resp.status(), name);
                    return Ok(None);
                }

                let json: serde_json::Value = resp.json().await.unwrap_or_default();
                Ok(json.get("downloads").and_then(|d| d.as_i64()))
            }
            Err(e) => {
                tracing::debug!("Failed to fetch downloads for {}: {}", name, e);
                Ok(None)
            }
        }
    }
}

/// URL-encode a package name (for scoped packages)
fn encode_package_name(name: &str) -> String {
    if name.starts_with('@') {
        name.replace('/', "%2F")
    } else {
        name.to_string()
    }
}

/// Collect JavaScript/TypeScript source files from the package
fn collect_source_files(root: &Path) -> Result<Vec<SourceFile>> {
    let mut files = Vec::new();

    fn visit_dir(dir: &Path, files: &mut Vec<SourceFile>, base: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip node_modules and hidden directories
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == "node_modules" || name.starts_with('.') {
                    continue;
                }
            }

            if path.is_dir() {
                visit_dir(&path, files, base);
            } else if path.is_file() {
                // Check if it's a JS/TS file
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(
                    ext,
                    "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx"
                ) {
                    // Read file (limit size to avoid huge files)
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() < 1_000_000 {
                            // 1MB limit
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                let relative_path = path
                                    .strip_prefix(base)
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|_| path.to_string_lossy().to_string());

                                files.push(SourceFile {
                                    path: relative_path,
                                    content,
                                    language: Language::from_extension(ext),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    visit_dir(root, &mut files, root);

    Ok(files)
}
