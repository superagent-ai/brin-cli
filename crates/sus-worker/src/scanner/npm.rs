//! npm registry client

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use reqwest::Client;
use std::path::{Path, PathBuf};
use sus_common::{NpmPackageMetadata, NpmVersionInfo};
use tar::Archive;
use tempfile::TempDir;

/// Extracted package contents
pub struct ExtractedPackage {
    /// Temporary directory containing extracted files
    pub dir: TempDir,
    /// Path to package root
    pub root: PathBuf,
    /// README content if present
    pub readme: Option<String>,
    /// package.json content
    pub package_json: serde_json::Value,
    /// Source files (.js, .ts, .mjs, .cjs)
    pub source_files: Vec<SourceFile>,
    /// Has binding.gyp (native module)
    pub has_binding_gyp: bool,
    /// Has N-API binding
    pub has_napi: bool,
    /// Install scripts from package.json
    pub scripts: PackageScripts,
}

/// A source file
pub struct SourceFile {
    pub path: String,
    pub content: String,
}

/// Package scripts
#[derive(Default)]
pub struct PackageScripts {
    pub preinstall: Option<String>,
    pub install: Option<String>,
    pub postinstall: Option<String>,
    pub prepare: Option<String>,
}

/// Client for npm registry
pub struct NpmClient {
    client: Client,
    registry_url: String,
}

impl NpmClient {
    /// Create a new npm client
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

    /// Fetch package metadata
    pub async fn fetch_metadata(&self, package: &str) -> Result<NpmPackageMetadata> {
        let url = format!("{}/{}", self.registry_url, encode_package_name(package));

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.npm.install-v1+json")
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
    pub async fn fetch_version_info(&self, package: &str, version: &str) -> Result<NpmVersionInfo> {
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

    /// Download and extract package tarball
    pub async fn download_and_extract(
        &self,
        package: &str,
        version: &str,
    ) -> Result<ExtractedPackage> {
        // Get tarball URL
        let version_info = self.fetch_version_info(package, version).await?;
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

        // Create temp directory
        let dir = TempDir::new().context("Failed to create temp directory")?;

        // Extract tarball
        let decoder = GzDecoder::new(bytes.as_ref());
        let mut archive = Archive::new(decoder);

        archive
            .unpack(dir.path())
            .context("Failed to extract tarball")?;

        // npm tarballs have a "package" folder inside
        let root = dir.path().join("package");

        // Read README
        let readme = try_read_file(&root.join("README.md"))
            .or_else(|| try_read_file(&root.join("readme.md")))
            .or_else(|| try_read_file(&root.join("Readme.md")));

        // Read package.json
        let package_json_path = root.join("package.json");
        let package_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&package_json_path)
                .context("Failed to read package.json")?,
        )
        .context("Failed to parse package.json")?;

        // Extract scripts
        let scripts = PackageScripts {
            preinstall: package_json
                .get("scripts")
                .and_then(|s| s.get("preinstall"))
                .and_then(|s| s.as_str())
                .map(String::from),
            install: package_json
                .get("scripts")
                .and_then(|s| s.get("install"))
                .and_then(|s| s.as_str())
                .map(String::from),
            postinstall: package_json
                .get("scripts")
                .and_then(|s| s.get("postinstall"))
                .and_then(|s| s.as_str())
                .map(String::from),
            prepare: package_json
                .get("scripts")
                .and_then(|s| s.get("prepare"))
                .and_then(|s| s.as_str())
                .map(String::from),
        };

        // Check for native modules
        let has_binding_gyp = root.join("binding.gyp").exists();
        let has_napi = package_json
            .get("dependencies")
            .and_then(|d| d.as_object())
            .map(|deps| deps.contains_key("node-addon-api") || deps.contains_key("napi-rs"))
            .unwrap_or(false);

        // Collect source files
        let source_files = collect_source_files(&root)?;

        Ok(ExtractedPackage {
            dir,
            root,
            readme,
            package_json,
            source_files,
            has_binding_gyp,
            has_napi,
            scripts,
        })
    }

    /// Extract a local tarball file (for uploaded packages)
    pub fn extract_local_tarball(&self, tarball_path: &Path) -> Result<ExtractedPackage> {
        // Read tarball file
        let bytes = std::fs::read(tarball_path)
            .context(format!("Failed to read tarball: {:?}", tarball_path))?;

        // Create temp directory
        let dir = TempDir::new().context("Failed to create temp directory")?;

        // Extract tarball
        let decoder = GzDecoder::new(bytes.as_slice());
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
            // Find the first directory in the extracted content
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

        // Read README
        let readme = try_read_file(&root.join("README.md"))
            .or_else(|| try_read_file(&root.join("readme.md")))
            .or_else(|| try_read_file(&root.join("Readme.md")));

        // Read package.json
        let package_json_path = root.join("package.json");
        let package_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&package_json_path)
                .context("Failed to read package.json")?,
        )
        .context("Failed to parse package.json")?;

        // Extract scripts
        let scripts = PackageScripts {
            preinstall: package_json
                .get("scripts")
                .and_then(|s| s.get("preinstall"))
                .and_then(|s| s.as_str())
                .map(String::from),
            install: package_json
                .get("scripts")
                .and_then(|s| s.get("install"))
                .and_then(|s| s.as_str())
                .map(String::from),
            postinstall: package_json
                .get("scripts")
                .and_then(|s| s.get("postinstall"))
                .and_then(|s| s.as_str())
                .map(String::from),
            prepare: package_json
                .get("scripts")
                .and_then(|s| s.get("prepare"))
                .and_then(|s| s.as_str())
                .map(String::from),
        };

        // Check for native modules
        let has_binding_gyp = root.join("binding.gyp").exists();
        let has_napi = package_json
            .get("dependencies")
            .and_then(|d| d.as_object())
            .map(|deps| deps.contains_key("node-addon-api") || deps.contains_key("napi-rs"))
            .unwrap_or(false);

        // Collect source files
        let source_files = collect_source_files(&root)?;

        Ok(ExtractedPackage {
            dir,
            root,
            readme,
            package_json,
            source_files,
            has_binding_gyp,
            has_napi,
            scripts,
        })
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

/// Try to read a file, returning None on failure
fn try_read_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Collect JavaScript/TypeScript source files from the package
fn collect_source_files(root: &std::path::Path) -> Result<Vec<SourceFile>> {
    let mut files = Vec::new();

    fn visit_dir(dir: &std::path::Path, root: &std::path::Path, files: &mut Vec<SourceFile>) {
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
                visit_dir(&path, root, files);
            } else if path.is_file() {
                // Check if it's a JS/TS file
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx") {
                    // Read file (limit size to avoid huge files)
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() < 1_000_000 {
                            // 1MB limit
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                let relative_path = path
                                    .strip_prefix(root)
                                    .unwrap_or(&path)
                                    .to_string_lossy()
                                    .to_string();
                                files.push(SourceFile {
                                    path: relative_path,
                                    content,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    visit_dir(root, root, &mut files);

    Ok(files)
}
