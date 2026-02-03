//! PyPI registry client

use anyhow::{Context, Result};
use common::{PypiPackageMetadata, PypiReleaseInfo};
use flate2::read::GzDecoder;
use reqwest::Client;
use std::path::{Path, PathBuf};
use tar::Archive;
use tempfile::TempDir;
use zip::ZipArchive;

/// Extracted Python package contents
pub struct ExtractedPypiPackage {
    /// Temporary directory containing extracted files (must keep for ownership)
    #[allow(dead_code)]
    pub dir: TempDir,
    /// Path to package root
    pub root: PathBuf,
    /// Package metadata (from PKG-INFO or pyproject.toml)
    pub metadata: serde_json::Value,
    /// Source files (.py, .pyi)
    pub source_files: Vec<PythonSourceFile>,
    /// Has C extensions
    pub has_c_extension: bool,
    /// Has Cython files
    pub has_cython: bool,
}

/// A Python source file
pub struct PythonSourceFile {
    #[allow(dead_code)]
    pub path: String,
    pub content: String,
}

/// Client for PyPI registry
pub struct PypiClient {
    client: Client,
    registry_url: String,
}

impl PypiClient {
    /// Create a new PyPI client
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-worker/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
            registry_url: std::env::var("PYPI_REGISTRY_URL")
                .unwrap_or_else(|_| "https://pypi.org/pypi".to_string()),
        }
    }

    /// Fetch package metadata (all versions)
    pub async fn fetch_metadata(&self, package: &str) -> Result<PypiPackageMetadata> {
        let url = format!(
            "{}/{}/json",
            self.registry_url,
            normalize_package_name(package)
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch package metadata")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("Package '{}' not found on PyPI", package);
        }

        let json: serde_json::Value = response
            .error_for_status()
            .context("PyPI registry returned an error")?
            .json()
            .await
            .context("Failed to parse package metadata")?;

        parse_pypi_metadata(&json)
    }

    /// Fetch specific version info
    pub async fn fetch_version_info(
        &self,
        package: &str,
        version: &str,
    ) -> Result<PypiPackageMetadata> {
        let url = format!(
            "{}/{}/{}/json",
            self.registry_url,
            normalize_package_name(package),
            version
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch version info")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("Package '{}@{}' not found on PyPI", package, version);
        }

        let json: serde_json::Value = response
            .error_for_status()
            .context("PyPI registry returned an error")?
            .json()
            .await
            .context("Failed to parse version info")?;

        parse_pypi_metadata(&json)
    }

    /// Download and extract package source distribution
    pub async fn download_and_extract(
        &self,
        package: &str,
        version: &str,
    ) -> Result<ExtractedPypiPackage> {
        // Get package info to find download URL
        let metadata = self.fetch_version_info(package, version).await?;

        // Find the best release to download (prefer sdist over wheel for source analysis)
        let release = metadata
            .releases
            .iter()
            .find(|r| r.packagetype == "sdist")
            .or_else(|| {
                metadata
                    .releases
                    .iter()
                    .find(|r| r.packagetype == "bdist_wheel")
            })
            .ok_or_else(|| {
                anyhow::anyhow!("No downloadable release found for {}@{}", package, version)
            })?;

        tracing::debug!(
            "Downloading {} ({}) from {}",
            package,
            release.packagetype,
            release.url
        );

        // Download the release
        let response = self
            .client
            .get(&release.url)
            .send()
            .await
            .context("Failed to download package")?;

        let bytes = response
            .error_for_status()
            .context("Failed to download package")?
            .bytes()
            .await?;

        // Create temp directory
        let dir = TempDir::new().context("Failed to create temp directory")?;

        // Extract based on file type
        let root = if release.filename.ends_with(".tar.gz") || release.filename.ends_with(".tgz") {
            extract_tarball(&bytes, dir.path())?
        } else if release.filename.ends_with(".whl") || release.filename.ends_with(".zip") {
            extract_zip(&bytes, dir.path())?
        } else {
            anyhow::bail!("Unsupported package format: {}", release.filename);
        };

        // Read package metadata
        let pkg_metadata = read_package_metadata(&root)?;

        // Check for native extensions
        let has_c_extension = check_for_c_extensions(&root);
        let has_cython = check_for_cython(&root);

        // Collect Python source files
        let source_files = collect_python_source_files(&root)?;

        Ok(ExtractedPypiPackage {
            dir,
            root,
            metadata: pkg_metadata,
            source_files,
            has_c_extension,
            has_cython,
        })
    }

    /// Extract a local tarball or wheel file (for uploaded packages)
    pub fn extract_local_package(&self, path: &Path) -> Result<ExtractedPypiPackage> {
        let bytes = std::fs::read(path).context(format!("Failed to read package: {:?}", path))?;

        let dir = TempDir::new().context("Failed to create temp directory")?;

        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let root = if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
            extract_tarball(&bytes, dir.path())?
        } else if filename.ends_with(".whl") || filename.ends_with(".zip") {
            extract_zip(&bytes, dir.path())?
        } else {
            anyhow::bail!("Unsupported package format: {}", filename);
        };

        let pkg_metadata = read_package_metadata(&root)?;
        let has_c_extension = check_for_c_extensions(&root);
        let has_cython = check_for_cython(&root);
        let source_files = collect_python_source_files(&root)?;

        Ok(ExtractedPypiPackage {
            dir,
            root,
            metadata: pkg_metadata,
            source_files,
            has_c_extension,
            has_cython,
        })
    }

    /// Fetch download statistics from pypistats.org
    pub async fn fetch_weekly_downloads(&self, package: &str) -> Result<Option<i64>> {
        let url = format!(
            "https://pypistats.org/api/packages/{}/recent",
            normalize_package_name(package)
        );

        let response = self.client.get(&url).send().await;

        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    tracing::debug!("pypistats API returned {} for {}", resp.status(), package);
                    return Ok(None);
                }

                let json: serde_json::Value = resp.json().await.unwrap_or_default();
                // pypistats returns {"data": {"last_week": 12345, ...}}
                Ok(json
                    .get("data")
                    .and_then(|d| d.get("last_week"))
                    .and_then(|w| w.as_i64()))
            }
            Err(e) => {
                tracing::debug!("Failed to fetch downloads for {}: {}", package, e);
                Ok(None)
            }
        }
    }
}

/// Normalize package name according to PEP 503
/// (lowercase, replace hyphens/underscores with hyphens)
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// Parse PyPI JSON API response into our metadata struct
fn parse_pypi_metadata(json: &serde_json::Value) -> Result<PypiPackageMetadata> {
    let info = json
        .get("info")
        .ok_or_else(|| anyhow::anyhow!("Missing 'info' in PyPI response"))?;

    let name = info
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let version = info
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let summary = info
        .get("summary")
        .and_then(|v| v.as_str())
        .map(String::from);

    let author = info
        .get("author")
        .and_then(|v| v.as_str())
        .map(String::from);

    let author_email = info
        .get("author_email")
        .and_then(|v| v.as_str())
        .map(String::from);

    let maintainer = info
        .get("maintainer")
        .and_then(|v| v.as_str())
        .map(String::from);

    let maintainer_email = info
        .get("maintainer_email")
        .and_then(|v| v.as_str())
        .map(String::from);

    let home_page = info
        .get("home_page")
        .and_then(|v| v.as_str())
        .map(String::from);

    let project_url = info
        .get("project_url")
        .and_then(|v| v.as_str())
        .map(String::from);

    let project_urls = info
        .get("project_urls")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        });

    let license = info
        .get("license")
        .and_then(|v| v.as_str())
        .map(String::from);

    let requires_python = info
        .get("requires_python")
        .and_then(|v| v.as_str())
        .map(String::from);

    let requires_dist = info
        .get("requires_dist")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });

    let classifiers = info
        .get("classifiers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });

    // Parse releases (URLs array in the response)
    let releases = json
        .get("urls")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(PypiReleaseInfo {
                        filename: r.get("filename")?.as_str()?.to_string(),
                        url: r.get("url")?.as_str()?.to_string(),
                        packagetype: r.get("packagetype")?.as_str()?.to_string(),
                        size: r.get("size").and_then(|v| v.as_i64()),
                        digests: r.get("digests").cloned(),
                        upload_time: r
                            .get("upload_time")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(PypiPackageMetadata {
        name,
        version,
        summary,
        author,
        author_email,
        maintainer,
        maintainer_email,
        home_page,
        project_url,
        project_urls,
        license,
        requires_python,
        requires_dist,
        classifiers,
        releases,
    })
}

/// Extract a .tar.gz archive
fn extract_tarball(bytes: &[u8], dest: &Path) -> Result<PathBuf> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);

    archive.unpack(dest).context("Failed to extract tarball")?;

    // Find the root directory (usually {package}-{version}/)
    find_package_root(dest)
}

/// Extract a .zip or .whl archive
fn extract_zip(bytes: &[u8], dest: &Path) -> Result<PathBuf> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("Failed to open zip archive")?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest.join(file.mangled_name());

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    // For wheels, the root is the dest directory itself
    // For zip source dists, find the root directory
    find_package_root(dest)
}

/// Find the package root directory after extraction
fn find_package_root(dest: &Path) -> Result<PathBuf> {
    // Look for the first directory, or return dest if it contains Python files directly
    let entries: Vec<_> = std::fs::read_dir(dest)?.filter_map(|e| e.ok()).collect();

    // If there's exactly one directory, use it as root
    if entries.len() == 1 && entries[0].path().is_dir() {
        return Ok(entries[0].path());
    }

    // If there are Python files or a setup.py directly in dest, use dest
    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.ends_with(".py") || name_str == "setup.py" || name_str == "pyproject.toml" {
            return Ok(dest.to_path_buf());
        }
    }

    // Look for a directory that looks like {package}-{version}
    for entry in entries {
        if entry.path().is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Skip dist-info and egg-info directories
            if !name_str.ends_with(".dist-info") && !name_str.ends_with(".egg-info") {
                return Ok(entry.path());
            }
        }
    }

    // Fallback to dest
    Ok(dest.to_path_buf())
}

/// Read package metadata from PKG-INFO, pyproject.toml, or setup.py
fn read_package_metadata(root: &Path) -> Result<serde_json::Value> {
    // Try PKG-INFO first (standard metadata file)
    let pkg_info_path = root.join("PKG-INFO");
    if pkg_info_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_info_path) {
            return Ok(serde_json::json!({
                "type": "PKG-INFO",
                "content": content
            }));
        }
    }

    // Try pyproject.toml
    let pyproject_path = root.join("pyproject.toml");
    if pyproject_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&pyproject_path) {
            return Ok(serde_json::json!({
                "type": "pyproject.toml",
                "content": content
            }));
        }
    }

    // Try setup.py
    let setup_path = root.join("setup.py");
    if setup_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&setup_path) {
            return Ok(serde_json::json!({
                "type": "setup.py",
                "content": content
            }));
        }
    }

    // Look in dist-info directory (for wheels)
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".dist-info") {
                let metadata_path = entry.path().join("METADATA");
                if metadata_path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&metadata_path) {
                        return Ok(serde_json::json!({
                            "type": "METADATA",
                            "content": content
                        }));
                    }
                }
            }
        }
    }

    Ok(serde_json::json!({
        "type": "unknown",
        "content": ""
    }))
}

/// Check if the package contains C extensions
fn check_for_c_extensions(root: &Path) -> bool {
    fn check_dir(dir: &Path) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip hidden and common non-source directories
            if name_str.starts_with('.') || name_str == "__pycache__" {
                continue;
            }

            if path.is_dir() {
                if check_dir(&path) {
                    return true;
                }
            } else if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "c" | "cpp" | "cxx" | "h" | "hpp" | "so" | "pyd") {
                    return true;
                }
            }
        }
        false
    }

    check_dir(root)
}

/// Check if the package contains Cython files
fn check_for_cython(root: &Path) -> bool {
    fn check_dir(dir: &Path) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with('.') || name_str == "__pycache__" {
                continue;
            }

            if path.is_dir() {
                if check_dir(&path) {
                    return true;
                }
            } else if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "pyx" | "pxd") {
                    return true;
                }
            }
        }
        false
    }

    check_dir(root)
}

/// Collect Python source files from the package
fn collect_python_source_files(root: &Path) -> Result<Vec<PythonSourceFile>> {
    let mut files = Vec::new();

    fn visit_dir(dir: &Path, files: &mut Vec<PythonSourceFile>, base: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip hidden directories, __pycache__, egg-info, dist-info
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.')
                    || name == "__pycache__"
                    || name.ends_with(".egg-info")
                    || name.ends_with(".dist-info")
                    || name == "venv"
                    || name == ".venv"
                    || name == "node_modules"
                {
                    continue;
                }
            }

            if path.is_dir() {
                visit_dir(&path, files, base);
            } else if path.is_file() {
                // Check if it's a Python file
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "py" | "pyi") {
                    // Read file (limit size to avoid huge files)
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() < 1_000_000 {
                            // 1MB limit
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                let relative_path = path
                                    .strip_prefix(base)
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|_| path.to_string_lossy().to_string());

                                files.push(PythonSourceFile {
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

    visit_dir(root, &mut files, root);

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_package_name() {
        assert_eq!(normalize_package_name("Flask"), "flask");
        assert_eq!(normalize_package_name("my_package"), "my-package");
        assert_eq!(normalize_package_name("My_Package"), "my-package");
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_fetch_metadata() {
        let client = PypiClient::new();
        let metadata = client.fetch_metadata("requests").await.unwrap();

        assert_eq!(metadata.name.to_lowercase(), "requests");
        assert!(metadata.summary.is_some());
    }
}
