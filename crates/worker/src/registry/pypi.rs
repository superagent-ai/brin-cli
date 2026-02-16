//! PyPI registry adapter

use super::{ExtractedPackage, Language, Maintainer, PackageMetadata, RegistryAdapter, SourceFile};
use anyhow::{Context, Result};
use async_trait::async_trait;
use common::{PypiPackageMetadata, PypiReleaseInfo, Registry};
use flate2::read::GzDecoder;
use reqwest::Client;
use std::path::{Path, PathBuf};
use tar::Archive;
use tempfile::TempDir;
use zip::ZipArchive;

/// Adapter for PyPI registry
pub struct PypiAdapter {
    client: Client,
    registry_url: String,
}

impl PypiAdapter {
    /// Create a new PyPI adapter
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("brin-worker/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
            registry_url: std::env::var("PYPI_REGISTRY_URL")
                .unwrap_or_else(|_| "https://pypi.org/pypi".to_string()),
        }
    }

    /// Fetch raw PyPI package metadata
    async fn fetch_pypi_metadata(&self, package: &str) -> Result<PypiPackageMetadata> {
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
    async fn fetch_version_info(
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

    /// Extract package from bytes
    fn extract_package_bytes(
        &self,
        bytes: &[u8],
        filename: &str,
    ) -> Result<(TempDir, PathBuf, serde_json::Value)> {
        let dir = TempDir::new().context("Failed to create temp directory")?;

        let root = if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
            extract_tarball(bytes, dir.path())?
        } else if filename.ends_with(".whl") || filename.ends_with(".zip") {
            extract_zip(bytes, dir.path())?
        } else {
            anyhow::bail!("Unsupported package format: {}", filename);
        };

        let manifest = read_package_metadata(&root)?;

        Ok((dir, root, manifest))
    }

    /// Build ExtractedPackage from extracted directory
    fn build_extracted_package(
        &self,
        dir: TempDir,
        root: PathBuf,
        manifest: serde_json::Value,
    ) -> Result<ExtractedPackage> {
        // Check for native extensions
        let has_c_extension = check_for_c_extensions(&root);
        let has_cython = check_for_cython(&root);

        // Collect Python source files
        let source_files = collect_python_source_files(&root)?;

        Ok(ExtractedPackage {
            dir,
            root,
            source_files,
            manifest,
            has_native_code: has_c_extension || has_cython,
        })
    }
}

impl Default for PypiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryAdapter for PypiAdapter {
    fn registry(&self) -> Registry {
        Registry::Pypi
    }

    async fn fetch_metadata(&self, name: &str, version: Option<&str>) -> Result<PackageMetadata> {
        let pypi_metadata = match version {
            Some(v) => self.fetch_version_info(name, v).await?,
            None => self.fetch_pypi_metadata(name).await?,
        };

        // Convert maintainers
        let mut maintainers = Vec::new();
        if pypi_metadata.author.is_some() || pypi_metadata.author_email.is_some() {
            maintainers.push(Maintainer {
                name: pypi_metadata.author.clone(),
                email: pypi_metadata.author_email.clone(),
            });
        }
        if pypi_metadata.maintainer.is_some() || pypi_metadata.maintainer_email.is_some() {
            // Only add if different from author
            if pypi_metadata.maintainer != pypi_metadata.author
                || pypi_metadata.maintainer_email != pypi_metadata.author_email
            {
                maintainers.push(Maintainer {
                    name: pypi_metadata.maintainer.clone(),
                    email: pypi_metadata.maintainer_email.clone(),
                });
            }
        }

        // Get repository URL
        let repository = pypi_metadata
            .project_urls
            .as_ref()
            .and_then(|urls| {
                let repo_keys = [
                    "Source",
                    "Repository",
                    "GitHub",
                    "GitLab",
                    "Bitbucket",
                    "Code",
                ];
                for key in repo_keys {
                    if let Some(url) = urls.get(key) {
                        return Some(url.clone());
                    }
                }
                None
            })
            .or_else(|| {
                // Also check home_page for repository hosts
                pypi_metadata.home_page.as_ref().and_then(|home| {
                    if home.contains("github.com")
                        || home.contains("gitlab.com")
                        || home.contains("bitbucket.org")
                    {
                        Some(home.clone())
                    } else {
                        None
                    }
                })
            });

        Ok(PackageMetadata {
            name: pypi_metadata.name.clone(),
            version: pypi_metadata.version.clone(),
            description: pypi_metadata.summary.clone(),
            repository,
            maintainers,
            downloads: None,    // Fetched separately
            published_at: None, // PyPI doesn't provide in metadata
            license: pypi_metadata.license.clone(),
            extras: serde_json::to_value(&pypi_metadata).unwrap_or_default(),
        })
    }

    async fn download_package(&self, name: &str, version: &str) -> Result<ExtractedPackage> {
        // Get package info to find download URL
        let pypi_metadata = self.fetch_version_info(name, version).await?;

        // Find the best release to download (prefer sdist over wheel for source analysis)
        let release = pypi_metadata
            .releases
            .iter()
            .find(|r| r.packagetype == "sdist")
            .or_else(|| {
                pypi_metadata
                    .releases
                    .iter()
                    .find(|r| r.packagetype == "bdist_wheel")
            })
            .ok_or_else(|| {
                anyhow::anyhow!("No downloadable release found for {}@{}", name, version)
            })?;

        tracing::debug!(
            "Downloading {} ({}) from {}",
            name,
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

        let (dir, root, manifest) = self.extract_package_bytes(&bytes, &release.filename)?;
        self.build_extracted_package(dir, root, manifest)
    }

    fn extract_local(&self, path: &Path) -> Result<ExtractedPackage> {
        let bytes = std::fs::read(path).context(format!("Failed to read package: {:?}", path))?;
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let (dir, root, manifest) = self.extract_package_bytes(&bytes, filename)?;
        self.build_extracted_package(dir, root, manifest)
    }

    fn compute_trust_score(&self, metadata: &PackageMetadata) -> u8 {
        let mut score = 50u8; // Base score

        // Has maintainers (+5 each, up to +10)
        match metadata.maintainers.len() {
            0 => {}
            1 => score = score.saturating_add(5),
            _ => score = score.saturating_add(10),
        }

        // Has repository URL (+10)
        if metadata.repository.is_some() {
            score = score.saturating_add(10);
        }

        // Has description (+5)
        if metadata.description.is_some() {
            score = score.saturating_add(5);
        }

        // Has license (+5)
        if metadata.license.is_some() {
            score = score.saturating_add(5);
        }

        // Check for classifiers in extras
        if let Some(extras) = metadata.extras.as_object() {
            if let Some(classifiers) = extras.get("classifiers").and_then(|c| c.as_array()) {
                if !classifiers.is_empty() {
                    score = score.saturating_add(5);

                    // Check for stable development status (+10)
                    for classifier in classifiers {
                        if let Some(c) = classifier.as_str() {
                            if c.contains("Development Status :: 5 - Production/Stable")
                                || c.contains("Development Status :: 6 - Mature")
                            {
                                score = score.saturating_add(10);
                                break;
                            }
                        }
                    }
                }
            }
        }

        score.min(100)
    }

    fn cve_ecosystem(&self) -> Option<&'static str> {
        Some("PyPI")
    }

    async fn fetch_downloads(&self, name: &str) -> Result<Option<i64>> {
        let url = format!(
            "https://pypistats.org/api/packages/{}/recent",
            normalize_package_name(name)
        );

        let response = self.client.get(&url).send().await;

        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    tracing::debug!("pypistats API returned {} for {}", resp.status(), name);
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
                tracing::debug!("Failed to fetch downloads for {}: {}", name, e);
                Ok(None)
            }
        }
    }
}

/// Normalize package name according to PEP 503
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// Parse PyPI JSON API response into metadata struct
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

    find_package_root(dest)
}

/// Find the package root directory after extraction
fn find_package_root(dest: &Path) -> Result<PathBuf> {
    let entries: Vec<_> = std::fs::read_dir(dest)?.filter_map(|e| e.ok()).collect();

    // If there's exactly one directory, use it as root
    if entries.len() == 1 && entries[0].path().is_dir() {
        return Ok(entries[0].path());
    }

    // If there are Python files or setup.py directly in dest, use dest
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
            if !name_str.ends_with(".dist-info") && !name_str.ends_with(".egg-info") {
                return Ok(entry.path());
            }
        }
    }

    Ok(dest.to_path_buf())
}

/// Read package metadata from PKG-INFO, pyproject.toml, or setup.py
fn read_package_metadata(root: &Path) -> Result<serde_json::Value> {
    // Try PKG-INFO first
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
fn collect_python_source_files(root: &Path) -> Result<Vec<SourceFile>> {
    let mut files = Vec::new();

    fn visit_dir(dir: &Path, files: &mut Vec<SourceFile>, base: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();

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
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "py" | "pyi") {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() < 1_000_000 {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                let relative_path = path
                                    .strip_prefix(base)
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|_| path.to_string_lossy().to_string());

                                files.push(SourceFile {
                                    path: relative_path,
                                    content,
                                    language: Language::Python,
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
}
