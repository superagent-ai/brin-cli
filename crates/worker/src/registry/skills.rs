//! skills.sh registry adapter
//!
//! Fetches Agent Skills from GitHub repositories. Skills are identified by
//! `owner/repo` or `owner/repo/path/to/skill` for monorepos.

use super::{ExtractedPackage, Language, Maintainer, PackageMetadata, RegistryAdapter, SourceFile};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use common::Registry;
use reqwest::Client;
use serde::Deserialize;
use std::path::Path;
use tempfile::TempDir;

/// Adapter for skills.sh / GitHub-hosted Agent Skills
pub struct SkillsAdapter {
    client: Client,
}

/// Parsed skill identifier: owner/repo with optional subpath
#[derive(Debug, Clone)]
pub struct SkillIdentifier {
    pub owner: String,
    pub repo: String,
    /// Optional path within the repo (e.g., "skills/mcp-builder")
    pub path: Option<String>,
}

impl SkillIdentifier {
    /// Parse a skill identifier like "anthropics/skills" or "anthropics/skills/mcp-builder"
    pub fn parse(input: &str) -> Result<Self> {
        let parts: Vec<&str> = input.splitn(3, '/').collect();
        match parts.len() {
            2 => Ok(Self {
                owner: parts[0].to_string(),
                repo: parts[1].to_string(),
                path: None,
            }),
            3 => Ok(Self {
                owner: parts[0].to_string(),
                repo: parts[1].to_string(),
                path: Some(parts[2].to_string()),
            }),
            _ => anyhow::bail!(
                "Invalid skill identifier '{}'. Expected format: owner/repo or owner/repo/path",
                input
            ),
        }
    }

    /// Full display name
    pub fn full_name(&self) -> String {
        match &self.path {
            Some(p) => format!("{}/{}/{}", self.owner, self.repo, p),
            None => format!("{}/{}", self.owner, self.repo),
        }
    }

    /// GitHub API URL for the repo
    fn repo_api_url(&self) -> String {
        format!("https://api.github.com/repos/{}/{}", self.owner, self.repo)
    }

    /// Raw content URL for SKILL.md
    fn raw_skill_md_url(&self, branch: &str) -> String {
        match &self.path {
            Some(p) => format!(
                "https://raw.githubusercontent.com/{}/{}/{}/{}/SKILL.md",
                self.owner, self.repo, branch, p
            ),
            None => format!(
                "https://raw.githubusercontent.com/{}/{}/{}/SKILL.md",
                self.owner, self.repo, branch
            ),
        }
    }

    /// GitHub API URL for listing directory contents
    fn contents_api_url(&self) -> String {
        match &self.path {
            Some(p) => format!(
                "https://api.github.com/repos/{}/{}/contents/{}",
                self.owner, self.repo, p
            ),
            None => format!(
                "https://api.github.com/repos/{}/{}/contents",
                self.owner, self.repo
            ),
        }
    }
}

/// GitHub repo metadata from API
#[derive(Debug, Deserialize)]
struct GitHubRepo {
    description: Option<String>,
    default_branch: Option<String>,
    stargazers_count: Option<u64>,
    license: Option<GitHubLicense>,
    created_at: Option<String>,
    pushed_at: Option<String>,
    owner: Option<GitHubOwner>,
}

#[derive(Debug, Deserialize)]
struct GitHubLicense {
    spdx_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubOwner {
    login: Option<String>,
    #[serde(rename = "type")]
    owner_type: Option<String>,
}

/// GitHub commit info
#[derive(Debug, Deserialize)]
struct GitHubCommit {
    sha: String,
}

/// GitHub contents API item
#[derive(Debug, Deserialize)]
struct GitHubContentItem {
    name: String,
    #[serde(rename = "type")]
    item_type: String,
    download_url: Option<String>,
    size: Option<u64>,
}

impl SkillsAdapter {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("brin-worker/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Get the GitHub token if available (for higher rate limits)
    fn github_token() -> Option<String> {
        std::env::var("GITHUB_TOKEN")
            .ok()
            .or_else(|| std::env::var("GH_TOKEN").ok())
    }

    /// Build a request with optional auth header
    fn authed_get(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(url);
        if let Some(token) = Self::github_token() {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        req.header("Accept", "application/vnd.github.v3+json")
    }

    /// Fetch the latest commit SHA for the skill path (used as version)
    async fn fetch_latest_commit_sha(&self, id: &SkillIdentifier) -> Result<String> {
        let url = match &id.path {
            Some(p) => format!(
                "https://api.github.com/repos/{}/{}/commits?path={}&per_page=1",
                id.owner, id.repo, p
            ),
            None => format!(
                "https://api.github.com/repos/{}/{}/commits?per_page=1",
                id.owner, id.repo
            ),
        };

        let response = self
            .authed_get(&url)
            .send()
            .await
            .context("Failed to fetch commit info from GitHub")?;

        if !response.status().is_success() {
            anyhow::bail!("GitHub API returned status {}", response.status());
        }

        let commits: Vec<GitHubCommit> = response.json().await?;
        let sha = commits
            .first()
            .map(|c| c.sha[..7].to_string())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(sha)
    }

    /// Collect all readable files in a skill directory
    async fn fetch_skill_files(
        &self,
        id: &SkillIdentifier,
        branch: &str,
    ) -> Result<Vec<(String, String)>> {
        let mut files = Vec::new();

        let url = id.contents_api_url();
        let response = self.authed_get(&url).send().await?;

        if !response.status().is_success() {
            // If contents listing fails, just try to get SKILL.md directly
            let skill_url = id.raw_skill_md_url(branch);
            let content = self.client.get(&skill_url).send().await?.text().await?;
            files.push(("SKILL.md".to_string(), content));
            return Ok(files);
        }

        let items: Vec<GitHubContentItem> = response.json().await.unwrap_or_default();

        for item in &items {
            if item.item_type != "file" {
                continue;
            }
            // Only fetch text files that are relevant for scanning
            let ext = item.name.rsplit('.').next().unwrap_or("").to_lowercase();
            let is_relevant = matches!(
                ext.as_str(),
                "md" | "txt" | "yaml" | "yml" | "json" | "js" | "ts" | "py" | "sh" | "bash"
            ) || item.name == "SKILL.md"
                || item.name == "README.md";

            if !is_relevant {
                continue;
            }

            // Skip files that are too large (> 500KB)
            if item.size.unwrap_or(0) > 500_000 {
                continue;
            }

            if let Some(download_url) = &item.download_url {
                match self.client.get(download_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(content) = resp.text().await {
                            files.push((item.name.clone(), content));
                        }
                    }
                    _ => continue,
                }
            }
        }

        // Ensure we have SKILL.md
        if !files.iter().any(|(name, _)| name == "SKILL.md") {
            let skill_url = id.raw_skill_md_url(branch);
            if let Ok(resp) = self.client.get(&skill_url).send().await {
                if resp.status().is_success() {
                    if let Ok(content) = resp.text().await {
                        files.push(("SKILL.md".to_string(), content));
                    }
                }
            }
        }

        if files.is_empty() {
            anyhow::bail!(
                "No SKILL.md found for skill '{}'. Is this a valid skill?",
                id.full_name()
            );
        }

        Ok(files)
    }
}

impl Default for SkillsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryAdapter for SkillsAdapter {
    fn registry(&self) -> Registry {
        Registry::Skills
    }

    async fn fetch_metadata(&self, name: &str, version: Option<&str>) -> Result<PackageMetadata> {
        let id = SkillIdentifier::parse(name)?;

        // Fetch repo metadata from GitHub API
        let repo_url = id.repo_api_url();
        let response = self
            .authed_get(&repo_url)
            .send()
            .await
            .context("Failed to fetch repo metadata from GitHub")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("Skill '{}' not found on GitHub", id.full_name());
        }

        if !response.status().is_success() {
            anyhow::bail!("GitHub API returned status {}", response.status());
        }

        let repo: GitHubRepo = response.json().await?;

        // Use provided version or fetch latest commit SHA
        let version = match version {
            Some(v) => v.to_string(),
            None => self.fetch_latest_commit_sha(&id).await?,
        };

        // Build maintainer from repo owner
        let maintainers = repo
            .owner
            .as_ref()
            .map(|o| {
                vec![Maintainer {
                    name: o.login.clone(),
                    email: None,
                }]
            })
            .unwrap_or_default();

        // Parse published_at from pushed_at
        let published_at: Option<DateTime<Utc>> = repo
            .pushed_at
            .as_ref()
            .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Build extras with GitHub-specific data
        let extras = serde_json::json!({
            "stars": repo.stargazers_count.unwrap_or(0),
            "owner_type": repo.owner.as_ref().and_then(|o| o.owner_type.clone()),
            "created_at": repo.created_at,
            "default_branch": repo.default_branch,
        });

        Ok(PackageMetadata {
            name: id.full_name(),
            version,
            description: repo.description.clone(),
            repository: Some(format!("https://github.com/{}/{}", id.owner, id.repo)),
            maintainers,
            downloads: None,
            published_at,
            license: repo.license.and_then(|l| l.spdx_id),
            extras,
        })
    }

    async fn download_package(&self, name: &str, _version: &str) -> Result<ExtractedPackage> {
        let id = SkillIdentifier::parse(name)?;

        // Fetch repo info to get default branch
        let repo_url = id.repo_api_url();
        let response = self.authed_get(&repo_url).send().await?;
        let repo: GitHubRepo = response.json().await?;
        let branch = repo.default_branch.unwrap_or_else(|| "main".to_string());

        // Fetch all skill files
        let files = self.fetch_skill_files(&id, &branch).await?;

        // Create temp directory and write files
        let dir = TempDir::new().context("Failed to create temp directory")?;
        let root = dir.path().join("skill");
        std::fs::create_dir_all(&root)?;

        let mut source_files = Vec::new();

        for (filename, content) in &files {
            let file_path = root.join(filename);
            std::fs::write(&file_path, content)?;

            let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

            let language = match ext.as_str() {
                "md" | "txt" | "yaml" | "yml" => Language::Other,
                "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
                "ts" | "mts" | "cts" | "tsx" => Language::TypeScript,
                "py" => Language::Python,
                _ => Language::Other,
            };

            source_files.push(SourceFile {
                path: filename.clone(),
                content: content.clone(),
                language,
            });
        }

        // Build a manifest from the SKILL.md frontmatter
        let manifest = build_skill_manifest(&id, &files);

        Ok(ExtractedPackage {
            dir,
            root,
            source_files,
            manifest,
            has_native_code: false,
        })
    }

    fn extract_local(&self, path: &Path) -> Result<ExtractedPackage> {
        // Skills are fetched from GitHub, not local tarballs.
        // However, support scanning a local SKILL.md directory.
        let dir = TempDir::new()?;
        let root = dir.path().join("skill");

        if path.is_dir() {
            // Copy directory contents
            copy_dir_contents(path, &root)?;
        } else if path.is_file() {
            // Single SKILL.md file
            std::fs::create_dir_all(&root)?;
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("SKILL.md");
            std::fs::copy(path, root.join(filename))?;
        } else {
            anyhow::bail!("Path {:?} is neither a file nor a directory", path);
        }

        // Collect source files
        let source_files = collect_skill_files(&root)?;

        let manifest = serde_json::json!({
            "name": path.file_name().and_then(|n| n.to_str()).unwrap_or("local-skill"),
            "version": "local",
        });

        Ok(ExtractedPackage {
            dir,
            root,
            source_files,
            manifest,
            has_native_code: false,
        })
    }

    fn compute_trust_score(&self, metadata: &PackageMetadata) -> u8 {
        let mut score = 40u8; // Base score (lower than packages — skills are newer ecosystem)

        // Stars (capped contribution)
        let stars = metadata
            .extras
            .get("stars")
            .and_then(|s| s.as_u64())
            .unwrap_or(0);
        match stars {
            0..=9 => {}
            10..=99 => score = score.saturating_add(5),
            100..=999 => score = score.saturating_add(10),
            1000..=9999 => score = score.saturating_add(15),
            _ => score = score.saturating_add(20),
        }

        // Organization owner (+10)
        if metadata.extras.get("owner_type").and_then(|t| t.as_str()) == Some("Organization") {
            score = score.saturating_add(10);
        }

        // Has repository (always true for GitHub skills) (+5)
        if metadata.repository.is_some() {
            score = score.saturating_add(5);
        }

        // Has description (+5)
        if metadata.description.is_some() {
            score = score.saturating_add(5);
        }

        // Has license (+10)
        if metadata.license.is_some() {
            score = score.saturating_add(10);
        }

        score.min(100)
    }

    fn cve_ecosystem(&self) -> Option<&'static str> {
        None // Skills don't have CVEs
    }

    async fn fetch_downloads(&self, _name: &str) -> Result<Option<i64>> {
        // GitHub doesn't expose clone/traffic counts without push access
        Ok(None)
    }
}

/// Build a manifest JSON from SKILL.md frontmatter
fn build_skill_manifest(id: &SkillIdentifier, files: &[(String, String)]) -> serde_json::Value {
    let skill_md = files
        .iter()
        .find(|(name, _)| name == "SKILL.md")
        .map(|(_, content)| content.as_str())
        .unwrap_or("");

    // Parse YAML frontmatter
    let mut name = None;
    let mut description = None;

    if let Some(stripped) = skill_md.strip_prefix("---") {
        if let Some(end) = stripped.find("---") {
            let frontmatter = &stripped[..end];
            for line in frontmatter.lines() {
                let line = line.trim();
                if let Some(val) = line.strip_prefix("name:") {
                    name = Some(val.trim().to_string());
                } else if let Some(val) = line.strip_prefix("description:") {
                    description = Some(val.trim().to_string());
                }
            }
        }
    }

    serde_json::json!({
        "name": name.unwrap_or_else(|| id.full_name()),
        "description": description,
        "skill_identifier": id.full_name(),
    })
}

/// Copy directory contents recursively
fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_contents(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Collect source files from a skill directory
fn collect_skill_files(root: &Path) -> Result<Vec<SourceFile>> {
    let mut files = Vec::new();

    fn visit_dir(dir: &Path, files: &mut Vec<SourceFile>, base: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip hidden directories
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
            }

            if path.is_dir() {
                visit_dir(&path, files, base);
            } else if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let is_relevant = matches!(
                    ext,
                    "md" | "txt" | "yaml" | "yml" | "json" | "js" | "ts" | "py" | "sh"
                );

                if is_relevant {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() < 500_000 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_skill_identifier_simple() {
        let id = SkillIdentifier::parse("anthropics/skills").unwrap();
        assert_eq!(id.owner, "anthropics");
        assert_eq!(id.repo, "skills");
        assert!(id.path.is_none());
        assert_eq!(id.full_name(), "anthropics/skills");
    }

    #[test]
    fn test_parse_skill_identifier_with_path() {
        let id = SkillIdentifier::parse("anthropics/skills/mcp-builder").unwrap();
        assert_eq!(id.owner, "anthropics");
        assert_eq!(id.repo, "skills");
        assert_eq!(id.path, Some("mcp-builder".to_string()));
        assert_eq!(id.full_name(), "anthropics/skills/mcp-builder");
    }

    #[test]
    fn test_parse_skill_identifier_deep_path() {
        let id = SkillIdentifier::parse("org/repo/skills/deep/path").unwrap();
        assert_eq!(id.owner, "org");
        assert_eq!(id.repo, "repo");
        assert_eq!(id.path, Some("skills/deep/path".to_string()));
    }

    #[test]
    fn test_parse_skill_identifier_invalid() {
        assert!(SkillIdentifier::parse("just-one-part").is_err());
    }

    #[test]
    fn test_build_skill_manifest_with_frontmatter() {
        let id = SkillIdentifier::parse("test/skill").unwrap();
        let files = vec![(
            "SKILL.md".to_string(),
            "---\nname: my-skill\ndescription: A test skill\n---\n# My Skill".to_string(),
        )];

        let manifest = build_skill_manifest(&id, &files);
        assert_eq!(manifest["name"], "my-skill");
        assert_eq!(manifest["description"], "A test skill");
    }

    #[test]
    fn test_build_skill_manifest_without_frontmatter() {
        let id = SkillIdentifier::parse("test/skill").unwrap();
        let files = vec![(
            "SKILL.md".to_string(),
            "# My Skill\nSome content".to_string(),
        )];

        let manifest = build_skill_manifest(&id, &files);
        assert_eq!(manifest["name"], "test/skill");
    }

    #[test]
    fn test_raw_skill_md_url() {
        let id = SkillIdentifier::parse("anthropics/skills/mcp-builder").unwrap();
        assert_eq!(
            id.raw_skill_md_url("main"),
            "https://raw.githubusercontent.com/anthropics/skills/main/mcp-builder/SKILL.md"
        );

        let id = SkillIdentifier::parse("owner/repo").unwrap();
        assert_eq!(
            id.raw_skill_md_url("main"),
            "https://raw.githubusercontent.com/owner/repo/main/SKILL.md"
        );
    }
}
