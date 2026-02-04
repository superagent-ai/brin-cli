//! Core data models for sus

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use uuid::Uuid;

/// Risk level assessment for a package
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Clean,
    Warning,
    Critical,
}

impl RiskLevel {
    pub fn emoji(&self) -> &'static str {
        match self {
            RiskLevel::Clean => "✅",
            RiskLevel::Warning => "⚠️",
            RiskLevel::Critical => "🚨",
        }
    }
}

/// Types of security threats that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    // LLM Safety (Agentic Threats)
    PromptInjection,
    ImproperOutputHandling,
    InsecureToolUsage,
    InstructionOverride,

    // Secrets Management
    HardcodedSecrets,

    // Insecure Data Handling
    WeakCrypto,
    SensitiveDataLogging,
    PiiViolations,
    InsecureDeserialization,

    // Injection Vulnerabilities
    Xss,
    Sqli,
    CommandInjection,
    Ssrf,
    Ssti,
    CodeInjection,

    // Authentication & Session
    AuthBypass,
    WeakSessionTokens,
    InsecurePasswordReset,

    // Supply Chain
    MaliciousInstallScripts,
    DependencyConfusion,
    Typosquatting,
    ObfuscatedCode,

    // Other
    PathTraversal,
    PrototypePollution,
    Backdoor,
    CryptoMiner,
    DataExfiltration,
    SocialEngineering,

    // Legacy (kept for backward compatibility)
    #[serde(alias = "install_script_injection")]
    InstallScriptInjection,
    MaliciousCode,
}

/// Priority levels for scan jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Immediate = 3,
}

/// Package registry type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type, Default)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Registry {
    #[default]
    Npm,
    Pypi,
    Crates,
}

impl Registry {
    pub fn as_str(&self) -> &'static str {
        match self {
            Registry::Npm => "npm",
            Registry::Pypi => "pypi",
            Registry::Crates => "crates",
        }
    }
}

impl std::fmt::Display for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A package scan result stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Package {
    pub id: i32,
    pub name: String,
    pub version: String,
    pub registry: Registry,
    pub risk_level: RiskLevel,
    pub risk_reasons: serde_json::Value,
    pub trust_score: Option<i16>,
    pub publisher_verified: Option<bool>,
    pub weekly_downloads: Option<i64>,
    pub maintainer_count: Option<i32>,
    pub last_publish: Option<DateTime<Utc>>,
    pub capabilities: serde_json::Value,
    /// Maintainers list as JSON array
    pub maintainers: Option<serde_json::Value>,
    pub skill_md: Option<String>,
    pub scanned_at: DateTime<Utc>,
    pub scan_version: Option<String>,
}

/// CVE information linked to a package
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PackageCve {
    pub id: i32,
    pub package_id: i32,
    pub cve_id: String,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub fixed_in: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
}

/// Agentic threat detected in a package
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgenticThreat {
    pub id: i32,
    pub package_id: i32,
    pub threat_type: ThreatType,
    pub confidence: f32,
    pub location: Option<String>,
    pub snippet: Option<String>,
    pub detected_at: DateTime<Utc>,
}

/// Network capabilities of a package
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkCapabilities {
    pub makes_requests: bool,
    pub domains: Vec<String>,
    pub protocols: Vec<String>,
}

/// Filesystem capabilities of a package
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemCapabilities {
    pub reads: bool,
    pub writes: bool,
    pub paths: Vec<PathPermission>,
}

/// Path permission entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPermission {
    pub path: String,
    pub mode: String, // "r", "w", "rw"
}

/// Process capabilities of a package
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessCapabilities {
    pub spawns_children: bool,
    pub commands: Vec<String>,
}

/// Environment capabilities of a package
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvironmentCapabilities {
    pub accessed_vars: Vec<String>,
}

/// Native module capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NativeCapabilities {
    pub has_native: bool,
    pub native_modules: Vec<String>,
}

/// Combined package capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageCapabilities {
    pub network: NetworkCapabilities,
    pub filesystem: FilesystemCapabilities,
    pub process: ProcessCapabilities,
    pub environment: EnvironmentCapabilities,
    pub native: NativeCapabilities,
}

/// Usage documentation for a package (generated by AI)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageDocs {
    /// Package description/summary
    pub description: Option<String>,
    /// Quick start code example
    pub quick_start: Option<String>,
    /// Key APIs and their usage
    pub key_apis: Vec<ApiDoc>,
    /// Best practices for using this package
    pub best_practices: Vec<String>,
    /// Common patterns and idioms
    pub common_patterns: Vec<String>,
    /// Common gotchas or pitfalls to avoid
    pub gotchas: Vec<String>,
}

/// Documentation for a single API/function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiDoc {
    /// Name of the API (function, class, method)
    pub name: String,
    /// Brief description
    pub description: String,
    /// Example usage
    pub example: Option<String>,
}

/// A job in the scan queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: Uuid,
    pub package: String,
    pub version: Option<String>,
    /// Registry type (defaults to Npm for backwards compatibility with old queue jobs)
    #[serde(default)]
    pub registry: Registry,
    pub priority: ScanPriority,
    pub requested_at: DateTime<Utc>,
    pub requested_by: Option<String>, // "user", "watcher", "cve-update"
    /// Optional path to a local tarball (for scanning uploaded packages)
    pub tarball_path: Option<String>,
}

impl ScanJob {
    pub fn new(package: String, version: Option<String>, priority: ScanPriority) -> Self {
        Self {
            id: Uuid::new_v4(),
            package,
            version,
            registry: Registry::Npm,
            priority,
            requested_at: Utc::now(),
            requested_by: None,
            tarball_path: None,
        }
    }

    pub fn with_registry(
        package: String,
        version: Option<String>,
        registry: Registry,
        priority: ScanPriority,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            package,
            version,
            registry,
            priority,
            requested_at: Utc::now(),
            requested_by: None,
            tarball_path: None,
        }
    }

    /// Create a job for scanning a local tarball
    pub fn from_tarball(package: String, version: String, tarball_path: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            package,
            version: Some(version),
            registry: Registry::Npm,
            priority: ScanPriority::Immediate,
            requested_at: Utc::now(),
            requested_by: Some("tarball-upload".to_string()),
            tarball_path: Some(tarball_path),
        }
    }
}

/// CVE summary for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSummary {
    pub cve_id: String,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub fixed_in: Option<String>,
}

/// Agentic threat summary for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticThreatSummary {
    pub threat_type: ThreatType,
    pub confidence: f32,
    pub location: Option<String>,
    pub snippet: Option<String>,
}

/// Publisher information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublisherInfo {
    pub name: Option<String>,
    pub verified: bool,
}

/// Maintainer information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintainerInfo {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Install script information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallScripts {
    pub preinstall: bool,
    pub install: bool,
    pub postinstall: bool,
    pub prepare: bool,
}

impl InstallScripts {
    pub fn has_any(&self) -> bool {
        self.preinstall || self.install || self.postinstall || self.prepare
    }

    pub fn count(&self) -> usize {
        [
            self.preinstall,
            self.install,
            self.postinstall,
            self.prepare,
        ]
        .iter()
        .filter(|&&v| v)
        .count()
    }
}

/// Lightweight package item for list views (no full CVE/threat details)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageListItem {
    pub name: String,
    pub version: String,
    pub registry: Registry,
    pub risk_level: RiskLevel,
    pub trust_score: Option<u8>,
    pub weekly_downloads: Option<u64>,
    pub publisher_verified: Option<bool>,
    pub cve_count: i64,
    pub threat_count: i64,
    pub capabilities: PackageCapabilities,
    pub scanned_at: DateTime<Utc>,
}

/// Paginated list response for packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageListResponse {
    pub packages: Vec<PackageListItem>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Pagination query parameters
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub q: Option<String>,    // Search query
    pub latest: Option<bool>, // If true, return only latest version per package
}

/// Full package response for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageResponse {
    pub name: String,
    pub version: String,
    pub registry: Registry,
    pub risk_level: RiskLevel,
    pub risk_reasons: Vec<String>,
    pub trust_score: Option<u8>,
    pub publisher: Option<PublisherInfo>,
    pub weekly_downloads: Option<u64>,
    pub maintainers: Option<Vec<MaintainerInfo>>,
    pub maintainer_count: Option<u32>,
    pub last_publish: Option<DateTime<Utc>>,
    pub install_scripts: InstallScripts,
    pub cves: Vec<CveSummary>,
    pub agentic_threats: Vec<AgenticThreatSummary>,
    pub capabilities: PackageCapabilities,
    pub skill_md: Option<String>,
    pub scanned_at: DateTime<Utc>,
}

/// Request to scan a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub name: String,
    pub version: Option<String>,
    #[serde(default)]
    pub registry: Option<Registry>,
}

/// Response after requesting a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequestResponse {
    pub job_id: Uuid,
    pub estimated_seconds: u32,
}

/// Bulk lookup request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkLookupRequest {
    pub packages: Vec<PackageVersionPair>,
}

/// Package name and version pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVersionPair {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub registry: Option<Registry>,
}

/// npm package metadata from registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackageMetadata {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "dist-tags")]
    pub dist_tags: Option<serde_json::Value>,
    pub versions: Option<serde_json::Value>,
    pub maintainers: Option<Vec<NpmMaintainer>>,
    pub repository: Option<serde_json::Value>,
    /// Publish timestamps for each version (version -> ISO timestamp)
    pub time: Option<HashMap<String, String>>,
}

/// npm maintainer info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmMaintainer {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// npm package version info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmVersionInfo {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub main: Option<String>,
    pub scripts: Option<serde_json::Value>,
    pub dependencies: Option<serde_json::Value>,
    #[serde(rename = "devDependencies")]
    pub dev_dependencies: Option<serde_json::Value>,
    pub dist: Option<NpmDist>,
}

/// npm distribution info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmDist {
    pub tarball: Option<String>,
    pub shasum: Option<String>,
    pub integrity: Option<String>,
}

// =============================================================================
// PyPI-specific types
// =============================================================================

/// PyPI package metadata from registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiPackageMetadata {
    pub name: String,
    pub version: String,
    pub summary: Option<String>,
    pub author: Option<String>,
    pub author_email: Option<String>,
    pub maintainer: Option<String>,
    pub maintainer_email: Option<String>,
    pub home_page: Option<String>,
    pub project_url: Option<String>,
    pub project_urls: Option<HashMap<String, String>>,
    pub license: Option<String>,
    pub requires_python: Option<String>,
    pub requires_dist: Option<Vec<String>>,
    pub classifiers: Option<Vec<String>>,
    /// Available releases/downloads for this version
    pub releases: Vec<PypiReleaseInfo>,
}

/// PyPI release/distribution info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiReleaseInfo {
    pub filename: String,
    pub url: String,
    pub packagetype: String,
    pub size: Option<i64>,
    pub digests: Option<serde_json::Value>,
    pub upload_time: Option<String>,
}

/// PyPI maintainer info (derived from author/maintainer fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiMaintainer {
    pub name: Option<String>,
    pub email: Option<String>,
}

impl PypiPackageMetadata {
    /// Get maintainers from the metadata (author and maintainer fields)
    pub fn get_maintainers(&self) -> Vec<PypiMaintainer> {
        let mut maintainers = Vec::new();

        if self.author.is_some() || self.author_email.is_some() {
            maintainers.push(PypiMaintainer {
                name: self.author.clone(),
                email: self.author_email.clone(),
            });
        }

        if self.maintainer.is_some() || self.maintainer_email.is_some() {
            // Only add if different from author
            let maintainer = PypiMaintainer {
                name: self.maintainer.clone(),
                email: self.maintainer_email.clone(),
            };
            if maintainer.name != self.author || maintainer.email != self.author_email {
                maintainers.push(maintainer);
            }
        }

        maintainers
    }

    /// Check if package has a repository URL in project_urls
    pub fn has_repository(&self) -> bool {
        if let Some(urls) = &self.project_urls {
            let repo_keys = [
                "Source",
                "Repository",
                "GitHub",
                "GitLab",
                "Bitbucket",
                "Code",
            ];
            for key in repo_keys {
                if urls.contains_key(key) {
                    return true;
                }
            }
        }
        // Also check home_page for common repository hosts
        if let Some(home) = &self.home_page {
            let repo_hosts = ["github.com", "gitlab.com", "bitbucket.org"];
            for host in repo_hosts {
                if home.contains(host) {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_serialization() {
        // Test serialization
        assert_eq!(
            serde_json::to_string(&RiskLevel::Clean).unwrap(),
            "\"clean\""
        );
        assert_eq!(
            serde_json::to_string(&RiskLevel::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&RiskLevel::Critical).unwrap(),
            "\"critical\""
        );

        // Test deserialization
        assert_eq!(
            serde_json::from_str::<RiskLevel>("\"clean\"").unwrap(),
            RiskLevel::Clean
        );
        assert_eq!(
            serde_json::from_str::<RiskLevel>("\"warning\"").unwrap(),
            RiskLevel::Warning
        );
        assert_eq!(
            serde_json::from_str::<RiskLevel>("\"critical\"").unwrap(),
            RiskLevel::Critical
        );
    }

    #[test]
    fn test_risk_level_emoji() {
        assert_eq!(RiskLevel::Clean.emoji(), "✅");
        assert_eq!(RiskLevel::Warning.emoji(), "⚠️");
        assert_eq!(RiskLevel::Critical.emoji(), "🚨");
    }

    #[test]
    fn test_threat_type_serialization() {
        // LLM Safety
        assert_eq!(
            serde_json::to_string(&ThreatType::PromptInjection).unwrap(),
            "\"prompt_injection\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatType::ImproperOutputHandling).unwrap(),
            "\"improper_output_handling\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatType::InsecureToolUsage).unwrap(),
            "\"insecure_tool_usage\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatType::InstructionOverride).unwrap(),
            "\"instruction_override\""
        );

        // Secrets
        assert_eq!(
            serde_json::to_string(&ThreatType::HardcodedSecrets).unwrap(),
            "\"hardcoded_secrets\""
        );

        // Data Handling
        assert_eq!(
            serde_json::to_string(&ThreatType::WeakCrypto).unwrap(),
            "\"weak_crypto\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatType::InsecureDeserialization).unwrap(),
            "\"insecure_deserialization\""
        );

        // Injection
        assert_eq!(serde_json::to_string(&ThreatType::Xss).unwrap(), "\"xss\"");
        assert_eq!(
            serde_json::to_string(&ThreatType::Sqli).unwrap(),
            "\"sqli\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatType::CommandInjection).unwrap(),
            "\"command_injection\""
        );

        // Supply Chain
        assert_eq!(
            serde_json::to_string(&ThreatType::MaliciousInstallScripts).unwrap(),
            "\"malicious_install_scripts\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatType::Typosquatting).unwrap(),
            "\"typosquatting\""
        );

        // Other
        assert_eq!(
            serde_json::to_string(&ThreatType::DataExfiltration).unwrap(),
            "\"data_exfiltration\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatType::Backdoor).unwrap(),
            "\"backdoor\""
        );

        // Test deserialization
        assert_eq!(
            serde_json::from_str::<ThreatType>("\"prompt_injection\"").unwrap(),
            ThreatType::PromptInjection
        );
        assert_eq!(
            serde_json::from_str::<ThreatType>("\"social_engineering\"").unwrap(),
            ThreatType::SocialEngineering
        );
        assert_eq!(
            serde_json::from_str::<ThreatType>("\"xss\"").unwrap(),
            ThreatType::Xss
        );
        assert_eq!(
            serde_json::from_str::<ThreatType>("\"malicious_install_scripts\"").unwrap(),
            ThreatType::MaliciousInstallScripts
        );

        // Test legacy alias deserialization
        assert_eq!(
            serde_json::from_str::<ThreatType>("\"install_script_injection\"").unwrap(),
            ThreatType::InstallScriptInjection
        );
    }

    #[test]
    fn test_scan_job_creation() {
        let job = ScanJob::new(
            "express".to_string(),
            Some("4.18.0".to_string()),
            ScanPriority::High,
        );

        assert_eq!(job.package, "express");
        assert_eq!(job.version, Some("4.18.0".to_string()));
        assert_eq!(job.registry, Registry::Npm);
        assert_eq!(job.priority, ScanPriority::High);
        assert!(job.tarball_path.is_none());
        assert!(job.requested_by.is_none());
    }

    #[test]
    fn test_scan_job_with_registry() {
        let job = ScanJob::with_registry(
            "requests".to_string(),
            Some("2.28.0".to_string()),
            Registry::Pypi,
            ScanPriority::Medium,
        );

        assert_eq!(job.package, "requests");
        assert_eq!(job.version, Some("2.28.0".to_string()));
        assert_eq!(job.registry, Registry::Pypi);
        assert_eq!(job.priority, ScanPriority::Medium);
    }

    #[test]
    fn test_scan_job_from_tarball() {
        let job = ScanJob::from_tarball(
            "my-package".to_string(),
            "1.0.0".to_string(),
            "/tmp/my-package.tgz".to_string(),
        );

        assert_eq!(job.package, "my-package");
        assert_eq!(job.version, Some("1.0.0".to_string()));
        assert_eq!(job.registry, Registry::Npm);
        assert_eq!(job.priority, ScanPriority::Immediate);
        assert_eq!(job.tarball_path, Some("/tmp/my-package.tgz".to_string()));
        assert_eq!(job.requested_by, Some("tarball-upload".to_string()));
    }

    #[test]
    fn test_registry_serialization() {
        assert_eq!(serde_json::to_string(&Registry::Npm).unwrap(), "\"npm\"");
        assert_eq!(serde_json::to_string(&Registry::Pypi).unwrap(), "\"pypi\"");
        assert_eq!(
            serde_json::to_string(&Registry::Crates).unwrap(),
            "\"crates\""
        );

        assert_eq!(
            serde_json::from_str::<Registry>("\"npm\"").unwrap(),
            Registry::Npm
        );
        assert_eq!(
            serde_json::from_str::<Registry>("\"pypi\"").unwrap(),
            Registry::Pypi
        );
        assert_eq!(
            serde_json::from_str::<Registry>("\"crates\"").unwrap(),
            Registry::Crates
        );
    }

    #[test]
    fn test_registry_display() {
        assert_eq!(Registry::Npm.as_str(), "npm");
        assert_eq!(Registry::Pypi.as_str(), "pypi");
        assert_eq!(Registry::Crates.as_str(), "crates");
        assert_eq!(format!("{}", Registry::Npm), "npm");
    }

    #[test]
    fn test_install_scripts_has_any() {
        let empty = InstallScripts::default();
        assert!(!empty.has_any());
        assert_eq!(empty.count(), 0);

        let with_postinstall = InstallScripts {
            postinstall: true,
            ..Default::default()
        };
        assert!(with_postinstall.has_any());
        assert_eq!(with_postinstall.count(), 1);

        let with_multiple = InstallScripts {
            preinstall: true,
            postinstall: true,
            prepare: true,
            ..Default::default()
        };
        assert!(with_multiple.has_any());
        assert_eq!(with_multiple.count(), 3);
    }

    #[test]
    fn test_scan_priority_ordering() {
        assert!(ScanPriority::Low < ScanPriority::Medium);
        assert!(ScanPriority::Medium < ScanPriority::High);
        assert!(ScanPriority::High < ScanPriority::Immediate);
    }
}
