//! Package scanner module

mod agentic;
mod capabilities;
mod cve;

use crate::registry::{AdapterRegistry, ExtractedPackage, PackageMetadata, RegistryAdapter};
use crate::skill_generator::generate_skill_md;
use anyhow::Result;
use capabilities::CapabilityExtractor;
use common::{
    db::{NewAgenticThreat, NewPackage, NewPackageCve},
    AgenticThreatSummary, CveSummary, Database, NpmPackageMetadata, PackageCapabilities,
    PypiPackageMetadata, Registry, RiskLevel, UsageDocs,
};
use cve::CveScanner;
use std::sync::Arc;

// Re-export AgenticScanner for OpenCode installation check from main.rs
pub use agentic::AgenticScanner;

/// Calculate trust score (0-100) based on package metadata (for backward compatibility)
///
/// Scoring:
/// - Base score: 50
/// - 0 maintainers: -10
/// - 2-5 maintainers: +10
/// - 6+ maintainers: +20
/// - Has repository: +10
/// - Has description: +5
#[allow(dead_code)]
pub fn calculate_trust_score(metadata: Option<&NpmPackageMetadata>) -> u8 {
    let mut score = 50u8; // Base score

    // If no metadata (local tarball), return base score
    let Some(metadata) = metadata else {
        return score;
    };

    // Maintainer count (up to +20)
    if let Some(maintainers) = &metadata.maintainers {
        match maintainers.len() {
            0 => score = score.saturating_sub(10),
            1 => {}
            2..=5 => score = score.saturating_add(10),
            _ => score = score.saturating_add(20),
        }
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

/// Calculate trust score (0-100) based on unified package metadata
#[allow(dead_code)]
pub fn calculate_trust_score_unified(metadata: Option<&PackageMetadata>) -> u8 {
    let mut score = 50u8; // Base score

    let Some(metadata) = metadata else {
        return score;
    };

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

    // Has license (+5)
    if metadata.license.is_some() {
        score = score.saturating_add(5);
    }

    score.min(100)
}

/// Calculate risk level and reasons based on CVEs, threats, capabilities, and trust score
pub fn calculate_risk(
    cves: &[CveSummary],
    agentic_threats: &[AgenticThreatSummary],
    capabilities: &PackageCapabilities,
    trust_score: u8,
) -> (RiskLevel, Vec<String>) {
    let mut reasons = Vec::new();
    let mut max_level = RiskLevel::Clean;

    // Check CVEs
    for cve in cves {
        let severity = cve.severity.as_deref().unwrap_or("unknown").to_uppercase();
        match severity.as_str() {
            "CRITICAL" | "HIGH" => {
                reasons.push(format!("{}: {}", cve.cve_id, severity));
                max_level = RiskLevel::Critical;
            }
            "MEDIUM" => {
                reasons.push(format!("{}: {}", cve.cve_id, severity));
                if max_level != RiskLevel::Critical {
                    max_level = RiskLevel::Warning;
                }
            }
            _ => {
                reasons.push(format!("{}: {}", cve.cve_id, severity));
            }
        }
    }

    // Check agentic threats
    for threat in agentic_threats {
        if threat.confidence > 0.8 {
            reasons.push(format!(
                "{:?} detected ({}% confidence)",
                threat.threat_type,
                (threat.confidence * 100.0) as u8
            ));
            max_level = RiskLevel::Critical;
        } else if threat.confidence > 0.5 {
            reasons.push(format!(
                "Possible {:?} ({}% confidence)",
                threat.threat_type,
                (threat.confidence * 100.0) as u8
            ));
            if max_level != RiskLevel::Critical {
                max_level = RiskLevel::Warning;
            }
        }
    }

    // Check risky capabilities
    if capabilities.native.has_native {
        reasons.push("Contains native code".to_string());
        if max_level == RiskLevel::Clean {
            max_level = RiskLevel::Warning;
        }
    }

    if capabilities.process.spawns_children {
        reasons.push("Can spawn child processes".to_string());
        if max_level == RiskLevel::Clean {
            max_level = RiskLevel::Warning;
        }
    }

    // Low trust score
    if trust_score < 30 {
        reasons.push(format!("Low trust score ({})", trust_score));
        if max_level == RiskLevel::Clean {
            max_level = RiskLevel::Warning;
        }
    }

    (max_level, reasons)
}

/// Calculate trust score (0-100) for PyPI packages
///
/// Scoring:
/// - Base score: 50
/// - Has author: +5
/// - Has maintainer: +5
/// - Has repository URL: +10
/// - Has description: +5
/// - Has license: +5
/// - Has classifiers: +5
/// - Development Status stable: +10
#[allow(dead_code)]
pub fn calculate_trust_score_pypi(metadata: Option<&PypiPackageMetadata>) -> u8 {
    let mut score = 50u8; // Base score

    let Some(metadata) = metadata else {
        return score;
    };

    // Has author (+5)
    if metadata.author.is_some() {
        score = score.saturating_add(5);
    }

    // Has maintainer (+5)
    if metadata.maintainer.is_some() {
        score = score.saturating_add(5);
    }

    // Has repository URL (+10)
    if metadata.has_repository() {
        score = score.saturating_add(10);
    }

    // Has description (+5)
    if metadata.summary.is_some() {
        score = score.saturating_add(5);
    }

    // Has license (+5)
    if metadata.license.is_some() {
        score = score.saturating_add(5);
    }

    // Has classifiers (+5)
    if let Some(classifiers) = &metadata.classifiers {
        if !classifiers.is_empty() {
            score = score.saturating_add(5);

            // Check for stable development status (+10)
            for classifier in classifiers {
                if classifier.contains("Development Status :: 5 - Production/Stable")
                    || classifier.contains("Development Status :: 6 - Mature")
                {
                    score = score.saturating_add(10);
                    break;
                }
            }
        }
    }

    score.min(100)
}

/// Extract package name and version from PyPI metadata
fn extract_pypi_name_version(metadata: &serde_json::Value) -> Result<(String, String)> {
    // Try to parse from PKG-INFO or pyproject.toml content
    if let Some(content) = metadata.get("content").and_then(|c| c.as_str()) {
        let metadata_type = metadata.get("type").and_then(|t| t.as_str()).unwrap_or("");

        if metadata_type == "PKG-INFO" || metadata_type == "METADATA" {
            // Parse PKG-INFO format (email-like headers)
            let mut name = None;
            let mut version = None;

            for line in content.lines() {
                if let Some(n) = line.strip_prefix("Name: ") {
                    name = Some(n.trim().to_string());
                } else if let Some(v) = line.strip_prefix("Version: ") {
                    version = Some(v.trim().to_string());
                }
                if name.is_some() && version.is_some() {
                    break;
                }
            }

            if let (Some(n), Some(v)) = (name, version) {
                return Ok((n, v));
            }
        } else if metadata_type == "pyproject.toml" {
            // Basic TOML parsing for name and version
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("name") {
                    if let Some(v) = extract_toml_string_value(line) {
                        if let Some(version) = find_toml_version(content) {
                            return Ok((v, version));
                        }
                    }
                }
            }
        } else if metadata_type == "setup.py" {
            // Very basic setup.py parsing - look for name= and version=
            if let (Some(name), Some(version)) = (
                extract_setup_py_value(content, "name"),
                extract_setup_py_value(content, "version"),
            ) {
                return Ok((name, version));
            }
        }
    }

    anyhow::bail!("Could not extract package name and version from metadata")
}

/// Extract a string value from a TOML line like: name = "value"
fn extract_toml_string_value(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() == 2 {
        let value = parts[1].trim();
        // Remove quotes
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            return Some(value[1..value.len() - 1].to_string());
        }
    }
    None
}

/// Find version in TOML content
fn find_toml_version(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("version") {
            return extract_toml_string_value(line);
        }
    }
    None
}

/// Extract a value from setup.py like: name="value" or name='value'
fn extract_setup_py_value(content: &str, key: &str) -> Option<String> {
    let patterns = [
        format!("{}=\"", key),
        format!("{}='", key),
        format!("{} = \"", key),
        format!("{} = '", key),
    ];

    for pattern in &patterns {
        if let Some(start) = content.find(pattern) {
            let value_start = start + pattern.len();
            let quote_char = if pattern.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = content[value_start..].find(quote_char) {
                return Some(content[value_start..value_start + end].to_string());
            }
        }
    }
    None
}

/// Result of scanning a package
#[allow(dead_code)]
pub struct ScanResult {
    pub package: String,
    pub version: String,
    pub risk_level: RiskLevel,
    pub risk_reasons: Vec<String>,
    pub trust_score: u8,
    pub cves: Vec<CveSummary>,
    pub agentic_threats: Vec<AgenticThreatSummary>,
    pub capabilities: PackageCapabilities,
    pub skill_md: String,
}

/// Main package scanner
pub struct PackageScanner {
    db: Database,
    adapters: AdapterRegistry,
    cve_scanner: CveScanner,
    agentic_scanner: AgenticScanner,
    capability_extractor: CapabilityExtractor,
}

impl PackageScanner {
    /// Create a new package scanner
    ///
    /// Note: Agentic scanning now uses OpenCode CLI instead of direct API calls.
    /// OpenCode handles its own API key configuration.
    pub fn new(db: Database) -> Self {
        Self {
            db,
            adapters: AdapterRegistry::new(),
            cve_scanner: CveScanner::new(),
            agentic_scanner: AgenticScanner::new(None),
            capability_extractor: CapabilityExtractor::new(),
        }
    }

    /// Unified scan method for all registries
    pub async fn scan_unified(
        &self,
        registry: Registry,
        name: &str,
        version: Option<&str>,
    ) -> Result<ScanResult> {
        let adapter = self
            .adapters
            .get(registry)
            .ok_or_else(|| anyhow::anyhow!("Unsupported registry: {:?}", registry))?;

        // 1. Fetch metadata
        tracing::debug!(name, ?registry, "Fetching package metadata");
        let metadata = adapter.fetch_metadata(name, version).await?;

        // 2. Download and extract
        tracing::debug!(name, version = %metadata.version, "Downloading package");
        let extracted = adapter.download_package(name, &metadata.version).await?;

        self.scan_extracted_unified(adapter, name, &metadata, extracted)
            .await
    }

    /// Scan a local tarball using the appropriate adapter
    pub async fn scan_tarball_unified(
        &self,
        registry: Registry,
        tarball_path: &std::path::Path,
    ) -> Result<ScanResult> {
        let adapter = self
            .adapters
            .get(registry)
            .ok_or_else(|| anyhow::anyhow!("Unsupported registry: {:?}", registry))?;

        tracing::debug!(tarball_path = ?tarball_path, ?registry, "Extracting local package");
        let extracted = adapter.extract_local(tarball_path)?;

        // Get package name and version from manifest
        let (name, version) = self.extract_name_version(&extracted, registry)?;

        // Create basic metadata (no remote metadata available for local tarball)
        let metadata = PackageMetadata {
            name: name.clone(),
            version: version.clone(),
            ..Default::default()
        };

        self.scan_extracted_unified(adapter, &name, &metadata, extracted)
            .await
    }

    /// Extract name and version from manifest
    fn extract_name_version(
        &self,
        extracted: &ExtractedPackage,
        registry: Registry,
    ) -> Result<(String, String)> {
        match registry {
            Registry::Npm => {
                let name = extracted
                    .manifest
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("No name in package.json"))?
                    .to_string();

                let version = extracted
                    .manifest
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0")
                    .to_string();

                Ok((name, version))
            }
            Registry::Pypi => {
                // Try to extract from PKG-INFO or pyproject.toml
                extract_pypi_name_version(&extracted.manifest)
            }
            Registry::Crates => {
                // TODO: Implement for Cargo.toml
                anyhow::bail!("Crates.io registry not yet supported")
            }
        }
    }

    /// Common scanning logic for extracted packages (unified)
    async fn scan_extracted_unified(
        &self,
        adapter: Arc<dyn RegistryAdapter>,
        name: &str,
        metadata: &PackageMetadata,
        extracted: ExtractedPackage,
    ) -> Result<ScanResult> {
        let registry = adapter.registry();
        let version = &metadata.version;

        // Run all analyses in parallel
        let (cves, agentic_threats, capabilities, usage_docs) = tokio::join!(
            self.scan_cves_with_adapter(&*adapter, name, version),
            self.agentic_scanner.scan(&extracted),
            async { self.capability_extractor.extract(&extracted) },
            self.agentic_scanner.generate_usage_docs(&extracted, name)
        );

        let cves = cves.unwrap_or_else(|e| {
            tracing::warn!("CVE scan failed: {}", e);
            vec![]
        });

        let agentic_threats = agentic_threats.unwrap_or_else(|e| {
            tracing::warn!("Agentic scan failed: {}", e);
            vec![]
        });

        // Verify threats if any were detected
        let agentic_threats = if !agentic_threats.is_empty() {
            tracing::info!(
                "Verifying {} detected threats with secondary model",
                agentic_threats.len()
            );
            match self
                .agentic_scanner
                .verify_threats(&extracted, agentic_threats.clone())
                .await
            {
                Ok(verified) => verified,
                Err(e) => {
                    tracing::warn!(
                        "Threat verification failed, keeping original {} threats: {}",
                        agentic_threats.len(),
                        e
                    );
                    agentic_threats
                }
            }
        } else {
            agentic_threats
        };

        let capabilities = capabilities.unwrap_or_default();

        let usage_docs = usage_docs.unwrap_or_else(|e| {
            tracing::warn!("Usage docs generation failed: {}", e);
            UsageDocs::default()
        });

        // Calculate trust score using adapter
        let trust_score = adapter.compute_trust_score(metadata);

        // Determine risk level
        let (risk_level, risk_reasons) =
            calculate_risk(&cves, &agentic_threats, &capabilities, trust_score);

        // Generate SKILL.md
        let skill_md = generate_skill_md(
            name,
            version,
            &capabilities,
            &risk_level,
            &risk_reasons,
            &usage_docs,
        );

        // Fetch download stats
        let weekly_downloads = adapter.fetch_downloads(name).await.unwrap_or(None);

        // Save to database
        let maintainer_count = metadata.maintainers.len() as i32;
        let maintainers_json = serde_json::to_value(&metadata.maintainers).ok();

        let package_id = self
            .db
            .upsert_package(&NewPackage {
                name: name.to_string(),
                version: version.to_string(),
                registry,
                risk_level,
                risk_reasons: serde_json::to_value(&risk_reasons)?,
                trust_score: Some(trust_score as i16),
                publisher_verified: None,
                weekly_downloads,
                maintainer_count: Some(maintainer_count),
                maintainers: maintainers_json,
                last_publish: metadata.published_at,
                capabilities: serde_json::to_value(&capabilities)?,
                skill_md: Some(skill_md.clone()),
                scan_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            })
            .await?;

        // Clear old CVEs and threats
        self.db.delete_package_cves(package_id).await?;
        self.db.delete_package_threats(package_id).await?;

        // Insert new CVEs
        for cve in &cves {
            self.db
                .insert_cve(&NewPackageCve {
                    package_id,
                    cve_id: cve.cve_id.clone(),
                    severity: cve.severity.clone(),
                    description: cve.description.clone(),
                    fixed_in: cve.fixed_in.clone(),
                    published_at: None,
                })
                .await?;
        }

        // Insert new threats
        for threat in &agentic_threats {
            self.db
                .insert_threat(&NewAgenticThreat {
                    package_id,
                    threat_type: threat.threat_type,
                    confidence: threat.confidence,
                    location: threat.location.clone(),
                    snippet: threat.snippet.clone(),
                })
                .await?;
        }

        Ok(ScanResult {
            package: name.to_string(),
            version: version.to_string(),
            risk_level,
            risk_reasons,
            trust_score,
            cves,
            agentic_threats,
            capabilities,
            skill_md,
        })
    }

    /// Scan for CVEs using adapter's ecosystem
    async fn scan_cves_with_adapter(
        &self,
        adapter: &dyn RegistryAdapter,
        name: &str,
        version: &str,
    ) -> Result<Vec<CveSummary>> {
        match adapter.cve_ecosystem() {
            Some(ecosystem) => {
                self.cve_scanner
                    .scan_with_ecosystem(name, version, ecosystem)
                    .await
            }
            None => Ok(vec![]),
        }
    }

    /// Scan a package from npm registry (delegates to unified scan)
    #[allow(dead_code)]
    pub async fn scan(&self, package: &str, version: Option<&str>) -> Result<ScanResult> {
        self.scan_unified(Registry::Npm, package, version).await
    }

    /// Scan a local tarball file (delegates to unified scan)
    #[allow(dead_code)]
    pub async fn scan_tarball(&self, tarball_path: &std::path::Path) -> Result<ScanResult> {
        self.scan_tarball_unified(Registry::Npm, tarball_path).await
    }

    /// Scan a package from PyPI registry (delegates to unified scan)
    #[allow(dead_code)]
    pub async fn scan_pypi(&self, package: &str, version: Option<&str>) -> Result<ScanResult> {
        self.scan_unified(Registry::Pypi, package, version).await
    }

    /// Scan a local Python package file (delegates to unified scan)
    #[allow(dead_code)]
    pub async fn scan_pypi_tarball(&self, path: &std::path::Path) -> Result<ScanResult> {
        self.scan_tarball_unified(Registry::Pypi, path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{NpmMaintainer, ThreatType};

    // Trust score tests

    #[test]
    fn test_trust_score_no_metadata() {
        let score = calculate_trust_score(None);
        assert_eq!(score, 50, "Base score without metadata should be 50");
    }

    #[test]
    fn test_trust_score_zero_maintainers() {
        let metadata = NpmPackageMetadata {
            name: "test".to_string(),
            description: None,
            dist_tags: None,
            versions: None,
            maintainers: Some(vec![]),
            repository: None,
            time: None,
        };
        let score = calculate_trust_score(Some(&metadata));
        assert_eq!(score, 40, "0 maintainers should be 50-10=40");
    }

    #[test]
    fn test_trust_score_one_maintainer() {
        let metadata = NpmPackageMetadata {
            name: "test".to_string(),
            description: None,
            dist_tags: None,
            versions: None,
            maintainers: Some(vec![NpmMaintainer {
                name: Some("dev".to_string()),
                email: None,
            }]),
            repository: None,
            time: None,
        };
        let score = calculate_trust_score(Some(&metadata));
        assert_eq!(score, 50, "1 maintainer should keep base score 50");
    }

    #[test]
    fn test_trust_score_multiple_maintainers() {
        let metadata = NpmPackageMetadata {
            name: "test".to_string(),
            description: None,
            dist_tags: None,
            versions: None,
            maintainers: Some(vec![
                NpmMaintainer {
                    name: Some("dev1".to_string()),
                    email: None,
                },
                NpmMaintainer {
                    name: Some("dev2".to_string()),
                    email: None,
                },
                NpmMaintainer {
                    name: Some("dev3".to_string()),
                    email: None,
                },
            ]),
            repository: None,
            time: None,
        };
        let score = calculate_trust_score(Some(&metadata));
        assert_eq!(score, 60, "2-5 maintainers should be 50+10=60");
    }

    #[test]
    fn test_trust_score_many_maintainers() {
        let maintainers: Vec<NpmMaintainer> = (0..10)
            .map(|i| NpmMaintainer {
                name: Some(format!("dev{}", i)),
                email: None,
            })
            .collect();
        let metadata = NpmPackageMetadata {
            name: "test".to_string(),
            description: None,
            dist_tags: None,
            versions: None,
            maintainers: Some(maintainers),
            repository: None,
            time: None,
        };
        let score = calculate_trust_score(Some(&metadata));
        assert_eq!(score, 70, "6+ maintainers should be 50+20=70");
    }

    #[test]
    fn test_trust_score_with_repo_and_description() {
        let metadata = NpmPackageMetadata {
            name: "test".to_string(),
            description: Some("A great package".to_string()),
            dist_tags: None,
            versions: None,
            maintainers: Some(vec![NpmMaintainer {
                name: Some("dev".to_string()),
                email: None,
            }]),
            repository: Some(
                serde_json::json!({"type": "git", "url": "https://github.com/test/test"}),
            ),
            time: None,
        };
        let score = calculate_trust_score(Some(&metadata));
        assert_eq!(score, 65, "1 maintainer + repo + desc should be 50+10+5=65");
    }

    #[test]
    fn test_trust_score_max_100() {
        let maintainers: Vec<NpmMaintainer> = (0..20)
            .map(|i| NpmMaintainer {
                name: Some(format!("dev{}", i)),
                email: None,
            })
            .collect();
        let metadata = NpmPackageMetadata {
            name: "test".to_string(),
            description: Some("A great package".to_string()),
            dist_tags: None,
            versions: None,
            maintainers: Some(maintainers),
            repository: Some(
                serde_json::json!({"type": "git", "url": "https://github.com/test/test"}),
            ),
            time: None,
        };
        let score = calculate_trust_score(Some(&metadata));
        assert!(score <= 100, "Trust score should never exceed 100");
    }

    // Risk calculation tests

    #[test]
    fn test_risk_clean_package() {
        let (level, reasons) = calculate_risk(&[], &[], &PackageCapabilities::default(), 75);
        assert_eq!(level, RiskLevel::Clean);
        assert!(reasons.is_empty());
    }

    #[test]
    fn test_risk_critical_cve() {
        let cves = vec![CveSummary {
            cve_id: "CVE-2024-1234".to_string(),
            severity: Some("CRITICAL".to_string()),
            description: Some("Bad vulnerability".to_string()),
            fixed_in: Some("2.0.0".to_string()),
        }];
        let (level, reasons) = calculate_risk(&cves, &[], &PackageCapabilities::default(), 75);
        assert_eq!(level, RiskLevel::Critical);
        assert!(reasons.iter().any(|r| r.contains("CVE-2024-1234")));
    }

    #[test]
    fn test_risk_high_cve() {
        let cves = vec![CveSummary {
            cve_id: "CVE-2024-5678".to_string(),
            severity: Some("HIGH".to_string()),
            description: None,
            fixed_in: None,
        }];
        let (level, _) = calculate_risk(&cves, &[], &PackageCapabilities::default(), 75);
        assert_eq!(
            level,
            RiskLevel::Critical,
            "HIGH severity should be Critical"
        );
    }

    #[test]
    fn test_risk_medium_cve() {
        let cves = vec![CveSummary {
            cve_id: "CVE-2024-9999".to_string(),
            severity: Some("MEDIUM".to_string()),
            description: None,
            fixed_in: None,
        }];
        let (level, _) = calculate_risk(&cves, &[], &PackageCapabilities::default(), 75);
        assert_eq!(
            level,
            RiskLevel::Warning,
            "MEDIUM severity should be Warning"
        );
    }

    #[test]
    fn test_risk_high_confidence_threat() {
        let threats = vec![AgenticThreatSummary {
            threat_type: ThreatType::PromptInjection,
            confidence: 0.9,
            location: Some("README.md".to_string()),
            snippet: Some("ignore previous instructions".to_string()),
        }];
        let (level, reasons) = calculate_risk(&[], &threats, &PackageCapabilities::default(), 75);
        assert_eq!(level, RiskLevel::Critical);
        assert!(reasons.iter().any(|r| r.contains("PromptInjection")));
    }

    #[test]
    fn test_risk_medium_confidence_threat() {
        let threats = vec![AgenticThreatSummary {
            threat_type: ThreatType::DataExfiltration,
            confidence: 0.6,
            location: None,
            snippet: None,
        }];
        let (level, reasons) = calculate_risk(&[], &threats, &PackageCapabilities::default(), 75);
        assert_eq!(level, RiskLevel::Warning);
        assert!(reasons.iter().any(|r| r.contains("Possible")));
    }

    #[test]
    fn test_risk_low_confidence_threat_ignored() {
        let threats = vec![AgenticThreatSummary {
            threat_type: ThreatType::SocialEngineering,
            confidence: 0.3,
            location: None,
            snippet: None,
        }];
        let (level, reasons) = calculate_risk(&[], &threats, &PackageCapabilities::default(), 75);
        assert_eq!(
            level,
            RiskLevel::Clean,
            "Low confidence threats should be ignored"
        );
        assert!(reasons.is_empty());
    }

    #[test]
    fn test_risk_native_code() {
        let mut capabilities = PackageCapabilities::default();
        capabilities.native.has_native = true;
        let (level, reasons) = calculate_risk(&[], &[], &capabilities, 75);
        assert_eq!(level, RiskLevel::Warning);
        assert!(reasons.iter().any(|r| r.contains("native code")));
    }

    #[test]
    fn test_risk_spawns_children() {
        let mut capabilities = PackageCapabilities::default();
        capabilities.process.spawns_children = true;
        let (level, reasons) = calculate_risk(&[], &[], &capabilities, 75);
        assert_eq!(level, RiskLevel::Warning);
        assert!(reasons.iter().any(|r| r.contains("spawn child processes")));
    }

    #[test]
    fn test_risk_low_trust_score() {
        let (level, reasons) = calculate_risk(&[], &[], &PackageCapabilities::default(), 25);
        assert_eq!(level, RiskLevel::Warning);
        assert!(reasons.iter().any(|r| r.contains("Low trust score")));
    }

    #[test]
    fn test_risk_critical_overrides_warning() {
        let cves = vec![
            CveSummary {
                cve_id: "CVE-2024-1111".to_string(),
                severity: Some("MEDIUM".to_string()),
                description: None,
                fixed_in: None,
            },
            CveSummary {
                cve_id: "CVE-2024-2222".to_string(),
                severity: Some("CRITICAL".to_string()),
                description: None,
                fixed_in: None,
            },
        ];
        let (level, _) = calculate_risk(&cves, &[], &PackageCapabilities::default(), 75);
        assert_eq!(
            level,
            RiskLevel::Critical,
            "Critical should override Warning"
        );
    }
}
