//! Package scanner module

mod agentic;
mod capabilities;
mod cve;
mod npm;

use crate::skill_generator::generate_skill_md;
use anyhow::Result;
use capabilities::CapabilityExtractor;
use common::{
    db::{NewAgenticThreat, NewPackage, NewPackageCve},
    AgenticThreatSummary, CveSummary, Database, NpmPackageMetadata, PackageCapabilities, RiskLevel,
    UsageDocs,
};
use cve::CveScanner;
use npm::NpmClient;

// Re-export AgenticScanner for OpenCode installation check from main.rs
pub use agentic::AgenticScanner;

/// Calculate trust score (0-100) based on package metadata
///
/// Scoring:
/// - Base score: 50
/// - 0 maintainers: -10
/// - 2-5 maintainers: +10
/// - 6+ maintainers: +20
/// - Has repository: +10
/// - Has description: +5
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
    npm: NpmClient,
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
            npm: NpmClient::new(),
            cve_scanner: CveScanner::new(),
            agentic_scanner: AgenticScanner::new(None),
            capability_extractor: CapabilityExtractor::new(),
        }
    }

    /// Scan a package from npm registry
    pub async fn scan(&self, package: &str, version: Option<&str>) -> Result<ScanResult> {
        // 1. Fetch package metadata
        tracing::debug!(package, "Fetching package metadata");
        let metadata = self.npm.fetch_metadata(package).await?;

        // Determine version to scan
        let version = match version {
            Some(v) => v.to_string(),
            None => {
                // Get latest version from dist-tags
                metadata
                    .dist_tags
                    .as_ref()
                    .and_then(|tags| tags.get("latest"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .ok_or_else(|| anyhow::anyhow!("Could not determine latest version"))?
            }
        };

        // 2. Fetch version-specific info
        tracing::debug!(package, version = %version, "Fetching version info");
        let version_info = self.npm.fetch_version_info(package, &version).await?;

        // 3. Download and extract tarball
        tracing::debug!(package, version = %version, "Downloading tarball");
        let extracted = self.npm.download_and_extract(package, &version).await?;

        self.scan_extracted(
            package,
            &version,
            Some(&metadata),
            Some(&version_info),
            extracted,
        )
        .await
    }

    /// Scan a local tarball file
    pub async fn scan_tarball(&self, tarball_path: &std::path::Path) -> Result<ScanResult> {
        tracing::debug!(tarball_path = ?tarball_path, "Extracting local tarball");
        let extracted = self.npm.extract_local_tarball(tarball_path)?;

        // Get package name and version from package.json
        let package = extracted
            .package_json
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("No name in package.json"))?
            .to_string();

        let version = extracted
            .package_json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0")
            .to_string();

        self.scan_extracted(&package, &version, None, None, extracted)
            .await
    }

    /// Common scanning logic for extracted packages
    async fn scan_extracted(
        &self,
        package: &str,
        version: &str,
        metadata: Option<&common::NpmPackageMetadata>,
        _version_info: Option<&common::NpmVersionInfo>,
        extracted: npm::ExtractedPackage,
    ) -> Result<ScanResult> {
        // 4. Run all analyses in parallel
        let (cves, agentic_threats, capabilities, usage_docs) = tokio::join!(
            self.cve_scanner.scan(package, version),
            self.agentic_scanner.scan(&extracted),
            async { self.capability_extractor.extract(&extracted) },
            self.agentic_scanner
                .generate_usage_docs(&extracted, package)
        );

        let cves = cves.unwrap_or_else(|e| {
            tracing::warn!("CVE scan failed: {}", e);
            vec![]
        });

        let agentic_threats = agentic_threats.unwrap_or_else(|e| {
            tracing::warn!("Agentic scan failed: {}", e);
            vec![]
        });

        let capabilities = capabilities.unwrap_or_default();

        let usage_docs = usage_docs.unwrap_or_else(|e| {
            tracing::warn!("Usage docs generation failed: {}", e);
            UsageDocs::default()
        });

        // 5. Calculate trust score
        let trust_score = calculate_trust_score(metadata);

        // 6. Determine risk level
        let (risk_level, risk_reasons) =
            calculate_risk(&cves, &agentic_threats, &capabilities, trust_score);

        // 7. Generate SKILL.md
        let skill_md = generate_skill_md(
            package,
            version,
            &capabilities,
            &risk_level,
            &risk_reasons,
            &usage_docs,
        );

        // 8. Save to database
        let package_id = self
            .db
            .upsert_package(&NewPackage {
                name: package.to_string(),
                version: version.to_string(),
                risk_level,
                risk_reasons: serde_json::to_value(&risk_reasons)?,
                trust_score: Some(trust_score as i16),
                publisher_verified: None, // TODO: check npm verified publisher
                weekly_downloads: None,   // TODO: fetch from npm
                maintainer_count: metadata
                    .and_then(|m| m.maintainers.as_ref())
                    .map(|m| m.len() as i32),
                last_publish: None,
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
            package: package.to_string(),
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
