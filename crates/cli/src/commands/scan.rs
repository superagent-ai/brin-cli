//! Scan command - scan current project for vulnerabilities

use crate::api_client::SusClient;
use crate::ui::{self, print_scan_summary};
use anyhow::Result;
use colored::Colorize;
use common::{PackageResponse, PackageVersionPair, RiskLevel};
use std::collections::HashMap;
use std::path::Path;

/// Run the scan command
pub async fn run(client: &SusClient, json: bool) -> Result<()> {
    // Find package.json
    if !Path::new("package.json").exists() {
        anyhow::bail!("No package.json found in current directory");
    }

    // Parse dependencies
    let pb = ui::spinner("reading dependencies...");
    let deps = get_all_dependencies()?;
    ui::finish_spinner(&pb, "📦", &format!("found {} packages", deps.len()));

    if deps.is_empty() {
        println!("  no dependencies found");
        return Ok(());
    }

    if !json {
        println!();
        println!("🔍 scanning {} packages...", deps.len());
        println!();
    }

    // Batch lookup
    let pb = ui::spinner("checking security database...");
    let assessments = client.bulk_lookup(&deps).await.unwrap_or_else(|e| {
        tracing::warn!(
            "Bulk lookup failed: {}, falling back to individual lookups",
            e
        );
        vec![]
    });
    ui::finish_spinner(&pb, "✓", &format!("got {} assessments", assessments.len()));

    // Build lookup map
    let assessment_map: HashMap<String, &PackageResponse> = assessments
        .iter()
        .map(|a| (format!("{}@{}", a.name, a.version), a))
        .collect();

    // Categorize
    let mut clean = Vec::new();
    let mut warnings = Vec::new();
    let mut critical = Vec::new();
    let mut unknown = Vec::new();

    for dep in &deps {
        let key = format!("{}@{}", dep.name, dep.version);
        if let Some(assessment) = assessment_map.get(&key) {
            match assessment.risk_level {
                RiskLevel::Clean => clean.push(*assessment),
                RiskLevel::Warning => warnings.push(*assessment),
                RiskLevel::Critical => critical.push(*assessment),
            }
        } else {
            unknown.push(dep);
        }
    }

    if json {
        let output = serde_json::json!({
            "total": deps.len(),
            "clean": clean.len(),
            "warnings": warnings.len(),
            "critical": critical.len(),
            "unknown": unknown.len(),
            "packages": assessments,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // Print critical issues
    for assessment in &critical {
        println!();
        println!("📦 {}@{}", assessment.name.red().bold(), assessment.version);
        print!("   🚨 MEGA SUS");
        if let Some(reason) = assessment.risk_reasons.first() {
            print!(" — {}", reason.red());
        }
        println!();
    }

    // Print warnings
    for assessment in &warnings {
        println!();
        println!("📦 {}@{}", assessment.name.yellow(), assessment.version);
        print!("   ⚠️  kinda sus");
        if let Some(cve) = assessment.cves.first() {
            let severity = cve.severity.as_deref().unwrap_or("unknown");
            print!(" — {} ({})", cve.cve_id.yellow(), severity.to_lowercase());
        } else if let Some(reason) = assessment.risk_reasons.first() {
            print!(" — {}", reason);
        }
        println!();
    }

    // Print unknown packages
    if !unknown.is_empty() {
        println!(
            "📦 {} packages not yet scanned:",
            unknown.len().to_string().dimmed()
        );
        for dep in &unknown {
            println!("   {} {}@{}", "?".dimmed(), dep.name, dep.version);
        }
        println!();
        println!("   run {} to request scans", "sus check <package>".cyan());
        println!();
    }

    // Summary
    print_scan_summary(clean.len(), warnings.len(), critical.len());

    if !critical.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

/// Parse package.json and package-lock.json to get all dependencies
fn get_all_dependencies() -> Result<Vec<PackageVersionPair>> {
    let mut deps = Vec::new();

    // Read package.json
    let pkg_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("package.json")?)?;

    // Collect from dependencies
    if let Some(dependencies) = pkg_json.get("dependencies").and_then(|d| d.as_object()) {
        for (name, version) in dependencies {
            if let Some(v) = version.as_str() {
                deps.push(PackageVersionPair {
                    name: name.clone(),
                    version: clean_version(v),
                    registry: None,
                });
            }
        }
    }

    // Collect from devDependencies
    if let Some(dev_deps) = pkg_json.get("devDependencies").and_then(|d| d.as_object()) {
        for (name, version) in dev_deps {
            if let Some(v) = version.as_str() {
                deps.push(PackageVersionPair {
                    name: name.clone(),
                    version: clean_version(v),
                    registry: None,
                });
            }
        }
    }

    // Try to get exact versions from lock file
    if Path::new("package-lock.json").exists() {
        if let Ok(content) = std::fs::read_to_string("package-lock.json") {
            if let Ok(lock_json) = serde_json::from_str::<serde_json::Value>(&content) {
                // Try v3 format (npm 7+)
                if let Some(packages) = lock_json.get("packages").and_then(|p| p.as_object()) {
                    deps.clear();
                    for (path, info) in packages {
                        // Skip root package
                        if path.is_empty() {
                            continue;
                        }
                        // Extract package name from path like "node_modules/lodash"
                        let name = path.strip_prefix("node_modules/").unwrap_or(path);
                        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                            deps.push(PackageVersionPair {
                                name: name.to_string(),
                                version: version.to_string(),
                                registry: None,
                            });
                        }
                    }
                }
                // Try v1/v2 format
                else if let Some(dependencies) =
                    lock_json.get("dependencies").and_then(|d| d.as_object())
                {
                    deps.clear();
                    collect_lock_deps(dependencies, &mut deps);
                }
            }
        }
    }

    // Deduplicate
    deps.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    deps.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(deps)
}

/// Recursively collect dependencies from package-lock v1/v2 format
fn collect_lock_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    out: &mut Vec<PackageVersionPair>,
) {
    for (name, info) in deps {
        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
            out.push(PackageVersionPair {
                name: name.clone(),
                version: version.to_string(),
                registry: None,
            });
        }
        // Recurse into nested dependencies
        if let Some(nested) = info.get("dependencies").and_then(|d| d.as_object()) {
            collect_lock_deps(nested, out);
        }
    }
}

/// Clean version string (remove ^, ~, etc.)
fn clean_version(version: &str) -> String {
    version
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches('>')
        .trim_start_matches('<')
        .trim_start_matches('=')
        .to_string()
}
