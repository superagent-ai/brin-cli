//! Scan command - scan current project for vulnerabilities

use crate::api_client::SusClient;
use crate::ui::{self, print_scan_summary};
use anyhow::Result;
use colored::Colorize;
use common::{PackageResponse, PackageVersionPair, Registry, RiskLevel};
use std::collections::HashMap;
use std::path::Path;

/// Detected project type
#[derive(Debug, Clone, Copy, PartialEq)]
enum ProjectType {
    Npm,
    Python,
}

/// Run the scan command
pub async fn run(client: &SusClient, json: bool) -> Result<()> {
    // Detect project type
    let project_type = detect_project_type();

    let (deps, project_name) = match project_type {
        Some(ProjectType::Npm) => {
            let pb = ui::spinner("reading npm dependencies...");
            let deps = get_npm_dependencies()?;
            ui::finish_spinner(&pb, "📦", &format!("found {} npm packages", deps.len()));
            (deps, "npm")
        }
        Some(ProjectType::Python) => {
            let pb = ui::spinner("reading python dependencies...");
            let deps = get_python_dependencies()?;
            ui::finish_spinner(&pb, "🐍", &format!("found {} python packages", deps.len()));
            (deps, "python")
        }
        None => {
            anyhow::bail!(
                "No supported project files found.\n\
                 Supported files:\n\
                 - npm: package.json\n\
                 - python: requirements.txt, pyproject.toml"
            );
        }
    };

    if deps.is_empty() {
        println!("  no dependencies found");
        return Ok(());
    }

    if !json {
        println!();
        println!("🔍 scanning {} {} packages...", deps.len(), project_name);
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
            "project_type": project_name,
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

/// Detect the project type based on files present
fn detect_project_type() -> Option<ProjectType> {
    // Check for npm first
    if Path::new("package.json").exists() {
        return Some(ProjectType::Npm);
    }

    // Check for Python
    if Path::new("requirements.txt").exists()
        || Path::new("pyproject.toml").exists()
        || Path::new("setup.py").exists()
        || Path::new("Pipfile").exists()
    {
        return Some(ProjectType::Python);
    }

    None
}

/// Parse package.json and package-lock.json to get all npm dependencies
fn get_npm_dependencies() -> Result<Vec<PackageVersionPair>> {
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
                    registry: Some(Registry::Npm),
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
                    registry: Some(Registry::Npm),
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
                                registry: Some(Registry::Npm),
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

/// Parse Python dependency files to get all dependencies
fn get_python_dependencies() -> Result<Vec<PackageVersionPair>> {
    let mut deps = Vec::new();

    // Try requirements.txt first (most common)
    if Path::new("requirements.txt").exists() {
        let content = std::fs::read_to_string("requirements.txt")?;
        parse_requirements_txt(&content, &mut deps);
    }

    // Try pyproject.toml
    if Path::new("pyproject.toml").exists() {
        let content = std::fs::read_to_string("pyproject.toml")?;
        parse_pyproject_toml(&content, &mut deps);
    }

    // Try Pipfile (Pipenv)
    if Path::new("Pipfile").exists() {
        let content = std::fs::read_to_string("Pipfile")?;
        parse_pipfile(&content, &mut deps);
    }

    // Try Pipfile.lock for exact versions
    if Path::new("Pipfile.lock").exists() {
        if let Ok(content) = std::fs::read_to_string("Pipfile.lock") {
            parse_pipfile_lock(&content, &mut deps);
        }
    }

    // Deduplicate (keep the one with a version if there are duplicates)
    deps.sort_by(|a, b| {
        let name_cmp = a.name.to_lowercase().cmp(&b.name.to_lowercase());
        if name_cmp == std::cmp::Ordering::Equal {
            // Prefer non-empty versions
            b.version.len().cmp(&a.version.len())
        } else {
            name_cmp
        }
    });
    deps.dedup_by(|a, b| a.name.to_lowercase() == b.name.to_lowercase());

    Ok(deps)
}

/// Parse requirements.txt format
fn parse_requirements_txt(content: &str, deps: &mut Vec<PackageVersionPair>) {
    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Skip -r, -e, --extra-index-url, etc.
        if line.starts_with('-') {
            continue;
        }

        // Parse package==version, package>=version, package~=version, etc.
        if let Some((name, version)) = parse_python_requirement(line) {
            deps.push(PackageVersionPair {
                name,
                version,
                registry: Some(Registry::Pypi),
            });
        }
    }
}

/// Parse a single Python requirement line
fn parse_python_requirement(line: &str) -> Option<(String, String)> {
    // Remove environment markers (everything after ;)
    let line = line.split(';').next()?.trim();

    // Remove extras (e.g., package[extra1,extra2])
    let line = if let Some(bracket_pos) = line.find('[') {
        if let Some(bracket_end) = line.find(']') {
            format!("{}{}", &line[..bracket_pos], &line[bracket_end + 1..])
        } else {
            line.to_string()
        }
    } else {
        line.to_string()
    };

    // Try different version specifiers
    let specifiers = ["===", "==", "~=", "!=", ">=", "<=", ">", "<"];

    for spec in specifiers {
        if let Some(pos) = line.find(spec) {
            let name = line[..pos].trim().to_string();
            let version_part = line[pos + spec.len()..].trim();

            // Handle version ranges like >=1.0,<2.0
            let version = version_part
                .split(',')
                .next()
                .unwrap_or(version_part)
                .trim()
                .to_string();

            if !name.is_empty() {
                return Some((name, version));
            }
        }
    }

    // No version specified - just package name
    let name = line.trim().to_string();
    if !name.is_empty() && !name.contains(' ') {
        return Some((name, "latest".to_string()));
    }

    None
}

/// Parse pyproject.toml for dependencies
fn parse_pyproject_toml(content: &str, deps: &mut Vec<PackageVersionPair>) {
    // Simple line-by-line parsing for dependencies
    let mut in_dependencies = false;
    let mut in_optional_deps = false;

    for line in content.lines() {
        let line = line.trim();

        // Check for dependencies section
        if line == "[project.dependencies]" || line.starts_with("dependencies = [") {
            in_dependencies = true;
            continue;
        }

        if line.starts_with("[project.optional-dependencies") {
            in_optional_deps = true;
            continue;
        }

        // End of section
        if line.starts_with('[') && !line.contains("dependencies") {
            in_dependencies = false;
            in_optional_deps = false;
            continue;
        }

        // Parse inline dependencies array
        if line.starts_with("dependencies = [") {
            // Handle single-line: dependencies = ["pkg1", "pkg2"]
            if let Some(start) = line.find('[') {
                let deps_str = &line[start + 1..];
                if let Some(end) = deps_str.find(']') {
                    parse_toml_deps_array(&deps_str[..end], deps);
                }
            }
            continue;
        }

        // Parse dependencies in multi-line array
        if in_dependencies || in_optional_deps {
            // Handle closing bracket
            if line == "]" || line == "]," {
                in_dependencies = false;
                in_optional_deps = false;
                continue;
            }

            // Parse quoted dependency
            let line = line.trim_matches(',');
            if let Some(dep) = extract_quoted_string(line) {
                if let Some((name, version)) = parse_python_requirement(&dep) {
                    deps.push(PackageVersionPair {
                        name,
                        version,
                        registry: Some(Registry::Pypi),
                    });
                }
            }
        }
    }
}

/// Parse TOML dependencies array content (between [ and ])
fn parse_toml_deps_array(content: &str, deps: &mut Vec<PackageVersionPair>) {
    // Split by comma and parse each
    for part in content.split(',') {
        if let Some(dep) = extract_quoted_string(part.trim()) {
            if let Some((name, version)) = parse_python_requirement(&dep) {
                deps.push(PackageVersionPair {
                    name,
                    version,
                    registry: Some(Registry::Pypi),
                });
            }
        }
    }
}

/// Extract string content from quotes
fn extract_quoted_string(s: &str) -> Option<String> {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}

/// Parse Pipfile for dependencies
fn parse_pipfile(content: &str, deps: &mut Vec<PackageVersionPair>) {
    let mut in_packages = false;
    let mut in_dev_packages = false;

    for line in content.lines() {
        let line = line.trim();

        if line == "[packages]" {
            in_packages = true;
            in_dev_packages = false;
            continue;
        }

        if line == "[dev-packages]" {
            in_packages = false;
            in_dev_packages = true;
            continue;
        }

        if line.starts_with('[') {
            in_packages = false;
            in_dev_packages = false;
            continue;
        }

        if in_packages || in_dev_packages {
            // Parse: package = "version" or package = "*"
            if let Some(eq_pos) = line.find('=') {
                let name = line[..eq_pos].trim().to_string();
                let version_part = line[eq_pos + 1..].trim();

                // Remove quotes
                let version = version_part
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();

                if !name.is_empty() {
                    let version = if version == "*" {
                        "latest".to_string()
                    } else {
                        version
                    };

                    deps.push(PackageVersionPair {
                        name,
                        version,
                        registry: Some(Registry::Pypi),
                    });
                }
            }
        }
    }
}

/// Parse Pipfile.lock for exact versions
fn parse_pipfile_lock(content: &str, deps: &mut Vec<PackageVersionPair>) {
    if let Ok(lock_json) = serde_json::from_str::<serde_json::Value>(content) {
        for section in ["default", "develop"] {
            if let Some(packages) = lock_json.get(section).and_then(|p| p.as_object()) {
                for (name, info) in packages {
                    if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                        // Version in Pipfile.lock starts with ==
                        let version = version.trim_start_matches("==").to_string();
                        deps.push(PackageVersionPair {
                            name: name.clone(),
                            version,
                            registry: Some(Registry::Pypi),
                        });
                    }
                }
            }
        }
    }
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
                registry: Some(Registry::Npm),
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
