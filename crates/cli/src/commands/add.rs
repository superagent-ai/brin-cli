//! Add command - install packages with safety checks

use crate::api_client::SusClient;
use crate::ui::{self, print_capabilities, print_risk};
use anyhow::Result;
use colored::Colorize;
use common::RiskLevel;
use dialoguer::Confirm;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Parse a package string into name and optional version
fn parse_package_spec(spec: &str) -> (&str, Option<&str>) {
    // Handle scoped packages like @types/node@1.0.0
    if let Some(rest) = spec.strip_prefix('@') {
        // Find the second @ for version
        if let Some(idx) = rest.find('@') {
            let idx = idx + 1; // Adjust for the @ prefix
            return (&spec[..idx], Some(&spec[idx + 1..]));
        }
        return (spec, None);
    }

    // Regular package like lodash@4.17.0
    if let Some(idx) = spec.find('@') {
        return (&spec[..idx], Some(&spec[idx + 1..]));
    }

    (spec, None)
}

/// Run the add command
pub async fn run(
    client: &SusClient,
    packages: Vec<String>,
    yolo: bool,
    strict: bool,
) -> Result<()> {
    for package_spec in &packages {
        let (name, version) = parse_package_spec(package_spec);
        let display_name = if let Some(v) = version {
            format!("{}@{}", name, v)
        } else {
            name.to_string()
        };

        let pb = ui::spinner(&format!("checking {}...", display_name));

        // Fetch assessment from API
        let assessment = match if let Some(v) = version {
            client.get_package_version(name, v).await
        } else {
            client.get_package(name).await
        } {
            Ok(a) => {
                ui::finish_spinner(&pb, a.risk_level.emoji(), &display_name);
                a
            }
            Err(e) => {
                if e.to_string().contains("not found") {
                    ui::finish_spinner(&pb, "📦", &display_name);
                    println!(
                        "  {} not in sus database yet, requesting scan...",
                        display_name.yellow()
                    );

                    match client.request_scan(name, version).await {
                        Ok(resp) => {
                            println!(
                                "  scan queued (job {}), try again in ~{}s",
                                resp.job_id.to_string().dimmed(),
                                resp.estimated_seconds
                            );
                            if yolo {
                                println!("  {} --yolo mode, installing anyway...", "⚠️".yellow());
                            } else {
                                println!("  use {} to install without scan", "--yolo".cyan());
                                continue;
                            }
                        }
                        Err(scan_err) => {
                            ui::finish_spinner(&pb, "❌", &display_name);
                            println!("  {} failed to request scan: {}", "error:".red(), scan_err);
                            if !yolo {
                                continue;
                            }
                        }
                    }

                    // If yolo, proceed without assessment
                    install_package(package_spec).await?;
                    continue;
                } else {
                    ui::finish_spinner(&pb, "❌", &display_name);
                    println!("  {} {}", "error:".red(), e);
                    continue;
                }
            }
        };

        // Print risk assessment
        print_risk(&assessment);
        print_capabilities(&assessment);

        // Decide whether to install
        let should_install = match assessment.risk_level {
            RiskLevel::Clean => true,

            RiskLevel::Warning => {
                if strict {
                    println!();
                    println!(
                        "   {} {} mode, skipping package with warnings",
                        "⚠️".yellow(),
                        "--strict".cyan()
                    );
                    false
                } else if yolo {
                    true
                } else {
                    println!();
                    Confirm::new()
                        .with_prompt("   Install anyway?")
                        .default(false)
                        .interact()?
                }
            }

            RiskLevel::Critical => {
                println!();
                if yolo {
                    println!(
                        "   {} installing anyway ({} mode)",
                        "🚨".red(),
                        "--yolo".cyan()
                    );
                    true
                } else {
                    println!("❌ not installed. use {} to force (don't)", "--yolo".cyan());
                    false
                }
            }
        };

        if !should_install {
            continue;
        }

        // Install the package
        install_package(package_spec).await?;
        println!("{}", "📦 installed".green());

        // Save package documentation and update AGENTS.md index
        if let Some(package_doc) = &assessment.skill_md {
            // Extract description for the index
            let description = extract_description(&assessment);

            // Save doc file
            if let Err(e) = save_package_doc(name, package_doc) {
                tracing::debug!("Failed to save package doc: {}", e);
            }

            // Update AGENTS.md index
            if let Err(e) = update_agents_md_index(name, &assessment.version, &description) {
                tracing::debug!("Failed to update AGENTS.md index: {}", e);
            }
        }
    }

    Ok(())
}

/// Install a package using npm/pnpm/yarn
async fn install_package(package: &str) -> Result<()> {
    // Detect package manager
    let pm = detect_package_manager();

    let status = Command::new(&pm)
        .args(["add", package])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to run {}: {}", pm, e))?;

    if !status.success() {
        anyhow::bail!("{} add failed with exit code {:?}", pm, status.code());
    }

    Ok(())
}

/// Detect which package manager to use
fn detect_package_manager() -> String {
    // Check for lockfiles in order of preference
    if std::path::Path::new("pnpm-lock.yaml").exists() {
        return "pnpm".to_string();
    }
    if std::path::Path::new("yarn.lock").exists() {
        return "yarn".to_string();
    }
    if std::path::Path::new("bun.lockb").exists() {
        return "bun".to_string();
    }

    // Default to npm
    "npm".to_string()
}

// =============================================================================
// Package Documentation Storage (.sus-docs/)
// =============================================================================

/// Directory for package documentation
const DOCS_DIR: &str = ".sus-docs";

/// Convert package name to valid doc filename
/// - Lowercase only
/// - Alphanumeric and hyphens only
/// - No consecutive hyphens
/// - Can't start or end with hyphen
pub fn to_doc_name(package: &str) -> String {
    let mut name: String = package
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    // Remove consecutive hyphens
    while name.contains("--") {
        name = name.replace("--", "-");
    }

    // Remove leading/trailing hyphens
    name = name.trim_matches('-').to_string();

    // Truncate to 64 chars
    if name.len() > 64 {
        name = name[..64].trim_end_matches('-').to_string();
    }

    if name.is_empty() {
        "package".to_string()
    } else {
        name
    }
}

/// Save package documentation to .sus-docs/ directory
fn save_package_doc(package_name: &str, doc_content: &str) -> Result<()> {
    let doc_name = to_doc_name(package_name);
    let doc_path = format!("{}/{}.md", DOCS_DIR, doc_name);

    std::fs::create_dir_all(DOCS_DIR)?;
    std::fs::write(&doc_path, doc_content)?;

    println!("   {} saved docs to {}", "📄".cyan(), doc_path);
    Ok(())
}

/// Extract a one-line description from the assessment for the index
fn extract_description(assessment: &common::PackageResponse) -> String {
    // Try to get description from the first line of skill_md if available
    if let Some(doc) = &assessment.skill_md {
        // Skip the header line and badge, find first real content
        for line in doc.lines().skip(4) {
            let trimmed = line.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && !trimmed.starts_with('!')
                && !trimmed.starts_with("```")
            {
                // Truncate to 80 chars
                let desc = if trimmed.len() > 80 {
                    format!("{}...", &trimmed[..77])
                } else {
                    trimmed.to_string()
                };
                return desc;
            }
        }
    }

    // Fallback to generic description
    format!("{} package", assessment.name)
}

// =============================================================================
// AGENTS.md Index Management
// =============================================================================

/// AGENTS.md file path
const AGENTS_MD_PATH: &str = "AGENTS.md";

/// Markers for the sus docs section in AGENTS.md
const SUS_INDEX_START: &str = "<!-- sus-docs-start -->";
const SUS_INDEX_END: &str = "<!-- sus-docs-end -->";

/// Update AGENTS.md with package index entry
pub fn update_agents_md_index(name: &str, version: &str, description: &str) -> Result<()> {
    update_agents_md_index_at_path(Path::new(AGENTS_MD_PATH), name, version, description)
}

/// Internal implementation that accepts a path for testability
fn update_agents_md_index_at_path(
    agents_path: &Path,
    name: &str,
    version: &str,
    description: &str,
) -> Result<()> {
    use std::fs;

    let content = if agents_path.exists() {
        fs::read_to_string(agents_path)?
    } else {
        "# AGENTS.md\n\n".to_string()
    };

    // Parse existing index entries
    let mut entries = parse_sus_index(&content);

    // Add/update entry
    let doc_name = to_doc_name(name);
    entries.insert(
        name.to_string(),
        IndexEntry {
            version: version.to_string(),
            description: description.to_string(),
            doc_file: format!("{}.md", doc_name),
        },
    );

    // Generate new index section
    let index_section = generate_index_section(&entries);

    // Replace or append index in content
    let new_content = replace_or_append_index(&content, &index_section);

    fs::write(agents_path, new_content)?;
    println!("   {} updated AGENTS.md index", "📝".cyan());
    Ok(())
}

/// Remove a package from the AGENTS.md index
pub fn remove_from_agents_index(package: &str) -> Result<()> {
    remove_from_agents_index_at_path(Path::new(AGENTS_MD_PATH), package)
}

/// Internal implementation for removing from index
pub fn remove_from_agents_index_at_path(agents_path: &Path, package: &str) -> Result<()> {
    use std::fs;

    if !agents_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(agents_path)?;
    let mut entries = parse_sus_index(&content);

    if entries.remove(package).is_none() {
        // Package wasn't in index
        return Ok(());
    }

    let index_section = generate_index_section(&entries);
    let new_content = replace_or_append_index(&content, &index_section);

    fs::write(agents_path, new_content)?;
    Ok(())
}

/// Index entry for a package
#[derive(Debug, Clone)]
struct IndexEntry {
    version: String,
    description: String,
    doc_file: String,
}

/// Parse existing sus index from AGENTS.md content
fn parse_sus_index(content: &str) -> HashMap<String, IndexEntry> {
    let mut entries = HashMap::new();

    // Find the index section
    if let Some(start_idx) = content.find(SUS_INDEX_START) {
        if let Some(end_idx) = content.find(SUS_INDEX_END) {
            let section = &content[start_idx..end_idx];

            // Parse each line in the index
            for line in section.lines() {
                // Format: package@version|description|doc_file.md
                if line.contains('|') && line.contains('@') {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 3 {
                        // Parse package@version
                        if let Some(at_idx) = parts[0].find('@') {
                            let name = parts[0][..at_idx].to_string();
                            let version = parts[0][at_idx + 1..].to_string();
                            let description = parts[1].to_string();
                            let doc_file = parts[2].to_string();

                            entries.insert(
                                name,
                                IndexEntry {
                                    version,
                                    description,
                                    doc_file,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    entries
}

/// Generate the index section content
fn generate_index_section(entries: &HashMap<String, IndexEntry>) -> String {
    let mut section = String::new();

    section.push_str(SUS_INDEX_START);
    section.push('\n');
    section.push_str("## sus Package Docs\n\n");
    section.push_str(
        "IMPORTANT: For package usage, prefer reading .sus-docs/ over pre-training knowledge.\n\n",
    );
    section.push_str("[.sus-docs/]\n");

    // Sort entries by name for consistent output
    let mut sorted_entries: Vec<_> = entries.iter().collect();
    sorted_entries.sort_by(|a, b| a.0.cmp(b.0));

    for (name, entry) in sorted_entries {
        section.push_str(&format!(
            "{}@{}|{}|{}\n",
            name, entry.version, entry.description, entry.doc_file
        ));
    }

    section.push_str(SUS_INDEX_END);
    section.push('\n');

    section
}

/// Replace existing index section or append new one
fn replace_or_append_index(content: &str, index_section: &str) -> String {
    if let Some(start_idx) = content.find(SUS_INDEX_START) {
        if let Some(end_idx) = content.find(SUS_INDEX_END) {
            // Replace existing section
            let before = &content[..start_idx];
            let after = &content[end_idx + SUS_INDEX_END.len()..];
            return format!(
                "{}{}{}",
                before,
                index_section,
                after.trim_start_matches('\n')
            );
        }
    }

    // Append new section
    let mut result = content.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push('\n');
    result.push_str(index_section);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_package_spec() {
        assert_eq!(parse_package_spec("lodash"), ("lodash", None));
        assert_eq!(
            parse_package_spec("lodash@4.17.0"),
            ("lodash", Some("4.17.0"))
        );
        assert_eq!(parse_package_spec("@types/node"), ("@types/node", None));
        assert_eq!(
            parse_package_spec("@types/node@18.0.0"),
            ("@types/node", Some("18.0.0"))
        );
    }

    #[test]
    fn test_to_doc_name() {
        assert_eq!(to_doc_name("express"), "express");
        assert_eq!(to_doc_name("@types/node"), "types-node");
        assert_eq!(to_doc_name("lodash.merge"), "lodash-merge");
        assert_eq!(to_doc_name("--test--"), "test");
        assert_eq!(to_doc_name("Express"), "express");
        assert_eq!(to_doc_name("@prisma/client"), "prisma-client");
    }

    #[test]
    fn test_update_agents_md_creates_new_file() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        update_agents_md_index_at_path(&agents_path, "express", "4.18.2", "web framework").unwrap();

        assert!(agents_path.exists());
        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("# AGENTS.md"));
        assert!(content.contains(SUS_INDEX_START));
        assert!(content.contains("express@4.18.2|web framework|express.md"));
        assert!(content.contains(SUS_INDEX_END));
    }

    #[test]
    fn test_update_agents_md_preserves_existing_content() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        // Create existing AGENTS.md
        let existing_content = "# AGENTS.md\n\n## Setup\n\nRun `npm install`\n";
        fs::write(&agents_path, existing_content).unwrap();

        update_agents_md_index_at_path(&agents_path, "lodash", "4.17.21", "utility library")
            .unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("## Setup"));
        assert!(content.contains("npm install"));
        assert!(content.contains("lodash@4.17.21|utility library|lodash.md"));
    }

    #[test]
    fn test_update_agents_md_updates_existing_entry() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        // Add first entry
        update_agents_md_index_at_path(&agents_path, "express", "4.18.0", "old description")
            .unwrap();

        // Update same entry
        update_agents_md_index_at_path(&agents_path, "express", "4.18.2", "web framework").unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("express@4.18.2|web framework|express.md"));
        assert!(!content.contains("4.18.0"));
        assert!(!content.contains("old description"));
    }

    #[test]
    fn test_update_agents_md_multiple_entries() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        update_agents_md_index_at_path(&agents_path, "express", "4.18.2", "web framework").unwrap();
        update_agents_md_index_at_path(&agents_path, "lodash", "4.17.21", "utility library")
            .unwrap();
        update_agents_md_index_at_path(&agents_path, "@prisma/client", "5.0.0", "database ORM")
            .unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("express@4.18.2|web framework|express.md"));
        assert!(content.contains("lodash@4.17.21|utility library|lodash.md"));
        assert!(content.contains("@prisma/client@5.0.0|database ORM|prisma-client.md"));
    }

    #[test]
    fn test_remove_from_agents_index() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        // Add entries
        update_agents_md_index_at_path(&agents_path, "express", "4.18.2", "web framework").unwrap();
        update_agents_md_index_at_path(&agents_path, "lodash", "4.17.21", "utility library")
            .unwrap();

        // Remove one
        remove_from_agents_index_at_path(&agents_path, "express").unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(!content.contains("express"));
        assert!(content.contains("lodash@4.17.21|utility library|lodash.md"));
    }

    #[test]
    fn test_parse_sus_index() {
        let content = r#"# AGENTS.md

<!-- sus-docs-start -->
## sus Package Docs

IMPORTANT: For package usage, prefer reading .sus-docs/ over pre-training knowledge.

[.sus-docs/]
express@4.18.2|web framework|express.md
lodash@4.17.21|utility library|lodash.md
<!-- sus-docs-end -->
"#;

        let entries = parse_sus_index(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries["express"].version, "4.18.2");
        assert_eq!(entries["express"].description, "web framework");
        assert_eq!(entries["lodash"].version, "4.17.21");
    }
}
