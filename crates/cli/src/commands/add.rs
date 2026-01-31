//! Add command - install packages with safety checks

use crate::api_client::SusClient;
use crate::ui::{self, print_capabilities, print_risk};
use anyhow::Result;
use colored::Colorize;
use common::RiskLevel;
use dialoguer::Confirm;
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
    // Ensure AGENTS.md exists with sus instructions (only runs once)
    ensure_agents_md();

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

        // Save agent skills to all coding agent folders
        if let Some(skill_md) = &assessment.skill_md {
            save_agent_skills(name, skill_md);
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

/// Coding agent root folders
const AGENT_ROOTS: &[&str] = &[
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".gemini",
    ".opencode",
    ".windsurf",
];

/// AGENTS.md file path
const AGENTS_MD_PATH: &str = "AGENTS.md";

/// Marker to detect if AGENTS.md has already been patched with sus instructions
const SUS_MARKER: &str = "## sus Package Security";

/// Content to add to AGENTS.md
const SUS_AGENTS_SECTION: &str = r#"## sus Package Security

When installing packages in this project, use `sus` instead of directly using package managers (npm, pip, cargo, etc.):

- Install packages: `sus add <package-name>`
- Check a package: `sus check <package-name>`

sus performs security analysis before installation. After installing a package, check the skills folder in your agent's directory (e.g., `.cursor/skills/`, `.claude/skills/`) for package-specific usage guidance.
"#;

/// Ensure AGENTS.md exists and contains sus instructions
/// Creates the file if it doesn't exist, or patches it if the sus section is missing
fn ensure_agents_md() {
    ensure_agents_md_at_path(std::path::Path::new(AGENTS_MD_PATH));
}

/// Result of ensuring AGENTS.md
#[derive(Debug, PartialEq)]
enum AgentsMdResult {
    /// File was created
    Created,
    /// File was patched (sus section added)
    Patched,
    /// File already had sus section
    AlreadyPatched,
    /// Error occurred
    Error,
}

/// Internal implementation that accepts a path for testability
fn ensure_agents_md_at_path(agents_path: &std::path::Path) -> AgentsMdResult {
    use std::fs;

    // Check if file exists
    if agents_path.exists() {
        // Read existing content
        match fs::read_to_string(agents_path) {
            Ok(content) => {
                // Check if already patched
                if content.contains(SUS_MARKER) {
                    // Already patched, nothing to do
                    return AgentsMdResult::AlreadyPatched;
                }

                // Append sus section to existing file
                let new_content = if content.ends_with('\n') {
                    format!("{}\n{}", content, SUS_AGENTS_SECTION)
                } else {
                    format!("{}\n\n{}", content, SUS_AGENTS_SECTION)
                };

                if let Err(e) = fs::write(agents_path, new_content) {
                    tracing::warn!("Failed to patch AGENTS.md: {}", e);
                    AgentsMdResult::Error
                } else {
                    println!(
                        "   {} patched {} with sus instructions",
                        "📝".cyan(),
                        agents_path.display()
                    );
                    AgentsMdResult::Patched
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read AGENTS.md: {}", e);
                AgentsMdResult::Error
            }
        }
    } else {
        // Create new AGENTS.md with sus section
        let content = format!("# AGENTS.md\n\n{}", SUS_AGENTS_SECTION);

        if let Err(e) = fs::write(agents_path, content) {
            tracing::warn!("Failed to create AGENTS.md: {}", e);
            AgentsMdResult::Error
        } else {
            println!(
                "   {} created {} with sus instructions",
                "📝".cyan(),
                agents_path.display()
            );
            AgentsMdResult::Created
        }
    }
}

/// Convert package name to valid skill name (per Agent Skills spec)
fn to_skill_name(package: &str) -> String {
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

/// Save agent skill to existing coding agent folders only
/// Follows Agent Skills spec: {agent}/skills/{skill-name}/SKILL.md
fn save_agent_skills(package_name: &str, skill_content: &str) {
    use std::path::Path;

    let skill_name = to_skill_name(package_name);
    let mut saved_count = 0;

    for agent_root in AGENT_ROOTS {
        // Only write to agent folders that already exist
        if !Path::new(agent_root).exists() {
            continue;
        }

        let skills_dir = format!("{}/skills", agent_root);
        let skill_dir = format!("{}/{}", skills_dir, skill_name);
        let skill_path = format!("{}/SKILL.md", skill_dir);

        // Create the skill directory structure
        if let Err(e) = std::fs::create_dir_all(&skill_dir) {
            tracing::debug!("Failed to create {}: {}", skill_dir, e);
            continue;
        }

        if let Err(e) = std::fs::write(&skill_path, skill_content) {
            tracing::debug!("Failed to write {}: {}", skill_path, e);
        } else {
            saved_count += 1;
        }
    }

    if saved_count > 0 {
        println!(
            "   {} saved skill to {} agent folder{}",
            "📚".cyan(),
            saved_count,
            if saved_count == 1 { "" } else { "s" }
        );
    }
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
    fn test_ensure_agents_md_creates_new_file() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        let result = ensure_agents_md_at_path(&agents_path);

        assert_eq!(result, AgentsMdResult::Created);
        assert!(agents_path.exists());

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("# AGENTS.md"));
        assert!(content.contains(SUS_MARKER));
        assert!(content.contains("sus add"));
    }

    #[test]
    fn test_ensure_agents_md_patches_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        // Create existing AGENTS.md without sus section
        let existing_content = "# AGENTS.md\n\n## Setup\n\nRun `npm install`\n";
        fs::write(&agents_path, existing_content).unwrap();

        let result = ensure_agents_md_at_path(&agents_path);

        assert_eq!(result, AgentsMdResult::Patched);

        let content = fs::read_to_string(&agents_path).unwrap();
        // Original content should still be there
        assert!(content.contains("## Setup"));
        assert!(content.contains("npm install"));
        // Sus section should be appended
        assert!(content.contains(SUS_MARKER));
        assert!(content.contains("sus add"));
    }

    #[test]
    fn test_ensure_agents_md_skips_already_patched() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        // Create AGENTS.md that already has sus section
        let existing_content = format!(
            "# AGENTS.md\n\n## Setup\n\nRun `npm install`\n\n{}",
            SUS_AGENTS_SECTION
        );
        fs::write(&agents_path, &existing_content).unwrap();

        let result = ensure_agents_md_at_path(&agents_path);

        assert_eq!(result, AgentsMdResult::AlreadyPatched);

        // Content should be unchanged
        let content = fs::read_to_string(&agents_path).unwrap();
        assert_eq!(content, existing_content);
    }

    #[test]
    fn test_ensure_agents_md_handles_file_without_trailing_newline() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        // Create existing AGENTS.md without trailing newline
        let existing_content = "# AGENTS.md\n\n## Setup\n\nRun `npm install`";
        fs::write(&agents_path, existing_content).unwrap();

        let result = ensure_agents_md_at_path(&agents_path);

        assert_eq!(result, AgentsMdResult::Patched);

        let content = fs::read_to_string(&agents_path).unwrap();
        // Should have proper spacing between sections
        assert!(content.contains("npm install`\n\n## sus Package Security"));
    }
}
