//! Add command - install packages with safety checks

use crate::agents_md;
use crate::api_client::SusClient;
use crate::config;
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
    // Check if AGENTS.md docs feature is enabled
    let agents_md_enabled = config::is_agents_md_enabled();

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

        // Save docs and update AGENTS.md index if enabled
        if agents_md_enabled {
            if let Some(skill_md) = &assessment.skill_md {
                save_package_docs(name, skill_md);
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

/// Save package documentation to .sus-docs/ and update AGENTS.md index
fn save_package_docs(package_name: &str, doc_content: &str) {
    // Save doc to .sus-docs/
    if let Err(e) = agents_md::save_doc(package_name, doc_content) {
        tracing::warn!("Failed to save package doc: {}", e);
        return;
    }

    // Update AGENTS.md index
    if let Err(e) = agents_md::update_agents_md_index() {
        tracing::warn!("Failed to update AGENTS.md index: {}", e);
        return;
    }

    println!(
        "   {} saved docs to {} and updated {}",
        "📚".cyan(),
        ".sus-docs/".cyan(),
        "AGENTS.md".cyan()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
