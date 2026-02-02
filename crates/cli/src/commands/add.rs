//! Add command - install packages with safety checks

use crate::agents_md;
use crate::api_client::SusClient;
use crate::config;
use crate::project::{self, NpmPackageManager, ProjectType, PypiPackageManager};
use crate::ui::{self, print_capabilities, print_risk};
use anyhow::Result;
use colored::Colorize;
use common::RiskLevel;
use dialoguer::Confirm;
use std::process::Command;

/// Run the add command
pub async fn run(
    client: &SusClient,
    packages: Vec<String>,
    yolo: bool,
    strict: bool,
) -> Result<()> {
    // Detect project type
    let project_type = match project::detect_project_type() {
        Some(pt) => pt,
        None => {
            anyhow::bail!(
                "No supported project files found.\n\
                 Supported files:\n\
                 - npm: package.json, pnpm-lock.yaml, yarn.lock, bun.lockb\n\
                 - python: requirements.txt, pyproject.toml, Pipfile, setup.py"
            );
        }
    };

    // Check if AGENTS.md docs feature is enabled
    let agents_md_enabled = config::is_agents_md_enabled();

    for package_spec in &packages {
        let (name, version) = project::parse_package_spec(package_spec, &project_type);
        let display_name = if let Some(ref v) = version {
            format_display_name(&name, v, &project_type)
        } else {
            name.clone()
        };

        let pb = ui::spinner(&format!("checking {}...", display_name));

        // Fetch assessment from API
        let assessment = match if let Some(ref v) = version {
            client.get_package_version(&name, v).await
        } else {
            client.get_package(&name).await
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

                    let registry = project_type.registry();
                    match client
                        .request_scan_with_registry(&name, version.as_deref(), Some(registry))
                        .await
                    {
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
                    install_package(package_spec, &project_type)?;
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
        install_package(package_spec, &project_type)?;
        println!("{}", "📦 installed".green());

        // Save docs and update AGENTS.md index if enabled
        if agents_md_enabled {
            if let Some(skill_md) = &assessment.skill_md {
                save_package_docs(&name, skill_md);
            }
        }
    }

    Ok(())
}

/// Format display name based on project type
fn format_display_name(name: &str, version: &str, project_type: &ProjectType) -> String {
    match project_type {
        ProjectType::Npm(_) => format!("{}@{}", name, version),
        ProjectType::Pypi(_) => format!("{}=={}", name, version),
    }
}

/// Install a package using the appropriate package manager
fn install_package(package: &str, project_type: &ProjectType) -> Result<()> {
    match project_type {
        ProjectType::Npm(pm) => install_npm_package(package, *pm),
        ProjectType::Pypi(pm) => install_pypi_package(package, *pm),
    }
}

/// Install an npm package
fn install_npm_package(package: &str, pm: NpmPackageManager) -> Result<()> {
    let cmd = pm.command();
    let install_cmd = pm.install_cmd();

    let status = Command::new(cmd)
        .args([install_cmd, package])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to run {}: {}", cmd, e))?;

    if !status.success() {
        anyhow::bail!(
            "{} {} failed with exit code {:?}",
            cmd,
            install_cmd,
            status.code()
        );
    }

    Ok(())
}

/// Install a PyPI package
fn install_pypi_package(package: &str, pm: PypiPackageManager) -> Result<()> {
    let cmd = pm.command();
    let install_cmd = pm.install_cmd();

    let status = Command::new(cmd)
        .args([install_cmd, package])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to run {}: {}", cmd, e))?;

    if !status.success() {
        anyhow::bail!(
            "{} {} failed with exit code {:?}",
            cmd,
            install_cmd,
            status.code()
        );
    }

    Ok(())
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
    fn test_format_display_name() {
        let npm = ProjectType::Npm(NpmPackageManager::Npm);
        let pypi = ProjectType::Pypi(PypiPackageManager::Pip);

        assert_eq!(
            format_display_name("lodash", "4.17.0", &npm),
            "lodash@4.17.0"
        );
        assert_eq!(
            format_display_name("requests", "2.31.0", &pypi),
            "requests==2.31.0"
        );
    }
}
