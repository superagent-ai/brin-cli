//! Remove command - remove packages

use crate::agents_md;
use crate::config;
use anyhow::Result;
use colored::Colorize;
use std::process::Command;

/// Run the remove command
pub async fn run(packages: Vec<String>) -> Result<()> {
    // Check if AGENTS.md docs feature is enabled
    let agents_md_enabled = config::is_agents_md_enabled();

    for package in &packages {
        println!("📦 removing {}...", package.cyan());

        let pm = detect_package_manager();

        let status = Command::new(&pm)
            .args(["remove", package])
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to run {}: {}", pm, e))?;

        if !status.success() {
            println!("  {} {} remove failed", "✗".red(), pm);
            continue;
        }

        println!("  {} removed {}", "✓".green(), package);

        // Remove docs from .sus-docs/ and update AGENTS.md index if enabled
        if agents_md_enabled {
            remove_package_docs(package);
        }
    }

    Ok(())
}

/// Detect which package manager to use
fn detect_package_manager() -> String {
    if std::path::Path::new("pnpm-lock.yaml").exists() {
        return "pnpm".to_string();
    }
    if std::path::Path::new("yarn.lock").exists() {
        return "yarn".to_string();
    }
    if std::path::Path::new("bun.lockb").exists() {
        return "bun".to_string();
    }
    "npm".to_string()
}

/// Remove package documentation from .sus-docs/ and update AGENTS.md index
fn remove_package_docs(package_name: &str) {
    // Remove doc from .sus-docs/
    match agents_md::remove_doc(package_name) {
        Ok(true) => {
            // Update AGENTS.md index
            if let Err(e) = agents_md::update_agents_md_index() {
                tracing::warn!("Failed to update AGENTS.md index: {}", e);
                return;
            }
            println!(
                "  {} removed docs from {} and updated {}",
                "📚".cyan(),
                ".sus-docs/".cyan(),
                "AGENTS.md".cyan()
            );
        }
        Ok(false) => {
            // Doc didn't exist, nothing to do
        }
        Err(e) => {
            tracing::warn!("Failed to remove package doc: {}", e);
        }
    }
}
