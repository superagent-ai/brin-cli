//! Remove command - remove packages and clean up docs

use crate::commands::add::{remove_from_agents_index, to_doc_name};
use anyhow::Result;
use colored::Colorize;
use std::process::Command;

/// Directory for package documentation
const DOCS_DIR: &str = ".sus-docs";

/// Run the remove command
pub async fn run(packages: Vec<String>) -> Result<()> {
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

        // Remove doc file from .sus-docs/
        let doc_name = to_doc_name(package);
        let doc_path = format!("{}/{}.md", DOCS_DIR, doc_name);
        if std::path::Path::new(&doc_path).exists() {
            if let Err(e) = std::fs::remove_file(&doc_path) {
                tracing::warn!("Failed to remove {}: {}", doc_path, e);
            } else {
                println!("   {} removed {}", "🗑️".dimmed(), doc_path);
            }
        }

        // Remove from AGENTS.md index
        if let Err(e) = remove_from_agents_index(package) {
            tracing::debug!("Failed to update AGENTS.md index: {}", e);
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
