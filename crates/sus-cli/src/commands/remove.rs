//! Remove command - remove packages

use anyhow::Result;
use colored::Colorize;
use std::process::Command;

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
            println!(
                "  {} {} remove failed",
                "✗".red(),
                pm
            );
            continue;
        }

        println!("  {} removed {}", "✓".green(), package);

        // Remove SKILL.md if it exists
        let skill_path = format!(".sus/{}.skill.md", package.replace('/', "__"));
        if std::path::Path::new(&skill_path).exists() {
            if let Err(e) = std::fs::remove_file(&skill_path) {
                tracing::warn!("Failed to remove {}: {}", skill_path, e);
            }
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
