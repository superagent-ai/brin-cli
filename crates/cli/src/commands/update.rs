//! Update command - update dependencies

use crate::api_client::SusClient;
use crate::ui;
use anyhow::Result;
use colored::Colorize;
use common::PackageVersionPair;
use std::process::Command;

/// Run the update command
pub async fn run(client: &SusClient, dry_run: bool) -> Result<()> {
    // Find package.json
    if !std::path::Path::new("package.json").exists() {
        anyhow::bail!("No package.json found in current directory");
    }

    let pb = ui::spinner("checking for updates...");

    // Get current dependencies
    let pkg_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("package.json")?)?;

    let mut updates = Vec::new();

    // Check dependencies
    if let Some(dependencies) = pkg_json.get("dependencies").and_then(|d| d.as_object()) {
        for (name, version) in dependencies {
            if let Some(v) = version.as_str() {
                let clean_v = clean_version(v);
                // Check if there's a newer safe version
                if let Ok(assessment) = client.get_package(name).await {
                    if assessment.version != clean_v {
                        updates.push(PackageVersionPair {
                            name: name.clone(),
                            version: assessment.version.clone(),
                        });
                    }
                }
            }
        }
    }

    ui::finish_spinner(&pb, "✓", &format!("found {} updates", updates.len()));

    if updates.is_empty() {
        println!();
        println!("  {} all packages up to date", "✓".green());
        return Ok(());
    }

    println!();
    println!("📦 Available updates:");
    println!();

    for update in &updates {
        println!("  {} → {}", update.name, update.version.green());
    }

    if dry_run {
        println!();
        println!("  {} dry run, no changes made", "ℹ".blue());
        return Ok(());
    }

    println!();

    let pm = detect_package_manager();

    for update in &updates {
        let pb = ui::spinner(&format!("updating {}...", update.name));

        let status = Command::new(&pm)
            .args(["add", &format!("{}@{}", update.name, update.version)])
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to run {}: {}", pm, e))?;

        if status.success() {
            ui::finish_spinner(&pb, "✓", &format!("updated {}", update.name));
        } else {
            ui::finish_spinner(&pb, "✗", &format!("failed to update {}", update.name));
        }
    }

    Ok(())
}

/// Clean version string
fn clean_version(version: &str) -> String {
    version
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches('>')
        .trim_start_matches('<')
        .trim_start_matches('=')
        .to_string()
}

/// Detect package manager
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
