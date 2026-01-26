//! Why command - show why a package is in your dependency tree

use anyhow::Result;
use colored::Colorize;
use std::process::Command;

/// Run the why command
pub async fn run(package: &str) -> Result<()> {
    println!();
    println!("🔍 tracing {}...", package.cyan());
    println!();

    let pm = detect_package_manager();

    let output = Command::new(&pm)
        .args(["why", package])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run {} why: {}", pm, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not found") || stderr.contains("No dependency") {
            println!("  {} is not in your dependency tree", package.yellow());
        } else {
            println!("  {} failed to trace: {}", "error:".red(), stderr.trim());
        }
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Pretty-print the output
    for line in stdout.lines() {
        if line.contains(package) {
            println!("  {}", line.cyan());
        } else if line.starts_with(' ') || line.starts_with("└") || line.starts_with("├") {
            println!("  {}", line);
        } else {
            println!("  {}", line.dimmed());
        }
    }

    Ok(())
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
