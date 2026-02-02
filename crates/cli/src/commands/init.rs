//! Init command - initialize sus in a project

use crate::agents_md;
use crate::config::{save_config, SusConfig};
use anyhow::Result;
use colored::Colorize;
use dialoguer::Confirm;
use std::path::Path;

const CONFIG_FILE: &str = "sus.json";

/// Run the init command
pub async fn run(yes: bool) -> Result<()> {
    println!();
    println!("  {} initializing sus...", "🔧".cyan());
    println!();

    // Check if already initialized
    if Path::new(CONFIG_FILE).exists() {
        println!(
            "  {} sus.json already exists. Reinitializing...",
            "ℹ️".blue()
        );
        println!();
    }

    // Ask about AGENTS.md docs index (skip if --yes flag is passed)
    let agents_md_enabled = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("  Enable AGENTS.md docs index for AI coding agents?")
            .default(true)
            .interact()?
    };

    // Create config
    let config = SusConfig {
        agents_md: agents_md_enabled,
    };

    // Save config
    save_config(&config)?;
    println!();
    println!("  {} created sus.json", "✓".green());

    if agents_md_enabled {
        // Create .sus-docs directory
        agents_md::ensure_docs_dir()?;
        println!("  {} created .sus-docs/", "✓".green());

        // Create/update AGENTS.md with initial index
        agents_md::update_agents_md_index()?;
        println!("  {} updated AGENTS.md with sus docs index", "✓".green());

        println!();
        println!(
            "  {} AGENTS.md docs index enabled. When you run {},",
            "📚".cyan(),
            "sus add <package>".cyan()
        );
        println!(
            "     package documentation will be saved to {} and indexed in {}.",
            ".sus-docs/".cyan(),
            "AGENTS.md".cyan()
        );
    } else {
        println!();
        println!(
            "  {} AGENTS.md docs index disabled. You can enable it later by running {}.",
            "ℹ️".blue(),
            "sus init".cyan()
        );
    }

    println!();
    println!("  {} sus initialized successfully!", "✓".green());
    println!();

    Ok(())
}
