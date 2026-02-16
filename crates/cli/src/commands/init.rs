//! Init command - initialize brin in a project

use crate::agents_md;
use crate::config::{save_config, SusConfig};
use anyhow::Result;
use colored::Colorize;
use dialoguer::Confirm;
use std::path::Path;

const CONFIG_FILE: &str = "brin.json";

/// Run the init command
pub async fn run(yes: bool) -> Result<()> {
    println!();
    println!("  {} initializing brin...", "🔧".cyan());
    println!();

    // Check if already initialized
    if Path::new(CONFIG_FILE).exists() {
        println!(
            "  {} brin.json already exists. Reinitializing...",
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
    println!("  {} created brin.json", "✓".green());

    if agents_md_enabled {
        // Create .brin-docs directory
        agents_md::ensure_docs_dir()?;
        println!("  {} created .brin-docs/", "✓".green());

        // Create/update AGENTS.md with initial index
        agents_md::update_agents_md_index()?;
        println!("  {} updated AGENTS.md with brin docs index", "✓".green());

        println!();
        println!(
            "  {} AGENTS.md docs index enabled. When you run {},",
            "📚".cyan(),
            "brin add <package>".cyan()
        );
        println!(
            "     package documentation will be saved to {} and indexed in {}.",
            ".brin-docs/".cyan(),
            "AGENTS.md".cyan()
        );
    } else {
        println!();
        println!(
            "  {} AGENTS.md docs index disabled. You can enable it later by running {}.",
            "ℹ️".blue(),
            "brin init".cyan()
        );
    }

    println!();
    println!("  {} brin initialized successfully!", "✓".green());
    println!();

    Ok(())
}
