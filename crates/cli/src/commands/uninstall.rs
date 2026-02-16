//! Uninstall command - remove brin from the system

use crate::agents_md;
use anyhow::Result;
use colored::Colorize;
use dialoguer::Confirm;
use std::path::Path;

/// Run the uninstall command
pub async fn run(yes: bool, all: bool) -> Result<()> {
    // Get the current executable path
    let exe_path = std::env::current_exe()?;

    println!();
    println!("🗑️  brin uninstaller");
    println!();
    println!(
        "   Binary location: {}",
        exe_path.display().to_string().cyan()
    );

    // Check for project-level files
    let brin_docs = Path::new(".brin-docs");
    let brin_json = Path::new("brin.json");
    let agents_md = Path::new("AGENTS.md");
    let has_agents_md_section = agents_md.exists()
        && std::fs::read_to_string(agents_md)
            .map(|c| c.contains("[brin Docs Index]"))
            .unwrap_or(false);
    let has_project_files = brin_docs.exists() || brin_json.exists() || has_agents_md_section;

    if all && has_project_files {
        println!();
        println!("   Project files to remove:");
        if brin_docs.exists() {
            println!("   - {}", ".brin-docs/".cyan());
        }
        if brin_json.exists() {
            println!("   - {}", "brin.json".cyan());
        }
        if has_agents_md_section {
            println!("   - {}", "AGENTS.md (brin section only)".cyan());
        }
    }

    // Confirm unless --yes flag
    if !yes {
        println!();
        let confirm = Confirm::new()
            .with_prompt("   Remove brin?")
            .default(false)
            .interact()?;

        if !confirm {
            println!();
            println!("   {} Uninstall cancelled.", "✗".red());
            return Ok(());
        }
    }

    // Remove project-level files if --all flag
    if all {
        if brin_docs.exists() {
            std::fs::remove_dir_all(brin_docs)?;
            println!("   {} Removed .brin-docs/", "✓".green());
        }
        if brin_json.exists() {
            std::fs::remove_file(brin_json)?;
            println!("   {} Removed brin.json", "✓".green());
        }
        if has_agents_md_section {
            agents_md::remove_agents_md_index()?;
            println!("   {} Removed brin section from AGENTS.md", "✓".green());
        }
    }

    // Delete the binary
    // Note: On some systems, we can't delete a running executable directly
    // So we try a few approaches
    #[cfg(unix)]
    {
        // On Unix, we can usually delete the file while it's running
        // The file will be removed when the process exits
        std::fs::remove_file(&exe_path)?;
    }

    #[cfg(windows)]
    {
        // On Windows, we need to schedule deletion or use a workaround
        // For now, we'll try direct deletion which works in some cases
        if let Err(_) = std::fs::remove_file(&exe_path) {
            // If direct deletion fails, create a batch script to delete after exit
            let batch_path = std::env::temp_dir().join("brin_uninstall.bat");
            let batch_content = format!(
                "@echo off\n\
                 :loop\n\
                 del \"{}\" 2>nul\n\
                 if exist \"{}\" goto loop\n\
                 del \"%~f0\"\n",
                exe_path.display(),
                exe_path.display()
            );
            std::fs::write(&batch_path, batch_content)?;
            std::process::Command::new("cmd")
                .args(["/C", "start", "/min", batch_path.to_str().unwrap()])
                .spawn()?;
        }
    }

    println!();
    println!("   {} brin has been uninstalled.", "✓".green());
    println!();

    // Suggest cleanup if project files exist but --all wasn't used
    if !all && has_project_files {
        println!(
            "   {} Project files (.brin-docs/, brin.json) were not removed.",
            "note:".yellow()
        );
        println!("   Run with {} to remove them too.", "--all".cyan());
        println!();
    }

    Ok(())
}
