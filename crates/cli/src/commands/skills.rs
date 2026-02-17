//! Skills command - scan and install Agent Skills with safety checks

use crate::api_client::SusClient;
use crate::ui::{self, print_capabilities, print_risk};
use anyhow::Result;
use colored::Colorize;
use common::{Registry, RiskLevel};
use dialoguer::Confirm;
use std::process::Command;

/// Validate skill identifier format (owner/repo or owner/repo/path)
fn validate_skill_id(skill: &str) -> Result<()> {
    let parts: Vec<&str> = skill.splitn(3, '/').collect();
    if parts.len() < 2 {
        anyhow::bail!(
            "Invalid skill identifier '{}'. Expected format: owner/repo or owner/repo/path\n\
             Examples:\n\
             - anthropics/skills\n\
             - anthropics/skills/mcp-builder\n\
             - vercel-labs/agent-skills",
            skill
        );
    }
    Ok(())
}

/// URL-encode a skill name for API requests (encode slashes)
fn encode_skill_name(name: &str) -> String {
    name.replace('/', "%2F")
}

/// Run the skills add command
pub async fn run_add(client: &SusClient, skill: &str, yolo: bool, strict: bool) -> Result<()> {
    validate_skill_id(skill)?;

    let pb = ui::spinner(&format!("checking skill {}...", skill));

    // Check if skill has already been scanned
    let encoded = encode_skill_name(skill);
    let assessment = match client.get_package(&encoded).await {
        Ok(a) => {
            // Verify it's actually from the skills registry
            if a.registry != Registry::Skills {
                ui::finish_spinner(&pb, "???", skill);
                println!(
                    "  {} found as a {} package, not a skill. Use {} instead.",
                    skill.yellow(),
                    a.registry,
                    "brin add".cyan()
                );
                return Ok(());
            }
            ui::finish_spinner(&pb, a.risk_level.emoji(), skill);
            a
        }
        Err(e) => {
            if e.to_string().contains("not found") {
                ui::finish_spinner(&pb, "????", skill);
                println!(
                    "  {} not in brin database yet, requesting scan...",
                    skill.yellow()
                );

                match client
                    .request_scan_with_registry(skill, None, Some(Registry::Skills))
                    .await
                {
                    Ok(resp) => {
                        println!(
                            "  scan queued (job {}), try again in ~{}s",
                            resp.job_id.to_string().dimmed(),
                            resp.estimated_seconds
                        );
                        if yolo {
                            println!("  {} --yolo mode, installing anyway...", "??????".yellow());
                        } else {
                            println!("  use {} to install without scan", "--yolo".cyan());
                            return Ok(());
                        }
                    }
                    Err(scan_err) => {
                        println!("  {} failed to request scan: {}", "error:".red(), scan_err);
                        if !yolo {
                            return Ok(());
                        }
                    }
                }

                // If yolo, proceed without assessment
                install_skill(skill)?;
                return Ok(());
            } else {
                ui::finish_spinner(&pb, "???", skill);
                println!("  {} {}", "error:".red(), e);
                return Ok(());
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
                    "   {} {} mode, skipping skill with warnings",
                    "??????".yellow(),
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
                    "????".red(),
                    "--yolo".cyan()
                );
                true
            } else {
                println!(
                    "??? not installed. use {} to force (don't)",
                    "--yolo".cyan()
                );
                false
            }
        }
    };

    if !should_install {
        return Ok(());
    }

    // Install the skill via npx skills add
    install_skill(skill)?;
    println!("{}", "???? installed".green());

    Ok(())
}

/// Run the skills check command (scan without installing)
pub async fn run_check(client: &SusClient, skill: &str) -> Result<()> {
    validate_skill_id(skill)?;

    let pb = ui::spinner(&format!("checking skill {}...", skill));

    let encoded = encode_skill_name(skill);
    match client.get_package(&encoded).await {
        Ok(assessment) => {
            ui::finish_spinner(&pb, assessment.risk_level.emoji(), skill);
            print_risk(&assessment);
            print_capabilities(&assessment);
        }
        Err(e) => {
            if e.to_string().contains("not found") {
                ui::finish_spinner(&pb, "????", skill);
                println!(
                    "  {} not in brin database yet, requesting scan...",
                    skill.yellow()
                );

                match client
                    .request_scan_with_registry(skill, None, Some(Registry::Skills))
                    .await
                {
                    Ok(resp) => {
                        println!(
                            "  scan queued (job {}), try again in ~{}s",
                            resp.job_id.to_string().dimmed(),
                            resp.estimated_seconds
                        );
                    }
                    Err(scan_err) => {
                        println!("  {} failed to request scan: {}", "error:".red(), scan_err);
                    }
                }
            } else {
                ui::finish_spinner(&pb, "???", skill);
                println!("  {} {}", "error:".red(), e);
            }
        }
    }

    Ok(())
}

/// Install a skill using npx skills add
fn install_skill(skill: &str) -> Result<()> {
    let status = Command::new("npx")
        .args(["skills", "add", skill])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to run 'npx skills add': {}. Is npx installed?", e))?;

    if !status.success() {
        anyhow::bail!("npx skills add failed with exit code {:?}", status.code());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_skill_id_valid() {
        assert!(validate_skill_id("anthropics/skills").is_ok());
        assert!(validate_skill_id("anthropics/skills/mcp-builder").is_ok());
        assert!(validate_skill_id("owner/repo/deep/path").is_ok());
    }

    #[test]
    fn test_validate_skill_id_invalid() {
        assert!(validate_skill_id("just-one-part").is_err());
        assert!(validate_skill_id("").is_err());
    }

    #[test]
    fn test_encode_skill_name() {
        assert_eq!(
            encode_skill_name("anthropics/skills"),
            "anthropics%2Fskills"
        );
        assert_eq!(
            encode_skill_name("anthropics/skills/mcp-builder"),
            "anthropics%2Fskills%2Fmcp-builder"
        );
    }
}
