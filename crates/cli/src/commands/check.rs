//! Check command - check a package without installing

use crate::api_client::SusClient;
use crate::ui::{self, print_capabilities, print_risk};
use anyhow::Result;
use colored::Colorize;

/// Parse a package string into name and optional version
fn parse_package_spec(spec: &str) -> (&str, Option<&str>) {
    if let Some(rest) = spec.strip_prefix('@') {
        if let Some(idx) = rest.find('@') {
            let idx = idx + 1;
            return (&spec[..idx], Some(&spec[idx + 1..]));
        }
        return (spec, None);
    }

    if let Some(idx) = spec.find('@') {
        return (&spec[..idx], Some(&spec[idx + 1..]));
    }

    (spec, None)
}

/// Run the check command
pub async fn run(client: &SusClient, package: &str) -> Result<()> {
    let (name, version) = parse_package_spec(package);
    let display_name = if let Some(v) = version {
        format!("{}@{}", name, v)
    } else {
        name.to_string()
    };

    println!();
    println!("📦 {}", display_name.bold());
    println!();

    let pb = ui::spinner("fetching security assessment...");

    let assessment = match if let Some(v) = version {
        client.get_package_version(name, v).await
    } else {
        client.get_package(name).await
    } {
        Ok(a) => {
            ui::finish_spinner(&pb, "✓", "assessment found");
            a
        }
        Err(e) => {
            if e.to_string().contains("not found") {
                ui::finish_spinner(&pb, "❓", "not in database");
                println!();
                println!(
                    "  {} is not yet in the sus database.",
                    display_name.yellow()
                );
                println!();
                println!("  requesting scan...");

                match client.request_scan(name, version).await {
                    Ok(resp) => {
                        println!(
                            "  {} scan queued (job: {})",
                            "✓".green(),
                            resp.job_id.to_string().dimmed()
                        );
                        println!("  estimated time: ~{}s", resp.estimated_seconds);
                        println!();
                        println!(
                            "  run {} again in a moment.",
                            format!("sus check {}", package).cyan()
                        );
                    }
                    Err(scan_err) => {
                        println!("  {} failed to request scan: {}", "✗".red(), scan_err);
                    }
                }

                return Ok(());
            }

            ui::finish_spinner(&pb, "❌", "error");
            anyhow::bail!("Failed to check package: {}", e);
        }
    };

    println!();
    print_risk(&assessment);
    print_capabilities(&assessment);

    // Show when it was scanned
    println!();
    println!(
        "  scanned: {}",
        assessment
            .scanned_at
            .format("%Y-%m-%d %H:%M UTC")
            .to_string()
            .dimmed()
    );

    // Final verdict
    println!();
    match assessment.risk_level {
        common::RiskLevel::Clean => {
            println!(
                "  {} This package appears safe to use.",
                "verdict:".green().bold()
            );
        }
        common::RiskLevel::Warning => {
            println!(
                "  {} Review the warnings above before using.",
                "verdict:".yellow().bold()
            );
        }
        common::RiskLevel::Critical => {
            println!(
                "  {} This package has critical security issues. Do not use.",
                "verdict:".red().bold()
            );
        }
    }

    println!();

    Ok(())
}
