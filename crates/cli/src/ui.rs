//! Terminal UI utilities

use colored::Colorize;
use common::{PackageResponse, RiskLevel};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Create a spinner with a message
pub fn spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Finish spinner with an emoji
pub fn finish_spinner(pb: &ProgressBar, emoji: &str, message: &str) {
    pb.set_style(ProgressStyle::default_spinner().template("{msg}").unwrap());
    pb.finish_with_message(format!("{} {}", emoji, message));
}

/// Format downloads count for display
fn format_downloads(downloads: u64) -> String {
    if downloads >= 1_000_000 {
        format!("{}M/week", downloads / 1_000_000)
    } else if downloads >= 1_000 {
        format!("{}K/week", downloads / 1_000)
    } else {
        format!("{}/week", downloads)
    }
}

/// Print a package risk assessment in tree format (original README style)
pub fn print_risk(assessment: &PackageResponse) {
    match assessment.risk_level {
        RiskLevel::Clean => print_clean_assessment(assessment),
        RiskLevel::Warning => print_warning_assessment(assessment),
        RiskLevel::Critical => print_critical_assessment(assessment),
    }
}

/// Print assessment for clean packages
fn print_clean_assessment(assessment: &PackageResponse) {
    println!("{}", "✅ not sus".green().bold());

    // Publisher
    if let Some(publisher) = &assessment.publisher {
        let publisher_name = publisher.name.as_deref().unwrap_or("unknown");
        let verified = if publisher.verified {
            " (verified)".green()
        } else {
            "".normal()
        };
        println!("   ├─ publisher: {}{}", publisher_name, verified);
    }

    // Downloads
    if let Some(downloads) = assessment.weekly_downloads {
        println!("   ├─ downloads: {}", format_downloads(downloads));
    }

    // CVEs
    println!("   ├─ cves: {}", assessment.cves.len());

    // Install scripts
    if assessment.install_scripts.has_any() {
        let count = assessment.install_scripts.count();
        println!(
            "   └─ install scripts: {} {}",
            count,
            "(review recommended)".yellow()
        );
    } else {
        println!("   └─ install scripts: {}", "none".green());
    }
}

/// Print assessment for warning packages
fn print_warning_assessment(assessment: &PackageResponse) {
    println!("{}", "⚠️  kinda sus".yellow().bold());

    // Publisher
    if let Some(publisher) = &assessment.publisher {
        let publisher_name = publisher.name.as_deref().unwrap_or("unknown");
        let verified = if publisher.verified {
            " (verified)".green()
        } else {
            " (unverified)".yellow()
        };
        println!("   ├─ publisher: {}{}", publisher_name, verified);
    }

    // Downloads
    if let Some(downloads) = assessment.weekly_downloads {
        println!("   ├─ downloads: {}", format_downloads(downloads));
    }

    // CVEs
    if !assessment.cves.is_empty() {
        for (i, cve) in assessment.cves.iter().enumerate() {
            let prefix = if i == assessment.cves.len() - 1 && assessment.agentic_threats.is_empty()
            {
                "└─"
            } else {
                "├─"
            };
            let severity = cve.severity.as_deref().unwrap_or("unknown");
            let desc = cve.description.as_deref().unwrap_or("");
            let short_desc = if desc.len() > 40 {
                format!("{}...", &desc[..37])
            } else {
                desc.to_string()
            };
            println!(
                "   {} {}: {} ({})",
                prefix,
                cve.cve_id.yellow(),
                short_desc,
                severity.to_lowercase()
            );
        }
    }

    // Agentic threats
    for (i, threat) in assessment.agentic_threats.iter().enumerate() {
        let prefix = if i == assessment.agentic_threats.len() - 1 {
            "└─"
        } else {
            "├─"
        };
        let confidence = (threat.confidence * 100.0) as u8;
        println!(
            "   {} {:?}: {}% confidence",
            prefix, threat.threat_type, confidence
        );
    }

    // Install scripts warning
    if assessment.install_scripts.has_any() {
        println!(
            "   └─ install scripts: {} {}",
            assessment.install_scripts.count(),
            "⚠️".yellow()
        );
    }
}

/// Print assessment for critical packages
fn print_critical_assessment(assessment: &PackageResponse) {
    println!("{}", "🚨 MEGA SUS".red().bold());

    // Show the most critical issues first
    let mut items: Vec<String> = Vec::new();

    // Malware/threats first
    for threat in &assessment.agentic_threats {
        if threat.confidence > 0.8 {
            let threat_desc = match threat.threat_type {
                // LLM Safety
                common::ThreatType::PromptInjection => "prompt injection attack",
                common::ThreatType::ImproperOutputHandling => "improper output handling",
                common::ThreatType::InsecureToolUsage => "insecure tool usage",
                common::ThreatType::InstructionOverride => "instruction override attack",
                // Secrets
                common::ThreatType::HardcodedSecrets => "hardcoded secrets",
                // Data Handling
                common::ThreatType::WeakCrypto => "weak cryptography",
                common::ThreatType::SensitiveDataLogging => "sensitive data logging",
                common::ThreatType::PiiViolations => "PII violations",
                common::ThreatType::InsecureDeserialization => "insecure deserialization",
                // Injection
                common::ThreatType::Xss => "XSS vulnerability",
                common::ThreatType::Sqli => "SQL injection",
                common::ThreatType::CommandInjection => "command injection",
                common::ThreatType::Ssrf => "SSRF vulnerability",
                common::ThreatType::Ssti => "SSTI vulnerability",
                common::ThreatType::CodeInjection => "code injection",
                // Auth
                common::ThreatType::AuthBypass => "authentication bypass",
                common::ThreatType::WeakSessionTokens => "weak session tokens",
                common::ThreatType::InsecurePasswordReset => "insecure password reset",
                // Supply Chain
                common::ThreatType::MaliciousInstallScripts => "malicious install script",
                common::ThreatType::DependencyConfusion => "dependency confusion",
                common::ThreatType::Typosquatting => "typosquatting",
                common::ThreatType::ObfuscatedCode => "obfuscated code",
                // Other
                common::ThreatType::PathTraversal => "path traversal",
                common::ThreatType::PrototypePollution => "prototype pollution",
                common::ThreatType::Backdoor => "backdoor detected",
                common::ThreatType::CryptoMiner => "crypto miner",
                common::ThreatType::DataExfiltration => "data exfiltration attempt",
                common::ThreatType::SocialEngineering => "social engineering attack",
                // Legacy
                common::ThreatType::InstallScriptInjection => "malicious install script",
                common::ThreatType::MaliciousCode => "malware detected",
            };
            items.push(format!("{}: {}", "threat".red(), threat_desc));
        }
    }

    // Critical CVEs
    for cve in &assessment.cves {
        let severity = cve.severity.as_deref().unwrap_or("").to_uppercase();
        if severity == "CRITICAL" || severity == "HIGH" {
            let desc = cve.description.as_deref().unwrap_or("vulnerability");
            let short_desc = if desc.len() > 30 {
                format!("{}...", &desc[..27])
            } else {
                desc.to_string()
            };
            items.push(format!("{}: {}", cve.cve_id, short_desc));
        }
    }

    // Add status if known malware
    if assessment
        .risk_reasons
        .iter()
        .any(|r| r.to_lowercase().contains("malware") || r.to_lowercase().contains("malicious"))
    {
        items.push("status: COMPROMISED".to_string());
    }

    // Print items in tree format
    for (i, item) in items.iter().enumerate() {
        let prefix = if i == items.len() - 1 {
            "└─"
        } else {
            "├─"
        };
        println!("   {} {}", prefix, item);
    }

    // If no specific items, show risk reasons
    if items.is_empty() {
        for (i, reason) in assessment.risk_reasons.iter().enumerate() {
            let prefix = if i == assessment.risk_reasons.len() - 1 {
                "└─"
            } else {
                "├─"
            };
            println!("   {} {}", prefix, reason.red());
        }
    }
}

/// Print capabilities summary (compact version)
pub fn print_capabilities(assessment: &PackageResponse) {
    let caps = &assessment.capabilities;

    // Only show if there are notable capabilities
    let has_notable = caps.network.makes_requests
        || caps.filesystem.reads
        || caps.filesystem.writes
        || caps.process.spawns_children
        || !caps.environment.accessed_vars.is_empty()
        || caps.native.has_native;

    if !has_notable {
        return;
    }

    println!();
    println!("   📋 capabilities:");

    if caps.network.makes_requests {
        print!("   ├─ 🌐 network");
        if !caps.network.domains.is_empty() && caps.network.domains.len() <= 3 {
            print!(": {}", caps.network.domains.join(", "));
        }
        println!();
    }

    if caps.filesystem.reads || caps.filesystem.writes {
        let mode = match (caps.filesystem.reads, caps.filesystem.writes) {
            (true, true) => "read/write",
            (true, false) => "read",
            (false, true) => "write",
            _ => unreachable!(),
        };
        println!("   ├─ 📁 filesystem ({})", mode);
    }

    if caps.process.spawns_children {
        println!("   ├─ ⚙️  spawns processes");
    }

    if !caps.environment.accessed_vars.is_empty() {
        let vars: Vec<&str> = caps
            .environment
            .accessed_vars
            .iter()
            .take(3)
            .map(|s| s.as_str())
            .collect();
        print!("   ├─ 🔑 env vars: {}", vars.join(", "));
        if caps.environment.accessed_vars.len() > 3 {
            print!(" +{} more", caps.environment.accessed_vars.len() - 3);
        }
        println!();
    }

    if caps.native.has_native {
        println!("   └─ {} native code", "🔧".yellow());
    }
}

/// Print a summary line for scan results
pub fn print_scan_summary(clean: usize, warnings: usize, critical: usize) {
    println!();
    println!("───────────────────────────────────");
    println!(
        "summary: {} clean, {} warning, {} critical",
        clean.to_string().green(),
        warnings.to_string().yellow(),
        critical.to_string().red()
    );
}
