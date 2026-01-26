//! SKILL.md manifest generator following Agent Skills spec
//! https://agentskills.io/specification

use sus_common::{PackageCapabilities, RiskLevel, UsageDocs};

/// Convert a package name to a valid skill name
/// - Lowercase only
/// - Alphanumeric and hyphens only
/// - No consecutive hyphens
/// - Can't start or end with hyphen
pub fn to_skill_name(package: &str) -> String {
    let mut name: String = package
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Remove consecutive hyphens
    while name.contains("--") {
        name = name.replace("--", "-");
    }

    // Remove leading/trailing hyphens
    name = name.trim_matches('-').to_string();

    // Truncate to 64 chars
    if name.len() > 64 {
        name = name[..64].trim_end_matches('-').to_string();
    }

    // Ensure non-empty
    if name.is_empty() {
        name = "package".to_string();
    }

    name
}

/// Generate a SKILL.md manifest following Agent Skills spec
pub fn generate_skill_md(
    package: &str,
    version: &str,
    caps: &PackageCapabilities,
    risk_level: &RiskLevel,
    risk_reasons: &[String],
    usage_docs: &UsageDocs,
) -> String {
    let mut md = String::new();

    let skill_name = to_skill_name(package);

    // Build description
    let description = usage_docs
        .description
        .clone()
        .unwrap_or_else(|| format!("Usage guide for {} npm package.", package));

    // Truncate description to 1024 chars max
    let description = if description.len() > 1024 {
        format!("{}...", &description[..1020])
    } else {
        description
    };

    // YAML Frontmatter (required by spec)
    md.push_str("---\n");
    md.push_str(&format!("name: {}\n", skill_name));
    md.push_str(&format!(
        "description: {} Use when working with {} in your project.\n",
        description, package
    ));
    md.push_str(&format!(
        "metadata:\n  package: {}\n  version: {}\n  generator: sus\n  generator-version: \"{}\"\n",
        package,
        version,
        env!("CARGO_PKG_VERSION")
    ));
    md.push_str("---\n\n");

    // Body content
    md.push_str(&format!("# {}@{}\n\n", package, version));

    // Risk badge
    let badge = match risk_level {
        RiskLevel::Clean => "![status](https://img.shields.io/badge/sus-clean-green)",
        RiskLevel::Warning => "![status](https://img.shields.io/badge/sus-warning-yellow)",
        RiskLevel::Critical => "![status](https://img.shields.io/badge/sus-critical-red)",
    };
    md.push_str(badge);
    md.push_str("\n\n");

    // Quick Start
    if let Some(quick_start) = &usage_docs.quick_start {
        md.push_str("## Quick Start\n\n");
        md.push_str("```javascript\n");
        md.push_str(quick_start);
        if !quick_start.ends_with('\n') {
            md.push('\n');
        }
        md.push_str("```\n\n");
    }

    // Key APIs
    if !usage_docs.key_apis.is_empty() {
        md.push_str("## Key APIs\n\n");
        for api in &usage_docs.key_apis {
            md.push_str(&format!("### `{}`\n\n", api.name));
            md.push_str(&api.description);
            md.push_str("\n\n");
            if let Some(example) = &api.example {
                md.push_str("```javascript\n");
                md.push_str(example);
                if !example.ends_with('\n') {
                    md.push('\n');
                }
                md.push_str("```\n\n");
            }
        }
    }

    // Best Practices
    if !usage_docs.best_practices.is_empty() {
        md.push_str("## Best Practices\n\n");
        for practice in &usage_docs.best_practices {
            md.push_str(&format!("- {}\n", practice));
        }
        md.push_str("\n");
    }

    // Common Patterns
    if !usage_docs.common_patterns.is_empty() {
        md.push_str("## Common Patterns\n\n");
        for pattern in &usage_docs.common_patterns {
            md.push_str(&format!("- {}\n", pattern));
        }
        md.push_str("\n");
    }

    // Gotchas
    if !usage_docs.gotchas.is_empty() {
        md.push_str("## Gotchas\n\n");
        for gotcha in &usage_docs.gotchas {
            md.push_str(&format!("- {}\n", gotcha));
        }
        md.push_str("\n");
    }

    // Capabilities
    md.push_str("## Capabilities\n\n");
    md.push_str("```yaml\n");
    md.push_str("permissions:\n");

    // Network
    if caps.network.makes_requests {
        md.push_str("  network:\n");
        if caps.network.domains.is_empty() {
            md.push_str("    - \"*\"\n");
        } else {
            for domain in &caps.network.domains {
                md.push_str(&format!("    - \"{}\"\n", domain));
            }
        }
    }

    // Filesystem
    if caps.filesystem.reads || caps.filesystem.writes {
        md.push_str("  filesystem:\n");
        let mode = match (caps.filesystem.reads, caps.filesystem.writes) {
            (true, true) => "rw",
            (true, false) => "r",
            (false, true) => "w",
            _ => "r",
        };
        if caps.filesystem.paths.is_empty() {
            md.push_str(&format!("    - path: \"*\"\n      mode: \"{}\"\n", mode));
        } else {
            for path_perm in &caps.filesystem.paths {
                md.push_str(&format!(
                    "    - path: \"{}\"\n      mode: \"{}\"\n",
                    path_perm.path, path_perm.mode
                ));
            }
        }
    }

    // Process
    if caps.process.spawns_children {
        md.push_str("  process: true\n");
    }

    // Environment
    if !caps.environment.accessed_vars.is_empty() {
        md.push_str("  environment:\n");
        for var in &caps.environment.accessed_vars {
            md.push_str(&format!("    - \"{}\"\n", var));
        }
    }

    // Native
    if caps.native.has_native {
        md.push_str("  native: true\n");
    }

    // If no capabilities
    if !caps.network.makes_requests
        && !caps.filesystem.reads
        && !caps.filesystem.writes
        && !caps.process.spawns_children
        && caps.environment.accessed_vars.is_empty()
        && !caps.native.has_native
    {
        md.push_str("  # No special permissions required\n");
    }

    md.push_str("```\n\n");

    // Risk Assessment (only if there are issues)
    if !risk_reasons.is_empty() {
        md.push_str("## Risk Assessment\n\n");
        for reason in risk_reasons {
            md.push_str(&format!("- {}\n", reason));
        }
        md.push_str("\n");
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use sus_common::{ApiDoc, NetworkCapabilities, ProcessCapabilities};

    #[test]
    fn test_to_skill_name() {
        assert_eq!(to_skill_name("express"), "express");
        assert_eq!(to_skill_name("@types/node"), "types-node");
        assert_eq!(to_skill_name("lodash.merge"), "lodash-merge");
        assert_eq!(to_skill_name("--test--"), "test");
        assert_eq!(to_skill_name("Express"), "express");
    }

    #[test]
    fn test_generate_skill_md_has_frontmatter() {
        let caps = PackageCapabilities::default();
        let usage_docs = UsageDocs {
            description: Some("A test package".to_string()),
            ..Default::default()
        };

        let md = generate_skill_md(
            "test-pkg",
            "1.0.0",
            &caps,
            &RiskLevel::Clean,
            &[],
            &usage_docs,
        );

        assert!(md.starts_with("---\n"));
        assert!(md.contains("name: test-pkg"));
        assert!(md.contains("description:"));
        assert!(md.contains("metadata:"));
        assert!(md.contains("---\n\n#"));
    }

    #[test]
    fn test_generate_skill_md_with_usage_docs() {
        let caps = PackageCapabilities {
            network: NetworkCapabilities {
                makes_requests: true,
                domains: vec!["api.example.com".to_string()],
                protocols: vec!["https".to_string()],
            },
            process: ProcessCapabilities {
                spawns_children: true,
                commands: vec!["npm".to_string()],
            },
            ..Default::default()
        };

        let usage_docs = UsageDocs {
            description: Some("A test package for testing".to_string()),
            quick_start: Some("import test from 'test-pkg';\ntest.run();".to_string()),
            key_apis: vec![ApiDoc {
                name: "run".to_string(),
                description: "Runs the test".to_string(),
                example: Some("test.run()".to_string()),
            }],
            best_practices: vec!["Always call init() first".to_string()],
            common_patterns: vec!["Use with async/await".to_string()],
            gotchas: vec!["Don't forget to close connections".to_string()],
        };

        let md = generate_skill_md(
            "test-pkg",
            "1.0.0",
            &caps,
            &RiskLevel::Warning,
            &["Test warning".to_string()],
            &usage_docs,
        );

        assert!(md.contains("name: test-pkg"));
        assert!(md.contains("# test-pkg@1.0.0"));
        assert!(md.contains("A test package for testing"));
        assert!(md.contains("## Quick Start"));
        assert!(md.contains("import test from 'test-pkg'"));
        assert!(md.contains("## Key APIs"));
        assert!(md.contains("### `run`"));
        assert!(md.contains("## Best Practices"));
        assert!(md.contains("Always call init() first"));
        assert!(md.contains("## Common Patterns"));
        assert!(md.contains("## Gotchas"));
        assert!(md.contains("warning-yellow"));
        assert!(md.contains("api.example.com"));
        assert!(md.contains("process: true"));
    }
}
