//! Package documentation generator for AGENTS.md method
//! Generates plain markdown docs instead of SKILL.md files

use common::{PackageCapabilities, RiskLevel, UsageDocs};

/// Generate package documentation as plain markdown
/// No YAML frontmatter - designed for passive context via AGENTS.md index
pub fn generate_package_doc(
    package: &str,
    version: &str,
    caps: &PackageCapabilities,
    risk_level: &RiskLevel,
    risk_reasons: &[String],
    usage_docs: &UsageDocs,
) -> String {
    let mut md = String::new();

    // Header with package name and version
    md.push_str(&format!("# {}@{}\n\n", package, version));

    // Risk badge
    let badge = match risk_level {
        RiskLevel::Clean => "![status](https://img.shields.io/badge/sus-clean-green)",
        RiskLevel::Warning => "![status](https://img.shields.io/badge/sus-warning-yellow)",
        RiskLevel::Critical => "![status](https://img.shields.io/badge/sus-critical-red)",
    };
    md.push_str(badge);
    md.push_str("\n\n");

    // Description
    if let Some(description) = &usage_docs.description {
        md.push_str(description);
        md.push_str("\n\n");
    }

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
        md.push('\n');
    }

    // Common Patterns
    if !usage_docs.common_patterns.is_empty() {
        md.push_str("## Common Patterns\n\n");
        for pattern in &usage_docs.common_patterns {
            md.push_str(&format!("- {}\n", pattern));
        }
        md.push('\n');
    }

    // Gotchas
    if !usage_docs.gotchas.is_empty() {
        md.push_str("## Gotchas\n\n");
        for gotcha in &usage_docs.gotchas {
            md.push_str(&format!("- {}\n", gotcha));
        }
        md.push('\n');
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
        md.push('\n');
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{ApiDoc, NetworkCapabilities, ProcessCapabilities};

    #[test]
    fn test_generate_package_doc_no_frontmatter() {
        let caps = PackageCapabilities::default();
        let usage_docs = UsageDocs {
            description: Some("A test package".to_string()),
            ..Default::default()
        };

        let md = generate_package_doc(
            "test-pkg",
            "1.0.0",
            &caps,
            &RiskLevel::Clean,
            &[],
            &usage_docs,
        );

        // Should NOT have YAML frontmatter
        assert!(!md.starts_with("---\n"));
        assert!(!md.contains("name: test-pkg"));
        assert!(!md.contains("metadata:"));

        // Should start with header
        assert!(md.starts_with("# test-pkg@1.0.0\n"));
        assert!(md.contains("A test package"));
    }

    #[test]
    fn test_generate_package_doc_with_usage_docs() {
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

        let md = generate_package_doc(
            "test-pkg",
            "1.0.0",
            &caps,
            &RiskLevel::Warning,
            &["Test warning".to_string()],
            &usage_docs,
        );

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
        assert!(md.contains("## Risk Assessment"));
        assert!(md.contains("Test warning"));
    }
}
