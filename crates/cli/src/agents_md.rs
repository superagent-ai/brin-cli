//! AGENTS.md docs index management
//!
//! Manages the compressed docs index in AGENTS.md following Vercel's approach:
//! https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals

use anyhow::Result;
use std::fs;
use std::path::Path;

const AGENTS_MD_PATH: &str = "AGENTS.md";
const BRIN_DOCS_DIR: &str = ".brin-docs";

/// Marker to detect brin section in AGENTS.md
const BRIN_MARKER_START: &str = "[brin Docs Index]";
const BRIN_MARKER_END: &str = "[/brin Docs Index]";

/// Marker to detect package installation instructions in AGENTS.md
const INSTALL_INSTRUCTIONS_MARKER: &str = "## Package Installation";

/// Convert a package name to a valid filename
/// - Lowercase only
/// - Alphanumeric and hyphens only
/// - No consecutive hyphens
/// - Can't start or end with hyphen
pub fn to_doc_filename(package: &str) -> String {
    let mut name: String = package
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
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

    format!("{}.md", name)
}

/// Save package documentation to .brin-docs/
pub fn save_doc(package: &str, content: &str) -> Result<()> {
    save_doc_at_path(package, content, Path::new(BRIN_DOCS_DIR))
}

fn save_doc_at_path(package: &str, content: &str, docs_dir: &Path) -> Result<()> {
    // Create .brin-docs directory if it doesn't exist
    fs::create_dir_all(docs_dir)?;

    let filename = to_doc_filename(package);
    let doc_path = docs_dir.join(&filename);
    fs::write(&doc_path, content)?;

    Ok(())
}

/// Remove package documentation from .brin-docs/
pub fn remove_doc(package: &str) -> Result<bool> {
    remove_doc_at_path(package, Path::new(BRIN_DOCS_DIR))
}

fn remove_doc_at_path(package: &str, docs_dir: &Path) -> Result<bool> {
    let filename = to_doc_filename(package);
    let doc_path = docs_dir.join(&filename);

    if doc_path.exists() {
        fs::remove_file(&doc_path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Update AGENTS.md with current .brin-docs index
pub fn update_agents_md_index() -> Result<()> {
    update_agents_md_index_at_path(Path::new(AGENTS_MD_PATH), Path::new(BRIN_DOCS_DIR))
}

fn update_agents_md_index_at_path(agents_path: &Path, docs_dir: &Path) -> Result<()> {
    let index = generate_index(docs_dir)?;

    if agents_path.exists() {
        // Read existing content
        let content = fs::read_to_string(agents_path)?;

        // Check if brin section exists
        if content.contains(BRIN_MARKER_START) {
            // Replace existing brin section
            let new_content = replace_brin_section(&content, &index);
            fs::write(agents_path, new_content)?;
        } else {
            // Append brin section
            let new_content = if content.ends_with('\n') {
                format!("{}\n{}", content, index)
            } else {
                format!("{}\n\n{}", content, index)
            };
            fs::write(agents_path, new_content)?;
        }
    } else {
        // Create new AGENTS.md with brin section
        let content = format!("# AGENTS.md\n\n{}", index);
        fs::write(agents_path, content)?;
    }

    Ok(())
}

/// Remove brin section from AGENTS.md
pub fn remove_agents_md_index() -> Result<()> {
    remove_agents_md_index_at_path(Path::new(AGENTS_MD_PATH))
}

fn remove_agents_md_index_at_path(agents_path: &Path) -> Result<()> {
    if !agents_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(agents_path)?;

    if !content.contains(BRIN_MARKER_START) {
        return Ok(());
    }

    let new_content = remove_brin_section(&content);

    // If only the brin section was there, remove the file
    let trimmed = new_content.trim();
    if trimmed.is_empty() || trimmed == "# AGENTS.md" {
        fs::remove_file(agents_path)?;
    } else {
        fs::write(agents_path, new_content)?;
    }

    Ok(())
}

/// Generate compressed index from .brin-docs/ contents
fn generate_index(docs_dir: &Path) -> Result<String> {
    let mut packages: Vec<String> = Vec::new();

    if docs_dir.exists() {
        for entry in fs::read_dir(docs_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(filename) = path.file_name() {
                    if let Some(name) = filename.to_str() {
                        if name.ends_with(".md") {
                            packages.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    // Sort for deterministic output
    packages.sort();

    let packages_list = if packages.is_empty() {
        String::new()
    } else {
        packages.join(",")
    };

    // Build compressed index following Vercel's format
    let mut index = String::new();
    index.push_str(BRIN_MARKER_START);
    index.push_str("|root: ./");
    index.push_str(BRIN_DOCS_DIR);
    index.push('\n');
    index.push_str("|IMPORTANT: Prefer retrieval-led reasoning over pre-training-led reasoning\n");

    if !packages_list.is_empty() {
        index.push_str(&format!("|packages:{{{}}}\n", packages_list));
    }

    index.push_str(BRIN_MARKER_END);
    index.push('\n');

    Ok(index)
}

/// Replace existing brin section with new index
fn replace_brin_section(content: &str, new_index: &str) -> String {
    let start_idx = content.find(BRIN_MARKER_START);
    let end_idx = content.find(BRIN_MARKER_END);

    match (start_idx, end_idx) {
        (Some(start), Some(end)) => {
            let end_of_marker = end + BRIN_MARKER_END.len();
            // Skip any trailing newline after end marker
            let end_of_section = if content[end_of_marker..].starts_with('\n') {
                end_of_marker + 1
            } else {
                end_of_marker
            };

            let before = &content[..start];
            let after = &content[end_of_section..];

            // Handle spacing
            let before_trimmed = before.trim_end_matches('\n');
            let after_trimmed = after.trim_start_matches('\n');

            if before_trimmed.is_empty() && after_trimmed.is_empty() {
                new_index.to_string()
            } else if before_trimmed.is_empty() {
                format!("{}\n{}", new_index, after_trimmed)
            } else if after_trimmed.is_empty() {
                format!("{}\n\n{}", before_trimmed, new_index)
            } else {
                format!("{}\n\n{}\n{}", before_trimmed, new_index, after_trimmed)
            }
        }
        _ => {
            // Marker not properly closed, append new index
            if content.ends_with('\n') {
                format!("{}\n{}", content, new_index)
            } else {
                format!("{}\n\n{}", content, new_index)
            }
        }
    }
}

/// Remove brin section from content
fn remove_brin_section(content: &str) -> String {
    let start_idx = content.find(BRIN_MARKER_START);
    let end_idx = content.find(BRIN_MARKER_END);

    match (start_idx, end_idx) {
        (Some(start), Some(end)) => {
            let end_of_marker = end + BRIN_MARKER_END.len();
            // Skip any trailing newlines after end marker
            let end_of_section = if content[end_of_marker..].starts_with('\n') {
                end_of_marker + 1
            } else {
                end_of_marker
            };

            let before = &content[..start];
            let after = &content[end_of_section..];

            // Clean up extra newlines
            let before_trimmed = before.trim_end_matches('\n');
            let after_trimmed = after.trim_start_matches('\n');

            if before_trimmed.is_empty() && after_trimmed.is_empty() {
                String::new()
            } else if before_trimmed.is_empty() {
                after_trimmed.to_string()
            } else if after_trimmed.is_empty() {
                format!("{}\n", before_trimmed)
            } else {
                format!("{}\n\n{}", before_trimmed, after_trimmed)
            }
        }
        _ => content.to_string(),
    }
}

/// Add package installation instructions to AGENTS.md (idempotent)
pub fn add_install_instructions() -> Result<()> {
    add_install_instructions_at_path(Path::new(AGENTS_MD_PATH))
}

fn add_install_instructions_at_path(agents_path: &Path) -> Result<()> {
    let instructions = r#"
## Package Installation

Use `brin` for all package operations:
- `brin add <pkg>` -- install with security scan
- `brin remove <pkg>` -- uninstall
- `brin scan` -- audit all dependencies
- `brin check <pkg>` -- look up without installing

Do not use npm install, yarn add, pnpm add, or pip install directly.
"#;

    if agents_path.exists() {
        let content = fs::read_to_string(agents_path)?;
        if content.contains(INSTALL_INSTRUCTIONS_MARKER) {
            // Already present, nothing to do
            return Ok(());
        }
        let new_content = format!("{}{}", content, instructions);
        fs::write(agents_path, new_content)?;
    } else {
        // Create new AGENTS.md with just the instructions
        let content = format!("# AGENTS.md\n{}", instructions);
        fs::write(agents_path, content)?;
    }

    Ok(())
}

/// Ensure .brin-docs directory exists
pub fn ensure_docs_dir() -> Result<()> {
    fs::create_dir_all(BRIN_DOCS_DIR)?;
    Ok(())
}

/// List all packages in .brin-docs/
#[allow(dead_code)]
pub fn list_docs() -> Result<Vec<String>> {
    list_docs_at_path(Path::new(BRIN_DOCS_DIR))
}

fn list_docs_at_path(docs_dir: &Path) -> Result<Vec<String>> {
    let mut packages = Vec::new();

    if !docs_dir.exists() {
        return Ok(packages);
    }

    for entry in fs::read_dir(docs_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(filename) = path.file_name() {
                if let Some(name) = filename.to_str() {
                    if let Some(stripped) = name.strip_suffix(".md") {
                        packages.push(stripped.to_string());
                    }
                }
            }
        }
    }

    packages.sort();
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_to_doc_filename() {
        assert_eq!(to_doc_filename("express"), "express.md");
        assert_eq!(to_doc_filename("@types/node"), "types-node.md");
        assert_eq!(to_doc_filename("lodash.merge"), "lodash-merge.md");
        assert_eq!(to_doc_filename("--test--"), "test.md");
        assert_eq!(to_doc_filename("Express"), "express.md");
    }

    #[test]
    fn test_save_and_remove_doc() {
        let temp_dir = TempDir::new().unwrap();
        let docs_dir = temp_dir.path().join(".brin-docs");

        save_doc_at_path("express", "# Express docs", &docs_dir).unwrap();
        assert!(docs_dir.join("express.md").exists());

        let removed = remove_doc_at_path("express", &docs_dir).unwrap();
        assert!(removed);
        assert!(!docs_dir.join("express.md").exists());
    }

    #[test]
    fn test_generate_index_empty() {
        let temp_dir = TempDir::new().unwrap();
        let docs_dir = temp_dir.path().join(".brin-docs");

        let index = generate_index(&docs_dir).unwrap();
        assert!(index.contains("[brin Docs Index]"));
        assert!(index.contains("retrieval-led reasoning"));
        assert!(!index.contains("packages:"));
    }

    #[test]
    fn test_generate_index_with_packages() {
        let temp_dir = TempDir::new().unwrap();
        let docs_dir = temp_dir.path().join(".brin-docs");
        fs::create_dir_all(&docs_dir).unwrap();

        fs::write(docs_dir.join("express.md"), "# Express").unwrap();
        fs::write(docs_dir.join("lodash.md"), "# Lodash").unwrap();

        let index = generate_index(&docs_dir).unwrap();
        assert!(index.contains("[brin Docs Index]"));
        assert!(index.contains("packages:{express.md,lodash.md}"));
    }

    #[test]
    fn test_update_agents_md_creates_new() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");
        let docs_dir = temp_dir.path().join(".brin-docs");
        fs::create_dir_all(&docs_dir).unwrap();
        fs::write(docs_dir.join("express.md"), "# Express").unwrap();

        update_agents_md_index_at_path(&agents_path, &docs_dir).unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("# AGENTS.md"));
        assert!(content.contains("[brin Docs Index]"));
        assert!(content.contains("express.md"));
    }

    #[test]
    fn test_update_agents_md_appends() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");
        let docs_dir = temp_dir.path().join(".brin-docs");
        fs::create_dir_all(&docs_dir).unwrap();

        // Create existing AGENTS.md
        fs::write(&agents_path, "# AGENTS.md\n\n## Setup\n\nRun npm install\n").unwrap();

        update_agents_md_index_at_path(&agents_path, &docs_dir).unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("## Setup"));
        assert!(content.contains("[brin Docs Index]"));
    }

    #[test]
    fn test_update_agents_md_replaces() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");
        let docs_dir = temp_dir.path().join(".brin-docs");
        fs::create_dir_all(&docs_dir).unwrap();

        // Create existing AGENTS.md with brin section
        let existing = "# AGENTS.md\n\n[brin Docs Index]|root: ./.brin-docs\n|packages:{old.md}\n[/brin Docs Index]\n";
        fs::write(&agents_path, existing).unwrap();

        // Add new package
        fs::write(docs_dir.join("express.md"), "# Express").unwrap();

        update_agents_md_index_at_path(&agents_path, &docs_dir).unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("express.md"));
        assert!(!content.contains("old.md"));
    }

    #[test]
    fn test_add_install_instructions_to_existing() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        fs::write(&agents_path, "# AGENTS.md\n\nSome content\n").unwrap();

        add_install_instructions_at_path(&agents_path).unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("## Package Installation"));
        assert!(content.contains("brin add <pkg>"));
        assert!(content.contains("Do not use npm install"));
    }

    #[test]
    fn test_add_install_instructions_idempotent() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        fs::write(&agents_path, "# AGENTS.md\n\nSome content\n").unwrap();

        add_install_instructions_at_path(&agents_path).unwrap();
        let content_after_first = fs::read_to_string(&agents_path).unwrap();

        add_install_instructions_at_path(&agents_path).unwrap();
        let content_after_second = fs::read_to_string(&agents_path).unwrap();

        assert_eq!(content_after_first, content_after_second);
    }

    #[test]
    fn test_add_install_instructions_creates_new() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        add_install_instructions_at_path(&agents_path).unwrap();

        let content = fs::read_to_string(&agents_path).unwrap();
        assert!(content.contains("# AGENTS.md"));
        assert!(content.contains("## Package Installation"));
    }

    #[test]
    fn test_remove_agents_md_index() {
        let temp_dir = TempDir::new().unwrap();
        let agents_path = temp_dir.path().join("AGENTS.md");

        // Create AGENTS.md with brin section and other content
        let content = "# AGENTS.md\n\n## Setup\n\n[brin Docs Index]|root: ./.brin-docs\n[/brin Docs Index]\n\n## Other\n";
        fs::write(&agents_path, content).unwrap();

        remove_agents_md_index_at_path(&agents_path).unwrap();

        let new_content = fs::read_to_string(&agents_path).unwrap();
        assert!(!new_content.contains("[brin Docs Index]"));
        assert!(new_content.contains("## Setup"));
        assert!(new_content.contains("## Other"));
    }
}
