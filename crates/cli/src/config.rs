//! Configuration management for brin.json

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

const CONFIG_FILE: &str = "brin.json";

/// brin project configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SusConfig {
    /// Whether to generate AGENTS.md docs index
    #[serde(default)]
    pub agents_md: bool,
}

/// Load configuration from brin.json in current directory
/// Returns None if file doesn't exist, errors on parse failures
pub fn load_config() -> Option<SusConfig> {
    load_config_from_path(Path::new(CONFIG_FILE))
}

/// Internal implementation for testability
fn load_config_from_path(path: &Path) -> Option<SusConfig> {
    if !path.exists() {
        return None;
    }

    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(config) => Some(config),
            Err(e) => {
                tracing::warn!("Failed to parse brin.json: {}", e);
                None
            }
        },
        Err(e) => {
            tracing::warn!("Failed to read brin.json: {}", e);
            None
        }
    }
}

/// Save configuration to brin.json in current directory
pub fn save_config(config: &SusConfig) -> Result<()> {
    save_config_to_path(config, Path::new(CONFIG_FILE))
}

/// Internal implementation for testability
fn save_config_to_path(config: &SusConfig, path: &Path) -> Result<()> {
    let content = serde_json::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}

/// Check if AGENTS.md docs feature is enabled
pub fn is_agents_md_enabled() -> bool {
    load_config().map(|c| c.agents_md).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_config_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("brin.json");

        let config = load_config_from_path(&config_path);
        assert!(config.is_none());
    }

    #[test]
    fn test_save_and_load_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("brin.json");

        let config = SusConfig { agents_md: true };
        save_config_to_path(&config, &config_path).unwrap();

        let loaded = load_config_from_path(&config_path).unwrap();
        assert!(loaded.agents_md);
    }

    #[test]
    fn test_load_config_with_agents_md_false() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("brin.json");

        std::fs::write(&config_path, r#"{"agents_md": false}"#).unwrap();

        let loaded = load_config_from_path(&config_path).unwrap();
        assert!(!loaded.agents_md);
    }

    #[test]
    fn test_load_config_defaults() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("brin.json");

        // Empty JSON object should use defaults
        std::fs::write(&config_path, r#"{}"#).unwrap();

        let loaded = load_config_from_path(&config_path).unwrap();
        assert!(!loaded.agents_md); // default is false
    }

    #[test]
    fn test_load_config_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("brin.json");

        std::fs::write(&config_path, "not valid json").unwrap();

        let config = load_config_from_path(&config_path);
        assert!(config.is_none());
    }
}
