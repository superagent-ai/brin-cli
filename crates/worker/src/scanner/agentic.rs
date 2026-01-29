//! Agentic threat detection and usage documentation using OpenCode CLI
//! https://github.com/anomalyco/opencode

use super::npm::ExtractedPackage;
use anyhow::{Context, Result};
use common::{AgenticThreatSummary, ApiDoc, ThreatType, UsageDocs};
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

/// Timeout for OpenCode commands (5 minutes)
const OPENCODE_TIMEOUT_SECS: u64 = 300;

/// OpenCode threat report structure
#[derive(Debug, Deserialize, Default)]
struct OpenCodeThreatReport {
    #[serde(default)]
    threats: Vec<OpenCodeThreat>,
}

/// Individual threat from OpenCode analysis
#[derive(Debug, Deserialize)]
struct OpenCodeThreat {
    #[serde(alias = "type", alias = "threat_type")]
    threat_type: String,
    #[serde(default)]
    confidence: Option<f32>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    snippet: Option<String>,
}

/// Generated usage documentation from OpenCode
#[derive(Debug, Deserialize, Default)]
struct GeneratedUsageDocs {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    quick_start: Option<String>,
    #[serde(default)]
    key_apis: Vec<GeneratedApiDoc>,
    #[serde(default)]
    best_practices: Vec<String>,
    #[serde(default)]
    common_patterns: Vec<String>,
    #[serde(default)]
    gotchas: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GeneratedApiDoc {
    name: String,
    description: String,
    #[serde(default)]
    example: Option<String>,
}

/// Agentic threat scanner using OpenCode CLI
pub struct AgenticScanner {
    // No API key needed - OpenCode handles its own configuration
}

impl AgenticScanner {
    /// Create a new agentic scanner
    pub fn new(_api_key: Option<String>) -> Self {
        // API key parameter kept for backward compatibility but not used
        // OpenCode uses its own configuration (~/.opencode/config or ANTHROPIC_API_KEY env)
        Self {}
    }

    /// Get the OpenCode binary path (checks multiple locations)
    fn opencode_binary() -> String {
        // Check home directory install first (curl installer puts it here)
        if let Ok(home) = std::env::var("HOME") {
            let home_path = format!("{}/.opencode/bin/opencode", home);
            if std::path::Path::new(&home_path).exists() {
                return home_path;
            }
        }

        // Check common system locations
        for path in &[
            "/usr/local/bin/opencode", // npm global install
            "/usr/bin/opencode",
        ] {
            if std::path::Path::new(path).exists() {
                return path.to_string();
            }
        }

        // Fall back to PATH lookup
        "opencode".to_string()
    }

    /// Check if OpenCode is installed
    pub async fn is_opencode_installed() -> bool {
        Command::new(Self::opencode_binary())
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Install OpenCode if not present
    pub async fn ensure_installed() -> Result<()> {
        if Self::is_opencode_installed().await {
            tracing::debug!("OpenCode is already installed");
            return Ok(());
        }

        tracing::info!("Installing OpenCode...");

        // Install using the official installer
        let output = Command::new("sh")
            .arg("-c")
            .arg("curl -fsSL https://opencode.ai/install | bash")
            .output()
            .await
            .context("Failed to run OpenCode installer")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("OpenCode installation failed: {}", stderr);
        }

        // Verify installation
        if !Self::is_opencode_installed().await {
            anyhow::bail!("OpenCode installation completed but binary not found in PATH");
        }

        tracing::info!("OpenCode installed successfully");
        Ok(())
    }

    /// Scan extracted package for agentic threats using OpenCode
    pub async fn scan(&self, extracted: &ExtractedPackage) -> Result<Vec<AgenticThreatSummary>> {
        let package_dir = &extracted.root;

        tracing::debug!("Running OpenCode threat scan in {:?}", package_dir);

        let prompt = r#"Scan this repository for repo poisoning, prompt injection, or other attacks targeting AI agents. Only output a report, no other text.

Output your findings as a JSON object with this structure:
{
  "threats": [
    {
      "threat_type": "prompt_injection" | "repo_poisoning" | "instruction_override" | "data_exfiltration" | "social_engineering",
      "severity": "critical" | "high" | "medium" | "low",
      "confidence": 0.0-1.0,
      "location": "file path or location description",
      "description": "what the threat does",
      "snippet": "relevant code snippet (max 100 chars)"
    }
  ],
  "summary": "brief summary of findings"
}

If no threats found, return: {"threats": [], "summary": "No threats detected"}"#;

        let output = self.run_opencode(package_dir, prompt).await?;

        // Parse the JSON output
        let report: OpenCodeThreatReport = self.parse_json_output(&output)?;

        // Convert to AgenticThreatSummary
        let threats: Vec<AgenticThreatSummary> = report
            .threats
            .into_iter()
            .filter(|t| t.confidence.unwrap_or(0.5) >= 0.5)
            .map(|t| AgenticThreatSummary {
                threat_type: parse_threat_type(&t.threat_type),
                confidence: t.confidence.unwrap_or(0.7),
                location: t.location,
                snippet: t.snippet,
            })
            .collect();

        if !threats.is_empty() {
            tracing::info!("OpenCode detected {} potential threats", threats.len());
        }

        Ok(threats)
    }

    /// Generate usage documentation for a package using OpenCode
    pub async fn generate_usage_docs(
        &self,
        extracted: &ExtractedPackage,
        package_name: &str,
    ) -> Result<UsageDocs> {
        let package_dir = &extracted.root;

        tracing::debug!("Generating usage docs for {} using OpenCode", package_name);

        let prompt = format!(
            r#"Generate usage documentation for this npm package "{}" following the Agent Skills specification (agentskills.io).

Output a JSON object with this exact structure:
{{
  "description": "Brief 1-2 sentence description (max 1024 chars)",
  "quick_start": "A minimal working code example with imports",
  "key_apis": [
    {{
      "name": "functionOrClassName",
      "description": "What it does",
      "example": "Short usage example"
    }}
  ],
  "best_practices": ["Practice 1", "Practice 2"],
  "common_patterns": ["Pattern 1", "Pattern 2"],
  "gotchas": ["Gotcha 1", "Gotcha 2"]
}}

Rules:
- quick_start should be a complete, runnable JavaScript/TypeScript example
- key_apis should list the 3-5 most important exports
- best_practices should be actionable tips
- gotchas should warn about common mistakes
- Use modern ES6+ syntax in examples"#,
            package_name
        );

        let output = self.run_opencode(package_dir, &prompt).await?;

        // Parse the JSON output
        let generated: GeneratedUsageDocs = self.parse_json_output(&output)?;

        Ok(UsageDocs {
            description: generated.description,
            quick_start: generated.quick_start,
            key_apis: generated
                .key_apis
                .into_iter()
                .map(|api| ApiDoc {
                    name: api.name,
                    description: api.description,
                    example: api.example,
                })
                .collect(),
            best_practices: generated.best_practices,
            common_patterns: generated.common_patterns,
            gotchas: generated.gotchas,
        })
    }

    /// Run OpenCode CLI command in a directory
    async fn run_opencode(&self, working_dir: &Path, prompt: &str) -> Result<String> {
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(OPENCODE_TIMEOUT_SECS),
            Command::new(Self::opencode_binary())
                .arg("run")
                .arg("-m")
                .arg("opencode/kimi-k2.5-free")
                .arg(prompt)
                .arg("--format")
                .arg("json")
                .current_dir(working_dir)
                .output(),
        )
        .await
        .context("OpenCode command timed out")?
        .context("Failed to execute OpenCode")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("OpenCode command failed: {}", stderr);
            // Return empty result instead of failing completely
            return Ok("{}".to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    }

    /// Parse JSON from OpenCode output
    /// OpenCode outputs NDJSON (newline-delimited JSON) with event types
    /// The actual response text is in events with "type":"text" under part.text
    fn parse_json_output<T: for<'de> Deserialize<'de> + Default>(&self, output: &str) -> Result<T> {
        // Extract text from OpenCode NDJSON format
        let text_content = extract_opencode_text(output);

        if text_content.is_empty() {
            tracing::warn!("No text content found in OpenCode output");
            return Ok(T::default());
        }

        tracing::debug!(
            "Extracted text from OpenCode: {}",
            &text_content[..text_content.len().min(200)]
        );

        // Try direct parse first
        if let Ok(parsed) = serde_json::from_str(&text_content) {
            return Ok(parsed);
        }

        // Try to extract JSON object from the text (model might include extra text)
        let json_text = extract_json_object(&text_content);
        if let Ok(parsed) = serde_json::from_str(&json_text) {
            return Ok(parsed);
        }

        // Try to extract JSON array
        let json_array = extract_json_array(&text_content);
        if let Ok(parsed) = serde_json::from_str(&json_array) {
            return Ok(parsed);
        }

        tracing::warn!(
            "Failed to parse OpenCode text as JSON, using defaults. Text: {}",
            &text_content[..text_content.len().min(500)]
        );
        Ok(T::default())
    }
}

/// OpenCode NDJSON text event structure
#[derive(Deserialize)]
struct OpenCodeEvent {
    #[serde(rename = "type")]
    event_type: String,
    part: Option<OpenCodePart>,
}

#[derive(Deserialize)]
struct OpenCodePart {
    text: Option<String>,
}

/// Extract text content from OpenCode NDJSON output
fn extract_opencode_text(output: &str) -> String {
    let mut text_parts = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Ok(event) = serde_json::from_str::<OpenCodeEvent>(line) {
            if event.event_type == "text" {
                if let Some(part) = event.part {
                    if let Some(text) = part.text {
                        text_parts.push(text);
                    }
                }
            }
        }
    }

    text_parts.join("")
}

/// Parse threat type string to enum
fn parse_threat_type(s: &str) -> ThreatType {
    match s.to_lowercase().as_str() {
        "prompt_injection" | "prompt-injection" => ThreatType::PromptInjection,
        "instruction_override" | "instruction-override" => ThreatType::InstructionOverride,
        "data_exfiltration" | "data-exfiltration" => ThreatType::DataExfiltration,
        "social_engineering" | "social-engineering" => ThreatType::SocialEngineering,
        "repo_poisoning" | "repo-poisoning" => ThreatType::PromptInjection, // Map to closest type
        _ => ThreatType::PromptInjection,                                   // Default
    }
}

/// Extract JSON object from response text
fn extract_json_object(text: &str) -> String {
    // Try to find JSON object in the response
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            return text[start..=end].to_string();
        }
    }
    "{}".to_string()
}

/// Extract JSON array from response text
fn extract_json_array(text: &str) -> String {
    // Try to find JSON array in the response
    if let Some(start) = text.find('[') {
        if let Some(end) = text.rfind(']') {
            return text[start..=end].to_string();
        }
    }
    "[]".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_object() {
        assert_eq!(extract_json_object("{}"), "{}");
        assert_eq!(
            extract_json_object("Here's the result: {\"test\": 1}"),
            "{\"test\": 1}"
        );
        assert_eq!(
            extract_json_object("```json\n{\"threats\": []}\n```"),
            "{\"threats\": []}"
        );
    }

    #[test]
    fn test_extract_json_array() {
        assert_eq!(extract_json_array("[]"), "[]");
        assert_eq!(
            extract_json_array("Here's the result: [{\"test\": 1}]"),
            "[{\"test\": 1}]"
        );
    }

    #[test]
    fn test_parse_threat_type() {
        assert!(matches!(
            parse_threat_type("prompt_injection"),
            ThreatType::PromptInjection
        ));
        assert!(matches!(
            parse_threat_type("prompt-injection"),
            ThreatType::PromptInjection
        ));
        assert!(matches!(
            parse_threat_type("PROMPT_INJECTION"),
            ThreatType::PromptInjection
        ));
        assert!(matches!(
            parse_threat_type("data_exfiltration"),
            ThreatType::DataExfiltration
        ));
        assert!(matches!(
            parse_threat_type("repo_poisoning"),
            ThreatType::PromptInjection
        ));
    }

    #[tokio::test]
    async fn test_scanner_creation() {
        // Scanner should create without API key
        let _scanner = AgenticScanner::new(None);
        let _scanner = AgenticScanner::new(Some("test-key".to_string()));
    }
}
