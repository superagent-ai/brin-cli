//! npm registry changes feed client

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};

const CHANGES_URL: &str = "https://replicate.npmjs.com/_changes";
const STATE_FILE: &str = ".sus-watcher-seq";

/// A package change event
#[derive(Debug, Clone)]
pub struct PackageChange {
    pub name: String,
    pub version: Option<String>,
    pub change_type: ChangeType,
}

/// Type of change
#[derive(Debug, Clone, Copy)]
pub enum ChangeType {
    New,
    Update,
    Unpublish,
}

/// Response from CouchDB changes feed
#[derive(Deserialize)]
struct ChangesResponse {
    results: Vec<ChangeResult>,
    last_seq: serde_json::Value,
}

#[derive(Deserialize)]
struct ChangeResult {
    id: String,
    seq: serde_json::Value,
    deleted: Option<bool>,
    changes: Vec<ChangeRevision>,
}

#[derive(Deserialize)]
struct ChangeRevision {
    rev: String,
}

/// npm registry watcher
pub struct NpmWatcher {
    client: Client,
    last_seq: AtomicU64,
}

impl NpmWatcher {
    /// Create a new npm watcher
    pub fn new() -> Self {
        // Try to load last sequence from file
        let last_seq = std::fs::read_to_string(STATE_FILE)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        Self {
            client: Client::builder()
                .user_agent(format!("sus-watcher/{}", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("Failed to create HTTP client"),
            last_seq: AtomicU64::new(last_seq),
        }
    }

    /// Poll for changes since last sequence
    pub async fn poll(&self) -> Result<Vec<PackageChange>> {
        let since = self.last_seq.load(Ordering::Relaxed);

        tracing::debug!("Polling npm changes since seq {}", since);

        // Limit results to avoid huge responses
        let limit = std::env::var("CHANGES_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let url = format!(
            "{}?since={}&limit={}&include_docs=false",
            CHANGES_URL, since, limit
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "npm changes feed returned status {}",
                response.status()
            );
        }

        let changes_response: ChangesResponse = response.json().await?;

        // Parse last_seq (can be string or number)
        let new_seq = parse_seq(&changes_response.last_seq);
        if new_seq > since {
            self.last_seq.store(new_seq, Ordering::Relaxed);

            // Persist to file
            if let Err(e) = std::fs::write(STATE_FILE, new_seq.to_string()) {
                tracing::warn!("Failed to persist last_seq: {}", e);
            }
        }

        // Convert to PackageChange
        let changes: Vec<PackageChange> = changes_response
            .results
            .into_iter()
            .filter_map(|result| {
                // Skip design documents
                if result.id.starts_with('_') {
                    return None;
                }

                let change_type = if result.deleted.unwrap_or(false) {
                    ChangeType::Unpublish
                } else if result
                    .changes
                    .first()
                    .map(|c| c.rev.starts_with("1-"))
                    .unwrap_or(false)
                {
                    ChangeType::New
                } else {
                    ChangeType::Update
                };

                Some(PackageChange {
                    name: result.id,
                    version: None, // We'd need to fetch the doc to get the version
                    change_type,
                })
            })
            .collect();

        Ok(changes)
    }

    /// Get the current sequence number
    pub fn current_seq(&self) -> u64 {
        self.last_seq.load(Ordering::Relaxed)
    }
}

/// Parse sequence number from JSON value
fn parse_seq(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
        serde_json::Value::String(s) => {
            // CouchDB 2.x uses format like "123-abc"
            s.split('-').next().and_then(|n| n.parse().ok()).unwrap_or(0)
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_seq() {
        assert_eq!(parse_seq(&serde_json::json!(123)), 123);
        assert_eq!(parse_seq(&serde_json::json!("456-abc")), 456);
        assert_eq!(parse_seq(&serde_json::json!("789")), 789);
    }
}
