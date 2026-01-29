//! npm registry changes feed client
//!
//! Uses the npm replicate.npmjs.com CouchDB changes feed with descending=true
//! to get the most recent package updates.

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Mutex;

const CHANGES_URL: &str = "https://replicate.npmjs.com/_changes";

/// A package change event
#[derive(Debug, Clone)]
pub struct PackageChange {
    pub name: String,
    pub version: Option<String>,
}

/// Response from CouchDB changes feed
#[derive(Deserialize)]
struct ChangesResponse {
    results: Vec<ChangeResult>,
}

#[derive(Deserialize)]
struct ChangeResult {
    seq: u64,
    id: String,
    deleted: Option<bool>,
}

/// npm registry watcher
pub struct NpmWatcher {
    client: Client,
    /// Track seen sequence numbers to avoid processing duplicates
    seen_seqs: Mutex<HashSet<u64>>,
    /// Maximum number of seqs to track (prevent unbounded memory growth)
    max_seen: usize,
}

impl NpmWatcher {
    /// Create a new npm watcher
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("sus-watcher/{}", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            seen_seqs: Mutex::new(HashSet::new()),
            max_seen: 10000, // Keep track of last 10k sequences
        }
    }

    /// Poll for recent changes using descending=true
    /// Returns new packages that haven't been seen before
    pub async fn poll(&self) -> Result<Vec<PackageChange>> {
        // Limit results to avoid huge responses
        let limit = std::env::var("CHANGES_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        // Use descending=true to get most recent changes first
        let url = format!("{}?descending=true&limit={}", CHANGES_URL, limit);

        tracing::debug!("Polling npm changes: {}", url);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("npm changes feed returned status {}", response.status());
        }

        let changes_response: ChangesResponse = response.json().await?;

        let mut seen = self.seen_seqs.lock().unwrap();

        // Prune old entries if we've accumulated too many
        if seen.len() > self.max_seen {
            seen.clear();
            tracing::debug!("Cleared seen_seqs cache");
        }

        // Filter to only new changes we haven't seen
        let changes: Vec<PackageChange> = changes_response
            .results
            .into_iter()
            .filter(|result| {
                // Skip if we've seen this seq before
                if seen.contains(&result.seq) {
                    return false;
                }
                // Skip design documents and deleted packages
                if result.id.starts_with('_') || result.deleted.unwrap_or(false) {
                    return false;
                }
                // Mark as seen
                seen.insert(result.seq);
                true
            })
            .map(|result| PackageChange {
                name: result.id,
                version: None,
            })
            .collect();

        Ok(changes)
    }
}
