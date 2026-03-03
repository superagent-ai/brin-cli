//! check command — look up an artifact's security assessment

use crate::api_client::BrinClient;
use anyhow::{bail, Result};

/// Parse `<origin>/<identifier>` from the artifact string.
///
/// The origin is always the first path segment; the identifier is everything
/// that follows (which may itself contain slashes, e.g. `repo/owner/repo` or
/// `commit/owner/repo@sha`).
pub(crate) fn parse_artifact(artifact: &str) -> Result<(&str, &str)> {
    match artifact.split_once('/') {
        Some((origin, identifier)) if !origin.is_empty() && !identifier.is_empty() => {
            Ok((origin, identifier))
        }
        _ => bail!(
            concat!(
                "invalid artifact format: {:?}\n\n",
                "expected <origin>/<identifier>, for example:\n\n",
                "  brin check npm/express\n",
                "  brin check npm/lodash@4.17.21\n",
                "  brin check pypi/requests\n",
                "  brin check crate/serde\n",
                "  brin check repo/expressjs/express\n",
                "  brin check mcp/modelcontextprotocol/servers\n",
                "  brin check skill/owner/repo\n",
                "  brin check domain/example.com\n",
                "  brin check commit/owner/repo@abc123def",
            ),
            artifact
        ),
    }
}

/// Run the check command
pub async fn run(
    client: &BrinClient,
    artifact: &str,
    details: bool,
    webhook: Option<&str>,
    headers: bool,
) -> Result<()> {
    let (origin, identifier) = parse_artifact(artifact)?;

    let result = client.check(origin, identifier, details, webhook).await?;

    if headers {
        // Print only the X-Brin-* response headers, one per line
        if let Some(v) = &result.headers.score {
            println!("X-Brin-Score: {}", v);
        }
        if let Some(v) = &result.headers.verdict {
            println!("X-Brin-Verdict: {}", v);
        }
        if let Some(v) = &result.headers.confidence {
            println!("X-Brin-Confidence: {}", v);
        }
        if let Some(v) = &result.headers.tolerance {
            println!("X-Brin-Tolerance: {}", v);
        }
    } else {
        // Print the raw JSON body exactly as returned by the API
        println!("{}", result.body);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_artifact;

    // ── valid inputs ─────────────────────────────────────────────────────

    #[test]
    fn simple_package() {
        let (origin, id) = parse_artifact("npm/express").unwrap();
        assert_eq!(origin, "npm");
        assert_eq!(id, "express");
    }

    #[test]
    fn versioned_package() {
        let (origin, id) = parse_artifact("npm/lodash@4.17.21").unwrap();
        assert_eq!(origin, "npm");
        assert_eq!(id, "lodash@4.17.21");
    }

    #[test]
    fn pypi_package() {
        let (origin, id) = parse_artifact("pypi/requests").unwrap();
        assert_eq!(origin, "pypi");
        assert_eq!(id, "requests");
    }

    #[test]
    fn crate_package() {
        let (origin, id) = parse_artifact("crate/serde").unwrap();
        assert_eq!(origin, "crate");
        assert_eq!(id, "serde");
    }

    #[test]
    fn repo_multi_segment() {
        // identifier contains a slash — everything after the first slash is the identifier
        let (origin, id) = parse_artifact("repo/expressjs/express").unwrap();
        assert_eq!(origin, "repo");
        assert_eq!(id, "expressjs/express");
    }

    #[test]
    fn mcp_multi_segment() {
        let (origin, id) = parse_artifact("mcp/modelcontextprotocol/servers").unwrap();
        assert_eq!(origin, "mcp");
        assert_eq!(id, "modelcontextprotocol/servers");
    }

    #[test]
    fn commit_with_sha() {
        let (origin, id) = parse_artifact("commit/owner/repo@abc123def").unwrap();
        assert_eq!(origin, "commit");
        assert_eq!(id, "owner/repo@abc123def");
    }

    #[test]
    fn domain() {
        let (origin, id) = parse_artifact("domain/example.com").unwrap();
        assert_eq!(origin, "domain");
        assert_eq!(id, "example.com");
    }

    #[test]
    fn page_with_path() {
        let (origin, id) = parse_artifact("page/example.com/login").unwrap();
        assert_eq!(origin, "page");
        assert_eq!(id, "example.com/login");
    }

    #[test]
    fn skill_multi_segment() {
        let (origin, id) = parse_artifact("skill/owner/repo").unwrap();
        assert_eq!(origin, "skill");
        assert_eq!(id, "owner/repo");
    }

    // ── invalid inputs ───────────────────────────────────────────────────

    #[test]
    fn no_slash_is_error() {
        assert!(parse_artifact("badformat").is_err());
    }

    #[test]
    fn empty_string_is_error() {
        assert!(parse_artifact("").is_err());
    }

    #[test]
    fn only_slash_is_error() {
        assert!(parse_artifact("/").is_err());
    }

    #[test]
    fn missing_origin_is_error() {
        // leading slash — origin would be empty
        assert!(parse_artifact("/express").is_err());
    }

    #[test]
    fn missing_identifier_is_error() {
        // trailing slash — identifier would be empty
        assert!(parse_artifact("npm/").is_err());
    }
}
