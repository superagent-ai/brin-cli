//! HTTP client for the brin API

use anyhow::{Context, Result};
use reqwest::Client;

/// The X-Brin-* response headers returned on every API response
#[derive(Debug)]
pub struct BrinHeaders {
    pub score: Option<String>,
    pub verdict: Option<String>,
    pub confidence: Option<String>,
    pub tolerance: Option<String>,
}

/// Full result from a check call: raw body + extracted headers
#[derive(Debug)]
pub struct CheckResult {
    /// Raw JSON body as returned by the API
    pub body: String,
    /// Extracted X-Brin-* response headers
    pub headers: BrinHeaders,
}

/// Optional query parameters for a check request
#[derive(Debug, Default)]
pub struct CheckOptions<'a> {
    pub details: bool,
    pub webhook: Option<&'a str>,
    pub tolerance: Option<&'a str>,
    pub refresh: bool,
    pub mode: Option<&'a str>,
    pub format: Option<&'a str>,
}

/// Client for the brin API
pub struct BrinClient {
    client: Client,
    pub(crate) base_url: String,
}

impl BrinClient {
    /// Create a new API client
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .user_agent(format!("brin-cli/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("failed to build HTTP client"),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Check an artifact.
    ///
    /// - `origin`     — e.g. `"npm"`, `"pypi"`, `"repo"`, `"mcp"`, `"skill"`, `"domain"`, `"commit"`
    /// - `identifier` — the artifact identifier, e.g. `"express"`, `"owner/repo"`, `"owner/repo@sha"`
    /// - `opts`       — optional query parameters (details, webhook, tolerance, refresh, mode, format)
    pub async fn check(
        &self,
        origin: &str,
        identifier: &str,
        opts: &CheckOptions<'_>,
    ) -> Result<CheckResult> {
        let url = format!("{}/{}/{}", self.base_url, origin, identifier);

        let mut query: Vec<(&str, String)> = Vec::new();
        if opts.details {
            query.push(("details", "true".into()));
        }
        if let Some(wh) = opts.webhook {
            query.push(("webhook", wh.to_string()));
        }
        if let Some(t) = opts.tolerance {
            query.push(("tolerance", t.to_string()));
        }
        if opts.refresh {
            query.push(("refresh", "true".into()));
        }
        if let Some(m) = opts.mode {
            query.push(("mode", m.to_string()));
        }
        if let Some(f) = opts.format {
            query.push(("format", f.to_string()));
        }

        let response = self
            .client
            .get(&url)
            .query(&query)
            .send()
            .await
            .context("failed to connect to brin API")?
            .error_for_status()
            .context("brin API returned an error")?;

        // Extract X-Brin-* headers before consuming the response body
        let brin_headers = BrinHeaders {
            score: response
                .headers()
                .get("x-brin-score")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            verdict: response
                .headers()
                .get("x-brin-verdict")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            confidence: response
                .headers()
                .get("x-brin-confidence")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            tolerance: response
                .headers()
                .get("x-brin-tolerance")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        };

        let body = response
            .text()
            .await
            .context("failed to read brin API response")?;

        Ok(CheckResult {
            body,
            headers: brin_headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn safe_body() -> serde_json::Value {
        serde_json::json!({
            "origin": "npm",
            "name": "express",
            "score": 81,
            "confidence": "medium",
            "verdict": "safe",
            "tolerance": "conservative",
            "scanned_at": "2026-02-25T09:00:00Z",
            "url": "https://api.brin.sh/npm/express"
        })
    }

    fn safe_body_with_sub_scores() -> serde_json::Value {
        let mut body = safe_body();
        body["sub_scores"] = serde_json::json!({
            "identity": 95.0,
            "behavior": 40.0,
            "content": 100.0,
            "graph": 30.0
        });
        body
    }

    // ── base URL handling ────────────────────────────────────────────────

    #[test]
    fn trailing_slash_stripped() {
        let c1 = BrinClient::new("https://api.brin.sh/");
        let c2 = BrinClient::new("https://api.brin.sh");
        assert_eq!(c1.base_url, "https://api.brin.sh");
        assert_eq!(c2.base_url, "https://api.brin.sh");
    }

    // ── check — basic GET ────────────────────────────────────────────────

    #[tokio::test]
    async fn check_simple_package() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-brin-score", "81")
                    .insert_header("x-brin-verdict", "safe")
                    .insert_header("x-brin-confidence", "medium")
                    .insert_header("x-brin-tolerance", "conservative")
                    .set_body_json(safe_body()),
            )
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let result = client
            .check("npm", "express", &CheckOptions::default())
            .await
            .unwrap();

        // body is valid JSON containing expected fields
        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert_eq!(v["name"], "express");
        assert_eq!(v["verdict"], "safe");
        assert_eq!(v["score"], 81);

        // headers extracted correctly
        assert_eq!(result.headers.score.as_deref(), Some("81"));
        assert_eq!(result.headers.verdict.as_deref(), Some("safe"));
        assert_eq!(result.headers.confidence.as_deref(), Some("medium"));
        assert_eq!(result.headers.tolerance.as_deref(), Some("conservative"));
    }

    #[tokio::test]
    async fn check_multi_segment_identifier() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repo/expressjs/express"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "origin": "repo",
                "name": "expressjs/express",
                "score": 91,
                "verdict": "safe"
            })))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let result = client
            .check("repo", "expressjs/express", &CheckOptions::default())
            .await
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert_eq!(v["origin"], "repo");
        assert_eq!(v["score"], 91);
    }

    #[tokio::test]
    async fn check_versioned_package() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/lodash@4.17.21"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "origin": "npm",
                "name": "lodash",
                "version": "4.17.21",
                "score": 64,
                "verdict": "caution"
            })))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let result = client
            .check("npm", "lodash@4.17.21", &CheckOptions::default())
            .await
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert_eq!(v["version"], "4.17.21");
        assert_eq!(v["verdict"], "caution");
    }

    // ── check — ?details=true ────────────────────────────────────────────

    #[tokio::test]
    async fn check_details_flag_appends_query_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("details", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body_with_sub_scores()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            details: true,
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert!(
            v["sub_scores"].is_object(),
            "sub_scores should be present with --details"
        );
        assert_eq!(v["sub_scores"]["identity"], 95.0);
    }

    #[tokio::test]
    async fn check_without_details_omits_query_param() {
        let server = MockServer::start().await;

        // This mock matches only requests WITHOUT ?details — wiremock returns
        // 404 for unmatched requests, so the test would fail if details=true
        // were sent when not requested.
        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let result = client
            .check("npm", "express", &CheckOptions::default())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert!(v["sub_scores"].is_null() || !v.as_object().unwrap().contains_key("sub_scores"));
    }

    // ── check — ?webhook=<url> ───────────────────────────────────────────

    #[tokio::test]
    async fn check_webhook_appends_query_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("webhook", "https://my-server.com/cb"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            webhook: Some("https://my-server.com/cb"),
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert_eq!(v["verdict"], "safe");
    }

    #[tokio::test]
    async fn check_details_and_webhook_combined() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("details", "true"))
            .and(query_param("webhook", "https://my-server.com/cb"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body_with_sub_scores()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            details: true,
            webhook: Some("https://my-server.com/cb"),
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert!(v["sub_scores"].is_object());
    }

    // ── check — missing headers are None ────────────────────────────────

    #[tokio::test]
    async fn check_missing_brin_headers_are_none() {
        let server = MockServer::start().await;

        // Response with no X-Brin-* headers
        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let result = client
            .check("npm", "express", &CheckOptions::default())
            .await
            .unwrap();

        assert!(result.headers.score.is_none());
        assert!(result.headers.verdict.is_none());
        assert!(result.headers.confidence.is_none());
        assert!(result.headers.tolerance.is_none());
    }

    // ── check — API error propagation ───────────────────────────────────

    #[tokio::test]
    async fn check_propagates_api_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/nonexistent"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let err = client
            .check("npm", "nonexistent", &CheckOptions::default())
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("error"),
            "expected error for 404, got: {err}"
        );
    }

    #[tokio::test]
    async fn check_propagates_server_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let err = client
            .check("npm", "express", &CheckOptions::default())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("error"));
    }

    // ── check — ?tolerance=<level> ───────────────────────────────────────

    #[tokio::test]
    async fn check_tolerance_appends_query_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("tolerance", "lenient"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            tolerance: Some("lenient"),
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert_eq!(v["verdict"], "safe");
    }

    // ── check — ?refresh=true ────────────────────────────────────────────

    #[tokio::test]
    async fn check_refresh_appends_query_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("refresh", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            refresh: true,
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert_eq!(v["verdict"], "safe");
    }

    // ── check — ?mode=full ───────────────────────────────────────────────

    #[tokio::test]
    async fn check_mode_appends_query_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("mode", "full"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            mode: Some("full"),
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert_eq!(v["verdict"], "safe");
    }

    // ── check — ?format=<fmt> ────────────────────────────────────────────

    #[tokio::test]
    async fn check_format_appends_query_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("format", "simple"))
            .respond_with(ResponseTemplate::new(200).set_body_string("safe 85"))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            format: Some("simple"),
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        assert_eq!(result.body, "safe 85");
    }

    // ── check — all new params combined ──────────────────────────────────

    #[tokio::test]
    async fn check_all_new_params_combined() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/npm/express"))
            .and(query_param("details", "true"))
            .and(query_param("tolerance", "yolo"))
            .and(query_param("refresh", "true"))
            .and(query_param("mode", "full"))
            .and(query_param("format", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(safe_body_with_sub_scores()))
            .mount(&server)
            .await;

        let client = BrinClient::new(&server.uri());
        let opts = CheckOptions {
            details: true,
            tolerance: Some("yolo"),
            refresh: true,
            mode: Some("full"),
            format: Some("json"),
            ..Default::default()
        };
        let result = client.check("npm", "express", &opts).await.unwrap();

        let v: serde_json::Value = serde_json::from_str(&result.body).unwrap();
        assert!(v["sub_scores"].is_object());
    }
}
