//! Seed script to populate the scan queue with npm packages

use anyhow::Result;
use clap::Parser;
use common::models::{ScanJob, ScanPriority};
use common::queue::ScanQueue;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

const DOWNLOAD_COUNTS_URL: &str = "https://unpkg.com/download-counts@latest/counts.json";

#[derive(Parser)]
#[command(name = "seed", about = "Seed the scan queue with npm packages")]
struct Args {
    /// Number of top packages to fetch by download count
    #[arg(short, long, default_value = "1000")]
    count: usize,

    /// Include AI/agent ecosystem packages
    #[arg(long, default_value = "true")]
    include_ai: bool,

    /// Include packages with known CVEs from OSV
    #[arg(long, default_value = "true")]
    include_cves: bool,

    /// Scan priority for seeded packages
    #[arg(long, default_value = "low")]
    priority: String,

    /// Dry run - don't actually push to queue
    #[arg(long)]
    dry_run: bool,

    /// Redis URL (can also use REDIS_URL env var)
    #[arg(long, env = "REDIS_URL")]
    redis_url: String,
}

/// OSV vulnerability response
#[derive(Debug, Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: Option<OsvPackage>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    name: Option<String>,
}

/// Curated list of AI/agent ecosystem packages
const AI_PACKAGES: &[&str] = &[
    // OpenAI ecosystem
    "openai",
    "gpt-3-encoder",
    "gpt-tokenizer",
    "tiktoken",
    // Anthropic
    "anthropic",
    "@anthropic-ai/sdk",
    // LangChain
    "langchain",
    "@langchain/core",
    "@langchain/openai",
    "@langchain/anthropic",
    "@langchain/community",
    // Vector stores
    "pinecone-client",
    "@pinecone-database/pinecone",
    "chromadb",
    "@qdrant/js-client-rest",
    "weaviate-client",
    // AI utilities
    "ai",
    "@ai-sdk/openai",
    "@ai-sdk/anthropic",
    "replicate",
    "cohere-ai",
    "llamaindex",
    // MCP and tools
    "@modelcontextprotocol/sdk",
    "zod",
    "zod-to-json-schema",
    // Embeddings
    "@xenova/transformers",
    "sentence-transformers",
    // Agent frameworks
    "autogen",
    "crewai",
    // Common in AI pipelines
    "pdf-parse",
    "mammoth",
    "cheerio",
    "puppeteer",
    "playwright",
];

/// Packages known to have install scripts (higher risk)
const INSTALL_SCRIPT_PACKAGES: &[&str] = &[
    "esbuild",
    "node-gyp",
    "node-pre-gyp",
    "@swc/core",
    "sharp",
    "canvas",
    "sqlite3",
    "bcrypt",
    "argon2",
    "better-sqlite3",
    "fsevents",
    "node-sass",
    "puppeteer",
    "electron",
];

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("seed=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    let priority = match args.priority.as_str() {
        "immediate" => ScanPriority::Immediate,
        "high" => ScanPriority::High,
        "medium" => ScanPriority::Medium,
        _ => ScanPriority::Low,
    };

    println!("🌱 sus database seeder\n");

    let mut packages: HashSet<String> = HashSet::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 min timeout for large file
        .build()?;

    // 1. Fetch top packages from download-counts
    println!(
        "📦 Fetching top {} packages by download count...",
        args.count
    );
    println!("   (downloading ~90MB of npm stats, this may take a moment)");

    match fetch_top_packages(&client, args.count).await {
        Ok(top_packages) => {
            println!("   Found {} top packages", top_packages.len());
            packages.extend(top_packages);
        }
        Err(e) => {
            println!("   Warning: Failed to fetch top packages: {}", e);
            println!("   Continuing with AI and CVE packages only...");
        }
    }

    // 2. Add AI/agent packages
    if args.include_ai {
        println!("\n🤖 Adding AI/agent ecosystem packages...");
        for pkg in AI_PACKAGES {
            packages.insert(pkg.to_string());
        }
        println!("   Added {} AI packages", AI_PACKAGES.len());
    }

    // 3. Add packages with known install scripts
    println!("\n⚠️  Adding packages with install scripts...");
    for pkg in INSTALL_SCRIPT_PACKAGES {
        packages.insert(pkg.to_string());
    }
    println!(
        "   Added {} install script packages",
        INSTALL_SCRIPT_PACKAGES.len()
    );

    // 4. Fetch packages with CVEs
    if args.include_cves {
        println!("\n🔒 Fetching packages with known CVEs...");
        match fetch_cve_packages(&client).await {
            Ok(cve_packages) => {
                println!("   Found {} packages with CVEs", cve_packages.len());
                packages.extend(cve_packages);
            }
            Err(e) => {
                println!("   Warning: Failed to fetch CVE packages: {}", e);
            }
        }
    }

    // Deduplicate and report
    let packages: Vec<String> = packages.into_iter().collect();
    println!("\n📊 Total unique packages to seed: {}", packages.len());

    if args.dry_run {
        println!("\n🔍 Dry run - packages that would be queued:");
        for (i, pkg) in packages.iter().enumerate().take(20) {
            println!("   {}. {}", i + 1, pkg);
        }
        if packages.len() > 20 {
            println!("   ... and {} more", packages.len() - 20);
        }
        return Ok(());
    }

    // Connect to Redis and push jobs
    println!("\n🔗 Connecting to Redis...");
    let queue = ScanQueue::new(&args.redis_url).await?;

    // Check existing queue size
    let existing = queue.total_len().await?;
    if existing > 0 {
        println!("   Note: Queue already has {} pending jobs", existing);
    }

    println!("\n🚀 Pushing packages to scan queue...\n");

    let pb = ProgressBar::new(packages.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )?
            .progress_chars("#>-"),
    );

    let mut success = 0;
    let mut failed = 0;

    for package in &packages {
        let job = ScanJob {
            id: uuid::Uuid::new_v4(),
            package: package.clone(),
            version: None, // Will fetch latest
            priority,
            requested_at: chrono::Utc::now(),
            requested_by: Some("seed".to_string()),
            tarball_path: None,
        };

        match queue.push(job).await {
            Ok(_) => success += 1,
            Err(e) => {
                tracing::warn!("Failed to queue {}: {}", package, e);
                failed += 1;
            }
        }
        pb.inc(1);
    }

    pb.finish_and_clear();

    println!("✅ Seeding complete!");
    println!("   Queued: {} packages", success);
    if failed > 0 {
        println!("   Failed: {} packages", failed);
    }

    let total = queue.total_len().await?;
    println!("\n📈 Total queue size: {} jobs", total);

    Ok(())
}

/// Fetch top packages from npm download-counts
async fn fetch_top_packages(client: &reqwest::Client, count: usize) -> Result<Vec<String>> {
    // Fetch the download counts JSON (this is a large file ~90MB)
    let response = client
        .get(DOWNLOAD_COUNTS_URL)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch download counts: {}", response.status());
    }

    // Parse as HashMap<package_name, download_count>
    let counts: HashMap<String, u64> = response.json().await?;

    // Sort by download count (descending) and take top N
    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let top_packages: Vec<String> = sorted
        .into_iter()
        .take(count)
        .map(|(name, _)| name)
        .collect();

    Ok(top_packages)
}

/// Fetch packages with known CVEs from OSV
async fn fetch_cve_packages(client: &reqwest::Client) -> Result<Vec<String>> {
    let mut packages = HashSet::new();

    // Query OSV for recent npm vulnerabilities
    let query = serde_json::json!({
        "package": {
            "ecosystem": "npm"
        }
    });

    let response = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .await?;

    if response.status().is_success() {
        let osv: OsvResponse = response.json().await?;

        if let Some(vulns) = osv.vulns {
            for vuln in vulns.iter().take(500) {
                // Limit to avoid too many
                if let Some(affected) = &vuln.affected {
                    for a in affected {
                        if let Some(pkg) = &a.package {
                            if let Some(name) = &pkg.name {
                                packages.insert(name.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(packages.into_iter().collect())
}
