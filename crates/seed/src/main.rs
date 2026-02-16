//! Seed script to populate the scan queue with packages from npm or PyPI

use anyhow::Result;
use clap::Parser;
use common::models::{Registry, ScanJob, ScanPriority};
use common::queue::ScanQueue;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// npm download counts URL
const NPM_DOWNLOAD_COUNTS_URL: &str = "https://unpkg.com/download-counts@latest/counts.json";

/// PyPI top packages URL (from hugovk/top-pypi-packages)
const PYPI_TOP_PACKAGES_URL: &str =
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json";

#[derive(Parser)]
#[command(
    name = "seed",
    about = "Seed the scan queue with packages from npm or PyPI"
)]
struct Args {
    /// Number of top packages to fetch by download count
    #[arg(short, long, default_value = "1000")]
    count: usize,

    /// Offset to skip the first N packages (for incremental seeding)
    #[arg(short, long, default_value = "0")]
    offset: usize,

    /// Registry to seed packages from (npm or pypi)
    #[arg(short, long, default_value = "npm")]
    registry: String,

    /// Include AI/agent ecosystem packages
    #[arg(long)]
    include_ai: bool,

    /// Include packages with known CVEs from OSV
    #[arg(long)]
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

/// Curated list of AI/agent ecosystem packages (npm)
const NPM_AI_PACKAGES: &[&str] = &[
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

/// Curated list of AI/agent ecosystem packages (PyPI)
const PYPI_AI_PACKAGES: &[&str] = &[
    // OpenAI ecosystem
    "openai",
    "tiktoken",
    // Anthropic
    "anthropic",
    // LangChain
    "langchain",
    "langchain-core",
    "langchain-openai",
    "langchain-anthropic",
    "langchain-community",
    // Vector stores
    "pinecone-client",
    "chromadb",
    "qdrant-client",
    "weaviate-client",
    // ML/AI frameworks
    "transformers",
    "torch",
    "tensorflow",
    "numpy",
    "pandas",
    "scikit-learn",
    // AI utilities
    "llama-index",
    "huggingface-hub",
    "sentence-transformers",
    "guidance",
    "instructor",
    // Agent frameworks
    "autogen",
    "crewai",
    "agentops",
    // Common in AI pipelines
    "pydantic",
    "fastapi",
    "httpx",
    "aiohttp",
    "requests",
    "beautifulsoup4",
    "pypdf",
    "python-docx",
    // MCP
    "mcp",
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

    // Parse registry
    let registry = match args.registry.to_lowercase().as_str() {
        "pypi" | "python" => Registry::Pypi,
        _ => Registry::Npm,
    };

    let priority = match args.priority.as_str() {
        "immediate" => ScanPriority::Immediate,
        "high" => ScanPriority::High,
        "medium" => ScanPriority::Medium,
        _ => ScanPriority::Low,
    };

    let registry_name = match registry {
        Registry::Npm => "npm",
        Registry::Pypi => "PyPI",
        Registry::Crates => "crates.io",
    };

    println!("🌱 brin database seeder ({})\n", registry_name);

    let mut packages: HashSet<String> = HashSet::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 min timeout for large file
        .build()?;

    // 1. Fetch top packages by download count
    if args.offset > 0 {
        println!(
            "📦 Fetching {} packages {} to {} by download count...",
            registry_name,
            args.offset + 1,
            args.offset + args.count
        );
    } else {
        println!(
            "📦 Fetching top {} {} packages by download count...",
            args.count, registry_name
        );
    }

    match registry {
        Registry::Npm => {
            println!("   (downloading ~90MB of npm stats, this may take a moment)");
            match fetch_top_npm_packages(&client, args.count, args.offset).await {
                Ok(top_packages) => {
                    println!("   Found {} top packages", top_packages.len());
                    packages.extend(top_packages);
                }
                Err(e) => {
                    println!("   Warning: Failed to fetch top packages: {}", e);
                    println!("   Continuing with AI and CVE packages only...");
                }
            }
        }
        Registry::Pypi => {
            println!("   (downloading PyPI stats from top-pypi-packages)");
            match fetch_top_pypi_packages(&client, args.count, args.offset).await {
                Ok(top_packages) => {
                    println!("   Found {} top packages", top_packages.len());
                    packages.extend(top_packages);
                }
                Err(e) => {
                    println!("   Warning: Failed to fetch top packages: {}", e);
                    println!("   Continuing with AI and CVE packages only...");
                }
            }
        }
        Registry::Crates => {
            println!("   Warning: crates.io seeding not yet implemented");
        }
    }

    // 2. Add AI/agent packages
    if args.include_ai {
        println!("\n🤖 Adding AI/agent ecosystem packages...");
        match registry {
            Registry::Npm => {
                for pkg in NPM_AI_PACKAGES {
                    packages.insert(pkg.to_string());
                }
                println!("   Added {} AI packages", NPM_AI_PACKAGES.len());
            }
            Registry::Pypi => {
                for pkg in PYPI_AI_PACKAGES {
                    packages.insert(pkg.to_string());
                }
                println!("   Added {} AI packages", PYPI_AI_PACKAGES.len());
            }
            Registry::Crates => {
                println!("   Warning: crates.io AI packages not yet defined");
            }
        }
    }

    // 3. Add packages with known install scripts (npm only)
    if args.include_ai && registry == Registry::Npm {
        println!("\n⚠️  Adding packages with install scripts...");
        for pkg in INSTALL_SCRIPT_PACKAGES {
            packages.insert(pkg.to_string());
        }
        println!(
            "   Added {} install script packages",
            INSTALL_SCRIPT_PACKAGES.len()
        );
    }

    // 4. Fetch packages with CVEs
    if args.include_cves {
        println!("\n🔒 Fetching packages with known CVEs...");
        let ecosystem = match registry {
            Registry::Npm => "npm",
            Registry::Pypi => "PyPI",
            Registry::Crates => "crates.io",
        };
        match fetch_cve_packages(&client, ecosystem).await {
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
    println!(
        "\n📊 Total unique {} packages to seed: {}",
        registry_name,
        packages.len()
    );

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

    println!("\n🚀 Pushing {} packages to scan queue...\n", registry_name);

    // Create all jobs
    let jobs: Vec<ScanJob> = packages
        .iter()
        .map(|package| ScanJob {
            id: uuid::Uuid::new_v4(),
            package: package.clone(),
            version: None, // Will fetch latest
            registry,
            priority,
            requested_at: chrono::Utc::now(),
            requested_by: Some("seed".to_string()),
            tarball_path: None,
        })
        .collect();

    // Push in batches of 500 using pipelining
    const BATCH_SIZE: usize = 500;
    let mut success = 0;
    let mut failed = 0;

    let pb = ProgressBar::new(jobs.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )?
            .progress_chars("#>-"),
    );

    for chunk in jobs.chunks(BATCH_SIZE) {
        match queue.push_batch(chunk.to_vec()).await {
            Ok(count) => {
                success += count;
                pb.inc(count as u64);
            }
            Err(e) => {
                tracing::warn!("Failed to queue batch: {}", e);
                failed += chunk.len();
                pb.inc(chunk.len() as u64);
            }
        }
    }

    pb.finish_and_clear();

    println!("✅ Seeding complete!");
    println!("   Queued: {} {} packages", success, registry_name);
    if failed > 0 {
        println!("   Failed: {} packages", failed);
    }

    let total = queue.total_len().await?;
    println!("\n📈 Total queue size: {} jobs", total);

    Ok(())
}

/// PyPI top packages response structure
#[derive(Debug, Deserialize)]
struct PypiTopPackagesResponse {
    rows: Vec<PypiPackageRow>,
}

#[derive(Debug, Deserialize)]
struct PypiPackageRow {
    project: String,
    #[allow(dead_code)]
    download_count: u64,
}

/// Fetch top packages from npm download-counts
async fn fetch_top_npm_packages(
    client: &reqwest::Client,
    count: usize,
    offset: usize,
) -> Result<Vec<String>> {
    // Fetch the download counts JSON (this is a large file ~90MB)
    let response = client
        .get(NPM_DOWNLOAD_COUNTS_URL)
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
        .skip(offset)
        .take(count)
        .map(|(name, _)| name)
        .collect();

    Ok(top_packages)
}

/// Fetch top packages from PyPI (via hugovk/top-pypi-packages)
async fn fetch_top_pypi_packages(
    client: &reqwest::Client,
    count: usize,
    offset: usize,
) -> Result<Vec<String>> {
    let response = client
        .get(PYPI_TOP_PACKAGES_URL)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch PyPI top packages: {}", response.status());
    }

    let data: PypiTopPackagesResponse = response.json().await?;

    let top_packages: Vec<String> = data
        .rows
        .into_iter()
        .skip(offset)
        .take(count)
        .map(|r| r.project)
        .collect();

    Ok(top_packages)
}

/// Fetch packages with known CVEs from OSV
async fn fetch_cve_packages(client: &reqwest::Client, ecosystem: &str) -> Result<Vec<String>> {
    let mut packages = HashSet::new();

    // Query OSV for recent vulnerabilities in the specified ecosystem
    let query = serde_json::json!({
        "package": {
            "ecosystem": ecosystem
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
