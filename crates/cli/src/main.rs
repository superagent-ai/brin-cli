//! sus CLI - Security-first package gateway for AI agents

mod agents_md;
mod api_client;
mod commands;
mod config;
mod project;
mod ui;

use clap::{Parser, Subcommand};

const BANNER: &str = r#"
   ___  __  __  ___
  / __// / / / / __/
 _\ \ / /_/ / _\ \ 
/___/ \____/ /___/ 
"#;

#[derive(Parser)]
#[command(name = "sus")]
#[command(about = "is this package sus? 🔍 security-first package gateway for ai agents")]
#[command(before_help = BANNER)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// API endpoint to use
    #[arg(long, env = "SUS_API_URL", default_value = "https://api.sus-pm.com")]
    api_url: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize sus in the current project
    Init {
        /// Skip prompts and use defaults (enables AGENTS.md docs)
        #[arg(long, short)]
        yes: bool,
    },

    /// Add packages (with safety checks)
    Add {
        /// Packages to install (e.g., "lodash", "express@4.18.0")
        packages: Vec<String>,

        /// Skip all safety checks (dangerous!)
        #[arg(long)]
        yolo: bool,

        /// Block packages with any warnings
        #[arg(long)]
        strict: bool,
    },

    /// Remove packages
    Remove {
        /// Packages to remove
        packages: Vec<String>,
    },

    /// Scan current project for vulnerabilities
    Scan {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Check a package without installing
    Check {
        /// Package to check (e.g., "lodash", "express@4.18.0")
        package: String,
    },

    /// Update dependencies
    Update {
        /// Show what would be updated without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// Show why a package is in your dependency tree
    Why {
        /// Package to trace
        package: String,
    },

    /// Uninstall sus from this system
    Uninstall {
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,

        /// Also remove project-level files (.sus-docs/, sus.json)
        #[arg(long)]
        all: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sus=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let client = api_client::SusClient::new(&cli.api_url);

    match cli.command {
        Commands::Init { yes } => commands::init::run(yes).await,

        Commands::Add {
            packages,
            yolo,
            strict,
        } => commands::add::run(&client, packages, yolo, strict).await,

        Commands::Remove { packages } => commands::remove::run(packages).await,

        Commands::Scan { json } => commands::scan::run(&client, json).await,

        Commands::Check { package } => commands::check::run(&client, &package).await,

        Commands::Update { dry_run } => commands::update::run(&client, dry_run).await,

        Commands::Why { package } => commands::why::run(&package).await,

        Commands::Uninstall { yes, all } => commands::uninstall::run(yes, all).await,
    }
}
