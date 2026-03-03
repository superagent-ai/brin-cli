//! brin CLI — thin client for the brin security API

mod api_client;
mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "brin")]
#[command(
    about = "brin — security scanning for packages, repos, MCP servers, skills, domains, commits and more"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// API endpoint to use
    #[arg(long, env = "BRIN_API_URL", default_value = "https://api.brin.sh")]
    api_url: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Check an artifact's security assessment
    ///
    /// ARTIFACT format: <origin>/<identifier>
    ///
    /// Examples:
    ///   brin check npm/express
    ///   brin check npm/lodash@4.17.21
    ///   brin check pypi/requests
    ///   brin check crate/serde
    ///   brin check repo/expressjs/express
    ///   brin check mcp/modelcontextprotocol/servers
    ///   brin check skill/owner/repo
    ///   brin check domain/example.com
    ///   brin check commit/owner/repo@abc123def
    Check {
        /// Artifact to check, formatted as <origin>/<identifier>
        artifact: String,

        /// Include sub-scores (identity, behavior, content, graph) in the response
        #[arg(long)]
        details: bool,

        /// Webhook URL to receive tier-completion events as the deep scan progresses
        #[arg(long, value_name = "URL")]
        webhook: Option<String>,

        /// Print only the X-Brin-* response headers instead of the JSON body
        #[arg(long)]
        headers: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = api_client::BrinClient::new(&cli.api_url);

    match cli.command {
        Commands::Check {
            artifact,
            details,
            webhook,
            headers,
        } => commands::check::run(&client, &artifact, details, webhook.as_deref(), headers).await,
    }
}
